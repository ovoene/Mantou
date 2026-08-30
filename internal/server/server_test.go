package server

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"mantou/internal/config"
	"mantou/internal/logx"
	"mantou/internal/modules/cert"
)

func newPanelTestCertificate(t *testing.T) *tls.Certificate {
	t.Helper()
	return newPanelTestCertificateForDomains(t, "panel.example.com", "*.example.net")
}

func newPanelTestCertificateForDomains(t *testing.T, domains ...string) *tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: domains[0]},
		DNSNames:     domains,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func TestPanelTLSConfigRequiresConfiguredDomain(t *testing.T) {
	cert := newPanelTestCertificate(t)
	cfgManager := config.NewManager(filepath.Join(t.TempDir(), "config.json"))
	if err := cfgManager.Load(); err != nil {
		t.Fatal(err)
	}
	if err := cfgManager.Update(func(cfg *config.Config) {
		cfg.Panel.HTTPS.Domain = "panel.example.com"
	}); err != nil {
		t.Fatal(err)
	}
	s := &Server{deps: Deps{Config: cfgManager}, panelCert: cert}
	cfg, err := s.panelTLSConfig()
	if err != nil {
		t.Fatal(err)
	}
	if cert.Leaf == nil {
		t.Fatal("certificate Leaf was not populated")
	}

	for _, tc := range []struct {
		name       string
		serverName string
		wantErr    bool
	}{
		{name: "configured DNS name", serverName: "panel.example.com"},
		{name: "other covered DNS name", serverName: "api.example.net", wantErr: true},
		{name: "empty SNI", wantErr: true},
		{name: "IP SNI", serverName: "192.0.2.1", wantErr: true},
		{name: "certificate-external SNI", serverName: "other.example.com", wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := cfg.GetCertificate(&tls.ClientHelloInfo{ServerName: tc.serverName})
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got != cert {
				t.Fatal("unexpected certificate")
			}
		})
	}
}

// fakeTLSConn 只为让 tls.ClientHelloInfo.Conn 能报出一个指定的对端地址。
// 其余 net.Conn 方法不会被 GetCertificate 调用，留空实现即可。
type fakeTLSConn struct {
	net.Conn
	remote net.Addr
}

func (c fakeTLSConn) RemoteAddr() net.Addr { return c.remote }

// TestPanelTLSConfigIgnoresPeerAddress 钉住 SNI 校验不看对端地址——回环也没有例外。
//
// 这里曾经有一条放行：「空 SNI + 回环对端」直接发面板证书，为的是容器健康探测。
// RFC 6066 §3 禁止把 IP 字面量放进 SNI，探测只能连 127.0.0.1，所以它的 ServerName 恒为空，
// 一律按域名校验就会把探测拒在握手阶段。探活整套移除后这条放行也收回了。
//
// 收回的意义在于把判定压回单一条件：能不能拿到面板证书，只取决于 SNI 是否等于配置域名。
// 对端是谁一概不看，因此"先设法让连接看起来来自本机"这条思路在 TLS 层就没有出口，
// 后面所有 HTTP 中间件也就不必再考虑"这个连接是不是走了握手期的特例"。
func TestPanelTLSConfigIgnoresPeerAddress(t *testing.T) {
	cert := newPanelTestCertificate(t)
	cfgManager := config.NewManager(filepath.Join(t.TempDir(), "config.json"))
	if err := cfgManager.Load(); err != nil {
		t.Fatal(err)
	}
	if err := cfgManager.Update(func(cfg *config.Config) {
		cfg.Panel.HTTPS.Domain = "panel.example.com"
	}); err != nil {
		t.Fatal(err)
	}
	s := &Server{deps: Deps{Config: cfgManager}, panelCert: cert}
	cfg, err := s.panelTLSConfig()
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name       string
		serverName string
		remote     net.Addr
		wantErr    bool
	}{
		// 空 SNI 一律被拒，来自本机也一样：这是被收回的那条放行。
		{
			name:    "IPv4 回环无 SNI：拒绝",
			remote:  &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 47672},
			wantErr: true,
		},
		{
			name:    "IPv6 回环无 SNI：拒绝",
			remote:  &net.TCPAddr{IP: net.IPv6loopback, Port: 47673},
			wantErr: true,
		},
		{
			name:    "外部来源无 SNI：拒绝",
			remote:  &net.TCPAddr{IP: net.IPv4(203, 0, 113, 7), Port: 51000},
			wantErr: true,
		},
		{
			name:       "回环但 SNI 不匹配：拒绝",
			serverName: "other.example.com",
			remote:     &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 47674},
			wantErr:    true,
		},
		// 正面用例：SNI 对得上就发证书，对端是外网地址也照发——
		// 面板本来就是给远程访问的，这一条同时说明上面几条不是"把所有连接都拒了"。
		{
			name:       "外部来源 SNI 匹配：放行",
			serverName: "panel.example.com",
			remote:     &net.TCPAddr{IP: net.IPv4(203, 0, 113, 7), Port: 51001},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := cfg.GetCertificate(&tls.ClientHelloInfo{
				ServerName: tc.serverName,
				Conn:       fakeTLSConn{remote: tc.remote},
			})
			if tc.wantErr {
				if err == nil {
					t.Fatal("期望被拒绝，实际放行了")
				}
				return
			}
			if err != nil {
				t.Fatalf("SNI 与配置域名一致时应能取到证书：%v", err)
			}
			if got != cert {
				t.Fatal("返回的不是面板证书")
			}
		})
	}
}

func TestPanelTLSConfigRejectsDomainNotCoveredByCertificate(t *testing.T) {
	cfgManager := config.NewManager(filepath.Join(t.TempDir(), "config.json"))
	if err := cfgManager.Load(); err != nil {
		t.Fatal(err)
	}
	if err := cfgManager.Update(func(cfg *config.Config) {
		cfg.Panel.HTTPS.Domain = "other.example.com"
	}); err != nil {
		t.Fatal(err)
	}
	s := &Server{deps: Deps{Config: cfgManager}, panelCert: newPanelTestCertificate(t)}
	if _, err := s.panelTLSConfig(); err == nil {
		t.Fatal("expected uncovered domain to be rejected")
	}
}

func TestPanelTLSConfigReadsRenewedCertificate(t *testing.T) {
	dataDir := t.TempDir()
	cfgManager := config.NewManager(filepath.Join(dataDir, "config.json"))
	if err := cfgManager.Load(); err != nil {
		t.Fatal(err)
	}
	if err := cfgManager.Update(func(cfg *config.Config) {
		cfg.Panel.HTTPS.CertID = "panel"
		cfg.Panel.HTTPS.Domain = "panel.example.com"
		cfg.Certs = []config.Certificate{{ID: "panel", Method: "file", Enabled: true}}
	}); err != nil {
		t.Fatal(err)
	}
	certModule := cert.New(logx.New(logx.Options{}), filepath.Join(dataDir, "certs"), cfgManager)
	defer certModule.Close()
	first := newPanelTestCertificateForDomains(t, "panel.example.com")
	firstPEM, firstKeyPEM := panelTestCertificatePEM(t, first)
	if err := certModule.Import("panel", firstPEM, firstKeyPEM); err != nil {
		t.Fatal(err)
	}
	s := &Server{deps: Deps{Config: cfgManager, Cert: certModule}}
	tlsConfig, err := s.panelTLSConfig()
	if err != nil {
		t.Fatal(err)
	}
	before, err := tlsConfig.GetCertificate(&tls.ClientHelloInfo{ServerName: "panel.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	second := newPanelTestCertificateForDomains(t, "panel.example.com")
	secondPEM, secondKeyPEM := panelTestCertificatePEM(t, second)
	if err := certModule.Import("panel", secondPEM, secondKeyPEM); err != nil {
		t.Fatal(err)
	}
	after, err := tlsConfig.GetCertificate(&tls.ClientHelloInfo{ServerName: "panel.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if before == after {
		t.Fatal("expected renewed certificate to be read dynamically")
	}
}

func panelTestCertificatePEM(t *testing.T, certificate *tls.Certificate) ([]byte, []byte) {
	t.Helper()
	keyDER, err := x509.MarshalPKCS8PrivateKey(certificate.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Certificate[0]}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
}

func TestRequestPanelRestartUsesInProcessCallbackOnce(t *testing.T) {
	called := make(chan struct{}, 2)
	s := &Server{deps: Deps{
		Log: logx.New(logx.Options{}),
		RestartPanel: func() {
			called <- struct{}{}
		},
	}}

	s.requestPanelRestart("restart")
	s.requestPanelRestart("restart")

	select {
	case <-called:
	case <-time.After(2 * time.Second):
		t.Fatal("restart callback was not called")
	}
	select {
	case <-called:
		t.Fatal("restart callback called more than once")
	case <-time.After(100 * time.Millisecond):
	}
}

func TestRequirePanelCertificateHost(t *testing.T) {
	gin.SetMode(gin.TestMode)
	cfgManager := config.NewManager(filepath.Join(t.TempDir(), "config.json"))
	if err := cfgManager.Load(); err != nil {
		t.Fatal(err)
	}
	if err := cfgManager.Update(func(cfg *config.Config) {
		cfg.Panel.HTTPS.Domain = "panel.example.com"
	}); err != nil {
		t.Fatal(err)
	}
	s := &Server{deps: Deps{Config: cfgManager}, panelHTTPS: true}
	r := gin.New()
	r.Use(s.requirePanelCertificateHost())
	r.GET("/", func(c *gin.Context) { c.Status(http.StatusNoContent) })

	for _, tc := range []struct {
		name   string
		host   string
		status int
	}{
		{name: "matching host", host: "panel.example.com:8443", status: http.StatusNoContent},
		{name: "other certificate host", host: "api.example.net", status: http.StatusForbidden},
		{name: "IP host", host: "192.0.2.1:8443", status: http.StatusForbidden},
		{name: "other host", host: "other.example.com", status: http.StatusForbidden},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "https://"+tc.host+"/", nil)
			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)
			if w.Code != tc.status {
				t.Fatalf("expected status %d, got %d", tc.status, w.Code)
			}
		})
	}
}

// 域名不匹配页不许告诉匿名访客两件事：这里是管理面板、以及该换成哪个域名。
// 走到这一页的请求最常见的来源就是按 IP 扫端口，两条信息合起来正好是入口的全部线索。
func TestRequirePanelCertificateHostRevealsNothing(t *testing.T) {
	gin.SetMode(gin.TestMode)
	cfgManager := config.NewManager(filepath.Join(t.TempDir(), "config.json"))
	if err := cfgManager.Load(); err != nil {
		t.Fatal(err)
	}
	if err := cfgManager.Update(func(cfg *config.Config) {
		cfg.Panel.HTTPS.Domain = "panel.example.com"
		cfg.Panel.BasePath = "/mymantou"
	}); err != nil {
		t.Fatal(err)
	}
	s := &Server{deps: Deps{Config: cfgManager}, panelHTTPS: true}
	r := gin.New()
	r.Use(s.requirePanelCertificateHost())
	r.GET("/", func(c *gin.Context) { c.Status(http.StatusNoContent) })

	// 浏览器（HTML 卡片页）与脚本 / 前端 XHR（JSON）两条分支都要查。
	for _, accept := range []string{"text/html,application/xhtml+xml", "application/json"} {
		req := httptest.NewRequest(http.MethodGet, "https://192.0.2.1:8443/", nil)
		req.Header.Set("Accept", accept)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		if w.Code != http.StatusForbidden {
			t.Fatalf("Accept=%s: 状态 = %d，期望 403", accept, w.Code)
		}
		body := w.Body.String()
		for _, leak := range []string{"panel.example.com", "面板", "mymantou"} {
			if strings.Contains(body, leak) {
				t.Fatalf("Accept=%s: 响应里出现了 %q，这一页不该透露管理入口的任何线索：\n%s",
					accept, leak, body)
			}
		}
	}
}
