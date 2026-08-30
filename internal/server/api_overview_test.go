package server

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"mantou/internal/config"
	"mantou/internal/logx"
	"mantou/internal/modules/cert"
)

func TestUpdateSettingsRejectsHTTPSWithoutCertificate(t *testing.T) {
	gin.SetMode(gin.TestMode)
	cfg := config.NewManager(filepath.Join(t.TempDir(), "config.json"))
	if err := cfg.Load(); err != nil {
		t.Fatal(err)
	}
	s := &Server{deps: Deps{Config: cfg}}
	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	ctx.Request = httptest.NewRequest(http.MethodPut, "/settings", strings.NewReader(`{"panel":{"https":{"enabled":true,"certId":"","domain":"panel.example.com"}}}`))
	ctx.Request.Header.Set("Content-Type", "application/json")

	s.handleUpdateSettings(ctx)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected status %d, got %d: %s", http.StatusBadRequest, w.Code, w.Body.String())
	}
}

func TestUpdateSettingsRejectsHTTPSWithoutDomain(t *testing.T) {
	gin.SetMode(gin.TestMode)
	dataDir := t.TempDir()
	cfg := config.NewManager(filepath.Join(dataDir, "config.json"))
	if err := cfg.Load(); err != nil {
		t.Fatal(err)
	}
	if err := cfg.Update(func(c *config.Config) {
		c.Certs = []config.Certificate{{ID: "panel", Name: "panel", Method: "file", Enabled: true}}
	}); err != nil {
		t.Fatal(err)
	}
	certModule := cert.New(logx.New(logx.Options{}), filepath.Join(dataDir, "certs"), cfg)
	defer certModule.Close()
	certPEM, keyPEM := newBackupTestCertificate(t)
	if err := certModule.Import("panel", certPEM, keyPEM); err != nil {
		t.Fatal(err)
	}
	s := &Server{deps: Deps{Config: cfg, Cert: certModule, Log: logx.New(logx.Options{}), RestartPanel: func() {}}}
	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	ctx.Request = httptest.NewRequest(http.MethodPut, "/settings", strings.NewReader(`{"panel":{"https":{"enabled":true,"certId":"panel","domain":""}}}`))
	ctx.Request.Header.Set("Content-Type", "application/json")

	s.handleUpdateSettings(ctx)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected status %d, got %d: %s", http.StatusBadRequest, w.Code, w.Body.String())
	}
	if cfg.Get().Panel.HTTPS.Enabled {
		t.Fatal("HTTPS setting must not be saved without a domain")
	}
}

// 面板域名填了通配符要报得出原因：这条路径原先把 normalizePanelDomain 的错误
// 换成了一句笼统的"必须填写有效的单一访问域名"，用户看不出错在哪一个字上。
// 不需要真证书——写法校验排在证书存在性之前。
func TestUpdateSettingsRejectsWildcardPanelDomain(t *testing.T) {
	gin.SetMode(gin.TestMode)
	cfg := config.NewManager(filepath.Join(t.TempDir(), "config.json"))
	if err := cfg.Load(); err != nil {
		t.Fatal(err)
	}
	s := &Server{deps: Deps{Config: cfg}}
	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	ctx.Request = httptest.NewRequest(http.MethodPut, "/settings", strings.NewReader(`{"panel":{"https":{"enabled":true,"certId":"panel","domain":"*.example.com"}}}`))
	ctx.Request.Header.Set("Content-Type", "application/json")

	s.handleUpdateSettings(ctx)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("通配符域名应被拒，实际 %d：%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "通配符") {
		t.Fatalf("错误应说明问题出在通配符：%s", w.Body.String())
	}
	if cfg.Get().Panel.HTTPS.Enabled {
		t.Fatal("被拒的请求不该把面板 HTTPS 存成启用")
	}
}

func TestUpdateSettingsRejectsDomainNotCoveredByCertificate(t *testing.T) {
	gin.SetMode(gin.TestMode)
	dataDir := t.TempDir()
	cfg := config.NewManager(filepath.Join(dataDir, "config.json"))
	if err := cfg.Load(); err != nil {
		t.Fatal(err)
	}
	if err := cfg.Update(func(c *config.Config) {
		c.Certs = []config.Certificate{{ID: "panel", Name: "panel", Method: "file", Enabled: true}}
	}); err != nil {
		t.Fatal(err)
	}
	certModule := cert.New(logx.New(logx.Options{}), filepath.Join(dataDir, "certs"), cfg)
	defer certModule.Close()
	certPEM, keyPEM := newBackupTestCertificate(t)
	if err := certModule.Import("panel", certPEM, keyPEM); err != nil {
		t.Fatal(err)
	}
	s := &Server{deps: Deps{Config: cfg, Cert: certModule, Log: logx.New(logx.Options{}), RestartPanel: func() {}}}
	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	ctx.Request = httptest.NewRequest(http.MethodPut, "/settings", strings.NewReader(`{"panel":{"https":{"enabled":true,"certId":"panel","domain":"other.example.com"}}}`))
	ctx.Request.Header.Set("Content-Type", "application/json")

	s.handleUpdateSettings(ctx)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected status %d, got %d: %s", http.StatusBadRequest, w.Code, w.Body.String())
	}
}

func TestUpdateSettingsAcceptsSingleLegacyAllowedHost(t *testing.T) {
	gin.SetMode(gin.TestMode)
	dataDir := t.TempDir()
	cfg := config.NewManager(filepath.Join(dataDir, "config.json"))
	if err := cfg.Load(); err != nil {
		t.Fatal(err)
	}
	if err := cfg.Update(func(c *config.Config) {
		c.Certs = []config.Certificate{{ID: "panel", Name: "panel", Method: "file", Enabled: true}}
	}); err != nil {
		t.Fatal(err)
	}
	certModule := cert.New(logx.New(logx.Options{}), filepath.Join(dataDir, "certs"), cfg)
	defer certModule.Close()
	certPEM, keyPEM := newBackupTestCertificate(t)
	if err := certModule.Import("panel", certPEM, keyPEM); err != nil {
		t.Fatal(err)
	}
	s := &Server{deps: Deps{Config: cfg, Cert: certModule, Log: logx.New(logx.Options{}), RestartPanel: func() {}}}
	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	ctx.Request = httptest.NewRequest(http.MethodPut, "/settings", strings.NewReader(`{"panel":{"https":{"enabled":true,"certId":"panel","allowedHosts":["backup.example.com"]}}}`))
	ctx.Request.Header.Set("Content-Type", "application/json")

	s.handleUpdateSettings(ctx)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d: %s", http.StatusOK, w.Code, w.Body.String())
	}
	https := cfg.Get().Panel.HTTPS
	if https.Domain != "backup.example.com" || len(https.AllowedHosts) != 0 {
		t.Fatalf("unexpected migrated HTTPS config: %#v", https)
	}
}

// TestUpdateSettingsRejectsDisabledCert 固化「禁用即不可引用」硬约束：
// 被禁用的证书不允许被选作面板 HTTPS 证书，否则面板重启后会因证书解析失败而无法启动。
func TestUpdateSettingsRejectsDisabledCert(t *testing.T) {
	gin.SetMode(gin.TestMode)
	dataDir := t.TempDir()
	cfg := config.NewManager(filepath.Join(dataDir, "config.json"))
	if err := cfg.Load(); err != nil {
		t.Fatal(err)
	}
	if err := cfg.Update(func(c *config.Config) {
		c.Certs = []config.Certificate{{ID: "panel", Name: "panel", Method: "file", Enabled: false}}
	}); err != nil {
		t.Fatal(err)
	}
	certModule := cert.New(logx.New(logx.Options{}), filepath.Join(dataDir, "certs"), cfg)
	defer certModule.Close()
	certPEM, keyPEM := newBackupTestCertificate(t)
	if err := certModule.Import("panel", certPEM, keyPEM); err != nil {
		t.Fatal(err)
	}
	s := &Server{deps: Deps{Config: cfg, Cert: certModule, Log: logx.New(logx.Options{}), RestartPanel: func() {}}}
	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	ctx.Request = httptest.NewRequest(http.MethodPut, "/settings", strings.NewReader(`{"panel":{"https":{"enabled":true,"certId":"panel","domain":"panel.example.com"}}}`))
	ctx.Request.Header.Set("Content-Type", "application/json")

	s.handleUpdateSettings(ctx)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected status %d for disabled cert, got %d: %s", http.StatusBadRequest, w.Code, w.Body.String())
	}
	if cfg.Get().Panel.HTTPS.Enabled {
		t.Fatal("panel HTTPS must stay disabled when the selected certificate is disabled")
	}
}
