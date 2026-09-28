package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"mantou/internal/auth"
	"mantou/internal/config"
	"mantou/internal/logx"
	"mantou/internal/modules/cert"
)

// 证书私钥是这套接口里后果最持久的一样东西：会话可以撤、密码可以改，一份带走的私钥却能
// 一直冒充这个域名，直到证书过期。别的凭证一律不让一条会话读到（列表脱敏、整份备份导出要验
// 密码），唯独它原先只凭会话就能整份取走。下面钉住：带私钥的导出要当场验一次当前密码。
//
// 同一个文件里顺带钉住证书导入的 ID 约束：只能导入到配置里已有、且不是路径方式的条目上。

// newCertExportTest 一台装着一张可导出证书（ID c1，上传文件方式）的面板。
func newCertExportTest(t *testing.T) (*Server, *gin.Engine) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	dataDir := t.TempDir()
	manager := config.NewManager(filepath.Join(dataDir, "config.json"))
	if err := manager.Load(); err != nil {
		t.Fatal(err)
	}
	hash, err := auth.HashPassword(testLoginPass)
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.Update(func(c *config.Config) {
		c.Auth.Initialized = true
		c.Auth.Username = testLoginUser
		c.Auth.PasswordHash = hash
		c.Certs = []config.Certificate{
			{ID: "c1", Name: "站点证书", Enabled: true, Method: "file"},
			{ID: "p1", Name: "路径证书", Enabled: true, Method: "path", CertPath: "/nowhere/a.crt", KeyPath: "/nowhere/a.key"},
		}
	}); err != nil {
		t.Fatal(err)
	}
	log := logx.New(logx.Options{})
	module := cert.New(log, filepath.Join(dataDir, "certs"), manager)
	certPEM, keyPEM := newBackupTestCertificate(t)
	if err := module.Import("c1", certPEM, keyPEM); err != nil {
		t.Fatal(err)
	}
	s := &Server{deps: Deps{Config: manager, Log: log, Cert: module, DataDir: dataDir}, sessions: newSessionRegistry()}
	t.Cleanup(s.sessions.close)

	router := gin.New()
	router.GET("/certs/:id/export", s.handleExportCert)
	router.POST("/certs/:id/export", s.handleExportCertWithKey)
	router.POST("/certs/import", s.handleImportCert)
	return s, router
}

// TestCertExportGetRefusesPrivateKey 旧的 GET ?includePrivateKey=true 不再给私钥：
// 那条路上没有地方验密码，放行就等于这道复核不存在。
func TestCertExportGetRefusesPrivateKey(t *testing.T) {
	_, router := newCertExportTest(t)
	w := performJSONRequest(router, http.MethodGet, "/certs/c1/export?includePrivateKey=true", "")
	if w.Code != http.StatusForbidden {
		t.Fatalf("GET 带私钥应当被拒，实际 %d：%s", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), "PRIVATE KEY") {
		t.Fatalf("被拒的响应里带出了私钥：%s", w.Body.String())
	}
}

// TestCertExportGetCertOnly 不带私钥的导出照旧只凭会话即可：证书本来就是公开信息。
func TestCertExportGetCertOnly(t *testing.T) {
	_, router := newCertExportTest(t)
	w := performJSONRequest(router, http.MethodGet, "/certs/c1/export", "")
	if w.Code != http.StatusOK {
		t.Fatalf("只导出证书应当成功，实际 %d：%s", w.Code, w.Body.String())
	}
	body := w.Body.String()
	if !strings.Contains(body, "CERTIFICATE") || strings.Contains(body, "PRIVATE KEY") {
		t.Fatalf("应当只有证书、没有私钥：%s", body)
	}
}

// TestCertExportWithKeyRequiresPassword 带私钥的导出：凭据不对一律 403 且不带私钥，
// 凭据正确才给私钥，并留一条"含私钥"的审计记录。
func TestCertExportWithKeyRequiresPassword(t *testing.T) {
	for _, tc := range []struct{ name, body string }{
		{"不带凭据", `{}`},
		{"密码不对", `{"account":"` + testLoginUser + `","password":"wrong-password"}`},
		{"账户不对", `{"account":"root","password":"` + testLoginPass + `"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, router := newCertExportTest(t)
			w := performJSONRequest(router, http.MethodPost, "/certs/c1/export", tc.body)
			if w.Code != http.StatusForbidden {
				t.Fatalf("凭据不对应当 403，实际 %d：%s", w.Code, w.Body.String())
			}
			if strings.Contains(w.Body.String(), "PRIVATE KEY") {
				t.Fatalf("被拒的响应里带出了私钥：%s", w.Body.String())
			}
		})
	}

	s, router := newCertExportTest(t)
	w := performJSONRequest(router, http.MethodPost, "/certs/c1/export",
		`{"account":"`+testLoginUser+`","password":"`+testLoginPass+`"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("凭据正确应当导出成功，实际 %d：%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "PRIVATE KEY") {
		t.Fatalf("凭据正确时应当带上私钥：%s", w.Body.String())
	}
	mustLogEntry(t, s.deps.Log, "导出 SSL/TLS 证书", "INFO")
}

// TestCertExportWithKeyCountsTowardReauth 这条路与其它复核共用一份失败计数：猜满之后照样 429。
func TestCertExportWithKeyCountsTowardReauth(t *testing.T) {
	s, _ := newCertExportTest(t)
	const token = "token-cert-export"
	s.sessions.add(token, testLoginUser, time.Hour)
	send := func(body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/api/certs/c1/export", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		ctx, _ := gin.CreateTestContext(rec)
		ctx.Request = req
		ctx.Params = gin.Params{{Key: "id", Value: "c1"}}
		req.AddCookie(&http.Cookie{Name: sessionCookie, Value: token})
		s.handleExportCertWithKey(ctx)
		return rec
	}
	for i := 0; i < reauthMaxFails; i++ {
		if rec := send(`{"account":"root","password":"x"}`); rec.Code != http.StatusForbidden {
			t.Fatalf("第 %d 次状态码 %d，期望 403", i+1, rec.Code)
		}
	}
	wantLocked(t, send(`{"account":"`+testLoginUser+`","password":"`+testLoginPass+`"}`), "打满之后的私钥导出")
}

// TestCertImportRequiresKnownID 配置里没有的 ID 不收：那样写出的文件是孤儿，
// 进了内存索引还可能抢走真证书的域名。
func TestCertImportRequiresKnownID(t *testing.T) {
	_, router := newCertExportTest(t)
	certPEM, keyPEM := newBackupTestCertificate(t)
	body := `{"id":"ghost","certPem":` + jsonQuote(string(certPEM)) + `,"keyPem":` + jsonQuote(string(keyPEM)) + `}`
	w := performJSONRequest(router, http.MethodPost, "/certs/import", body)
	if w.Code != http.StatusNotFound {
		t.Fatalf("配置里没有的 ID 应当 404，实际 %d：%s", w.Code, w.Body.String())
	}
}

// TestCertImportRejectsPathCert 路径方式的证书内容来自用户指定的磁盘路径，不能往证书目录里导入。
func TestCertImportRejectsPathCert(t *testing.T) {
	_, router := newCertExportTest(t)
	certPEM, keyPEM := newBackupTestCertificate(t)
	body := `{"id":"p1","certPem":` + jsonQuote(string(certPEM)) + `,"keyPem":` + jsonQuote(string(keyPEM)) + `}`
	w := performJSONRequest(router, http.MethodPost, "/certs/import", body)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("路径方式的证书应当拒绝导入，实际 %d：%s", w.Code, w.Body.String())
	}
}

// TestCertImportKnownFileCert 正常路径：导入到已有的文件方式条目上。
func TestCertImportKnownFileCert(t *testing.T) {
	_, router := newCertExportTest(t)
	certPEM, keyPEM := newBackupTestCertificate(t)
	body := `{"id":"c1","certPem":` + jsonQuote(string(certPEM)) + `,"keyPem":` + jsonQuote(string(keyPEM)) + `}`
	if w := performJSONRequest(router, http.MethodPost, "/certs/import", body); w.Code != http.StatusOK {
		t.Fatalf("导入到已有条目应当成功，实际 %d：%s", w.Code, w.Body.String())
	}
}

// jsonQuote 把一段文本写成 JSON 字符串字面量（PEM 里有换行，不能直接拼）。
func jsonQuote(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}
