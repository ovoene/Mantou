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
)

// 面板自身的安全响应头（审计 NEW-3）。
//
// 此前这三类头只存在于**用户站点**那一侧（internal/modules/webservice/middleware.go 的
// withSecurityHeaders，还要由 WebChild.FrameDeny 开），面板一个都不发。
//
// 这一组用例盯两件事，缺任何一件这道修复都会静默退化：
//
//  1. **取值**。frame-ancestors 取 none 而不是 self（面板前端全域无 iframe，
//     没有要放行的自嵌套场景）；Referrer-Policy 取 same-origin 而不是浏览器默认的
//     strict-origin-when-cross-origin（后者仍会把面板 origin 送给外站）。
//  2. **位置**。中间件排在入站防护**前面**，于是被防护拦下的 403、限速的 429、
//     鉴权失败的 401 都带着这四道头。没有这一条，"每个响应都带"会随着日后新增的
//     早退路径慢慢变成"大部分响应带"，而漏掉的恰好都是错误页——最容易被嵌进 iframe 的那些。
//
// 顺带钉住"不发 default-src / script-src"：面板是 Vue + Element Plus，运行期注入 style，
// 收紧那两项必须配合构建产物一起改并逐页验证。哪天有人顺手加上，这里要先红一次。

// wantPanelSecurityHeaders 是面板每个响应都必须带的四道头。
var wantPanelSecurityHeaders = map[string]string{
	"Content-Security-Policy": "frame-ancestors 'none'",
	"X-Frame-Options":         "DENY",
	"Referrer-Policy":         "same-origin",
	"X-Content-Type-Options":  "nosniff",
}

// newHeaderTestEngine 用 New 构建真实中间件链——必须走 New，
// 否则测的就只是 securityHeaders 这个函数本身，而不是它在链上的位置。
func newHeaderTestEngine(t *testing.T) *gin.Engine {
	t.Helper()
	gin.SetMode(gin.TestMode)
	manager := config.NewManager(filepath.Join(t.TempDir(), "config.json"))
	if err := manager.Load(); err != nil {
		t.Fatal(err)
	}
	// 不关防护：本组用例正需要它开着（默认启用 + 仅局域网），好让 403 那一支可测。
	s := New(Deps{Config: manager, Log: logx.New(logx.Options{})})
	engine, ok := s.http.Handler.(*gin.Engine)
	if !ok {
		t.Fatalf("面板 Handler 不是 *gin.Engine，而是 %T", s.http.Handler)
	}
	return engine
}

func assertPanelSecurityHeaders(t *testing.T, rec *httptest.ResponseRecorder, ctx string) {
	t.Helper()
	for name, want := range wantPanelSecurityHeaders {
		if got := rec.Header().Get(name); got != want {
			t.Errorf("%s：%s 应为 %q，实际 %q", ctx, name, want, got)
		}
	}
}

// TestSecurityHeadersOnEveryExit 每条出口都带这四道头，包括中途早退的。
func TestSecurityHeadersOnEveryExit(t *testing.T) {
	engine := newHeaderTestEngine(t)

	cases := []struct {
		name       string
		method     string
		path       string
		remote     string
		wantStatus int
	}{
		{
			name: "免鉴权接口正常返回", method: http.MethodGet, path: "/api/init/status",
			remote: "127.0.0.1:40001", wantStatus: http.StatusOK,
		},
		{
			// 这一条是"位置"那件事的锁：403 由 firewallGuard 发出，
			// 若 securityHeaders 排到它后面，这里的头会全空。
			name: "被入站防护拦下的 403", method: http.MethodGet, path: "/api/init/status",
			remote: "203.0.113.5:40002", wantStatus: http.StatusForbidden,
		},
		{
			name: "鉴权失败的 401", method: http.MethodGet, path: "/api/auth/me",
			remote: "127.0.0.1:40003", wantStatus: http.StatusUnauthorized,
		},
		{
			name: "不存在的 API 路径", method: http.MethodGet, path: "/api/nope",
			remote: "127.0.0.1:40004", wantStatus: http.StatusNotFound,
		},
		{
			// 跨站的状态变更请求由 csrfGuard 早退，同样要带头。
			name: "CSRF 判定拒绝的请求", method: http.MethodPost, path: "/api/auth/login",
			remote: "127.0.0.1:40005", wantStatus: http.StatusForbidden,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.path, nil)
			req.RemoteAddr = tc.remote
			if tc.method == http.MethodPost {
				// 造一个"两个头都没有、但带着会话 Cookie"的请求：csrfGuard 收紧后的那一格。
				req.AddCookie(&http.Cookie{Name: sessionCookie, Value: "whatever"})
			}
			rec := httptest.NewRecorder()
			engine.ServeHTTP(rec, req)
			if rec.Code != tc.wantStatus {
				t.Fatalf("状态码应为 %d，实际 %d，body=%s", tc.wantStatus, rec.Code, rec.Body.String())
			}
			assertPanelSecurityHeaders(t, rec, tc.name)
		})
	}
}

// TestSecurityHeadersOnFrontendPage 前端页面（HTML）这一路也要带。
//
// 单列一条是因为它走的是另一套处理器（静态资源 / index.html 回退，见 registerRoutes），
// 而点击劫持防护恰恰只对 HTML 页面有意义——API 的 JSON 被嵌进 iframe 没什么可点的。
func TestSecurityHeadersOnFrontendPage(t *testing.T) {
	engine := newHeaderTestEngine(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "127.0.0.1:40010"
	rec := httptest.NewRecorder()
	engine.ServeHTTP(rec, req)
	assertPanelSecurityHeaders(t, rec, "前端页面")
}

// TestSecurityHeadersCSPStaysFrameOnly CSP 只管 frame-ancestors。
//
// 加 default-src / script-src / style-src 是另一件事（抗 XSS），且面板前端在运行期注入
// style 标签，收紧后必须配合构建产物一起改并逐页在浏览器里验。哪天有人顺手加上，
// 这条用例先红——它不是反对上完整 CSP，是要求那件事带着自己的验证一起来。
func TestSecurityHeadersCSPStaysFrameOnly(t *testing.T) {
	engine := newHeaderTestEngine(t)
	req := httptest.NewRequest(http.MethodGet, "/api/init/status", nil)
	req.RemoteAddr = "127.0.0.1:40011"
	rec := httptest.NewRecorder()
	engine.ServeHTTP(rec, req)

	csp := rec.Header().Get("Content-Security-Policy")
	for _, forbidden := range []string{"default-src", "script-src", "style-src", "connect-src"} {
		if strings.Contains(csp, forbidden) {
			t.Errorf("CSP 里出现了 %q：%q —— 这一项要配合前端构建与浏览器回归一起加", forbidden, csp)
		}
	}
}
