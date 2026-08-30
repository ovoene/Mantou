package server

import (
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
)

// 会话 Cookie 的名字与 Secure 属性必须跟随**每次请求的真实协议**，而不是面板配置。
// 这一组测试锁住的是一个真实故障：面板启用 HTTPS 后再关闭，浏览器里残留一条带 Secure 的
// 会话 Cookie，此后从 http + 同一域名登录时，按 RFC 6265bis 的 Strict Secure Cookies 规则
// （非安全来源不得创建或覆盖同名同域同路径的 Secure Cookie），新下发的同名 Cookie 会被
// 浏览器整条丢弃——接口返回 200、日志写「登录成功」，界面却进不去。
// 详见 middleware.go 中 sessionCookie / sessionCookieSecure / sessionCookieLegacy 的说明。

const testLoginUser = "admin"
const testLoginPass = "correct-horse-battery-staple"

var testLoginBody = `{"username":"` + testLoginUser + `","password":"` + testLoginPass + `"}`

// newAuthTestServer 构造一个足以跑通 handleLogin / authRequired 的 Server：
// 已初始化的账户 + 关闭登录锁定的限流器（maxFails≤0）+ 服务端会话表。
func newAuthTestServer(t *testing.T) *Server {
	t.Helper()
	gin.SetMode(gin.TestMode)
	cfg := config.NewManager(filepath.Join(t.TempDir(), "config.json"))
	if err := cfg.Load(); err != nil {
		t.Fatal(err)
	}
	hash, err := auth.HashPassword(testLoginPass)
	if err != nil {
		t.Fatal(err)
	}
	if err := cfg.Update(func(c *config.Config) {
		c.Auth.Initialized = true
		c.Auth.Username = testLoginUser
		c.Auth.PasswordHash = hash
	}); err != nil {
		t.Fatal(err)
	}
	s := &Server{
		deps:     Deps{Config: cfg, Log: logx.New(logx.Options{})},
		limiter:  newLoginLimiter(0, time.Minute, time.Minute), // 不锁定：同一测试里会连续登录多次
		sessions: newSessionRegistry(),
	}
	t.Cleanup(s.sessions.close)
	return s
}

// newSchemeRequest 构造一个明文或 TLS 请求。
// httptest.NewRequest 会为 https:// 目标填好 req.TLS，这里再断言一次：整套修复都以
// c.Request.TLS 判定协议，若这个前提不成立，后面的断言会全部变成假通过。
func newSchemeRequest(t *testing.T, secure bool, method, path, body string) *http.Request {
	t.Helper()
	scheme := "http"
	if secure {
		scheme = "https"
	}
	req := httptest.NewRequest(method, scheme+"://panel.example.com"+path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if secure && req.TLS == nil {
		t.Fatal("https 目标应带 req.TLS，测试前提不成立")
	}
	if !secure && req.TLS != nil {
		t.Fatal("http 目标不应带 req.TLS，测试前提不成立")
	}
	return req
}

// findCookie 返回响应里指定名字的 Set-Cookie；不存在时返回 nil。
func findCookie(resp *http.Response, name string) *http.Cookie {
	for _, ck := range resp.Cookies() {
		if ck.Name == name {
			return ck
		}
	}
	return nil
}

// liveCookies 只保留「真正在下发会话」的 Set-Cookie，过滤掉作废用的空值条目。
func liveCookies(resp *http.Response) []*http.Cookie {
	var out []*http.Cookie
	for _, ck := range resp.Cookies() {
		if ck.Value != "" && ck.MaxAge >= 0 {
			out = append(out, ck)
		}
	}
	return out
}

func TestSessionCookieFollowsRequestScheme(t *testing.T) {
	for _, tc := range []struct {
		name    string
		secure  bool
		want    string
		notWant string
	}{
		{name: "明文连接用非 Secure 的普通名字", secure: false, want: sessionCookie, notWant: sessionCookieSecure},
		{name: "TLS 连接用 __Host- 前缀名", secure: true, want: sessionCookieSecure, notWant: sessionCookie},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newAuthTestServer(t)
			w := httptest.NewRecorder()
			ctx, _ := gin.CreateTestContext(w)
			ctx.Request = newSchemeRequest(t, tc.secure, http.MethodPost, "/auth/login", testLoginBody)

			s.handleLogin(ctx)

			if w.Code != http.StatusOK {
				t.Fatalf("登录应成功，得到 %d: %s", w.Code, w.Body.String())
			}
			resp := w.Result()
			if got := findCookie(resp, tc.notWant); got != nil {
				t.Fatalf("不应下发 %s（会与另一协议下的同名 Cookie 冲突）", tc.notWant)
			}
			ck := findCookie(resp, tc.want)
			if ck == nil {
				t.Fatalf("未下发会话 Cookie %s，Set-Cookie: %v", tc.want, resp.Header.Values("Set-Cookie"))
			}
			if ck.Value == "" {
				t.Fatal("会话 Cookie 的值为空")
			}
			if ck.Secure != tc.secure {
				t.Fatalf("Secure 应为 %v，实际 %v", tc.secure, ck.Secure)
			}
			if !ck.HttpOnly {
				t.Fatal("会话 Cookie 必须是 HttpOnly，否则 XSS 可直接读取")
			}
			// 不设 Max-Age/Expires：浏览器关闭即失效（"关闭页面自动退出"）。
			if ck.MaxAge != 0 || !ck.Expires.IsZero() {
				t.Fatalf("会话 Cookie 不应带有效期，实际 MaxAge=%d Expires=%v", ck.MaxAge, ck.Expires)
			}
			// 旧名字只能被作废，绝不能再被写入有效令牌。
			if legacy := findCookie(resp, sessionCookieLegacy); legacy != nil {
				if legacy.Value != "" || legacy.MaxAge != -1 {
					t.Fatalf("旧名字 %s 只应被作废，实际 Value=%q MaxAge=%d",
						sessionCookieLegacy, legacy.Value, legacy.MaxAge)
				}
			}
		})
	}
}

// TestSessionCookieNamesAreDisjointAcrossSchemes 锁住本次 bug 的核心不变量：
// **同一个 Cookie 名绝不能既在 TLS 下带 Secure 下发、又在明文下不带 Secure 下发**，
// 并且两个名字都不得等于修复前用过的旧名字。
//
// 故障本身发生在浏览器里，服务端单看一次响应看不出异常——这也是它极难自查的原因：
// HTTPS 时期浏览器存下了带 Secure 的旧名字 Cookie；关闭 HTTPS 后服务端下发的同名无 Secure
// Cookie 被浏览器整条丢弃（Strict Secure Cookies），于是登录接口 200、日志写「登录成功」，
// 而浏览器手里一条可用会话都没有。服务端在明文连接上也无法覆盖或删除那条残留
// （删除同样是 Set-Cookie，同样被丢弃）。
// 因此唯一可验证、也唯一有效的服务端约束就是「名字互不相同，且都避开旧名字」——
// 后者让修复前就已陷入该状态的浏览器在升级后自动恢复，不必手动清 Cookie。
func TestSessionCookieNamesAreDisjointAcrossSchemes(t *testing.T) {
	s := newAuthTestServer(t)

	issued := map[bool]*http.Cookie{} // 请求是否 TLS → 下发的会话 Cookie
	for _, secure := range []bool{false, true} {
		w := httptest.NewRecorder()
		ctx, _ := gin.CreateTestContext(w)
		ctx.Request = newSchemeRequest(t, secure, http.MethodPost, "/auth/login", testLoginBody)
		// 刻意把 HTTPS 时期的残留一起发过去（真实浏览器不会在明文连接发送带 Secure 的那条，
		// 这里是为了验证服务端既不把它当有效会话、也不会因它改变下发行为）。
		ctx.Request.Header.Set("Cookie", sessionCookieLegacy+"=stale-token-from-https-era")

		s.handleLogin(ctx)

		if w.Code != http.StatusOK {
			t.Fatalf("secure=%v：登录应成功，得到 %d: %s", secure, w.Code, w.Body.String())
		}
		live := liveCookies(w.Result())
		if len(live) != 1 {
			t.Fatalf("secure=%v：一次登录应只下发一条有效 Cookie，实际 %d 条: %v", secure, len(live), live)
		}
		if live[0].Value == "stale-token-from-https-era" {
			t.Fatalf("secure=%v：新会话不应复用残留令牌", secure)
		}
		if live[0].Name == sessionCookieLegacy {
			t.Fatalf("secure=%v：不得复用修复前的旧名字 %q——浏览器里带 Secure 的残留会挡掉它，"+
				"用户必须手动清 Cookie 才能登录", secure, sessionCookieLegacy)
		}
		issued[secure] = live[0]
	}

	if issued[false].Name == issued[true].Name {
		t.Fatalf("明文与 TLS 下发了同名会话 Cookie %q：关闭面板 HTTPS 后，浏览器会因残留的 "+
			"Secure 同名 Cookie 丢弃新 Set-Cookie，登录看似成功却进不去面板", issued[false].Name)
	}
}

// TestLoginOverHTTPWithStaleSecureCookie 走一遍「关闭面板 HTTPS 后从 http+域名 登录」的
// 完整链路：登录拿到的 Cookie，连同 HTTPS 时期的残留一起带上，必须能通过鉴权中间件。
func TestLoginOverHTTPWithStaleSecureCookie(t *testing.T) {
	s := newAuthTestServer(t)

	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	ctx.Request = newSchemeRequest(t, false, http.MethodPost, "/auth/login", testLoginBody)
	ctx.Request.Header.Set("Cookie", sessionCookieLegacy+"=stale-token-from-https-era")

	s.handleLogin(ctx)

	if w.Code != http.StatusOK {
		t.Fatalf("登录应成功，得到 %d: %s", w.Code, w.Body.String())
	}
	fresh := findCookie(w.Result(), sessionCookie)
	if fresh == nil {
		t.Fatalf("未下发明文会话 Cookie，Set-Cookie: %v", w.Result().Header.Values("Set-Cookie"))
	}

	// 带着新旧两条 Cookie 走一次需要鉴权的请求：必须通过（旧的那条无效令牌不能干扰）。
	r := gin.New()
	r.Use(s.authRequired())
	r.GET("/me", func(c *gin.Context) { c.Status(http.StatusNoContent) })

	req := newSchemeRequest(t, false, http.MethodGet, "/me", "")
	req.Header.Set("Cookie", sessionCookieLegacy+"=stale-token-from-https-era; "+sessionCookie+"="+fresh.Value)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("关闭面板 HTTPS 后从 http+域名 登录应能访问受保护接口，得到 %d: %s", rec.Code, rec.Body.String())
	}
}

// 升级不应把已登录的人踢下线：旧名字的 Cookie 仍要被认。
func TestLegacySessionCookieStillAccepted(t *testing.T) {
	s := newAuthTestServer(t)
	cfg := s.deps.Config.Snapshot()
	token, err := auth.IssueToken(cfg.Auth.JWTSecret, cfg.Auth.Username, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	s.sessions.add(token, cfg.Auth.Username, time.Hour)

	r := gin.New()
	r.Use(s.authRequired())
	r.GET("/me", func(c *gin.Context) { c.Status(http.StatusNoContent) })

	for _, secure := range []bool{false, true} {
		req := newSchemeRequest(t, secure, http.MethodGet, "/me", "")
		req.Header.Set("Cookie", sessionCookieLegacy+"="+token)
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
		if rec.Code != http.StatusNoContent {
			t.Fatalf("secure=%v：升级前签发的会话应继续有效，得到 %d: %s", secure, rec.Code, rec.Body.String())
		}
	}
}

func TestExtractTokenPrefersSchemeMatchingCookie(t *testing.T) {
	s := &Server{}
	both := sessionCookie + "=plain; " + sessionCookieSecure + "=secure"
	for _, tc := range []struct {
		name   string
		secure bool
		cookie string
		want   string
	}{
		{name: "TLS 下优先取 __Host- 那条", secure: true, cookie: both, want: "secure"},
		{name: "明文下优先取普通那条", secure: false, cookie: both, want: "plain"},
		{
			name: "只有普通那条时 TLS 也认（TLS 反代终止在前面的部署）", secure: true,
			cookie: sessionCookie + "=plain", want: "plain",
		},
		{
			name: "只有 __Host- 那条时明文也认（不主动制造 401）", secure: false,
			cookie: sessionCookieSecure + "=secure", want: "secure",
		},
		{
			name: "旧名字排在最后：新名字在就不看它", secure: false,
			cookie: sessionCookieLegacy + "=legacy; " + sessionCookie + "=plain", want: "plain",
		},
		{
			name: "只剩旧名字时仍然认", secure: false,
			cookie: sessionCookieLegacy + "=legacy", want: "legacy",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			ctx, _ := gin.CreateTestContext(w)
			ctx.Request = newSchemeRequest(t, tc.secure, http.MethodGet, "/", "")
			ctx.Request.Header.Set("Cookie", tc.cookie)
			if got := s.extractToken(ctx); got != tc.want {
				t.Fatalf("期望取到 %q，实际 %q", tc.want, got)
			}
		})
	}

	t.Run("无 Cookie 时回退 Bearer", func(t *testing.T) {
		w := httptest.NewRecorder()
		ctx, _ := gin.CreateTestContext(w)
		ctx.Request = newSchemeRequest(t, false, http.MethodGet, "/", "")
		ctx.Request.Header.Set("Authorization", "Bearer from-header")
		if got := s.extractToken(ctx); got != "from-header" {
			t.Fatalf("期望取到 %q，实际 %q", "from-header", got)
		}
	})
}

// 退出登录要清掉全部三个名字：协议切换后浏览器可能同时存着多条，只清相符的那条会让其余的
// 在切回去时复活（服务端会话已删，表现为「刚退出就被 401 弹回登录页」的多余往返）。
func TestClearSessionCookiesClearsAllNames(t *testing.T) {
	s := &Server{}
	for _, secure := range []bool{false, true} {
		w := httptest.NewRecorder()
		ctx, _ := gin.CreateTestContext(w)
		ctx.Request = newSchemeRequest(t, secure, http.MethodPost, "/auth/logout", "")

		s.clearSessionCookies(ctx)

		resp := w.Result()
		for _, name := range []string{sessionCookie, sessionCookieSecure, sessionCookieLegacy} {
			ck := findCookie(resp, name)
			if ck == nil {
				t.Fatalf("secure=%v：未清除 %s，Set-Cookie: %v", secure, name, resp.Header.Values("Set-Cookie"))
			}
			if ck.Value != "" || ck.MaxAge != -1 {
				t.Fatalf("secure=%v：%s 未被作废，Value=%q MaxAge=%d", secure, name, ck.Value, ck.MaxAge)
			}
		}
		// __Host- 前缀的 Cookie 只有带 Secure 才被浏览器接受，删除同样要带上，否则删不掉。
		if ck := findCookie(resp, sessionCookieSecure); ck != nil && !ck.Secure {
			t.Fatalf("secure=%v：清除 %s 时必须保留 Secure 属性", secure, sessionCookieSecure)
		}
	}
}
