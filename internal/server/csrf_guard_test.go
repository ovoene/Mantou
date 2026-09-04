package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

// 这一组盯的是 csrfGuard（见 middleware.go）。
//
// 收紧前它只有一条判断：带了 Origin 且不同源就拒，其余全放。于是"两个头都不带"这一格
// 是敞开的——跨站表单在部分旧浏览器上不发 Origin，而 Cookie 照常带上，整道防线绕过。
// 下面每条用例都直打真实路由（New() 建的 engine），不手拼中间件链，否则测的就不是线上那条路。
//
// 被打的接口取 POST /api/settings/firewall/bans/clear：需要鉴权、可空体、幂等，
// 且封禁表本来是空的，重复调用不会互相干扰。

// csrfProbe 用给定的头 + 会话发一次状态变更请求，返回状态码与响应体。
func csrfProbe(t *testing.T, engine *gin.Engine, cookie *http.Cookie, bearer string, headers map[string]string) (int, string) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/settings/firewall/bans/clear", strings.NewReader("{}"))
	req.Header.Set("Content-Type", "application/json")
	if cookie != nil {
		req.AddCookie(cookie)
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	engine.ServeHTTP(rec, req)
	return rec.Code, rec.Body.String()
}

// blockedAsCrossSite 判断这次响应是不是被 csrfGuard 拦下的。
// 光看 403 不够：别的中间件也会回 403，认准那句文案才说明是这一道拦的。
func blockedAsCrossSite(code int, body string) bool {
	return code == http.StatusForbidden && strings.Contains(body, "请求来源不被允许")
}

func TestCSRFGuardTrustsSecFetchSite(t *testing.T) {
	_, engine := versionAuthEngine(t, "")
	ck := loginCookie(t, engine, "")

	cases := []struct {
		site    string
		blocked bool
		why     string
	}{
		{site: "same-origin", blocked: false, why: "面板前端自己的 fetch 就是这个值"},
		{site: "none", blocked: false, why: "用户直接发起的导航（地址栏 / 书签）"},
		{site: "same-site", blocked: true, why: "同站不等于同源：旁边一个子域被拿下就能打过来"},
		{site: "cross-site", blocked: true, why: "跨站，正是要拦的那一类"},
	}
	for _, tc := range cases {
		t.Run(tc.site, func(t *testing.T) {
			code, body := csrfProbe(t, engine, ck, "", map[string]string{"Sec-Fetch-Site": tc.site})
			if got := blockedAsCrossSite(code, body); got != tc.blocked {
				t.Fatalf("Sec-Fetch-Site=%s 期望拦截=%v，实际拦截=%v（%d %s）；%s",
					tc.site, tc.blocked, got, code, clipBody(body), tc.why)
			}
		})
	}
}

// Sec-Fetch-Site 的优先级必须高于 Origin：前者浏览器自己填、页面脚本改不了，
// 后者在非浏览器客户端手里可以随便写。所以"Origin 看着同源、Sec-Fetch-Site 说跨站"
// 这种组合要按跨站处理，而不是被 Origin 放过去。
func TestCSRFGuardPrefersSecFetchSiteOverOrigin(t *testing.T) {
	_, engine := versionAuthEngine(t, "")
	ck := loginCookie(t, engine, "")

	code, body := csrfProbe(t, engine, ck, "", map[string]string{
		"Sec-Fetch-Site": "cross-site",
		"Origin":         "http://example.com", // httptest.NewRequest 的默认 Host
	})
	if !blockedAsCrossSite(code, body) {
		t.Fatalf("Sec-Fetch-Site=cross-site 被一个同源 Origin 盖过去了：%d %s", code, clipBody(body))
	}
}

// 没有 Sec-Fetch-Site 的旧浏览器退回 Origin 比对，与收紧前的行为一致。
func TestCSRFGuardFallsBackToOrigin(t *testing.T) {
	_, engine := versionAuthEngine(t, "")
	ck := loginCookie(t, engine, "")

	if code, body := csrfProbe(t, engine, ck, "", map[string]string{"Origin": "http://example.com"}); blockedAsCrossSite(code, body) {
		t.Fatalf("同源 Origin 被拦了：%d %s", code, clipBody(body))
	}
	if code, body := csrfProbe(t, engine, ck, "", map[string]string{"Origin": "https://evil.example"}); !blockedAsCrossSite(code, body) {
		t.Fatalf("跨源 Origin 没被拦：%d %s", code, clipBody(body))
	}
}

// 这条是本次收紧的正主：两个头都不带、但带着会话 Cookie，必须拒。
// 收紧前这里返回 200——也就是说只要客户端不发 Origin，CSRF 校验等于不存在。
func TestCSRFGuardRejectsHeaderlessCookieRequest(t *testing.T) {
	_, engine := versionAuthEngine(t, "")
	ck := loginCookie(t, engine, "")

	code, body := csrfProbe(t, engine, ck, "", nil)
	if !blockedAsCrossSite(code, body) {
		t.Fatalf("带 Cookie 却不带任何来源头的状态变更请求应当被拒，实际 %d %s", code, clipBody(body))
	}
}

// 收紧不能把 API 的脚本可用性一起关掉，这条钉住那两条出路。
//
// 之所以只对"带 Cookie"的请求收紧：CSRF 的载体只有 Cookie（浏览器自动附加）。
// Authorization 是自定义头，跨站发它会先触发 CORS 预检，而本服务不放行任何跨源预检，
// 所以 Bearer 请求在 CSRF 意义上根本构造不出来，不需要来源头。
func TestCSRFGuardKeepsScriptAccessWorking(t *testing.T) {
	_, engine := versionAuthEngine(t, "")
	ck := loginCookie(t, engine, "")

	t.Run("登录本身不带任何头也能通过", func(t *testing.T) {
		// loginCookie 走的就是这条：POST /api/auth/login，无 Origin、无 Cookie。
		// 它在上面已经成功过一次；这里再显式声明一遍这个前提，避免将来有人
		// 把"缺来源头就拒"扩大到不带 Cookie 的请求上，把登录接口一起锁死。
		if ck == nil {
			t.Fatal("登录没拿到会话——缺来源头的登录请求被拦了")
		}
	})

	t.Run("Bearer 令牌无需来源头", func(t *testing.T) {
		code, body := csrfProbe(t, engine, nil, ck.Value, nil)
		if blockedAsCrossSite(code, body) {
			t.Fatalf("Bearer 鉴权的脚本请求被 CSRF 拦了：%d %s", code, clipBody(body))
		}
		if code != http.StatusOK {
			t.Fatalf("Bearer 鉴权应当正常通过，实际 %d %s", code, clipBody(body))
		}
	})

	t.Run("既无 Cookie 也无 Bearer 时交给鉴权层拒绝", func(t *testing.T) {
		// 未鉴权的请求应当是 401（未登录），不是 403（来源不允许）：
		// csrfGuard 不该替鉴权层回答"你是谁"这个问题，否则匿名探测者能从
		// 403/401 的差异里读出接口是否存在。
		code, body := csrfProbe(t, engine, nil, "", nil)
		if code != http.StatusUnauthorized {
			t.Fatalf("匿名状态变更请求应当 401，实际 %d %s", code, clipBody(body))
		}
	})
}

// 安全方法不受影响：GET/HEAD/OPTIONS 不改状态，拦它们只会把跨站取图、预检之类的
// 正常场景一起打掉。
func TestCSRFGuardIgnoresSafeMethods(t *testing.T) {
	_, engine := versionAuthEngine(t, "")
	ck := loginCookie(t, engine, "")

	for _, method := range []string{http.MethodGet, http.MethodHead, http.MethodOptions} {
		req := httptest.NewRequest(method, "/api/settings/firewall/bans", nil)
		req.AddCookie(ck)
		req.Header.Set("Origin", "https://evil.example")
		req.Header.Set("Sec-Fetch-Site", "cross-site")
		rec := httptest.NewRecorder()
		engine.ServeHTTP(rec, req)
		if blockedAsCrossSite(rec.Code, rec.Body.String()) {
			t.Errorf("%s 被 CSRF 拦了：安全方法不该进这道闸", method)
		}
	}
}
