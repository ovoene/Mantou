package webservice

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"mantou/internal/config"
	"mantou/internal/logx"
)

// 本文件钉住两道安全响应头（见 withSecurityHeaders）：
//
//   - X-Content-Type-Options: nosniff —— 无条件发，没有开关。它挡的是"静态站点根目录里
//     放着用户上传的东西，浏览器嗅探把它当 HTML 执行"这条从上传到同域 XSS 的路。
//   - X-Frame-Options / CSP frame-ancestors —— 显式开启（WebChild.FrameDeny）才发。
//     不能默认开：反代后面挂着的系统被自家门户 iframe 嵌进去是常见部署，
//     默认开等于升级之后那些页面全变空白，而用户看不出是谁干的。
//
// 这两件事最容易坏在"某条早退的分支上忘了带头"，所以下面按分支逐条过：正常放行、
// HTTPS 跳转、IP 被拒、限流、以及真实静态文件那条（压缩与统一错误页两层都在上面）。

// headerProbe 用 applyMiddleware 组一条完整的子项中间件链，返回指定请求打上去的结果。
// 直接测 withSecurityHeaders 只能证明那一个函数对，证不了它在链条里的位置对——
// 而 P2-1 真正的风险恰恰是"被别的中间件抢先早退了"。
func headerProbe(t *testing.T, ch config.WebChild, prep func(*http.Request)) *httptest.ResponseRecorder {
	t.Helper()
	m := New(logx.New(logx.Options{}))
	t.Cleanup(func() { _ = m.Close() })
	h := applyMiddleware(m, "站点", ch, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	req := httptest.NewRequest(http.MethodGet, "http://site.example.com/x", nil)
	if prep != nil {
		prep(req)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// TestNoSniffOnEveryBranch 每条出口都带 nosniff，包括中途早退的那几条。
//
// 早退的三条（HTTPS 跳转、IP 被拒、限流）里有两条根本走不到 withSecurityHeaders——
// IP 过滤与限流包在它外面。它们的页面由 errpage.Write 出，那里自己带着这道头。
// 把这三条一起钉住，是为了将来谁调整中间件顺序或改 errpage 时，缺口会当场暴露，
// 而不是变成"某些错误页可以被嗅探"这种没人会注意到的洞。
func TestNoSniffOnEveryBranch(t *testing.T) {
	for _, tc := range []struct {
		name     string
		ch       config.WebChild
		prep     func(*http.Request)
		wantCode int
	}{
		{
			name:     "正常放行",
			ch:       config.WebChild{ID: "ch"},
			wantCode: http.StatusOK,
		},
		{
			name:     "HTTPS 跳转",
			ch:       config.WebChild{ID: "ch", RedirectHTTPS: true},
			wantCode: http.StatusTemporaryRedirect,
		},
		{
			name: "IP 被拒",
			ch: config.WebChild{ID: "ch", Access: config.WebAccess{
				IPFilter: true, IPFilterMode: "deny", DenyIPs: []string{"192.0.2.0/24"},
			}},
			prep:     func(r *http.Request) { r.RemoteAddr = "192.0.2.7:40000" },
			wantCode: http.StatusForbidden,
		},
		{
			name:     "限流",
			ch:       config.WebChild{ID: "ch", Access: config.WebAccess{RateLimit: 1}},
			wantCode: http.StatusTooManyRequests,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// 限流那一页要先把额度用掉才看得到：令牌桶起手是满的，第一发必然放行。
			rec := headerProbe(t, tc.ch, tc.prep)
			if tc.wantCode == http.StatusTooManyRequests {
				rec = drainedRateLimit(t, tc.ch)
			}
			if rec.Code != tc.wantCode {
				t.Fatalf("状态码应为 %d，实际 %d", tc.wantCode, rec.Code)
			}
			if got := rec.Header().Get("X-Content-Type-Options"); got != "nosniff" {
				t.Errorf("X-Content-Type-Options 应为 nosniff，实际 %q", got)
			}
		})
	}
}

// drainedRateLimit 把每秒 1 次的额度用光，返回第二发（被限流）的响应。
func drainedRateLimit(t *testing.T, ch config.WebChild) *httptest.ResponseRecorder {
	t.Helper()
	m := New(logx.New(logx.Options{}))
	t.Cleanup(func() { _ = m.Close() })
	h := applyMiddleware(m, "站点", ch, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	var rec *httptest.ResponseRecorder
	for i := 0; i < 40; i++ {
		req := httptest.NewRequest(http.MethodGet, "http://site.example.com/x", nil)
		rec = httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code == http.StatusTooManyRequests {
			return rec
		}
	}
	t.Fatalf("连发 40 次都没触发限流，最后一次 %d", rec.Code)
	return rec
}

// TestNoSniffReachesRealStaticFile 真实静态文件那条路上这道头也在。
//
// 这条单独测：静态响应外面还套着压缩（httpx.WithGzip）与统一错误页拦截
// （errpage.Intercept）两层 ResponseWriter 包装，而它们都有权改写响应头。
// 只测中间件那一层的话，包装层把头吃掉了这里也看不见。
func TestNoSniffReachesRealStaticFile(t *testing.T) {
	root := siteTree(t)
	m := New(logx.New(logx.Options{}))
	t.Cleanup(func() { _ = m.Close() })
	ch := config.WebChild{ID: "ch-static", Enabled: true, Type: "static",
		Static: config.WebStatic{Root: root, Index: "index.html"}}
	h, _ := buildChildHandler(m, "站点", ch)

	// 顺手把压缩那条也走一遍：gzip 包装层是另一个可能吃掉响应头的地方。
	for _, enc := range []string{"", "gzip"} {
		req := httptest.NewRequest(http.MethodGet, "http://site.example.com/hello.txt", nil)
		if enc != "" {
			req.Header.Set("Accept-Encoding", enc)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("Accept-Encoding=%q：状态码应为 200，实际 %d", enc, rec.Code)
		}
		if got := rec.Header().Get("X-Content-Type-Options"); got != "nosniff" {
			t.Errorf("Accept-Encoding=%q：静态文件响应缺少 nosniff，实际 %q", enc, got)
		}
	}
}

// TestFrameDenyOptIn 点击劫持防护默认关、开了才发，且两个头一起发。
//
// 两个都要：CSP 的 frame-ancestors 是现行标准、优先级高于 X-Frame-Options，
// 而 XFO 是给还不认 frame-ancestors 的老浏览器兜底的。只发一个等于挑一半用户保护。
func TestFrameDenyOptIn(t *testing.T) {
	// 默认关：升级之后别人的 iframe 嵌入不该突然失效。
	off := headerProbe(t, config.WebChild{ID: "ch"}, nil)
	if got := off.Header().Get("X-Frame-Options"); got != "" {
		t.Errorf("未开启时不该发 X-Frame-Options，实际 %q", got)
	}
	if got := off.Header().Get("Content-Security-Policy"); got != "" {
		t.Errorf("未开启时不该发 CSP，实际 %q", got)
	}

	on := headerProbe(t, config.WebChild{ID: "ch", FrameDeny: true}, nil)
	// SAMEORIGIN 而不是 DENY：同站点自己的页面互相 iframe（后台里嵌一个预览窗）
	// 是正常用法，DENY 会把它一起掐掉，而它挡不住的东西 SAMEORIGIN 一样挡得住。
	if got := on.Header().Get("X-Frame-Options"); got != "SAMEORIGIN" {
		t.Errorf("X-Frame-Options 应为 SAMEORIGIN，实际 %q", got)
	}
	if got := on.Header().Get("Content-Security-Policy"); got != "frame-ancestors 'self'" {
		t.Errorf("CSP 应为 frame-ancestors 'self'，实际 %q", got)
	}
	// 只管框嵌：CSP 里不该顺手带上 default-src 之类，那会把托管站点自己的
	// 内联脚本与外部资源一起拦掉——一个"防点击劫持"的开关不该有这种副作用。
	if csp := on.Header().Get("Content-Security-Policy"); strings.Contains(csp, "default-src") ||
		strings.Contains(csp, "script-src") {
		t.Errorf("CSP 只该限定 frame-ancestors，实际 %q", csp)
	}
}

// TestFrameDenyOnRedirectBranch HTTPS 跳转那条早退路径上这两个头也在。
//
// 跳转是在设完头之后才发的，顺序反了的话，明文请求收到的 307 上什么都没有——
// 而攻击者完全可以只让受害者访问明文那一版。
func TestFrameDenyOnRedirectBranch(t *testing.T) {
	rec := headerProbe(t, config.WebChild{ID: "ch", FrameDeny: true, RedirectHTTPS: true}, nil)
	if rec.Code != http.StatusTemporaryRedirect {
		t.Fatalf("状态码应为 307，实际 %d", rec.Code)
	}
	for k, want := range map[string]string{
		"X-Content-Type-Options":  "nosniff",
		"X-Frame-Options":         "SAMEORIGIN",
		"Content-Security-Policy": "frame-ancestors 'self'",
	} {
		if got := rec.Header().Get(k); got != want {
			t.Errorf("跳转响应上 %s 应为 %q，实际 %q", k, want, got)
		}
	}
}
