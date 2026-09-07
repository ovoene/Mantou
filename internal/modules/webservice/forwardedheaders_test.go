package webservice

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"mantou/internal/config"
	"mantou/internal/logx"
)

// 本文件盯住反代交给后端的那几个「你是谁」头（审计 L-03）。
//
// 这一栏的可信度是后端 IP 名单、限流与审计的全部依据，而它完全由本模块写出来。
// 两类事故都不会在日常使用里暴露：链条里多一段（后端把代理自己当成一跳）、
// 或者访客有办法让某个头根本到不了后端（后端于是退回"没有这个头"的分支）。
//
// httptest.NewRequest 的对端固定是 192.0.2.1:1234，下面各处的 clientIP 都指它。
const fwdClientIP = "192.0.2.1"

// forwardedTo 造一条反代子项、送一个请求进去，返回**后端实际收到**的请求头。
// mutate 用来模拟访客自己塞进来的头。
func forwardedTo(t *testing.T, trustProxy bool, mutate func(*http.Request)) http.Header {
	t.Helper()
	got := make(chan http.Header, 1)
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got <- r.Header.Clone()
		w.WriteHeader(http.StatusNoContent)
	}))
	defer backend.Close()

	m := New(logx.New(logx.Options{}))
	t.Cleanup(func() { _ = m.Close() })
	ch := config.WebChild{
		ID: "ch-fwd", Enabled: true, Type: "proxy",
		Domains:           []string{"site.example.com"},
		Upstreams:         []config.WebUpstream{{URL: backend.URL, Weight: 1}},
		TrustProxyHeaders: trustProxy,
		// 用户自己配的头也一起测：它可能是后端用来认"这是从面板过来的"的凭证。
		Headers: map[string]string{"X-Api-Key": "set-by-panel"},
	}
	h, _ := buildChildHandler(m, "站点", ch)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = "site.example.com"
	if mutate != nil {
		mutate(req)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusNoContent {
		t.Fatalf("请求没能到达后端：状态 %d", w.Code)
	}
	select {
	case hdr := <-got:
		return hdr
	default:
		t.Fatal("后端没收到请求")
		return nil
	}
}

// TestProxyForwardedForChain X-Forwarded-For 的链条必须**恰好**是该有的那几段。
//
// 多一段少一段都不是"格式问题"：后端普遍按「最左即原始客户端、其余为途经代理」读，
// 链条长度还常被用来判断"经过了几层"。同一个 IP 出现两次会让后端把代理自己
// 当成一跳，而这正是 ReverseProxy 的 Director 钩子会造成的事（见 handler.go 里
// Rewrite 处的说明）。
func TestProxyForwardedForChain(t *testing.T) {
	cases := []struct {
		name  string
		trust bool
		given string // 访客自己送来的 XFF；空串表示不送
		want  string
	}{
		{"默认不采信：只有真实来源", false, "", fwdClientIP},
		{"默认不采信：访客自称的整段丢掉", false, "203.0.113.7", fwdClientIP},
		{"信任上游：原链条后面接上对端", true, "203.0.113.7", "203.0.113.7, " + fwdClientIP},
		{"信任上游但没送：只有对端", true, "", fwdClientIP},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			hdr := forwardedTo(t, c.trust, func(r *http.Request) {
				if c.given != "" {
					r.Header.Set("X-Forwarded-For", c.given)
				}
			})
			if v := hdr["X-Forwarded-For"]; len(v) != 1 {
				t.Fatalf("X-Forwarded-For 应是一条（折叠后的）头，实际 %q", v)
			}
			if got := hdr.Get("X-Forwarded-For"); got != c.want {
				t.Fatalf("X-Forwarded-For = %q，应为 %q", got, c.want)
			}
		})
	}
}

// TestProxyForwardedHostProto 访客访问的域名与协议照实转给后端。
func TestProxyForwardedHostProto(t *testing.T) {
	hdr := forwardedTo(t, false, nil)
	if got := hdr.Get("X-Forwarded-Host"); got != "site.example.com" {
		t.Errorf("X-Forwarded-Host = %q，应为访客访问的域名", got)
	}
	if got := hdr.Get("X-Forwarded-Proto"); got != "http" {
		t.Errorf("X-Forwarded-Proto = %q，应为 http", got)
	}
	if got := hdr.Get("X-Real-IP"); got != fwdClientIP {
		t.Errorf("X-Real-IP = %q，应为真实来源", got)
	}
}

// TestProxyInjectedHeadersSurviveConnectionToken 访客不得决定"哪些注入的头能到后端"。
//
// 攻击形状：把想删掉的头名字列进 Connection——按 HTTP 规范那是"逐跳头"的声明，
// 代理理应删掉它们。问题在于删的时机：ReverseProxy 的 Director 钩子跑在删除**之前**，
// 于是访客点名什么，我们刚注入的就掉什么（标准库自己把 Director 标成
// "This function is insecure"）。X-Real-IP 掉了，后端退回"拿不到来源"的分支；
// 用户配在 Headers 里的凭证头掉了，后端那边就是一个没带凭证的请求。
func TestProxyInjectedHeadersSurviveConnectionToken(t *testing.T) {
	hdr := forwardedTo(t, false, func(r *http.Request) {
		r.Header.Set("Connection", "X-Real-IP, X-Api-Key, X-Forwarded-For")
		r.Header.Set("X-Real-IP", "203.0.113.7")
		r.Header.Set("X-Api-Key", "forged")
	})
	if got := hdr.Get("X-Real-IP"); got != fwdClientIP {
		t.Errorf("X-Real-IP = %q，访客点名也不该抹掉它", got)
	}
	if got := hdr.Get("X-Api-Key"); got != "set-by-panel" {
		t.Errorf("X-Api-Key = %q，应是面板注入的那个值", got)
	}
	if got := hdr.Get("X-Forwarded-For"); got != fwdClientIP {
		t.Errorf("X-Forwarded-For = %q，应为真实来源", got)
	}
	// Connection 本身是逐跳头，不该转给后端。
	if got := hdr.Get("Connection"); got != "" {
		t.Errorf("Connection = %q，应当被摘掉", got)
	}
}
