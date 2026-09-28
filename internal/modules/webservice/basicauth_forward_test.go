package webservice

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"mantou/internal/auth"
	"mantou/internal/config"
	"mantou/internal/logx"
)

// 网关的 Basic 认证口令是这一层自己的东西。原先认证通过后请求原样交给下一层，
// 反代于是把 `Authorization: Basic …`（base64 即明文）逐请求转发给后端——后端地址常常是
// http:// 内网地址，"开 Basic 认证必须先开 HTTPS、口令不许明文过网"在那一跳上形同虚设。

// TestWithBasicAuthStripsCredential 认证通过后，下一层拿到的请求里不再带 Authorization，
// 而传进来的那个请求本身不被改动（net/http 约定处理器不改 Request）。
func TestWithBasicAuthStripsCredential(t *testing.T) {
	hash, err := auth.HashPassword("s3cret")
	if err != nil {
		t.Fatal(err)
	}
	var seen string
	var called bool
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		seen = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	})
	h := withBasicAuth(basicModule(t), childWithBasic(true, "admin", hash), next)

	req := authReq("admin", "s3cret")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK || !called {
		t.Fatalf("正确凭证应当放行，实际 %d", w.Code)
	}
	if seen != "" {
		t.Fatalf("网关口令被传给了下一层：%q", seen)
	}
	if req.Header.Get("Authorization") == "" {
		t.Fatal("传进来的请求被就地改动了，应当 Clone 之后再删")
	}
}

// TestProxyDoesNotForwardGatewayCredential 端到端：开了 Basic 认证的反代子项，后端收不到网关口令，
// 其余请求头照常到达。
func TestProxyDoesNotForwardGatewayCredential(t *testing.T) {
	hash, err := auth.HashPassword("s3cret")
	if err != nil {
		t.Fatal(err)
	}
	got := make(chan http.Header, 1)
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got <- r.Header.Clone()
		w.WriteHeader(http.StatusNoContent)
	}))
	defer backend.Close()

	m := New(logx.New(logx.Options{}))
	t.Cleanup(func() { _ = m.Close() })
	ch := config.WebChild{
		ID: "ch-basic-fwd", Enabled: true, Type: "proxy", TLS: true,
		Domains:   []string{"site.example.com"},
		Upstreams: []config.WebUpstream{{URL: backend.URL, Weight: 1}},
	}
	ch.Access.BasicAuth = true
	ch.Access.BasicAuthUser = "admin"
	ch.Access.BasicAuthPass = hash
	h, _ := buildChildHandler(m, "站点", ch)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = "site.example.com"
	req.SetBasicAuth("admin", "s3cret")
	req.Header.Set("X-Custom", "keep-me")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusNoContent {
		t.Fatalf("请求没能到达后端：状态 %d", w.Code)
	}
	var hdr http.Header
	select {
	case hdr = <-got:
	default:
		t.Fatal("后端没收到请求")
	}
	if v := hdr.Get("Authorization"); v != "" {
		t.Fatalf("后端收到了网关的 Basic 口令：%q", v)
	}
	if hdr.Get("X-Custom") != "keep-me" {
		t.Fatalf("其余请求头应照常转发，实际：%v", hdr)
	}
}
