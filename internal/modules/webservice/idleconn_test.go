package webservice

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"mantou/internal/config"
	"mantou/internal/logx"
)

// 反代子项各有一个连接池（http.Transport）。监听是按端口重建的，改一次配置这个端口下的
// 全部子项都要重来，旧的连接池连同池子里的空闲连接一起被丢掉——而 Go 不会因为它成了垃圾
// 就关掉那些 socket，它们要等 IdleConnTimeout（90 秒）到期才关。
//
// 下面这条量的是"关掉监听之后，后端那侧看到连接断了没有"。

// countingBackend 起一个能报出当前活跃连接数的后端。h 为 nil 时直接回 200。
func countingBackend(t *testing.T, open *int32, h http.HandlerFunc) *httptest.Server {
	t.Helper()
	if h == nil {
		h = func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }
	}
	srv := httptest.NewUnstartedServer(h)
	srv.Config.ConnState = func(_ net.Conn, s http.ConnState) {
		switch s {
		case http.StateNew:
			atomic.AddInt32(open, 1)
		case http.StateClosed, http.StateHijacked:
			atomic.AddInt32(open, -1)
		}
	}
	srv.Start()
	t.Cleanup(srv.Close)
	return srv
}

// waitFor 等条件成立，最多 2 秒。不用固定 sleep：连接关闭是异步的，
// 而"关"这个动作本身在微秒级，等不到就是真的没关。
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("等了 2 秒，%s 仍未成立", what)
}

// TestCloseReleasesProxyIdleConns 关掉监听要连带关掉反代池子里的空闲连接。
//
// 刻意在同一个端口下放两个反代子项：监听是按端口重建的，一个端口下有几个子项就有几个
// 连接池，全都得关。只放一个子项的话，「只收集最后一个」「只关第一个」这类写法照样能过。
func TestCloseReleasesProxyIdleConns(t *testing.T) {
	var open int32
	a, b := countingBackend(t, &open, nil), countingBackend(t, &open, nil)

	m := New(logx.New(logx.Options{}))
	t.Cleanup(func() { _ = m.Close() })
	g := &wsGroup{family: "v4", port: 18080, bindings: []childBinding{
		{service: "站点/甲", child: config.WebChild{
			ID: "ch1", Enabled: true, Type: "proxy", Domains: []string{"a.example"},
			Upstreams: []config.WebUpstream{{URL: a.URL}},
		}},
		{service: "站点/乙", child: config.WebChild{
			ID: "ch2", Enabled: true, Type: "proxy", Domains: []string{"b.example"},
			Upstreams: []config.WebUpstream{{URL: b.URL}},
		}},
	}}
	ls := newListenServer(g, nil, m, m.log)
	if len(ls.idle) != 2 {
		t.Fatalf("两个反代子项的连接池都应被收集起来，实际 %d 个", len(ls.idle))
	}

	// 各走一次请求，让两个池子里各留下一条到后端的空闲连接。
	for _, host := range []string{"a.example", "b.example"} {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Host = host
		req.RemoteAddr = "203.0.113.9:40000"
		w := httptest.NewRecorder()
		ls.handler().ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("请求 %s 应打到后端，实际 %d", host, w.Code)
		}
	}
	waitFor(t, "两个后端各看到一条连接", func() bool { return atomic.LoadInt32(&open) == 2 })

	ls.close()
	waitFor(t, "监听关闭后两条后端连接都被断开", func() bool { return atomic.LoadInt32(&open) == 0 })
}

// TestNoUpstreamHasNoIdlePool 没有可用后端的反代子项不建连接池，收集端也就没得可关。
func TestNoUpstreamHasNoIdlePool(t *testing.T) {
	m := New(logx.New(logx.Options{}))
	t.Cleanup(func() { _ = m.Close() })
	for _, ch := range []config.WebChild{
		{ID: "ch1", Enabled: true, Type: "proxy"}, // 没填后端
		{ID: "ch2", Enabled: true, Type: "redirect", Redirect: config.WebRedirect{Target: "https://example.com"}},
		{ID: "ch3", Enabled: true, Type: "static", Static: config.WebStatic{Root: t.TempDir()}},
	} {
		g := &wsGroup{family: "v4", port: 18081,
			bindings: []childBinding{{service: "站点", child: ch}},
		}
		if ls := newListenServer(g, nil, m, m.log); len(ls.idle) != 0 {
			t.Fatalf("子项 %s（%s）不该有连接池，实际 %d 个", ch.ID, ch.Type, len(ls.idle))
		}
	}
}

// TestCloseInflightConnAlsoClosed 关监听时还在途的请求：既不能被掐断，做完之后它那条
// 后端连接也不许留下。
//
// CloseIdleConnections 只关"当下空闲"的连接，在途请求用的那条不算——但它同时给
// Transport 记了一笔"往后变空闲的也关"，所以请求做完归还时那条也会被关。这条量的就是
// 这两件事：Shutdown 等它做完（不掐断），以及它最终确实被关掉。
func TestCloseInflightConnAlsoClosed(t *testing.T) {
	var open int32
	entered := make(chan struct{})
	backend := countingBackend(t, &open, func(w http.ResponseWriter, r *http.Request) {
		close(entered) // 只发一条请求，关一次
		time.Sleep(150 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	})

	m := New(logx.New(logx.Options{}))
	t.Cleanup(func() { _ = m.Close() })
	g := &wsGroup{family: "v4", port: 18082, bindings: []childBinding{
		{service: "站点", child: config.WebChild{
			ID: "ch1", Enabled: true, Type: "proxy",
			Upstreams: []config.WebUpstream{{URL: backend.URL}},
		}},
	}}
	ls := newListenServer(g, nil, m, m.log)

	// 手动装配一个只绑回环口的监听：本条要的是"Shutdown 真的等在途请求"，
	// 而 httptest.NewRecorder 那条路径不经过 http.Server；start() 绑的是 0.0.0.0，
	// 测试里换成 127.0.0.1 与随机端口，不占固定端口也不惊动防火墙。
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("绑回环口失败：%v", err)
	}
	ls.srv = &http.Server{Handler: ls.handler()}
	ls.ln = ln
	go func() { _ = ls.srv.Serve(ln) }()

	done := make(chan error, 1)
	go func() {
		resp, err := http.Get("http://" + ln.Addr().String() + "/")
		if err == nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
		}
		done <- err
	}()

	<-entered  // 请求已进到后端，此刻那条后端连接正在用
	ls.close() // Shutdown 会等它做完，之后它才变成空闲
	if err := <-done; err != nil {
		t.Fatalf("在途请求应正常做完（Shutdown 不该掐断它），实际 %v", err)
	}
	waitFor(t, "在途请求做完后那条后端连接也被断开", func() bool { return atomic.LoadInt32(&open) == 0 })
}
