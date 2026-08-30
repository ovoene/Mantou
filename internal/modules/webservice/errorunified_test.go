package webservice

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"mantou/internal/config"
	"mantou/internal/logx"
)

// 本文件盯的是「站点内部出错时也走统一卡片页」这一条，两路各一组：
// 静态站点（错误由标准库的文件服务器写出）与反向代理（错误由上游后端写出）。
//
// 每一路都同时钉两个方向，后一个更要紧：
//   - 人拿浏览器撞上不存在的路径，看到卡片；
//   - 正常访问一个字节不变，接口调用拿到的还是原来那段响应。
//
// 判定本身（哪些响应会被改写）在 internal/errpage 里测，这里只测「装上去了、且没装错位置」。

// staticSite 起一个静态站点子项，返回它的处理器与站点根目录。
// 根目录里放一个 hello.txt，用来验证正常访问未受影响。
func staticSite(t *testing.T, gzip bool) (http.Handler, string) {
	t.Helper()
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "hello.txt"), []byte("hello, 馒头"), 0o600); err != nil {
		t.Fatal(err)
	}
	m := New(logx.New(logx.Options{}))
	ch := config.WebChild{
		ID: "ch-static", Enabled: true, Type: "static",
		Domains: []string{"site.example.com"},
		Static:  config.WebStatic{Root: root, Gzip: gzip},
	}
	h, _ := buildChildHandler(m, "站点", ch)
	return h, root
}

// browserReq 一个浏览器导航请求。
func browserReq(path string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, path, nil)
	r.Host = "site.example.com"
	r.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	return r
}

// 静态站点上访问不存在的路径：卡片页，而不是标准库那句 "404 page not found"。
func TestStaticMissingPathServesCardPage(t *testing.T) {
	h, _ := staticSite(t, false)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, browserReq("/a"))

	if w.Code != http.StatusNotFound {
		t.Fatalf("状态码应为 404，实际 %d", w.Code)
	}
	body := w.Body.String()
	for _, want := range []string{"<!doctype html>", "404", "页面不存在", "site.example.com/a"} {
		if !strings.Contains(body, want) {
			t.Errorf("卡片页应含 %q", want)
		}
	}
	if strings.Contains(body, "404 page not found") {
		t.Error("标准库那句纯文本仍留在响应体里")
	}
	// 页面上不许出现站点根目录——那是本程序的内部信息。
	if strings.Contains(body, os.TempDir()) || strings.Contains(body, "TempDir") {
		t.Error("页面上出现了服务端目录路径")
	}
}

// 开了压缩也一样：拦截器必须装在压缩之内，否则扣下的响应体是压过的。
func TestStaticMissingPathServesCardPageWithGzip(t *testing.T) {
	h, _ := staticSite(t, true)
	req := browserReq("/a")
	req.Header.Set("Accept-Encoding", "gzip")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("状态码应为 404，实际 %d", w.Code)
	}
	// 错误页不压缩（只压 200，见 httpx.PrepareGzipResponse），所以能直接读。
	if enc := w.Header().Get("Content-Encoding"); enc != "" {
		t.Fatalf("错误页不该被压缩，实际 %q", enc)
	}
	if !strings.Contains(w.Body.String(), "页面不存在") {
		t.Fatalf("应为卡片页：%q", w.Body.String())
	}
}

// 正常访问一个字节都不能变。
func TestStaticNormalAccessUnaffected(t *testing.T) {
	for _, gz := range []bool{false, true} {
		t.Run(fmt.Sprintf("gzip=%v", gz), func(t *testing.T) {
			h, _ := staticSite(t, gz)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, browserReq("/hello.txt"))
			if w.Code != http.StatusOK {
				t.Fatalf("状态码应为 200，实际 %d", w.Code)
			}
			if got := w.Body.String(); got != "hello, 馒头" {
				t.Fatalf("正文被改动：%q", got)
			}
		})
	}
}

// 探针 / 脚本撞上 404 时，拿到的还是原来那段纯文本。
func TestStaticMissingPathKeepsPlainForNonBrowser(t *testing.T) {
	h, _ := staticSite(t, false)
	req := httptest.NewRequest(http.MethodGet, "/a", nil)
	req.Host = "site.example.com"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Fatalf("状态码应为 404，实际 %d", w.Code)
	}
	if got := strings.TrimSpace(w.Body.String()); got != "404 page not found" {
		t.Fatalf("非浏览器的响应体应原样放行，实际 %q", got)
	}
}

// SPA 回退时索引文件缺失也走卡片页：原先是标准库那句纯文本。
func TestStaticSPAFallbackMissingIndexServesCardPage(t *testing.T) {
	m := New(logx.New(logx.Options{}))
	ch := config.WebChild{
		ID: "ch-spa", Enabled: true, Type: "static",
		Domains: []string{"site.example.com"},
		Static:  config.WebStatic{Root: t.TempDir(), SPAFallback: true},
	}
	h, _ := buildChildHandler(m, "站点", ch)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, browserReq("/any/route"))
	if w.Code != http.StatusNotFound {
		t.Fatalf("状态码应为 404，实际 %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "页面不存在") {
		t.Fatalf("应为卡片页：%q", w.Body.String())
	}
}

// ---- 反向代理那一路 ----

// proxySite 起一个反代子项，后端由 handler 扮演。
func proxySite(t *testing.T, backend http.Handler) http.Handler {
	t.Helper()
	srv := httptest.NewServer(backend)
	t.Cleanup(srv.Close)
	m := New(logx.New(logx.Options{}))
	ch := config.WebChild{
		ID: "ch-proxy", Enabled: true, Type: "proxy",
		Domains:   []string{"site.example.com"},
		Upstreams: []config.WebUpstream{{URL: srv.URL, Weight: 1}},
	}
	h, _ := buildChildHandler(m, "站点", ch)
	return h
}

// 后端吐一句朴素 404（Go 程序的默认行为）：浏览器看到卡片页。
func TestProxyUpstreamPlainErrorServesCardPage(t *testing.T) {
	h := proxySite(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, browserReq("/a"))

	if w.Code != http.StatusNotFound {
		t.Fatalf("状态码应为 404，实际 %d", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, "页面不存在") {
		t.Fatalf("应为卡片页：%q", body)
	}
	if strings.Contains(body, "404 page not found") {
		t.Error("后端那句纯文本仍留在响应体里")
	}
	// 后端地址一个字都不许出现在页面上：ModifyResponse 拿到的是出站请求，
	// 它的 Host 就是后端的地址。
	if strings.Contains(body, "127.0.0.1") || strings.Contains(body, "[::1]") {
		t.Error("页面上回显了后端地址")
	}
}

// 后端自己写了错误页就用它的；正常响应与接口调用一律不动。
func TestProxyUpstreamOtherResponsesUnaffected(t *testing.T) {
	const own = "<html><body>后端自己的 404</body></html>"
	h := proxySite(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/own404":
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(own))
		case "/api":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"error":"not found"}`))
		default:
			_, _ = w.Write([]byte("正常内容"))
		}
	}))

	for _, tc := range []struct {
		name, path, want string
		code             int
	}{
		{"后端自带错误页", "/own404", own, http.StatusNotFound},
		{"接口的 JSON 错误", "/api", `{"error":"not found"}`, http.StatusNotFound},
		{"正常访问", "/", "正常内容", http.StatusOK},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			h.ServeHTTP(w, browserReq(tc.path))
			if w.Code != tc.code {
				t.Fatalf("状态码应为 %d，实际 %d", tc.code, w.Code)
			}
			if got := w.Body.String(); got != tc.want {
				t.Fatalf("响应体应原样放行，实际 %q", got)
			}
		})
	}
}

// 改写不能影响访问日志里的状态码：面板上的「错误」事件是按它统计的。
func TestRewrittenErrorStillCountedAsError(t *testing.T) {
	m := New(logx.New(logx.Options{}))
	root := t.TempDir()
	ch := config.WebChild{
		ID: "ch-log", Enabled: true, Type: "static",
		Domains: []string{"site.example.com"},
		Static:  config.WebStatic{Root: root},
		Proxy:   config.WebProxyOptions{AccessLog: true},
	}
	h, _ := buildChildHandler(m, "站点", ch)
	h.ServeHTTP(httptest.NewRecorder(), browserReq("/missing"))

	var found bool
	for _, e := range m.ChildLogs(ch.ID, 50) {
		if e.Event == eventError && e.Status == http.StatusNotFound {
			found = true
		}
	}
	if !found {
		t.Fatal("改写之后访问日志里没了 404 的「错误」事件——面板上的错误统计会漏")
	}
}
