package webservice

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"mantou/internal/config"
	"mantou/internal/logx"
)

// 「未匹配到站点」这一页是全项目错误页的样板（用户就是指着它说"其它页面也照这个来"），
// 所以它的两面都得钉住：拿浏览器撞上来的人看到卡片，反代探针与脚本看到一行纯文本。
//
// 注意这一页只对**局域网**来源发卡片（理由见 writeSiteNotFound 的说明），所以本用例
// 里的请求都来自内网地址；公网那一侧由 TestSiteNotFoundIsBareForPublic 负责。
//
// 页面本体与转义在 internal/errpage 里测；这里只测这条监听接上去之后的表现。
func TestSiteNotFoundPage(t *testing.T) {
	m := New(logx.New(logx.Options{}))
	t.Cleanup(func() { _ = m.Close() })
	g := &wsGroup{family: "ipv4", port: 8080,
		bindings: []childBinding{{service: "官网", child: config.WebChild{
			ID: "ch1", Enabled: true, Type: "redirect", Domains: []string{"www.example.com"},
			Redirect: config.WebRedirect{Target: "https://example.com", Code: 301},
		}}},
	}
	ls := newListenServer(g, nil, m, m.log)

	// 浏览器：卡片页，并把访问用的主机名回显出来供用户核对。
	req := httptest.NewRequest(http.MethodGet, "/anything", nil)
	req.Host = "wrong.example.com"
	req.RemoteAddr = "192.168.1.20:40000"
	req.Header.Set("Accept", "text/html,application/xhtml+xml,*/*;q=0.8")
	w := httptest.NewRecorder()
	ls.handler().ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Fatalf("状态码应为 404，实际 %d", w.Code)
	}
	body := w.Body.String()
	for _, want := range []string{"<!doctype html>", "未匹配到站点", "wrong.example.com", "404"} {
		if !strings.Contains(body, want) {
			t.Errorf("卡片页应含 %q：%s", want, body)
		}
	}

	// 探针 / 脚本：一行纯文本。反代与监控撞上这一页的次数远多于人，
	// 给它们塞一整页 HTML 只会把对方的日志堆满标签。
	plainReq := httptest.NewRequest(http.MethodGet, "/anything", nil)
	plainReq.Host = "wrong.example.com"
	plainReq.RemoteAddr = "192.168.1.20:40000"
	plain := httptest.NewRecorder()
	ls.handler().ServeHTTP(plain, plainReq)
	if ct := plain.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Fatalf("非浏览器应拿到纯文本：%q", ct)
	}
	if got := strings.TrimSpace(plain.Body.String()); !strings.Contains(got, "未匹配到站点") {
		t.Fatalf("纯文本也该说清是什么事：%q", got)
	}
}

// TestSiteNotFoundIsBareForPublic 公网来源拿不到那张卡片。
//
// 这条路径是拿 IP 直连时的默认落点，也就是全网扫描器必定踩到的一页。那张卡片外观独特，
// 见过一次就能靠它把扫描结果里的 mantou 实例全挑出来，接下来的猜路径、试接口都省了侦察。
// 换成标准库那句朴素 404 之后，这台机器混进互联网上数量最庞大的那一类 Go 服务里。
//
// 断言写成"不含任何一处卡片特征"而不是"等于某个字符串"：将来换措辞不该让这条失效，
// 但把品牌痕迹漏回去必须当场失败。
func TestSiteNotFoundIsBareForPublic(t *testing.T) {
	m := New(logx.New(logx.Options{}))
	t.Cleanup(func() { _ = m.Close() })
	g := &wsGroup{family: "ipv4", port: 8080,
		bindings: []childBinding{{service: "官网", child: config.WebChild{
			ID: "ch1", Enabled: true, Type: "redirect", Domains: []string{"www.example.com"},
			Redirect: config.WebRedirect{Target: "https://example.com", Code: 301},
		}}},
	}
	ls := newListenServer(g, nil, m, m.log)

	// 连"像人拿浏览器来的"都不给卡片：扫描器伪装 Accept 头是零成本的。
	for _, accept := range []string{"", "text/html,application/xhtml+xml,*/*;q=0.8"} {
		req := httptest.NewRequest(http.MethodGet, "/wp-login.php", nil)
		req.Host = "" // 拿 IP 直连的典型形态
		req.RemoteAddr = "203.0.113.9:40000"
		if accept != "" {
			req.Header.Set("Accept", accept)
		}
		w := httptest.NewRecorder()
		ls.handler().ServeHTTP(w, req)

		if w.Code != http.StatusNotFound {
			t.Fatalf("Accept=%q：状态码应为 404，实际 %d", accept, w.Code)
		}
		body := w.Body.String()
		for _, leak := range []string{"<!doctype html", "未匹配到站点", "<svg", "#4f6bed", "站点配置"} {
			if strings.Contains(strings.ToLower(body), strings.ToLower(leak)) {
				t.Errorf("Accept=%q：公网响应里出现了卡片特征 %q：%s", accept, leak, body)
			}
		}
		if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
			t.Errorf("Accept=%q：公网响应应是纯文本，实际 %q", accept, ct)
		}
		// 标准库的朴素 404 一直带着这道头，换实现时别把它丢了。
		if w.Header().Get("X-Content-Type-Options") != "nosniff" {
			t.Errorf("Accept=%q：缺少 X-Content-Type-Options: nosniff", accept)
		}
	}
}

// TestSiteNotFoundBareBehindProxy 挂在反代后面时，"局域网"这条判据不能单独说话。
//
// mantou 挂在同机 nginx / cloudflared 后面是常见部署，那时对端永远是 127.0.0.1——
// 只看 IP 的话这道遮蔽恰好在最需要它的形态上完全失效，公网扫描器照样拿到那张卡片。
// 所以带任何代理转发头的请求一律按公网处理。
func TestSiteNotFoundBareBehindProxy(t *testing.T) {
	m := New(logx.New(logx.Options{}))
	t.Cleanup(func() { _ = m.Close() })
	ls := newListenServer(&wsGroup{family: "ipv4", port: 8080}, nil, m, m.log)

	for _, hdr := range []string{"X-Forwarded-For", "X-Real-IP", "Forwarded", "CF-Connecting-IP"} {
		req := httptest.NewRequest(http.MethodGet, "/wp-login.php", nil)
		req.Host = "wrong.example.com"
		req.RemoteAddr = "127.0.0.1:40000" // 同机反代转进来的样子
		req.Header.Set("Accept", "text/html")
		req.Header.Set(hdr, "203.0.113.9")
		w := httptest.NewRecorder()
		ls.handler().ServeHTTP(w, req)

		body := w.Body.String()
		if strings.Contains(body, "未匹配到站点") || strings.Contains(strings.ToLower(body), "<!doctype html") {
			t.Errorf("带 %s 的请求仍拿到了卡片：%s", hdr, body)
		}
	}

	// 反过来钉一次：同一个来源不带任何代理头时，卡片照发。
	// 否则上面那几条只要把整页换成朴素 404 就能"通过"，等于什么都没测。
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.Host = "wrong.example.com"
	req.RemoteAddr = "127.0.0.1:40000"
	req.Header.Set("Accept", "text/html")
	w := httptest.NewRecorder()
	ls.handler().ServeHTTP(w, req)
	if !strings.Contains(w.Body.String(), "未匹配到站点") {
		t.Fatalf("本机直连应看到卡片：%s", w.Body.String())
	}
}
