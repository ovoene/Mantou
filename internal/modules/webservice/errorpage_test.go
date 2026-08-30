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
// 页面本体与转义在 internal/errpage 里测；这里只测这条监听接上去之后的表现。
func TestSiteNotFoundPage(t *testing.T) {
	m := New(logx.New(logx.Options{}))
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
	plain := serveHost(ls, "wrong.example.com")
	if ct := plain.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Fatalf("非浏览器应拿到纯文本：%q", ct)
	}
	if got := strings.TrimSpace(plain.Body.String()); !strings.Contains(got, "未匹配到站点") {
		t.Fatalf("纯文本也该说清是什么事：%q", got)
	}
}
