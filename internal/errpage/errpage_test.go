package errpage

import (
	"bufio"
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// 这一页天生要回显请求里的东西（主机、路径），而 Host 头是外部可控的。
// 从前那份手拼 HTML 的实现（webservice.writeSiteNotFound）就是 fmt.Sprintf + Write，
// 全靠 net/http 自己的 Host 校验兜着（见 internal/stress/hostheader_test.go）。
// 这条断言是这个包存在的理由之一，不能少。
func TestRenderEscapesUntrustedText(t *testing.T) {
	html := string(Render(Page{
		Status: 404,
		Title:  "页面不存在",
		Where:  `<script>alert(1)</script>`,
		Detail: `a" onmouseover="alert(1)`,
	}))
	for _, bad := range []string{"<script>", `onmouseover="`} {
		if strings.Contains(html, bad) {
			t.Fatalf("外来内容必须转义，页面里出现了 %q", bad)
		}
	}
	if !strings.Contains(html, "&lt;script&gt;") {
		t.Fatal("转义后的内容应仍然显示出来，供用户核对自己访问的地址")
	}
}

func TestRenderShowsCodeAndText(t *testing.T) {
	html := string(Render(Page{Status: 502, Title: "后端不可用", Detail: "连不上", Hint: "去改配置"}))
	for _, want := range []string{"502", "后端不可用", "连不上", "去改配置"} {
		if !strings.Contains(html, want) {
			t.Errorf("页面里应含 %q", want)
		}
	}
	// 空字段不该留下空标签：一个空的提示框看着像页面渲染坏了。
	if strings.Contains(string(Render(Page{Status: 404, Title: "x"})), `class="hint"`) {
		t.Error("没有提示时不该输出提示框")
	}
}

func TestWriteNegotiatesByAccept(t *testing.T) {
	p := Page{Status: 403, Title: "访问被拒绝", Plain: "rejected"}

	// 浏览器：卡片页。
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/x", nil)
	r.Header.Set("Accept", "text/html,application/xhtml+xml,*/*;q=0.8")
	Write(w, r, p)
	if w.Code != 403 {
		t.Fatalf("状态码应原样写出：%d", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Fatalf("浏览器应拿到 HTML：%q", ct)
	}
	if !strings.Contains(w.Body.String(), "访问被拒绝") {
		t.Fatal("卡片页里应有标题")
	}

	// 第三方推送系统 / curl：还是原来那句纯文本。塞 HTML 过去只会让对方的日志变成一团标签。
	w = httptest.NewRecorder()
	r = httptest.NewRequest(http.MethodPost, "/x", nil)
	Write(w, r, p)
	if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Fatalf("非浏览器应拿到纯文本：%q", ct)
	}
	if got := strings.TrimSpace(w.Body.String()); got != "rejected" {
		t.Fatalf("Plain 应原样输出（第三方可能已经在依赖它）：%q", got)
	}
}

func TestWantsHTML(t *testing.T) {
	cases := []struct {
		name   string
		accept string
		xhr    bool
		want   bool
	}{
		{"浏览器导航", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8", false, true},
		{"curl 默认", "*/*", false, false},
		{"什么都不带", "", false, false},
		{"要 JSON", "application/json", false, false},
		{"fetch 显式要 JSON 又列了 html", "application/json, text/html", false, false},
		{"XHR", "text/html", true, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			if c.accept != "" {
				r.Header.Set("Accept", c.accept)
			}
			if c.xhr {
				r.Header.Set("X-Requested-With", "XMLHttpRequest")
			}
			if got := WantsHTML(r); got != c.want {
				t.Fatalf("WantsHTML = %v，应为 %v", got, c.want)
			}
		})
	}
	if WantsHTML(nil) {
		t.Error("nil 请求应按非浏览器处理")
	}
}

// HEAD 不能带正文：写了会被 net/http 丢掉，并在日志里刷一条 superfluous 警告。
func TestWriteHeadHasNoBody(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodHead, "/", nil)
	r.Header.Set("Accept", "text/html")
	Write(w, r, Page{Status: 404, Title: "页面不存在"})
	if w.Body.Len() != 0 {
		t.Fatalf("HEAD 不该有正文：%d 字节", w.Body.Len())
	}
	if w.Header().Get("Content-Length") == "" {
		t.Error("HEAD 仍要给出 Content-Length")
	}
}

func TestPlainFallbacks(t *testing.T) {
	cases := []struct {
		p    Page
		want string
	}{
		{Page{Status: 404, Title: "页面不存在"}, "页面不存在"},
		{Page{Status: 404, Title: "页面不存在", Detail: "路径写错了"}, "页面不存在：路径写错了"},
		{Page{Status: 404, Plain: "not found", Title: "页面不存在"}, "not found"},
		{Page{Status: 404}, http.StatusText(404)},
	}
	for _, c := range cases {
		if got := plainOf(c.p); got != c.want {
			t.Errorf("plainOf = %q，应为 %q", got, c.want)
		}
	}
}

// WriteRaw 是给没有 HTTP 服务器的场合用的（端口转发那条裸 TCP 的路）：
// 状态行与响应头全靠手拼，拼错一个字节对面就解析不出响应。所以这里用标准库的
// http.ReadResponse 反过来解一遍——能解出来才算数，逐字比对拼串等于把 bug 抄两遍。
func TestWriteRawIsParsableHTTPResponse(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/x", nil)
	r.Header.Set("Accept", "text/html")
	var buf bytes.Buffer
	if err := WriteRaw(&buf, r, Page{Status: 502, Title: "站点暂时不可用"}); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(&buf), r)
	if err != nil {
		t.Fatalf("拼出来的响应解析不了: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 502 {
		t.Fatalf("状态码 = %d", resp.StatusCode)
	}
	if !resp.Close {
		t.Error("应带 Connection: close")
	}
	if resp.Header.Get("X-Content-Type-Options") != "nosniff" {
		t.Error("缺 nosniff")
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	// Content-Length 必须与正文实际长度一致，否则对端会一直等下去（或截断）。
	if int64(len(body)) != resp.ContentLength {
		t.Fatalf("Content-Length = %d，正文实际 %d 字节", resp.ContentLength, len(body))
	}
	if !strings.Contains(string(body), "站点暂时不可用") {
		t.Error("正文不是那页卡片")
	}
}

// 内容协商的口径与 Write 一致：非浏览器拿那一行纯文本。
func TestWriteRawNegotiatesByAccept(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/x", nil)
	r.Header.Set("Accept", "*/*")
	var buf bytes.Buffer
	if err := WriteRaw(&buf, r, Page{Status: 502, Title: "站点暂时不可用"}); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "Content-Type: text/plain") {
		t.Fatalf("非浏览器应拿纯文本: %q", out)
	}
	if strings.Contains(out, "<!doctype html>") {
		t.Error("非浏览器拿到了 HTML")
	}
}

// 状态行的原因短语不能空着：非标准状态码在 http.StatusText 那里取不到名字，
// 拼出来会是 "HTTP/1.1 599 " 这种末尾带空格的行——合法，但一些中间设备会挑刺。
func TestWriteRawFillsReasonForUnknownStatus(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteRaw(&buf, nil, Page{Status: 599, Title: "出错了"}); err != nil {
		t.Fatal(err)
	}
	line, _, _ := strings.Cut(buf.String(), "\r\n")
	if line != "HTTP/1.1 599 Error" {
		t.Fatalf("状态行 = %q", line)
	}
}
