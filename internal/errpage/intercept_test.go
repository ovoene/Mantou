package errpage

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// 本文件盯的是「改写别人写的错误响应」这条路。
//
// 要钉住的其实是两件相反的事，后一件更要紧：
//   - 人拿浏览器撞上一段朴素纯文本错误时，看到的是卡片页；
//   - 除此之外的一切原样放行——接口调用、后端自带的错误页、正常的 200、
//     流式响应、大响应体。这一条是"一定不要影响正常的访问"的落点。

// browserGet 一个浏览器导航请求。
func browserGet(path string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, path, nil)
	r.Host = "site.example.com"
	r.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	return r
}

// plainErr 是标准库 http.Error 的行为：text/plain 一行字。
func plainErr(msg string, code int) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, msg, code)
	})
}

func TestInterceptRewritesPlainNotFoundForBrowser(t *testing.T) {
	w := httptest.NewRecorder()
	Intercept(plainErr("404 page not found", http.StatusNotFound)).ServeHTTP(w, browserGet("/a"))

	if w.Code != http.StatusNotFound {
		t.Fatalf("状态码必须原样保留，实际 %d", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Fatalf("浏览器应拿到 HTML，实际 %q", ct)
	}
	body := w.Body.String()
	for _, want := range []string{"<!doctype html>", "404", "页面不存在", "site.example.com/a"} {
		if !strings.Contains(body, want) {
			t.Errorf("卡片页应含 %q", want)
		}
	}
	// 原来那行小字不该还留在页面上。
	if strings.Contains(body, "404 page not found") {
		t.Error("原始纯文本仍留在响应体里")
	}
	// 长度头必须跟着新正文，否则浏览器会把页面截断。
	if got, want := w.Header().Get("Content-Length"), len(body); got != "" && got != itoa(want) {
		t.Errorf("Content-Length %q 与正文长度 %d 不符", got, want)
	}
}

// 非浏览器一律原样放行：探针、脚本、反代拿到的还是那一行纯文本。
// 这一条是"不影响正常访问"里最容易被改坏的一半——塞 HTML 过去，
// 对方的日志就变成一团标签。
func TestInterceptLeavesNonBrowserUntouched(t *testing.T) {
	for _, tc := range []struct {
		name   string
		accept string
		xhr    bool
	}{
		{"curl", "*/*", false},
		{"不带 Accept", "", false},
		{"要 JSON", "application/json", false},
		{"XHR", "text/html", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/a", nil)
			if tc.accept != "" {
				r.Header.Set("Accept", tc.accept)
			}
			if tc.xhr {
				r.Header.Set("X-Requested-With", "XMLHttpRequest")
			}
			w := httptest.NewRecorder()
			Intercept(plainErr("404 page not found", http.StatusNotFound)).ServeHTTP(w, r)

			if w.Code != http.StatusNotFound {
				t.Fatalf("状态码应为 404，实际 %d", w.Code)
			}
			if got := strings.TrimSpace(w.Body.String()); got != "404 page not found" {
				t.Fatalf("响应体应原样放行，实际 %q", got)
			}
		})
	}
}

// 后端自己写了错误页（text/html）就用它的：那是站点作者的意思，不是"丑的默认显示"。
// JSON / XML 之类结构化响应更是一律不动——那是给程序读的。
func TestInterceptLeavesTypedBodiesUntouched(t *testing.T) {
	for _, tc := range []struct{ name, ct, body string }{
		{"后端自带 HTML 错误页", "text/html; charset=utf-8", "<html><body>我家的 404</body></html>"},
		{"JSON 错误", "application/json", `{"error":"not found"}`},
		{"XML 错误", "application/xml", `<err>404</err>`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", tc.ct)
				w.WriteHeader(http.StatusNotFound)
				_, _ = w.Write([]byte(tc.body))
			})
			w := httptest.NewRecorder()
			Intercept(h).ServeHTTP(w, browserGet("/a"))
			if got := w.Body.String(); got != tc.body {
				t.Fatalf("响应体应原样放行，实际 %q", got)
			}
			if ct := w.Header().Get("Content-Type"); ct != tc.ct {
				t.Fatalf("Content-Type 应原样保留，实际 %q", ct)
			}
		})
	}
}

// 非 GET/HEAD 不动：表单与上传接口的错误响应体是给调用方读的。
func TestInterceptLeavesNonGETUntouched(t *testing.T) {
	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete} {
		r := httptest.NewRequest(method, "/a", nil)
		r.Header.Set("Accept", "text/html")
		w := httptest.NewRecorder()
		Intercept(plainErr("boom", http.StatusBadRequest)).ServeHTTP(w, r)
		if got := strings.TrimSpace(w.Body.String()); got != "boom" {
			t.Fatalf("%s 的响应体应原样放行，实际 %q", method, got)
		}
	}
}

// 正常的 200 必须一个字节都不变——这是本改动最不能出错的一条。
func TestInterceptPassesSuccessThrough(t *testing.T) {
	const payload = "hello, 馒头"
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte(payload))
	})
	w := httptest.NewRecorder()
	Intercept(h).ServeHTTP(w, browserGet("/ok"))
	if w.Code != http.StatusOK {
		t.Fatalf("状态码应为 200，实际 %d", w.Code)
	}
	if got := w.Body.String(); got != payload {
		t.Fatalf("正文被改动了：%q", got)
	}
}

// 3xx 不动：正文没人看，改写只会破坏跳转。
func TestInterceptLeavesRedirectUntouched(t *testing.T) {
	w := httptest.NewRecorder()
	Intercept(http.RedirectHandler("/b", http.StatusMovedPermanently)).ServeHTTP(w, browserGet("/a"))
	if w.Code != http.StatusMovedPermanently {
		t.Fatalf("状态码应为 301，实际 %d", w.Code)
	}
	if loc := w.Header().Get("Location"); loc != "/b" {
		t.Fatalf("Location 应保留，实际 %q", loc)
	}
}

// 超过上限的纯文本响应体不是"朴素错误"，扣下的部分必须完整补发。
// 漏掉补发的话，一个大响应会被截断成前 8 KB——那是静默的数据损坏。
func TestInterceptReleasesOversizeBodyIntact(t *testing.T) {
	body := strings.Repeat("x", maxInterceptBody*2+7)
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusInternalServerError)
		// 分多次写，逼着改写逻辑在"已经扣了一部分"的状态下放弃。
		for off := 0; off < len(body); off += 1000 {
			end := off + 1000
			if end > len(body) {
				end = len(body)
			}
			_, _ = w.Write([]byte(body[off:end]))
		}
	})
	w := httptest.NewRecorder()
	Intercept(h).ServeHTTP(w, browserGet("/big"))
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("状态码应为 500，实际 %d", w.Code)
	}
	if got := w.Body.String(); got != body {
		t.Fatalf("大响应体被改动：长度 %d，期望 %d", len(got), len(body))
	}
}

// Flush 意味着流式响应：不能再扣着，已扣下的要立刻补发。
func TestInterceptFlushReleasesHeldBody(t *testing.T) {
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte("第一段"))
		w.(http.Flusher).Flush()
		_, _ = w.Write([]byte("第二段"))
	})
	w := httptest.NewRecorder()
	Intercept(h).ServeHTTP(w, browserGet("/stream"))
	if got := w.Body.String(); got != "第一段第二段" {
		t.Fatalf("流式响应被改动：%q", got)
	}
}

// ReadFrom 必须透到底层：少了它，静态大文件下载会丢掉 sendfile 快路径。
func TestInterceptReadFromDelegates(t *testing.T) {
	rf := &readFromSpy{ResponseWriter: httptest.NewRecorder()}
	iw := &interceptor{ResponseWriter: rf, req: browserGet("/f")}
	if _, err := iw.ReadFrom(strings.NewReader("data")); err != nil {
		t.Fatal(err)
	}
	if !rf.used {
		t.Fatal("成功路径没走底层的 ReadFrom——大文件下载会退化成用户态复制")
	}
}

// 扣着的时候走 ReadFrom 不能无限递归（interceptor 自己就实现了 ReadFrom）。
func TestInterceptReadFromWhileHoldingDoesNotRecurse(t *testing.T) {
	w := httptest.NewRecorder()
	iw := &interceptor{ResponseWriter: w, req: browserGet("/f")}
	iw.Header().Set("Content-Type", "text/plain")
	iw.WriteHeader(http.StatusNotFound)
	if !iw.holding {
		t.Fatal("应当处于扣着的状态")
	}
	if _, err := iw.ReadFrom(strings.NewReader("404 page not found")); err != nil {
		t.Fatal(err)
	}
	iw.finish()
	if !strings.Contains(w.Body.String(), "页面不存在") {
		t.Fatalf("应换成卡片页：%q", w.Body.String())
	}
}

// HEAD 只要头不要正文：写了正文会被 net/http 丢掉并记一条 superfluous 日志。
func TestInterceptHEADHasNoBody(t *testing.T) {
	r := httptest.NewRequest(http.MethodHead, "/a", nil)
	r.Header.Set("Accept", "text/html")
	w := httptest.NewRecorder()
	Intercept(plainErr("404 page not found", http.StatusNotFound)).ServeHTTP(w, r)
	if w.Code != http.StatusNotFound {
		t.Fatalf("状态码应为 404，实际 %d", w.Code)
	}
	if w.Body.Len() != 0 {
		t.Fatalf("HEAD 不该有正文，实际 %d 字节", w.Body.Len())
	}
	if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Fatalf("HEAD 也该声明 HTML，实际 %q", ct)
	}
}

// 各状态码都得有一句人能看懂的话，且一律不带本程序的内部信息。
func TestPageForWordingHasNoInternals(t *testing.T) {
	for _, code := range []int{400, 401, 403, 404, 405, 408, 410, 413, 500, 502, 503, 504, 599} {
		p := PageFor(code, "site.example.com/x")
		if p.Title == "" {
			t.Errorf("%d 没有标题", code)
		}
		text := p.Title + p.Detail + p.Hint
		// "站点管理员"是允许的（那是站点主人，与本模块其它错误页同一口径）；
		// 不允许的是任何指向本程序自身的东西：管理入口、内部路径、上游地址、配置项。
		for _, banned := range []string{
			"mantou", "Mantou", "/api", "config.json", "面板", "管理入口", "上游",
			"后端地址", "根目录", "root", "127.0.0.1", "localhost", "端口",
		} {
			if strings.Contains(text, banned) {
				t.Errorf("%d 的文案里出现了不该出现的 %q：%s", code, banned, text)
			}
		}
	}
}

// 回显的主机名与路径要截断，否则一个几 KB 的路径能把卡片撑成一屏乱码；
// 截断还必须落在 rune 边界上，不能切出半个汉字。
func TestPageForClipsWhere(t *testing.T) {
	long := "site.example.com/" + strings.Repeat("馒", 400)
	p := PageFor(http.StatusNotFound, long)
	if len(p.Where) > whereMaxLen+len("…") {
		t.Fatalf("回显没截断：%d 字节", len(p.Where))
	}
	if !strings.HasSuffix(p.Where, "…") {
		t.Fatalf("截断后应带省略号：%q", p.Where)
	}
	if strings.ContainsRune(p.Where, '�') {
		t.Fatalf("截断切坏了多字节字符：%q", p.Where)
	}
}

// ---- 反代那一路 ----

// upstreamResp 造一个上游响应，Request 是**出站**请求（Host 已被改写成上游地址）。
func upstreamResp(code int, ct, body string, accept, method string) *http.Response {
	out := httptest.NewRequest(method, "http://10.0.0.9:8080/a", nil)
	out.Host = "10.0.0.9:8080"
	if accept != "" {
		out.Header.Set("Accept", accept)
	}
	h := http.Header{}
	if ct != "" {
		h.Set("Content-Type", ct)
	}
	return &http.Response{
		StatusCode:    code,
		Header:        h,
		Body:          io.NopCloser(strings.NewReader(body)),
		ContentLength: int64(len(body)),
		Request:       out,
	}
}

func TestRewriteUpstreamReplacesPlainError(t *testing.T) {
	resp := upstreamResp(404, "text/plain; charset=utf-8", "404 page not found",
		"text/html,*/*;q=0.8", http.MethodGet)
	if err := RewriteUpstream(resp); err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	if !bytes.Contains(body, []byte("页面不存在")) {
		t.Fatalf("应换成卡片页：%q", body)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Fatalf("Content-Type 没跟着改：%q", ct)
	}
	if resp.ContentLength != int64(len(body)) || resp.Header.Get("Content-Length") != itoa(len(body)) {
		t.Fatalf("长度头与正文不符：头 %q，ContentLength %d，正文 %d",
			resp.Header.Get("Content-Length"), resp.ContentLength, len(body))
	}
	// 最要紧的一条：ModifyResponse 拿到的是出站请求，它的 Host 是上游内网地址。
	// 回显出去正好是不该说的那一句。
	if bytes.Contains(body, []byte("10.0.0.9")) {
		t.Fatal("卡片页上回显了上游的内网地址")
	}
}

func TestRewriteUpstreamLeavesOthersUntouched(t *testing.T) {
	for _, tc := range []struct {
		name           string
		code           int
		ct, body       string
		accept, method string
	}{
		{"后端自带 HTML 错误页", 404, "text/html", "<h1>my 404</h1>", "text/html", http.MethodGet},
		{"JSON 错误", 404, "application/json", `{"e":1}`, "text/html", http.MethodGet},
		{"接口调用", 404, "text/plain", "not found", "*/*", http.MethodGet},
		{"POST", 400, "text/plain", "bad", "text/html", http.MethodPost},
		{"正常 200", 200, "text/plain", "ok", "text/html", http.MethodGet},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp := upstreamResp(tc.code, tc.ct, tc.body, tc.accept, tc.method)
			if err := RewriteUpstream(resp); err != nil {
				t.Fatal(err)
			}
			body, _ := io.ReadAll(resp.Body)
			if string(body) != tc.body {
				t.Fatalf("响应体应原样放行，实际 %q", body)
			}
		})
	}
}

// 已知体积过大的响应体不动：那里面几乎一定有调用方要用的内容。
func TestRewriteUpstreamLeavesOversizeUntouched(t *testing.T) {
	big := strings.Repeat("x", maxInterceptBody+1)
	resp := upstreamResp(500, "text/plain", big, "text/html", http.MethodGet)
	if err := RewriteUpstream(resp); err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != big {
		t.Fatalf("大响应体被改动：%d 字节", len(body))
	}
}

// 压过的响应体不动：解压再判类型不值得，而错判会吐出一段乱码。
func TestRewriteUpstreamLeavesEncodedUntouched(t *testing.T) {
	resp := upstreamResp(404, "text/plain", "\x1f\x8b...", "text/html", http.MethodGet)
	resp.Header.Set("Content-Encoding", "gzip")
	if err := RewriteUpstream(resp); err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "\x1f\x8b..." {
		t.Fatalf("压过的响应体被改动：%q", body)
	}
}

// nil 与缺 Request 的响应不能让它 panic：ModifyResponse 里 panic 会变成 502。
func TestRewriteUpstreamTolerantOfNil(t *testing.T) {
	if err := RewriteUpstream(nil); err != nil {
		t.Fatal(err)
	}
	if err := RewriteUpstream(&http.Response{StatusCode: 404, Header: http.Header{}}); err != nil {
		t.Fatal(err)
	}
}

// ---- 小工具 ----

type readFromSpy struct {
	http.ResponseWriter
	used bool
}

func (s *readFromSpy) ReadFrom(r io.Reader) (int64, error) {
	s.used = true
	return io.Copy(s.ResponseWriter, r)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
