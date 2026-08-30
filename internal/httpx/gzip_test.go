package httpx

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
)

// TestAcceptsGzip Accept-Encoding 的解析细节：q=0 是「拒绝」，`*` 通配代表接受。
func TestAcceptsGzip(t *testing.T) {
	yes := []string{"gzip", "GZIP", " gzip ", "deflate, gzip", "gzip;q=1.0", "*", "br, *;q=0.5", "gzip, *;q=0"}
	no := []string{"", "identity", "deflate", "br", "gzip;q=0", "gzip; q=0.0", "*;q=0", "identity;q=1, *;q=0"}
	for _, s := range yes {
		if !AcceptsGzip(s) {
			t.Errorf("Accept-Encoding %q 应视为接受 gzip", s)
		}
	}
	for _, s := range no {
		if AcceptsGzip(s) {
			t.Errorf("Accept-Encoding %q 不应视为接受 gzip", s)
		}
	}
}

// TestCompressibleType 白名单判定：文本与结构化文本压，二进制与已压缩格式不压。
func TestCompressibleType(t *testing.T) {
	yes := []string{
		"text/html; charset=utf-8", "text/css", "text/plain", "TEXT/HTML",
		"application/json", "application/javascript", "application/xml",
		"application/manifest+json", "image/svg+xml", "application/wasm",
		"application/xhtml+xml", "image/x-icon",
	}
	no := []string{
		"", "image/png", "image/jpeg", "image/webp", "video/mp4",
		"application/zip", "application/gzip", "application/octet-stream",
		"font/woff", "font/woff2", "audio/mpeg",
		// 事件流是 text/ 之下唯一的例外：压了会变成缓冲式推送。
		"text/event-stream", "text/event-stream; charset=utf-8",
	}
	for _, ct := range yes {
		if !CompressibleType(ct) {
			t.Errorf("%q 应被压缩", ct)
		}
	}
	for _, ct := range no {
		if CompressibleType(ct) {
			t.Errorf("%q 不应被压缩", ct)
		}
	}
}

// TestGzipAllowedForRequest 三道请求侧的闸。
// Range 与 HEAD 这两条是正确性问题（206 的区间与压缩流对不上、HEAD 不许有 body），
// 不是优化，所以它们必须在处理器执行之前就把包装层挡掉。
func TestGzipAllowedForRequest(t *testing.T) {
	cases := []struct {
		name, method, accept, rng string
		want                      bool
	}{
		{"常规 GET", http.MethodGet, "gzip, deflate, br", "", true},
		{"客户端不接受", http.MethodGet, "", "", false},
		{"客户端显式拒绝", http.MethodGet, "gzip;q=0", "", false},
		{"范围请求", http.MethodGet, "gzip", "bytes=0-99", false},
		{"HEAD 请求", http.MethodHead, "gzip", "", false},
	}
	for _, c := range cases {
		req := httptest.NewRequest(c.method, "/x", nil)
		if c.accept != "" {
			req.Header.Set("Accept-Encoding", c.accept)
		}
		if c.rng != "" {
			req.Header.Set("Range", c.rng)
		}
		if got := GzipAllowedForRequest(req); got != c.want {
			t.Errorf("%s：GzipAllowedForRequest = %v，期望 %v", c.name, got, c.want)
		}
	}
}

// TestPrepareGzipResponse 两道响应侧的闸，以及压缩时对响应头的改写。
func TestPrepareGzipResponse(t *testing.T) {
	cases := []struct {
		name   string
		code   int
		header map[string]string
		want   bool
	}{
		{"可压缩且够大", http.StatusOK,
			map[string]string{"Content-Type": "application/json", "Content-Length": "4096"}, true},
		{"没有 Content-Length 也压", http.StatusOK,
			map[string]string{"Content-Type": "text/html; charset=utf-8"}, true},
		{"小于阈值", http.StatusOK,
			map[string]string{"Content-Type": "application/json", "Content-Length": "60"}, false},
		{"不可压缩类型", http.StatusOK,
			map[string]string{"Content-Type": "image/webp", "Content-Length": "40960"}, false},
		{"缺 Content-Type", http.StatusOK, map[string]string{"Content-Length": "4096"}, false},
		{"已被上游编码", http.StatusOK,
			map[string]string{"Content-Type": "text/css", "Content-Encoding": "br", "Content-Length": "4096"}, false},
		{"206 部分内容", http.StatusPartialContent,
			map[string]string{"Content-Type": "text/plain", "Content-Length": "4096"}, false},
		{"304 未修改", http.StatusNotModified,
			map[string]string{"Content-Type": "application/javascript"}, false},
		{"500 错误页", http.StatusInternalServerError,
			map[string]string{"Content-Type": "text/html", "Content-Length": "4096"}, false},
	}
	for _, c := range cases {
		h := http.Header{}
		for k, v := range c.header {
			h.Set(k, v)
		}
		h.Set("Accept-Ranges", "bytes")
		got := PrepareGzipResponse(h, c.code, -1)
		if got != c.want {
			t.Errorf("%s：PrepareGzipResponse = %v，期望 %v", c.name, got, c.want)
			continue
		}
		if !got {
			// 不压缩时不得留下任何压缩响应该有的痕迹。
			if h.Get("Content-Encoding") == "gzip" {
				t.Errorf("%s：没压缩却写了 Content-Encoding: gzip", c.name)
			}
			if want := c.header["Content-Length"]; want != "" && h.Get("Content-Length") != want {
				t.Errorf("%s：没压缩却动了 Content-Length（%q → %q）",
					c.name, want, h.Get("Content-Length"))
			}
			continue
		}
		if h.Get("Content-Encoding") != "gzip" {
			t.Errorf("%s：要压缩却没写 Content-Encoding", c.name)
		}
		if h.Get("Content-Length") != "" {
			t.Errorf("%s：压缩后长度未知，不应保留 Content-Length", c.name)
		}
		if h.Get("Accept-Ranges") != "" {
			t.Errorf("%s：压缩后不应声明 Accept-Ranges", c.name)
		}
		if h.Get("Vary") != "Accept-Encoding" {
			t.Errorf("%s：必须声明 Vary: Accept-Encoding，实际 %q", c.name, h.Get("Vary"))
		}
	}
}

// TestPrepareGzipResponseVaryOnSkippedSmallBody 体积没过闸时也要留 Vary。
// 少了它，共享缓存会把这次的未压缩响应与另一次的压缩响应存进同一个键。
func TestPrepareGzipResponseVaryOnSkippedSmallBody(t *testing.T) {
	h := http.Header{}
	h.Set("Content-Type", "application/json")
	h.Set("Content-Length", strconv.Itoa(GzipMinSize-1))
	if PrepareGzipResponse(h, http.StatusOK, -1) {
		t.Fatal("小于阈值不应压缩")
	}
	if h.Get("Vary") != "Accept-Encoding" {
		t.Errorf("可压缩类型即使这次没压也要声明 Vary，实际 %q", h.Get("Vary"))
	}
}

// TestPrepareGzipResponseExplicitSize 显式传入的长度优先于 Content-Length 头。
// gin 的渲染器不设那个头，面板侧只能把攒出来的长度传进来，这条路必须真的生效——
// 否则体积闸对面板等于不存在（面板绝大多数响应都是几十字节的 JSON）。
func TestPrepareGzipResponseExplicitSize(t *testing.T) {
	small := http.Header{}
	small.Set("Content-Type", "application/json")
	if PrepareGzipResponse(small, http.StatusOK, 60) {
		t.Error("显式给了 60 字节，不该压缩")
	}

	big := http.Header{}
	big.Set("Content-Type", "application/json")
	if !PrepareGzipResponse(big, http.StatusOK, GzipMinSize) {
		t.Error("显式给了刚好到阈值的长度，应当压缩")
	}

	// 长度未知（-1）且没有 Content-Length：只能压——这正是 Flush / ReadFrom 那两条路。
	unknown := http.Header{}
	unknown.Set("Content-Type", "text/html")
	if !PrepareGzipResponse(unknown, http.StatusOK, -1) {
		t.Error("长度未知的可压缩响应应当压缩")
	}

	// 显式长度优先：头里写着很大，实际只有 60 字节。
	lying := http.Header{}
	lying.Set("Content-Type", "application/json")
	lying.Set("Content-Length", "40960")
	if PrepareGzipResponse(lying, http.StatusOK, 60) {
		t.Error("显式长度应当盖过 Content-Length 头")
	}
}
