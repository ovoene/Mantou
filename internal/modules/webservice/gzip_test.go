package webservice

import (
	"bytes"
	"compress/gzip"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"mantou/internal/config"
	"mantou/internal/httpx"
)

// newGzipTestSite 建一个带若干文件的静态站点，返回其处理器（gzip 已开启）。
func newGzipTestSite(t *testing.T, files map[string]string) http.Handler {
	t.Helper()
	root := t.TempDir()
	for name, body := range files {
		path := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	ch := config.WebChild{Type: "static", Static: config.WebStatic{Root: root, Gzip: true}}
	return httpx.WithGzip(staticHandler(ch))
}

// bigText 生成一段远超 httpx.GzipMinSize 且高度可压缩的文本。
func bigText() string { return strings.Repeat("mantou static asset payload 0123456789\n", 200) }

// TestGzipCompressesText 可压缩类型应被压缩，且解压后与原文一致（压缩链路不能损坏内容）。
func TestGzipCompressesText(t *testing.T) {
	body := bigText()
	h := newGzipTestSite(t, map[string]string{"app.js": body})

	req := httptest.NewRequest(http.MethodGet, "/app.js", nil)
	req.Header.Set("Accept-Encoding", "gzip, deflate, br")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	res := rec.Result()
	if got := res.Header.Get("Content-Encoding"); got != "gzip" {
		t.Fatalf("Content-Encoding 应为 gzip，实际 %q", got)
	}
	if res.Header.Get("Content-Length") != "" {
		t.Errorf("压缩后长度未知，不应保留 Content-Length")
	}
	if res.Header.Get("Accept-Ranges") != "" {
		t.Errorf("压缩后不应声明 Accept-Ranges")
	}
	if vary := res.Header.Get("Vary"); !strings.Contains(vary, "Accept-Encoding") {
		t.Errorf("必须声明 Vary: Accept-Encoding，实际 %q", vary)
	}
	if rec.Body.Len() >= len(body) {
		t.Errorf("压缩后体积应明显变小：%d → %d", len(body), rec.Body.Len())
	}
	zr, err := gzip.NewReader(bytes.NewReader(rec.Body.Bytes()))
	if err != nil {
		t.Fatalf("响应不是合法 gzip 流: %v", err)
	}
	got, err := io.ReadAll(zr)
	if err != nil {
		t.Fatalf("解压失败（很可能是漏了 Close 导致尾块缺失）: %v", err)
	}
	if err := zr.Close(); err != nil {
		t.Fatalf("gzip 流未正常结束: %v", err)
	}
	if string(got) != body {
		t.Errorf("解压内容与原文不一致")
	}
}

// TestGzipSkips 覆盖所有不应压缩的情形。
func TestGzipSkips(t *testing.T) {
	// PNG 魔数开头，确保 net/http 嗅探出 image/png。
	png := "\x89PNG\r\n\x1a\n" + strings.Repeat("\x00\x01\x02\x03", 500)
	h := newGzipTestSite(t, map[string]string{
		"app.js":  bigText(),
		"pic.png": png,
		"tiny.js": "x=1",
	})

	cases := []struct {
		name, path, accept, method, rng string
	}{
		{"客户端不接受 gzip", "/app.js", "", http.MethodGet, ""},
		{"客户端显式拒绝 gzip", "/app.js", "gzip;q=0, deflate", http.MethodGet, ""},
		{"已压缩的内容类型", "/pic.png", "gzip", http.MethodGet, ""},
		{"小于阈值", "/tiny.js", "gzip", http.MethodGet, ""},
		{"范围请求", "/app.js", "gzip", http.MethodGet, "bytes=0-99"},
		{"HEAD 请求", "/app.js", "gzip", http.MethodHead, ""},
	}
	for _, c := range cases {
		req := httptest.NewRequest(c.method, c.path, nil)
		if c.accept != "" {
			req.Header.Set("Accept-Encoding", c.accept)
		}
		if c.rng != "" {
			req.Header.Set("Range", c.rng)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if got := rec.Result().Header.Get("Content-Encoding"); got != "" {
			t.Errorf("%s：不应压缩，实际 Content-Encoding=%q", c.name, got)
		}
	}
}

// TestGzipRangeStaysIntact 范围请求必须原样走未压缩路径，否则声明的区间与实际字节对不上。
func TestGzipRangeStaysIntact(t *testing.T) {
	body := bigText()
	h := newGzipTestSite(t, map[string]string{"app.js": body})

	req := httptest.NewRequest(http.MethodGet, "/app.js", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	req.Header.Set("Range", "bytes=0-9")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	res := rec.Result()
	if res.StatusCode != http.StatusPartialContent {
		t.Fatalf("应返回 206，实际 %d", res.StatusCode)
	}
	if got := rec.Body.String(); got != body[:10] {
		t.Errorf("范围内容不正确: %q", got)
	}
}
