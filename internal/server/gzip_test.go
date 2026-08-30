package server

import (
	"bytes"
	"compress/gzip"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"mantou/internal/httpx"
)

// fakeWebP 造一段能被识别成 image/webp 的字节（RIFF....WEBP + 填充），且远超体积闸，
// 这样"没被压缩"只可能是类型闸的功劳。
func fakeWebP(n int) []byte {
	head := []byte("RIFF\x00\x00\x00\x00WEBPVP8 ")
	return append(head, bytes.Repeat([]byte("\x11\x22\x33\x44"), (n-len(head))/4+1)...)
}

// 这条是审计四记下的可复现缺陷（4-C）：/uploads/ 走 http.ServeContent，会响应 Range 并回 206，
// 而旧的 gin-contrib/gzip 既不看内容类型（.webp 不在它的排除表里）也不看 Range 与状态码，
// 于是同一个响应里「Content-Range 描述未压缩长度」与「body 是压缩流」并存。
func TestUploadsWebPNeverCompressed(t *testing.T) {
	body := fakeWebP(8 << 10)
	engine, cookie := uploadsEnv(t, "", map[string][]byte{"bg.webp": body})

	req := httptest.NewRequest(http.MethodGet, "/uploads/bg.webp", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	req.Header.Set("Cookie", cookie)
	rec := httptest.NewRecorder()
	engine.ServeHTTP(rec, req)
	res := rec.Result()

	if res.StatusCode != http.StatusOK {
		t.Fatalf("取背景图应当 200，实际 %d", res.StatusCode)
	}
	if ct := res.Header.Get("Content-Type"); httpx.CompressibleType(ct) {
		t.Fatalf("测试前提不成立：本机把 .webp 判成了可压缩类型 %q", ct)
	}
	if got := res.Header.Get("Content-Encoding"); got != "" {
		t.Fatalf("已压缩格式不该再压一遍，实际 Content-Encoding=%q", got)
	}
	if res.Header.Get("Accept-Ranges") != "bytes" {
		t.Errorf("未压缩的静态文件应当保留 Accept-Ranges，实际 %q", res.Header.Get("Accept-Ranges"))
	}
	if !bytes.Equal(rec.Body.Bytes(), body) {
		t.Errorf("响应体与原文件不一致（%d → %d 字节）", len(body), rec.Body.Len())
	}
}

// Range 请求必须原样透传。这条测试故意用**可压缩**的文本文件而不是图片：
// 图片会先被内容类型闸挡掉，那样即便 Range 闸与状态码闸全被拆掉测试也照样通过，
// 盯不住任何东西。用文本文件时，拦住它的只能是 Range 闸或 206 状态码闸。
// 片段也必须大于体积闸，否则"没被压"可能只是因为片段太小。
func TestUploadsRangeRequestStaysIntact(t *testing.T) {
	const span = 4 << 10
	if span <= httpx.GzipMinSize {
		t.Fatalf("测试前提不成立：取的片段 %d 字节没超过体积闸 %d", span, httpx.GzipMinSize)
	}
	body := []byte(strings.Repeat("mantou uploads plain text 0123456789\n", 400)) // 远大于 span
	engine, cookie := uploadsEnv(t, "", map[string][]byte{"notes.txt": body})

	req := httptest.NewRequest(http.MethodGet, "/uploads/notes.txt", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	req.Header.Set("Cookie", cookie)
	req.Header.Set("Range", "bytes=0-"+strconv.Itoa(span-1))
	rec := httptest.NewRecorder()
	engine.ServeHTTP(rec, req)
	res := rec.Result()

	if res.StatusCode != http.StatusPartialContent {
		t.Fatalf("范围请求应当 206，实际 %d", res.StatusCode)
	}
	if ct := res.Header.Get("Content-Type"); !httpx.CompressibleType(ct) {
		t.Fatalf("测试前提不成立：内容类型 %q 本身就不可压缩，拦住它的不是 Range 闸", ct)
	}
	if got := res.Header.Get("Content-Encoding"); got != "" {
		t.Fatalf("206 的 body 是按未压缩偏移切出来的，压了就与 Content-Range 自相矛盾（%q）", got)
	}
	if got := res.Header.Get("Content-Range"); got == "" {
		t.Error("206 必须带 Content-Range")
	}
	if got := rec.Body.Bytes(); !bytes.Equal(got, body[:span]) {
		t.Errorf("范围内容不正确（%d 字节）", len(got))
	}
}

// 面板绝大多数响应是几十字节的 JSON。压这类响应的输出比原文更长，还白付一次 deflate，
// 而这项开销随「轮询频率 × 客户端数」线性放大（审计四 4-B）。
func TestSmallJSONResponseNotCompressed(t *testing.T) {
	_, engine := panelEngine(t, "")

	req := httptest.NewRequest(http.MethodGet, "/api/init/status", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	rec := httptest.NewRecorder()
	engine.ServeHTTP(rec, req)
	res := rec.Result()

	if rec.Body.Len() >= httpx.GzipMinSize {
		t.Fatalf("测试前提不成立：这个响应有 %d 字节，已经过了体积闸", rec.Body.Len())
	}
	if got := res.Header.Get("Content-Encoding"); got != "" {
		t.Errorf("%d 字节的响应不该压缩，实际 Content-Encoding=%q", rec.Body.Len(), got)
	}
	if !strings.Contains(rec.Body.String(), "initialized") {
		t.Errorf("响应体不是预期的初始化状态 JSON：%s", rec.Body.String())
	}
	// 可压缩类型即使这次没压也要声明 Vary，否则共享缓存会把两种副本存进同一个键。
	if vary := res.Header.Get("Vary"); !strings.Contains(vary, "Accept-Encoding") {
		t.Errorf("必须声明 Vary: Accept-Encoding，实际 %q", vary)
	}
}

// 够大的可压缩响应要真的压，且解压后与原文逐字节一致。
// 两条写入路径都要覆盖，因为 gin.ResponseWriter 是个**有两个写方法**的接口：
//   - Write：c.JSON / c.Data / c.String 目前都落到这里（gin v1.10 的 render.WriteString
//     用的是 w.Write，不是 io.WriteString）；
//   - WriteString：接口里明摆着的另一个入口，处理器与中间件可以直接调。
//
// 包装层只覆盖 Write 的话，WriteString 会从内嵌接口提升上来直接写到底层：
// 响应头那边可能已经写了 Content-Encoding: gzip，客户端却收到明文，整页解不开。
// 所以这里直接按接口调 WriteString——面板现在没有这样的调用点，但这个洞不该留着。
func TestLargeResponseCompressedOnBothWritePaths(t *testing.T) {
	body := strings.Repeat("mantou panel payload 0123456789\n", 200)
	s := &Server{}
	r := gin.New()
	r.Use(s.compressResponses())
	r.GET("/data", func(c *gin.Context) { c.Data(http.StatusOK, "application/json", []byte(body)) })
	r.GET("/string", func(c *gin.Context) {
		c.Header("Content-Type", "text/plain; charset=utf-8")
		c.Status(http.StatusOK)
		if _, err := c.Writer.WriteString(body); err != nil {
			t.Errorf("WriteString 失败: %v", err)
		}
	})

	for _, path := range []string{"/data", "/string"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Header.Set("Accept-Encoding", "gzip")
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
		res := rec.Result()

		if got := res.Header.Get("Content-Encoding"); got != "gzip" {
			t.Fatalf("%s：应当压缩，实际 Content-Encoding=%q", path, got)
		}
		if res.Header.Get("Content-Length") != "" {
			t.Errorf("%s：压缩后长度未知，不应保留 Content-Length", path)
		}
		if rec.Body.Len() >= len(body) {
			t.Errorf("%s：压缩后体积应明显变小：%d → %d", path, len(body), rec.Body.Len())
		}
		zr, err := gzip.NewReader(bytes.NewReader(rec.Body.Bytes()))
		if err != nil {
			t.Fatalf("%s：响应不是合法 gzip 流: %v", path, err)
		}
		got, err := io.ReadAll(zr)
		if err != nil {
			t.Fatalf("%s：解压失败（很可能是漏了 Close 导致尾块缺失）: %v", path, err)
		}
		if err := zr.Close(); err != nil {
			t.Fatalf("%s：gzip 流未正常结束: %v", path, err)
		}
		if string(got) != body {
			t.Errorf("%s：解压内容与原文不一致", path)
		}
	}
}

// 非 200 一律不压：错误页与重定向的 body 都小，而 204/304 根本没有 body。
func TestNon200ResponsesNotCompressed(t *testing.T) {
	big := strings.Repeat("这是一段够长的错误说明，用来确保体积闸不是拦住它的原因。", 100)
	s := &Server{}
	r := gin.New()
	r.Use(s.compressResponses())
	r.GET("/e500", func(c *gin.Context) { c.String(http.StatusInternalServerError, "%s", big) })
	r.GET("/e404", func(c *gin.Context) { c.String(http.StatusNotFound, "%s", big) })

	for _, path := range []string{"/e500", "/e404"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Header.Set("Accept-Encoding", "gzip")
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
		if got := rec.Result().Header.Get("Content-Encoding"); got != "" {
			t.Errorf("%s：非 200 不该压缩，实际 %q", path, got)
		}
		if rec.Body.String() != big {
			t.Errorf("%s：错误页 body 被改动了", path)
		}
	}
}

// 上传型接口靠 extendRequestDeadlines 放宽逐请求超时，而 ResponseController 是顺着
// Unwrap 链找 SetReadDeadline 的。压缩包装层不实现 Unwrap，放宽就静默失效——
// 表现为大文件"上传到一半失败"，且日志里只有一条 DEBUG。这条测试盯的就是那一环。
func TestGzipWriterKeepsResponseControllerReachable(t *testing.T) {
	s := &Server{}
	r := gin.New()
	r.Use(s.compressResponses())
	r.GET("/deadline", func(c *gin.Context) {
		if err := http.NewResponseController(c.Writer).SetReadDeadline(time.Now().Add(time.Minute)); err != nil {
			c.String(http.StatusInternalServerError, "SetReadDeadline: %v", err)
			return
		}
		c.String(http.StatusOK, "ok")
	})

	srv := httptest.NewServer(r)
	defer srv.Close()

	req, err := http.NewRequest(http.MethodGet, srv.URL+"/deadline", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Accept-Encoding", "gzip") // 手动指定，避免 Transport 自动解压掉证据
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	payload, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != http.StatusOK {
		t.Fatalf("放宽截止时间失败，说明 Unwrap 链断了：%s", payload)
	}
}
