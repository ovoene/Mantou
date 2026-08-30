package server

import (
	"compress/gzip"
	"io"
	"net/http"

	"github.com/gin-gonic/gin"

	"mantou/internal/httpx"
)

// compressResponses 是面板的 gzip 中间件。
//
// 判定全部来自 internal/httpx，与用户站点静态子项用的是同一份（见那里的说明）。
// 换掉 gin-contrib/gzip 的原因是它只看请求、不看响应：
//   - 响应类型不看 → 面板 /uploads/ 下的 .webp 会被压缩，而那条路由由 http.FileServer 提供、
//     会响应 Range 并回 206，于是出现「Content-Range 描述未压缩长度、body 却是压缩流」的响应；
//   - 响应体积不看 → 面板大量几十字节的 JSON 也压，压完比原文长，还白付一次 deflate；
//   - 状态码不看、Accept-Ranges 不删、Unwrap 不实现（见 gzipWriter.Unwrap）。
//
// 这不是那个库写错了，是它在 next() 之前就得决定压不压——那时状态码、Content-Type、
// Content-Length 都还不存在。所以判定必须推迟到响应头就绪的那一刻，也就是下面这个写入器。
func (s *Server) compressResponses() gin.HandlerFunc {
	return func(c *gin.Context) {
		if !httpx.GzipAllowedForRequest(c.Request) {
			c.Next()
			return
		}
		gw := &gzipWriter{ResponseWriter: c.Writer}
		c.Writer = gw
		defer func() {
			gw.close()
			c.Writer = gw.ResponseWriter // 后续中间件（如访问日志）拿回原始写入器
		}()
		c.Next()
	}
}

// gzipWriter 是 gin.ResponseWriter 版的压缩写入器。
//
// 与 net/http 那份的唯一区别是判定时机：那边服务的是 http.ServeContent，
// 响应头里总有 Content-Length，看一眼就能过体积闸；gin 的渲染器从不设这个头
// （net/http 要等 body 写完才补），所以这里先把 body 攒到 GzipMinSize 字节再判定——
// 攒满了就是"够大"，请求结束时还没攒满就是"确实小"，两种情况都不必猜。
//
// 代价是每个在压缩链路上的请求最多多占 1 KiB，且它只在响应确实小于 1 KiB 时才真正分配。
// 换来的是面板那些几十字节的 JSON 不再白压一遍——这类响应占面板全部响应的绝大多数。
type gzipWriter struct {
	gin.ResponseWriter
	zw      *gzip.Writer // 非 nil 表示本次响应正在压缩
	status  int          // WriteHeader 记下的状态码，判定时才用得上
	pending []byte       // 判定之前暂存的 body，最多 GzipMinSize 字节
	decided bool
}

// decide 一次性判定本次响应压不压。bodySize 为 -1 表示"还会继续写，长度未知"。
func (g *gzipWriter) decide(bodySize int) {
	g.decided = true
	code := g.status
	if code == 0 {
		code = http.StatusOK // 处理器没显式调 WriteHeader，隐含 200
	}
	if httpx.PrepareGzipResponse(g.Header(), code, bodySize) {
		g.zw = httpx.AcquireGzipWriter(g.ResponseWriter)
	}
}

// stage 是所有 body 写入的唯一入口：未判定时先攒，攒够了就地判定并把攒的一起送出去。
func (g *gzipWriter) stage(b []byte) (int, error) {
	if !g.decided {
		if len(g.pending)+len(b) < httpx.GzipMinSize {
			g.pending = append(g.pending, b...)
			return len(b), nil
		}
		g.decide(-1)
		if err := g.flushPending(); err != nil {
			return 0, err
		}
	}
	if g.zw != nil {
		return g.zw.Write(b)
	}
	return g.ResponseWriter.Write(b)
}

// flushPending 把攒下的 body 送进已选定的写入路径。
func (g *gzipWriter) flushPending() error {
	if len(g.pending) == 0 {
		return nil
	}
	p := g.pending
	g.pending = nil
	var err error
	if g.zw != nil {
		_, err = g.zw.Write(p)
	} else {
		_, err = g.ResponseWriter.Write(p)
	}
	return err
}

// WriteHeader 只记录状态码。gin 的同名方法本身也只是记录（真正发头要等 WriteHeaderNow），
// 所以此刻还不必判定，也还改得动响应头。
func (g *gzipWriter) WriteHeader(code int) {
	if code > 0 {
		g.status = code
	}
	g.ResponseWriter.WriteHeader(code)
}

func (g *gzipWriter) Write(b []byte) (int, error) { return g.stage(b) }

// WriteString 是 gin.ResponseWriter 接口里除 Write 之外的另一个写入口。
// gin v1.10 自己不走它（render.WriteString 用的是 w.Write），但它是公开接口的一部分，
// 处理器与中间件都可以直接调。不覆盖它，调用就会从内嵌接口提升上去直接落到底层：
// 响应头里可能已经写了 Content-Encoding: gzip，客户端却收到明文，整页解不开。
func (g *gzipWriter) WriteString(s string) (int, error) { return g.stage([]byte(s)) }

// ReadFrom 保住不压缩分支上的 sendfile 快路径（面板的 /uploads/ 走这条）。
// 走到这里说明 body 由 io.Copy 从别处搬过来，长度未知，不进暂存直接判定——
// 静态文件服务此前已经设好 Content-Length，体积闸仍然有依据。
func (g *gzipWriter) ReadFrom(src io.Reader) (int64, error) {
	if !g.decided {
		g.decide(-1)
		if err := g.flushPending(); err != nil {
			return 0, err
		}
	}
	if g.zw != nil {
		return io.Copy(g.zw, src)
	}
	if rf, ok := g.ResponseWriter.(io.ReaderFrom); ok {
		return rf.ReadFrom(src)
	}
	return io.Copy(g.ResponseWriter, src)
}

// Flush 是"这些字节现在就要出去"的明确指令，因此暂存不能再留：
// 就地判定（长度按未知算）、送出已攒的、再冲压缩器与底层。
func (g *gzipWriter) Flush() {
	if !g.decided {
		g.decide(-1)
	}
	_ = g.flushPending()
	if g.zw != nil {
		_ = g.zw.Flush()
	}
	g.ResponseWriter.Flush()
}

// Unwrap 让 http.ResponseController 能穿过本层拿到底层连接。
//
// 这一条不是可选的：上传型接口（背景图 / 备份导入 / 自更新包）都靠
// extendRequestDeadlines 逐请求放宽读写截止时间，而 ResponseController 是顺着
// Unwrap 链找 SetReadDeadline 的。链上任何一层不实现 Unwrap，放宽就静默失效，
// 表现为大文件"上传到一半失败"——gin-contrib/gzip 的包装层正是缺这一条。
func (g *gzipWriter) Unwrap() http.ResponseWriter { return g.ResponseWriter }

// close 收尾：还没判定说明整个 body 都在暂存里，长度就此确定。
func (g *gzipWriter) close() {
	if !g.decided {
		g.decide(len(g.pending))
	}
	_ = g.flushPending()
	if g.zw != nil {
		httpx.ReleaseGzipWriter(g.zw)
		g.zw = nil
	}
}
