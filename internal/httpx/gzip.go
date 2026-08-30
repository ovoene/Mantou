// Package httpx 放与具体业务无关的 HTTP 传输层部件。
//
// 目前只有 gzip 一件事，但它必须住在这里：面板（gin）与用户站点（net/http）是两套
// 处理器体系，压不压的判定却应当只有一份。此前两边各用一套——用户站点用本文件这份，
// 面板用 gin-contrib/gzip——结果是同一个仓库里"webp 不该压"既被测试保护着、
// 又在面板的 /uploads/ 上真实发生。判定留一份，两套写入器各自适配，是唯一不会再漂移的形状。
package httpx

import (
	"compress/gzip"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
)

// GzipMinSize 低于该字节数不压缩：小响应压缩后常常反而变大，且省下的字节还不够抵掉
// gzip 头尾（约 18 字节）与一次压缩的 CPU。
// 判定需要知道 body 有多长，而这个长度有两种来源：响应头里的 Content-Length
// （静态文件服务会先设好），或者调用方自己数出来的字节数（面板走这条，见 PrepareGzipResponse）。
const GzipMinSize = 1024

// gzipWriterPool 复用 gzip.Writer。一个 writer 内含 32 KB 滑动窗口与哈希表，
// 实测常驻约 260 KB；若每个请求新建一个，稍有并发就会把这部分全压到堆上并推高 GC。
// 池的实际占用与并发数成正比，而不是与请求数成正比。
var gzipWriterPool = sync.Pool{New: func() any { return gzip.NewWriter(io.Discard) }}

// AcquireGzipWriter 从池中取一个压缩器并接到 w 上。
func AcquireGzipWriter(w io.Writer) *gzip.Writer {
	zw := gzipWriterPool.Get().(*gzip.Writer)
	zw.Reset(w)
	return zw
}

// ReleaseGzipWriter 结束压缩流并归还压缩器。必须调用：deflate 的尾块只在 Close 时写出，
// 漏掉会让客户端收到被截断的响应体。
func ReleaseGzipWriter(zw *gzip.Writer) {
	if zw == nil {
		return
	}
	_ = zw.Close()
	zw.Reset(io.Discard) // 断开对 ResponseWriter 的引用，避免连接被池里的对象拖住不回收
	gzipWriterPool.Put(zw)
}

// GzipAllowedForRequest 是三道**请求侧**的闸，在处理器执行之前就能判定。
func GzipAllowedForRequest(r *http.Request) bool {
	switch {
	case !AcceptsGzip(r.Header.Get("Accept-Encoding")):
		// 客户端不接受（或显式 q=0 拒绝）gzip。
		return false
	case r.Header.Get("Range") != "":
		// 字节范围请求：ServeContent 会按**未压缩**长度算 Content-Range 并只发该片段，
		// 若在其外层压缩，客户端拿到的字节区间与声明的范围对不上，文件必然损坏。
		return false
	case r.Method == http.MethodHead:
		// HEAD 响应不允许有 body，net/http 会丢弃所有 body 写入；
		// 此时 gzip 的头尾也写不出去，Close 只会返回一个无意义的错误。
		return false
	}
	return true
}

// PrepareGzipResponse 是两道**响应侧**的闸，只能在响应头已就绪、body 尚未写出的那一刻判定。
// 返回 true 表示本次响应要压缩，此时 h 已被改成压缩响应该有的样子。
//
// 请求侧的三道闸（GzipAllowedForRequest）必须在调用本函数之前就过掉：状态码与内容类型
// 在处理器跑完之前并不存在，而 Range / HEAD 在处理器跑完之后已经来不及了。
//
// bodySize 是已经确知的响应体字节数，-1 表示未知——未知时退回读 Content-Length 头。
// 之所以要多这个入口：Content-Length 并不总在写 body 之前就有。静态文件服务
// （http.ServeContent）会先设好它，而 gin 的渲染器从不设——那个头是 net/http 在
// body 写完之后才补的。所以面板那一侧由写入器先攒够 GzipMinSize 字节再来判定，
// 把攒出来的确切长度从这里传进来（见 server/gzip.go）。少了这条，体积闸对面板形同不存在。
func PrepareGzipResponse(h http.Header, code, bodySize int) bool {
	if code != http.StatusOK {
		// 只压 200：204/304 无 body，206 已被 Range 闸挡掉，重定向的 body 也小到不值得压。
		return false
	}
	if h.Get("Content-Encoding") != "" {
		return false // 处理器自己已经编码过（如直接吐 .gz 文件），不叠加第二层
	}
	if !CompressibleType(h.Get("Content-Type")) {
		return false
	}
	// 内容类型可压缩即声明 Vary：哪怕这次因体积太小没压，共享缓存也必须按 Accept-Encoding
	// 分键存储，否则压缩过的副本会被发给不支持 gzip 的客户端。
	AddVaryAcceptEncoding(h)
	if bodySize < 0 {
		if n, err := strconv.Atoi(h.Get("Content-Length")); err == nil {
			bodySize = n
		}
	}
	if bodySize >= 0 && bodySize < GzipMinSize {
		return false
	}
	h.Del("Content-Length") // 压缩后长度未知，改为分块传输
	// 压缩后的 body 不再按原字节偏移寻址，保留 Accept-Ranges 会诱导客户端发出无法正确
	// 满足的范围请求（那些请求会走上面的 Range 闸、以未压缩形式返回，语义就割裂了）。
	h.Del("Accept-Ranges")
	h.Set("Content-Encoding", "gzip")
	return true
}

// AddVaryAcceptEncoding 声明"响应随 Accept-Encoding 变化"，已经声明过就不再重复。
// 去重是必要的：静态资源那边为了让 304 也带上这一条，会在交给文件服务器之前先自己设好
// （见 server/assets.go），若这里无条件 Add，同一个响应上就会出现两个 Vary 头。
func AddVaryAcceptEncoding(h http.Header) {
	for _, v := range h.Values("Vary") {
		for _, field := range strings.Split(v, ",") {
			field = strings.TrimSpace(field)
			if field == "*" || strings.EqualFold(field, "Accept-Encoding") {
				return
			}
		}
	}
	h.Add("Vary", "Accept-Encoding")
}

// WithGzip 给一个 net/http 处理器加 gzip 压缩（用户站点的静态子项走这条）。
//
// 压缩与 sendfile 天然互斥——压缩必须过用户态。这里按响应的 Content-Type 分流：
// 可压缩类型（HTML/CSS/JS/JSON/SVG/wasm…）走压缩，其余（图片、视频、已压缩归档、woff2）
// 原样透传，且透传路径保留 io.ReaderFrom，因此大文件下载仍能走 sendfile(2) 零拷贝。
//
// 这条路径不需要为体积闸攒数据：它服务的是 http.ServeContent，那边总是先设好
// Content-Length 再写 body，判定时长度已知。
func WithGzip(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !GzipAllowedForRequest(r) {
			next.ServeHTTP(w, r)
			return
		}
		gw := &gzipResponseWriter{ResponseWriter: w}
		defer gw.close()
		next.ServeHTTP(gw, r)
	})
}

// gzipResponseWriter 在首次 WriteHeader / Write 时决定本次响应是否压缩，之后据此分流写入。
type gzipResponseWriter struct {
	http.ResponseWriter
	zw      *gzip.Writer // 非 nil 表示本次响应正在压缩
	decided bool
}

func (g *gzipResponseWriter) decide(code int) {
	g.decided = true
	if PrepareGzipResponse(g.Header(), code, -1) {
		g.zw = AcquireGzipWriter(g.ResponseWriter)
	}
}

func (g *gzipResponseWriter) WriteHeader(code int) {
	if !g.decided {
		g.decide(code)
	}
	g.ResponseWriter.WriteHeader(code)
}

func (g *gzipResponseWriter) Write(b []byte) (int, error) {
	if !g.decided {
		// 处理器没显式调 WriteHeader，隐含 200。
		g.decide(http.StatusOK)
	}
	if g.zw != nil {
		return g.zw.Write(b)
	}
	return g.ResponseWriter.Write(b)
}

// ReadFrom 保住不压缩分支上的 sendfile 快路径：压缩必须过用户态，不压缩就没理由过。
func (g *gzipResponseWriter) ReadFrom(src io.Reader) (int64, error) {
	if !g.decided {
		g.decide(http.StatusOK)
	}
	if g.zw != nil {
		return io.Copy(g.zw, src)
	}
	if rf, ok := g.ResponseWriter.(io.ReaderFrom); ok {
		return rf.ReadFrom(src)
	}
	return io.Copy(g.ResponseWriter, src)
}

// Flush 先冲掉压缩器内的待压数据，再冲底层，否则数据会滞留在 deflate 缓冲里。
func (g *gzipResponseWriter) Flush() {
	if g.zw != nil {
		_ = g.zw.Flush()
	}
	if f, ok := g.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Unwrap 供 http.ResponseController 穿透本包装层。
func (g *gzipResponseWriter) Unwrap() http.ResponseWriter { return g.ResponseWriter }

func (g *gzipResponseWriter) close() {
	if g.zw == nil {
		return
	}
	ReleaseGzipWriter(g.zw)
	g.zw = nil
}

// CompressibleType 判断 Content-Type 是否值得压缩。
// 采用白名单而非「按扩展名排除」：新型已压缩格式层出不穷，漏掉一个就是白烧 CPU，
// 而可压缩的文本类型是可枚举的。woff2 / 图片 / 视频 / 归档因此天然落在名单之外。
func CompressibleType(ct string) bool {
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = ct[:i] // 去掉 charset 等参数
	}
	ct = strings.ToLower(strings.TrimSpace(ct))
	switch {
	case ct == "":
		return false
	case ct == "text/event-stream":
		// 唯一一个"是 text/ 却不该压"的类型：事件流靠逐条即时送达，
		// 压缩器会把内容攒在 deflate 缓冲里，一路上的代理也常对压缩过的事件流处理不当。
		// 本仓库目前没有这类端点，写在这里是为了将来加一个时不会静默变成缓冲式推送。
		return false
	case strings.HasPrefix(ct, "text/"):
		return true
	case strings.HasSuffix(ct, "+json"), strings.HasSuffix(ct, "+xml"):
		// application/manifest+json、image/svg+xml、application/xhtml+xml 等。
		return true
	}
	switch ct {
	case "application/json", "application/javascript", "application/x-javascript",
		"application/ecmascript", "application/xml", "application/wasm",
		"application/vnd.ms-fontobject",
		"image/x-icon", "image/vnd.microsoft.icon",
		"font/ttf", "font/otf", "application/x-font-ttf":
		return true
	}
	return false
}

// AcceptsGzip 解析 Accept-Encoding。需要正确处理两处细节：
// q=0 是「明确拒绝」而非「优先级最低」；`*` 通配也代表接受。
func AcceptsGzip(header string) bool {
	viaWildcard := false
	for _, part := range strings.Split(header, ",") {
		name, params, _ := strings.Cut(strings.TrimSpace(part), ";")
		switch strings.ToLower(strings.TrimSpace(name)) {
		case "gzip":
			return !zeroQuality(params)
		case "*":
			viaWildcard = !zeroQuality(params)
		}
	}
	return viaWildcard
}

// zeroQuality 判断参数串里是否带 q=0（含 0.0、0.000）。
func zeroQuality(params string) bool {
	for _, p := range strings.Split(params, ";") {
		k, v, ok := strings.Cut(p, "=")
		if !ok || !strings.EqualFold(strings.TrimSpace(k), "q") {
			continue
		}
		f, err := strconv.ParseFloat(strings.TrimSpace(v), 64)
		return err == nil && f == 0
	}
	return false
}
