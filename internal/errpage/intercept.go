package errpage

// 本文件补上统一错误页的最后一段：那些**不是本项目自己生成**的错误响应。
//
// 各模块显式调 Write 的地方都已经是卡片页了，但还有两类漏在外面：
//
//	一、标准库替我们回的。静态站点走 http.FileServer，路径不存在时它写的是
//	    "404 page not found" 一行纯文本——浏览器上就是左上角一行小字，
//	    既看不出这是哪个站点，也看不出下一步该干什么。
//	二、上游后端回的。反向代理把后端的响应原样透传，后端要是个 Go 程序，
//	    它的 404 同样是那一行纯文本。
//
// 两类都改写，但改写的门槛刻意订得很高——错误响应体是会被程序消费的东西，
// 把它换掉是有代价的。四道闸（见 Rewritable）合起来的效果是：只有「人拿浏览器
// 导航到一个地址、结果拿回一段朴素纯文本」这一种情形会被换成卡片，
// 接口调用、自带错误页的后端、流式响应、大响应体一律原样放行。
//
// 页面上不回显任何本程序的内部信息：不写站点根目录、不写上游地址、不写配置项名字。
// 反代那一路连请求主机名都不回显——ModifyResponse 拿到的是**出站**请求，
// 它的 Host 已经被改写成上游的内网地址了，回显出去正好是不该说的那一句。

import (
	"bufio"
	"bytes"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
)

// maxInterceptBody 改写时最多接管多少字节的原响应体。
//
// 朴素错误响应都极短（标准库那句 19 字节，nginx 的默认页也就几百字节）。
// 超过这个数的响应体几乎一定带着调用方要用的内容，原样放行。
// 这道闸同时是内存护栏：扣着响应体等于把它整段留在内存里。
const maxInterceptBody = 8 << 10

// whereMaxLen 回显到页面上的「你访问的是」最多留多少字节。
// 主机名与路径都由对方决定，几 KB 的路径会把卡片撑成一屏乱码。
const whereMaxLen = 160

// Rewritable 判断一个已经定型的错误响应该不该换成卡片页。
//
// 反代与静态两路共用这一个判定，是为了让「什么会被改写」只有一处定义——
// 两边各写一套的话，日后放宽了一边就再没人记得另一边还是紧的。
//
// 四道闸，缺一不可：
//
//  1. 状态码在 4xx/5xx。3xx 带着 Location，正文没人看；2xx 不是错误。
//  2. 请求方式是 GET / HEAD。POST/PUT 的错误响应体多半是给程序读的
//     （表单接口的校验结果、上传接口的失败原因），换掉就是在破坏调用方。
//  3. 请求来自浏览器导航（WantsHTML）。XHR、fetch、curl、探针、推送系统
//     要的是可解析的响应体，塞 HTML 过去等于把对方的错误提示变成一堆标签。
//  4. 响应体是朴素纯文本：Content-Type 为空或 text/plain，且没有内容编码。
//     后端自己写了错误页（text/html）就用它的——那是站点作者的意思，不是"丑的默认显示"；
//     JSON / XML / 图片一律不动。
func Rewritable(status int, h http.Header, r *http.Request) bool {
	if status < 400 || status > 599 {
		return false
	}
	if r == nil || (r.Method != http.MethodGet && r.Method != http.MethodHead) {
		return false
	}
	if !WantsHTML(r) {
		return false
	}
	if h == nil {
		return true
	}
	// 内容编码非空说明响应体是压过的，解压再判类型不值得——原样放行。
	if h.Get("Content-Encoding") != "" {
		return false
	}
	if ct := strings.TrimSpace(h.Get("Content-Type")); ct != "" {
		mt := strings.ToLower(strings.TrimSpace(strings.SplitN(ct, ";", 2)[0]))
		if mt != "text/plain" {
			return false
		}
	}
	return true
}

// PageFor 给一个状态码配一页说得清的卡片。
//
// 措辞的口径与项目里其它错误页一致：说清出了什么事、给一句能照着做的下一步，
// 不提本程序的任何内部信息（目录、上游地址、配置项、管理入口的位置）。
// where 可空，非空时是请求方自己发来的主机名与路径——它本来就知道，不构成信息泄露。
func PageFor(status int, where string) Page {
	p := Page{Status: status, Where: clipWhere(where)}
	switch status {
	case http.StatusNotFound, http.StatusGone:
		p.Title = "页面不存在"
		p.Detail = "这个地址在本站点上没有对应的内容。"
		p.Hint = "请确认地址是否输入正确。"
	case http.StatusForbidden:
		p.Title = "没有访问权限"
		p.Detail = "这个地址不允许访问。"
		p.Hint = "如果你认为这是误拦，请联系站点管理员。"
	case http.StatusUnauthorized:
		p.Title = "需要先登录"
		p.Detail = "这个地址要求身份验证后才能访问。"
	case http.StatusMethodNotAllowed:
		p.Title = "这个地址不接受此种请求"
		p.Detail = "地址是对的，但它不处理这一类请求。"
	case http.StatusRequestTimeout:
		p.Title = "请求超时了"
		p.Detail = "这次请求在完成之前就超过了等待时间。"
		p.Hint = "请稍后再试。"
	case http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		p.Title = "站点暂时不可用"
		p.Detail = "站点收到了你的请求，但它后面的服务没有正常响应。"
		p.Hint = "请稍后再试，或联系站点管理员。"
	default:
		if status >= 500 {
			p.Title = "站点出错了"
			p.Detail = "这次请求在处理过程中出错了。"
			p.Hint = "请稍后再试，或联系站点管理员。"
			break
		}
		p.Title = "请求无法完成"
		p.Detail = "这个请求没能被站点接受。"
		p.Hint = "请确认地址是否输入正确。"
	}
	return p
}

// whereOf 从入站请求里取「你访问的是」。
// 只可用于**入站**请求：反代的 ModifyResponse 拿到的是出站请求，
// 它的 Host 是上游的内网地址，不能往页面上写（见文件头说明）。
func whereOf(r *http.Request) string {
	if r == nil {
		return ""
	}
	if r.URL == nil {
		return r.Host
	}
	return r.Host + r.URL.Path
}

// clipWhere 按字节截断，并在 rune 边界上回退，避免切出半个汉字。
func clipWhere(s string) string {
	if len(s) <= whereMaxLen {
		return s
	}
	cut := whereMaxLen
	for cut > 0 && !isRuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + "…"
}

func isRuneStart(b byte) bool { return b&0xC0 != 0x80 }

// Intercept 包住一个处理器，把它写出的朴素错误响应换成卡片页。
//
// 用于本项目"交给标准库去写响应"的那些路径（静态站点的文件服务）。反代不走这里：
// 那一路用 RewriteUpstream 挂在 ModifyResponse 上，在那里能拿到上游真实的 Content-Type，
// 判定比在 ResponseWriter 这一层准。
//
// 必须包在最内层（贴着被包的处理器）：包在压缩中间件外面的话，扣下来的响应体是压过的，
// 判类型就得先解压。
func Intercept(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		iw := &interceptor{ResponseWriter: w, req: r}
		next.ServeHTTP(iw, r)
		iw.finish()
	})
}

// interceptor 扣住一个疑似朴素错误的响应，等看清了再决定放行还是改写。
//
// "扣住"只针对 Rewritable 认可的响应头；其余一切照原样直通，包括
// sendfile 快路径（ReadFrom）、流式响应（Flush）与协议升级（Hijack）。
type interceptor struct {
	http.ResponseWriter
	req     *http.Request
	status  int
	wrote   bool // 响应头已交给底层（或已确定原样直通）
	holding bool // 正扣着一个待改写的错误响应
	buf     bytes.Buffer
}

func (i *interceptor) WriteHeader(code int) {
	// 重复调用照标准库的规矩忽略掉，否则会多写一次响应头。
	if i.wrote || i.holding {
		return
	}
	i.status = code
	if Rewritable(code, i.Header(), i.req) {
		i.holding = true
		return
	}
	i.wrote = true
	i.ResponseWriter.WriteHeader(code)
}

func (i *interceptor) Write(b []byte) (int, error) {
	if i.holding {
		if i.buf.Len()+len(b) > maxInterceptBody {
			// 超出朴素错误的体量：这不是"丑的默认显示"，把扣下的原样补发出去。
			i.release()
			return i.ResponseWriter.Write(b)
		}
		return i.buf.Write(b)
	}
	i.ensureHeader()
	return i.ResponseWriter.Write(b)
}

// ReadFrom 保住静态文件的 sendfile 快路径。
//
// 少了这一个方法，http.ServeContent 里对 io.ReaderFrom 的断言就会落空，
// 大文件下载退化成用户态 32 KB 循环——那是实打实地"影响正常的访问"。
func (i *interceptor) ReadFrom(src io.Reader) (int64, error) {
	if i.holding {
		// 错误响应体极短，走 Write 那条路缓冲即可。
		// 不能直接 io.Copy(i, src)：i 自己实现了 ReadFrom，会无限递归。
		return io.Copy(writeOnly{i}, src)
	}
	i.ensureHeader()
	if rf, ok := i.ResponseWriter.(io.ReaderFrom); ok {
		return rf.ReadFrom(src)
	}
	return io.Copy(i.ResponseWriter, src)
}

// Flush 一被调用就说明这是流式响应，不能再扣着。
func (i *interceptor) Flush() {
	if i.holding {
		i.release()
	}
	i.ensureHeader()
	if f, ok := i.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Unwrap 供 http.ResponseController 穿透包装层（Go 1.20+）。
func (i *interceptor) Unwrap() http.ResponseWriter { return i.ResponseWriter }

// Hijack 透传协议升级（WebSocket 等）。接管连接就没有"响应体"可言了，
// 还扣着的话先把它放掉。
func (i *interceptor) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if i.holding {
		i.release()
	}
	hj, ok := i.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, http.ErrNotSupported
	}
	return hj.Hijack()
}

// release 放弃改写：把扣下的响应头与已缓冲的字节原样补发出去。
func (i *interceptor) release() {
	i.holding = false
	i.wrote = true
	i.ResponseWriter.WriteHeader(i.status)
	if i.buf.Len() > 0 {
		_, _ = i.ResponseWriter.Write(i.buf.Bytes())
	}
	i.buf.Reset()
}

// ensureHeader 只记账，不主动写响应头：底层的 Write 会隐式补 200，
// 抢在它前面写反而会把 Content-Length 之类还没设好的头定死。
func (i *interceptor) ensureHeader() {
	if i.wrote {
		return
	}
	i.wrote = true
	if i.status == 0 {
		i.status = http.StatusOK
	}
}

// finish 处理器返回后收尾：还扣着就说明这确实是一段朴素错误，换成卡片。
func (i *interceptor) finish() {
	if !i.holding {
		return
	}
	i.holding = false
	i.wrote = true
	i.buf.Reset()
	h := i.Header()
	// 原响应体的这几个头必须清掉：长度变了，类型变了，也不再支持范围请求。
	h.Del("Content-Length")
	h.Del("Content-Type")
	h.Del("Accept-Ranges")
	Write(i.ResponseWriter, i.req, PageFor(i.status, whereOf(i.req)))
}

// writeOnly 只暴露 Write，用来阻断 io.Copy 挑中 ReadFrom 造成的递归。
type writeOnly struct{ w io.Writer }

func (o writeOnly) Write(b []byte) (int, error) { return o.w.Write(b) }

// RewriteUpstream 把上游后端吐回来的朴素错误响应换成卡片页。
// 挂在 httputil.ReverseProxy.ModifyResponse 上。
//
// 与 Intercept 共用 Rewritable 那一套判定；额外多一条：响应体已知且过大时不动。
// 这一路刻意不回显主机名与路径——resp.Request 是**出站**请求，
// 它的 Host 已经被 Director 改成上游的内网地址（见文件头说明）。
//
// 返回值恒为 nil：改写失败不该让一个错误响应升级成 502。
func RewriteUpstream(resp *http.Response) error {
	if resp == nil || resp.Request == nil || resp.Header == nil {
		return nil
	}
	if !Rewritable(resp.StatusCode, resp.Header, resp.Request) {
		return nil
	}
	if resp.ContentLength > maxInterceptBody {
		return nil
	}
	html := Render(PageFor(resp.StatusCode, ""))
	if resp.Body != nil {
		// 不读就关：错误响应的连接不值得为了复用而把它读空。
		_ = resp.Body.Close()
	}
	resp.Body = io.NopCloser(bytes.NewReader(html))
	resp.ContentLength = int64(len(html))
	resp.Header.Set("Content-Type", "text/html; charset=utf-8")
	resp.Header.Set("Content-Length", strconv.Itoa(len(html)))
	resp.Header.Set("X-Content-Type-Options", "nosniff")
	resp.Header.Del("Accept-Ranges")
	return nil
}
