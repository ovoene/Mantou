// Package errpage 提供全项目统一的错误页。
//
// 为什么要有这个包：这个项目对外开着好几个端口（面板、Web 服务的共享 80/443、
// 消息路由的入站端口），出错的地方分散在各个模块里，从前各写各的——有的回一句
// "not found"，有的回一行 JSON，有的回 "rejected"。用户拿浏览器撞上任何一个，
// 看到的都是一屏白底黑字，既看不出这是哪个服务，也看不出下一步该干什么。
//
// 两条硬规则：
//
//	一、内容协商。浏览器（Accept 里有 text/html）拿到卡片页，其余客户端拿到原来那句
//	纯文本。这不是为了好看：入站端口那一侧是第三方推送系统，它们要的是一个短小的
//	状态码与原因，塞一整页 HTML 过去只会让对方的日志变成一团乱码。
//
//	二、一切外来内容都经 html/template 转义。这一页天生要回显请求里的东西
//	（主机名、路径），而 Host 头是攻击者可控的（见 internal/stress/hostheader_test.go：
//	Go 的 Host 校验能挡住尖括号，但那是运行时的偶然，不该拿它当唯一防线）。
package errpage

import (
	"bytes"
	"html/template"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Page 一页错误页的全部内容。
//
// 拆成四段而不是一句话，是因为用户在这一页上要依次回答三个不同的问题：
// 出了什么事（Title）、为什么（Detail）、我该做什么（Hint）。
// 把它们揉成一句话，最后一定是"因为某某原因导致某某失败，请检查配置"这种没人能照着做的话。
type Page struct {
	// Status HTTP 状态码，同时显示在卡片上——用户来问的时候能直接报出这个数字。
	Status int
	// Title 一句话说清出了什么事，例如「页面不存在」。
	Title string
	// Detail 简洁的原因。刻意允许为空：安全相关的拒绝（令牌错、IP 不在名单里）
	// 就是不该在页面上说原因的，那等于给探测者提示（原因照常进执行历史）。
	Detail string
	// Hint 下一步该做什么。可空。
	Hint string
	// Where 请求落在哪里（主机 / 路径），以等宽字体显示。可空。
	// 只回显请求方自己发来的东西——它本来就知道，不构成信息泄露；
	// 但一定要转义（见包注释）。
	Where string
	// Plain 非浏览器客户端看到的纯文本。为空时用 Title。
	// 单独留这一项是为了不动那些已经被第三方系统依赖的响应体（例如入站端口的 "not found"）。
	Plain string
}

// tpl 卡片页。内联样式与内联 SVG，不引用任何外部资源：
// 这一页要在消息路由与 Web 服务的监听上也能用，那两处没有静态资源可服务。
// color-scheme + prefers-color-scheme 一起用，跟随系统深浅色。
var tpl = template.Must(template.New("errpage").Parse(`<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex">
<title>{{.Status}} · {{.Title}}</title>
<style>
  :root { color-scheme: light dark; }
  * { box-sizing: border-box; }
  body { margin:0; min-height:100vh; display:flex; align-items:center; justify-content:center;
    padding:24px;
    font-family: system-ui, -apple-system, 'PingFang SC', 'Microsoft YaHei', sans-serif;
    background:#f3f4f8; color:#2a2f3a; }
  .card { text-align:center; padding:40px 44px; border-radius:18px; max-width:460px; width:100%;
    background:rgba(255,255,255,0.85); box-shadow:0 10px 40px rgba(20,27,45,0.12); }
  .logo { width:56px; height:56px; margin:0 auto 14px; display:block; }
  .code { font-size:40px; font-weight:800; line-height:1; letter-spacing:1px;
    background:linear-gradient(120deg,#4f6bed,#22c1a6); -webkit-background-clip:text;
    background-clip:text; color:transparent; }
  h1 { font-size:20px; margin:10px 0 8px; font-weight:600; }
  p { margin:6px 0; color:#6b7280; font-size:14px; line-height:1.7; }
  .hint { margin-top:14px; padding:10px 12px; border-radius:10px; text-align:left;
    background:rgba(79,107,237,0.08); color:#4a5568; font-size:13px; line-height:1.7; }
  .where { margin-top:14px; font-family:ui-monospace,Menlo,Consolas,monospace; font-size:13px;
    color:#4f6bed; word-break:break-all; }
  .time { margin-top:16px; font-size:12px; color:#9aa3b2; font-variant-numeric:tabular-nums; }
  @media (prefers-color-scheme: dark) {
    body { background:#14171f; color:#e7e9ee; }
    .card { background:rgba(30,34,46,0.9); box-shadow:0 10px 40px rgba(0,0,0,0.4); }
    p { color:#9aa3b2; }
    .hint { background:rgba(79,107,237,0.16); color:#c2c9d6; }
  }
</style>
</head>
<body>
  <div class="card">
    <svg class="logo" viewBox="0 0 64 64" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
      <defs>
        <linearGradient id="mtg" x1="0" y1="0" x2="1" y2="1">
          <stop offset="0" stop-color="#4f6bed"/>
          <stop offset="1" stop-color="#22c1a6"/>
        </linearGradient>
      </defs>
      <rect x="6" y="6" width="52" height="52" rx="14" fill="url(#mtg)"/>
      <text x="32" y="45" text-anchor="middle" font-family="system-ui, -apple-system, sans-serif"
        font-size="34" font-weight="800" fill="#fff">M</text>
    </svg>
    <div class="code">{{.Status}}</div>
    <h1>{{.Title}}</h1>
    {{if .Detail}}<p>{{.Detail}}</p>{{end}}
    {{if .Hint}}<div class="hint">{{.Hint}}</div>{{end}}
    {{if .Where}}<div class="where">{{.Where}}</div>{{end}}
    <div class="time">{{.Time}}</div>
  </div>
</body>
</html>
`))

// Render 渲染卡片页。单独导出是为了能在测试里直接断言转义与内容。
func Render(p Page) []byte {
	if p.Status == 0 {
		p.Status = http.StatusInternalServerError
	}
	if p.Title == "" {
		p.Title = http.StatusText(p.Status)
	}
	var buf bytes.Buffer
	data := struct {
		Page
		Time string
	}{Page: p, Time: time.Now().Format("2006-01-02 15:04:05")}
	if err := tpl.Execute(&buf, data); err != nil {
		// 模板是编译期常量，执行失败只可能是改坏了模板本身。
		// 这里退回纯文本而不是 panic：一个监听上的错误页不该把整个进程带走。
		return []byte(plainOf(p))
	}
	return buf.Bytes()
}

// Write 按客户端类型输出错误页：浏览器得到卡片，其余客户端得到纯文本。
//
// 调用方必须在此之前设好所有要带的响应头（例如 401 的 WWW-Authenticate）——
// 这里会立刻写出状态码。
func Write(w http.ResponseWriter, r *http.Request, p Page) {
	if p.Status == 0 {
		p.Status = http.StatusInternalServerError
	}
	if !WantsHTML(r) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.WriteHeader(p.Status)
		_, _ = w.Write([]byte(plainOf(p) + "\n"))
		return
	}
	html := Render(p)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Length", strconv.Itoa(len(html)))
	w.WriteHeader(p.Status)
	// HEAD 请求不写正文：写了会被 net/http 丢掉并记一条 "superfluous" 日志。
	if r == nil || r.Method != http.MethodHead {
		_, _ = w.Write(html)
	}
}

// WriteRaw 把一页错误页当作一整个 HTTP/1.1 响应写到 w 上。
//
// 给没有 HTTP 服务器的场合用：端口转发是裸 TCP 的字节管道，手里只有一个 net.Conn，
// 没有 ResponseWriter，状态行与响应头都得自己拼。内容协商的口径与 Write 完全一致
// （浏览器拿卡片、其余客户端拿那一行纯文本），所以调用方传的是同一个 *http.Request。
//
// 只发一次 Write：状态行、响应头、正文先在内存里拼好，一次交给内核。
// 分几次写在裸连接上会被对端看成几个 TCP 段，某些客户端（以及中间设备）对
// "只收到响应头就先解析"很敏感，而这里也没有分段的必要——整页就几 KB。
func WriteRaw(w io.Writer, r *http.Request, p Page) error {
	if p.Status == 0 {
		p.Status = http.StatusInternalServerError
	}
	body := Render(p)
	ctype := "text/html; charset=utf-8"
	if !WantsHTML(r) {
		body = []byte(plainOf(p) + "\n")
		ctype = "text/plain; charset=utf-8"
	}
	reason := http.StatusText(p.Status)
	if reason == "" {
		reason = "Error"
	}
	var buf bytes.Buffer
	buf.WriteString("HTTP/1.1 " + strconv.Itoa(p.Status) + " " + reason + "\r\n")
	buf.WriteString("Content-Type: " + ctype + "\r\n")
	buf.WriteString("Content-Length: " + strconv.Itoa(len(body)) + "\r\n")
	buf.WriteString("X-Content-Type-Options: nosniff\r\n")
	buf.WriteString("Date: " + time.Now().UTC().Format(http.TimeFormat) + "\r\n")
	// 一律写完就关：调用方是"这条连接已经注定失败"才走到这里的，
	// 同一条连接上的下一个请求不会有别的结果，留着它反而让客户端以为还能用。
	buf.WriteString("Connection: close\r\n\r\n")
	// HEAD 不写正文，但 Content-Length 照给——那正是 HEAD 要问的（正文会有多长）。
	if r == nil || r.Method != http.MethodHead {
		buf.Write(body)
	}
	_, err := w.Write(buf.Bytes())
	return err
}

// plainOf 非浏览器客户端看到的那一行。
func plainOf(p Page) string {
	if p.Plain != "" {
		return p.Plain
	}
	if p.Title == "" {
		return http.StatusText(p.Status)
	}
	if p.Detail == "" {
		return p.Title
	}
	return p.Title + "：" + p.Detail
}

// WantsHTML 判断这个请求是不是"人拿浏览器发来的"。
//
// 只认 Accept 里的 text/html：浏览器导航请求一定带它，而 curl、各类推送系统、
// 反向代理探针发的是 */* 或干脆不带。XHR/fetch 会带 X-Requested-With 或明确要 JSON，
// 那种请求要的是可解析的响应体，塞 HTML 给它等于让前端的错误提示变成一堆标签。
func WantsHTML(r *http.Request) bool {
	if r == nil {
		return false
	}
	if r.Header.Get("X-Requested-With") == "XMLHttpRequest" {
		return false
	}
	accept := r.Header.Get("Accept")
	if !strings.Contains(accept, "text/html") {
		return false
	}
	// 同时要 HTML 又要 JSON 的只有 fetch 手动拼出来的请求，以 JSON 为准。
	if i := strings.Index(accept, "application/json"); i >= 0 && i < strings.Index(accept, "text/html") {
		return false
	}
	return true
}
