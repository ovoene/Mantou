package webservice

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"mantou/internal/config"
	"mantou/internal/errpage"
	"mantou/internal/httpx"
	"mantou/internal/ipx"
	"mantou/internal/logx"
)

// 本文件是 webservice 的请求处理层：三类子项（反代 / 静态 / 重定向）各自的 http.Handler，
// 以及包裹在它们外面的计数与访问日志埋点（instrument）和响应写入器（statusWriter）。

// idleCloser 是「能主动关掉自己连接池里空闲连接」的东西，实际只有 *http.Transport。
//
// 单独起个接口是为了让 listenServer 不必知道处理器里到底藏了什么：静态站点与跳转
// 压根没有连接池，反代才有，收集端拿到 nil 就跳过。
type idleCloser interface{ CloseIdleConnections() }

// buildChildHandler 依据子项类型构造处理器（反向代理 / 静态站点 / 重定向），
// 叠加访问控制中间件，最外层再包裹连接计数与访问日志。
//
// 第二个返回值是这个子项的连接池（只有反代有，其余为 nil）：监听被关闭或重建时
// 要就地把它池子里的空闲连接关掉，否则那些 socket 得等 IdleConnTimeout 到期。
func buildChildHandler(m *Module, service string, ch config.WebChild) (http.Handler, idleCloser) {
	var base http.Handler
	var idle idleCloser
	switch ch.Type {
	case "static":
		// Intercept 贴着文件服务器：http.FileServer 找不到文件时写的是
		// "404 page not found" 一行纯文本，那正是要换掉的"默认显示"。
		// 必须在压缩之内（更靠里），否则扣下来的响应体是压过的。
		base = errpage.Intercept(staticHandler(ch))
		if ch.Static.Gzip {
			// 只压静态路径，且包在访问控制之内：
			//   - 不包反向代理——后端很可能已经压过（重复压缩纯耗 CPU，还要处理 Content-Encoding
			//     协商），对 SSE 这类流式响应加压缩还会破坏实时性；
			//   - 包在访问控制之内，所以 403/429 这类小错误页也不会走压缩。
			// 压不压的五道闸在 internal/httpx，与面板共用同一份判定。
			base = httpx.WithGzip(base)
		}
	case "redirect":
		base = redirectHandler(ch)
	default: // proxy
		var tr *http.Transport
		base, tr = proxyHandler(m.log, service, ch)
		if tr != nil {
			idle = tr
		}
	}
	h := applyMiddleware(m, service, ch, base)
	counter := m.connCounter(ch.ID)
	return m.instrument(service, ch, counter, h), idle
}

// instrument 包裹子项处理器：仅负责统计活跃连接数，以及（在开启「记录访问日志」时）记录
// 三类事件——连接 / 断开 / 错误；每类按 IP（连接/断开）或签名（错误）在 10 分钟窗口内仅首条，杜绝刷屏。
// 「链接状态」（前端到后端是否正常访问）由周期主动探测 (runProbe) 统一维护，与本路径完全解耦：
// 即便零访问、或访问日志开关关闭、或受 10/s 写速限速压制，链接状态仍独立、准时地反映后端可达性。
// 开关关闭时不写任何访问日志（含环形缓冲）。
func (m *Module) instrument(service string, ch config.WebChild, counter *int64, next http.Handler) http.Handler {
	logAccess := ch.Proxy.AccessLog
	childID := ch.ID
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(counter, 1)
		defer atomic.AddInt64(counter, -1)
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(sw, r)
		dur := time.Since(start).Milliseconds()
		now := time.Now()
		ip := remoteIP(r)
		// 判定事件类型：客户端主动挂断 → 断开；状态码 ≥400 → 错误；其余 → 连接（新连接 / 在途活动）。
		kind := eventConnect
		status := 0
		var sig, reason string
		switch {
		case sw.clientAborted:
			kind = eventDisconnect
		case sw.status >= 400:
			// 403 专属 IP 规则拒绝（见 withIPFilter），已由 recordDenied 记为独立的 denied 事件，
			// 此处不再作为通用 error 重复记录，避免一条拒绝产生两条日志。
			if sw.status == http.StatusForbidden {
				return
			}
			kind = eventError
			status = sw.status
			// 路径进的是抑制表的键（那张表最多 8192 条），而它的长度由请求方决定：
			// 不截断的话，一批各不相同的超长路径就能把这张"有界"的表撑到几个 GB。
			// 截短只会让超长路径共用一个去重窗口，那正是想要的效果。
			sig = childID + "\x00" + clampAccessField(r.URL.Path) + "\x00" + strconv.Itoa(sw.status)
			// 具体原因：优先取上游 err.Error()（ErrorHandler 捕获），
			// 回退到 http.StatusText（如后端直返 404/500 时无上游 err）。
			reason = sw.errMsg
			if reason == "" {
				reason = http.StatusText(status)
			}
		}
		// 注：链接状态（linkStatus）不再由逐请求驱动，改由周期主动探测 (runProbe) 统一写入，
		// 与真实流量、10/s 日志限速完全解耦；此处只负责「访问日志」三类事件的记录与限速。
		// 访问日志开关关闭：完全不写任何访问/连接/错误日志。
		if !logAccess {
			return
		}
		// 抑制：连接/断开按「IP + 子项」去重（同一 IP 访问不同服务各自独立计窗口，
		//   既避免单服务被同一 IP 刷屏，又不会吞掉其它子项的访问记录）；错误按签名去重。
		key := kind + "\x00" + ip + "\x00" + childID
		if kind == eventError {
			key = eventError + "\x00" + sig
		}
		if !m.suppressor.allow(key, now) {
			return
		}
		// 全局访问日志写速限速：每秒最多 logGlobalRPS 条。
		// 即便海量不同 IP 各自通过去重（每个都是新 key），实际落盘/入缓冲的写速也被压到该值，
		// 与抑制表、环形缓冲共同构成「内存有界 + 写速有界」双保险。
		if !m.logRate.allow(now) {
			return
		}
		entry := AccessEntry{
			Time:    now.UnixMilli(),
			ChildID: childID,
			Service: service,
			Method:  eventLabel(kind), // 前端「请求」列以事件类型标注
			// Host 与 Reason 的内容由请求方决定，进环形缓冲之前先截断（见 clampAccessField）。
			Host:   clampAccessField(r.Host),
			Status: status,
			DurMS:  dur,
			Remote: ip,
			Event:  kind,
			Reason: clampAccessField(reason),
		}
		m.recordAccess(entry)
		parent, child := splitService(service)
		switch kind {
		case eventConnect:
			m.log.Info(accessSentence("访问了", ip, parent, child, 0, ""), "childId", childID)
		case eventDisconnect:
			m.log.Info(accessSentence("断开了", ip, parent, child, 0, ""), "childId", childID)
		default: // eventError
			m.log.Warn(accessSentence("访问", ip, parent, child, status, reason), "childId", childID, "status", status)
		}
	})
}

func staticHandler(ch config.WebChild) http.Handler {
	root := ch.Static.Root
	// 防御性校验：即便配置绕过保存期校验，也拒绝把系统根目录或数据目录当作静态根暴露。
	// 比较前统一成正斜杠：Windows 上 filepath.Clean("/") 得到的是 `\`。
	clean := filepath.ToSlash(filepath.Clean(root))
	if vol := filepath.VolumeName(filepath.Clean(root)); vol != "" {
		// 盘符根：C:\ 与 C:（Clean 后成 "C:."）都要算。
		clean = strings.TrimPrefix(clean, filepath.ToSlash(vol))
		if clean == "" || clean == "." {
			clean = "/"
		}
	}
	if strings.TrimSpace(root) == "" || clean == "/" || clean == "." || clean == ".." ||
		clean == "/data" || strings.HasPrefix(clean, "/data/") {
		// 原因只进日志。这一页是给公网访客看的，写上"去哪个页面改哪个字段"等于
		// 把管理面的存在与位置告诉正在扫路径的人；管理员从日志与站点配置页都能看到真因。
		logx.L().Warn("静态站点的根目录配置不合法，该子项将对访客返回 500",
			"childId", ch.ID, "root", root)
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			errpage.Write(w, r, errpage.Page{
				Status: http.StatusInternalServerError,
				Title:  "站点配置不可用",
				Detail: "这个站点暂时无法提供服务。",
				Hint:   "请稍后再试，或联系站点管理员。",
			})
		})
	}
	index := ch.Static.Index
	if index == "" {
		index = "index.html"
	}
	site := &staticFiles{dir: http.Dir(root), index: index, spa: ch.Static.SPAFallback}
	if ch.Static.DirList {
		// 只有开了目录列表才用得上 FileServer——那页索引是它在这里唯一还有用的部分。
		site.lister = http.FileServer(site.dir)
	}
	return site
}

// staticFiles 提供静态站点的文件。刻意不把请求整个交给 http.FileServer：
//   - 路径先规范化再落到磁盘。原先 SPA 回退那步是 os.Stat(root + r.URL.Path)，
//     ".." 会把它带到站点外，于是响应码成了"这个绝对路径在宿主机上存不存在"的探针；
//   - 目录默认不列清单（列表会把备份文件、子目录一并交给访客）；
//   - 点开头的文件默认不发（.git/、.env 这类），.well-known 例外；
//   - 配置里那个 Index 文件名真正生效——FileServer 只认死了的 index.html。
type staticFiles struct {
	dir    http.Dir
	index  string
	spa    bool
	lister http.Handler // 非 nil 表示允许列目录
}

func (s *staticFiles) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	rel, ok := cleanSitePath(r.URL.Path)
	if !ok || hiddenSitePath(rel) {
		// 与"文件不存在"同一个出口：拒绝的理由不该从状态码里读出来。
		s.miss(w, r)
		return
	}
	f, st, err := s.open(rel)
	if err != nil {
		s.miss(w, r)
		return
	}
	defer f.Close()
	if st.IsDir() {
		// 目录必须带尾斜杠，否则页面内的相对链接会少拼一层（标准库同样这么跳）。
		if !strings.HasSuffix(r.URL.Path, "/") {
			redirectToDir(w, r)
			return
		}
		s.serveDir(w, r, rel)
		return
	}
	http.ServeContent(w, r, st.Name(), st.ModTime(), f)
}

// open 打开站点内的一个路径。走 http.Dir.Open 而不是自己拼字符串：它会把路径
// 收敛在根目录以内，并挡掉 Windows 上用反斜杠当分隔符的写法。
func (s *staticFiles) open(rel string) (http.File, os.FileInfo, error) {
	f, err := s.dir.Open(rel)
	if err != nil {
		return nil, nil, err
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, nil, err
	}
	return f, st, nil
}

// serveDir 处理命中目录的请求：先找本目录的 Index 文件，其次才考虑列清单。
func (s *staticFiles) serveDir(w http.ResponseWriter, r *http.Request, rel string) {
	if f, st, err := s.open(path.Join(rel, s.index)); err == nil {
		defer f.Close()
		if !st.IsDir() {
			http.ServeContent(w, r, st.Name(), st.ModTime(), f)
			return
		}
	}
	if s.lister != nil {
		s.lister.ServeHTTP(w, r)
		return
	}
	s.miss(w, r)
}

// miss 是所有"给不出这个路径"的统一出口：SPA 站回站点首页交给前端路由认路，
// 否则 404。
func (s *staticFiles) miss(w http.ResponseWriter, r *http.Request) {
	if s.spa {
		if f, st, err := s.open(s.index); err == nil {
			defer f.Close()
			if !st.IsDir() {
				http.ServeContent(w, r, st.Name(), st.ModTime(), f)
				return
			}
		}
	}
	http.NotFound(w, r)
}

// cleanSitePath 把请求路径规范化成站点内的相对路径；含 ".." 段一律判否。
// 浏览器发出请求前就会自己规范化掉 ".."，所以带着它到达的请求本就不是正常访问。
func cleanSitePath(p string) (string, bool) {
	if p == "" {
		return "/", true
	}
	for _, seg := range strings.Split(p, "/") {
		if seg == ".." {
			return "", false
		}
	}
	return path.Clean("/" + p), true
}

// hiddenSitePath 判断路径里有没有点开头的文件名。默认不发这类文件：静态根目录
// 常常就是一个项目目录，.git/config 与 .env 都在里面。.well-known 是公认的例外
// （证书校验、各类站点声明文件都放在那儿）。
func hiddenSitePath(rel string) bool {
	for _, seg := range strings.Split(rel, "/") {
		if len(seg) > 1 && seg[0] == '.' && seg != ".well-known" {
			return true
		}
	}
	return false
}

// redirectToDir 给目录补上尾斜杠，与标准库一致用 301。
func redirectToDir(w http.ResponseWriter, r *http.Request) {
	loc := r.URL.EscapedPath() + "/"
	if q := r.URL.RawQuery; q != "" {
		loc += "?" + q
	}
	w.Header().Set("Location", loc)
	w.WriteHeader(http.StatusMovedPermanently)
}

// maxUpstreamWeight 单个后端的权重上限：防止用户填入超大权重使加权展开表过度膨胀。
const maxUpstreamWeight = 128

// proxyMaxIdleConnsPerHost 反代到单个后端保持的最大空闲连接数。
// 标准库默认仅 2，反代高并发下会频繁新建/关闭到后端的连接；这里显式放大以复用连接、降低握手开销。
const proxyMaxIdleConnsPerHost = 128

// proxyCopyBufSize ReverseProxy 复制响应体所用缓冲区大小（与标准库默认值一致）。
const proxyCopyBufSize = 32 * 1024

// proxyBufferPool 为所有反代子项共享的响应体复制缓冲池。
// 标准库在 BufferPool 为 nil 时对「每个请求」都新分配 32 KB；高并发下这部分内存
// 全部落到堆上并推高 GC 频率。改为 sync.Pool 复用后，稳态分配量与并发数成正比而非请求数。
// 注意：走 sendfile/ReadFrom 快路径的响应不会用到这里的缓冲（无需分配）。
var proxyBufferPool = &bufferPool{
	pool: sync.Pool{New: func() any {
		b := make([]byte, proxyCopyBufSize)
		return &b
	}},
}

// bufferPool 实现 httputil.BufferPool。
type bufferPool struct {
	pool sync.Pool
}

func (p *bufferPool) Get() []byte {
	return *(p.pool.Get().(*[]byte))
}

func (p *bufferPool) Put(b []byte) {
	if cap(b) < proxyCopyBufSize {
		return // 非本池分配的短缓冲不回收，避免污染池内元素尺寸
	}
	b = b[:proxyCopyBufSize]
	p.pool.Put(&b)
}

// proxyHandler 构造反向代理处理器，并把它用的连接池一并交出去（见 buildChildHandler）。
func proxyHandler(log *logx.Logger, service string, ch config.WebChild) (http.Handler, *http.Transport) {
	// 收集有效后端及其权重：权重 ≤0 视为 1，并夹到上限，避免超大权重撑爆下方展开表。
	type upstream struct {
		url    *url.URL
		weight int
	}
	var ups []upstream
	for _, up := range ch.Upstreams {
		raw := strings.TrimSpace(up.URL)
		if raw == "" {
			continue
		}
		u, err := url.Parse(raw)
		if err != nil {
			continue
		}
		w := up.Weight
		if w <= 0 {
			w = 1
		} else if w > maxUpstreamWeight {
			w = maxUpstreamWeight
		}
		ups = append(ups, upstream{url: u, weight: w})
	}
	if len(ups) == 0 {
		// 同 staticHandler：真因进日志，页面上不提管理面。
		log.Warn("反向代理站点没有可用后端，该子项将对访客返回 502",
			"service", service, "childId", ch.ID)
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			errpage.Write(w, r, errpage.Page{
				Status: http.StatusBadGateway,
				Title:  "站点暂时不可用",
				Detail: "这个站点后面没有可以处理请求的服务。",
				Hint:   "请稍后再试，或联系站点管理员。",
			})
		}), nil
	}

	// 将后端按权重展开成一张选择表：权重为 n 的后端出现 n 次。
	// 轮询按序号取模、iphash 按客户端 IP 哈希取模，都落到此表即可同时兼顾「加权」。
	var ring []*url.URL
	for _, u := range ups {
		for k := 0; k < u.weight; k++ {
			ring = append(ring, u.url)
		}
	}

	// preserveHost=true 时透传客户端原始 Host；默认（false）改写为上游目标 Host。
	preserveHost := ch.Proxy.PreserveHost
	// trustProxy 决定客户端送来的 X-Forwarded-* 采信不采信（见下面 Director 里那段）。
	// 与入站侧的 HTTPS 判定用的是同一个开关（见 middleware.go 的 forwardedHTTPS）。
	trustProxy := ch.TrustProxyHeaders
	// iphash：同一来源 IP 稳定落到同一后端（会话保持）；其余（含空/roundrobin）按加权轮询。
	useIPHash := strings.EqualFold(strings.TrimSpace(ch.LB), "iphash")

	var idx uint32
	pick := func(req *http.Request) *url.URL {
		if len(ring) == 1 {
			return ring[0]
		}
		if useIPHash {
			return ring[hashString(ipx.RemoteHost(req.RemoteAddr))%uint32(len(ring))]
		}
		// 取模在 uint32 上做，不要先转 int：32 位平台上 int 是 32 位有符号数，
		// 计数器绕过 2^31 之后 int(i) 变负数，索引直接 panic（约 21 亿个请求一次，
		// 一个跑得久的站点是够得着的）。
		i := atomic.AddUint32(&idx, 1) - 1
		return ring[i%uint32(len(ring))]
	}

	proxy := &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			// 访客请求的那个 Host 要在改写之前存下来：X-Forwarded-Host 说的是
			// "访客访问的是哪个域名"，而 preserveHost 关着时 req.Host 一会儿就被
			// 换成上游地址了。
			origHost := req.Host
			t := pick(req)
			req.URL.Scheme = t.Scheme
			req.URL.Host = t.Host
			if !preserveHost {
				req.Host = t.Host
			}
			if t.Path != "" && t.Path != "/" {
				req.URL.Path = singleJoin(t.Path, req.URL.Path)
			}
			for k, v := range ch.Headers {
				req.Header.Set(k, v)
			}
			// 注入 X-Forwarded-*：让后端拿到真实客户端 IP（去掉端口）与原始协议/域名。
			//
			// 客户端自己送来的这几个头默认**不采信**：谁都能填，而后端普遍按"XFF 最左
			// 即原始客户端"读，于是原样往后追加等于让请求方自称是谁——后端的 IP 名单、
			// 限流、审计全部跟着失真，而这几样恰恰是它们该挡住的东西。
			// 只有开了「信任上游代理头」才说明 mantou 前面真有一层可信代理，
			// 那时才该保留它送来的链条（与入站侧的 HTTPS 判定同一个开关）。
			clientHost := ipx.RemoteHost(req.RemoteAddr)
			if prior := req.Header.Get("X-Forwarded-For"); trustProxy && prior != "" {
				req.Header.Set("X-Forwarded-For", prior+", "+clientHost)
			} else {
				req.Header.Set("X-Forwarded-For", clientHost)
			}
			proto := "http"
			if req.TLS != nil {
				proto = "https"
			}
			if trustProxy {
				if given := forwardedProto(req.Header.Get("X-Forwarded-Proto")); given != "" {
					proto = given
				}
			}
			req.Header.Set("X-Forwarded-Proto", proto)
			if origHost != "" {
				req.Header.Set("X-Forwarded-Host", origHost)
			}
			if !trustProxy {
				// 同一件事的另外两种写法：nginx 系的后端读 X-Real-IP，
				// RFC 7239 的读 Forwarded。只按住 XFF 而放这两个原样过去，等于没按住。
				req.Header.Set("X-Real-IP", clientHost)
				req.Header.Del("Forwarded")
			}
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			// 客户端主动断开（context canceled 等）属正常行为：不回写 502、不告警，
			// 交由 instrument 记为「断开」事件，避免误报为后端错误。
			if isClientAbort(err) {
				if sw, ok := w.(*statusWriter); ok {
					sw.clientAborted = true
				}
				return
			}
			// 真实后端错误：回写 502 给客户端；不在此告警，统一由 instrument 以「错误」
			// 事件记录（按签名去重），避免与访问日志重复记录而刷屏。
			// 同时捕获 err.Error() 到 sw.errMsg，供 instrument 写入 Reason 字段。
			if sw, ok := w.(*statusWriter); ok {
				sw.errMsg = err.Error()
			}
			// 刻意不把 err.Error() 印到页面上：那句话里带着后端的内网地址与端口，
			// 而这一页是对公网访客展示的。原因照常进访问日志与「错误」事件（sw.errMsg）。
			errpage.Write(w, r, errpage.Page{
				Status: http.StatusBadGateway,
				Title:  "后端暂时不可用",
				Detail: "站点收到了你的请求，但它后面的服务没有正常响应。",
				Hint:   "请稍后再试，或联系站点管理员。",
			})
		},
	}

	// 上游把朴素错误（如后端 Go 程序的 "404 page not found"）原样透传上来时，
	// 换成统一卡片页。改写的门槛全在 errpage.Rewritable 里：接口调用、
	// 后端自带的错误页、流式与大响应体一律不动，见那里的四道闸。
	proxy.ModifyResponse = errpage.RewriteUpstream

	// 统一设置连接池（无论是否忽略后端证书校验），显式放大每后端空闲连接数。
	// MaxIdleConns 是「全局」上限，若小于 MaxIdleConnsPerHost×后端数，多后端场景下
	// 会先撞上全局上限而把刚放回池的连接直接关掉（每后端 128 永远达不到），
	// 表现为高并发下持续重建后端连接。这里按实际后端数推导，保证两者不互相掐死，
	// 同时仍是确定性上界（不用 0/无限制，避免空闲连接无边界占用内存与后端句柄）。
	idleHosts := make(map[string]struct{}, len(ups))
	for _, u := range ups {
		idleHosts[u.url.Host] = struct{}{}
	}
	maxIdleConns := proxyMaxIdleConnsPerHost * len(idleHosts)
	transport := &http.Transport{
		// 刻意不用 http.ProxyFromEnvironment：反代的上游多半在内网，而宿主机上的
		// HTTP_PROXY / HTTPS_PROXY / ALL_PROXY 通常是给别的用途设的（机场、公司网关）。
		// 采信它等于把本该直连内网的流量静默拐进一个第三方代理——请求头里带着
		// Basic 认证与业务令牌，而界面上没有任何地方看得出这件事。
		Proxy:                 nil,
		DialContext:           (&net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          maxIdleConns,
		MaxIdleConnsPerHost:   proxyMaxIdleConnsPerHost,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
	if ch.Proxy.InsecureSkipVerify {
		// 忽略后端 TLS 证书校验（自签后端场景），由用户显式开启。
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec
	}
	proxy.Transport = transport
	proxy.BufferPool = proxyBufferPool
	return proxy, transport
}

// hashString 返回字符串的 FNV-1a 32 位哈希，用于 iphash 负载均衡按来源稳定分桶。
func hashString(s string) uint32 {
	const (
		offset32 = 2166136261
		prime32  = 16777619
	)
	h := uint32(offset32)
	for i := 0; i < len(s); i++ {
		h ^= uint32(s[i])
		h *= prime32
	}
	return h
}

// forwardedProto 读上游代理声明的协议，只认 http / https 两个值，其余（空串、
// 逗号链、随手填的垃圾）一律返回空串交回调用方兜底。
// 只在子项开了「信任上游代理头」时才会被调用。
func forwardedProto(v string) string {
	p := strings.ToLower(strings.TrimSpace(strings.SplitN(v, ",", 2)[0]))
	if p == "http" || p == "https" {
		return p
	}
	return ""
}

// redirectHandler 依据配置发起 30x 跳转，可选保留原始路径与查询串。
func redirectHandler(ch config.WebChild) http.Handler {
	target := strings.TrimSpace(ch.Redirect.Target)
	code := ch.Redirect.Code
	switch code {
	case 301, 302, 307, 308:
	default:
		code = http.StatusFound // 302
	}
	keepPath := ch.Redirect.KeepPath
	keepQuery := ch.Redirect.KeepQuery
	if target == "" {
		// 同 staticHandler：真因进日志，页面上不提管理面。
		logx.L().Warn("跳转站点没有填目标地址，该子项将对访客返回 500", "childId", ch.ID)
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if target == "" {
			errpage.Write(w, r, errpage.Page{
				Status: http.StatusInternalServerError,
				Title:  "站点配置不可用",
				Detail: "这个站点暂时无法提供服务。",
				Hint:   "请稍后再试，或联系站点管理员。",
			})
			return
		}
		loc := target
		// 用 EscapedPath 而不是 Path：Path 是解码后的形态，拿它拼跳转地址会把
		// 段内的 %2F 变成真的斜杠（/a%2Fb → /a/b），到了目标那边就是另一个路径。
		if p := r.URL.EscapedPath(); keepPath && p != "" && p != "/" {
			loc = singleJoin(strings.TrimRight(target, "/"), p)
		}
		if keepQuery && r.URL.RawQuery != "" {
			if strings.Contains(loc, "?") {
				loc += "&" + r.URL.RawQuery
			} else {
				loc += "?" + r.URL.RawQuery
			}
		}
		http.Redirect(w, r, loc, code)
	})
}

// statusWriter 包裹 ResponseWriter 以捕获状态码，同时透传 Flush/Hijack，
// 保证流式响应与 WebSocket 升级（反向代理）不受影响。
type statusWriter struct {
	http.ResponseWriter
	status        int
	wrote         bool
	clientAborted bool   // 反向代理过程中客户端主动断开（context canceled 等）
	errMsg        string // 上游错误原文（ErrorHandler 捕获的 err.Error()），供 instrument 写入 AccessEntry.Reason
}

func (s *statusWriter) WriteHeader(code int) {
	if !s.wrote {
		s.status = code
		s.wrote = true
	}
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusWriter) Write(b []byte) (int, error) {
	if !s.wrote {
		s.wrote = true
	}
	return s.ResponseWriter.Write(b)
}

func (s *statusWriter) Flush() {
	if f, ok := s.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// ReadFrom 把响应体复制委托给底层 ResponseWriter 的 io.ReaderFrom 实现。
// 这对静态文件服务至关重要：net/http 的 *response 实现了 io.ReaderFrom，当源是 *os.File
// 时会走 sendfile(2) 零拷贝；若包装层只提供 Write，http.ServeContent 内部的 io.Copy 就会
// 退化为「用户态 32 KB 缓冲循环」，大文件下载的吞吐与 CPU 占用都明显变差。
func (s *statusWriter) ReadFrom(src io.Reader) (int64, error) {
	if !s.wrote {
		s.wrote = true
		if s.status == 0 {
			s.status = http.StatusOK
		}
	}
	if rf, ok := s.ResponseWriter.(io.ReaderFrom); ok {
		return rf.ReadFrom(src)
	}
	return io.Copy(s.ResponseWriter, src)
}

// Unwrap 供 http.ResponseController 穿透包装层访问底层 ResponseWriter，
// 使 SetReadDeadline/SetWriteDeadline/Flush 等控制接口在被包装后依然生效（Go 1.20+）。
func (s *statusWriter) Unwrap() http.ResponseWriter { return s.ResponseWriter }

func (s *statusWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if hj, ok := s.ResponseWriter.(http.Hijacker); ok {
		return hj.Hijack()
	}
	return nil, nil, fmt.Errorf("底层 ResponseWriter 不支持 Hijack")
}

func singleJoin(a, b string) string {
	aslash := len(a) > 0 && a[len(a)-1] == '/'
	bslash := len(b) > 0 && b[0] == '/'
	switch {
	case aslash && bslash:
		return a + b[1:]
	case !aslash && !bslash:
		return a + "/" + b
	}
	return a + b
}
