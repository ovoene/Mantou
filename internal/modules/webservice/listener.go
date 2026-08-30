package webservice

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"golang.org/x/net/netutil"

	"mantou/internal/errpage"
	"mantou/internal/logx"
)

// 本文件是 webservice 的监听层：一个 listenServer == 一个 (地址族, 端口) 监听。
// 负责地址绑定、TLS 装配、并发连接数上限，以及把请求按 Host 分流到对应子项的处理器。

// listenServer 是绑定在单个 (族, 端口) 上的 HTTP(S) 服务，按前端地址（域名）分发到具体子项。
type listenServer struct {
	family    string
	port      int
	addr      string // 实际绑定地址（仅用于日志）
	tls       bool
	tlsMinVer uint16 // TLS 最低版本（0 表示用 Go 默认）
	resolver  CertResolver
	log       *logx.Logger

	// 域名 → 处理器；空域名作为默认处理器。
	routes  map[string]http.Handler
	defawlt http.Handler
	// defaultOwner 默认处理器归哪个子项，仅用于"多个子项都想当默认"时的告警去重。
	defaultOwner string

	srv    *http.Server
	ln     net.Listener
	failed atomic.Bool
	sig    string // 配置指纹，用于 Reload 时判断是否需要重建该监听
	// conns 本监听当下握着的连接台账，停机时用它把关不掉的连接（尤其是被 Hijack 过的
	// WebSocket）兜底关掉，见 close 与 conntrack.go。
	conns *connTracker
	// idle 本监听下各反代子项的连接池，close 时逐个关掉其中的空闲连接。
	// 只在构造时写入，close 时只读，故不需要加锁。
	idle []idleCloser
}

func newListenServer(g *wsGroup, resolver CertResolver, m *Module, log *logx.Logger) *listenServer {
	ls := &listenServer{
		family:    g.family,
		port:      g.port,
		tls:       g.useTLS,
		tlsMinVer: g.minVer,
		resolver:  resolver,
		log:       log,
		routes:    make(map[string]http.Handler),
		conns:     newConnTracker(),
	}
	for _, b := range g.bindings {
		h, idle := buildChildHandler(m, b.service, b.child)
		if idle != nil {
			ls.idle = append(ls.idle, idle)
		}
		if len(b.child.Domains) == 0 {
			ls.setDefault(h, b.service, b.child.ID)
			continue
		}
		for _, d := range b.child.Domains {
			d = routeKey(d)
			if d == "" {
				ls.setDefault(h, b.service, b.child.ID)
				continue
			}
			ls.routes[d] = h
		}
	}
	// 外部模块（消息路由）挂在本监听上的域名路由。放在子项之后覆盖同名键没有意义——
	// 域名唯一性由保存期校验保证，这里撞车只可能来自手改配置，让后写的赢即可。
	for _, e := range g.extRoutes {
		if h := m.externalHandler(e.owner); h != nil {
			ls.routes[routeKey(e.domain)] = h
		}
	}
	return ls
}

// routeKey 归一化域名路由键。域名大小写不敏感（RFC 4343），而 Host 头里的大小写由客户端决定：
// 键与查询都折成小写，才不会出现"配了 Hook.example.com、第三方按小写发过来就 404"。
func routeKey(d string) string { return strings.ToLower(strings.TrimSpace(d)) }

// setDefault 设置本监听的默认处理器（没填访问域名的子项，或域名填成了空串）。
//
// 同一个端口上只该有一个这样的子项。真有两个时，谁最后赢由 g.bindings 的顺序决定，
// 而用户看到的是"两个站点里只有一个能打开、另一个像不存在"——两边配置页上都是绿的，
// 没有任何地方能看出被顶掉了。保存时已经把这种组合拦下了（见 validateWebService），
// 走到这里只可能是手改过配置文件，所以照旧让后来的赢，但必须留一条说得清的日志。
func (ls *listenServer) setDefault(h http.Handler, service, childID string) {
	if ls.defawlt != nil && ls.defaultOwner != childID {
		ls.log.Warn("同一端口上有多个未填访问域名的子项，只有最后一个会生效",
			"port", ls.port, "family", ls.family, "service", service, "childId", childID)
	}
	ls.defawlt = h
	ls.defaultOwner = childID
}

func (ls *listenServer) healthy() bool { return !ls.failed.Load() }

func (ls *listenServer) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 请求体停滞超时（见 conntrack.go）。装在最外层：这里的 w 还是 Server 交出来的
		// 原始 ResponseWriter，读超时能落到连接上。
		guardBodyRead(w, r)
		host := r.Host
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		if h, ok := ls.routes[routeKey(host)]; ok {
			h.ServeHTTP(w, r)
			return
		}
		if ls.defawlt != nil {
			ls.defawlt.ServeHTTP(w, r)
			return
		}
		writeSiteNotFound(w, r, host)
	})
}

// writeSiteNotFound 「未匹配到站点」。页面本体在 internal/errpage——面板、Web 服务、
// 消息路由三处的错误页从前各写各的，用户撞上哪个都看不出这是同一个系统。
func writeSiteNotFound(w http.ResponseWriter, r *http.Request, host string) {
	display := host
	if display == "" {
		display = "未知主机"
	}
	errpage.Write(w, r, errpage.Page{
		Status: http.StatusNotFound,
		Title:  "未匹配到站点",
		Detail: "这个主机名暂无对应的站点配置。",
		Hint:   "请检查访问用的域名 / IP 是否正确。",
		Where:  display,
	})
}

func (ls *listenServer) start() error {
	network, bindAddr := bindTarget(ls.family, ls.port)
	ls.addr = bindAddr
	ls.srv = &http.Server{
		Handler:           ls.handler(),
		ReadHeaderTimeout: 15 * time.Second,
		// 主动回收空闲 keep-alive 连接，避免慢速/挂起客户端长期占用连接与 goroutine
		// （资源耗尽型风险）。注意：刻意不设置 ReadTimeout/WriteTimeout，
		// 以免大文件上传/下载或慢速传输被中途掐断——企业系统传大附件时尤为关键。
		// 由此留下的缺口（正文发一半就不动了）由请求体停滞超时补上，见 guardBodyRead。
		IdleTimeout: 120 * time.Second,
		ErrorLog:    ls.log.Standard(slog.LevelWarn, "Web TLS 或连接异常"),
	}

	ln, err := net.Listen(network, bindAddr)
	if err != nil {
		ls.failed.Store(true)
		return err
	}
	// 并发连接上限：把「内存占用由对端决定」变成可预算的确定值。
	// 每条 HTTP 连接约 20 KB（读写缓冲 + goroutine 栈），HTTPS 约 32 KB，
	// 因此 2000 的上界对应约 40–64 MB，落在 README 给出的内存预算内；
	// 不加限制时一次压测或扫描就能把 RSS 推到 OOM。
	// LimitListener 在达到上限时让 Accept 阻塞（连接留在内核 backlog 里等待，
	// 而不是被立刻拒绝），对 HTTP 语义合适：客户端按自己的超时决定是否放弃。
	// 也正因为超限是"阻塞"而不是"拒绝"，一批赖着不走的连接就能让正常访客连不进来——
	// 那个缺口由请求体停滞超时补上（见 guardBodyRead）。
	//
	// 台账套在最外层：停机时要拿着这些连接自己关（见 close）。
	ln = ls.conns.wrap(netutil.LimitListener(ln, maxConnsPerListener))
	ls.ln = ln
	ls.failed.Store(false)

	if ls.tls {
		ls.srv.TLSConfig = &tls.Config{
			MinVersion: ls.tlsMinVer,
			GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
				if ls.resolver != nil {
					if cert, ok := ls.resolver(hello.ServerName); ok {
						return cert, nil
					}
				}
				return nil, fmt.Errorf("无可用证书: %s", hello.ServerName)
			},
		}
		go func() {
			if err := ls.srv.ServeTLS(ln, "", ""); err != nil && err != http.ErrServerClosed {
				ls.failed.Store(true)
				ls.log.Warn("Web(HTTPS) 服务退出", "addr", ls.addr, "err", err.Error())
			}
		}()
	} else {
		go func() {
			if err := ls.srv.Serve(ln); err != nil && err != http.ErrServerClosed {
				ls.failed.Store(true)
				ls.log.Warn("Web 服务退出", "addr", ls.addr, "err", err.Error())
			}
		}()
	}
	ls.log.Info("Web 服务已启动", "addr", ls.addr, "family", ls.family, "tls", ls.tls)
	return nil
}

// bindTarget 依据地址族返回监听网络与绑定地址：
// v4 → tcp4/0.0.0.0:port（仅 IPv4）；v6 → tcp6/[::]:port（仅 IPv6）；both → tcp/:port（双栈）。
func bindTarget(family string, port int) (string, string) {
	switch family {
	case "v4":
		return "tcp4", fmt.Sprintf("0.0.0.0:%d", port)
	case "v6":
		return "tcp6", fmt.Sprintf("[::]:%d", port)
	default:
		return "tcp", fmt.Sprintf(":%d", port)
	}
}

func (ls *listenServer) close() {
	if ls.srv != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := ls.srv.Shutdown(ctx); err != nil {
			// 5 秒内没停干净：有请求还在跑，或者有 WebSocket 这类升级过的长连接。
			// Shutdown 超时返回时**不会**去动那些连接，只靠它这个监听会一直活着——
			// 端口占着不放（新配置起不来，界面上是「地址已被占用」），旧配置的处理器
			// 还在继续服务请求（用户刚改的 IP 名单、刚关掉的站点仍然生效）。
			_ = ls.srv.Close()
		}
	}
	if ls.ln != nil {
		_ = ls.ln.Close()
	}
	// 收尾：把仍然握在手里的连接全关掉。srv.Close 关不到被 Hijack 过的连接——
	// WebSocket 升级之后那条连接就从 Server 的账本上摘掉了，而反代是支持 WebSocket 的，
	// 所以这类连接一定会有。不自己记一份台账，改一次配置就漏一批连接（见 conntrack.go）。
	if n := ls.conns.closeAll(); n > 0 {
		ls.log.Warn("停止 Web 监听时强制关闭了仍未结束的连接", "addr", ls.addr, "count", n)
	}
	// 主动关掉丢弃的连接池。Go 不会因为 Transport 成了垃圾就关掉它池子里的空闲连接，
	// 那些 socket 要等 IdleConnTimeout（90 秒）到期才关。监听是按端口重建的，改一次
	// 配置这个端口下的全部子项都要重来，于是每次保存都滞留一批句柄，本地与后端两侧
	// 各最多 128 × 后端数；反复调参数时表现为句柄数阶梯式堆高再慢慢回落。
	//
	// 位置在 Shutdown 之后，但顺序其实不敏感：CloseIdleConnections 除了关掉当下空闲的
	// 连接，还会给 Transport 记上一笔"往后变空闲的也一并关掉"，在途请求做完后归还的
	// 那条同样会被关。只有一种情形两者有别——这笔标记会被"又来了新请求"清掉，放在
	// Shutdown 之后就不必去想还有没有请求能挤进停机窗口。
	for _, c := range ls.idle {
		c.CloseIdleConnections()
	}
}
