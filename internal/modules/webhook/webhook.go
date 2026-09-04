// Package webhook 是消息路由模块：接收第三方系统推来的 Webhook，
// 按条件命中规则、用模板渲染成消息，再交给 notify 模块投递到钉钉 / 企业微信 / 自定义 HTTP。
//
// 全部行为由配置驱动，代码里没有任何一家来源系统的字段名——
// 消息来源不止一家，各家的载荷结构完全不同，写死任何一家的结构都会让这个模块只对那一家有用。
//
// 分工：
//
//	match.go     路径取值与条件匹配
//	receiver.go  配置 → 运行态（预编译正则 / 模板 / 名单 / 限流桶）
//	event.go     HTTP 请求 → 内部事件信封
//	process.go   条件命中 → 渲染 → 决定目标（无副作用，试运行与真实请求共用）
//	handler.go   入站 HTTP：鉴权、限流、体积校验、派发
//	testrun.go   实时试运行（只抓包不投递）的状态机
//	history.go   执行历史（内存环 + 日志文件）与调试包
//	webhook.go   模块生命周期与独立监听
package webhook

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/netutil"

	"mantou/internal/config"
	"mantou/internal/inboundfw"
	"mantou/internal/ipx"
	"mantou/internal/logx"
	"mantou/internal/module"
	"mantou/internal/modules/notify"
)

// maxConns 本模块监听的并发连接上限。
// 与 webservice 同口径：把"内存占用由对端决定"变成可预算的确定值。
// 入站 Webhook 的正常并发是个位数，512 已经远超真实需要。
const maxConns = 512

// Notifier 出站能力，由 notify 模块实现。
// 用接口而不是直接依赖 *notify.Module：本模块的测试要能在不起 4 个 worker 的前提下跑。
type Notifier interface {
	Enqueue(req notify.Request) error
	Targets() map[string]string
}

// CertResolver 按证书 ID 取证书，由 cert 模块实现。
type CertResolver func(id string) (*tls.Certificate, bool)

// StatsWriter 记接收器的统计：收下多少条、被挡掉多少条、最近一次是什么时候。
// 由 runstats.Store 实现，数字只在内存里、重启归零（原因见 runstats 包说明）。
//
// 原先这里声明的是 config 的运行态回写方法，统计跟着配置条目一起存。问题是这条路
// 每条入站请求都要走一次、频率由公网决定，而每次都要换一份配置、涨一次 rev、
// 等一次落盘——全局只有一把配置写锁，外面推得越快面板越卡。统计既然没有任何逻辑
// 会读，就没有理由为它付这个代价。
//
// 收下与被挡掉分成两个方法，而不是一个带布尔的方法：被挡掉的那条**不该**碰
// 「最近收到」的时刻与结果文本（见 runstats.Store.Rejected），签名分开之后，
// 调用方没法把它们混起来写。
type StatsWriter interface {
	Received(id string, at int64, status string)
	Rejected(id string)
}

// listenSpec 监听的全部决定因素。
// 单独抽出来是为了让 Reload 能判断"这次保存要不要重启监听"——
// 每次保存都重启会掐断正在传输的请求，而配置保存在实际使用中远比推消息频繁。
type listenSpec struct {
	enabled bool
	addr    string
	port    int // 与 addr 里的端口一致，单独存一份供 ReleasePort 比对，省得回头解析地址
	tls     bool
	certID  string
	domain  string
	// shared 表示这个端口由 Web 服务的监听持有，本模块只是挂在它上面的一条 Host 路由
	// （见 config.WebhookSharesWebServicePort）。此时不能自己 net.Listen——
	// 那是抢同一个端口，谁先绑谁赢、另一个报「地址已被占用」。
	shared bool
}

// Module 消息路由模块。
type Module struct {
	log     *logx.Logger
	stats   StatsWriter
	logPath string

	notifier atomic.Pointer[Notifier]
	certs    atomic.Pointer[CertResolver]

	// routes 路由表整体替换。用 atomic 而非锁：请求路径上只读它，
	// 而 Reload 极罕见——读路径不该为此付一次加锁。
	routes atomic.Pointer[routeTable]

	hist  *history
	tests *testRunStore
	// sources 被拒收 / 被丢弃的入站原文留存（见 source.go）。只在内存里。
	sources *sourceStore
	// anon 给"没有接收器可归属的拒收"发放记录配额（见 anonlimit.go）。
	anon *anonRecorder
	// rejQuota 给"路由到接收器之后的拒收"发放记录配额，每接收器一份（见 anonlimit.go）。
	// 与 limiter 同样挂在模块上，跨配置保存存活。
	rejQuota *rejectQuota
	// gate 入站并发闸：单条请求的体积有上限，同时在处理的条数也要有（见 inflight.go）。
	gate inflightGate
	// limiter 每 IP 限流的桶表，全部接收器共用一张（桶键 = 接收器 ID + 来源 IP）。
	//
	// 挂在模块上而不是路由表上，因此**跨配置保存存活**：跟着路由表重建的话，
	// 保存一次配置就等于把所有来源的令牌重新加满，正在被限流的一方只要等用户
	// 保存一次就能重新开跑。
	limiter *ipx.IPLimiter

	mu      sync.Mutex
	spec    listenSpec
	srv     *http.Server
	ln      net.Listener
	lastErr string
	closed  bool
	// globalFirewall 服务防护（连接层）的运行态，由 app 装配时注入（见 SetGlobalFirewall）。
	// 它保护本模块独立端口的入站连接，与面板入站防护是两套独立机制。
	globalFirewall *inboundfw.Firewall

	received atomic.Int64
	rejected atomic.Int64
	dropped  atomic.Int64
}

// New 创建模块。logPath 是执行历史的日志文件路径（data/logs/webhook.log）。
func New(log *logx.Logger, stats StatsWriter, logPath string) *Module {
	m := &Module{
		log:      log,
		stats:    stats,
		logPath:  logPath,
		hist:     newHistory(logx.DefaultLogEntries),
		tests:    newTestRunStore(),
		sources:  newSourceStore(),
		anon:     newAnonRecorder(),
		rejQuota: newRejectQuota(),
		limiter:  ipx.NewIPLimiter(),
	}
	m.routes.Store(&routeTable{
		byPath:    map[string]*receiverRT{},
		byPathAll: map[string]*receiverRT{},
	})
	return m
}

// SetNotifier 注入出站能力。由 app 装配时调用一次。
func (m *Module) SetNotifier(n Notifier) { m.notifier.Store(&n) }

// SetCertResolver 注入证书解析器。
func (m *Module) SetCertResolver(r CertResolver) { m.certs.Store(&r) }

// SetGlobalFirewall 注入服务防护（连接层）。由 app 装配时调用一次。
//
// 只存指针：封禁表是全局唯一的，Web 服务与消息路由共享同一份，跨 Reload 存活。
// 注入缺失时监听退化为不拦截（见 startListen 的 nil 处理），不影响正常服务。
func (m *Module) SetGlobalFirewall(f *inboundfw.Firewall) {
	m.mu.Lock()
	m.globalFirewall = f
	m.mu.Unlock()
}

// firewall 取当前注入的防火墙。**调用方不得持有 m.mu**（本函数自己要取）。
// 起监听时只在这里读一次，把值传给下面两处使用点，见 startListen。
func (m *Module) firewall() *inboundfw.Firewall {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.globalFirewall
}

// Name 实现 module.Module。
func (m *Module) Name() string { return "webhook" }

// Reload 应用配置。不修改传入的 cfg。
func (m *Module) Reload(cfg *config.Config) error {
	table := compileAll(cfg)
	m.routes.Store(table)

	// 试运行只按"接收器还在不在"清理，不看启用状态：停用的接收器正是要能开着试运行调路径。
	// 删掉一个接收器时它抓到的那份完整载荷必须立刻消失，而不是等进程重启。
	alive := make(map[string]struct{}, len(cfg.WebhookReceivers))
	for _, r := range cfg.WebhookReceivers {
		alive[r.ID] = struct{}{}
	}
	m.tests.keep(alive)

	m.hist.setCap(cfg.Settings.Log.MaxEntries)
	m.syncLogFile(cfg.Settings.Log.MaxEntries)

	// 原文留存的额度跟着「模块设置 → 原文留存」走（0 表示不留存）。
	// 与上面那行 setCap 同一个位置、同一个道理：这是个用户随时会改的数，
	// 而生效点必须是保存配置的那一刻——放到"下一条消息进来时再读一遍"上，
	// 用户在界面上看不出自己刚才那一下有没有起作用。
	m.sources.setBudget(cfg.Webhook.SourceRetainMB << 20)

	// 只报启用中的接收器：停用的那份可能正处在"还没配完"的中间状态
	// （用户就是为此才先停用），每次 Reload 都刷一遍它的告警只会淹掉真正的问题。
	for _, r := range table.list {
		if !r.cfg.Enabled {
			continue
		}
		for _, w := range r.warnings {
			m.log.Warn("消息路由配置存在问题", "receiver", r.cfg.Name, "detail", w)
		}
	}

	return m.applyListen(cfg)
}

// syncLogFile 首次需要时打开历史日志文件，之后只同步行数上限。
//
// 行数跟着「设置 → 日志 → 日志最大条数」走，与程序日志、访问日志共用同一个数字
// （见 logx.MinLogEntries 那段说明）。打不开只记一条警告：内存历史仍然可用，
// 不该因为磁盘写不了就让整个模块起不来；下次保存配置还会再试一次。
func (m *Module) syncLogFile(maxEntries int) {
	if m.logPath == "" {
		return
	}
	if f := m.hist.logFile(); f != nil {
		f.SetMaxEntries(maxEntries)
		return
	}
	f, err := logx.NewRotatingFile(m.logPath, maxEntries)
	if err != nil {
		m.log.Warn("消息路由历史日志文件打不开，仅保留内存历史", "path", m.logPath, "err", err.Error())
		return
	}
	m.hist.setFile(f)
}

// applyListen 依据配置启停监听。
func (m *Module) applyListen(cfg *config.Config) error {
	want := listenSpec{
		enabled: cfg.Webhook.Enabled,
		addr:    fmt.Sprintf("%s:%d", listenHost(cfg.Webhook.Listen), cfg.Webhook.Port),
		port:    cfg.Webhook.Port,
		tls:     cfg.Webhook.HTTPS.Enabled,
		certID:  cfg.Webhook.HTTPS.CertID,
		domain:  cfg.Webhook.Domain,
		shared:  cfg.WebhookSharesWebServicePort(),
	}

	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return nil
	}
	same := m.spec == want && (m.srv != nil) == (want.enabled && !want.shared)
	m.mu.Unlock()
	if same {
		return nil
	}

	m.stopListen()

	m.mu.Lock()
	m.spec = want
	m.lastErr = ""
	m.mu.Unlock()

	if !want.enabled {
		m.log.Info("消息路由未启用，不监听")
		return nil
	}
	// 共享端口：Web 服务的监听会按域名把请求转进 m.handler()，这里什么都不做。
	// spec 仍然记下来——serve 靠它校验 Host，Status 靠它显示监听情况。
	if want.shared {
		m.log.Info("消息路由与 Web 服务共用监听", "addr", want.addr, "domain", want.domain)
		return nil
	}
	return m.startListen(want)
}

// Handler 返回入站处理器，供 Web 服务在共享端口上按域名转发。
//
// 每次调用返回一个新的 HandlerFunc 值，但它们的行为完全一致（都指向 m.serve），
// 所以 Web 服务可以在任意时刻取一次并长期持有。
func (m *Module) Handler() http.Handler { return m.handler() }

// ReleasePort 让出端口：本模块此刻正独占监听 port 时关掉它，返回是否真的让了。
//
// 由 Web 服务在绑定共享端口之前调用（原因见 webservice.WebhookPeer 的说明）。
// 刻意不动 m.spec：本模块的 Reload 紧跟在后面，applyListen 会照配置重新判定共享与否，
// 那时 spec.shared 由 false 变 true，与 want 不同，不会被"配置没变"的快速路径跳过。
func (m *Module) ReleasePort(port int) bool {
	m.mu.Lock()
	holding := m.srv != nil && m.spec.port == port
	m.mu.Unlock()
	if !holding {
		return false
	}
	m.stopListen()
	m.log.Info("消息路由让出端口，改由 Web 服务按域名转发", "port", port)
	return true
}

// listenHost 监听地址固定 0.0.0.0（与面板同口径，不在 UI 暴露）。
func listenHost(s string) string {
	if s = strings.TrimSpace(s); s != "" {
		return s
	}
	return "0.0.0.0"
}

// startListen 起监听。
//
// **启用 HTTPS 时不存在明文回落**：证书取不到或域名没被覆盖，就干脆不监听，
// 并把原因记进 lastErr（总览页与模块状态可见）。回落成明文会让一个
// 以为自己在用 HTTPS 的用户把令牌与业务数据裸奔在网上——那比"服务没起来"严重得多。
func (m *Module) startListen(spec listenSpec) error {
	// 防火墙指针在锁内取一次，后面两处都用这个局部变量。
	// 直接读 m.globalFirewall 是数据竞争：写它的 SetGlobalFirewall 持 m.mu，而本函数的调用方
	// applyListen 在调进来之前已经把锁放掉了（它必须放——起监听要花时间，不能占着模块锁）。
	// 实际装配顺序下这个竞争碰不上（注入只在启动时发生一次，早于任何 Reload），
	// 但 -race 会报，而且"取两次可能取到不同值"本身就是个说不清的状态。
	fw := m.firewall()

	srv := &http.Server{
		Handler:           m.handler(),
		ReadHeaderTimeout: 15 * time.Second,
		// 入站 Webhook 的请求体已有 MaxBodyKB 上限，读整个体不该超过 30 秒；
		// 与 webservice 不同，这里没有大文件传输场景，所以敢设 ReadTimeout。
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
		// fw 为 nil 时 WrapErrorLog 原样返回 base：未注入防火墙等于不拦截，日志行为不变。
		ErrorLog: fw.WrapErrorLog(m.log.Standard(slog.LevelWarn, "消息路由 TLS 或连接异常")),
	}

	if spec.tls {
		tlsCfg, err := m.tlsConfig(spec)
		if err != nil {
			m.setErr(err.Error())
			m.log.Error("消息路由 HTTPS 无法启动（已启用 HTTPS，不会回落明文）", "err", err.Error())
			return nil // 不返回错误：这是配置问题，不该触发模块回滚
		}
		srv.TLSConfig = tlsCfg
	}

	ln, err := net.Listen("tcp", spec.addr)
	if err != nil {
		m.setErr(err.Error())
		m.log.Error("消息路由监听失败", "addr", spec.addr, "err", err.Error())
		return nil
	}
	// 服务防护（连接层）夹在 LimitListener 与原始 listener 之间：Accept 处先按封禁/名单拦截，
	// 被拒的连接不会进入 LimitListener 的并发连接计数。共享端口由 Web 服务持有、本模块不绑监听，
	// 那份连接由 Web 服务那一侧的防火墙覆盖，不会漏。
	// fw 为 nil 时 Wrap 原样返回 ln。
	ln = netutil.LimitListener(fw.Wrap(ln), maxConns)

	m.mu.Lock()
	m.srv = srv
	m.ln = ln
	m.mu.Unlock()

	go func() {
		var serveErr error
		if spec.tls {
			serveErr = srv.ServeTLS(ln, "", "")
		} else {
			serveErr = srv.Serve(ln)
		}
		if serveErr != nil && serveErr != http.ErrServerClosed {
			m.setErr(serveErr.Error())
			m.log.Warn("消息路由服务退出", "addr", spec.addr, "err", serveErr.Error())
		}
	}()

	m.log.Info("消息路由已启动", "addr", spec.addr, "https", spec.tls, "receivers", m.routes.Load().active)
	return nil
}

// tlsConfig 取证书并校验域名。
func (m *Module) tlsConfig(spec listenSpec) (*tls.Config, error) {
	resolver := m.certs.Load()
	if resolver == nil || *resolver == nil {
		return nil, fmt.Errorf("证书模块不可用")
	}
	cert, ok := (*resolver)(spec.certID)
	if !ok {
		return nil, fmt.Errorf("证书 %s 无法加载（可能已被删除或停用）", spec.certID)
	}
	if spec.domain == "" {
		return nil, fmt.Errorf("启用 HTTPS 必须填写访问域名")
	}
	leaf, err := certLeaf(cert)
	if err != nil {
		return nil, fmt.Errorf("证书内容无法解析: %w", err)
	}
	if err := leaf.VerifyHostname(spec.domain); err != nil {
		return nil, fmt.Errorf("访问域名 %s 未被该证书覆盖: %w", spec.domain, err)
	}
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			// 每次握手重新解析：证书续期后无需重启模块即生效。
			if c, ok := (*resolver)(spec.certID); ok {
				return c, nil
			}
			return nil, fmt.Errorf("证书 %s 已不可用", spec.certID)
		},
	}, nil
}

// certLeaf 取证书链上的叶子证书。
func certLeaf(c *tls.Certificate) (*x509.Certificate, error) {
	if c.Leaf != nil {
		return c.Leaf, nil
	}
	if len(c.Certificate) == 0 {
		return nil, fmt.Errorf("证书链为空")
	}
	return x509.ParseCertificate(c.Certificate[0])
}

// stopListen 关闭当前监听并等待在途请求收尾。
func (m *Module) stopListen() {
	m.mu.Lock()
	srv, ln := m.srv, m.ln
	m.srv, m.ln = nil, nil
	m.mu.Unlock()

	if srv == nil {
		if ln != nil {
			_ = ln.Close()
		}
		return
	}
	// 5 秒足够让已收到的请求走完（派发是异步入队，处理器本身很快返回）。
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		_ = srv.Close()
	}
	// Shutdown 只关它已经跟踪到的监听：Serve 在另一个 goroutine 里注册自己，
	// 起监听后立刻停（同一轮里刚绑又要让出端口）时它可能还没跑起来，
	// 于是 Shutdown 返回了、socket 还开着。这里补一刀，让"函数返回=端口已空"
	// 成立——ReleasePort 的调用方紧接着就要绑这个端口。
	// 放在 Shutdown 之后：在途请求的收尾不受影响。
	if ln != nil {
		_ = ln.Close()
	}
}

// Close 停止模块。可重复调用。
func (m *Module) Close() error {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return nil
	}
	m.closed = true
	m.mu.Unlock()

	m.stopListen()
	// 试运行抓包的完整载荷只在内存里，退出时主动清掉，
	// 不留在可能被转储的进程内存中。
	m.tests.clear()
	// 落盘协程收尾：把队列里攒着的历史写完再关文件。放在 stopListen 之后，
	// 这样最后几条入站记录也在队列里了。
	m.hist.close()
	return nil
}

// setErr 记录最近一次错误，供状态展示。
func (m *Module) setErr(s string) {
	m.mu.Lock()
	m.lastErr = s
	m.mu.Unlock()
}

// Status 实现 module.StatusReporter。
//
// Name 必须是模块键名（与 Name() 一致），不能写中文标题：总览页拿它去查
// overview.modName.<键名> 的译名，查不到就原样显示。写死中文的话英文界面会漏出中文，
// 反过来漏掉译名就会在中文界面显示英文键名。
//
// Code / Args 同一条理由（见 module.Status.Code）：这里只给键名与数值，句子由前端按
// 当前语言拼（web/src/views/MessageRoutes.vue 的 statusText）。本模块的取值：
//
//	disabled     模块开关关着
//	shared       端口与 Web 服务共用（args: addr / domain / received[ / warnings]）
//	notListening 该监听却没监听，且没留下错误
//	startFailed  起监听失败（args: err——原始错误串，不翻译）
//	listening    正常监听（args: proto / addr / received[ / warnings]）
//
// warnings 只在大于零时给，前端据此决定要不要追加"N 项配置需要检查"那一句。
func (m *Module) Status() module.Status {
	table := m.routes.Load()
	m.mu.Lock()
	spec, lastErr, listening := m.spec, m.lastErr, m.srv != nil
	m.mu.Unlock()

	st := module.Status{Name: "webhook", Total: table.total, Active: table.active, Healthy: true}
	switch {
	case !spec.enabled:
		st.Code = "disabled"
	case spec.shared:
		// 端口由 Web 服务持有，本模块没有自己的 net.Listener，不能按 listening 判健康。
		st.Code = "shared"
		st.Args = map[string]any{"addr": spec.addr, "domain": spec.domain, "received": m.received.Load()}
		if table.warnings > 0 {
			st.Healthy = false
			st.Args["warnings"] = table.warnings
		}
	case !listening:
		st.Healthy = false
		st.Code = "notListening"
		if lastErr != "" {
			st.Code = "startFailed"
			st.Args = map[string]any{"err": lastErr}
		}
	default:
		proto := "HTTP"
		if spec.tls {
			proto = "HTTPS"
		}
		st.Code = "listening"
		st.Args = map[string]any{"proto": proto, "addr": spec.addr, "received": m.received.Load()}
		if table.warnings > 0 {
			st.Healthy = false
			st.Args["warnings"] = table.warnings
		}
	}
	return st
}

// Metrics 供总览页与接口读取计数。
func (m *Module) Metrics() (received, rejected, dropped int64) {
	return m.received.Load(), m.rejected.Load(), m.dropped.Load()
}

// History 返回执行历史，新的在前。筛选条件见 HistoryQuery，空字段表示不筛。
func (m *Module) History(q HistoryQuery) []HistoryEntry {
	return m.hist.recent(q)
}

// Source 取一条留存的入站原文。第二个返回值为 false 表示这条已被新记录顶掉，
// 或它本来就没有留存（见 source.go）。
func (m *Module) Source(id string) (SourceRecord, bool) {
	return m.sources.get(id)
}

// SourceStats 当前留存的条数与内容字节数，供面板显示"留了多少、占了多少"。
func (m *Module) SourceStats() (count, bytes int) {
	return m.sources.stats()
}

// SourceLimits 留存的三道上限，供面板把数字说给用户听而不是写死在文案里。
// 额度是可变的（跟着模块设置走），所以这里读的是运行期的当前值，不是那个初值常量。
func (m *Module) SourceLimits() (budget, bodyMax, maxEntries int) {
	return m.sources.currentBudget(), sourceBodyMax, sourceMaxEntries
}

// ClearSources 清空全部入站原文留存，返回清掉的条数。额度不变，下一条消息照常留存。
// 供面板上那个「清空原文留存」按钮调用：这份数据不落盘，别处没有能删它的地方。
func (m *Module) ClearSources() int {
	return m.sources.clear()
}

// RecordDelivery 把 notify 的投递结果并进本模块的执行历史，
// 让"收到 → 命中规则 → 各目标投递结果"能在同一个列表里按 eventId 串起来。
// 由 app 装配时注册为 notify 的结果回调。
func (m *Module) RecordDelivery(r notify.Result) {
	event := EventSent
	switch {
	case r.Retrying:
		event = EventRetrying
	case !r.OK:
		event = EventFailed
	}
	reason := ""
	if !r.OK {
		reason = r.Status
	}
	m.hist.add(HistoryEntry{
		Event:   event,
		EventID: r.EventID,
		Rule:    r.RuleName,
		Target:  r.TargetName,
		Reason:  reason,
		DurMS:   r.CostMS,
	})
}
