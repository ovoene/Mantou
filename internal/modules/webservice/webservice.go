package webservice

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"mantou/internal/config"
	"mantou/internal/ipx"
	"mantou/internal/logx"
	"mantou/internal/module"
)

// 本文件是 webservice 模块的骨架：模块状态（Module）、配置装配（Reload）与生命周期
// （New/Close/Status/Stats）。请求处理、监听器、访问日志、主动探测各自拆到同名文件：
//   handler.go   —— 反代 / 静态 / 重定向三类子项处理器与响应包装
//   listener.go  —— 端口监听（listenServer）：绑定、TLS、连接数上限、按 Host 分流
//   accesslog.go —— 访问事件环形缓冲、日志抑制与写速限制
//   probe.go     —— 周期主动探测与链接状态（linkStatus）

// maxConnsPerListener 单个 Web 监听端口允许的并发连接数上限（见 listenServer.start 处的说明）。
const maxConnsPerListener = 2000

// CertResolver 依据 SNI/域名返回可用证书；由证书模块注入，未配置时返回 nil。
type CertResolver func(serverName string) (*tls.Certificate, bool)

// Module 管理 Web 服务（反向代理 / 静态站点 / 重定向）。
// 模型：父项 = 一个 (端口, 地址族) 监听；子项 = 该监听下按前端地址分流到后端的规则。
// 同一 (端口, 地址族) 的多个父项会被聚合到同一监听（正常情况下前端已保证唯一）。
type Module struct {
	mu       sync.Mutex
	log      *logx.Logger
	servers  map[string]*listenServer // key = family|port
	resolver CertResolver
	// webhookPeer 消息路由模块；与它共用端口时挂成一条域名路由（见 SetWebhookPeer）。
	webhookPeer WebhookPeer
	// closed 使 Close 幂等（见 Close 的说明）。同时保证 Close 之后不再有监听被拉起。
	closed bool

	// 运行态统计：独立于 servers 的重建，跨 Reload 保留，避免每次改配置连接数清零。
	statMu sync.Mutex
	conns  map[string]*int64 // childID -> 活跃连接（在途请求）数
	// 访问日志环形缓冲（全局，按 childID 过滤展示）。这是**真环形**：len(access) 即环长，
	// 写入覆盖 accessNext 指向的槽位，稳态不分配、不拷贝。
	//
	// 原实现是 `append` + `access[len-cap:]` 的「伪环形」：每次越界只是把切片头往后挪，
	// 底层数组仍从尾部继续追加，直到容量耗尽才整段重新分配并拷贝——满载时约每 1000 条
	// 就要复制一遍全缓冲（1000 条约 260 KB），且旧数组在被切片引用期间无法回收，
	// 峰值内存接近两倍。日志本身是"写多读少"的旁路数据，不该有这种周期性抖动。
	access     []AccessEntry
	accessNext int // 下一条写入的槽位下标
	accessLen  int // 已填充条数（小于环长表示还没绕满一圈）
	accessCap  int // 目标容量（随「设置 → 日志 → 最大条数」联动，环按需增长到它）
	// 每子项最近一次成功 / 失败访问时间，用于「链接状态」展示（正常 / 失败 / 未访问）。
	linkStatus map[string]linkState
	// 链接状态日志去重：每个 childID 最近一次写入程序日志的状态（true=正常, false=错误）；
	// 探测结果与上次不同时才记录一条，避免每 60s 重复刷屏；启动/新增子项的首次探测也会记录。
	linkLogState map[string]bool

	// 日志抑制器：连接/断开按 IP、错误按签名，在 10 分钟窗口内仅记首条，内存有界。
	suppressor *logSuppressor
	// rateLimiter 每 IP 限流的桶表，全部子项共用一张（桶键 = 子项 ID + 来源 IP）。
	// 与上面几项同理：跨 servers 重建保留，保存一次配置不该把所有来源的令牌加满。
	rateLimiter *ipx.IPLimiter
	// scanBan 公网扫描自动封禁的记账表（见 scanban.go）。同样跨 Reload 存活：
	// 一次保存配置不该把正在封禁中的扫描器统统放出来。
	scanBan *scanBanner
	// 全局访问日志写速令牌桶：每秒至多记录 logGlobalRPS 条，防海量不同 IP 时写盘/CPU 被打爆。
	logRate *logRateLimiter

	// 周期主动探测：独立于真实流量与 10/s 日志限速，按固定间隔探测各子项后端可达性，
	// 写入 linkStatus，作为「前端到后端是否正常访问」的健康信号（反代/静态/重定向 三种模式统一）。
	probeTargets []probeTarget
	probeStop    chan struct{} // 关闭时通知探测 goroutine 退出
	probeKick    chan struct{} // 非阻塞触发一次立即探测（如 Reload 后刷新目标）
	probeWG      sync.WaitGroup
	// 探测调度状态：childID -> 下次应探测时间；按各子项所属父项的间隔分别排期。
	probeMu   sync.Mutex
	probeNext map[string]time.Time
	// 探测用 HTTP 客户端（按是否忽略后端证书校验区分），超时由 probeTimeout 约束，跨探测复用、只读不写。
	probeClientSecure   *http.Client
	probeClientInsecure *http.Client
}

// childBinding 是聚合到某监听上的一个子项及其展示名。
type childBinding struct {
	service       string
	child         config.WebChild
	probeInterval time.Duration // 该子项所属父项的主动探测间隔（作用于其下全部子项）
}

// wsGroup 是按 (地址族, 端口) 聚合后的监听配置（父项 + 其下已启用子项）。
type wsGroup struct {
	family    string
	port      int
	bindings  []childBinding
	extRoutes []extRoute // 其它模块挂在这个端口上的域名路由（目前只有消息路由）
	useTLS    bool
	minVer    uint16
}

// extRoute 是外部模块借用本监听的一条域名路由。
// 只放数据不放 http.Handler：groupSignature 用 %+v 生成指纹，
// 把处理器塞进来会让指纹带上一个函数地址，从而"每次 Reload 都像变了"，白白重建监听。
type extRoute struct {
	owner  string // 归属模块，取处理器时用
	domain string
}

// WebhookPeer 是消息路由模块在共享端口上要提供的两件能力。
//
// ReleasePort 存在的原因是重载顺序：本模块的 Reload 排在消息路由之前（见 app.Build），
// 用户刚把两者改成共享时，消息路由手里还攥着那个端口，本模块此刻去绑就是"地址已被占用"，
// 而它要等到本轮稍后才会松手——那一轮结束后端口上没有任何监听，直到下次保存才恢复。
// 所以在绑定共享端口之前先叫它松手，把顺序问题就地解决，不依赖重试也不依赖注册顺序。
type WebhookPeer interface {
	Handler() http.Handler
	ReleasePort(port int) bool
}

// externalHandler 按归属取外部模块注入的处理器。
func (m *Module) externalHandler(owner string) http.Handler {
	if owner == ownerWebhook && m.webhookPeer != nil {
		return m.webhookPeer.Handler()
	}
	return nil
}

// ownerWebhook 是消息路由模块在 extRoute 里的归属标记。
const ownerWebhook = "webhook"

// groupSignature 生成单个监听的配置指纹，用于判断是否需要重建：
// 涵盖地址族、端口、TLS 开关/最低版本与各子项绑定，任一影响运行时行为的字段变更都会改变指纹。
func groupSignature(g *wsGroup) string {
	return fmt.Sprintf("%+v", g)
}

// New 创建 Web 服务模块。
func New(log *logx.Logger) *Module {
	m := &Module{
		log:                 log,
		servers:             make(map[string]*listenServer),
		conns:               make(map[string]*int64),
		accessCap:           logx.DefaultLogEntries, // Reload / SetAccessCap 会按实际配置覆盖
		linkStatus:          make(map[string]linkState),
		linkLogState:        make(map[string]bool),
		suppressor:          newLogSuppressor(),
		logRate:             newLogRateLimiter(),
		rateLimiter:         ipx.NewIPLimiter(),
		scanBan:             newScanBanner(),
		probeStop:           make(chan struct{}),
		probeKick:           make(chan struct{}, 1),
		probeNext:           make(map[string]time.Time),
		probeClientSecure:   newProbeClient(false),
		probeClientInsecure: newProbeClient(true),
	}
	// 启动周期主动探测（独立于真实流量与日志限速），Close 时通过 probeStop 退出并等待。
	m.probeWG.Add(1)
	go m.runProbe()
	return m
}

// newProbeClient 造一个用于主动探测后端的 HTTP 客户端。insecure 为真时不校验后端证书
// （由用户在子项上显式开启）。
//
// 两个客户端都刻意不用 http.ProxyFromEnvironment，理由与反代那条 Transport 完全一样
// （见 handler.go 里 Proxy: nil 处的说明）：探测的目标就是反代要转发过去的那个后端地址，
// 多半在内网，而宿主机上的 HTTP_PROXY / HTTPS_PROXY / ALL_PROXY 通常是给别的用途设的。
// 采信它的话，界面上「后端连接正常」这句话说的其实是"那个第三方代理还活着"——
// 后端早停了也照样显示绿的，而这一栏正是用来判断后端死活的。
//
// 从前这里两侧还各错一半：忽略证书那一版显式写着 ProxyFromEnvironment，另一版没给
// Transport、于是用了同样采信环境变量的 http.DefaultTransport。合成一个构造函数之后，
// 这条红线只有一处、两边不可能再走散。
func newProbeClient(insecure bool) *http.Client {
	tr := &http.Transport{
		Proxy:                 nil,
		DialContext:           (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          10,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
	if insecure {
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // 由用户显式开启
	}
	return &http.Client{Timeout: probeTimeout, Transport: tr}
}

// SetCertResolver 注入证书解析器（由证书模块提供）。
func (m *Module) SetCertResolver(r CertResolver) {
	m.mu.Lock()
	m.resolver = r
	m.mu.Unlock()
}

// SetWebhookPeer 注入消息路由模块，用于与它共用 80 / 443 监听。
//
// 只注入模块本身、不注入配置：共不共享由 config.WebhookSharesWebServicePort 在 Reload 里现算，
// 两个模块读同一份配置得同一个结论，不存在"一方以为共享、另一方以为独占"的中间态。
func (m *Module) SetWebhookPeer(p WebhookPeer) {
	m.mu.Lock()
	m.webhookPeer = p
	m.mu.Unlock()
}

// Name 实现 module.Module。
func (m *Module) Name() string { return "webservice" }

// Reload 按 (地址族, 端口) 重建监听服务。
// 为避免「任意配置变更（如启用/禁用单个子项）都重启全部监听」造成的连接抖动与启动日志刷屏，
// 改为按监听差异重建：配置未变化的监听保持运行（不重建、不重记「已启动」日志），
// 仅关闭已移除或配置变化的监听，并启动新增的监听。
func (m *Module) Reload(cfg *config.Config) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		// 已关闭（进程退出 / 自更新替换映像中）：此时再拉起监听会让进程带着占用的端口离场。
		return nil
	}
	// 访问事件环容量随全局「日志最大条数」联动，约束整体内存占用。
	// 设置页保存时也会直接调用 SetAccessCap（不依赖 Reload），改完立即生效。
	m.SetAccessCap(cfg.Settings.Log.MaxEntries)

	// 按 (地址族, 端口) 聚合启用父项下的启用子项。
	groups := make(map[string]*wsGroup)
	var order []string
	present := make(map[string]bool) // 仍存在的子项 ID

	for pi := range cfg.WebServices {
		ws := &cfg.WebServices[pi]
		if !ws.Enabled || ws.Port <= 0 { // 父项关闭 → 其子项全部停用
			continue
		}
		// 运行时防御：Web 服务端口不得与容器自身（面板）端口冲突。
		// 面板必须先绑定其管理端口，若此处抢绑会导致面板进程崩溃、restart 死循环。
		// 即便配置经导入/迁移等渠道绕过了保存期校验，这里也直接跳过该服务并记录告警。
		if ws.Port == cfg.Panel.Port {
			m.log.Warn("Web 服务端口与面板管理端口冲突，已跳过启动", "port", ws.Port, "name", ws.Name)
			continue
		}
		family := normalizeFamily(ws.IPFamily)
		key := fmt.Sprintf("%s|%d", family, ws.Port)
		g := groups[key]
		if g == nil {
			g = &wsGroup{family: family, port: ws.Port}
			groups[key] = g
			order = append(order, key)
		}
		for ci := range ws.Children {
			ch := ws.Children[ci]
			if !ch.Enabled {
				continue
			}
			present[ch.ID] = true
			label := ws.Name
			if ch.Note != "" {
				label = strings.TrimSpace(ws.Name + " / " + ch.Note)
				label = strings.TrimPrefix(label, "/ ")
			}
			g.bindings = append(g.bindings, childBinding{service: label, child: ch, probeInterval: normalizeProbeInterval(ws.ProbeInterval)})
			if ch.TLS {
				g.useTLS = true
				if v := tlsMinVersion(ch.TLSMinVersion); v > g.minVer {
					g.minVer = v
				}
			}
		}
	}

	// 消息路由借用本模块的监听：它的端口撞上某个已启用父项时不自己绑，
	// 而是把自己的域名挂成这条监听上的一条路由（判据见 config.WebhookSharesWebServicePort）。
	// 必须在分组循环之后做：只有已经成型的分组才代表"确实会起来的监听"。
	if m.webhookPeer != nil && cfg.WebhookSharesWebServicePort() {
		peerFamily := cfg.WebhookListenFamily()
		for _, g := range groups {
			if g.port != cfg.Webhook.Port || len(g.bindings) == 0 {
				continue
			}
			// 地址族招待不到消息路由那一侧的监听照样挂路由：它确实不是"消息路由本该
			// 自己绑的那个监听"（共用判据已经排除了它，见 WebServiceListenerOnPort），
			// 但同端口上挂着同一个域名，从这一族进来的请求给消息路由处理是对的。
			// 只有真正接手了那一族的监听才需要核对协议口径，所以下面那句告警要挑着发。
			g.extRoutes = append(g.extRoutes, extRoute{owner: ownerWebhook, domain: cfg.Webhook.Domain})
			// TLS 口径不一致时仍然挂上去：这条监听已经定了协议，改不了。
			// 不挂的后果更差——消息路由会转去自己绑同一个端口，直接"地址已被占用"。
			// 保存期已经拦住这种组合，能走到这里只有手改配置一条路，所以留一条告警。
			if config.FamilyServes(g.family, peerFamily) && cfg.Webhook.HTTPS.Enabled != g.useTLS {
				m.log.Warn("消息路由与共用端口的 Web 服务协议不一致，请求可能无法握手",
					"port", g.port, "domain", cfg.Webhook.Domain,
					"webhookHttps", cfg.Webhook.HTTPS.Enabled, "listenerTls", g.useTLS)
			}
		}
	}

	// 裁剪已不存在子项的连接计数与链接状态，保证运行态映射只保留当前子项，
	// 内存随子项数有界（即便长期启停/增删子项也不会无限累计）。
	m.pruneConns(present)
	m.pruneLinkStatus(present)

	// 期望监听指纹：配置完全一致的监听无需重建。
	//
	// 刻意**不**在函数开头用「整份 WebServices 的指纹与上次相同就直接 return」来抄近路
	//（曾有一个只写不读的 m.sig 字段就是为此埋的，已随本次修复删除）：
	//   1. 任意设置保存都会触发 ReloadAll，其中 SetAccessCap（访问日志容量）来自
	//      Settings.Log，不在 WebServices 指纹覆盖范围内，早退会让该设置永不生效；
	//   2. 上一轮绑定失败的监听会以「不健康」状态留在 m.servers 里等下次 Reload 重试，
	//      早退会让它永远失去重试机会（端口被占用后哪怕占用方已退出也起不来）。
	// 真正省下"无谓重建"的是下面的**逐监听**指纹比对：配置未变且健康的监听不会被关闭，
	// 因此改一个无关的外观设置不会切断任何反代连接——这一点本就已经成立。
	desiredSig := make(map[string]string, len(groups))
	for key, g := range groups {
		desiredSig[key] = groupSignature(g)
	}

	// 快速路径：期望监听集合与现状完全一致且均健康 → 无需任何变更，直接返回。
	if len(groups) == len(m.servers) {
		allSame := true
		for key := range groups {
			s, ok := m.servers[key]
			if !ok || s.sig != desiredSig[key] || !s.healthy() {
				allSame = false
				break
			}
		}
		if allSame {
			return nil
		}
	}

	// 关闭并移除：已不存在、配置已变化（需重建路由/TLS），或不健康（需重建重试）的监听。
	for key, s := range m.servers {
		if _, wanted := groups[key]; !wanted || s.sig != desiredSig[key] || !s.healthy() {
			s.close()
			delete(m.servers, key)
		}
	}

	// 启动新增或重建的监听；配置未变的已有监听保持运行（不重建、不重记启动日志）。
	for _, key := range order {
		if _, exists := m.servers[key]; exists {
			continue // 配置未变，保留原监听
		}
		g := groups[key]
		if len(g.bindings) == 0 {
			continue
		}
		// 共享端口：先叫消息路由松手，再绑（原因见 WebhookPeer 的说明）。
		if len(g.extRoutes) > 0 && m.webhookPeer != nil {
			m.webhookPeer.ReleasePort(g.port)
		}
		s := newListenServer(g, m.resolver, m, m.log)
		s.sig = desiredSig[key]
		if err := s.start(); err != nil {
			m.log.Error("Web 服务启动失败", "listen", s.addr, "err", err.Error())
			m.servers[key] = s // 仍登记，Status 反映不健康
			continue
		}
		m.servers[key] = s
	}
	// 刷新主动探测目标：依据当前启用的子项重建清单（仅含已配置后端链接的子项），
	// 并立即触发一次探测，避免改配置后等待一个完整探测周期才反映最新可达性。
	m.refreshProbeTargets(groups)
	select {
	case m.probeKick <- struct{}{}:
	default:
	}
	return nil
}

// normalizeFamily 归一化地址族，未知值按双栈处理。
// 口径归 config 一处所有：这个值既决定建几个监听，也决定消息路由能不能共用端口，
// 两边差一点就会出现"端口被抢"或"根本没人监听"（见 config.NormalizeIPFamily）。
func normalizeFamily(f string) string { return config.NormalizeIPFamily(f) }

// tlsMinVersion 将配置中的版本字符串映射为 crypto/tls 常量；空或未知按 TLS 1.2。
func tlsMinVersion(s string) uint16 {
	switch strings.TrimSpace(s) {
	case "1.0":
		return tls.VersionTLS10
	case "1.1":
		return tls.VersionTLS11
	case "1.3":
		return tls.VersionTLS13
	default:
		return tls.VersionTLS12
	}
}

// Close 关闭全部 Web 服务，并停止周期主动探测 goroutine（等待其退出，避免写已释放状态）。
// 可重复调用：第二次及以后为空操作。自更新路径会先显式关闭模块再 exec 新二进制，
// exec 失败返回时 defer 里还会再关一次，若不做幂等，close(m.probeStop) 会因重复关闭 channel 而 panic。
func (m *Module) Close() error {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return nil
	}
	m.closed = true
	for key, s := range m.servers {
		s.close()
		delete(m.servers, key)
	}
	close(m.probeStop) // 通知探测 goroutine 退出
	m.mu.Unlock()
	m.probeWG.Wait() // 等待探测 goroutine 完全退出后再返回
	// 主动探测那两个客户端的连接池同样要自己关（与 listener.close 里同一个道理：Go 不会
	// 因为 Transport 没人引用了就关掉它池子里的空闲 socket，得等 IdleConnTimeout 90 秒到期）。
	// 这里比监听那处更该收：自更新路径会先关模块再 exec 新二进制，留着的话新老进程会
	// 在那 90 秒里同时握着连向同一批后端的连接。
	//
	// 从前这一步做不了：那时 probeClientSecure 没给 Transport，用的是共享的
	// http.DefaultTransport，在它上面调 CloseIdleConnections 会把在线更新、通知推送、
	// DDNS 正在复用的连接一并关掉，是净损失。现在两个客户端各有自己的 Transport
	// （见 newProbeClient），关的只是自己那一份。
	//
	// 位置必须在 probeWG.Wait() 之后——那笔"往后变空闲的也关掉"的标记会被新请求清掉，
	// 探测 goroutine 还活着就等于这一步可能白做。
	m.probeClientSecure.CloseIdleConnections()
	m.probeClientInsecure.CloseIdleConnections()
	return nil
}

// Status 实现 module.StatusReporter。
func (m *Module) Status() module.Status {
	m.mu.Lock()
	defer m.mu.Unlock()
	active, healthy := 0, true
	for _, s := range m.servers {
		if s.healthy() {
			active++
		} else {
			healthy = false
		}
	}
	return module.Status{
		Name:    "webservice",
		Total:   len(m.servers),
		Active:  active,
		Healthy: healthy,
	}
}

// Stats 返回每个子项当前的活跃连接数（childID -> count）。
func (m *Module) Stats() map[string]int64 {
	m.statMu.Lock()
	defer m.statMu.Unlock()
	out := make(map[string]int64, len(m.conns))
	for id, c := range m.conns {
		out[id] = atomic.LoadInt64(c)
	}
	return out
}

// connCounter 取（或惰性创建）某子项的连接计数器；同一 childID 复用同一指针，
// 使得跨 Reload 与旧服务在途请求对计数的增减保持一致。
func (m *Module) connCounter(childID string) *int64 {
	m.statMu.Lock()
	defer m.statMu.Unlock()
	c, ok := m.conns[childID]
	if !ok {
		c = new(int64)
		m.conns[childID] = c
	}
	return c
}

// pruneConns 删除不再存在的子项的连接计数（在途请求仍持有原指针，删除无副作用）。
func (m *Module) pruneConns(present map[string]bool) {
	m.statMu.Lock()
	defer m.statMu.Unlock()
	for id := range m.conns {
		if !present[id] {
			delete(m.conns, id)
		}
	}
}
