// Package inboundfw 是服务防护（连接层）的运行态：在 TCP 建立、TLS 握手之前，
// 按来源 IP 拦截 Web 服务与消息路由的入站连接，并按行为（持续的 TLS 握手异常）自动拉黑。
//
// 它属于 fail2ban 家族，与面板入站防护（server/firewall.go）是两套独立机制：
// 面板入站防护只管面板端口，本包只管 Web 服务与消息路由的入站，各管各的范围。
//
// # 为什么拦在连接层
//
// 它的首要目标是消掉「TLS handshake error from <公网 IP>」这类日志刷屏。那条日志由
// crypto/tls 在握手失败时产出，发生在 HTTP 层之前——等中间件看见请求，握手早就结束了，
// 任何挂在 http.Handler 上的防护都来不及。所以拦截点必须在 Accept，而行为信号（握手异常）
// 则只能从 http.Server.ErrorLog（一个 io.Writer）的写入链上 hook 拿到，详见 WrapErrorLog。
//
// # 判定顺序
//
//	拒绝名单 → 局域网/回环豁免 → 允许名单 → 自动封禁 → 放行
//
// 与面板入站防护同向：拒绝优先于允许（明示压过推测），本机回环永远进得来（最后的自救通道）。
// 没有「仅局域网」模式——Web 服务本就要对外暴露，限制来源那是面板入站防护的职责。
//
// 局域网豁免（含回环）是这份实现里最要紧的一条安全阀，理由见 decide。
//
// # 它不是什么
//
// 不是 DDoS 防护：判据是 per-IP，分布式僵尸网络（上万来源、每个发一点点）永远触发不了
// 任何阈值。不是包过滤防火墙：不做状态检测、NAT、端口/协议规则。
package inboundfw

import (
	"io"
	"log"
	"net"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"mantou/internal/config"
	"mantou/internal/ipx"
	"mantou/internal/logx"
	"mantou/internal/mapx"
)

const (
	// gfBanSweepInterval 清扫已过期条目的最小间隔。
	gfBanSweepInterval = time.Minute
	// gfBanShrinkFloor 触发整表重建的最小峰值（同 mapx.ShrinkSparse 的语义）。
	gfBanShrinkFloor = 512
	// gfBanLogInterval 「新增封禁」告警的最小间隔。
	//
	// 不加这道抑制，防火墙自己就会变成新的日志洪水源——一次分布式扫描能在一分钟内
	// 封掉上千个地址，而这个功能存在的初衷恰恰是让日志安静下来。
	gfBanLogInterval = 30 * time.Second
)

// gfVerdict 是一次判定的结果。区分原因只为了写日志；对被拦下的一方，所有拒绝都长得一模一样。
type gfVerdict int

const (
	gfPass       gfVerdict = iota // 放行
	gfDenyList                    // 命中拒绝名单
	gfDenyBanned                  // 命中自动封禁
	gfDenyNoIP                    // 拿不到对端 IP——失败关闭
)

func (v gfVerdict) reason() string {
	switch v {
	case gfDenyList:
		return "deny-list"
	case gfDenyBanned:
		return "auto-ban"
	case gfDenyNoIP:
		return "no-ip"
	}
	return "pass"
}

// gfLists 是配置快照对应的、已解析好的名单。缓存理由同面板入站防护：热路径不能每次都重解析名单。
type gfLists struct {
	src   *config.Config
	gf    config.GlobalFirewall
	allow *ipx.Matcher
	deny  *ipx.Matcher
}

// entry 一个来源的握手异常计数与封禁状态。
//
// 计数与封禁放同一条记录里，是为了让"正在被封"的来源同时占着计数位——
// 否则封禁期间记录被清掉，解封后又从零开始数，等于每轮攻击都要重新攒够阈值。
type entry struct {
	ip string // 展示用原文，避免从 [16]byte 反解
	// 常规窗口（滑动重置，不是滑动窗口）：距上次计数起点超过窗口就从头再数。
	firstHit time.Time
	strikes  int
	// 突发窗口：一个更短、更低阈值的窗口，专抓高速扫描。
	burstAt time.Time
	burst   int
	// 封禁状态。until 零值表示只在计数、尚未封禁。
	until    time.Time
	bannedAt time.Time // 本次封禁起点，供界面展示
	banRound int       // 累计被封次数，供界面判断"惯犯"
}

// Firewall 服务防护（连接层）的运行态。
//
// 它自己不持有配置：每次判定都从 config.Manager 取当前快照，因此设置一保存就生效，
// 不需要重启面板，也不需要往这里推送变更。
type Firewall struct {
	cfg *config.Manager
	log *logx.Logger

	// lists 是「快照 → 已解析名单」的单槽缓存，无锁读（同面板入站防护的 fwLists）。
	lists atomic.Pointer[gfLists]

	mu        sync.Mutex
	bans      map[[16]byte]*entry
	peak      int
	lastSweep time.Time
	// size 是 bans 的条目数副本，供无锁快速路径判断"表是空的"（同面板入站防护的 size）。
	size atomic.Int32

	logMu      sync.Mutex
	lastBanLog time.Time
	banSkipped int
}

// New 创建服务防护。cfg 与 log 由调用方持有并长期存活。
func New(cfg *config.Manager, log *logx.Logger) *Firewall {
	return &Firewall{
		cfg:  cfg,
		log:  log,
		bans: make(map[[16]byte]*entry),
		// lastSweep 必须播成"现在"，不能留零值：零值意味着第一次调用（可能是启动后
		// 第一个连接的 isBanned）就满足"距上次清扫超过一分钟"，于是要为一张空表
		// 白跑一遍全表扫描 + ShrinkSparse。同面板入站防护 newPanelFirewall 的处理。
		lastSweep: time.Now(),
	}
}

// current 返回当前配置快照对应的已解析名单。
func (f *Firewall) current() *gfLists {
	snap := f.cfg.Snapshot()
	if c := f.lists.Load(); c != nil && c.src == snap {
		return c
	}
	gf := snap.GlobalFirewall
	n := &gfLists{
		src:   snap,
		gf:    gf,
		allow: ipx.NewMatcher(gf.AllowIPs),
		deny:  ipx.NewMatcher(gf.DenyIPs),
	}
	f.lists.Store(n)
	return n
}

// maxEntries 封禁表条目上限，由「服务防护」模块的 MemoryMB 折算（与面板入站防护同一份换算）。
// 公式与兜底集中在 config.BanEntriesForMemoryMB，两份防火墙用同一个函数，保证「填的额度」与「表能装多少」一致。
//
// 取的是调用方**已经持有**的快照（l），不再自己 current() 一次：这个函数只在 f.mu 里被调用，
// 而 current() 可能要跑 ipx.NewMatcher 重建整份名单（一条 a-b 范围能展开成 4096 条）——
// 把那件事放进临界区，等于让每个连接都可能卡在一次名单重建后面。
func (f *Firewall) maxEntries(l *gfLists) int {
	return config.BanEntriesForMemoryMB(l.gf.MemoryMB)
}

// decide 对来源 IP 做判定。监听器与错误回灌共用这一个函数，于是两层语义不可能走偏。
//
// 顺序（每一步为什么在这个位置）：
//
//  1. **拒绝名单最先**，连回环与局域网都不豁免。它是用户明确写下的"这个不许进"，
//     任何自动规则都不该把它推翻；与面板入站防护、webservice 的 withIPFilter 同向。
//
//  2. **局域网（含回环）豁免**，跳过后面的自动封禁。这一条是这份实现里最要紧的安全阀：
//     判据是 TLS 握手失败，而**内网**里制造握手失败的东西太多了——上游反代的探活、
//     容器编排的健康检查、监控系统的端口拨测、一个还没配好证书的内部客户端。
//     它们会持续踩中阈值，然后被封掉几十分钟到几小时，而被封掉的往往正是
//     "让站点在负载均衡里保持在线"的那个探测，结果是整站从公网上消失。
//     这类误伤的排查路径极长（表现是间歇性 502，而不是任何一条错误日志），
//     代价远大于"内网可能有个坏客户端"带来的收益。要拦内网请写进拒绝名单——那是人的决定。
//     同口径的取舍见 webservice/scanban.go 的 ipx.IsLAN 豁免。
//
//  3. **允许名单先于自动封禁**：写进允许名单是人做的明示决定，自动封禁是机器的推测；
//     推测不该推翻明示，否则用户会遇到"我明明加白了却还是进不来"，而且无从得知原因。
//
//  4. **自动封禁最后**，它是唯一一条机器下的判断。
//
// ip 为 nil（对端地址解析不出来）时一律拒绝：这是失败关闭。放行的话，
// 一个畸形的 RemoteAddr 就等于把整道防火墙绕过去了。
func (f *Firewall) decide(l *gfLists, ip net.IP) gfVerdict {
	if !l.gf.Enabled {
		return gfPass
	}
	if ip == nil {
		return gfDenyNoIP
	}
	if l.deny.Match(ip) {
		return gfDenyList
	}
	if ipx.IsLAN(ip) {
		return gfPass // 局域网与回环豁免：见上面第 2 条
	}
	if l.allow.Match(ip) {
		return gfPass
	}
	if f.isBanned(ip) {
		return gfDenyBanned
	}
	return gfPass
}

// isBanned 查自动封禁表。表空时不加锁直接返回（常态）。
//
// 顺手做一次到期清扫：清扫原本只挂在 Note 上，而 Note 只在"有来源产生握手异常"时才跑。
// 攻击停了以后就没人再调它，于是过期条目会一直留在表里、size 永远大于零，
// 之后每个连接都要为一张全是死条目的表抢一次锁。这里已经持有 mu，清扫是顺路的事；
// 它自带最小间隔（gfBanSweepInterval），摊到每分钟一次可以忽略。
func (f *Firewall) isBanned(ip net.IP) bool {
	if f.size.Load() == 0 {
		return false
	}
	window := f.banWindow()
	f.mu.Lock()
	defer f.mu.Unlock()
	now := time.Now()
	f.sweepLocked(now, window)
	e := f.bans[ipx.Key(ip)]
	return e != nil && now.Before(e.until)
}

// banWindow 取"计数窗口"的时长，**在临界区之外**调用。
// 它读的是配置快照（可能触发一次名单重建），因此不能放进 f.mu 里，见 maxEntries 的说明。
func (f *Firewall) banWindow() time.Duration {
	return time.Duration(f.current().gf.WindowSeconds) * time.Second
}

// Note 记一次「来源产生了握手异常」，必要时转为封禁；返回本次是否**新**产生了一条封禁。
//
// 计数窗口有两套：常规窗口（WindowSeconds / WindowLimit）防慢速枚举，
// 突发窗口（BurstSeconds / BurstLimit）防高速扫描。任一越过阈值即封禁。
// 窗口是滑动重置而不是滑动窗口：距上次计数起点超过窗口就从头再数（理由见面板 firewall 的 strike）。
//
// 日志刻意放在**释放锁之后**：logBan 会调 BanCount 拿"当前生效条数"，而 BanCount 自己要取 f.mu。
// Go 的 sync.Mutex 不可重入，在锁内打这条日志会当场死锁，且死的方式最坏——
// f.mu 永久被占，之后每一个 Accept 的 isBanned 都会挂在上面，两个模块的入站连接一起停摆。
// 结构上把"改状态"（note，持锁）与"说出去"（logBan，无锁）分开，这个错就没法再犯一次。
func (f *Firewall) Note(ip net.IP, _ string) bool {
	l := f.current()
	if !l.gf.Enabled || !l.gf.AutoBan || ip == nil {
		return false
	}
	// 局域网与回环不计数：同 decide 第 2 条的理由（内网的探活/健康检查天然会制造握手失败）。
	if ipx.IsLAN(ip) {
		return false
	}
	// 允许名单里的来源永不封禁：明示压过推测。少了这一句，用户把自己加白之后
	// 照样会因为客户端重试风暴被机器关在门外。
	if l.allow.Match(ip) {
		return false
	}
	if !f.note(l, ip, time.Now()) {
		return false
	}
	f.logBan(ip.String(), l.gf.BanMinutes)
	return true
}

// note 是 Note 的持锁部分：只改状态，返回本次是否新产生了一条封禁。
// 它不打日志、不读配置快照——两件事都可能重新进入需要 f.mu 的代码。
func (f *Firewall) note(l *gfLists, ip net.IP, now time.Time) bool {
	window := time.Duration(l.gf.WindowSeconds) * time.Second
	burstWindow := time.Duration(l.gf.BurstSeconds) * time.Second
	maxEntries := f.maxEntries(l)

	f.mu.Lock()
	defer f.mu.Unlock()
	f.sweepLocked(now, window)

	k := ipx.Key(ip)
	e := f.bans[k]
	if e == nil {
		if len(f.bans) >= maxEntries {
			// 表满：先清一批已失效的，清不动就放弃这一次计数（同面板 firewall 的取舍：
			// 让新来的少数一次，比让已确认的攻击者提前放出来要安全）。
			f.evictLocked(now, window)
			if len(f.bans) >= maxEntries {
				return false
			}
		}
		e = &entry{ip: ip.String(), firstHit: now, burstAt: now}
		f.bans[k] = e
		f.size.Store(int32(len(f.bans)))
		if n := len(f.bans); n > f.peak {
			f.peak = n
		}
	}
	if now.Before(e.until) {
		// 已经封着了：刷新计数窗口，好让解封后紧接着的下一轮不必继承旧的起点。
		e.firstHit = now
		e.burstAt = now
		e.strikes = 0
		e.burst = 0
		return false
	}
	// 突发窗口
	if now.Sub(e.burstAt) > burstWindow {
		e.burstAt = now
		e.burst = 0
	}
	e.burst++
	if e.burst >= l.gf.BurstLimit {
		banLocked(e, now, l.gf.BanMinutes)
		return true
	}
	// 常规窗口
	if now.Sub(e.firstHit) > window {
		e.firstHit = now
		e.strikes = 0
	}
	e.strikes++
	if e.strikes >= l.gf.WindowLimit {
		banLocked(e, now, l.gf.BanMinutes)
		return true
	}
	return false
}

// banLocked 落一条封禁：纯状态变更，不打日志、不读配置。调用方须持有 f.mu。
//
// 写成不带接收者的函数是刻意的——它拿不到 *Firewall，就没法再从这里调出任何
// 需要 f.mu 的方法（那正是之前的死锁成因）。
func banLocked(e *entry, now time.Time, minutes int) {
	e.strikes = 0
	e.burst = 0
	e.firstHit = now
	e.burstAt = now
	e.bannedAt = now
	e.until = now.Add(time.Duration(minutes) * time.Minute)
	e.banRound++
}

// sweepLocked 清掉既没在封禁、计数窗口也早已过去的条目；调用方须持有 f.mu。
// window 由调用方在锁外算好传进来（见 maxEntries 的说明）。
func (f *Firewall) sweepLocked(now time.Time, window time.Duration) {
	if now.Sub(f.lastSweep) < gfBanSweepInterval {
		return
	}
	f.lastSweep = now
	f.dropExpiredLocked(now, window)
}

// evictLocked 表满时清掉**已经失效**的条目；调用方须持有 f.mu。不动仍在封禁或仍在计数窗口内的条目。
// 与 sweepLocked 的区别只有一个：它不受最小间隔约束（表满是必须当场处理的事）。
func (f *Firewall) evictLocked(now time.Time, window time.Duration) {
	f.dropExpiredLocked(now, window)
}

// dropExpiredLocked 删掉封禁已过期且计数窗口也过去的条目，并把 map 桶内存还回去。
func (f *Firewall) dropExpiredLocked(now time.Time, window time.Duration) {
	for k, e := range f.bans {
		if now.After(e.until) && now.Sub(e.firstHit) >= window {
			delete(f.bans, k)
		}
	}
	f.bans = mapx.ShrinkSparse(f.bans, &f.peak, gfBanShrinkFloor)
	f.size.Store(int32(len(f.bans)))
}

// BanView 一条封禁记录的对外视图（界面展示用）。
type BanView struct {
	IP       string `json:"ip"`
	BannedAt int64  `json:"bannedAt"` // Unix 秒
	Until    int64  `json:"until"`    // Unix 秒
	Rounds   int    `json:"rounds"`   // 累计被封次数
}

// BanList 快照当前**仍在生效**的封禁，按到期时间倒序（最近封的在前）。limit<=0 表示不限条数。
func (f *Firewall) BanList(limit int) []BanView {
	items, _ := f.BanSnapshot(limit)
	return items
}

// BanSnapshot 一次取回"要展示的那几条"与"总共封了多少条"。
//
// 合成一个方法是因为接口层两者都要：分两次调用就要抢两次锁，且两次之间表可能已经变了，
// 于是界面上会出现"列表 3 条、总数 2 条"这种自相矛盾的展示。
//
// 排序放在**释放锁之后**：原先是在锁内跑插入排序，O(n²)。实测 5 MB 额度能装到
// 27306 条，那次排序要 2.88 秒，而这整段是被一个只读状态组件（业务页上的防火墙状态条）
// 调用的——也就是说任何人打开 Web 服务页，都能让两个模块的入站连接停顿近三秒。
// 收集是 O(n) 且必须持锁（要读 entry），排序不需要碰共享状态，挪出来即可。
func (f *Firewall) BanSnapshot(limit int) (items []BanView, total int) {
	now := time.Now()

	f.mu.Lock()
	out := make([]BanView, 0, len(f.bans))
	for _, e := range f.bans {
		if !now.Before(e.until) {
			continue // 只在计数、尚未封禁，或封禁已过期
		}
		out = append(out, BanView{
			IP:       e.ip,
			BannedAt: e.bannedAt.Unix(),
			Until:    e.until.Unix(),
			Rounds:   e.banRound,
		})
	}
	f.mu.Unlock()

	total = len(out)
	sort.Slice(out, func(i, j int) bool {
		if out[i].Until != out[j].Until {
			return out[i].Until > out[j].Until
		}
		return out[i].IP < out[j].IP // 同秒到期时定序，免得每次刷新顺序都在跳
	})
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, total
}

// BanCount 当前仍在生效的封禁条数。
func (f *Firewall) BanCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	now := time.Now()
	n := 0
	for _, e := range f.bans {
		if now.Before(e.until) {
			n++
		}
	}
	return n
}

// ClearBans 解除全部自动封禁（连计数一起清），返回被解除的封禁条数。
func (f *Firewall) ClearBans() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	now := time.Now()
	for _, e := range f.bans {
		if now.Before(e.until) {
			n++
		}
	}
	f.bans = make(map[[16]byte]*entry)
	f.peak = 0
	f.size.Store(0)
	return n
}

// Unban 解除单个 IP 的封禁与计数，返回它此前是否确实被封着。
func (f *Firewall) Unban(raw string) bool {
	ip := net.ParseIP(raw)
	if ip == nil {
		return false
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	k := ipx.Key(ip)
	e := f.bans[k]
	if e == nil {
		return false
	}
	was := time.Now().Before(e.until)
	delete(f.bans, k)
	f.size.Store(int32(len(f.bans)))
	return was
}

// logBan 打一条「新增封禁」告警，按 gfBanLogInterval 抑制。被压掉的条数累计进下一条，不会凭空消失。
//
// **调用方不得持有 f.mu**：它要读"当前生效条数"，而那需要取 f.mu，而 sync.Mutex 不可重入。
// 这不是风格问题——在锁内调它会当场永久死锁，且卡住的是所有入站连接的判定路径。
// 唯一的调用点在 Note 里、锁释放之后（见那里的说明）。
func (f *Firewall) logBan(ip string, minutes int) {
	f.logMu.Lock()
	now := time.Now()
	if !f.lastBanLog.IsZero() && now.Sub(f.lastBanLog) < gfBanLogInterval {
		f.banSkipped++
		f.logMu.Unlock()
		return
	}
	skipped := f.banSkipped
	f.banSkipped = 0
	f.lastBanLog = now
	f.logMu.Unlock()

	args := []any{"ip", ip, "minutes", minutes, "active", f.BanCount()}
	if skipped > 0 {
		args = append(args, "suppressed", skipped)
	}
	f.log.Warn("服务防护自动封禁", args...)
}

// ---------------------------------------------------------------------------
// 连接层拦截
// ---------------------------------------------------------------------------

// listener 在 Accept 处按名单/封禁关掉不受欢迎的连接。它**不做握手异常的计数**——
// 计数是异步从 ErrorLog 回灌的（见 Note / WrapErrorLog），这一层只看名单与封禁表。
type listener struct {
	net.Listener
	fw *Firewall
}

// Accept 循环直到取到一个被放行的连接。
//
// 被拒绝的连接直接 Close 并继续循环，**不返回错误**——http.Server.Serve 见到非临时错误
// 就会退出整个服务，一次拒绝必须对上层完全不可见。
func (l *listener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		lists := l.fw.current()
		if !lists.gf.Enabled {
			return c, nil
		}
		ip := connIP(c)
		if v := l.fw.decide(lists, ip); v != gfPass {
			// Debug 级别：这条路径正是日志洪水的来源，按 WARN 输出等于用一种噪声换掉另一种。
			// 真正值得报警的是"新增了一条封禁"（见 logBan）。
			l.fw.log.Debug("服务防护拦截连接", "ip", remoteAddrOf(c), "reason", v.reason())
			_ = c.Close()
			continue
		}
		return c, nil
	}
}

// Wrap 给监听器包一层连接级拦截；fw 为 nil 时原样返回。
//
// **无条件**包装，不看当前是否启用：启用与否由每次 Accept 现读快照决定（见 listener.Accept），
// 于是界面上一开一关立刻生效，不需要重启监听器。在这里判一次的写法会把开关状态
// 焊死在监听器创建的那一刻——同 WrapErrorLog 里说明过的那个坑。
// 关闭状态下的代价只是每个连接多一次指针跳转与一次布尔判断。
func (f *Firewall) Wrap(ln net.Listener) net.Listener {
	if f == nil {
		return ln
	}
	return &listener{Listener: ln, fw: f}
}

// ---------------------------------------------------------------------------
// TLS 握手错误回灌
// ---------------------------------------------------------------------------

// errorTap 包住 http.Server.ErrorLog 的原始 writer：解析出 TLS 握手失败的来源 IP，
// 回灌进自动封禁计数；同时把原样字节转发给底层 writer，日志内容不变。
type errorTap struct {
	w  io.Writer
	fw *Firewall
}

// Write 实现 io.Writer。base.Writer() 拿到的是 logx 的 standardWriter，它接收的
// 就是标准库写来的原始行（形如 "http: TLS handshake error from 1.2.3.4:5678: ..."），
// 「Web TLS 或连接异常」那个前缀是 standardWriter 自己加的、不在此处。
//
// 无论解析结果如何，原样字节都必须转发给底层 writer：这里是日志链路上的一环，
// 顺带做的事出了任何岔子都不该让一行日志消失。
func (t *errorTap) Write(p []byte) (int, error) {
	if ip := parseHandshakeIP(string(p)); ip != nil {
		t.fw.Note(ip, "tls-handshake")
	}
	return t.w.Write(p)
}

// parseHandshakeIP 从一行标准库日志里取出 TLS 握手失败的来源 IP；取不出返回 nil。
//
// 标准库写的是 net.Addr.String()，因此 IPv6 带方括号：
//
//	http: TLS handshake error from 1.2.3.4:5678: EOF
//	http: TLS handshake error from [2001:db8::dead]:44322: EOF
//
// 早先的实现是「找第一个冒号，取它前面的部分」——对 IPv4 恰好正确，对 IPv6 会切出
// "[2001" 然后解析失败，于是**所有 IPv6 来源的握手异常都不计数**，自动封禁对着
// 一个如今相当常见的地址族完全失效，而且不留任何痕迹（解析失败是静默的）。
//
// 现在的做法：截到第一个空格（地址本身不含空格），去掉标准库在地址后面加的那个冒号，
// 剩下的交给 ipx.RemoteHost 拆 host:port 并剥掉 IPv6 的 zone。
func parseHandshakeIP(s string) net.IP {
	const marker = "TLS handshake error from "
	i := strings.Index(s, marker)
	if i < 0 {
		return nil
	}
	rest := s[i+len(marker):]
	// 到第一个空格为止：后面跟的是 ": EOF"、": remote error: ..." 之类的原因。
	if sp := strings.IndexAny(rest, " \t\r\n"); sp >= 0 {
		rest = rest[:sp]
	}
	rest = strings.TrimSuffix(strings.TrimSpace(rest), ":")
	if rest == "" {
		return nil
	}
	return net.ParseIP(ipx.RemoteHost(rest))
}

// WrapErrorLog 返回一个供 http.Server.ErrorLog 使用的 *log.Logger：其行为与 base 完全一致
// （相同的日志级别与前缀，日志内容不变），但会把 TLS 握手失败行额外回灌进自动封禁计数。
//
// **无条件**包装，不看当前是否启用。启用与否由 Note 每次调用时读快照现判——
// 原先在这里判一次的写法把开关状态**焊死在了监听器创建的那一刻**：关着的时候起服务，
// 之后从界面上打开防火墙，回灌永远不会挂上去，自动封禁表一条也不会增长，
// 而界面显示"已启用"、判定逻辑也确实在跑名单，看不出少了什么。要恢复只能重启进程。
//
// 代价是关闭状态下每行 ErrorLog 多一次字符串查找（strings.Index），
// 而这条链路只在"连接出错"时才有流量，量级与"每个请求"完全不同，可以忽略。
func (f *Firewall) WrapErrorLog(base *log.Logger) *log.Logger {
	if f == nil || base == nil {
		return base
	}
	return log.New(&errorTap{w: base.Writer(), fw: f}, base.Prefix(), base.Flags())
}

// ---------------------------------------------------------------------------
// 连接取 IP 的辅助
// ---------------------------------------------------------------------------

func connIP(c net.Conn) net.IP {
	addr := c.RemoteAddr()
	if addr == nil {
		return nil
	}
	if ta, ok := addr.(*net.TCPAddr); ok {
		return ta.IP
	}
	return net.ParseIP(ipx.RemoteHost(addr.String()))
}

func remoteAddrOf(c net.Conn) string {
	if addr := c.RemoteAddr(); addr != nil {
		return ipx.RemoteHost(addr.String())
	}
	return "unknown"
}
