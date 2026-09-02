package server

import (
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gin-gonic/gin"

	"mantou/internal/config"
	"mantou/internal/errpage"
	"mantou/internal/ipx"
	"mantou/internal/logx"
	"mantou/internal/mapx"
)

// 面板入站防火墙的服务端实现。配置模型与取值边界在 internal/config/firewall.go，
// 这里只管「怎么拦」。
//
// # 为什么要拦两次
//
// 同一套判断挂在两个高度上，各自解决一个另一个解决不了的问题：
//
//  1. **监听器**（firewallListener.Accept）——在 TLS 握手之前就把连接关掉。
//     这是唯一能消掉「TLS handshake error from <公网 IP>」这类日志的位置：
//     那条日志由 crypto/tls 在握手失败时产出，等 HTTP 层看见请求，握手早就结束了，
//     任何中间件都来不及。它同时也是最省的一层——一次 Close 对比一次完整的
//     密钥协商，差着几个数量级的 CPU。
//  2. **中间件**（Server.firewallGuard）——限速、超限计数与自动封禁。
//     速率是「请求」的属性不是「连接」的属性（keep-alive 上可以跑几千个请求），
//     只能在这一层数。它同时是监听器那层的补丁：一条在封禁生效**之前**就已建立的
//     长连接不会被 Accept 再看到一次，得靠这里把它挡住。
//
// # 判定顺序
//
//	回环 → 拒绝名单 → 自动封禁 → 允许名单 → 访问范围(Mode) → 限速
//
// 顺序即语义，每一步为什么在这个位置见 decide 的注释。

const (
	// fwBanMaxEntries 自动封禁表的条目上限。
	//
	// 必须有上限，而且理由比登录限流那张表更硬：这张表的键是**攻击者选的**。
	// IPv6 下一个 /64 就能提供 1.8e19 个来源地址，无上限等于把内存分配权交给对方。
	fwBanMaxEntries = 4096
	// fwBanShrinkFloor 触发整表重建的最小峰值（同 mapx.ShrinkSparse 的语义）：
	// delete 不归还 map 桶内存，一次大规模扫描退潮后那块内存会一直挂着。
	fwBanShrinkFloor = 512
	// fwBanSweepInterval 清扫已过期条目的最小间隔。
	fwBanSweepInterval = time.Minute
	// fwBanLogInterval 「新增封禁」告警的最小间隔。
	//
	// 不加这道抑制，防火墙自己就会变成新的日志洪水源——一次分布式扫描能在一分钟内
	// 封掉上千个地址，而这个功能存在的初衷恰恰是让日志安静下来。
	// 被压掉的条数会累计进下一条日志里，不会凭空消失（同 webservice 的 logSuppressor）。
	fwBanLogInterval = 30 * time.Second
	// fwLimiterScope 共用 ipx.IPLimiter 桶表时的作用域名。面板只有一个作用域。
	fwLimiterScope = "panel"
)

// fwVerdict 是一次判定的结果。区分原因只为了写日志与测试；
// 对被拦下的一方，所有拒绝都长得一模一样（见 writeFirewallRejected）。
type fwVerdict int

const (
	fwPass       fwVerdict = iota // 放行
	fwDenyList                    // 命中拒绝名单
	fwDenyBanned                  // 命中自动封禁
	fwDenyScope                   // 不在允许的来源范围内（Mode=lan 而来源不是局域网）
	fwDenyNoIP                    // 拿不到对端 IP——失败关闭
)

func (v fwVerdict) reason() string {
	switch v {
	case fwDenyList:
		return "deny-list"
	case fwDenyBanned:
		return "auto-ban"
	case fwDenyScope:
		return "scope"
	case fwDenyNoIP:
		return "no-ip"
	}
	return "pass"
}

// fwLists 是一份配置快照对应的、已解析好的名单。
//
// 缓存它是因为热路径不能每次都跑 ipx.ParseCIDRs：那会在每个请求上把整份名单
// 重新解析一遍，而一条「a-b」范围能展开成 4096 个条目。
// src 存的是快照指针本身——config.Manager 每次 Update 都会换一个新指针，
// 于是"配置变没变"退化成一次指针比较，不需要额外的版本号或锁。
type fwLists struct {
	src   *config.Config
	fw    config.PanelFirewall
	allow *ipx.Matcher
	deny  *ipx.Matcher
}

// fwBanEntry 一个来源的超限计数与封禁状态。
//
// 计数与封禁放同一条记录里，是为了让"正在被封"的来源同时占着计数位——
// 否则封禁期间它的记录被清掉，解封后又从零开始数，等于每轮攻击都要重新攒够阈值。
type fwBanEntry struct {
	ip        string    // 展示用原文，避免从 [16]byte 反解
	strikes   int       // 当前窗口内的超限次数
	firstHit  time.Time // 当前计数窗口的起点
	until     time.Time // 封禁截止；零值表示只在计数、尚未封禁
	bannedAt  time.Time // 本次封禁的起点，供界面展示
	banRounds int       // 累计被封次数，供界面判断"惯犯"
}

// panelFirewall 面板入站防火墙的运行态。
//
// 它自己不持有配置：每次判定都从 config.Manager 取当前快照，因此设置一保存就生效，
// 不需要重启面板，也不需要往这里推送变更。
type panelFirewall struct {
	cfg *config.Manager
	log *logx.Logger

	// lists 是「快照 → 已解析名单」的单槽缓存，无锁读。
	// 并发下可能有两个 goroutine 同时重建，结果等价，最后一个赢，无害。
	lists atomic.Pointer[fwLists]

	// limiter 每来源令牌桶。用 ipx 的共享表实现，自带上限、空闲回收与按空闲淘汰。
	limiter *ipx.IPLimiter

	mu        sync.Mutex
	bans      map[[16]byte]*fwBanEntry
	peak      int
	lastSweep time.Time
	// size 是 bans 的条目数副本，供无锁快速路径判断"表是空的"。
	//
	// 没有它的话，每个请求（以及每次 Accept）都要抢一次互斥锁才能知道"没人被封"——
	// 而绝大多数时间这张表就是空的。它只在持有 mu 时被写。
	size atomic.Int32

	// 「新增封禁」日志的抑制状态，见 fwBanLogInterval。
	logMu      sync.Mutex
	lastBanLog time.Time
	banSkipped int
}

func newPanelFirewall(cfg *config.Manager, log *logx.Logger) *panelFirewall {
	return &panelFirewall{
		cfg:       cfg,
		log:       log,
		limiter:   ipx.NewIPLimiter(),
		bans:      make(map[[16]byte]*fwBanEntry),
		lastSweep: time.Now(),
	}
}

// current 返回当前配置快照对应的已解析名单。
func (f *panelFirewall) current() *fwLists {
	snap := f.cfg.Snapshot()
	if c := f.lists.Load(); c != nil && c.src == snap {
		return c
	}
	fw := snap.Settings.Security.Firewall
	n := &fwLists{
		src: snap,
		fw:  fw,
		// NewMatcher 只读入参切片，不持有对快照内存的写权限；
		// 快照按约定是只读的，这里也确实没有任何一处会去改它。
		allow: ipx.NewMatcher(fw.AllowIPs),
		deny:  ipx.NewMatcher(fw.DenyIPs),
	}
	f.lists.Store(n)
	return n
}

// enabled 报告防火墙此刻是否生效。
func (f *panelFirewall) enabled() bool { return f.current().fw.Enabled }

// decide 对来源 IP 做**不含限速**的判定。监听器与中间件共用这一个函数，
// 于是两层的语义不可能走偏。
//
// 顺序（每一步都解释了为什么它必须在这个位置）：
//
//  1. **拒绝名单最先**，连回环都不豁免。它是用户明确写下的"这个不许进"，
//     任何自动规则都不该把它推翻；与 webservice 的 withIPFilter 同向。
//
//  2. **回环紧随其后**，豁免后面的一切自动判定。这是最后的自救通道：
//     配置写错、把自己关在门外时，还能从本机（或一条 SSH 隧道）进面板改回来。
//     一个能在本机发起连接的人，早就有比"绕过面板防火墙"更直接的手段。
//
//  3. **允许名单先于自动封禁**：写进允许名单是人做的明示决定，自动封禁是机器的推测；
//     推测不该推翻明示，否则用户会遇到"我明明加白了却还是进不来"，而且无从得知原因。
//     对应地，被加白的来源在 strike 里根本不会被计数（见那里的同一条理由）。
//
//  4. **允许名单先于 Mode**，因此"只允许局域网 + 允许名单里写着办公室出口 IP"
//     是一个可表达的策略。没有这一条，用户想放行一个外网地址就只能整个改成
//     不限来源——这是最容易被误用成"干脆全开"的那种设计。
//
//  5. **Mode 最后**：它是范围判断，前面几条都是针对具体地址的例外。
//
// ip 为 nil（对端地址解析不出来）时一律拒绝：这是失败关闭。放行的话，
// 一个畸形的 RemoteAddr 就等于把整道防火墙绕过去了。
func (f *panelFirewall) decide(l *fwLists, ip net.IP) fwVerdict {
	if !l.fw.Enabled {
		return fwPass
	}
	if ip == nil {
		return fwDenyNoIP
	}
	if l.deny.Match(ip) {
		return fwDenyList
	}
	if ip.IsLoopback() {
		return fwPass
	}
	if l.allow.Match(ip) {
		return fwPass
	}
	if f.isBanned(ip) {
		return fwDenyBanned
	}
	// 判的是「不是 all」而不是「等于 lan」：认不出的 Mode 要落到更严的那一侧。
	//
	// 规范化（config.normalizePanelFirewall）保证只会存下 lan / all 两个值，
	// 但它挂在加载与保存两条路径上，而 config.Manager.Update 刻意不跑 migrate——
	// 也就是说这条不变量靠的是"每个写入方都记得规范化"。按 == lan 写的话，一个
	// 手改的配置文件、或将来某个忘了规范化的新写入方，只要让 Mode 变成认不出的值，
	// 整道范围判定就会静默失效、防火墙看着是开的却谁都放进来。
	// 反过来写，同样的失误只会把面板收紧到仅局域网——那是能被发现并改回来的方向。
	if l.fw.Mode != config.FirewallModeAll && !ipx.IsLAN(ip) {
		return fwDenyScope
	}
	return fwPass
}

// isBanned 查自动封禁表。表空时不加锁直接返回（常态）。
//
// 顺手做一次到期清扫：清扫原本只挂在 strike 上，而 strike 只在"有人被限速拦下"时才跑。
// 攻击停了以后就没人再调它，于是过期条目会一直留在表里、size 永远大于零，
// 之后每个请求（与每次 Accept）都要为一张全是死条目的表抢一次锁。
// 这里已经持有 mu，清扫是顺路的事；它自带最小间隔（fwBanSweepInterval），
// 全表最多 fwBanMaxEntries 条，摊到每分钟一次可以忽略。
func (f *panelFirewall) isBanned(ip net.IP) bool {
	if f.size.Load() == 0 {
		return false
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	now := time.Now()
	f.sweepLocked(now)
	e := f.bans[ipx.Key(ip)]
	return e != nil && now.Before(e.until)
}

// allowRate 取一个令牌；RateLimit<=0 表示不限速。
func (f *panelFirewall) allowRate(l *fwLists, key string) bool {
	if l.fw.RateLimit <= 0 {
		return true
	}
	return f.limiter.Allow(fwLimiterScope, key, float64(l.fw.RateLimit))
}

// strike 记一次「被限速拦下」，必要时转为封禁；返回本次是否**新**产生了一条封禁。
//
// 计数窗口是滑动重置而不是滑动窗口：距上次计数起点超过窗口就从头再数。
// 精确的滑动窗口要为每个来源留一串时间戳，而这里要抗的正是"来源可以无限多"，
// 把每条记录压到定长是刻意的取舍。
func (f *panelFirewall) strike(l *fwLists, ip net.IP, display string) bool {
	if !l.fw.AutoBan || ip == nil || ip.IsLoopback() {
		return false
	}
	// 允许名单里的来源永不封禁：明示压过推测（见 decide 第 3 条）。
	// 少了这一句，用户把自己加白之后照样会因为手速过快被机器关在门外。
	if l.allow.Match(ip) {
		return false
	}
	window := time.Duration(config.FirewallAutoBanWindowMinutes()) * time.Minute
	banFor := time.Duration(l.fw.AutoBanMinutes) * time.Minute
	threshold := l.fw.AutoBanThreshold

	f.mu.Lock()
	defer f.mu.Unlock()
	now := time.Now()
	f.sweepLocked(now)

	k := ipx.Key(ip)
	e := f.bans[k]
	if e == nil {
		if len(f.bans) >= fwBanMaxEntries {
			// 表满：先清一批，清不动就放弃这一次计数。
			//
			// 放弃计数而不是"挤掉别人"，方向与 ipx.IPLimiter 相反，因为代价不对称：
			// 那边被挤掉意味着某个来源少限一次速（自愈），这边被挤掉意味着
			// **一条正在生效的封禁被提前解除**。让新来的少数一次，比让已确认的攻击者
			// 提前放出来要安全。上限本身仍是硬的，内存不会因此增长。
			f.evictLocked(now)
			if len(f.bans) >= fwBanMaxEntries {
				return false
			}
		}
		e = &fwBanEntry{ip: display, firstHit: now}
		f.bans[k] = e
		f.size.Store(int32(len(f.bans)))
		if n := len(f.bans); n > f.peak {
			f.peak = n
		}
	}
	if now.Before(e.until) {
		// 已经封着了。仍然刷新计数起点，好让解封后紧接着的下一轮超限
		// 不必从"上一轮的旧窗口"里继承一个可能已经过期的起点。
		e.firstHit = now
		e.strikes = 0
		return false
	}
	if now.Sub(e.firstHit) > window {
		e.firstHit = now
		e.strikes = 0
	}
	e.strikes++
	if e.strikes < threshold {
		return false
	}
	e.strikes = 0
	e.firstHit = now
	e.bannedAt = now
	e.until = now.Add(banFor)
	e.banRounds++
	return true
}

// sweepLocked 清掉既没在封禁、计数窗口也早已过去的条目；调用方须持有 f.mu。
func (f *panelFirewall) sweepLocked(now time.Time) {
	if now.Sub(f.lastSweep) < fwBanSweepInterval {
		return
	}
	f.lastSweep = now
	window := time.Duration(config.FirewallAutoBanWindowMinutes()) * time.Minute
	for k, e := range f.bans {
		if now.After(e.until) && now.Sub(e.firstHit) >= window {
			delete(f.bans, k)
		}
	}
	f.bans = mapx.ShrinkSparse(f.bans, &f.peak, fwBanShrinkFloor)
	f.size.Store(int32(len(f.bans)))
}

// evictLocked 表满时清掉**已经失效**的条目；调用方须持有 f.mu。
// 不动仍在封禁或仍在计数窗口内的条目——它们正是这张表存在的理由。
func (f *panelFirewall) evictLocked(now time.Time) {
	window := time.Duration(config.FirewallAutoBanWindowMinutes()) * time.Minute
	for k, e := range f.bans {
		if now.After(e.until) && now.Sub(e.firstHit) >= window {
			delete(f.bans, k)
		}
	}
	f.bans = mapx.ShrinkSparse(f.bans, &f.peak, fwBanShrinkFloor)
	f.size.Store(int32(len(f.bans)))
}

// fwBanView 一条封禁记录的对外视图（设置页展示用）。
type fwBanView struct {
	IP       string `json:"ip"`
	BannedAt int64  `json:"bannedAt"` // Unix 秒
	Until    int64  `json:"until"`    // Unix 秒
	Rounds   int    `json:"rounds"`   // 累计被封次数
}

// bans 快照当前**仍在生效**的封禁，按到期时间倒序（最近封的在前）。
// limit<=0 表示不限条数。
func (f *panelFirewall) banList(limit int) []fwBanView {
	f.mu.Lock()
	defer f.mu.Unlock()
	now := time.Now()
	out := make([]fwBanView, 0, len(f.bans))
	for _, e := range f.bans {
		if !now.Before(e.until) {
			continue // 只在计数、尚未封禁，或封禁已过期
		}
		out = append(out, fwBanView{
			IP:       e.ip,
			BannedAt: e.bannedAt.Unix(),
			Until:    e.until.Unix(),
			Rounds:   e.banRounds,
		})
	}
	// 插入排序：条目数受 fwBanMaxEntries 约束，且这个接口只在用户打开设置页时被调用。
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j].Until > out[j-1].Until; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}

// banCount 当前仍在生效的封禁条数。
func (f *panelFirewall) banCount() int {
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

// clearBans 解除全部自动封禁（连计数一起清），返回被解除的封禁条数。
func (f *panelFirewall) clearBans() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	now := time.Now()
	for _, e := range f.bans {
		if now.Before(e.until) {
			n++
		}
	}
	f.bans = make(map[[16]byte]*fwBanEntry)
	f.peak = 0
	f.size.Store(0)
	return n
}

// unban 解除单个 IP 的封禁与计数，返回它此前是否确实被封着。
func (f *panelFirewall) unban(raw string) bool {
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

// logBan 打一条「新增封禁」告警，按 fwBanLogInterval 抑制。
// 被压掉的条数累计进下一条，不会凭空消失。
func (f *panelFirewall) logBan(ip string, minutes int) {
	f.logMu.Lock()
	now := time.Now()
	if !f.lastBanLog.IsZero() && now.Sub(f.lastBanLog) < fwBanLogInterval {
		f.banSkipped++
		f.logMu.Unlock()
		return
	}
	skipped := f.banSkipped
	f.banSkipped = 0
	f.lastBanLog = now
	f.logMu.Unlock()

	args := []any{"ip", ip, "minutes", minutes, "active", f.banCount()}
	if skipped > 0 {
		args = append(args, "suppressed", skipped)
	}
	f.log.Warn("面板防火墙自动封禁", args...)
}

// ---------------------------------------------------------------------------
// 第一层：监听器
// ---------------------------------------------------------------------------

// firewallListener 在 Accept 处按名单/封禁/范围关掉不受欢迎的连接。
//
// 它**不做限速**：限速是请求的属性，而这一层只看得到连接（见文件头的说明）。
type firewallListener struct {
	net.Listener
	fw *panelFirewall
}

// Accept 循环直到取到一个被放行的连接。
//
// 被拒绝的连接直接 Close 并继续循环，**不返回错误**——这是这段代码最要紧的一条：
// http.Server.Serve 见到非临时错误就会退出整个服务。一次拒绝必须对上层完全不可见。
func (l *firewallListener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		lists := l.fw.current()
		if !lists.fw.Enabled {
			return c, nil
		}
		ip := connIP(c)
		if v := l.fw.decide(lists, ip); v != fwPass {
			// Debug 级别：这条路径正是日志洪水的来源，按 WARN 输出等于用一种噪声
			// 换掉另一种。真正值得报警的是"新增了一条封禁"（见 logBan）。
			l.fw.log.Debug("面板防火墙拦截连接",
				"ip", remoteAddrOf(c), "reason", v.reason())
			_ = c.Close()
			continue
		}
		return c, nil
	}
}

// connIP 取连接对端 IP；取不到返回 nil（由 decide 按失败关闭处理）。
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

// wrapListener 在防火墙启用时包一层连接级拦截。
// 关闭时原样返回，连一次指针跳转都不多加。
func (f *panelFirewall) wrapListener(ln net.Listener) net.Listener {
	if f == nil {
		return ln
	}
	return &firewallListener{Listener: ln, fw: f}
}

// ---------------------------------------------------------------------------
// 第二层：中间件
// ---------------------------------------------------------------------------

// firewallGuard 请求级的入站防火墙：复查名单/封禁/范围，并做限速与超限计数。
//
// 位置：紧跟 gin.CustomRecovery 之后、其余一切之前。
// 恢复中间件必须在最外层（它要兜住这里面的任何 panic），除此之外没有任何东西
// 该排在访问控制前面——被拒的来源不该有机会触发日志、压缩、CSRF 判定等任何工作。
func (s *Server) firewallGuard() gin.HandlerFunc {
	f := s.firewall
	return func(c *gin.Context) {
		if f == nil {
			c.Next()
			return
		}
		lists := f.current()
		if !lists.fw.Enabled {
			c.Next()
			return
		}
		// 只取真实对端，不看任何代理头：那些头由请求方填写，
		// 拿它做访问控制等于把名单交给对方（同 ipx.ClientIP 的说明）。
		ip := ipx.ClientIP(c.Request)
		// who 同时是限流分桶键、封禁表的展示原文与日志里的来源。
		// 解析得出时用 ip.String() 的归一形式，好让同一个地址不会因为写法不同
		// （如 ::ffff:1.2.3.4 与 1.2.3.4）分到两个令牌桶。
		who := ipx.RemoteHost(c.Request.RemoteAddr)
		if ip != nil {
			who = ip.String()
		}
		if v := f.decide(lists, ip); v != fwPass {
			f.log.Debug("面板防火墙拦截请求",
				"ip", who, "path", c.Request.URL.Path, "reason", v.reason())
			writeFirewallRejected(c)
			return
		}
		if !f.allowRate(lists, who) {
			if f.strike(lists, ip, who) {
				f.logBan(who, lists.fw.AutoBanMinutes)
			}
			writeFirewallThrottled(c)
			return
		}
		c.Next()
	}
}

// writeFirewallRejected 「你的来源不被允许」。
//
// 措辞里刻意不出现"面板""防火墙""局域网"这些词，也不区分四种拒绝原因：
// 这四种的差别恰好就是名单与策略本身的内容，那是不该从一个 403 页面上读出来的。
// 真实原因进 Debug 日志。
//
// 与 respondUnauthorized 一样分两路：面板前端靠 JSON 的 error 字段显示，
// 浏览器直敲地址栏的拿一页卡片。
func writeFirewallRejected(c *gin.Context) {
	c.Abort()
	if !errpage.WantsHTML(c.Request) {
		respondError(c, http.StatusForbidden, "访问被拒绝")
		return
	}
	errpage.Write(c.Writer, c.Request, errpage.Page{
		Status: http.StatusForbidden,
		Title:  "访问被拒绝",
		Detail: "当前来源不在允许访问的范围内。",
	})
}

// writeFirewallThrottled 429。Retry-After 给一秒：令牌桶按秒补充，等一秒必然又有额度。
func writeFirewallThrottled(c *gin.Context) {
	c.Abort()
	c.Writer.Header().Set("Retry-After", "1")
	if !errpage.WantsHTML(c.Request) {
		respondError(c, http.StatusTooManyRequests, "请求太频繁了，请稍后再试")
		return
	}
	errpage.Write(c.Writer, c.Request, errpage.Page{
		Status: http.StatusTooManyRequests,
		Title:  "请求太频繁了",
		Detail: "你的请求速度超出了限制。",
		Hint:   "等一会儿再刷新即可。",
	})
}

// ---------------------------------------------------------------------------
// 启动提示
// ---------------------------------------------------------------------------

// logFirewallState 启动时把防火墙的当前状态说清楚。
//
// 这条日志不是装饰：全新安装默认「只允许局域网」，装在 VPS 上的用户第一次启动就会
// 发现公网连不上面板，而连接是被直接关掉的——浏览器上看到的是"无法连接"，
// 与"服务没起来"长得一模一样。日志是他唯一能拿到的线索，因此必须把放开的办法写出来。
func (s *Server) logFirewallState() {
	if s.firewall == nil {
		return
	}
	fw := s.firewall.current().fw
	if !fw.Enabled {
		return
	}
	args := []any{
		"mode", fw.Mode,
		"rateLimit", fw.RateLimit,
		"autoBan", fw.AutoBan,
		"allow", len(fw.AllowIPs),
		"deny", len(fw.DenyIPs),
	}
	if fw.Mode == config.FirewallModeLAN {
		s.deps.Log.Warn("面板入站防火墙已启用：仅允许局域网访问。"+
			"若需从公网访问，请在「设置 → 登录安全 → 入站防火墙」改为不限来源，"+
			"或把可信 IP 加入允许名单；无法登录时可先经 SSH 隧道从本机进入面板", args...)
		return
	}
	s.deps.Log.Info("面板入站防火墙已启用", args...)
}
