package webservice

import (
	"net/http"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"mantou/internal/errpage"
	"mantou/internal/ipx"
	"mantou/internal/mapx"
)

// 本文件实现「公网扫描自动封禁」：一个来源在短时间内制造大量"什么都没打中"的请求时，
// 临时把它整体挡在门外，不再让它触达任何子项处理器。
//
// 为什么需要它。面板那侧早就有自动封禁（失败登录 → 封 IP），但那是面板自己的，
// 只保护管理端口。Web 服务这一侧托管的是用户真正暴露在公网上的站点，而它此前只有
// 「每 IP 每秒请求数」这一道闸——那个闸按请求数计，一个页面几十个子资源就要几十个令牌，
// 因此只能配得很宽（多数用户干脆不开）。结果是：一台扫描器可以整天用每秒两三个请求
// 遍历几万条路径找后台、找 .git、找 .env，从头到尾不越过任何一道限制。
// 单看每一个请求都合规，合起来是一次完整的资产测绘。
//
// 这道闸只数"没打中"的请求（401 / 403 / 404），因此它的判据与"访问量大"无关：
// 一个真实站点无论多热闹，都不会在一分钟内产出两百次 4xx；而扫描器的每一发几乎
// 必然是 4xx，因为它猜的路径本来就不存在。
//
// 三条刻意的边界：
//
//   - **没有配置项**。阈值定得远高于任何真实流量（见 scanBanStrikes 的算术），
//     因此不需要用户判断"该配多少"；多一个开关等于多一个可以配错的地方。
//
//   - **豁免局域网**。局域网里跑着的自动化（监控探针、内网爬虫、CI）撞 404 的花样最多，
//     而它们不是威胁模型里的对象。判据用 ipx.IsLAN，与面板的"仅局域网"同一口径。
//
//     由此带来一个必须说清楚的边界：mantou 挂在**同机** nginx / cloudflared 后面时，
//     每个请求的对端都是 127.0.0.1，于是这道闸对那台机器上的全部外部流量一并失效。
//     这不是疏漏而是唯一安全的选择——ipx.ClientIP 刻意不采信 X-Forwarded-For（那是
//     请求方能随便填的），所以在那种拓扑里这道闸能封的只有 127.0.0.1 本身，而封掉它
//     等于把整个站点关掉。这种部署形态下请让前面那层反代自己做扫描防护（nginx 的
//     limit_req、Cloudflare 的 WAF），它才是唯一知道真实来源的一环。
//
//   - **表是全模块共用一张、只按来源 IP 分键**，不按子项分。被扫的是这台机器，
//     不是某一个站点；扫描器在 A 站上暴露了自己，就没有理由让它接着去扫 B 站。
const (
	// scanBanWindow 记账窗口。窗口内累计到 scanBanStrikes 次即封禁；
	// 窗口过完自动清零，因此"每天零星撞几个 404"永远攒不起来。
	scanBanWindow = 60 * time.Second
	// scanBanStrikes 触发封禁的无效请求次数。
	//
	// 取 200 是往"绝不误伤"那一侧留足了余量：一分钟 200 次 4xx 等于持续每秒 3.3 次，
	// 而真实站点的 4xx 几乎只来自"页面里有几张图片挂了"这类情形——那种情况一次刷新
	// 产生几十条，随后被浏览器缓存住，下一次刷新不再重复。要靠正常浏览凑满 200，
	// 得在一分钟内不停刷新一个坏了几十处的页面。
	//
	// 而对扫描器这个数并不宽松：它意味着一次扫描最多探到 200 条路径就被打断 10 分钟，
	// 折算下来每小时不到 1200 条，常见字典（几万到几十万条）要跑上几天到几十天，
	// 期间每一次封禁都在日志里留痕。
	scanBanStrikes = 200
	// scanBanDuration 单次封禁时长。取 10 分钟：足以让自动化工具超时放弃并把这个目标
	// 判成"不可达"，又短到即便真误伤了谁，等一杯茶的工夫就自己恢复，不需要人去解封。
	scanBanDuration = 10 * time.Minute
	// scanBanMaxEntries 表内最多保留多少个来源，防止海量来源把内存撑爆。
	// 每条约 100 字节，8192 条约 0.8 MB，与 ipx 的桶表同一个量级。
	scanBanMaxEntries = 8192
	// scanBanShrinkFloor 触发整表重建的最小峰值：一次扫描能把表撑到上限附近，
	// 而 delete 不归还 map 桶内存（见 mapx.ShrinkSparse），退潮后那块内存会一直挂着。
	scanBanShrinkFloor = 512
	// scanBanEvictBatch 表满时一次淘汰的条数上限。成批淘汰是为了摊薄开销——
	// 挑淘汰对象要扫一遍全表，一次只淘汰一个就等于每来一个新来源付一次全表扫描。
	scanBanEvictBatch = scanBanMaxEntries / 8
)

// scanBanEntry 一个来源的记账状态。
type scanBanEntry struct {
	strikes  int       // 当前窗口内的无效请求数
	winStart time.Time // 当前窗口起点
	banUntil time.Time // 封禁到期时间；零值表示未被封禁
	seen     time.Time // 最近一次记账时间，供淘汰与回收判断"闲不闲"
}

// scanBanner 是那张按来源 IP 记账的表。
//
// 所有方法都对 nil 接收者安全：测试里直接组装的 &Module{} 没有这张表，
// 那种模块只该表现为"没有这道闸"，而不是在第一个请求上崩掉。
type scanBanner struct {
	mu      sync.Mutex
	entries map[string]*scanBanEntry
	lastGC  time.Time
	// peak 记录 entries 见过的最大条目数，供 GC 判断是否该重建 map 以真正释放内存。
	peak int
	// hot 是"当前最晚的一个封禁到期时间"（UnixNano），只增不减、用 CAS 抬高。
	//
	// 它存在的唯一目的是让 banned 在无人被封禁时**完全不加锁**：那是绝大多数时候的
	// 真实情况，而 banned 挂在每一个请求的最外层。一旦所有封禁都过期，hot 落到当下之前，
	// 这张表就重新退回"零成本"。只增不减让它可能偏晚（最后一个封禁过期后的一段时间里
	// 仍会走加锁路径），代价只是那段时间里每个请求多一次 map 查找，没有正确性影响。
	hot atomic.Int64
}

func newScanBanner() *scanBanner {
	return &scanBanner{entries: make(map[string]*scanBanEntry), lastGC: time.Now()}
}

// scanBanKey 取这次请求在表里的键。第二个返回值为 false 表示这个来源豁免记账。
//
// 解不出对端 IP 时回退到去端口的 RemoteAddr（与 ipx.LimitKey 同口径），
// 而不是豁免：一个畸形的 RemoteAddr 不该成为绕过这道闸的办法。
func scanBanKey(r *http.Request) (string, bool) {
	ip := ipx.ClientIP(r)
	if ipx.IsLAN(ip) {
		return "", false
	}
	if ip == nil {
		return ipx.RemoteHost(r.RemoteAddr), true
	}
	return ip.String(), true
}

// banned 报告这次请求是否来自正在封禁中的来源，以及还要等多久。
//
// 这是每个请求都要过一遍的判定，所以先看 hot：无人被封禁时它连锁都不碰。
func (b *scanBanner) banned(r *http.Request, now time.Time) (retry time.Duration, ok bool) {
	if b == nil || b.hot.Load() <= now.UnixNano() {
		return 0, false
	}
	key, count := scanBanKey(r)
	if !count {
		return 0, false
	}
	b.mu.Lock()
	var until time.Time
	if e := b.entries[key]; e != nil {
		until = e.banUntil
	}
	b.mu.Unlock()
	// 刻意不刷新 e.seen：封禁期间对方一直在撞门是常态，若把撞门也算成"活跃"，
	// 这条记录在封禁过期后永远等不到被回收的那一刻。
	if until.After(now) {
		return until.Sub(now), true
	}
	return 0, false
}

// strike 记一次"没打中"的请求。
//
// 返回封禁到期时间，以及这一次是否**刚刚**促成了封禁——只有"刚刚"那一次为 true，
// 调用方据此写一条日志。持续撞门不会反复触发，所以日志量与对方的请求量无关。
func (b *scanBanner) strike(r *http.Request, now time.Time) (until time.Time, newly bool) {
	if b == nil {
		return time.Time{}, false
	}
	key, count := scanBanKey(r)
	if !count {
		return time.Time{}, false
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.gcLocked(now)
	e := b.entries[key]
	if e == nil {
		if len(b.entries) >= scanBanMaxEntries {
			b.evictLocked(now)
			if len(b.entries) >= scanBanMaxEntries {
				// 腾不出位置，只可能是 8192 个来源同时处于封禁中（淘汰刻意不动它们）。
				// 此时放弃给新来源建账：这道闸退化成"不再新增封禁"，而不是让表继续长大。
				return time.Time{}, false
			}
		}
		e = &scanBanEntry{winStart: now}
		b.entries[key] = e
		if n := len(b.entries); n > b.peak {
			// 高水位只能在插入时记录：gcLocked 隔一段时间才跑一次，且是在删除之后才看长度，
			// 单靠它永远看不到真正的峰值，收缩条件也就永不成立。
			b.peak = n
		}
	}
	e.seen = now
	if now.Sub(e.winStart) >= scanBanWindow {
		e.winStart = now
		e.strikes = 0
	}
	e.strikes++
	if e.strikes < scanBanStrikes {
		return time.Time{}, false
	}
	if now.Before(e.banUntil) {
		// 已在封禁中还能走到这里，只能是封禁刚生效、这个请求已经在途。不重复登记。
		return e.banUntil, false
	}
	e.banUntil = now.Add(scanBanDuration)
	// 计数清零并重开窗口：封禁期满后从头开始数，而不是带着上一轮的余额一进门就再被封。
	e.strikes = 0
	e.winStart = now
	b.bumpHot(e.banUntil)
	return e.banUntil, true
}

// bumpHot 把 hot 抬到 until（若它更晚）。见 scanBanner.hot 的说明。
func (b *scanBanner) bumpHot(until time.Time) {
	n := until.UnixNano()
	for {
		cur := b.hot.Load()
		if cur >= n {
			return
		}
		if b.hot.CompareAndSwap(cur, n) {
			return
		}
	}
}

// Len 当前条目数。给测试用。
func (b *scanBanner) Len() int {
	if b == nil {
		return 0
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.entries)
}

// gcLocked 周期性回收既没在封禁中、又已经闲过一个窗口的条目；调用方须持有 b.mu。
// 闲过一个窗口意味着它的计数下次也会被清零，那条记录已经不含任何信息。
func (b *scanBanner) gcLocked(now time.Time) {
	if now.Sub(b.lastGC) < scanBanWindow {
		return
	}
	b.lastGC = now
	for k, e := range b.entries {
		if now.Before(e.banUntil) {
			continue
		}
		if now.Sub(e.seen) >= scanBanWindow {
			delete(b.entries, k)
		}
	}
	b.entries = mapx.ShrinkSparse(b.entries, &b.peak, scanBanShrinkFloor)
}

// evictLocked 在表满时淘汰一批条目，腾位置给新来源；调用方须持有 b.mu。
//
// 只淘汰"没在封禁中"的：把正在封禁的挤出去等于给对方开一条逃生通道——
// 制造足够多的新来源就能把自己解封，而那对 IPv6 下的攻击者几乎没有成本。
//
// 阈值取平均空闲时长，一次最多 scanBanEvictBatch 条。取平均是为了保证有进展：
// 平均值必然不大于最大值，因此至少最闲的那一条会被删掉。
func (b *scanBanner) evictLocked(now time.Time) {
	var total time.Duration
	n := 0
	for _, e := range b.entries {
		if now.Before(e.banUntil) {
			continue
		}
		total += now.Sub(e.seen)
		n++
	}
	if n == 0 {
		return // 全都在封禁中：不腾位置，由调用方放弃新增
	}
	cutoff := total / time.Duration(n)
	removed := 0
	for k, e := range b.entries {
		if now.Before(e.banUntil) || now.Sub(e.seen) < cutoff {
			continue
		}
		delete(b.entries, k)
		removed++
		if removed >= scanBanEvictBatch {
			return
		}
	}
}

// scanBanCountable 报告这次响应是否该记一次账。
//
// 只认 401 / 403 / 404——"你要的东西不在这儿"或"你没资格"，也就是扫描器几乎每一发
// 都会拿到的那三种。刻意排除：
//
//   - 5xx：那是**服务端**出了问题，把它算进来等于后端一抖就自己封掉一批真实访客；
//   - 429：那是本机限流刚刚回绝的请求，算进来就成了"因为被限流所以被封禁"的自激；
//   - 400 / 431 等：畸形请求由 net/http 在触达处理器之前就回掉了，这里根本看不到；
//   - 客户端主动挂断：状态码不代表服务端的判断。
func scanBanCountable(sw *statusWriter) bool {
	if sw.clientAborted {
		return false
	}
	switch sw.status {
	case http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound:
		return true
	}
	return false
}

// writeScanBanned 回给正在封禁中的来源的响应。
//
// 用 429 而不是 403：封禁是**临时**的，429 是唯一能把"过一会儿再来"说清楚的状态码，
// 也是 Retry-After 的标准归属（RFC 9110 §10.2.3）。403 还有一个副作用——
// 不少扫描器把 403 当成"这儿有东西，只是没权限"的线索，反而会去重点关照。
//
// 措辞与限流那一页几乎一致，也是有意的：页面上不该出现"你被封禁了"这类信息，
// 那等于告诉对方这台机器有封禁机制、以及自己踩到了哪条线。
func writeScanBanned(w http.ResponseWriter, r *http.Request, retry time.Duration) {
	secs := int(retry.Seconds()) + 1
	w.Header().Set("Retry-After", strconv.Itoa(secs))
	errpage.Write(w, r, errpage.Page{
		Status: http.StatusTooManyRequests,
		Title:  "请求太频繁了",
		Detail: "这个站点暂时不再接受来自你的请求。",
		Hint:   "稍等几分钟后再试即可。",
	})
}

// recordScanBan 记一条封禁事件：程序日志必写，访问日志按子项归属写。
//
// 事件类型复用 denied（「拒绝」）而不是新增一种：对来访者而言这确实是一次拒绝，
// 前端与接口都已认识这个类型，真实原因写在 Reason 里。新增一种事件类型要同时
// 动前端的标签映射与两份 i18n，而换来的信息量正好等于 Reason 那一句话。
//
// 不过抑制器：封禁本身就是每个来源每 scanBanDuration 至多一次，频率已经有界，
// 再压一层反而可能把"刚过期又立刻被封"的第二条吞掉——而那一条恰恰最值得看见。
// 全局写速令牌桶仍然过：极端情况下可能有海量来源在同一瞬间各自触线。
//
// childID 为空表示这次封禁是在监听层（未匹配到站点）触发的，不归属任何子项。
// 此时只写程序日志：访问日志按子项过滤查看，一条没有归属的记录在界面上看不见，
// 却照样占掉环形缓冲的槽位。
func (m *Module) recordScanBan(service, childID, ip string, until time.Time) {
	now := time.Now()
	if !m.logRate.allow(now) {
		return
	}
	mins := int(scanBanDuration / time.Minute)
	reason := "来源在 " + strconv.Itoa(int(scanBanWindow/time.Second)) + " 秒内产生大量无效请求，已临时封禁 " +
		strconv.Itoa(mins) + " 分钟"
	if childID != "" {
		m.recordAccess(AccessEntry{
			Time:    now.UnixMilli(),
			ChildID: childID,
			Service: service,
			Method:  eventLabel(eventDenied),
			Status:  http.StatusTooManyRequests,
			Remote:  ip,
			Event:   eventDenied,
			Reason:  reason,
		})
	}
	parent, child := splitService(service)
	m.log.Warn(accessSentence("被临时封禁，访问", ip, parent, child, 0, reason),
		"childId", childID, "until", until.Format(time.RFC3339))
}
