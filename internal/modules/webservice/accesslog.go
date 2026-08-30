package webservice

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"mantou/internal/ipx"
	"mantou/internal/logx"
	"mantou/internal/mapx"
	"mantou/internal/strutil"
)

// 本文件是 webservice 的「访问事件」记录层：环形缓冲（AccessEntry）、
// 同源抑制（logSuppressor）与全局写速限制（logRateLimiter），以及给面板用的读接口。
//
// 需要强调的是它记录的是**事件**而不是每一个 HTTP 请求：一条连接在窗口内只留首条，
// 全局写速还有 10 条/秒的硬上限。这是刻意的取舍——它是给人看的连接状态视图，
// 不是可用于计费或审计的完整请求流水。

// AccessEntry 一条访问（连接）日志记录，供前端「日志」按钮展示连接信息。
// 注意：访问日志不再记录请求路径（path），仅保留「谁(ip)、访问了哪个服务、何种事件、状态码」等必要信息，避免路径噪音。
type AccessEntry struct {
	Time    int64  `json:"time"`    // Unix 毫秒
	ChildID string `json:"childId"` // 所属子项
	Service string `json:"service"` // 展示名：父项名（/ 子项备注）
	Method  string `json:"method"`
	Host    string `json:"host"`
	Status  int    `json:"status"`
	DurMS   int64  `json:"ms"`
	Remote  string `json:"remote"`
	Event   string `json:"event"`            // 事件类型：connect=连接 / disconnect=断开 / error=错误 / denied=拒绝（前端据此标注）
	Reason  string `json:"reason,omitempty"` // 错误/拒绝的具体原因（上游 err.Error() 或 IP 规则模式说明）
}

// 访问（连接）日志仅记录三类事件，保持精简、不刷屏：
//   - connect：连接 —— 客户端成功建连并取回响应（含新连接 / 在途活动）；
//   - disconnect：断开 —— 客户端主动挂断（context canceled 等），非后端故障；
//   - error：错误 —— 状态码 ≥400（含 50X 与 404），排除客户端挂断。
//   - denied：拒绝 —— IP 规则拒绝（黑名单命中或白名单未命中）。
//   - probe：探测 —— 60s 周期主动探测的可达性结果（仅在状态变化或首次探测时记录，
//     与总览页「程序日志」的「后端 X 连接正常/访问错误」同源、同节流）。
const (
	eventConnect    = "connect"
	eventDisconnect = "disconnect"
	eventError      = "error"
	eventDenied     = "denied" // IP 规则拒绝：黑名单命中或白名单未命中
	eventProbe      = "probe"  // 周期主动探测结果：连接正常 / 访问错误+原因
)

// logSuppressWindow 日志抑制窗口：同一 (IP + 事件类型) 或同一 (子项+路径+状态码 签名)
// 仅记录首条，窗口内其余全部静默，避免 NAS 心跳 / 后端抖动等高频场景刷屏。默认 10 分钟。
const logSuppressWindow = 10 * time.Minute

// logMaxBuckets 抑制表硬上限，防止极端情况下映射无限增长、占用过多内存。
const logMaxBuckets = 8192

// logSuppressorShrinkFloor 触发整表重建的最小峰值：一次扫描能把抑制表撑到上限附近，
// 而过期清理只 delete 条目、不归还 map 桶内存（见 mapx.ShrinkSparse），
// 不重建就等于每遭一次扫描永久损失一块内存。峰值低于该阈值时不值得为此付一次全表拷贝。
const logSuppressorShrinkFloor = 1024

// logSuppressor 内存受限的日志去重器：
//   - 连接 / 断开：按「IP + 事件类型」在窗口内仅首条可记录；
//   - 错误：按「子项+路径+状态码」签名在窗口内仅首条可记录。
//
// 映射条目周期性清理（过期即删），超过硬上限时再强制裁剪，整体内存占用有界。
type logSuppressor struct {
	mu        sync.Mutex
	buckets   map[string]time.Time
	lastClean time.Time
	// peak 记录 buckets 见过的最大条目数，供 clean 判断是否该重建 map 以真正释放内存。
	peak int
}

func newLogSuppressor() *logSuppressor {
	return &logSuppressor{buckets: make(map[string]time.Time, 512), lastClean: time.Now()}
}

// allow 判断 key 是否应在当前窗口内记录：窗口外或首次 → 记录并刷新时间戳；窗口内 → 抑制（false）。
// 写入后做周期性清理与硬上限裁剪，保证内存有界。
func (s *logSuppressor) allow(key string, now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if now.Sub(s.lastClean) >= time.Minute {
		s.clean(now)
		s.lastClean = now
	}
	if t, ok := s.buckets[key]; ok && now.Sub(t) < logSuppressWindow {
		return false
	}
	s.buckets[key] = now
	// 高水位只能在插入时记录：clean 至多每分钟跑一次，且是在删除之后才看长度，
	// 单靠它永远看不到真正的峰值，收缩条件也就永不成立。
	if n := len(s.buckets); n > s.peak {
		s.peak = n
	}
	if len(s.buckets) > logMaxBuckets {
		s.clean(now)
		if len(s.buckets) > logMaxBuckets {
			// 仍超上限（极罕见）：直接清空，仅短暂丢失去重状态，换取内存有界。
			s.buckets = make(map[string]time.Time, 512)
			s.lastClean = now
			s.peak = 0 // 新表已按小容量分配，旧峰值不再对应任何实际占用
		}
	}
	return true
}

// clean 删除已超过窗口的条目；随后判断是否该整表重建，把删空后仍挂着的桶内存换掉。
func (s *logSuppressor) clean(now time.Time) {
	for k, t := range s.buckets {
		if now.Sub(t) >= logSuppressWindow {
			delete(s.buckets, k)
		}
	}
	s.buckets = mapx.ShrinkSparse(s.buckets, &s.peak, logSuppressorShrinkFloor)
}

// logGlobalRPS 访问日志全局写速上限（条/秒）。在「按 IP/签名 去重」之外再兜一层：
// 即便海量不同 IP 各自通过去重（每个都是新 key），实际落盘/入环形缓冲的写速也被压到该值，
// 防止扫描 / CC 等场景下日志写盘与 CPU 被打爆。内存已由环形缓冲与抑制表的有界上限保证。
const logGlobalRPS = 10

// initialAccessRing 是访问事件环的首次分配条数，之后按需翻倍到目标容量
// （目标容量即全局「日志最大条数」，见 Module.SetAccessCap）。只影响分配时机，不影响可见行为。
const initialAccessRing = 64

// logRateLimiter 访问日志全局写速令牌桶：每秒补充 logGlobalRPS 个令牌，桶容量同为 logGlobalRPS。
type logRateLimiter struct {
	mu     sync.Mutex
	tokens float64
	last   time.Time
}

func newLogRateLimiter() *logRateLimiter {
	return &logRateLimiter{tokens: float64(logGlobalRPS), last: time.Now()}
}

// allow 尝试消费一个令牌：令牌充足则放行并扣减，否则拒绝（限速）。
func (l *logRateLimiter) allow(now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	elapsed := now.Sub(l.last).Seconds()
	switch {
	case elapsed < 0:
		// 时钟被往回拨了（NTP 一次大步校正、或有人改了系统时间）。
		// 只把基准挪到当下、这一轮不补令牌：不处理的话 l.last 会一直停在未来，
		// 之后每次 elapsed 都是负数、桶永远补不上，访问日志就此**整体停写**，
		// 直到真实时间追上那个偏差为止（可能是几小时）。而现场看到的是
		// "日志突然什么都不记了"，配置与开关全都正常，几乎无从下手。
		l.last = now
	case elapsed > 0:
		l.tokens += elapsed * float64(logGlobalRPS)
		if l.tokens > float64(logGlobalRPS) {
			l.tokens = float64(logGlobalRPS)
		}
		l.last = now
	}
	if l.tokens >= 1 {
		l.tokens--
		return true
	}
	return false
}

// maxAccessFieldBytes 访问日志里由请求方决定内容的字段（Host、错误原因）的长度上限。
//
// 环形缓冲的内存预算是按"每条几百字节 × 最多 5000 条"算的（见 recordAccess），
// 而 Host 直接来自请求头：net/http 只管总头部大小（默认上限 1 MB），不管单个 Host 多长。
// 一个字符合法但长达几十万字节的 Host 就能让那份预算失效——5000 条全是这种记录时，
// 环形缓冲本身就能吃掉几个 GB，而"日志有界"这句话在代码里到处写着。
// 256 字节远超任何真实域名（DNS 全名上限 253），截断只会发生在刻意构造的请求上。
const maxAccessFieldBytes = 256

// clampAccessField 把由请求方决定内容的字段截到上限。
func clampAccessField(s string) string {
	if len(s) <= maxAccessFieldBytes {
		return s
	}
	return strutil.Truncate(s, maxAccessFieldBytes, "…")
}

// eventLabel 返回事件类型的中文标注，用于程序日志与前端「请求」列展示。
func eventLabel(kind string) string {
	switch kind {
	case eventConnect:
		return "连接"
	case eventDisconnect:
		return "断开"
	case eventError:
		return "错误"
	case eventDenied:
		return "拒绝"
	case eventProbe:
		return "探测"
	default:
		return kind
	}
}

// splitService 将 "父项 / 子项" 形式的 service 拆回父项名与子项名。
// 无子项备注时仅返回父项名（子项部分为空）。
func splitService(service string) (parent, child string) {
	if i := strings.Index(service, " / "); i >= 0 {
		return strings.TrimSpace(service[:i]), strings.TrimSpace(service[i+3:])
	}
	return strings.TrimSpace(service), ""
}

// accessSentence 生成可读性更好的中文访问摘要（用于程序日志与前端展示），
// 形如「ip为x.x.x.x，访问了Web服务下 父项 规则 下的 子项 服务。」；
// 断开对应「断开了」；错误在末尾追加「 出错（状态码 原因）」；拒绝（IP 规则）追加「（原因）」。
// 无子项时省略「规则 下的」一段。reason 为空时不追加括号段。
func accessSentence(verb, ip, parent, child string, status int, reason string) string {
	var b strings.Builder
	b.WriteString("ip为")
	b.WriteString(ip)
	b.WriteString("，")
	b.WriteString(verb)
	b.WriteString("Web服务下 ")
	b.WriteString(parent)
	if child != "" {
		b.WriteString(" 规则下 ")
		b.WriteString(child)
	}
	b.WriteString(" 服务")
	switch {
	case status == http.StatusForbidden && reason != "":
		fmt.Fprintf(&b, " 被拒绝（%d %s）", status, reason)
	case status > 0 && reason != "":
		fmt.Fprintf(&b, " 出错（%d %s）", status, reason)
	case status > 0:
		fmt.Fprintf(&b, " 出错（%d %s）", status, http.StatusText(status))
	case reason != "":
		fmt.Fprintf(&b, "（%s）", reason)
	}
	b.WriteString("。")
	return b.String()
}

// remoteIP 返回客户端 IP（不含端口）；解析失败时回退到原始 RemoteAddr。
func remoteIP(r *http.Request) string {
	if ip := ipx.ClientIP(r); ip != nil {
		return ip.String()
	}
	return r.RemoteAddr
}

// isClientAbort 判定反向代理错误是否由客户端主动断开造成（而非后端故障）。
// 典型信号：请求上下文被取消（Go 在客户端断开时取消 ctx），以及底层连接已关闭。
// 这类情况不记为「错误」，而记为「断开」，且无需回写 502 / 告警。
func isClientAbort(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.Canceled) {
		return true
	}
	if errors.Is(err, net.ErrClosed) {
		return true
	}
	msg := err.Error()
	if strings.Contains(msg, "context canceled") ||
		strings.Contains(msg, "client closed") ||
		strings.Contains(msg, "use of closed network connection") {
		return true
	}
	return false
}

// ChildLogs 返回指定子项的访问（连接）日志，按时间从新到旧，最多 limit 条。
// childID 为空时返回全部子项的日志。
func (m *Module) ChildLogs(childID string, limit int) []AccessEntry {
	m.statMu.Lock()
	defer m.statMu.Unlock()
	if limit <= 0 || limit > m.accessLen {
		limit = m.accessLen
	}
	out := make([]AccessEntry, 0, limit)
	n := len(m.access)
	// accessNext 指向下一个待写槽位，故 accessNext-1 是最新一条，倒着往回走即时间降序。
	for k := 1; k <= m.accessLen && len(out) < limit; k++ {
		e := &m.access[(m.accessNext-k+n)%n]
		if childID == "" || e.ChildID == childID {
			out = append(out, *e)
		}
	}
	return out
}

// recordAccess 追加一条访问日志，写满后覆盖最旧记录（真环形，见 Module.access 的说明）。
// 注意：链接状态（linkStatus）不再由逐请求驱动，改由周期主动探测 (runProbe) 统一写入，
// 与真实流量、10/s 日志限速完全解耦。
func (m *Module) recordAccess(e AccessEntry) {
	m.statMu.Lock()
	defer m.statMu.Unlock()
	c := m.accessCap
	if c <= 0 {
		c = logx.DefaultLogEntries
	}
	// 环已绕满且还没到目标容量：翻倍扩容（上界即目标容量）。刻意不一上来就按上限分配：
	// 上限可达 5000 条（约 1.2 MB），而绝大多数实例的访问量远达不到，空跑的面板不该
	// 先为"万一"付这份内存。整个进程生命周期内扩容最多发生 log2(5000/64) ≈ 7 次，
	// 之后稳态零分配、零拷贝。
	if n := len(m.access); m.accessLen == n && n < c {
		grow := max(n*2, initialAccessRing)
		m.resizeAccessRingLocked(min(grow, c))
	}
	m.access[m.accessNext] = e
	m.accessNext++
	if m.accessNext == len(m.access) {
		m.accessNext = 0
	}
	if m.accessLen < len(m.access) {
		m.accessLen++
	}
}

// resizeAccessRingLocked 把环重建为长度 c，保留最新的 min(已有条数, c) 条并按时间升序落到
// 新数组开头，因此重建后 accessNext 归位到 accessLen%c。调用方必须持有 statMu。
func (m *Module) resizeAccessRingLocked(c int) {
	if c <= 0 {
		c = logx.DefaultLogEntries
	}
	keep := min(m.accessLen, c)
	buf := make([]AccessEntry, c)
	if n := len(m.access); keep > 0 && n > 0 {
		// 最旧的那条保留记录位于 accessNext-keep；keep ≤ accessLen ≤ n 且 accessNext < n，
		// 因此加一个 n 即可让下标非负。
		for k := 0; k < keep; k++ {
			buf[k] = m.access[(m.accessNext-keep+k+n)%n]
		}
	}
	m.access = buf
	m.accessLen = keep
	m.accessNext = keep % c
}

// recordDenied 记录一条「被 IP 规则拒绝」的访问日志（event=denied），并写入程序日志（WARN）。
// 即便子项「访问日志」开关关闭也会记录——IP 规则拒绝属安全事件，应始终可见（不计入正常流量统计）。
// 复用与正常访问日志相同的抑制器与全局写速令牌桶，保证海量扫描 / CC 场景下内存与写速有界。
func (m *Module) recordDenied(service, childID, ip, mode string) {
	now := time.Now()
	// 抑制：按「IP + 子项」在 10 分钟窗口内仅首条，避免扫描刷屏。
	key := eventDenied + "\x00" + ip + "\x00" + childID
	if !m.suppressor.allow(key, now) {
		return
	}
	// 全局访问日志写速限速：每秒最多 logGlobalRPS 条。
	if !m.logRate.allow(now) {
		return
	}
	reason := "来源 IP 被 IP 规则拒绝"
	switch mode {
	case "allow-miss":
		reason = "来源 IP 不在允许（白名单）列表中"
	case "deny":
		reason = "来源 IP 命中拒绝（黑名单）列表"
	}
	entry := AccessEntry{
		Time:    now.UnixMilli(),
		ChildID: childID,
		Service: service,
		Method:  eventLabel(eventDenied), // 前端「请求」列以「拒绝」标注
		Status:  http.StatusForbidden,
		Remote:  ip,
		Event:   eventDenied,
		Reason:  reason,
	}
	m.recordAccess(entry)
	parent, child := splitService(service)
	verb := "被 IP 规则拒绝，"
	if mode == "allow-miss" {
		verb = "不在白名单被 IP 规则拒绝，"
	}
	m.log.Warn(accessSentence(verb, ip, parent, child, http.StatusForbidden, reason), "childId", childID, "mode", mode)
}

// ---- 周期主动探测：链接状态（linkStatus）的唯一写入来源 ----

// SetAccessCap 设定访问事件环形缓冲的目标容量（条数），取自全局「日志最大条数」。
// 传入值经 logx.NormalizeLogEntries 夹入合法区间；调小时立即重建环形缓冲（保留最新的 c 条），
// 保证内存有界；调大时不预先分配，由 recordAccess 按需增长。
//
// 由 Module.Reload 与设置保存（server.handleUpdateSettings）两处调用，改完立即生效、无需重启。
func (m *Module) SetAccessCap(maxEntries int) {
	c := logx.NormalizeLogEntries(maxEntries)
	m.statMu.Lock()
	m.accessCap = c
	if len(m.access) > c {
		m.resizeAccessRingLocked(c)
	}
	m.statMu.Unlock()
}
