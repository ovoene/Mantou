package webhook

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"mantou/internal/logx"
	"mantou/internal/strutil"
)

// 本文件是执行历史。用户的存储决策是"历史记录写入日志"，所以这里有两个去处：
//
//	内存环   给面板列表用，读得快、重启即空；
//	日志文件 data/logs/webhook.log，每条一行 JSON，靠 logx.RotatingFile 按行数轮转。
//
// 两者容量都跟着「设置 → 日志 → 日志最大条数」走，不再多加一个用户要理解的旋钮
//（见 logx.MinLogEntries 那段说明）；内存这一份另外受 1 MiB 预算约束，
// 见下面的 historyMemBudget。

// 历史事件类型。
const (
	EventReceived = "received" // 收到并已派发
	EventRejected = "rejected" // 鉴权 / 限流 / IP / 体积 / 必填校验被拒
	EventDropped  = "dropped"  // 没有任何规则命中，消息被丢弃
	EventError    = "error"    // 模板缺失或渲染失败
	EventSent     = "sent"     // 出站投递成功
	EventFailed   = "failed"   // 出站投递失败（重试用尽）
	EventRetrying = "retrying" // 出站失败但仍在重试
)

// HistoryQuery 执行历史的筛选条件。空字段表示不筛，Limit ≤ 0 表示不限条数。
//
// 用结构体而不是排一串同类型的参数：`History(receiverID, event, limit)` 这种签名
// 把两个字符串挨在一起，调用方写颠倒了照样编译通过，而症状是"筛选看着没生效"。
type HistoryQuery struct {
	ReceiverID string
	Event      string
	Limit      int
}

// HistoryEntry 一条执行记录。JSON 字段名同时是面板列表与日志文件的格式契约。
type HistoryEntry struct {
	Time       int64  `json:"time"` // Unix 毫秒
	Event      string `json:"event"`
	EventID    string `json:"eventId,omitempty"`
	ReceiverID string `json:"receiverId,omitempty"`
	Receiver   string `json:"receiver,omitempty"`
	Remote     string `json:"remote,omitempty"`
	Status     int    `json:"status,omitempty"` // 回给调用方的 HTTP 状态码
	Rule       string `json:"rule,omitempty"`
	Target     string `json:"target,omitempty"`
	Reason     string `json:"reason,omitempty"`
	DurMS      int64  `json:"ms,omitempty"`
	// SourceID 指向内存里留存的入站原文（见 source.go），空表示没有留存。
	// 只有被拒收与被丢弃的记录才有——那两类的原因是一句结论，不看原文查不下去。
	// 面板据此决定这一行的「来源」要不要做成可点的。
	SourceID string `json:"sourceId,omitempty"`
}

// maxReasonBytes 原因文本的长度上限。原因可能来自对端返回体，不设上限会让
// 一条记录把整个环形缓冲的内存预算吃掉。
const maxReasonBytes = 512

// ---- 内存预算 ----
//
// 这个程序里只活在内存、且装的是**外部推来的内容**的结构一共三个，各自一道字节闸：
//
//	执行历史（本文件）        1 MiB       —— historyMemBudget
//	入站原文留存（source.go） 0 ~ 3 MiB   —— defaultSourceBudget（默认 2 MiB）
//	出站重试队列（notify）     1 MiB       —— notify.queueMemBudget
//
// 相加最多 5 MiB，是这三者的硬上限；出厂默认 4 MiB。
// 中间那一项是界面上可调的（「消息路由 → 模块设置 → 原文留存」，0 表示不留存），
// 另两项写死——它们装的是本程序自己产出的结论与请求，量级由配置决定而不是由对端决定。
//
// 为什么条数上限不够、还要数字节：这些结构装的都是外部推来的内容
// （失败原因可能是对端返回体，消息正文由模板渲染，留存的正文就是对方发的那一整段），
// 条数管不住内存——2000 条各带 512 字节原因就是 1 MB，而这台机器上还有别的模块要用内存。
// 于是条数与字节数各是一道闸，谁先到就从最旧的开始淘汰；被淘汰的记录仍在日志文件里。
const (
	historyMemBudget = 1 << 20 // 1 MiB

	// historyEntryBase 一条记录自身占的字节数：64 位下 HistoryEntry 是 168 字节，
	// 取整到 176 留点零头（history_test.go 有断言守着这个数）。
	historyEntryBase = 176

	// historyMaxEntries 条数上限。
	//
	// 1 MiB 里槽位数组先占掉 2000 × 176 = 352 KB，剩下约 700 KB 装字符串内容，
	// 够 2000 条常见记录（多数记录没有 reason，一条一两百字节）。条数再往上加
	// 只会让空槽位吃掉字节预算，反而让真正能留住的记录变少。
	//
	// 它同时是「设置 → 日志 → 日志最大条数」（最大 5000）的上限：那个数管的是
	// **日志文件**的行数，内存这一份到 2000 条就不再往上走。
	historyMaxEntries = 2000

	// historyQueueDepth 落盘队列的深度。
	//
	// 队列存在的理由见 add：调用方里有 notify 的 4 个投递 worker，磁盘卡一下就占住其中一个。
	// 深度要按内存预算给，不能"给大一点保险些"——队列里躺的是完整的 HistoryEntry，
	// 一条最坏约 900 字节（176 字节结构体 + 512 字节原因 + 其余字段），256 条约 220 KB，
	// 与内存环那 1 MiB 同一个量级；再往上加就等于让磁盘卡顿的时长决定内存占用。
	//
	// 队列满了就丢，且丢的只是**文件**那一份（内存环在锁内同步写好了，面板照常显示），
	// 丢了多少条会补一行说明进文件，见 writeOne。
	historyQueueDepth = 256
)

// history 执行历史：内存环 + 日志文件。
//
// 两者的写入时机不同，这是有意的：内存环在锁内同步更新（面板读的是它，必须立刻准），
// 文件那一份交给一个专属协程去写（磁盘可能卡，而调用方里有入站请求和投递 worker）。
type history struct {
	mu    sync.Mutex
	buf   []HistoryEntry
	head  int // 最旧一条的下标
	count int // 当前条数
	bytes int // 当前所有记录的字符串内容字节数（不含槽位数组本身）
	file  *logx.RotatingFile

	// queue / wg 落盘协程。绑定文件时才创建，没有文件就不留空转协程。
	queue chan HistoryEntry
	wg    sync.WaitGroup
	// closed 已停止收新的落盘请求（close 之后）。内存环仍然照记。
	closed bool
	// dropped 队列满时丢掉的条数，等落盘协程喘过气来补一行说明。
	dropped atomic.Int64
}

// entryBytes 一条记录里"内容"部分的字节数。结构体自身已经算在槽位里（historyEntryBase），
// 这里只数堆上的字符串。
func entryBytes(e HistoryEntry) int {
	return len(e.Event) + len(e.EventID) + len(e.ReceiverID) + len(e.Receiver) +
		len(e.Remote) + len(e.Rule) + len(e.Target) + len(e.Reason) + len(e.SourceID)
}

// historySize 把外部传入的条数夹进合法区间，再压到 historyMaxEntries 以内。
func historySize(n int) int {
	return min(logx.NormalizeLogEntries(n), historyMaxEntries)
}

func newHistory(size int) *history {
	return &history{buf: make([]HistoryEntry, historySize(size))}
}

// setFile 绑定日志文件，并起一个落盘协程。
// 允许为 nil（打不开文件时只留内存历史，不因此让整个模块起不来）。
func (h *history) setFile(f *logx.RotatingFile) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.file = f
	if f == nil || h.queue != nil || h.closed {
		return
	}
	q := make(chan HistoryEntry, historyQueueDepth)
	h.queue = q
	h.wg.Add(1)
	// 把通道当参数传进去，落盘协程因此不必为了拿它去碰 h.mu。
	go h.writeLoop(q)
}

// close 停止落盘：把队列里攒着的写完，再关文件。可重复调用。
//
// 必须等队列排空，否则"退出前刚记的那几条历史"会随进程一起消失——
// 而重启前后那一段恰恰是出问题时最需要翻的。
func (h *history) close() {
	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		return
	}
	h.closed = true
	if h.queue != nil {
		close(h.queue)
	}
	h.mu.Unlock()

	h.wg.Wait()

	h.mu.Lock()
	f := h.file
	h.mu.Unlock()
	if f != nil {
		_ = f.Close()
	}
}

// writeLoop 落盘协程：串行写，顺序即入队顺序。
//
// 只用一个协程，不开池子：同一个 eventId 的"收到 → 命中 → 各目标结果"要在文件里
// 保持先后顺序，多个写者会把它们打乱；而写文件本来也是串行的（RotatingFile 一把锁）。
func (h *history) writeLoop(q chan HistoryEntry) {
	defer h.wg.Done()
	for e := range q {
		h.writeOne(e)
	}
}

// writeOne 写一条到文件。
func (h *history) writeOne(e HistoryEntry) {
	h.mu.Lock()
	f := h.file
	h.mu.Unlock()
	if f == nil {
		return
	}
	// 队列满过就先补一行说明。不补的话，文件里少掉的那一段与"这段时间没有请求"
	// 长得一模一样——按 Swap 取并清零，所以一次拥塞只补一行，不会自己刷屏。
	if n := h.dropped.Swap(0); n > 0 {
		writeHistoryLine(f, HistoryEntry{
			Time:  time.Now().UnixMilli(),
			Event: EventError,
			Reason: fmt.Sprintf("历史落盘一度跟不上，有 %d 条没有写进本文件"+
				"（面板里的执行历史不受影响）", n),
		})
	}
	writeHistoryLine(f, e)
}

// writeHistoryLine 一条记录一行 JSON。
func writeHistoryLine(f *logx.RotatingFile, e HistoryEntry) {
	if b, err := json.Marshal(e); err == nil {
		_, _ = f.Write(append(b, '\n'))
	}
}

// logFile 返回已绑定的日志文件，未绑定时为 nil。
func (h *history) logFile() *logx.RotatingFile {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.file
}

// setCap 跟随「日志最大条数」热调整容量（上限 historyMaxEntries）。
// 缩容会丢掉旧记录——它们已经在日志文件里了。
func (h *history) setCap(size int) {
	size = historySize(size)
	h.mu.Lock()
	defer h.mu.Unlock()
	if size == len(h.buf) {
		return
	}
	h.buf = make([]HistoryEntry, size)
	h.head, h.count, h.bytes = 0, 0, 0
}

// contentBudget 留给字符串内容的字节数：总预算减掉槽位数组占的那部分。
func (h *history) contentBudget() int {
	return historyMemBudget - len(h.buf)*historyEntryBase
}

// evictOldest 顶掉最旧一条。槽位必须清零：否则环仍持有那条记录的字符串，
// 账减了、内存却没真的还回去。
func (h *history) evictOldest() {
	h.bytes -= entryBytes(h.buf[h.head])
	h.buf[h.head] = HistoryEntry{}
	h.head = (h.head + 1) % len(h.buf)
	h.count--
}

// add 记一条历史。时间戳由本函数补齐，调用方不必自己取时钟。
//
// 内存环在锁内更新完就返回，文件那一份只是入队。序列化与写盘都不在调用方的协程上——
// 调用方有两种，一种比另一种严重：
//
//	入站请求的协程    卡住只影响这一条请求，对端本来就在等；
//	notify 的投递 worker（RecordDelivery）    只有 4 个，卡住一个就少掉 1/4 投递能力，
//	                  而被拖慢的是**别的**目标、别的接收器——它们与磁盘这件事毫无关系。
//
// 队列满时丢掉文件那一份并计数（见 writeOne 补的说明行），不阻塞：宁可日志缺一段，
// 也不能让磁盘的状况反过来决定这个程序还能不能收消息。
func (h *history) add(e HistoryEntry) {
	if e.Time == 0 {
		e.Time = time.Now().UnixMilli()
	}
	e.Reason = strutil.Truncate(strings.TrimSpace(e.Reason), maxReasonBytes, "…")

	h.mu.Lock()
	if n := len(h.buf); n > 0 {
		if h.count == n {
			h.evictOldest()
		}
		h.buf[(h.head+h.count)%n] = e
		h.count++
		h.bytes += entryBytes(e)
		// 字节数超预算：继续从最旧的开始顶。最后一条留着不动——哪怕它自己就超预算，
		// "刚发生的那条反而看不到"比省下几百字节更糟。
		for h.count > 1 && h.bytes > h.contentBudget() {
			h.evictOldest()
		}
	}
	// 非阻塞投递，所以放在锁内也不会把这把锁按住：入站请求路径要靠它记账。
	if h.queue != nil && !h.closed {
		select {
		case h.queue <- e:
		default:
			h.dropped.Add(1)
		}
	}
	h.mu.Unlock()
}

// recent 返回最近的记录，新的在前。limit ≤ 0 表示全部。
// receiverID / event 非空时按该值精确筛选；两者同时给就是"且"。
//
// 筛选在取数时做、而不是把全部记录交给前端去筛：limit 是在这里生效的，
// 先截 200 条再筛就会出现"筛完只剩 3 条"而其实第 201 条往后还有一堆的情况。
func (h *history) recent(q HistoryQuery) []HistoryEntry {
	h.mu.Lock()
	defer h.mu.Unlock()

	n := h.count
	if q.Limit > 0 && q.Limit < n {
		n = q.Limit
	}
	out := make([]HistoryEntry, 0, n)
	for i := 0; i < h.count; i++ {
		// 从最新一条往回走。
		e := h.buf[(h.head+h.count-1-i)%len(h.buf)]
		if q.ReceiverID != "" && e.ReceiverID != q.ReceiverID {
			continue
		}
		// 事件类型不认识时这里一条都匹配不上，于是返回空列表。这是刻意的：
		// 悄悄忽略筛选条件会把全部记录摆出来，看着像"筛选没生效"。
		if q.Event != "" && e.Event != q.Event {
			continue
		}
		out = append(out, e)
		if q.Limit > 0 && len(out) >= q.Limit {
			break
		}
	}
	return out
}
