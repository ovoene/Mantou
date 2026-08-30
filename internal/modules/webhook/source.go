package webhook

import (
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"mantou/internal/strutil"
)

// 本文件是「入站原文留存」：一条入站消息被拒收或被丢弃时，把当时收到的原文留一份在内存里，
// 面板在执行历史那一行点「来源」就能看到。
//
// 为什么需要它：这两类结果最难查，因为面板上原本只有一句结论。
//
//	被拒收  原因写着"正文里没有命中关键词"——到底对方发的是什么？是改了措辞，
//	        还是词表本身填错了？光看结论分不出来。
//	被丢弃  原因写着"没有规则命中"——那这条消息的字段长什么样？规则的条件该照着谁写？
//
// 没有原文时唯一的办法是"再让对方推一次，同时开着试运行"，而对方多半是个定时任务，
// 下一次可能是一小时以后；被拒收的那一条也不会自己重来。
//
// 为什么只在内存里、不落盘：这里存的是第三方推来的整段正文，内容不受本程序控制，
// 可能含姓名、手机号、内部地址。写进文件就成了一份长期留在磁盘上的明文副本，
// 而它的用途只是"刚出问题时看一眼"。重启即空，是刻意的。
//
// 与试运行抓包（testrun.go）的分工：试运行是"我现在盯着看"，只对一个接收器、开着才抓、
// 三小时过期；这里是"出问题之后回头看"，全部接收器、始终在记、按内存预算淘汰。

// ---- 容量 ----
//
// 与执行历史同一个思路：条数与字节数各是一道闸，谁先到就从最旧的开始淘汰。
// 单靠条数管不住内存——这里装的正是外部推来的整段正文。
const (
	// defaultSourceBudget 全部留存内容的默认字节预算。
	//
	// 2 MiB 是按"够查问题"定的，不是按"能存多少"定的：出问题时要翻的是最近这几条，
	// 而不是昨天那一批。配合下面 32 KiB 的单条上限，2 MiB 至少能留住 60 条满额正文；
	// 而真实的推送正文多数在几 KB，那就是好几百条。
	//
	// 这只是**初值**：实际额度由「模块设置 → 原文留存」下发（config.WebhookServer.SourceRetainMB，
	// 0 ~ 3 MB，0 表示不留存），每次 Reload 经 setBudget 应用。
	//
	// 为什么交给用户而不是写死：这份留存装的是第三方推来的整段正文，可能含姓名、手机号、
	// 内部地址。"正在查为什么没收到"的人需要它，不查问题的人希望这些内容根本不进内存——
	// 两种诉求都成立，而它们的差别只是一个数字。写死意味着替其中一方做了决定，
	// 且另一方没有任何补救办法（这份数据不落盘，事后也没法从磁盘上删）。
	defaultSourceBudget = 2 << 20 // 2 MiB

	// sourceBodyMax 单条正文的留存上限。超出的部分截掉并标记（见 clampBody）。
	//
	// 32 KiB 远小于接收器自己的请求体上限（默认几百 KB，可调到 4 MB）：查问题看的是
	// 正文的**结构**——字段名、层级、有没有那个关键词——头一两屏就够了。
	// 不设这道闸的话，一条 4 MB 的正文一进来就把整个预算清空，其余记录全被顶掉。
	//
	// 这一道不跟着额度调：它管的是"一条能占多大比例"，而不是"总共能占多少"。
	// 把它也做成旋钮，等于让用户去调一个只有把留存调坏了才看得出区别的数。
	sourceBodyMax = 32 << 10 // 32 KiB

	// sourceMaxEntries 条数上限。
	//
	// 500 是按预算配的：槽位数组先占掉 500 × sourceEntryBase ≈ 130 KB，
	// 剩下的字节预算按"一条几 KB"算正好是这个量级。条数再往上加只会让空槽位
	// 吃掉字节预算，反而让真正能留住的记录变少（与 historyMaxEntries 同一个道理）。
	sourceMaxEntries = 500

	// sourceEntryBase 一条记录自身占的字节数（不含堆上的字符串与 map 内容）。
	// 取整留了零头，source_test.go 有断言守着这个数。
	sourceEntryBase = 264

	// sourceMaxHeaders / sourceHeaderValueMax 请求头的留存上限：条数与单值长度。
	// 请求头名与值都由对端决定，不设闸就是又一条"外部决定内存"的路。
	sourceMaxHeaders     = 40
	sourceHeaderValueMax = 256

	// sourceQueryMax 查询串的留存上限。
	sourceQueryMax = 1024

	// sourcePathMax 请求路径的留存上限。路径由对端决定，扫描器会发很长的路径。
	sourcePathMax = 256
)

// SourceRecord 一条留存的入站原文。JSON 字段名是与面板之间的格式契约。
type SourceRecord struct {
	ID         string `json:"id"`
	Time       int64  `json:"time"` // Unix 毫秒
	Event      string `json:"event"`
	EventID    string `json:"eventId,omitempty"`
	ReceiverID string `json:"receiverId,omitempty"`
	Receiver   string `json:"receiver,omitempty"`
	Remote     string `json:"remote,omitempty"`
	Status     int    `json:"status,omitempty"`
	Reason     string `json:"reason,omitempty"`

	Method  string            `json:"method,omitempty"`
	Path    string            `json:"path,omitempty"`
	Query   string            `json:"query,omitempty"`
	Headers map[string]string `json:"headers,omitempty"`
	Body    string            `json:"body,omitempty"`

	// BodyRead 这次请求的正文是否被读取过。
	//
	// false 不等于"正文是空的"。入站检查刻意排成"方法 → IP 名单 → 限流 → 鉴权 →
	// 并发 → 体积 → 关键词"（见 handler.go 顶部），前面几道闸都在读正文之前，
	// 被它们拦下的请求根本没有正文可留。面板必须把这两种情况分开说，
	// 否则用户会以为"对方发了个空包"。
	BodyRead bool `json:"bodyRead"`
	// BodySize 正文的原始字节数（截断之前）。
	BodySize int `json:"bodySize"`
	// BodyTruncated 正文超过 sourceBodyMax，留存的是前一截。
	BodyTruncated bool `json:"bodyTruncated,omitempty"`
	// Sniffed 正文更像 json / kv / txt 中的哪一种，只在 BodyRead 时有意义。
	Sniffed string `json:"sniffed,omitempty"`
}

// sourceStore 入站原文留存：一个按内存预算淘汰的环。
//
// 刻意不建 ID → 下标的索引表：查一条只发生在用户点「来源」的那一下，
// 500 条的线性扫描是纳秒级的。而索引表要在每次新增与每次淘汰时同步维护，
// 一处漏掉就是"点开看到的是别人那条"——一个在界面上完全说得通、却查不出来的错。
type sourceStore struct {
	mu    sync.Mutex
	buf   []SourceRecord
	head  int // 最旧一条的下标
	count int
	bytes int // 当前所有记录的内容字节数（不含槽位数组本身）
	seq   uint64
	// budget 当前的字节预算，由「模块设置 → 原文留存」下发（见 setBudget）。
	// 为 0 表示不留存，此时 buf 也是 nil——槽位数组本身就有 130 KB，
	// 用户明确选了"不留存"却还留着它，与这个选项的用意不符。
	budget int
}

func newSourceStore() *sourceStore {
	return &sourceStore{buf: make([]SourceRecord, sourceMaxEntries), budget: defaultSourceBudget}
}

// contentBudget 留给内容的字节数：总预算减掉槽位数组占的那部分。
func (s *sourceStore) contentBudget() int {
	return s.budget - len(s.buf)*sourceEntryBase
}

// setBudget 换一个字节预算，并当场把超出的部分淘汰掉。
//
// 当场淘汰而不是"等下一条进来再说"：用户把额度调小（或调到 0）往往正是因为
// 不想让这些内容继续留在内存里，而这台机器上可能好几个小时都不会再来一条消息。
// 调小之后界面上那行用量必须立刻对得上，否则用户会以为设置没生效。
//
// 与 history.setCap 的差别：那边换容量是整个环重建、历史全丢；这里只淘汰到装得下为止。
// 原因是两者的"容量"不同源——历史的条数上限跟着日志设置走，一年也不会动一次；
// 而这个额度是用户为了当下这件事去调的，把已经留住的原文一起清掉正好毁掉他要查的东西。
func (s *sourceStore) setBudget(n int) {
	if n < 0 {
		n = 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.budget = n
	if n == 0 {
		// 不留存：连槽位数组一起还回去。之后 add 会走 len(buf)==0 那条路返回空 ID，
		// 于是历史记录上也不会再出现「来源」链接（见 add 的说明）。
		s.buf, s.head, s.count, s.bytes = nil, 0, 0, 0
		return
	}
	if s.buf == nil {
		s.buf = make([]SourceRecord, sourceMaxEntries)
	}
	// 与 add 里那一段同一个口径：最后一条留着不动——哪怕它自己就超预算，
	// "刚出问题的那条反而看不到"比省下几十 KB 更糟。
	for s.count > 1 && s.bytes > s.contentBudget() {
		s.evictOldest()
	}
}

// clear 清空全部留存，额度不变。
//
// 给界面上那个「清空原文留存」按钮用：这里装的是第三方推来的整段正文，
// 用户看完之后可能只想让它立刻消失，而不是等着被新消息顶掉——
// 这份数据不落盘，事后也没有别的地方能删。
//
// 保留 buf（不置 nil）：额度还在，下一条消息照常留存。
func (s *sourceStore) clear() (cleared int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cleared = s.count
	// 逐个清零而不是只把 count 归零：环仍持有那些记录的字符串与 map，
	// 账减了、内存却没真的还回去（与 evictOldest 里那一行同一个道理）。
	for i := range s.buf {
		s.buf[i] = SourceRecord{}
	}
	s.head, s.count, s.bytes = 0, 0, 0
	return cleared
}

// sourceBytes 一条记录里"内容"部分的字节数。结构体自身已经算在槽位里（sourceEntryBase）。
// 请求头按"键 + 值 + 每项的 map 开销"估，估宽一点比估窄一点安全。
func sourceBytes(r SourceRecord) int {
	n := len(r.ID) + len(r.Event) + len(r.EventID) + len(r.ReceiverID) + len(r.Receiver) +
		len(r.Remote) + len(r.Reason) + len(r.Method) + len(r.Path) + len(r.Query) +
		len(r.Body) + len(r.Sniffed)
	for k, v := range r.Headers {
		n += len(k) + len(v) + 48
	}
	return n
}

// evictOldest 顶掉最旧一条。槽位必须清零：否则环仍持有那条记录的字符串与 map，
// 账减了、内存却没真的还回去。
func (s *sourceStore) evictOldest() {
	s.bytes -= sourceBytes(s.buf[s.head])
	s.buf[s.head] = SourceRecord{}
	s.head = (s.head + 1) % len(s.buf)
	s.count--
}

// add 留存一条，返回分配到的 ID（供写进 HistoryEntry.SourceID）。
// 环容量为 0 时返回空串——调用方据此不给历史记录挂"来源"链接。
func (s *sourceStore) add(r SourceRecord) string {
	s.mu.Lock()
	defer s.mu.Unlock()

	n := len(s.buf)
	if n == 0 {
		return ""
	}
	s.seq++
	// 36 进制只为让 ID 短一点；它不是凭证，接口那一层要求已登录（见 api_webhook.go）。
	r.ID = "s" + strconv.FormatUint(s.seq, 36)
	if r.Time == 0 {
		r.Time = time.Now().UnixMilli()
	}

	if s.count == n {
		s.evictOldest()
	}
	s.buf[(s.head+s.count)%n] = r
	s.count++
	s.bytes += sourceBytes(r)
	// 字节数超预算：继续从最旧的开始顶。最后一条留着不动——哪怕它自己就超预算，
	// "刚出问题的那条反而看不到"比省下几十 KB 更糟。
	for s.count > 1 && s.bytes > s.contentBudget() {
		s.evictOldest()
	}
	return r.ID
}

// get 取一条。第二个返回值为 false 表示这条已经被新记录顶掉了——
// 面板必须把这句话说出来，而不是显示一片空白。
func (s *sourceStore) get(id string) (SourceRecord, bool) {
	if id == "" {
		return SourceRecord{}, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := 0; i < s.count; i++ {
		// 从最新一条往回找：刚出问题时点开的多半就是最近这几条。
		if r := s.buf[(s.head+s.count-1-i)%len(s.buf)]; r.ID == id {
			return r, true
		}
	}
	return SourceRecord{}, false
}

// stats 当前条数与内容字节数，供面板显示"留了多少"。
func (s *sourceStore) stats() (count, bytes int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.count, s.bytes
}

// currentBudget 当前的字节预算，供面板把这个数说给用户听。
//
// 单独一个读函数而不是让上层去读常量：这个数现在是可变的，
// 上层照抄常量就会出现"页脚写着 2 MB、实际按 3 MB 淘汰"这种只有算一遍才发现的错。
func (s *sourceStore) currentBudget() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.budget
}

// ---- 入库前的裁剪 ----

// clampBody 把正文裁到 max 字节以内。
// 返回留存文本、原始字节数、是否截断过。
//
// max 由调用方给（入站原文留存用 sourceBodyMax，试运行抓包用 captureBodyMax）：
// 两处的取舍不同，但截断这件事只该有一份实现——原因就在下面这段。
//
// 截断必须从 []byte 直接切，不能"先 string(raw) 再截一段"。后者在 Go 里是个陷阱：
// 子串与原串共用同一段底层数组，而 s[:n] + "" 会被运行时原样返回（concatstrings 对
// 单个非空操作数不做拷贝）。结果是留存里那条记录看着只有 32 KB，实际把整段 4 MB 的
// 入站正文一起压着不放——字节闸照常记账、内存照常涨，这道闸就等于没设。
// 实测 20 条这样的记录账上 640 KB，GC 之后实际存活 76 MB。
// string(raw[:cut]) 则是按 cut 精确分配一段新内存，原始缓冲区当场可回收。
func clampBody(raw []byte, max int) (body string, size int, truncated bool) {
	size = len(raw)
	if size <= max {
		return string(raw), size, false
	}
	// 按字节截，但不切开一个 UTF-8 字符——切开会让面板上出现一个替换符，
	// 看着像"对方发来的内容有乱码"。回退最多 3 字节，与 strutil.Truncate 同一个做法。
	cut := max
	for cut > 0 && !utf8.RuneStart(raw[cut]) {
		cut--
	}
	return string(raw[:cut]), size, true
}

// clampHeaders 把 headerMap 的结果裁成留存用的形态：条数与单值长度都设闸。
//
// 只接受 headerMap 的输出，不自己遍历 http.Header：凭证类请求头的打码规则
// 只该有一份（见 event.go 的 redactedHeaders 与 headerMap）。在这里另写一遍，
// 迟早会出现"模板里打了码、留存里没打"。
func clampHeaders(m map[string]any) map[string]string {
	if len(m) == 0 {
		return nil
	}
	out := make(map[string]string, min(len(m), sourceMaxHeaders))
	for k, v := range m {
		if len(out) >= sourceMaxHeaders {
			break
		}
		out[k] = strutil.Truncate(tostr(v), sourceHeaderValueMax, "…")
	}
	return out
}

// redactQuery 把查询串里的凭证打码后返回。
//
// 必须打码：本程序自己就支持用 ?token=… 传令牌（见 checkAuth），
// 而留存是给面板显示的——照原样存下来，等于把入站令牌明文摆在页面上。
// 另外两个名字（access_token / secret）不是本程序在用，但它们太常见了，
// 顺手一起挡掉的代价只是这两个名字下的内容看不到。
//
// 其余参数一律照原样：有些系统只能在 URL 上带参数推送（见 event.go 的 query 说明），
// 那时查询串**就是**消息正文，多打一个码就等于把这个功能废掉。
//
// 解析失败（对方发来的不是合法查询串）时整段打码：说不清哪一截是凭证，
// 就不要赌。这种请求本来也解析不出内容。
func redactQuery(raw string) string {
	if raw == "" {
		return ""
	}
	raw = strutil.Truncate(raw, sourceQueryMax, "…")
	q, err := url.ParseQuery(raw)
	if err != nil {
		return "***"
	}
	var b strings.Builder
	first := true
	for _, k := range sortedKeys(q) {
		for _, v := range q[k] {
			if !first {
				b.WriteByte('&')
			}
			first = false
			b.WriteString(k)
			b.WriteByte('=')
			if secretQueryKeys[strings.ToLower(k)] {
				b.WriteString("***")
				continue
			}
			b.WriteString(v)
		}
	}
	return b.String()
}

// secretQueryKeys 查询串里要打码的参数名（小写比较）。
var secretQueryKeys = map[string]bool{
	"token":        true,
	"access_token": true,
	"secret":       true,
}

// redactQueryKeepingRaw 同样把凭证打码，但其余部分**一个字节都不改**（也不排序）。
//
// 与 redactQuery 共用 secretQueryKeys 那一张表——规则只有一份；两种呈现是因为用途不同：
//
//	redactQuery           只拿去显示。解析→排序→重建，读起来整齐（%E4%B8%AD 还原成"中"）。
//	redactQueryKeepingRaw 还要被再解析一次。试运行抓包同时是全局唯一的样本载荷，
//	                      模板预览会把这段查询串原样送回后端重建事件（见 TemplateDialog
//	                      的 capturedQuery）。那时"解析→重建"会改掉内容：值里转义过的
//	                      & 或 = 重建后变成真的分隔符，于是预览里的字段和真实收到的
//	                      不是一回事——而预览的全部意义就是"与真实投递一字不差"。
//
// 键按解码后比较，值只做整段替换、不重新转义。max 之外的部分截掉（查询串长度由对端
// 决定，Go 只在请求行总长上有闸，那是 1 MB 量级）；截断处留下的省略号本身就是提示。
func redactQueryKeepingRaw(raw string, max int) string {
	if raw == "" {
		return ""
	}
	raw = strutil.Truncate(raw, max, "…")
	var b strings.Builder
	b.Grow(len(raw))
	for i, seg := range strings.Split(raw, "&") {
		if i > 0 {
			b.WriteByte('&')
		}
		eq := strings.IndexByte(seg, '=')
		if eq < 0 {
			// 形如 ?debug 的裸参数：没有值可打码，原样留着。
			b.WriteString(seg)
			continue
		}
		b.WriteString(seg[:eq+1])
		key := seg[:eq]
		if dec, err := url.QueryUnescape(key); err == nil {
			key = dec
		}
		if secretQueryKeys[strings.ToLower(key)] {
			b.WriteString("***")
			continue
		}
		b.WriteString(seg[eq+1:])
	}
	return b.String()
}

// sortedKeys 让重建出来的查询串顺序固定。
// url.ParseQuery 给的是 map，遍历顺序每次都不同，而这段字符串是要摆在界面上、
// 会被用户前后两次点开对照着看的——顺序乱跳会让人以为对方改了请求。
func sortedKeys(q url.Values) []string {
	out := make([]string, 0, len(q))
	for k := range q {
		out = append(out, k)
	}
	// 参数个数是个位数量级，插入排序比引入 sort 更贴合这里的规模。
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j] < out[j-1]; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}
