package webhook

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unsafe"

	"mantou/internal/logx"
)

// historyEntryBase 是内存记账的基数，必须真的盖住结构体本身的大小，
// 否则字节闸算出来的占用比实际小，1 MiB 上限就是个假承诺。
// HistoryEntry 一加字段这条就会红。
func TestHistoryEntryBaseCoversStruct(t *testing.T) {
	if got := int(unsafe.Sizeof(HistoryEntry{})); got > historyEntryBase {
		t.Fatalf("HistoryEntry 已经 %d 字节，超过 historyEntryBase=%d：请同时调大基数与预算注释里的估算", got, historyEntryBase)
	}
}

func TestHistorySizeClampsToMaxEntries(t *testing.T) {
	// 5000 是「日志最大条数」的上限，管的是日志文件行数；内存这一份到 2000 就不再往上。
	if got := historySize(5000); got != historyMaxEntries {
		t.Fatalf("historySize(5000)=%d，期望 %d", got, historyMaxEntries)
	}
	if got := historySize(0); got != logx.NormalizeLogEntries(0) {
		t.Fatalf("historySize(0)=%d，期望回落到默认条数 %d", got, logx.NormalizeLogEntries(0))
	}
}

// 条数闸：环满之后顶掉最旧的，且返回顺序仍是新的在前。
// 直接给 buf 定长而不走 newHistory：那条路会把条数抬到 logx.MinLogEntries（100），
// 用例就得灌 101 条才看得到淘汰。
func TestHistoryEvictsOldestByCount(t *testing.T) {
	h := &history{buf: make([]HistoryEntry, 3)}
	for _, ev := range []string{"a", "b", "c", "d"} {
		h.add(HistoryEntry{Event: ev})
	}
	got := h.recent(HistoryQuery{})
	if len(got) != 3 {
		t.Fatalf("条数期望 3，实际 %d", len(got))
	}
	for i, want := range []string{"d", "c", "b"} {
		if got[i].Event != want {
			t.Fatalf("第 %d 条期望 %q，实际 %q", i, want, got[i].Event)
		}
	}
}

// ---------- 筛选 ----------

// seedMixed 灌一批混合记录，供筛选用例共用。返回时环里从旧到新是：
// r1/received、r2/rejected、r1/dropped、r2/received、r1/rejected。
func seedMixed(h *history) {
	for _, e := range []HistoryEntry{
		{ReceiverID: "r1", Event: EventReceived, EventID: "e1"},
		{ReceiverID: "r2", Event: EventRejected, EventID: "e2"},
		{ReceiverID: "r1", Event: EventDropped, EventID: "e3"},
		{ReceiverID: "r2", Event: EventReceived, EventID: "e4"},
		{ReceiverID: "r1", Event: EventRejected, EventID: "e5"},
	} {
		h.add(e)
	}
}

// 按事件类型筛：只留该类型，且顺序仍是新的在前。
func TestHistoryFilterByEvent(t *testing.T) {
	h := newHistory(100)
	seedMixed(h)

	got := h.recent(HistoryQuery{Event: EventRejected})
	if len(got) != 2 {
		t.Fatalf("拒收应有 2 条，实际 %d：%+v", len(got), got)
	}
	for i, want := range []string{"e5", "e2"} {
		if got[i].EventID != want {
			t.Fatalf("第 %d 条期望 %q，实际 %q", i, want, got[i].EventID)
		}
	}
}

// 两个条件同时给是「且」，不是「或」。
// 写反成「或」时不筛的那一版会返回 4 条，正好和这条断言错开。
func TestHistoryFilterEventAndReceiverAreBothApplied(t *testing.T) {
	h := newHistory(100)
	seedMixed(h)

	got := h.recent(HistoryQuery{ReceiverID: "r1", Event: EventRejected})
	if len(got) != 1 || got[0].EventID != "e5" {
		t.Fatalf("r1 的拒收只有 e5 一条，实际 %+v", got)
	}
}

// limit 必须在筛完之后才数：先截 limit 条再筛，会出现"筛完只剩几条"
// 而其实更早的记录里还有一堆没被看到的情况。
//
// 这里 limit=2 而拒收的两条分别排在第 1 位和第 4 位：先截后筛的版本只能拿回 1 条。
func TestHistoryFilterAppliesLimitAfterFiltering(t *testing.T) {
	h := newHistory(100)
	seedMixed(h)

	got := h.recent(HistoryQuery{Event: EventRejected, Limit: 2})
	if len(got) != 2 {
		t.Fatalf("拒收共 2 条且 limit=2，应拿回 2 条，实际 %d：%+v", len(got), got)
	}
}

// limit 小于命中条数时按新的那几条截断。
func TestHistoryFilterLimitTruncatesNewest(t *testing.T) {
	h := newHistory(100)
	seedMixed(h)

	got := h.recent(HistoryQuery{ReceiverID: "r1", Limit: 2})
	if len(got) != 2 || got[0].EventID != "e5" || got[1].EventID != "e3" {
		t.Fatalf("应是 r1 最新的两条 e5、e3，实际 %+v", got)
	}
}

// 事件类型不认识时返回空列表，而不是"忽略筛选、把全部摆出来"。
// 后者在界面上看着像筛选没生效。
func TestHistoryFilterUnknownEventReturnsEmpty(t *testing.T) {
	h := newHistory(100)
	seedMixed(h)

	if got := h.recent(HistoryQuery{Event: "no-such-event"}); len(got) != 0 {
		t.Fatalf("不认识的事件类型应筛出空列表，实际 %d 条：%+v", len(got), got)
	}
}

// 字节闸：每条都带满 512 字节原因时，条数远没到上限就会先被字节数顶掉。
// 这是真实的最坏情况——原因文本来自对端返回体。
func TestHistoryEvictsOnByteBudget(t *testing.T) {
	h := newHistory(historyMaxEntries)
	fat := strings.Repeat("x", maxReasonBytes)
	for i := 0; i < historyMaxEntries; i++ {
		h.add(HistoryEntry{Event: EventFailed, Reason: fat})
	}
	if h.count >= historyMaxEntries {
		t.Fatalf("全是 512 字节原因时不该还能装满 %d 条，实际 %d 条", historyMaxEntries, h.count)
	}
	if h.bytes > h.contentBudget() {
		t.Fatalf("内容字节数 %d 超出预算 %d", h.bytes, h.contentBudget())
	}
	// 最新一条必须在，且被顶掉的槽位不能还攥着字符串。
	got := h.recent(HistoryQuery{Limit: 1})
	if len(got) != 1 || got[0].Reason != fat {
		t.Fatalf("最新一条应完整保留：%+v", got)
	}
	var live int
	for _, e := range h.buf {
		if e.Event != "" {
			live++
		}
	}
	if live != h.count {
		t.Fatalf("环里还有 %d 条非空记录，但账上只记了 %d 条：被淘汰的槽位没清零", live, h.count)
	}
}

// 单条自己就超预算时也要留住它："刚发生的那条反而看不到"比省下几百字节更糟。
func TestHistoryKeepsNewestEvenIfOversized(t *testing.T) {
	h := newHistory(historyMaxEntries)
	h.add(HistoryEntry{Event: EventFailed, Reason: strings.Repeat("y", 2<<20)})
	got := h.recent(HistoryQuery{})
	if len(got) != 1 {
		t.Fatalf("条数期望 1，实际 %d", len(got))
	}
	// Reason 先被 maxReasonBytes 截断，所以这条实际并不大。
	if n := len(got[0].Reason); n > maxReasonBytes+8 {
		t.Fatalf("原因未被截断：%d 字节", n)
	}
}

// setCap 换环之后账必须归零，否则字节数只增不减，很快就会"看着是空的却一直在淘汰"。
func TestHistorySetCapResetsAccounting(t *testing.T) {
	h := newHistory(100)
	for i := 0; i < 50; i++ {
		h.add(HistoryEntry{Event: EventSent, Reason: "some reason"})
	}
	h.setCap(200)
	if h.count != 0 || h.bytes != 0 || h.head != 0 {
		t.Fatalf("setCap 后应清空：count=%d bytes=%d head=%d", h.count, h.bytes, h.head)
	}
	if len(h.buf) != 200 {
		t.Fatalf("容量期望 200，实际 %d", len(h.buf))
	}
}

// ---------- 落盘：不在调用方的协程上（2.8-F）----------

// readHistoryLines 读回日志文件里的每一行 JSON。
func readHistoryLines(t *testing.T, path string) []HistoryEntry {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var out []HistoryEntry
	for _, ln := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if ln = strings.TrimSpace(ln); ln == "" {
			continue
		}
		var e HistoryEntry
		if err := json.Unmarshal([]byte(ln), &e); err != nil {
			t.Fatalf("日志行不是合法 JSON：%q（%v）", ln, err)
		}
		out = append(out, e)
	}
	return out
}

// newHistoryWithFile 绑定一个真实的轮转文件（条数给足，用例里不该发生轮转）。
func newHistoryWithFile(t *testing.T, size int) (*history, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "webhook.log")
	f, err := logx.NewRotatingFile(path, 5000)
	if err != nil {
		t.Fatal(err)
	}
	h := newHistory(size)
	h.setFile(f)
	return h, path
}

// 队列满时 add 不阻塞：丢掉文件那一份并计数，内存环一条不少。
//
// 刻意不起落盘协程（直接给 h.queue 赋值，不走 setFile），这样"队列必然填满"是确定的，
// 不依赖调度：靠 sleep 去制造拥塞的用例在快机器上会静默变成什么都没验。
//
// 这条同时是"落盘确实走了队列"的证明——同步写盘的版本里根本没有队列，
// 也就永远不可能丢，dropped 恒为 0。
func TestHistoryDropsFileCopyWhenQueueFull(t *testing.T) {
	h := &history{buf: make([]HistoryEntry, 10), queue: make(chan HistoryEntry, 2)}

	for i := 0; i < 5; i++ {
		h.add(HistoryEntry{Event: EventReceived, EventID: fmt.Sprintf("e%d", i)})
	}

	if got := len(h.queue); got != 2 {
		t.Fatalf("队列应被填满（容量 2），实际 %d", got)
	}
	if got := h.dropped.Load(); got != 3 {
		t.Fatalf("应记下 3 条被丢弃，实际 %d", got)
	}
	// 内存环是面板读的那一份，不能因为磁盘跟不上就缺记录。
	if got := h.recent(HistoryQuery{}); len(got) != 5 {
		t.Fatalf("内存环应仍有 5 条，实际 %d", len(got))
	}
}

// 丢过的条数要补一行说明，且一次拥塞只补一行。
//
// 少了这行，文件里缺掉的那一段与"这段时间没有请求"完全无法区分——
// 而这两件事在排查时的结论正好相反。
func TestHistoryDropWritesOneExplanationLine(t *testing.T) {
	h, path := newHistoryWithFile(t, 100)
	t.Cleanup(h.close)
	h.dropped.Store(7)

	h.writeOne(HistoryEntry{Event: EventReceived, EventID: "after-gap"})
	h.writeOne(HistoryEntry{Event: EventReceived, EventID: "next"})

	lines := readHistoryLines(t, path)
	if len(lines) != 3 {
		t.Fatalf("应是「说明 + 两条记录」共 3 行，实际 %d 行：%+v", len(lines), lines)
	}
	if lines[0].Event != EventError || !strings.Contains(lines[0].Reason, "7 条") {
		t.Fatalf("第一行应是丢弃说明并带上条数，实际 %+v", lines[0])
	}
	if lines[1].EventID != "after-gap" || lines[2].EventID != "next" {
		t.Fatalf("说明行之后应照原顺序接上记录：%+v", lines)
	}
	// 计数已清零，所以第二条记录前面不该再补一行。
	if got := h.dropped.Load(); got != 0 {
		t.Fatalf("补过说明之后计数应归零，实际 %d", got)
	}
}

// close 必须把队列排空再关文件：退出前那几条恰恰是出问题时最需要翻的。
func TestHistoryCloseDrainsQueue(t *testing.T) {
	h, path := newHistoryWithFile(t, 500)

	const n = 200 // 少于 historyQueueDepth，因此不该有任何丢弃
	for i := 0; i < n; i++ {
		h.add(HistoryEntry{Event: EventSent, EventID: fmt.Sprintf("e%03d", i)})
	}
	h.close()
	h.close() // 可重复调用

	if got := h.dropped.Load(); got != 0 {
		t.Fatalf("%d 条未超过队列深度 %d，不该有丢弃，实际丢了 %d", n, historyQueueDepth, got)
	}
	lines := readHistoryLines(t, path)
	if len(lines) != n {
		t.Fatalf("close 未把队列写完：期望 %d 行，实际 %d 行", n, len(lines))
	}
	// 顺序必须是入队顺序：同一个 eventId 的"收到 → 命中 → 各目标结果"靠它串起来。
	for i, e := range lines {
		if want := fmt.Sprintf("e%03d", i); e.EventID != want {
			t.Fatalf("第 %d 行顺序不对：%q，期望 %q", i, e.EventID, want)
		}
	}
}

// 没有日志文件时不起落盘协程，也不因为"队列不存在"就丢内存环那一份。
func TestHistoryWithoutFileKeepsMemoryRing(t *testing.T) {
	h := newHistory(100)
	if h.queue != nil {
		t.Fatal("没有绑定文件却建了落盘队列：等于留一个空转协程")
	}
	h.add(HistoryEntry{Event: EventReceived, EventID: "e1"})
	if got := h.recent(HistoryQuery{}); len(got) != 1 {
		t.Fatalf("内存环应有 1 条，实际 %d", len(got))
	}
	if got := h.dropped.Load(); got != 0 {
		t.Fatalf("没有文件不算丢弃，实际 %d", got)
	}
	h.close() // 没有协程也要能安全收尾
}

// Module.Close 必须把执行历史的落盘一起收尾。
// 单测 history.close 不够：漏接一行线就等于退出前的记录全丢，而那种漏接编译器不管。
//
// 灌 200 条而不是 1 条：漏接时落盘协程往往还能抢在用例读文件之前写掉几条，
// 只灌一条的话这个用例会时绿时红，等于什么都没钉住。
func TestModuleCloseFlushesHistoryFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "webhook.log")
	m := New(logx.New(logx.Options{}), nil, path)
	m.syncLogFile(5000)

	const n = 200 // 少于 historyQueueDepth，一条都不该丢
	for i := 0; i < n; i++ {
		m.hist.add(HistoryEntry{Event: EventReceived, EventID: fmt.Sprintf("e%03d", i)})
	}
	if err := m.Close(); err != nil {
		t.Fatal(err)
	}

	lines := readHistoryLines(t, path)
	if len(lines) != n {
		t.Fatalf("退出前记的历史没有全部落盘：期望 %d 行，实际 %d 行", n, len(lines))
	}
	if lines[n-1].EventID != fmt.Sprintf("e%03d", n-1) {
		t.Fatalf("最后一条不是退出前那条：%+v", lines[n-1])
	}
}
