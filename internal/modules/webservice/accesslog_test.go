package webservice

import (
	"strconv"
	"testing"

	"mantou/internal/logx"
)

// newRingTestModule 造一个只用来测访问日志环的模块：不启监听、不起探测协程。
func newRingTestModule(capacity int) *Module {
	return &Module{accessCap: capacity}
}

func recordN(m *Module, n int) {
	for i := 1; i <= n; i++ {
		m.recordAccess(AccessEntry{Time: int64(i), ChildID: "c1", Host: strconv.Itoa(i)})
	}
}

// TestAccessRingKeepsNewestAndBoundsMemory 真环形的两条核心性质：
// 写满后保留的是**最新**的 cap 条（而不是最旧的），且底层数组永远不超过目标容量。
func TestAccessRingKeepsNewestAndBoundsMemory(t *testing.T) {
	const capacity = 8
	m := newRingTestModule(capacity)
	recordN(m, 100)

	if got := len(m.access); got != capacity {
		t.Fatalf("环长应为 %d，实际 %d", capacity, got)
	}
	if got := cap(m.access); got != capacity {
		t.Fatalf("底层数组容量应恰为 %d（不再有 append 的隐式扩容），实际 %d", capacity, got)
	}
	if m.accessLen != capacity {
		t.Fatalf("已填充条数应为 %d，实际 %d", capacity, m.accessLen)
	}

	logs := m.ChildLogs("", 0)
	if len(logs) != capacity {
		t.Fatalf("应返回 %d 条，实际 %d", capacity, len(logs))
	}
	// 时间降序：最新的是第 100 条。
	for i, e := range logs {
		want := int64(100 - i)
		if e.Time != want {
			t.Fatalf("第 %d 条应为 %d，实际 %d", i, want, e.Time)
		}
	}
}

// TestAccessRingGrowsToTargetOnly 环按需翻倍，且不会越过目标容量。
func TestAccessRingGrowsToTargetOnly(t *testing.T) {
	m := newRingTestModule(100)
	recordN(m, 1)
	if got := len(m.access); got != initialAccessRing {
		t.Fatalf("首次写入应分配 %d 条，实际 %d", initialAccessRing, got)
	}
	recordN(m, initialAccessRing) // 越过首次容量 → 翻倍，但被目标容量 100 夹住
	if got := len(m.access); got != 100 {
		t.Fatalf("扩容应停在目标容量 100，实际 %d", got)
	}
}

// TestAccessRingReadsPartiallyFilled 尚未绕满一圈时，不能把没写过的空槽位当成日志返回。
func TestAccessRingReadsPartiallyFilled(t *testing.T) {
	m := newRingTestModule(1000)
	recordN(m, 3)
	logs := m.ChildLogs("", 0)
	if len(logs) != 3 {
		t.Fatalf("应返回 3 条，实际 %d", len(logs))
	}
	if logs[0].Time != 3 || logs[2].Time != 1 {
		t.Fatalf("顺序应为 3,2,1，实际 %d,%d,%d", logs[0].Time, logs[1].Time, logs[2].Time)
	}
	if got := m.ChildLogs("", 2); len(got) != 2 || got[0].Time != 3 {
		t.Fatalf("limit=2 应返回最新 2 条，实际 %#v", got)
	}
}

// TestAccessRingFiltersByChild childID 过滤仍在环形读取下成立，且不影响 limit 语义。
func TestAccessRingFiltersByChild(t *testing.T) {
	m := newRingTestModule(4)
	for i := 1; i <= 6; i++ {
		child := "a"
		if i%2 == 0 {
			child = "b"
		}
		m.recordAccess(AccessEntry{Time: int64(i), ChildID: child})
	}
	// 环里剩下第 3..6 条：a=3,5 b=4,6
	logs := m.ChildLogs("a", 0)
	if len(logs) != 2 || logs[0].Time != 5 || logs[1].Time != 3 {
		t.Fatalf("子项 a 应为 5,3，实际 %#v", logs)
	}
	if logs := m.ChildLogs("b", 0); len(logs) != 2 || logs[0].Time != 6 {
		t.Fatalf("子项 b 应为 6,4，实际 %#v", logs)
	}
}

// TestSetAccessCapShrinkKeepsNewest 把上限调小要立即释放内存，并保留最新的那几条。
// 用 logx.MinLogEntries 作为收缩目标：SetAccessCap 现在与全局「日志最大条数」共用区间，
// 比下限更小的值会被夹回来，测不出收缩行为。
func TestSetAccessCapShrinkKeepsNewest(t *testing.T) {
	const big = 2 * logx.MinLogEntries
	m := newRingTestModule(big)
	recordN(m, big)

	m.SetAccessCap(logx.MinLogEntries)
	if got := len(m.access); got != logx.MinLogEntries {
		t.Fatalf("收缩后环长应为 %d，实际 %d", logx.MinLogEntries, got)
	}
	logs := m.ChildLogs("", 0)
	if len(logs) != logx.MinLogEntries {
		t.Fatalf("收缩后应剩 %d 条，实际 %d", logx.MinLogEntries, len(logs))
	}
	// 时间降序，且丢掉的是最旧的一半：留下 big..(big/2+1)。
	if logs[0].Time != int64(big) || logs[len(logs)-1].Time != int64(logx.MinLogEntries+1) {
		t.Fatalf("应保留最新 %d 条：首 %d 末 %d", logx.MinLogEntries, logs[0].Time, logs[len(logs)-1].Time)
	}
	// 收缩后继续写入必须仍然正确绕圈：最新一条是新写的 2，最旧一条被顶掉两格。
	recordN(m, 2)
	logs = m.ChildLogs("", 0)
	if len(logs) != logx.MinLogEntries {
		t.Fatalf("收缩后继续写入，条数应稳定在 %d，实际 %d", logx.MinLogEntries, len(logs))
	}
	if logs[0].Time != 2 || logs[1].Time != 1 || logs[2].Time != int64(big) {
		t.Fatalf("收缩后继续写入结果错误：前三条 %d,%d,%d", logs[0].Time, logs[1].Time, logs[2].Time)
	}
}

// TestSetAccessCapClampsRange 越界的「日志最大条数」被夹回 [MinLogEntries, MaxLogEntries]。
// 访问事件环与程序日志环、磁盘文件共用同一区间，故直接复用 logx 的常量断言。
func TestSetAccessCapClampsRange(t *testing.T) {
	m := newRingTestModule(0)
	m.SetAccessCap(0)
	if m.accessCap != logx.DefaultLogEntries {
		t.Fatalf("0 应回落默认值 %d，实际 %d", logx.DefaultLogEntries, m.accessCap)
	}
	m.SetAccessCap(-5)
	if m.accessCap != logx.DefaultLogEntries {
		t.Fatalf("负数应回落默认值 %d，实际 %d", logx.DefaultLogEntries, m.accessCap)
	}
	m.SetAccessCap(1)
	if m.accessCap != logx.MinLogEntries {
		t.Fatalf("低于下限应夹到 %d，实际 %d", logx.MinLogEntries, m.accessCap)
	}
	m.SetAccessCap(999999)
	if m.accessCap != logx.MaxLogEntries {
		t.Fatalf("超上限应夹到 %d，实际 %d", logx.MaxLogEntries, m.accessCap)
	}
}

// TestSetAccessCapGrowDoesNotPreallocate 调大上限不应立刻吃内存，由写入按需增长。
func TestSetAccessCapGrowDoesNotPreallocate(t *testing.T) {
	m := newRingTestModule(8)
	recordN(m, 8)
	before := len(m.access)
	m.SetAccessCap(logx.MaxLogEntries)
	if len(m.access) != before {
		t.Fatalf("调大上限不应立即重新分配（%d → %d）", before, len(m.access))
	}
	recordN(m, 1)
	if len(m.access) <= before {
		t.Fatalf("下一次写入应触发扩容，实际仍为 %d", len(m.access))
	}
}
