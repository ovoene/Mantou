package runstats

import (
	"fmt"
	"runtime"
	"strings"
	"sync"
	"testing"

	"mantou/internal/config"
)

// 本文件盯三件事：数字对不对、内存有没有上限、装配层不带这个库时会不会炸。
//
// 第一件在界面上看得见（列表上那几列），第二件看不见——正是因为看不见才要钉：
// 这个库替掉的是「每条入站请求都改一次配置并等着落盘」的老路，一旦它自己没有上限，
// 就等于把磁盘压力换成了内存压力，而外面推得越猛涨得越快。

// ---------- 数字 ----------

// 三个数各写各的位置，计数累加，时刻取最后一次。
func TestReceivedWritesAllThree(t *testing.T) {
	s := New()
	for i := 1; i <= 3; i++ {
		s.Received("r1", int64(1700000000+i), "已接收并派发")
	}

	got := s.Recv("r1")
	if got.Received != 3 {
		t.Fatalf("收下计数应累加到 3，实际 %d", got.Received)
	}
	if got.LastAt != 1700000003 {
		t.Fatalf("时刻应是最后一次的值，实际 %d", got.LastAt)
	}
	if got.LastStatus != "已接收并派发" {
		t.Fatalf("结果文本不符：%q", got.LastStatus)
	}
	if got.Rejected != 0 {
		t.Fatalf("没有被拒的请求，拒收计数应为 0，实际 %d", got.Rejected)
	}
}

// 拒收只加自己那个数，不动时刻与结果文本。
//
// 这是 A5/A6 的正题。列表上那一列叫「最近收到」，用户读它就是「上一次真有数据进来」；
// 被限流挡掉的请求没带来任何数据，把时刻改成它等于把这一列变成「最近被人敲过」——
// 而那正是一个持续打这个地址的人能单方面控制的东西。
func TestRejectedDoesNotTouchLastSeen(t *testing.T) {
	s := New()
	s.Received("r1", 1000, "已接收并派发")
	for i := 0; i < 5; i++ {
		s.Rejected("r1")
	}

	got := s.Recv("r1")
	if got.Rejected != 5 {
		t.Fatalf("拒收计数应为 5，实际 %d", got.Rejected)
	}
	if got.Received != 1 {
		t.Fatalf("拒收不该算进收下计数，实际 %d", got.Received)
	}
	if got.LastAt != 1000 || got.LastStatus != "已接收并派发" {
		t.Fatalf("拒收改动了「最近收到」：at=%d status=%q", got.LastAt, got.LastStatus)
	}
}

// 从没见过的条目读出零值，等同于「还没收到过」——调用方不必先问「有没有」。
func TestReadUnknownIsZero(t *testing.T) {
	s := New()
	if got := s.Recv("没这条"); got != (Recv{}) {
		t.Fatalf("未知接收器应读出零值：%+v", got)
	}
	if got := s.Send("没这条"); got != (Send{}) {
		t.Fatalf("未知通知目标应读出零值：%+v", got)
	}
	if got := s.Wake("没这条"); got != (Wake{}) {
		t.Fatalf("未知设备应读出零值：%+v", got)
	}
}

// 投递成功与失败分别落到两个数上。
func TestSentSplitsOkAndFail(t *testing.T) {
	s := New()
	s.Sent("t1", 10, "HTTP 200", true)
	s.Sent("t1", 20, "HTTP 500", false)
	s.Sent("t1", 30, "HTTP 200", true)

	got := s.Send("t1")
	if got.Sent != 2 || got.Fail != 1 {
		t.Fatalf("成功/失败计数不符：%d / %d", got.Sent, got.Fail)
	}
	// 时刻与文本记的是「最近一次投递」，不分成功失败——失败也是一次投递结果，
	// 只显示成功的那次会让用户看不到刚刚发生的失败。
	if got.LastAt != 30 || got.LastStatus != "HTTP 200" {
		t.Fatalf("最近一次投递不符：at=%d status=%q", got.LastAt, got.LastStatus)
	}
}

// 三类共用一张表，键里带种类：ID 撞上也不该互相污染。
//
// 这三个 ID 是三个模块各自生成的，跨模块撞车的概率不为零（同一份配置导出再改，
// 或者用户手改 config.json）。撞了之后表现是「唤醒次数莫名跟着收到条数一起涨」。
func TestSameIDAcrossKindsDoesNotCollide(t *testing.T) {
	s := New()
	const id = "同一个ID"
	s.Received(id, 1, "收到")
	s.Sent(id, 2, "发出", true)
	s.Woke(id, 3, "唤醒")

	if got := s.Recv(id); got.Received != 1 || got.LastStatus != "收到" {
		t.Fatalf("接收器统计被串了：%+v", got)
	}
	if got := s.Send(id); got.Sent != 1 || got.LastStatus != "发出" {
		t.Fatalf("通知目标统计被串了：%+v", got)
	}
	if got := s.Wake(id); got.Count != 1 || got.LastText != "唤醒" {
		t.Fatalf("唤醒统计被串了：%+v", got)
	}
}

// 结果文本在**入库时**裁短，口径与 config.TruncateStatus 完全一致。
//
// 裁剪放在库里而不是各调用方：文本里有一部分来自对端可控的内容（拒收原因会带上
// 字段名与格式错误的片段），少裁一处就等于让对端决定这张表能占多少内存，
// 而这种超出在界面上完全看不出来。
func TestStatusTruncatedAtIngest(t *testing.T) {
	s := New()
	long := strings.Repeat("原", config.MaxStatusMessageLen*3)

	s.Received("r1", 1, long)
	s.Sent("t1", 1, long, true)
	s.Woke("w1", 1, long)

	want := config.TruncateStatus(long)
	if want == long {
		t.Fatal("config.TruncateStatus 没有裁短这段文本，用例的前提不成立")
	}
	if got := s.Recv("r1").LastStatus; got != want {
		t.Fatalf("接收器文本未按 TruncateStatus 裁短：\n实际 %q\n期望 %q", got, want)
	}
	if got := s.Send("t1").LastStatus; got != want {
		t.Fatalf("通知目标文本未按 TruncateStatus 裁短：%q", got)
	}
	if got := s.Wake("w1").LastText; got != want {
		t.Fatalf("唤醒文本未按 TruncateStatus 裁短：%q", got)
	}
}

// 空 ID 不建条目。
//
// 配置里的条目一定有 ID，空串只会来自调用方的疏漏（比如在匹配到接收器之前就记了一笔）。
// 建出来的话，那一条会被所有疏漏共用、数字越滚越大，而它对应不上界面上的任何一行。
func TestEmptyIDIsIgnored(t *testing.T) {
	s := New()
	s.Received("", 1, "收到")
	s.Rejected("")
	s.Sent("", 1, "发出", true)
	s.Woke("", 1, "唤醒")

	if n := s.Usage().Entries; n != 0 {
		t.Fatalf("空 ID 建出了 %d 条记录", n)
	}
}

// 读出来的是副本：调用方改手里的值不该影响库。
func TestReadReturnsCopy(t *testing.T) {
	s := New()
	s.Received("r1", 1000, "已接收")

	got := s.Recv("r1")
	got.Received = 999
	got.LastStatus = "被外面改掉了"

	if again := s.Recv("r1"); again.Received != 1 || again.LastStatus != "已接收" {
		t.Fatalf("库里的值被调用方改动了：%+v", again)
	}
}

// Forget 把三类一起删掉。
//
// 条目被删除时调用。只删一类会留下另两类的键——那些键再也没有界面能显示，
// 却还占着条数上限里的位置。
func TestForgetClearsAllKinds(t *testing.T) {
	s := New()
	const id = "r1"
	s.Received(id, 1, "收到")
	s.Sent(id, 2, "发出", true)
	s.Woke(id, 3, "唤醒")
	s.Received("留下的", 4, "收到")

	s.Forget(id)

	if got := s.Recv(id); got != (Recv{}) {
		t.Fatalf("接收器统计没删掉：%+v", got)
	}
	if got := s.Send(id); got != (Send{}) {
		t.Fatalf("通知目标统计没删掉：%+v", got)
	}
	if got := s.Wake(id); got != (Wake{}) {
		t.Fatalf("唤醒统计没删掉：%+v", got)
	}
	if got := s.Recv("留下的"); got.Received != 1 {
		t.Fatalf("Forget 连别的条目一起删了：%+v", got)
	}
}

// Reset 清空全部。
func TestResetClearsEverything(t *testing.T) {
	s := New()
	s.Received("r1", 1, "收到")
	s.Woke("w1", 2, "唤醒")

	s.Reset()

	if n := s.Usage().Entries; n != 0 {
		t.Fatalf("Reset 之后还剩 %d 条", n)
	}
	// 清空之后还能继续用：Reset 换的是新表，不是把表置成 nil。
	s.Received("r1", 3, "又收到")
	if got := s.Recv("r1"); got.Received != 1 || got.LastAt != 3 {
		t.Fatalf("Reset 之后写不进去了：%+v", got)
	}
}

// ---------- 上限 ----------

// 表满之后条数不再增长，淘汰的是最久没动静的那条，正在收数据的那条不受影响。
//
// 为什么是淘汰而不是拒绝新建：拒绝的话，受害的是当前真在收数据的那一条——它永远显示 0，
// 而用户完全无法理解为什么。淘汰 at 最小的那条，丢的是最久没动静的（很可能已经被删掉的）那一条。
func TestTableStopsGrowingAndEvictsOldest(t *testing.T) {
	s := New()
	// 灌满：at 从 1 开始递增，所以 at 最小的就是最早灌进去的那条。
	// 时刻由参数给定而不是取当前时间——按机器时钟排先后在这里排不出稳定的先后。
	for i := 1; i <= MaxEntries; i++ {
		s.Received(fmt.Sprintf("r%06d", i), int64(i), "收到")
	}
	if n := s.Usage().Entries; n != MaxEntries {
		t.Fatalf("灌满后应有 %d 条，实际 %d", MaxEntries, n)
	}

	// 再来一条新的：条数不变，最旧的那条（at=1）被顶掉，新的那条要在。
	s.Received("新来的", 999999, "收到")
	if n := s.Usage().Entries; n != MaxEntries {
		t.Fatalf("超出上限后条数涨到了 %d，上限是 %d", n, MaxEntries)
	}
	if got := s.Recv("新来的"); got.Received != 1 {
		t.Fatalf("表满时新条目被拒绝了：%+v", got)
	}
	if got := s.Recv("r000001"); got != (Recv{}) {
		t.Fatalf("被淘汰的应该是 at 最小的那条，但它还在：%+v", got)
	}
	if got := s.Recv(fmt.Sprintf("r%06d", MaxEntries)); got.Received != 1 {
		t.Fatalf("淘汰误伤了最新的那条：%+v", got)
	}

	// 已存在的条目继续计数不占新位置，也不该触发淘汰。
	s.Received("新来的", 1000000, "又收到")
	if n := s.Usage().Entries; n != MaxEntries {
		t.Fatalf("给已有条目加计数改变了条数：%d", n)
	}
}

// 折算是否站得住：把表灌到上限、每条都按最坏情况填，实测占用不得超过 MaxBytes。
//
// 这条用例是那个 entryBytes 常量的凭据。没有它，「1 MiB 上限」只是注释里的一句算术，
// 而算术漏算一项（比如 map 扩容那一刻的桶数组）不会有任何征兆。
func TestBudgetHoldsAtFullTable(t *testing.T) {
	// 最坏情况：结果文本顶到截断上限，ID 取 64 字节（界面新建的是 12 个字符，
	// 这里按导入进来的长 ID 算）。
	status := strings.Repeat("原", config.MaxStatusMessageLen)
	idPad := strings.Repeat("x", 50)

	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)

	s := New()
	for i := 0; i < MaxEntries; i++ {
		s.Received(fmt.Sprintf("%s%06d", idPad, i), int64(i+1), status)
	}

	runtime.GC()
	runtime.ReadMemStats(&after)
	// s 必须活到读数之后，否则 GC 可能已经把整张表收走，量出来的就是 0。
	if n := s.Usage().Entries; n != MaxEntries {
		t.Fatalf("没灌满：%d", n)
	}

	used := after.HeapAlloc - before.HeapAlloc
	if used > MaxBytes {
		t.Fatalf("灌满 %d 条实测占用 %d 字节，超过了 MaxBytes（%d）："+
			"entryBytes = %d 这个折算偏小了，改大它或改小 MaxEntries",
			MaxEntries, used, MaxBytes, entryBytes)
	}
	t.Logf("灌满 %d 条实测占用 %d 字节（上限 %d，用掉 %.0f%%）",
		MaxEntries, used, MaxBytes, float64(used)*100/float64(MaxBytes))

	// 同时核一遍算术本身：Usage 报的估值不得低于实测值，否则界面上会显示成
	// 「还很空」而实际已经贴着上限。
	if est := s.Usage().Bytes; uint64(est) < used {
		t.Fatalf("Usage 估值 %d 低于实测 %d：界面会低报占用", est, used)
	}
}

// 预算三个常量必须自洽。
func TestBudgetConstantsAreConsistent(t *testing.T) {
	if MaxEntries*entryBytes > MaxBytes {
		t.Fatalf("折算超了上限：%d × %d > %d", MaxEntries, entryBytes, MaxBytes)
	}
	if MaxBytes != 1<<20 {
		t.Fatalf("MaxBytes 应是 1 MiB，实际 %d：这个数是对用户承诺过的", MaxBytes)
	}
	// 实际用量的天花板是各模块条目上限之和，估算 300 条上下。上限必须明显高于它，
	// 否则正常使用就会开始淘汰，列表上的数字会莫名归零。
	const realWorldPeak = 300
	if MaxEntries < realWorldPeak*2 {
		t.Fatalf("上限 %d 条离正常用量（约 %d 条）太近了，正常使用就会开始淘汰",
			MaxEntries, realWorldPeak)
	}
}

// 单次写入的代价与表里已有多少条无关。
//
// 这是搬到内存里的全部意义：老路径每记一次都要换一份配置（代价与整份配置成正比）、
// 涨一次 rev、标一次脏等着落盘。新路径必须是一把锁加一次 map 写。
func TestWriteCostIgnoresTableSize(t *testing.T) {
	const calls = 500

	small := New()
	small.Received("r1", 1, "已接收并派发")

	big := New()
	for i := 0; i < MaxEntries/2; i++ {
		big.Received(fmt.Sprintf("r%06d", i), int64(i+1), "已接收并派发")
	}
	big.Received("r1", 1, "已接收并派发")

	smallCost := allocPerCall(calls, func(i int) { small.Received("r1", int64(i), "已接收并派发") })
	bigCost := allocPerCall(calls, func(i int) { big.Received("r1", int64(i), "已接收并派发") })

	// 先证明这把尺子能量到东西：一次已知会分配 1 KB 的调用必须被量出来。
	// 否则「两边都是 0 字节」既可能是真的不分配，也可能是尺子坏了，而后者什么都没钉住。
	ctrl := allocPerCall(calls, func(int) { sink = make([]byte, 1024) })
	if ctrl < 1024 {
		t.Fatalf("对照组只量出 %d 字节/次（应至少 1024）：这条用例没在量真东西", ctrl)
	}

	// 放宽到 +64 字节：量的是"不随表大小增长"，不是逐字节相等。
	if bigCost > smallCost+64 {
		t.Fatalf("单次代价随表大小增长了：1 条时 %d 字节/次，%d 条时 %d 字节/次",
			smallCost, MaxEntries/2+1, bigCost)
	}
	// 给已有条目加一次计数应该一个字节都不分配：改的是 map 里那个指针指着的结构体。
	if smallCost > 64 {
		t.Fatalf("给已有条目加计数分配了 %d 字节/次：写入路径上多了一次复制", smallCost)
	}
	t.Logf("单次写入：1 条时 %d 字节，%d 条时 %d 字节（对照组 %d 字节）",
		smallCost, MaxEntries/2+1, bigCost, ctrl)
}

// sink 挡住编译器把对照组那次分配优化掉。
var sink []byte

// allocPerCall 量 calls 次调用平均分配了多少字节。
func allocPerCall(calls int, fn func(i int)) uint64 {
	var a, b runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&a)
	for i := 0; i < calls; i++ {
		fn(i)
	}
	runtime.ReadMemStats(&b)
	return (b.TotalAlloc - a.TotalAlloc) / uint64(calls)
}

// ---------- 装配 ----------

// nil 库上的每个方法都得能调。
//
// 装配层允许不带这个库（server.Deps.Stats 可以是 nil，多数测试就是这么起的）。
// 靠调用点各自判空的话，漏掉的那一处就是一次崩溃，而漏掉的往往是最少走到的分支
// ——比如"接收器被删掉之后还有一条请求在处理"。
func TestNilStoreIsSafe(t *testing.T) {
	var s *Store

	s.Received("r1", 1, "收到")
	s.Rejected("r1")
	s.Sent("t1", 1, "发出", true)
	s.Woke("w1", 1, "唤醒")
	s.Forget("r1")
	s.Reset()

	if got := s.Recv("r1"); got != (Recv{}) {
		t.Fatalf("nil 库应读出零值：%+v", got)
	}
	if got := s.Send("t1"); got != (Send{}) {
		t.Fatalf("nil 库应读出零值：%+v", got)
	}
	if got := s.Wake("w1"); got != (Wake{}) {
		t.Fatalf("nil 库应读出零值：%+v", got)
	}
	if got := s.Usage(); got.Entries != 0 || got.MaxBytes != MaxBytes {
		t.Fatalf("nil 库的占用应是 0 条加上正常的上限：%+v", got)
	}
}

// 并发写同一条与不同条都不能丢数。
//
// 本机跑不了 -race（CGO 关着、没有 gcc），所以这里靠"总数必须精确对上"来兜：
// 少一把锁的话，两个 goroutine 读到同一个旧值再各写回去，计数就会少。
func TestConcurrentWritesKeepCount(t *testing.T) {
	s := New()
	const workers = 8
	const each = 500

	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < each; i++ {
				s.Received("共用的", int64(i+1), "收到")
				s.Rejected("共用的")
				s.Received(fmt.Sprintf("各自的%d", w), int64(i+1), "收到")
				_ = s.Recv("共用的")
			}
		}(w)
	}
	wg.Wait()

	if got := s.Recv("共用的"); got.Received != workers*each || got.Rejected != workers*each {
		t.Fatalf("并发下计数丢了：收下 %d / 拒收 %d，都应是 %d",
			got.Received, got.Rejected, workers*each)
	}
	for w := 0; w < workers; w++ {
		if got := s.Recv(fmt.Sprintf("各自的%d", w)); got.Received != each {
			t.Fatalf("第 %d 个 goroutine 自己那条计数不符：%d", w, got.Received)
		}
	}
}
