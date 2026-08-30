package metrics

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

// push 直接向环形缓冲写入采样点，绕过 gopsutil（单元测试不该依赖真实系统指标）。
func push(c *Collector, times ...int64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, ts := range times {
		c.pushLocked(Sample{Time: ts, SysCPU: float64(ts)})
	}
}

func timesOf(samples []Sample) []int64 {
	out := make([]int64, len(samples))
	for i, s := range samples {
		out[i] = s.Time
	}
	return out
}

func equalInts(a, b []int64) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// TestRingWrapsAndKeepsOrder 环形缓冲绕圈后仍须按时间升序导出，且只保留最近 size 个点。
func TestRingWrapsAndKeepsOrder(t *testing.T) {
	c := NewCollector(4, time.Second, "test")

	// 未满：只导出已写入的部分，不能带上尾部零值。
	push(c, 1, 2, 3)
	got, full := c.SeriesSince(0)
	if !full {
		t.Fatal("不带 since 时必须标记为全量")
	}
	if want := []int64{1, 2, 3}; !equalInts(timesOf(got), want) {
		t.Fatalf("未满时序列应为 %v，实际 %v", want, timesOf(got))
	}

	// 刚好写满。
	push(c, 4)
	got, _ = c.SeriesSince(0)
	if want := []int64{1, 2, 3, 4}; !equalInts(timesOf(got), want) {
		t.Fatalf("写满时序列应为 %v，实际 %v", want, timesOf(got))
	}

	// 绕圈：最旧的被覆盖，顺序不能错乱（这是"真环形"最容易写错的地方）。
	push(c, 5, 6)
	got, _ = c.SeriesSince(0)
	if want := []int64{3, 4, 5, 6}; !equalInts(timesOf(got), want) {
		t.Fatalf("绕圈后序列应为 %v，实际 %v", want, timesOf(got))
	}

	// 再绕一整圈，回到 next==0 的状态。
	push(c, 7, 8, 9, 10)
	got, _ = c.SeriesSince(0)
	if want := []int64{7, 8, 9, 10}; !equalInts(timesOf(got), want) {
		t.Fatalf("再绕一圈后序列应为 %v，实际 %v", want, timesOf(got))
	}
}

// TestSeriesSinceIncremental since 落在缓冲区内时只返回更新的点，且标记为增量。
func TestSeriesSinceIncremental(t *testing.T) {
	c := NewCollector(8, time.Second, "test")
	push(c, 10, 20, 30, 40)

	cases := []struct {
		since int64
		want  []int64
	}{
		{10, []int64{20, 30, 40}}, // 边界：等于最旧点，客户端已有它
		{20, []int64{30, 40}},
		{40, nil},  // 已是最新，无新点
		{999, nil}, // 比最新还新（时钟回拨等），同样没有可追加的点
	}
	for _, tc := range cases {
		got, full := c.SeriesSince(tc.since)
		if full {
			t.Errorf("since=%d 应返回增量而非全量", tc.since)
		}
		if !equalInts(timesOf(got), tc.want) {
			t.Errorf("since=%d 应返回 %v，实际 %v", tc.since, tc.want, timesOf(got))
		}
		if got == nil {
			t.Errorf("since=%d 返回了 nil：会被序列化成 JSON null，前端拿不到数组", tc.since)
		}
	}
}

// TestSeriesSinceFallsBackToFull since 早于缓冲区最旧点时必须回退成全量，
// 否则调用方的曲线会缺掉被淘汰的那一段。
func TestSeriesSinceFallsBackToFull(t *testing.T) {
	c := NewCollector(3, time.Second, "test")

	// 空缓冲：也算全量（前端据此走"整体替换"分支）。
	got, full := c.SeriesSince(5)
	if !full || len(got) != 0 || got == nil {
		t.Fatalf("空缓冲应返回空的全量切片，实际 full=%v got=%v", full, got)
	}

	push(c, 10, 20, 30, 40) // 10 已被挤出
	got, full = c.SeriesSince(10)
	if !full {
		t.Fatal("since 早于最旧点时必须回退为全量")
	}
	if want := []int64{20, 30, 40}; !equalInts(timesOf(got), want) {
		t.Fatalf("全量应为 %v，实际 %v", want, timesOf(got))
	}
}

// TestLatest 最近一次采样在绕圈前后都应取到真正的最新点。
func TestLatest(t *testing.T) {
	c := NewCollector(3, time.Second, "test")
	if _, ok := c.Latest(); ok {
		t.Fatal("空缓冲不应返回采样点")
	}
	push(c, 1, 2)
	if s, ok := c.Latest(); !ok || s.Time != 2 {
		t.Fatalf("未满时最新点应为 2，实际 %+v ok=%v", s, ok)
	}
	push(c, 3, 4, 5)
	if s, ok := c.Latest(); !ok || s.Time != 5 {
		t.Fatalf("绕圈后最新点应为 5，实际 %+v ok=%v", s, ok)
	}
}

// TestCurrentIntervalBacksOffWhenIdle 无人查看时降频，Touch 后立即恢复全速。
func TestCurrentIntervalBacksOffWhenIdle(t *testing.T) {
	c := NewCollector(4, 2*time.Second, "test")
	base := c.interval // Windows 上会被抬到 minWindowsInterval，故不写死 2s

	// 从未被访问过：lastAccess 为 0，保持全速（Start 会主动置一次，这里模拟未 Start）。
	if got := c.currentInterval(); got != base {
		t.Fatalf("未记录访问时应保持 %v，实际 %v", base, got)
	}

	c.lastAccess.Store(time.Now().Add(-idleAfter - time.Minute).UnixNano())
	if got := c.currentInterval(); got != idleInterval {
		t.Fatalf("空闲超过 %v 应降频到 %v，实际 %v", idleAfter, idleInterval, got)
	}

	c.Touch()
	if got := c.currentInterval(); got != base {
		t.Fatalf("Touch 后应恢复 %v，实际 %v", base, got)
	}
}

// TestTouchWakesOnlyOnTransition Touch 只在 idle→active 的跃变时唤醒采样协程；
// 面板每几秒一次的正常轮询若每次都唤醒，降频就等于没做。
func TestTouchWakesOnlyOnTransition(t *testing.T) {
	c := NewCollector(4, time.Second, "test")

	c.lastAccess.Store(time.Now().Add(-idleAfter - time.Minute).UnixNano())
	c.Touch()
	select {
	case <-c.wake:
	default:
		t.Fatal("从空闲恢复时应唤醒采样协程")
	}

	c.Touch() // 紧接着的第二次轮询
	select {
	case <-c.wake:
		t.Fatal("活跃期间的轮询不应反复唤醒采样协程")
	default:
	}
}

// TestWindowsIntervalFloor Windows 上 gopsutil 部分指标走 WMI，间隔必须抬到 5 秒。
// 非 Windows 平台保持调用方给的值。
func TestWindowsIntervalFloor(t *testing.T) {
	c := NewCollector(4, time.Second, "test")
	if runtime.GOOS == "windows" {
		if c.interval != minWindowsInterval {
			t.Fatalf("Windows 上应抬到 %v，实际 %v", minWindowsInterval, c.interval)
		}
		return
	}
	if c.interval != time.Second {
		t.Fatalf("非 Windows 平台应沿用调用方给的 1s，实际 %v", c.interval)
	}
}

// ---------- 容器整体内存占用（cgroupmem.go） ----------

// 口径必须与 docker stats 一致：用量减去可回收的干净页缓存。
// 减错了不会有任何报错，只是面板上的数字与用户 docker stats 看到的对不上——
// 而"对得上账"正是做这件事的全部理由。
func TestReadCgroupMemSubtractsInactiveFile(t *testing.T) {
	dir := t.TempDir()
	usage := filepath.Join(dir, "memory.current")
	stat := filepath.Join(dir, "memory.stat")
	// 100 MiB 用量，其中 40 MiB 是非活跃文件页 → 应显示 60 MiB。
	writeFile(t, usage, "104857600\n")
	writeFile(t, stat, "anon 20971520\nfile 41943040\ninactive_file 41943040\nslab 1048576\n")

	got, ok := readCgroupMem(usage, stat, "inactive_file")
	if !ok {
		t.Fatal("读不到用量")
	}
	if want := uint64(104857600 - 41943040); got != want {
		t.Fatalf("用量 = %d，应为 %d", got, want)
	}
}

// 两个文件不是同一瞬间读的，理论上能读出 inactive 比 usage 还大。
// 无符号相减会绕成一个天文数字（16 EB 那种），面板上就是一个荒谬的内存值。
func TestReadCgroupMemNeverUnderflows(t *testing.T) {
	dir := t.TempDir()
	usage := filepath.Join(dir, "memory.current")
	stat := filepath.Join(dir, "memory.stat")
	writeFile(t, usage, "1048576\n")
	writeFile(t, stat, "inactive_file 2097152\n")

	got, ok := readCgroupMem(usage, stat, "inactive_file")
	if !ok {
		t.Fatal("读不到用量")
	}
	if got != 1048576 {
		t.Fatalf("用量 = %d，应原样返回 1048576（宁可少减，不能绕回）", got)
	}
}

// memory.stat 缺了那一项时当 0：少减一项只是数字偏大一点，比整块放弃好。
func TestReadCgroupMemToleratesMissingStat(t *testing.T) {
	dir := t.TempDir()
	usage := filepath.Join(dir, "memory.current")
	writeFile(t, usage, "5242880\n")

	got, ok := readCgroupMem(usage, filepath.Join(dir, "no-such-file"), "inactive_file")
	if !ok {
		t.Fatal("stat 读不到时仍应返回用量")
	}
	if got != 5242880 {
		t.Fatalf("用量 = %d，应为 5242880", got)
	}
}

// 用量文件本身读不到（不在容器里、或换了 cgroup 版本）必须返回 false，
// 让调用方退回本进程 RSS，而不是把 0 显示成「内存归零」。
func TestReadCgroupMemFailsWithoutUsageFile(t *testing.T) {
	dir := t.TempDir()
	if _, ok := readCgroupMem(filepath.Join(dir, "nope"), filepath.Join(dir, "nope2"), "inactive_file"); ok {
		t.Fatal("用量文件不存在时不该返回 ok")
	}
}

// statField 只认整行的键，不能被"名字里包含它"的那一项蒙过去。
// cgroup v1 的 memory.stat 里 inactive_file 与 total_inactive_file 同时存在，
// 前缀匹配会取错那一个（差的正是子 cgroup 那部分）。
func TestStatFieldMatchesWholeKey(t *testing.T) {
	dir := t.TempDir()
	stat := filepath.Join(dir, "memory.stat")
	writeFile(t, stat, "inactive_file 111\ntotal_inactive_file 222\n")

	if got := statField(stat, "inactive_file"); got != 111 {
		t.Fatalf("inactive_file = %d，应为 111", got)
	}
	if got := statField(stat, "total_inactive_file"); got != 222 {
		t.Fatalf("total_inactive_file = %d，应为 222", got)
	}
	if got := statField(stat, "not_there"); got != 0 {
		t.Fatalf("缺失项应为 0，得到 %d", got)
	}
}

// 取不到容器用量时，Info 里的「内存占用」必须退回本进程 RSS，不能是 0。
// 在 Windows 与直接跑二进制的 Linux 上，走的正是这一条。
func TestInfoFallsBackToProcessMemory(t *testing.T) {
	c := NewCollector(10, time.Second, "test")
	c.mu.Lock()
	c.procMemMB = 42
	c.memUsedMB = 0 // 不在容器里
	c.mu.Unlock()

	if got := c.Info().MemUsedMB; got != 42 {
		t.Fatalf("内存占用 = %v，应退回本进程的 42", got)
	}
}

// 采样点里的内存值与 Info() 必须同一个口径（容器整体或本进程）。
// 卡片显示的是 Info 的 MemUsedMB，曲线画的是 Sample.MemUsedMB——两处口径不一致时，
// 图上那条线会跟卡片数字对不上，用户会以为曲线是另一台机器的。
func TestSampleMemMatchesInfoScope(t *testing.T) {
	for _, tc := range []struct {
		label       string
		procMemMB   float64
		memUsedMB   float64
		isContainer bool
		want        float64
	}{
		{"容器整体", 30, 52, true, 52},
		{"退回本进程", 42, 0, false, 42},
	} {
		c := NewCollector(10, time.Second, "test")
		c.mu.Lock()
		c.procMemMB = tc.procMemMB
		c.memUsedMB = tc.memUsedMB
		c.memIsContainer = tc.isContainer
		s := Sample{Time: 1}
		s.MemUsedMB = c.effectiveMemLocked()
		c.mu.Unlock()

		if s.MemUsedMB != tc.want {
			t.Fatalf("%s：采样点内存 = %v，应为 %v", tc.label, s.MemUsedMB, tc.want)
		}
		if s.MemUsedMB != c.Info().MemUsedMB {
			t.Fatalf("%s：采样点 (%v) 与 Info (%v) 口径不一致", tc.label, s.MemUsedMB, c.Info().MemUsedMB)
		}
	}
}

// /proc/self/cgroup 的两种版本各取各的那一行。
// v2 那行的层级号是 0 且控制器列表为空，v1 要在逗号分隔的控制器列表里找 memory。
func TestParseSelfCgroupReadsBothVersions(t *testing.T) {
	v2, v1 := parseSelfCgroup("0::/docker/abc\n11:memory:/docker/def\n9:cpu,cpuacct:/docker/ghi\n")
	if v2 != "/docker/abc" {
		t.Fatalf("v2 路径 = %q，应为 /docker/abc", v2)
	}
	if v1 != "/docker/def" {
		t.Fatalf("v1 路径 = %q，应为 /docker/def", v1)
	}
}

// 控制器列表是逗号分隔的多个时也得认出 memory 来，
// 否则 v1 下就只能退回挂载点根——那在 host 命名空间里是整台机器。
func TestParseSelfCgroupFindsMemoryInControllerList(t *testing.T) {
	_, v1 := parseSelfCgroup("4:cpuset,memory,pids:/kubepods/pod123\n")
	if v1 != "/kubepods/pod123" {
		t.Fatalf("v1 路径 = %q，应为 /kubepods/pod123", v1)
	}
}

// 带自己 cgroup 命名空间时（docker 的 --cgroupns=private）路径就是 "/"，
// 挂载点根本身即本容器；这时不该拼出多余的候选。
func TestCgroupMemCandidatesSkipsRootEquivalentPath(t *testing.T) {
	got := cgroupMemCandidates("/", "/")
	if len(got) != 2 {
		t.Fatalf("候选数 = %d，应为 2（v2 根 + v1 根）", len(got))
	}
	if got[0].usage != "/sys/fs/cgroup/memory.current" {
		t.Fatalf("第一个候选 = %q", got[0].usage)
	}
	if got[1].usage != "/sys/fs/cgroup/memory/memory.usage_in_bytes" {
		t.Fatalf("第二个候选 = %q", got[1].usage)
	}
}

// 宿主机 cgroup 命名空间下（--cgroupns=host，cgroup v1 的宿主机上是默认值），
// 容器里看到的挂载点根是宿主机的 cgroup 根，本容器那份在子目录里。
//
// 这里钉住的是**顺序**：拼出来的自身路径必须排在挂载点根前面。v1 的根在这种情形下
// 是读得通的，读出来却是整台机器的用量——先试根就会拿到一个大得离谱的数，且不报错。
func TestCgroupMemCandidatesPrefersOwnPathOverMountRoot(t *testing.T) {
	got := cgroupMemCandidates("/docker/abc", "/docker/abc")
	want := []string{
		"/sys/fs/cgroup/docker/abc/memory.current",
		"/sys/fs/cgroup/memory.current",
		"/sys/fs/cgroup/memory/docker/abc/memory.usage_in_bytes",
		"/sys/fs/cgroup/memory/memory.usage_in_bytes",
	}
	if len(got) != len(want) {
		t.Fatalf("候选数 = %d，应为 %d", len(got), len(want))
	}
	for i, w := range want {
		if got[i].usage != w {
			t.Fatalf("第 %d 个候选 = %q，应为 %q", i+1, got[i].usage, w)
		}
	}
	// memory.stat 必须跟用量文件同目录，而且两个版本要减的项名字不一样。
	if got[0].stat != "/sys/fs/cgroup/docker/abc/memory.stat" {
		t.Fatalf("v2 明细文件 = %q，应与用量文件同目录", got[0].stat)
	}
	if got[0].inactiveKey != "inactive_file" || got[2].inactiveKey != "total_inactive_file" {
		t.Fatalf("要减掉的项取错了：v2=%q v1=%q", got[0].inactiveKey, got[2].inactiveKey)
	}
}

// 读到了容器用量时，Info 报的口径必须是「容器整体」，数字用容器那个。
func TestInfoLabelsContainerScope(t *testing.T) {
	c := NewCollector(10, time.Second, "test")
	c.mu.Lock()
	c.procMemMB = 30
	c.memUsedMB = 52
	c.memIsContainer = true
	c.mu.Unlock()

	got := c.Info()
	if got.MemUsedMB != 52 {
		t.Fatalf("内存占用 = %v，应为容器的 52", got.MemUsedMB)
	}
	if got.MemScope != MemScopeContainer {
		t.Fatalf("口径 = %q，应为 %q", got.MemScope, MemScopeContainer)
	}
	if got.ProcMemMB != 30 {
		t.Fatalf("本进程占用 = %v，应仍为 30", got.ProcMemMB)
	}
}

// 退回本进程 RSS 时，口径也必须跟着改成「本程序」——否则数字小了一截却仍标着「容器整体」，
// 正是这次要修的那种"静默换口径"。
func TestInfoLabelsProcessScopeOnFallback(t *testing.T) {
	c := NewCollector(10, time.Second, "test")
	c.mu.Lock()
	c.procMemMB = 30
	c.memUsedMB = 0
	c.memIsContainer = false
	c.mu.Unlock()

	if got := c.Info().MemScope; got != MemScopeProcess {
		t.Fatalf("口径 = %q，应为 %q", got, MemScopeProcess)
	}
}

// 系统内存口径：「总量 − 可用」。
// 1568 MB 的机器上可用 1093 MB，就该是 475 MB / 30.3%，
// 而不是刨掉全部页缓存之后那个偏小的数（改前显示的是 6.9%）。
func TestSysMemUsageUsesAvailable(t *testing.T) {
	const mb = 1024 * 1024
	pct, usedMB, totalMB := sysMemUsage(1568*mb, 1093*mb)
	if usedMB != 475 {
		t.Fatalf("已用 = %v MB，应为 475", usedMB)
	}
	if totalMB != 1568 {
		t.Fatalf("总量 = %v MB，应为 1568", totalMB)
	}
	if pct < 30.2 || pct > 30.4 {
		t.Fatalf("百分比 = %v，应约为 30.3", pct)
	}
}

// 两个边界：总量读成 0 时不能除零，可用大于总量时不能让无符号相减绕成天文数字。
func TestSysMemUsageHandlesBadReadings(t *testing.T) {
	if pct, used, total := sysMemUsage(0, 0); pct != 0 || used != 0 || total != 0 {
		t.Fatalf("总量为 0 时应全部为 0，得到 %v %v %v", pct, used, total)
	}
	pct, used, _ := sysMemUsage(100, 200)
	if pct != 0 || used != 0 {
		t.Fatalf("可用大于总量时应报 0，得到 %v %v", pct, used)
	}
}

// 挑候选时"读得通的第一组"就是答案，后面的不再看。
//
// 这里造的正是这次要修的那种情形：宿主机 cgroup 命名空间下的 cgroup v1，挂载点根
// 和本容器的子目录都存在且都读得通，根那份是整台机器的用量。取错了不会报错，
// 只会在卡片上显示一个大得离谱的数——所以必须钉住"取的是子目录那份"。
func TestFirstReadableCgroupMemTakesOwnPathNotMountRoot(t *testing.T) {
	root := t.TempDir()
	own := filepath.Join(root, "docker", "abc")
	if err := os.MkdirAll(own, 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(own, "memory.usage_in_bytes"), "54525952\n")     // 52 MB，本容器
	writeFile(t, filepath.Join(own, "memory.stat"), "total_inactive_file 0\n")  //
	writeFile(t, filepath.Join(root, "memory.usage_in_bytes"), "1073741824\n")  // 1 GB，整台机器
	writeFile(t, filepath.Join(root, "memory.stat"), "total_inactive_file 0\n") //

	got, ok := firstReadableCgroupMem([]cgroupMemFiles{
		{filepath.Join(own, "memory.usage_in_bytes"), filepath.Join(own, "memory.stat"), "total_inactive_file"},
		{filepath.Join(root, "memory.usage_in_bytes"), filepath.Join(root, "memory.stat"), "total_inactive_file"},
	})
	if !ok {
		t.Fatal("两组都存在却一组都没读通")
	}
	if got != 54525952 {
		t.Fatalf("用量 = %d，应为本容器的 54525952（取到 1073741824 就是取成整机了）", got)
	}
}

// 前面的候选读不通时要接着往后试，不能一组失败就整个放弃。
func TestFirstReadableCgroupMemFallsThrough(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "memory.current"), "8388608\n")

	got, ok := firstReadableCgroupMem([]cgroupMemFiles{
		{filepath.Join(dir, "nope"), filepath.Join(dir, "nope"), "inactive_file"},
		{filepath.Join(dir, "memory.current"), filepath.Join(dir, "memory.stat"), "inactive_file"},
	})
	if !ok || got != 8388608 {
		t.Fatalf("用量 = %d ok=%v，应落到第二组的 8388608", got, ok)
	}
}

// 「系统内存」的口径必须发得出去，且只能是那两个值之一。
// 空串会让卡片上少一行——而加这一行的全部理由，就是让人看得出这个数是容器视角还是本机。
func TestInfoReportsSysMemScope(t *testing.T) {
	c := NewCollector(4, time.Second, "test")
	switch got := c.Info().SysMemScope; got {
	case SysMemScopeHost, SysMemScopeContainer:
		// 跑测试的机器可能在容器里也可能不在，两个都算对。
	default:
		t.Fatalf("口径 = %q，应为 %q 或 %q", got, SysMemScopeHost, SysMemScopeContainer)
	}

	c.sysMemScope = SysMemScopeContainer
	if got := c.Info().SysMemScope; got != SysMemScopeContainer {
		t.Fatalf("口径 = %q，应原样报出采集器里那个值 %q", got, SysMemScopeContainer)
	}
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}
