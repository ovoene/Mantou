package metrics

import (
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/mem"
	"github.com/shirou/gopsutil/v3/net"
	"github.com/shirou/gopsutil/v3/process"
)

// 采样节奏相关常量。
const (
	// idleAfter 距最近一次面板访问超过该时长即视为「无人查看」，采样降到 idleInterval。
	// 自托管面板绝大多数时间没人看，全速采出来的点只会被环形缓冲静静淘汰掉。
	idleAfter = 5 * time.Minute

	// idleInterval 无人查看时的采样间隔。仍然采（而不是停），是为了让「打开面板就有历史曲线」
	// 这一体验成立：完全停采会在图上留下一段死区，也拿不到这段时间的累计流量。
	idleInterval = 30 * time.Second

	// minWindowsInterval Windows 上的最小采样间隔。gopsutil 在 Windows 上部分指标走 WMI
	//（基于 COM 的重量级接口，单次 10–100 ms，会唤醒 WmiPrvSE.exe 并阻止 CPU 进入低功耗状态），
	// 2 秒一次是任务管理器里肉眼可见的持续抖动。5 秒对图表精度无实质影响。
	minWindowsInterval = 5 * time.Second
)

// Sample 是一次采样点。
type Sample struct {
	Time    int64   `json:"time"`    // Unix 毫秒
	SysCPU  float64 `json:"sysCpu"`  // 系统 CPU 使用率 %
	ProcCPU float64 `json:"procCpu"` // 本进程 CPU 使用率 %
	// SysMem 系统内存占用 %，口径是「总量 − 可用」÷ 总量，见 sampleOnce 里的说明。
	// 只用在卡片上，不画成曲线：容器里读到的是容器可见的那个上限（见 SysMemScopeContainer），
	// 画成一条随时间走的线，太容易被当成整机内存的趋势。
	SysMem   float64 `json:"sysMem"`
	DownRate float64 `json:"downRate"` // 下行速率 B/s
	UpRate   float64 `json:"upRate"`   // 上行速率 B/s
	// MemUsedMB 与 Info.MemUsedMB 同一个数（面板「内存占用」卡片显示的那个），
	// 一并放进采样点供曲线使用。口径（容器整体 / 本进程）同 Info.MemScope，见 effectiveMemLocked。
	MemUsedMB float64 `json:"memUsedMB"`
}

// 「内存占用」那个数的口径，随 Info 一起发给前端，由前端标在卡片上。
//
// 为什么要发这一项：容器整体与本程序是两个差得挺多的数（前者含页缓存、内核为容器分配的
// 内存以及容器里的其他进程），而读不到 cgroup 时会静默地从前者退到后者。不标出来，
// 用户只会看到数字忽然小了一截，无从判断是程序省了内存还是面板换了口径。
const (
	MemScopeContainer = "container" // 整个容器，与 docker stats 那一列同口径
	MemScopeProcess   = "process"   // 仅本程序（RSS）
)

// 「系统内存」那两个数是站在哪儿看的，同样随 Info 一起发给前端。
//
// 容器里的 /proc/meminfo 往往已经被容器化过（不少第三方容器平台用 lxcfs 那类做法做这件事），
// 读到的是**本容器可见的那个上限**，而不是宿主机的物理内存；再往外套一层容器，看到的就是
// 外层那一层的视角。从容器内部拿不到宿主机的真值——那正是隔离要做的事，没有接口能绕过去。
//
// 于是不去猜，直接把口径标在卡片上：知道这是容器视角，就不会拿它跟宿主机那边的监控对账，
// 也不会以为面板算错了。
const (
	SysMemScopeContainer = "container" // 容器可见的上限，未必等于宿主机内存
	SysMemScopeHost      = "host"      // 直接跑在机器上，读到的就是这台机器
)

// Info 是服务器/进程静态与实时信息。
type Info struct {
	StartedAt int64   `json:"startedAt"` // 进程启动时间（Unix 毫秒）
	QueriedAt int64   `json:"queriedAt"` // 当前查询时间
	ProcMemMB float64 `json:"procMemMB"` // 本进程占用内存 MB（RSS，由采样器维护，见 updateProcInfo）
	// MemUsedMB 面板「内存占用」显示的那个数：在容器里是整个容器的占用（与 docker stats
	// 那一列同口径，见 cgroupmem.go），不在容器里就等于 ProcMemMB。
	// 两个都留着：一个是"这台机器上这个容器吃了多少"，一个是"本程序自己吃了多少"，
	// 排查时要的往往是后者，而用户对得上账的是前者。
	MemUsedMB float64 `json:"memUsedMB"`
	// MemScope 上面那个数究竟是哪一种，取值见 MemScopeContainer / MemScopeProcess。
	MemScope string `json:"memScope"`
	// SysMemUsedMB / SysMemTotalMB 系统内存的已用与总量。
	// 与 Sample.SysMem 那个百分比出自同一次读取，所以三个数互相对得上（见 sampleOnce）。
	SysMemUsedMB  float64 `json:"sysMemUsedMB"`
	SysMemTotalMB float64 `json:"sysMemTotalMB"`
	// SysMemScope 上面这三个数是站在哪儿看的，取值见 SysMemScopeContainer / SysMemScopeHost。
	SysMemScope string `json:"sysMemScope"`
	RecvTotal   uint64 `json:"recvTotal"` // 接收总量（字节）
	SentTotal   uint64 `json:"sentTotal"` // 发送总量（字节）
	Version     string `json:"version"`   // mantou 版本
}

// Collector 周期性采集系统与进程指标，维护固定长度时间序列。
//
// 序列用真环形缓冲存放：buf 长度固定为 size，next 指向下一个写入位置，filled 标记是否已绕过一圈。
// 早先的实现是「切片 + 满了以后 copy(series, series[1:]) 整体左移」——每次采样都要搬动
// 整个数组（180 个 Sample ≈ 8 KB），而环形写入只是一次下标赋值。
type Collector struct {
	mu     sync.RWMutex
	buf    []Sample
	size   int
	next   int
	filled bool

	interval time.Duration

	proc      *process.Process
	startedAt time.Time
	version   string
	// sysMemScope 「系统内存」那几个数是站在哪儿看的（见 SysMemScopeContainer 的说明）。
	// 「跑不跑在容器里」在进程活着的这段时间内不会变，故在 NewCollector 里定一次；
	// 此后只读不写，读它不必加锁。
	sysMemScope string

	// procMemMB / memUsedMB / sysMem* 由采样协程写、Info() 读，均受 mu 保护。
	// 把它们从 Info() 移到采样器里是有意的：每个都要碰系统调用或 /sys 下的文件，
	// 而 Info() 的调用频率取决于有几个人开着总览页。并入采样器后 Info() 变成 O(1) 的
	// 内存读取，开销与观察者数量彻底解耦。
	//
	// memUsedMB 要读两个 cgroup 文件（见 cgroupmem.go）。不在容器里时它一直是 0，
	// Info() 那里会退回 procMemMB。
	//
	// memIsContainer 记的是"上面那个数到底读到没有"，而不是靠 memUsedMB == 0 反推——
	// 一个真占 0 字节的容器不存在，但用一个数兼职表示"没读到"，
	// 是那种平时看不出、出问题时又查不动的写法。
	//
	// sysMemUsedMB / sysMemTotalMB 与采样点里的百分比同出一次 mem.VirtualMemory()，
	// 所以放在这里由采样协程一起写，而不是在 Info() 里另读一次——另读一次就会出现
	// 「百分比和 MB 数对不上」，而这两个数摆在同一张卡片上。
	procMemMB      float64
	memUsedMB      float64
	memIsContainer bool
	sysMemUsedMB   float64
	sysMemTotalMB  float64

	lastNetRecv uint64
	lastNetSent uint64
	lastNetTime time.Time
	recvTotal   uint64
	sentTotal   uint64

	// lastAccess 最近一次面板读取指标的时刻（Unix 纳秒），由 Touch 更新。
	lastAccess atomic.Int64
	// wake 用于「长时间无人查看 → 有人打开面板」的瞬间立刻补一次采样，
	// 否则用户要等最多 idleInterval 才能看到第一个新点。
	wake chan struct{}

	stop chan struct{}
	done chan struct{}
}

// NewCollector 创建采集器。capacity 为保留的采样点数量，interval 为采样间隔。
func NewCollector(capacity int, interval time.Duration, version string) *Collector {
	if capacity <= 0 {
		capacity = 180
	}
	if interval <= 0 {
		interval = 2 * time.Second
	}
	if runtime.GOOS == "windows" && interval < minWindowsInterval {
		interval = minWindowsInterval
	}
	p, _ := process.NewProcess(int32(os.Getpid()))
	scope := SysMemScopeHost
	if insideContainer() {
		scope = SysMemScopeContainer
	}
	return &Collector{
		buf:         make([]Sample, capacity),
		size:        capacity,
		interval:    interval,
		proc:        p,
		startedAt:   time.Now(),
		version:     version,
		sysMemScope: scope,
		wake:        make(chan struct{}, 1),
		stop:        make(chan struct{}),
		done:        make(chan struct{}),
	}
}

// Start 启动后台采集循环。
func (c *Collector) Start() {
	// 预热 CPU 百分比计算。gopsutil 在 Windows 上（WMI/COM）偶发 panic，需 recover 兜底，
	// 否则会让整个进程直接崩溃（表现为 Windows 双击闪退）。
	c.safePreheat()
	c.safeInitNet()
	// 先填一次进程信息：否则首次采样之前打开面板，内存显示 0。
	c.safeUpdateProcInfo()
	// 视启动为一次「访问」：刚起来的几分钟按全速采，保证开机后立刻打开面板就有曲线。
	c.lastAccess.Store(time.Now().UnixNano())

	go func() {
		defer close(c.done)
		timer := time.NewTimer(c.currentInterval())
		defer timer.Stop()
		for {
			select {
			case <-c.stop:
				return
			case <-c.wake:
				// 从「无人查看」恢复为活跃，立即补采一点。
			case <-timer.C:
			}
			c.safeSample()
			// Go 1.23 起 Timer 通道不再缓冲，Stop 后直接 Reset 不会收到过期的旧值。
			timer.Stop()
			timer.Reset(c.currentInterval())
		}
	}()
}

// Touch 记录一次面板读取，用于按需采样：有人在看就全速采，没人看就降频。
// 由 /api/overview 与 /api/overview/series 两个处理器调用。
func (c *Collector) Touch() {
	now := time.Now()
	prev := c.lastAccess.Swap(now.UnixNano())
	// 仅在 idle → active 的跃变时唤醒采样协程。面板轮询本身是每几秒一次，
	// 若每次都唤醒就等于取消了降频。
	if prev != 0 && now.Sub(time.Unix(0, prev)) > idleAfter {
		select {
		case c.wake <- struct{}{}:
		default:
		}
	}
}

// currentInterval 按「是否有人在看」决定下一次采样的等待时长。
func (c *Collector) currentInterval() time.Duration {
	last := c.lastAccess.Load()
	if last != 0 && time.Since(time.Unix(0, last)) > idleAfter && c.interval < idleInterval {
		return idleInterval
	}
	return c.interval
}

// safePreheat 预热 CPU 采样；recover 防止 gopsutil panic 拖垮进程。
func (c *Collector) safePreheat() {
	defer func() { _ = recover() }()
	_, _ = cpu.Percent(0, false)
	if c.proc != nil {
		_, _ = c.proc.Percent(0)
	}
}

// safeInitNet 初始化网卡计数；recover 防止 gopsutil panic 拖垮进程。
func (c *Collector) safeInitNet() {
	defer func() { _ = recover() }()
	c.initNetCounters()
}

// safeUpdateProcInfo 采集进程信息；recover 防止 gopsutil panic 拖垮进程。
func (c *Collector) safeUpdateProcInfo() {
	defer func() { _ = recover() }()
	c.updateProcInfo()
}

// safeSample 执行一次采样；recover 防止 gopsutil panic 拖垮进程。
func (c *Collector) safeSample() {
	defer func() { _ = recover() }()
	c.sampleOnce()
}

// Stop 停止采集循环。
func (c *Collector) Stop() {
	select {
	case <-c.stop:
		// 已关闭
	default:
		close(c.stop)
	}
	<-c.done
}

func (c *Collector) initNetCounters() {
	recv, sent := readNetTotals()
	c.lastNetRecv = recv
	c.lastNetSent = sent
	c.lastNetTime = time.Now()
}

// updateProcInfo 刷新进程级指标（本进程 RSS、容器整体用量）。
// 取值失败时保留上一次的结果而不是清零：MemoryInfo 偶发失败、容器用量在非容器环境下
// 一直取不到，把 0 写进去会让面板显示成「内存归零」。
func (c *Collector) updateProcInfo() {
	if c.proc == nil {
		return
	}
	var (
		memMB    float64
		usedMB   float64
		haveMem  bool
		haveUsed bool
	)
	if mi, err := c.proc.MemoryInfo(); err == nil && mi != nil {
		memMB = round2(float64(mi.RSS) / 1024 / 1024)
		haveMem = true
	}
	// 容器整体用量：不在容器里就一直取不到，Info() 会退回本进程 RSS。
	if b, ok := containerMemBytes(); ok {
		usedMB = round2(float64(b) / 1024 / 1024)
		haveUsed = true
	}
	if !haveMem && !haveUsed {
		return
	}
	c.mu.Lock()
	if haveMem {
		c.procMemMB = memMB
	}
	if haveUsed {
		c.memUsedMB = usedMB
		c.memIsContainer = true
	}
	c.mu.Unlock()
}

func (c *Collector) sampleOnce() {
	now := time.Now()

	var sysCPU float64
	if p, err := cpu.Percent(0, false); err == nil && len(p) > 0 {
		sysCPU = p[0]
	}

	// 系统内存：口径是「总量 − 可用」，而不是 gopsutil 的 UsedPercent。
	//
	// 两者在 Linux 上差得很远。gopsutil 的 Used 是「总量 − 空闲 − buffers − 缓存」，
	// 也就是刨掉全部页缓存之后的那点，接近 free 命令 used 那一列；而"这台机器还剩多少内存
	// 可用"要看的是 MemAvailable——它已经算进了"缓存里有多少是能立刻回收的"。
	// 一台 1.5 GB 的小机器上，前者可能报 7%，后者是 30%：用户对着别处看到的是后者，
	// 而缓存本来就是内核拿空闲内存做的事，把它算成"空着"才更贴近"还能不能再跑点东西"。
	//
	// 顺带把已用与总量的 MB 数也存下来。三个数出自同一次读取，卡片上摆在一起才对得上；
	// 分两处各读一次，就会出现百分比与 MB 数互相矛盾的那半秒。
	var sysMem, sysMemUsedMB, sysMemTotalMB float64
	if vm, err := mem.VirtualMemory(); err == nil {
		sysMem, sysMemUsedMB, sysMemTotalMB = sysMemUsage(vm.Total, vm.Available)
	}

	var procCPU float64
	if c.proc != nil {
		if v, err := c.proc.Percent(0); err == nil {
			// 归一化到单核百分比区间，避免多核下超过 100 太多造成图表异常。
			procCPU = v / float64(runtime.NumCPU())
		}
	}

	c.updateProcInfo()

	// lastNet* 只由采集协程（Start 启动的那一个）读写：initNetCounters 在协程创建之前
	// 于 Start 中同步执行，故无需加锁。而 recvTotal / sentTotal 会被 Info() 并发读取，
	// 必须在锁内累加（见下）。
	recv, sent := readNetTotals()
	dt := now.Sub(c.lastNetTime).Seconds()
	var down, up float64
	var recvDelta, sentDelta uint64
	if dt > 0 {
		if recv >= c.lastNetRecv {
			recvDelta = recv - c.lastNetRecv
			down = float64(recvDelta) / dt
		}
		if sent >= c.lastNetSent {
			sentDelta = sent - c.lastNetSent
			up = float64(sentDelta) / dt
		}
	}
	c.lastNetRecv = recv
	c.lastNetSent = sent
	c.lastNetTime = now

	// 累计收发量与时间序列在同一临界区内更新。此前 recvTotal / sentTotal 是在锁外自增的，
	// 而 Info() 在 c.mu.RLock() 下读取它们——构成真实数据竞争（-race 可直接捕获）：
	// 面板「总览」每秒轮询 Info，与 2 秒一次的采样长期并发，读到的累计流量可能是撕裂值，
	// 在 32 位平台上尤甚（uint64 非原子，可能读到高低字来自不同次写入的组合）。
	c.mu.Lock()
	c.recvTotal += recvDelta
	c.sentTotal += sentDelta
	// 读失败时保留上一次的值而不是写 0，理由同 updateProcInfo：
	// 卡片上一个突然变成「0 / 0 MB」的读数，比一个稍微旧一点的读数糟得多。
	if sysMemTotalMB > 0 {
		c.sysMemUsedMB = sysMemUsedMB
		c.sysMemTotalMB = sysMemTotalMB
	}
	// 采样点的内存值与 Info() 出自同一口径（见 effectiveMemLocked）。
	memUsed := c.effectiveMemLocked()
	s := Sample{
		Time:      now.UnixMilli(),
		SysCPU:    round2(sysCPU),
		ProcCPU:   round2(procCPU),
		SysMem:    round2(sysMem),
		DownRate:  round2(down),
		UpRate:    round2(up),
		MemUsedMB: memUsed,
	}
	c.pushLocked(s)
	c.mu.Unlock()
}

// pushLocked 把一个采样点写入环形缓冲。调用方须持有 c.mu。
func (c *Collector) pushLocked(s Sample) {
	c.buf[c.next] = s
	c.next++
	if c.next == c.size {
		c.next = 0
		c.filled = true
	}
}

// count 返回当前有效采样点数量。调用方须持有 c.mu。
func (c *Collector) count() int {
	if c.filled {
		return c.size
	}
	return c.next
}

// at 返回按时间升序排列的第 i 个采样点（0 = 最旧）。调用方须持有 c.mu。
func (c *Collector) at(i int) Sample {
	if c.filled {
		return c.buf[(c.next+i)%c.size]
	}
	return c.buf[i]
}

// snapshotLocked 按时间升序导出全部采样点。调用方须持有 c.mu。
func (c *Collector) snapshotLocked() []Sample {
	n := c.count()
	out := make([]Sample, n)
	if c.filled {
		copy(out, c.buf[c.next:])
		copy(out[c.size-c.next:], c.buf[:c.next])
		return out
	}
	copy(out, c.buf[:n])
	return out
}

// SeriesSince 返回时间戳严格大于 since 的采样点，供面板增量拉取。
//
// full=true 表示返回的是**完整序列**，调用方应整体替换本地副本；出现在三种情形：
// 未提供 since（since ≤ 0）、缓冲区为空、since 早于缓冲区里最旧的点（那段历史已被淘汰，
// 只发增量会让调用方的曲线缺一段）。full=false 时返回的是可直接追加的增量（常见为 1–2 个点）。
//
// 收益：180 点 × 6 序列的全量响应约 18 KB（压缩前更大），而 3 秒一次的增量只有约 200 B。
func (c *Collector) SeriesSince(since int64) ([]Sample, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	n := c.count()
	if n == 0 {
		return []Sample{}, true
	}
	if since <= 0 || since < c.at(0).Time {
		return c.snapshotLocked(), true
	}
	// 采样点时间严格递增，从最新往回数出比 since 更新的点数（通常 0–2 个）。
	k := 0
	for k < n && c.at(n-1-k).Time > since {
		k++
	}
	out := make([]Sample, k)
	for i := 0; i < k; i++ {
		out[i] = c.at(n - k + i)
	}
	return out, false
}

// Latest 返回最近一次采样（若无则返回零值与 false）。
func (c *Collector) Latest() (Sample, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	n := c.count()
	if n == 0 {
		return Sample{}, false
	}
	return c.at(n - 1), true
}

// effectiveMemLocked 是「面板内存占用」那个数的口径决策：在容器里用容器整体用量，
// 否则退回本进程 RSS（见 cgroupmem.go）。采样点（Sample.MemUsedMB）与 Info() 都走
// 这一个函数，卡片数字与曲线上的点因此永远同口径——两处各自写一遍，迟早会写岔。
// 调用方须持有 c.mu（读 memUsedMB / procMemMB / memIsContainer）。
func (c *Collector) effectiveMemLocked() float64 {
	if c.memIsContainer {
		return c.memUsedMB
	}
	return c.procMemMB
}

// Info 返回服务器/进程信息。全部读自内存缓存，故为 O(1)。
func (c *Collector) Info() Info {
	c.mu.RLock()
	recv, sent := c.recvTotal, c.sentTotal
	memMB := c.procMemMB
	usedMB := c.effectiveMemLocked()
	isContainer := c.memIsContainer
	sysUsedMB, sysTotalMB := c.sysMemUsedMB, c.sysMemTotalMB
	c.mu.RUnlock()

	// 口径一并发出去，让卡片能标明这两种情形的区别（见 effectiveMemLocked）。
	scope := MemScopeContainer
	if !isContainer {
		scope = MemScopeProcess
	}
	return Info{
		StartedAt:     c.startedAt.UnixMilli(),
		QueriedAt:     time.Now().UnixMilli(),
		ProcMemMB:     memMB,
		MemUsedMB:     usedMB,
		MemScope:      scope,
		SysMemUsedMB:  sysUsedMB,
		SysMemTotalMB: sysTotalMB,
		SysMemScope:   c.sysMemScope,
		RecvTotal:     recv,
		SentTotal:     sent,
		Version:       c.version,
	}
}

// readNetTotals 读取所有网卡累计收发字节（排除回环）。
func readNetTotals() (recv, sent uint64) {
	counters, err := net.IOCounters(true)
	if err != nil {
		return 0, 0
	}
	for _, ct := range counters {
		if ct.Name == "lo" || len(ct.Name) >= 2 && ct.Name[:2] == "lo" {
			continue
		}
		recv += ct.BytesRecv
		sent += ct.BytesSent
	}
	return recv, sent
}

func round2(v float64) float64 {
	return float64(int64(v*100+0.5)) / 100
}

// sysMemUsage 把「总量 / 可用」换算成面板要的三个数：百分比、已用 MB、总量 MB。
//
// 单拎出来是为了能测那两个边界（总量为 0、可用大于总量）——它们在真机上很难造出来，
// 而无符号相减一旦绕回，卡片上就是一个 16 EB 级别的荒谬数字。
func sysMemUsage(total, available uint64) (pct, usedMB, totalMB float64) {
	if total == 0 {
		return 0, 0, 0
	}
	used := uint64(0)
	if total > available {
		used = total - available
	}
	return round2(float64(used) / float64(total) * 100),
		round2(float64(used) / 1024 / 1024),
		round2(float64(total) / 1024 / 1024)
}
