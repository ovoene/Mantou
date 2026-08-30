package wol

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"mantou/internal/config"
	"mantou/internal/logx"
	"mantou/internal/runstats"
)

// testLogger 只写内存环、不写控制台，避免测试输出被日志淹没。
func testLogger() *logx.Logger {
	return logx.New(logx.Options{Console: false, MaxEntries: logx.MinLogEntries})
}

// spyStats 包着真的统计库，额外做两件只有测试需要的事：数回写次数、把回写刻意变慢。
//
// 用装饰器而不是重写一份假的：统计的规则（状态文本截断、空 ID 忽略、满表淘汰）全在
// runstats 里，替身照抄就会漏一条，而本包的用例只关心「这一拍回写了几次、写进去的是什么」。
// delay 非零时每次回写都刻意变慢，用来模拟真实环境里让一拍超时的那些原因
// （网卡枚举耗时、系统调用被抢占、主机休眠恢复）。
type spyStats struct {
	*runstats.Store
	n     atomic.Int64
	delay time.Duration
}

func newSpyStats(delay time.Duration) *spyStats {
	return &spyStats{Store: runstats.New(), delay: delay}
}

// Woke 遮蔽内嵌 Store 的同名方法：先记账、再按需变慢，最后照常交给真库。
func (s *spyStats) Woke(id string, at int64, result string) {
	s.n.Add(1)
	if s.delay > 0 {
		time.Sleep(s.delay)
	}
	s.Store.Woke(id, at, result)
}

// parkedDevice 一台会让调度协程立刻停在「睡到次日」的设备：
// 时间字段非法 → planForDay 返回 ok=false → 当天不安排发送。
// 这样既真实占用 m.wg（能触发 WaitGroup 复用问题），又不会在测试里真的发包。
func parkedDevice(id string) config.WOLDevice {
	return config.WOLDevice{
		ID:      id,
		Enabled: true,
		Name:    id,
		MAC:     "AA:BB:CC:DD:EE:FF",
		Schedule: config.WOLSchedule{
			Enabled: true,
			Mode:    "fixed",
			Time:    "25:00", // 非法：当天不触发
		},
	}
}

func cfgWith(devs ...config.WOLDevice) *config.Config {
	return &config.Config{WOLDevices: devs}
}

// TestReloadCloseConcurrent 锁定 W-1：Reload 与 Close 必须互斥。
//
// 修复前本测试在第 0 轮即失败（Close 返回后仍存在未取消的调度代），
// 压到数千轮还会复现运行时硬 panic「sync: WaitGroup is reused before previous Wait has returned」。
// 两个断言分别对应那两种故障，缺一不可。
func TestReloadCloseConcurrent(t *testing.T) {
	const rounds = 2000
	cfg := cfgWith(parkedDevice("d1"))

	for round := 0; round < rounds; round++ {
		m := New(testLogger(), nil)

		// 用一把锁把多次 Reload 串起来，复现生产形态：module.Manager.ReloadAll 由 reloadMu
		// 保证「重载之间」互斥，但它与 CloseAll 之间没有任何约束。
		var reloadMu sync.Mutex
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			for i := 0; i < 3; i++ {
				reloadMu.Lock()
				_ = m.Reload(cfg)
				reloadMu.Unlock()
			}
		}()
		go func() {
			defer wg.Done()
			_ = m.Close()
		}()
		wg.Wait()

		// 断言一：Close 返回、且所有 Reload 也已结束之后，不允许存在活着的调度代。
		// 留着 cancel 就意味着有一代协程无人可停——关闭后仍在发包、仍在写运行态。
		m.mu.RLock()
		leaked := m.cancel != nil
		m.mu.RUnlock()
		if leaked {
			t.Fatalf("第 %d 轮：Close() 已返回，但仍存在未取消的调度代 —— 关闭后协程会继续发包", round)
		}

		// 断言二：Close 之后再 Reload 不得起新代（幂等且终态）。
		if err := m.Reload(cfg); err != nil {
			t.Fatalf("第 %d 轮：Close 之后 Reload 报错: %v", round, err)
		}
		m.mu.RLock()
		revived := m.cancel != nil
		devices := len(m.devices)
		m.mu.RUnlock()
		if revived {
			t.Fatalf("第 %d 轮：Close 之后的 Reload 又起了新的调度代", round)
		}
		// 设备清单仍应更新：Status() 要如实反映配置，只是不再调度。
		if devices != 1 {
			t.Fatalf("第 %d 轮：Close 之后 Reload 应仍更新设备清单，实际 %d 台", round, devices)
		}

		// Close 可重复调用。
		if err := m.Close(); err != nil {
			t.Fatalf("第 %d 轮：重复 Close 报错: %v", round, err)
		}
	}
}

// TestCloseStopsScheduling 锁定「Close 返回后不再有协程在跑」这一契约。
// 用真实的 Reload 起一代协程，Close 之后观察回写统计的次数不再增长。
func TestCloseStopsScheduling(t *testing.T) {
	w := newSpyStats(0)
	m := New(testLogger(), w)

	if err := m.Reload(cfgWith(parkedDevice("d1"), parkedDevice("d2"))); err != nil {
		t.Fatal(err)
	}
	if err := m.Close(); err != nil {
		t.Fatal(err)
	}
	before := w.n.Load()
	time.Sleep(50 * time.Millisecond)
	if after := w.n.Load(); after != before {
		t.Fatalf("Close 之后仍在回写运行态：%d → %d", before, after)
	}
}

// TestRunPlanDayStopsOnCancel 验证节拍循环在 ctx 取消后立即停止，不再发包。
func TestRunPlanDayStopsOnCancel(t *testing.T) {
	w := newSpyStats(0)
	m := New(testLogger(), w)
	now := time.Now()
	p := wakePlan{start: now, end: now.Add(10 * time.Second), interval: 20 * time.Millisecond, burst: 1}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan bool, 1)
	go func() { done <- m.runPlanDay(ctx, config.WOLDevice{ID: "d1", Broadcast: "127.0.0.1"}, p) }()

	time.Sleep(60 * time.Millisecond)
	cancel()
	select {
	case ok := <-done:
		if ok {
			t.Fatal("ctx 取消后 runPlanDay 应返回 false（调度结束）")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("ctx 取消后 runPlanDay 未在 2 秒内返回")
	}

	before := w.n.Load()
	time.Sleep(80 * time.Millisecond)
	if after := w.n.Load(); after != before {
		t.Fatalf("ctx 取消后仍在发包：%d → %d", before, after)
	}
}

// TestRunPlanDayNoFireAfterCancelOnOverrun 取消之后不得再发包，即使上一拍超时。
//
// 节拍循环原先只在 wait > 0 时检查 ctx。当上一拍的耗时超过一个间隔、但不足两个间隔时，
// 下一拍算出的 wait 落在 [-interval, 0]，被判为「正常抖动」而立即触发——
// 唯一的 ctx 检查点被整个绕过。于是取消之后仍会多发一个包（违反 Close 的契约），
// 且 Reload/Close 里的 m.wg.Wait() 要等两拍才能返回。
// 这里 interval 100 毫秒、每拍耗时 150 毫秒，正落在那个区间里。
func TestRunPlanDayNoFireAfterCancelOnOverrun(t *testing.T) {
	const (
		interval = 100 * time.Millisecond
		tickCost = 150 * time.Millisecond
	)
	w := newSpyStats(tickCost)
	m := New(testLogger(), w)

	now := time.Now()
	p := wakePlan{start: now, end: now.Add(10 * time.Second), interval: interval, burst: 1}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan bool, 1)
	go func() { done <- m.runPlanDay(ctx, config.WOLDevice{ID: "d1", Broadcast: "127.0.0.1"}, p) }()

	// 等到协程正卡在某一拍的回写里（spyStats 先计数再 Sleep），此刻取消。
	deadline := time.Now().Add(2 * time.Second)
	for w.n.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if w.n.Load() == 0 {
		t.Fatal("2 秒内没等到第一拍")
	}
	fired := w.n.Load()
	cancel()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("取消后 runPlanDay 未在 2 秒内返回")
	}
	if after := w.n.Load(); after != fired {
		t.Fatalf("取消之后又发了 %d 拍：Close 的契约是「返回后不再发包」", after-fired)
	}
}

// TestRunPlanDaySkipsLaggedTicks 锁定 W-2：落后的节拍必须丢弃，不得追赶补发。
//
// 场景：名义安排是「跨度 1 秒、每 10 毫秒一拍」= 101 拍，但每拍的回写被人为拖慢到 50 毫秒，
// 也就是每一拍都必然超时。修复前节拍时刻只做纯算术推进，超时后 time.Until(at) 恒为负、
// 每拍立即触发，于是 101 拍一个不落地打完、墙钟耗时 5.2 秒（实测）——名义上 1 秒的窗口
// 变成 5 秒的持续广播风暴。修复后应重新对齐到当前时间，拍数远少于 101，
// 且总耗时贴近名义跨度。
func TestRunPlanDaySkipsLaggedTicks(t *testing.T) {
	const (
		nominalTicks = 101 // 1 秒 / 10 毫秒 + 1
		perTick      = 50 * time.Millisecond
	)
	w := newSpyStats(perTick)
	m := New(testLogger(), w)

	start := time.Now()
	p := wakePlan{start: start, end: start.Add(time.Second), interval: 10 * time.Millisecond, burst: 1}
	// 目标用回环地址：sendPacket 会真的发一个包，但不触发网卡枚举，耗时可忽略，
	// 保证被测的慢因素只有注入的那 50 毫秒。
	if !m.runPlanDay(context.Background(), config.WOLDevice{ID: "d1", Broadcast: "127.0.0.1"}, p) {
		t.Fatal("未取消 ctx，runPlanDay 应返回 true")
	}
	elapsed := time.Since(start)
	ticks := w.n.Load()

	// 上界取名义拍数的三成：理论值约为 1 秒 / 50 毫秒 = 20 拍，留足调度抖动余量，
	// 同时与「追赶」的 101 拍有量级差别，不会误判。
	if ticks >= nominalTicks*3/10 {
		t.Fatalf("落后的节拍未被丢弃：实际发包 %d 拍（名义 %d 拍，期望 < %d 拍）",
			ticks, nominalTicks, nominalTicks*3/10)
	}
	// 墙钟必须贴近名义跨度：追赶的本质就是把 1 秒的窗口拉长成 5 秒。
	if elapsed > 1500*time.Millisecond {
		t.Fatalf("发包窗口被追赶拉长：名义跨度 1 秒，实际耗时 %v", elapsed)
	}
	t.Logf("名义 %d 拍 → 实际 %d 拍，耗时 %v", nominalTicks, ticks, elapsed)
}

// TestRunPlanDayFiresSmallJitter 落后不足一整拍属于正常抖动，仍应照常触发，
// 不能被跳过逻辑连带吞掉——否则间隔 1 秒的安排会因为每拍几毫秒的开销而漏发一半。
func TestRunPlanDayFiresSmallJitter(t *testing.T) {
	// 拍间隔取 100 毫秒、单拍耗时 60 毫秒：过了半拍但远不到一整拍，这一轮不该丢任何一拍。
	// 间隔不能取得更小——本机时钟粒度约 15 毫秒，20 毫秒一拍只剩几毫秒余量，
	// 一次调度打嗝就把某一拍推过整拍，测试于是偶发地失败在一个并不存在的缺陷上。
	const interval = 100 * time.Millisecond
	w := newSpyStats(60 * time.Millisecond)
	m := New(testLogger(), w)

	// 起点故意退后几毫秒：首拍必定是「刚刚过去」的那一拍，正对着要钉的宽容度。
	// 原先靠的是「取 start 到进循环之间恰好走过一点点」，那点时间差有多大取决于时钟粒度。
	start := time.Now().Add(-5 * time.Millisecond)
	p := wakePlan{start: start, end: start.Add(5 * interval), interval: interval, burst: 1}
	if !m.runPlanDay(context.Background(), config.WOLDevice{ID: "d1", Broadcast: "127.0.0.1"}, p) {
		t.Fatal("未取消 ctx，runPlanDay 应返回 true")
	}
	// 名义 6 拍：start 那一拍，加上后面 5 拍。首拍能算进来靠的是 runPlanDay 给首拍留的一整拍宽容度。
	if ticks := w.n.Load(); ticks != 6 {
		t.Fatalf("小幅抖动被误判为落后：名义 6 拍，实际 %d 拍", ticks)
	}
}
