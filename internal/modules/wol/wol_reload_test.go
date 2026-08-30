package wol

import (
	"testing"
	"time"

	"mantou/internal/config"
)

// tickingDevice 一台每秒发一拍的设备。目标用回环地址：sendPacket 会真的发包，
// 但不触发网卡枚举，耗时可忽略。
func tickingDevice(id string) config.WOLDevice {
	return config.WOLDevice{
		ID:        id,
		Enabled:   true,
		Name:      id,
		MAC:       "AA:BB:CC:DD:EE:FF",
		Broadcast: "127.0.0.1",
		Port:      9,
		Schedule: config.WOLSchedule{
			Enabled:     true,
			Mode:        "range",
			Start:       "00:00",
			End:         "23:59",
			IntervalSec: 1,
		},
	}
}

// waitFirstTick 等到调度协程真的进入了一拍（回写被调用），返回是否等到。
// 调用返回的瞬间协程正卡在回写里（spyStats 先计数再 Sleep），
// 这正是「Reload 撞上一拍」的时刻。
func waitFirstTick(w *spyStats, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if w.n.Load() > 0 {
			return true
		}
		time.Sleep(2 * time.Millisecond)
	}
	return false
}

// TestReloadKeepsGenerationWhenSchedulingUnchanged 锁定 W-7：
// 调度相关字段未变时，Reload 不得取消重建调度代。
//
// 观察方式是耗时：Reload 全程持 lifeMu 并 m.wg.Wait()，而 fireScheduled 里的
// 发包与统计回写都不可取消——重建就必须等当前这一拍走完。
// 这里把一拍的回写拖慢到 1.5 秒，然后在协程正卡在这一拍里时发起 Reload：
// 修复前它会阻塞约 1.5 秒（并连带推迟 ReloadAll 里其后所有模块的重载），修复后立即返回。
//
// 第二份配置刻意只改一个不参与调度的字段（备注），复现真实形态：
// ReloadAll 拿到的是一份「用户只顺手改了句备注」的当前配置。
// 若签名把这类字段也计入，这个优化对正在定时唤醒的设备就形同没有。
func TestReloadKeepsGenerationWhenSchedulingUnchanged(t *testing.T) {
	const tickCost = 1500 * time.Millisecond
	w := newSpyStats(tickCost)
	m := New(testLogger(), w)
	t.Cleanup(func() { _ = m.Close() })

	if err := m.Reload(cfgWith(tickingDevice("d1"))); err != nil {
		t.Fatal(err)
	}
	if !waitFirstTick(w, 3*time.Second) {
		t.Skip("2 秒内没等到第一拍（本机时钟或回环发包异常），无法验证")
	}

	// 同一台设备，只有不参与调度的字段不同。
	touched := tickingDevice("d1")
	touched.Note = "书房的台式机"

	start := time.Now()
	if err := m.Reload(cfgWith(touched)); err != nil {
		t.Fatal(err)
	}
	elapsed := time.Since(start)
	if elapsed > 300*time.Millisecond {
		t.Fatalf("调度字段未变却重建了调度代：Reload 等了 %v（一拍耗时 %v）"+
			"——无关配置保存会打断正在进行的一拍，并推迟其后所有模块的重载", elapsed, tickCost)
	}

	// 保留的必须是「活着的」那一代：回写要继续增长，而不是被悄悄跳过之后停摆。
	before := w.n.Load()
	deadline := time.Now().Add(2*time.Second + tickCost)
	for time.Now().Before(deadline) {
		if w.n.Load() > before {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("Reload 之后调度停摆：回写计数停在 %d", before)
}

// TestReloadRebuildsWhenScheduleChanges 反向断言：调度字段确实变了就必须重建。
// 否则上一条测试用「永远跳过」也能通过，而那意味着用户改了唤醒计划却不生效。
func TestReloadRebuildsWhenScheduleChanges(t *testing.T) {
	const tickCost = 1500 * time.Millisecond
	w := newSpyStats(tickCost)
	m := New(testLogger(), w)
	t.Cleanup(func() { _ = m.Close() })

	if err := m.Reload(cfgWith(tickingDevice("d1"))); err != nil {
		t.Fatal(err)
	}
	if !waitFirstTick(w, 3*time.Second) {
		t.Skip("2 秒内没等到第一拍（本机时钟或回环发包异常），无法验证")
	}

	changed := tickingDevice("d1")
	changed.Schedule.IntervalSec = 300 // 用户把间隔从 1 秒改成 5 分钟

	start := time.Now()
	if err := m.Reload(cfgWith(changed)); err != nil {
		t.Fatal(err)
	}
	elapsed := time.Since(start)
	// 重建必然要等当前这一拍走完（不可取消），因此耗时应接近一拍的代价。
	if elapsed < tickCost/3 {
		t.Fatalf("间隔从 1 秒改成 300 秒，Reload 只用了 %v —— 旧调度代没被换掉，新计划不生效", elapsed)
	}
}

// TestSchedulingSigIgnoresNote 备注不得进入签名：它不影响任何一拍怎么发，
// 却是用户最常顺手改的字段，计入签名就等于「改句备注也要打断正在进行的一拍」。
//
// 这条用例原先叫 TestSchedulingSigIgnoresRuntimeStateAndNote，还一并钉住「每拍回写的运行态
// 不得进入签名」。那半边现在是结构性的：设备结构体上已经没有运行态字段了（唤醒记录搬进了
// 内存，见 internal/runstats），签名想计入也无从计入。留下备注这半边——它仍是一个真实的选择。
func TestSchedulingSigIgnoresNote(t *testing.T) {
	base := tickingDevice("d1")
	other := base
	other.Note = "书房的台式机"

	if schedulingSig([]config.WOLDevice{base}) != schedulingSig([]config.WOLDevice{other}) {
		t.Fatal("备注被计入了签名：改一句备注就会打断正在进行的一拍")
	}
}

// TestSchedulingSigDetectsEveryField 调度协程实际读取的每个字段都必须被签名覆盖。
// 漏掉任何一个，用户改了它就不生效——这个方向的错误比多重建一次严重得多。
func TestSchedulingSigDetectsEveryField(t *testing.T) {
	cases := []struct {
		field string
		mut   func(*config.WOLDevice)
	}{
		{"ID", func(d *config.WOLDevice) { d.ID = "other" }},
		{"Name", func(d *config.WOLDevice) { d.Name = "改了名字（日志标签）" }},
		{"MAC", func(d *config.WOLDevice) { d.MAC = "11:22:33:44:55:66" }},
		{"Broadcast", func(d *config.WOLDevice) { d.Broadcast = "192.168.1.255" }},
		{"Port", func(d *config.WOLDevice) { d.Port = 7 }},
		{"Enabled", func(d *config.WOLDevice) { d.Enabled = false }},
		{"Schedule.Enabled", func(d *config.WOLDevice) { d.Schedule.Enabled = false }},
		{"Schedule.CalendarEnabled", func(d *config.WOLDevice) { d.Schedule.CalendarEnabled = true }},
		{"Schedule.Mode", func(d *config.WOLDevice) { d.Schedule.Mode = "fixed" }},
		{"Schedule.StartDate", func(d *config.WOLDevice) { d.Schedule.StartDate = "2026-01-01" }},
		{"Schedule.EndDate", func(d *config.WOLDevice) { d.Schedule.EndDate = "2026-12-31" }},
		{"Schedule.Time", func(d *config.WOLDevice) { d.Schedule.Time = "08:00" }},
		{"Schedule.Start", func(d *config.WOLDevice) { d.Schedule.Start = "07:30" }},
		{"Schedule.End", func(d *config.WOLDevice) { d.Schedule.End = "22:00" }},
		{"Schedule.Count", func(d *config.WOLDevice) { d.Schedule.Count = 3 }},
		{"Schedule.IntervalSec", func(d *config.WOLDevice) { d.Schedule.IntervalSec = 60 }},
	}
	base := schedulingSig([]config.WOLDevice{tickingDevice("d1")})
	for _, c := range cases {
		d := tickingDevice("d1")
		c.mut(&d)
		if schedulingSig([]config.WOLDevice{d}) == base {
			t.Errorf("%s 未被签名覆盖：改了它调度也不会重建，用户的修改不生效", c.field)
		}
	}
}

// TestSchedulingSigDetectsListShape 增删设备必须被察觉。
func TestSchedulingSigDetectsListShape(t *testing.T) {
	one := []config.WOLDevice{tickingDevice("d1")}
	two := []config.WOLDevice{tickingDevice("d1"), tickingDevice("d2")}
	if schedulingSig(one) == schedulingSig(two) {
		t.Fatal("新增设备未被察觉：新设备的调度协程不会被启动")
	}
	if schedulingSig(nil) == schedulingSig(one) {
		t.Fatal("从空清单变为一台设备未被察觉")
	}
	// 纯重排会被判为变化（只是多重建一次，不会错），这里锁定这一口径。
	rev := []config.WOLDevice{tickingDevice("d2"), tickingDevice("d1")}
	if schedulingSig(two) == schedulingSig(rev) {
		t.Fatal("签名对顺序不敏感？当前实现是顺序敏感的，口径变了要同步改注释")
	}
}

// TestSchedulingSigNoSeparatorCollision 字段内容由用户填写，
// 签名必须对内容单射：否则精心构造（或纯属巧合）的名字能让某些改动被判为「未变」而不生效。
func TestSchedulingSigNoSeparatorCollision(t *testing.T) {
	a := tickingDevice("d1")
	a.Name = "abc"
	a.MAC = "AA:BB:CC:DD:EE:FF"

	b := tickingDevice("d1")
	b.Name = "abcAA:BB:CC:DD:EE:FF" // 把下一个字段的内容并进本字段
	b.MAC = ""

	if schedulingSig([]config.WOLDevice{a}) == schedulingSig([]config.WOLDevice{b}) {
		t.Fatal("字段拼接可被内容穿越：签名需带长度前缀")
	}

	// 各种可能被当成分隔符的字符都不该造成歧义。
	for _, sep := range []string{":", "|", "\x00", "\n", ";"} {
		x := tickingDevice("d1")
		x.Name = "a" + sep + "b"
		x.Note = ""
		y := tickingDevice("d1")
		y.Name = "a"
		y.MAC = sep + "b" + y.MAC
		if schedulingSig([]config.WOLDevice{x}) == schedulingSig([]config.WOLDevice{y}) {
			t.Fatalf("分隔符 %q 可被内容伪造", sep)
		}
	}
}
