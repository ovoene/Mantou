package wol

import (
	"strings"
	"testing"
	"time"

	"mantou/internal/config"
)

// disabledDevice 一台开关关掉、但定时唤醒开着的设备：不该起调度协程。
func disabledDevice(id string) config.WOLDevice {
	d := parkedDevice(id)
	d.Enabled = false
	return d
}

// noScheduleDevice 一台开关开着、但没开定时唤醒的设备：也不该起调度协程。
func noScheduleDevice(id string) config.WOLDevice {
	d := parkedDevice(id)
	d.Schedule.Enabled = false
	return d
}

// TestStatusActiveCountsScheduledOnly 锁定 W-12：
// Active 必须是「真有调度协程在跑」的设备数，而不是设备总数。
//
// 修复前 Active 恒等于 Total，总览页那一栏永远显示「活跃 5 / 5」——
// 关掉某台设备的开关、或关掉它的定时唤醒，面板上一点变化都没有。
func TestStatusActiveCountsScheduledOnly(t *testing.T) {
	m := New(testLogger(), nil)
	defer m.Close()

	cfg := cfgWith(
		parkedDevice("on1"),         // 计入
		parkedDevice("on2"),         // 计入
		disabledDevice("off"),       // 设备开关关闭
		noScheduleDevice("nosched"), // 未开启定时唤醒
	)
	if err := m.Reload(cfg); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	st := m.Status()
	if st.Total != 4 {
		t.Errorf("Total=%d，应为配置里的设备总数 4", st.Total)
	}
	if st.Active != 2 {
		t.Errorf("Active=%d，应为 2（另两台一台开关关闭、一台未开定时唤醒，都没有调度协程）", st.Active)
	}
	if st.Name != "wol" || !st.Healthy {
		t.Errorf("Status 的 Name/Healthy 不应受影响: %+v", st)
	}
}

// TestStatusActiveAcrossConfigs Active 的口径在各种设备组合下都要对。
func TestStatusActiveAcrossConfigs(t *testing.T) {
	cases := []struct {
		why  string
		devs []config.WOLDevice
		want int
	}{
		{"空配置", nil, 0},
		{"全部启用", []config.WOLDevice{parkedDevice("a"), parkedDevice("b"), parkedDevice("c")}, 3},
		{"全部禁用", []config.WOLDevice{disabledDevice("a"), disabledDevice("b")}, 0},
		{"全部未开定时", []config.WOLDevice{noScheduleDevice("a")}, 0},
		{"混合", []config.WOLDevice{parkedDevice("a"), disabledDevice("b"), noScheduleDevice("c"), parkedDevice("d")}, 2},
	}
	for _, c := range cases {
		m := New(testLogger(), nil)
		if err := m.Reload(cfgWith(c.devs...)); err != nil {
			t.Fatalf("%s: Reload: %v", c.why, err)
		}
		if got := m.Status().Active; got != c.want {
			t.Errorf("%s: Active=%d，应为 %d", c.why, got, c.want)
		}
		if got := m.Status().Total; got != len(c.devs) {
			t.Errorf("%s: Total=%d，应为 %d", c.why, got, len(c.devs))
		}
		m.Close()
	}
}

// TestStatusActiveZeroAfterClose 关闭后一条协程都没有，Active 必须归零。
// 否则「已停止的模块」在总览页上仍显示为活跃。
func TestStatusActiveZeroAfterClose(t *testing.T) {
	m := New(testLogger(), nil)
	if err := m.Reload(cfgWith(parkedDevice("a"), parkedDevice("b"))); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	if got := m.Status().Active; got != 2 {
		t.Fatalf("关闭前 Active=%d，应为 2", got)
	}
	if err := m.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	st := m.Status()
	if st.Active != 0 {
		t.Errorf("关闭后 Active=%d，应为 0（Close 返回后保证没有调度协程在跑）", st.Active)
	}
	// 设备清单仍如实反映配置：Total 不因关闭而清零。
	if st.Total != 2 {
		t.Errorf("关闭后 Total=%d，应仍为 2", st.Total)
	}
	// 关闭后的 Reload 只更新清单、不起协程（见 Reload），Active 仍须为 0。
	if err := m.Reload(cfgWith(parkedDevice("a"), parkedDevice("b"), parkedDevice("c"))); err != nil {
		t.Fatalf("关闭后 Reload: %v", err)
	}
	st = m.Status()
	if st.Active != 0 {
		t.Errorf("关闭后再 Reload，Active=%d，应仍为 0", st.Active)
	}
	if st.Total != 3 {
		t.Errorf("关闭后再 Reload，Total=%d，应为 3（清单照常更新）", st.Total)
	}
}

// TestStatusActiveMatchesFiringDevices 与真实发包行为对账：
// Active 报几台，就应当**恰好**有这几台设备真的在发包（回写了唤醒记录）。
//
// 这条比字段断言更强：它不看实现里的判断条件，只看外部可观测的结果，
// 因此「Active 的判据」与「Reload 起协程的判据」若哪天走岔了，这里会立刻发现。
func TestStatusActiveMatchesFiringDevices(t *testing.T) {
	off := tickingDevice("off")
	off.Enabled = false
	nosched := tickingDevice("nosched")
	nosched.Schedule.Enabled = false

	cfg := cfgWith(tickingDevice("on1"), tickingDevice("on2"), off, nosched)
	w := newSpyStats(0)
	m := New(testLogger(), w)
	if err := m.Reload(cfg); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	active := m.Status().Active

	if !waitFirstTick(w, 5*time.Second) {
		m.Close()
		t.Skip("等不到第一拍，本机可能无法向回环发 UDP")
	}
	// 两台启用的设备各自 1 秒一拍，再多等一拍确保两条协程都发过。
	time.Sleep(1300 * time.Millisecond)
	// 先关闭：Close 返回后保证没有协程在写 cfg，之后读它才是安全的。
	if err := m.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	var fired []string
	for i := range cfg.WOLDevices {
		// 判据从「配置里的 LastWakeAt」换成了内存统计里的 LastAt：字段搬家了，
		// 性质没变——「这台设备这一段时间里真的发过包」。
		if w.Wake(cfg.WOLDevices[i].ID).LastAt != 0 {
			fired = append(fired, cfg.WOLDevices[i].ID)
		}
	}
	if len(fired) != active {
		t.Fatalf("Active 报了 %d 台，实际发包的是 %v（%d 台）", active, fired, len(fired))
	}
	if got := strings.Join(fired, ","); got != "on1,on2" {
		t.Fatalf("实际发包的设备是 [%s]，应为 [on1,on2]", got)
	}
}
