package wol

import (
	"strings"
	"testing"

	"mantou/internal/config"
)

// dev 一台参数完全合法的设备，供各用例按需改坏其中一项。
func dev(id string) config.WOLDevice {
	return config.WOLDevice{
		ID:        id,
		Enabled:   true,
		Name:      "设备 " + id,
		MAC:       "AA:BB:CC:DD:EE:FF",
		Broadcast: "192.168.1.255",
		Port:      9,
	}
}

// TestValidateTargetRejectsUnusableParams 锁定 W-13b 的判据：
// 「往哪发」这三项写坏时必须报错，而不是留给发送路径去撞。
func TestValidateTargetRejectsUnusableParams(t *testing.T) {
	bad := []struct {
		why   string
		mutFn func(*config.WOLDevice)
	}{
		{"MAC 为空", func(d *config.WOLDevice) { d.MAC = "" }},
		{"MAC 少一段", func(d *config.WOLDevice) { d.MAC = "AA:BB:CC:DD:EE" }},
		{"MAC 含非法字符", func(d *config.WOLDevice) { d.MAC = "AA:BB:CC:DD:EE:ZZ" }},
		{"广播地址是域名", func(d *config.WOLDevice) { d.Broadcast = "wol.example.com" }},
		{"广播地址是公网 IP", func(d *config.WOLDevice) { d.Broadcast = "1.1.1.1" }},
		{"端口为负", func(d *config.WOLDevice) { d.Port = -1 }},
		{"端口越界", func(d *config.WOLDevice) { d.Port = 70000 }},
		{"网卡名超长", func(d *config.WOLDevice) { d.Interface = strings.Repeat("x", MaxIfaceNameLen+1) }},
	}
	for _, c := range bad {
		d := dev("x")
		c.mutFn(&d)
		if err := ValidateTarget(d); err == nil {
			t.Errorf("%s：应报错，却通过了校验", c.why)
		}
	}

	ok := []struct {
		why   string
		mutFn func(*config.WOLDevice)
	}{
		{"标准写法", func(d *config.WOLDevice) {}},
		{"端口留空表示默认 9", func(d *config.WOLDevice) { d.Port = 0 }},
		{"广播留空表示自动逐网卡", func(d *config.WOLDevice) { d.Broadcast = "" }},
		{"全局广播", func(d *config.WOLDevice) { d.Broadcast = "255.255.255.255" }},
		{"指定内网单播地址", func(d *config.WOLDevice) { d.Broadcast = "10.0.0.7" }},
		{"横杠写法的 MAC", func(d *config.WOLDevice) { d.MAC = "aa-bb-cc-dd-ee-ff" }},
		// 网卡此刻不存在也要放行：配置常是从别的机器导入的，或网线正好没插。
		{"不存在的网卡名", func(d *config.WOLDevice) { d.Interface = "eth42" }},
	}
	for _, c := range ok {
		d := dev("x")
		c.mutFn(&d)
		if err := ValidateTarget(d); err != nil {
			t.Errorf("%s：应通过校验，却报了 %v", c.why, err)
		}
	}
}

// TestValidateTargetIgnoresScheduleFields 定时字段不属于本函数的判据。
//
// 这条边界很要紧：本函数的失败后果是「自动禁用设备」，而时间字段写坏只会让调度器
// 当天不发送（一个静默但无害的哑火）。为一个写歪的日期把整台设备关掉，
// 比它本身造成的损失更大。
func TestValidateTargetIgnoresScheduleFields(t *testing.T) {
	d := dev("x")
	d.Schedule = config.WOLSchedule{
		Enabled:         true,
		Mode:            "range",
		Start:           "25:99", // 非法时间
		End:             "!!!",
		IntervalSec:     0, // 非法间隔
		CalendarEnabled: true,
		StartDate:       "not-a-date",
	}
	if err := ValidateTarget(d); err != nil {
		t.Fatalf("定时字段非法不应影响发送参数校验，却报了 %v", err)
	}
}

// TestInvalidDevicesOnlyReportsEnabled 用户主动关掉的设备不参与告警：
// 它本来就不发包，为它每次启动刷一行 Warn 只是噪音。
// 这也是「告警 + 禁用」这套动作幂等的原因——禁用之后就不再被报出来。
func TestInvalidDevicesOnlyReportsEnabled(t *testing.T) {
	bad := dev("bad")
	bad.MAC = "坏的"
	badOff := dev("bad-off")
	badOff.MAC = "坏的"
	badOff.Enabled = false

	got := InvalidDevices([]config.WOLDevice{dev("good"), bad, badOff})
	if len(got) != 1 {
		t.Fatalf("报出 %d 条，应只报 1 条（那台已关闭的不算）：%+v", len(got), got)
	}
	if got[0].ID != "bad" {
		t.Fatalf("报出的是 %q，应为 bad", got[0].ID)
	}
	if got[0].Name != bad.Name || got[0].Reason == "" {
		t.Errorf("告警信息不完整：%+v（名称与原因都要带上，否则日志里认不出是哪台）", got[0])
	}
}

// TestDisableInvalidDevicesDisablesOnlyBadOnes 就地禁用只针对非法项，
// 且必须是幂等的：第二次调用不该再报任何东西。
func TestDisableInvalidDevicesDisablesOnlyBadOnes(t *testing.T) {
	badMAC := dev("bad-mac")
	badMAC.MAC = "not-a-mac"
	badBC := dev("bad-bc")
	badBC.Broadcast = "8.8.8.8"
	badPort := dev("bad-port")
	badPort.Port = 99999

	devices := []config.WOLDevice{dev("good1"), badMAC, badBC, dev("good2"), badPort}
	got := DisableInvalidDevices(devices)
	if len(got) != 3 {
		t.Fatalf("禁用了 %d 台，应为 3 台：%+v", len(got), got)
	}
	want := map[string]bool{"good1": true, "bad-mac": false, "bad-bc": false, "good2": true, "bad-port": false}
	for i := range devices {
		if devices[i].Enabled != want[devices[i].ID] {
			t.Errorf("%s 的开关是 %v，应为 %v", devices[i].ID, devices[i].Enabled, want[devices[i].ID])
		}
	}
	// 幂等：再跑一遍没有新的非法项（都已关闭），也不该把好的那两台连带关掉。
	if again := DisableInvalidDevices(devices); len(again) != 0 {
		t.Fatalf("第二次调用又报了 %d 条，应为 0（不幂等意味着每次启动都刷一遍告警）：%+v", len(again), again)
	}
	if !devices[0].Enabled || !devices[3].Enabled {
		t.Error("合法设备被第二次调用关掉了")
	}
}

// TestDisableInvalidDevicesKeepsEmptyIDDevices 历史条目可能没有 ID（手工编辑而来）。
// 按 ID 匹配时，多台空 ID 的设备会撞在同一个键上，不能因为其中一台非法就把别的也关掉。
func TestDisableInvalidDevicesKeepsEmptyIDDevices(t *testing.T) {
	bad := dev("")
	bad.Name = "无 ID 的坏设备"
	bad.MAC = "坏的"
	good := dev("")
	good.Name = "无 ID 的好设备"

	devices := []config.WOLDevice{bad, good}
	if got := DisableInvalidDevices(devices); len(got) != 1 {
		t.Fatalf("报出 %d 条，应为 1 条", len(got))
	}
	if devices[0].Enabled {
		t.Error("非法的那台没被禁用")
	}
	if !devices[1].Enabled {
		t.Error("合法设备因为共用空 ID 被连带禁用了")
	}
}

// TestDisableInvalidDevicesNoOpOnCleanList 全都合法时不改动任何字段，
// 调用方据此跳过写盘（见 app.SanitizeWOLDevices）。
func TestDisableInvalidDevicesNoOpOnCleanList(t *testing.T) {
	devices := []config.WOLDevice{dev("a"), dev("b")}
	if got := DisableInvalidDevices(devices); got != nil {
		t.Fatalf("干净的清单不该报出任何东西：%+v", got)
	}
	for i := range devices {
		if !devices[i].Enabled {
			t.Fatalf("%s 被误禁用", devices[i].ID)
		}
	}
}
