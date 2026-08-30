package app

import (
	"path/filepath"
	"testing"

	"mantou/internal/config"
	"mantou/internal/logx"
)

// wolDev 一台参数合法、开关打开的设备。
func wolDev(id string) config.WOLDevice {
	return config.WOLDevice{
		ID:        id,
		Enabled:   true,
		Name:      "设备 " + id,
		MAC:       "AA:BB:CC:DD:EE:FF",
		Broadcast: "192.168.1.255",
		Port:      9,
	}
}

func newTestManager(t *testing.T) (*config.Manager, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.json")
	m := config.NewManager(path)
	if err := m.Load(); err != nil {
		t.Fatal(err)
	}
	return m, path
}

// TestSanitizeWOLDevicesDisablesInvalidAndPersists 锁定 W-13b：
// 手工编辑 config.json（或导入备份）塞进来的非法设备，必须在模块启动前被禁用并落盘。
//
// 修复前 config.migrateWOL 只夹「一秒内发包次数」，不做任何合法性校验，
// 于是一条 MAC 写错、或广播地址填成公网 IP 的设备会被照常加载并起调度协程——
// 后者相当于一个每拍一发的任意 UDP 发包器（原因见 wol.ValidBroadcast）。
func TestSanitizeWOLDevicesDisablesInvalidAndPersists(t *testing.T) {
	mgr, path := newTestManager(t)
	log := logx.New(logx.Options{})

	badMAC := wolDev("bad-mac")
	badMAC.MAC = "这不是 MAC"
	badBC := wolDev("bad-broadcast")
	badBC.Broadcast = "1.1.1.1" // 公网地址
	badPort := wolDev("bad-port")
	badPort.Port = 70000
	if err := mgr.Update(func(c *config.Config) {
		c.WOLDevices = []config.WOLDevice{wolDev("good"), badMAC, badBC, badPort}
	}); err != nil {
		t.Fatal(err)
	}

	SanitizeWOLDevices(mgr, log)

	want := map[string]bool{"good": true, "bad-mac": false, "bad-broadcast": false, "bad-port": false}
	check := func(stage string, devices []config.WOLDevice) {
		if len(devices) != len(want) {
			t.Fatalf("%s：设备数变成 %d，应仍为 %d（禁用不是删除）", stage, len(devices), len(want))
		}
		for i := range devices {
			if devices[i].Enabled != want[devices[i].ID] {
				t.Errorf("%s：%s 的开关是 %v，应为 %v", stage, devices[i].ID, devices[i].Enabled, want[devices[i].ID])
			}
		}
	}
	check("内存", mgr.Snapshot().WOLDevices)

	// 必须真的落盘：否则下次启动又原样带病跑起来。
	reloaded := config.NewManager(path)
	if err := reloaded.Load(); err != nil {
		t.Fatal(err)
	}
	check("重新加载", reloaded.Snapshot().WOLDevices)
}

// TestSanitizeWOLDevicesKeepsCleanConfigUntouched 全部合法时一个字节都不该写。
//
// 否则每次启动都要整份重写一遍 config.json（外加 fsync），
// 且日志里天天多两行与用户无关的记录。
func TestSanitizeWOLDevicesKeepsCleanConfigUntouched(t *testing.T) {
	mgr, _ := newTestManager(t)
	if err := mgr.Update(func(c *config.Config) {
		c.WOLDevices = []config.WOLDevice{wolDev("a"), wolDev("b")}
	}); err != nil {
		t.Fatal(err)
	}
	before := mgr.Snapshot()

	SanitizeWOLDevices(mgr, logx.New(logx.Options{}))

	// Manager 只在内容确有变化时才换出内存配置（见 config.Manager.Update 的脏检查），
	// 因此快照仍是同一份对象即证明没有发生写入。
	if after := mgr.Snapshot(); after != before {
		t.Fatal("干净的配置被重写了一遍")
	}
}

// TestSanitizeWOLDevicesIdempotent 连跑两遍与跑一遍等价：
// 第二遍不该再写盘（非法项此时已是禁用状态，不再进入判据）。
func TestSanitizeWOLDevicesIdempotent(t *testing.T) {
	mgr, _ := newTestManager(t)
	log := logx.New(logx.Options{})
	bad := wolDev("bad")
	bad.MAC = "坏的"
	if err := mgr.Update(func(c *config.Config) {
		c.WOLDevices = []config.WOLDevice{wolDev("good"), bad}
	}); err != nil {
		t.Fatal(err)
	}

	SanitizeWOLDevices(mgr, log)
	afterFirst := mgr.Snapshot()
	SanitizeWOLDevices(mgr, log)
	if afterSecond := mgr.Snapshot(); afterSecond != afterFirst {
		t.Fatal("第二次调用又写了一次配置：每次启动都会白写一遍")
	}
	devices := afterFirst.WOLDevices
	if len(devices) != 2 {
		t.Fatalf("设备数变成 %d，应仍为 2", len(devices))
	}
	for i := range devices {
		want := devices[i].ID == "good"
		if devices[i].Enabled != want {
			t.Errorf("%s 的开关是 %v，应为 %v", devices[i].ID, devices[i].Enabled, want)
		}
	}
}

// TestSanitizeWOLDevicesLeavesDisabledInvalidAlone 已经关掉的非法设备不必再动，
// 也不该因此触发一次写盘。
func TestSanitizeWOLDevicesLeavesDisabledInvalidAlone(t *testing.T) {
	mgr, _ := newTestManager(t)
	bad := wolDev("bad")
	bad.MAC = "坏的"
	bad.Enabled = false
	if err := mgr.Update(func(c *config.Config) {
		c.WOLDevices = []config.WOLDevice{bad}
	}); err != nil {
		t.Fatal(err)
	}
	before := mgr.Snapshot()

	SanitizeWOLDevices(mgr, logx.New(logx.Options{}))

	if after := mgr.Snapshot(); after != before {
		t.Fatal("只有已禁用的非法设备时仍写了一次配置")
	}
	// 字段原样保留：用户填的坏 MAC 还在那儿，等他自己改。
	if got := mgr.Snapshot().WOLDevices[0].MAC; got != "坏的" {
		t.Fatalf("MAC 被改写成了 %q，应原样保留用户的输入", got)
	}
}
