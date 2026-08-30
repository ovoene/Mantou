package server

import (
	"net/http"
	"testing"

	"github.com/gin-gonic/gin"

	"mantou/internal/config"
)

// TestImportDisablesInvalidWOLDevices 锁定 W-13b 的导入路径：
// 备份里带进来的非法网络唤醒设备，导入后必须是禁用状态。
//
// 导入是接口层校验的一个缺口——整份配置由 Replace 原子替换，不经过 validateWOL。
// 备份可能来自另一台机器、来自旧版本，也可能被手工改过；其中一条广播地址指向公网的设备
// 一旦随导入生效，模块就成了一个每拍一发的任意 UDP 发包器（原因见 wol.ValidBroadcast）。
func TestImportDisablesInvalidWOLDevices(t *testing.T) {
	gin.SetMode(gin.TestMode)
	t.Setenv("MANTOU_MASTER_KEY", "") // 两台「机器」各自生成 master.key

	source, sourceManager, sourceDir := newE2EEnv(t)
	seedFullConfig(t, sourceManager, sourceDir)
	// 直接改源配置：手工编辑 config.json 就是这个效果，不经过任何接口校验。
	if err := sourceManager.Update(func(cfg *config.Config) {
		cfg.WOLDevices = []config.WOLDevice{
			{ID: "ok", Enabled: true, Name: "正常设备", MAC: "AA:BB:CC:DD:EE:FF", Broadcast: "192.168.1.255", Port: 9},
			{ID: "bad-mac", Enabled: true, Name: "MAC 写坏了", MAC: "AA:BB:CC:DD:EE", Broadcast: "192.168.1.255", Port: 9},
			{ID: "bad-bc", Enabled: true, Name: "广播打到公网", MAC: "AA:BB:CC:DD:EE:01", Broadcast: "1.1.1.1", Port: 9},
			{ID: "bad-port", Enabled: true, Name: "端口越界", MAC: "AA:BB:CC:DD:EE:02", Broadcast: "192.168.1.255", Port: 70000},
		}
	}); err != nil {
		t.Fatal(err)
	}

	backup := exportBackup(t, source)

	target, targetManager, _ := newE2EEnv(t)
	// 导入前先有一个本机管理员：导入要再验一次当前管理员的身份（见 handleImportConfig）。
	seedLocalAdmin(t, targetManager)
	if rec := importBackup(t, target, backup); rec.Code != http.StatusOK {
		t.Fatalf("导入失败: %d %s", rec.Code, rec.Body.String())
	}

	devices := targetManager.Snapshot().WOLDevices
	if len(devices) != 4 {
		t.Fatalf("导入后有 %d 台设备，应为 4 台（非法项是禁用，不是丢弃）", len(devices))
	}
	want := map[string]bool{"ok": true, "bad-mac": false, "bad-bc": false, "bad-port": false}
	for i := range devices {
		if devices[i].Enabled != want[devices[i].ID] {
			t.Errorf("%s（%s）导入后开关是 %v，应为 %v",
				devices[i].ID, devices[i].Name, devices[i].Enabled, want[devices[i].ID])
		}
	}
	// 用户填的原值一并保留：改好字段再打开开关即可，不必重新录入。
	for i := range devices {
		if devices[i].ID == "bad-bc" && devices[i].Broadcast != "1.1.1.1" {
			t.Errorf("bad-bc 的广播地址被改写成了 %q，应原样保留", devices[i].Broadcast)
		}
	}
}
