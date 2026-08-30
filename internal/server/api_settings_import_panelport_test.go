package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"

	"mantou/internal/config"
)

// 导入配置是面板端口的第二条入口，后果与保存设置那条一样重：备份来自另一台机器，
// 那台上空着的端口在这台上未必空着，绑不上就是整个进程退出（见 panelport.go）。
//
// 与保存设置不同的是处置方式：这里不回 400。用户手上只有一份加密备份，改不动里面的端口，
// 报错等于让他彻底导不进来。所以保留本机当前端口、其余照常导入，并写一条日志说明。

// importRestartRequired 取导入响应里的 restartRequired。
func importRestartRequired(t *testing.T, rec *httptest.ResponseRecorder) bool {
	t.Helper()
	var resp struct {
		Data struct {
			RestartRequired bool `json:"restartRequired"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("解析导入响应失败: %v（%s）", err, rec.Body.String())
	}
	return resp.Data.RestartRequired
}

// exportWithPanelPort 造一份"面板端口是 port"的加密备份。
func exportWithPanelPort(t *testing.T, port int) []byte {
	t.Helper()
	source, sourceManager, sourceDir := newE2EEnv(t)
	seedFullConfig(t, sourceManager, sourceDir)
	if err := sourceManager.Update(func(cfg *config.Config) { cfg.Panel.Port = port }); err != nil {
		t.Fatal(err)
	}
	return exportBackup(t, source)
}

// TestImportKeepsLocalPanelPortWhenBackupPortIsBusy 备份里的端口在本机绑不上时：
// 其余部分照常导入，端口保留本机现值，且面板不会因此重启。
func TestImportKeepsLocalPanelPortWhenBackupPortIsBusy(t *testing.T) {
	gin.SetMode(gin.TestMode)
	t.Setenv("MANTOU_MASTER_KEY", "")

	busy := busyPort(t)
	backup := exportWithPanelPort(t, busy)

	target, targetManager, _ := newE2EEnv(t)
	target.deps.RestartPanel = func() {}
	seedLocalConfig(t, targetManager)
	localPort := targetManager.Snapshot().Panel.Port
	if localPort == busy {
		t.Fatalf("测试前提不成立：本机端口正好等于备份里的端口 %d", busy)
	}

	rec := importBackup(t, target, backup)

	if rec.Code != http.StatusOK {
		t.Fatalf("导入失败: %d %s", rec.Code, rec.Body.String())
	}
	cfg := targetManager.Snapshot()
	// 前提：这次导入确实生效了。否则"端口没变"可能只是因为整份导入失败。
	if len(cfg.Forwards) != 1 || cfg.Forwards[0].ID != "fwd-e2e" {
		t.Fatalf("测试前提不成立：备份没被导入，端口转发是 %+v", cfg.Forwards)
	}
	if cfg.Panel.Port == busy {
		t.Fatalf("绑不上的端口 %d 被导入了，重启后面板起不来会带走整个进程", busy)
	}
	if cfg.Panel.Port != localPort {
		t.Fatalf("面板端口成了 %d，期望保留本机现值 %d", cfg.Panel.Port, localPort)
	}
	// 端口既然没变，就没有任何理由重启面板。
	if importRestartRequired(t, rec) {
		t.Error("端口被保留了却仍要求重启面板")
	}
}

// TestImportAppliesFreePanelPortFromBackup 反向钉住：端口能绑上时照常导入，
// 新增的兜底不能变成"面板端口永远不跟备份走"。
func TestImportAppliesFreePanelPortFromBackup(t *testing.T) {
	gin.SetMode(gin.TestMode)
	t.Setenv("MANTOU_MASTER_KEY", "")

	free := freePort(t)
	backup := exportWithPanelPort(t, free)

	target, targetManager, _ := newE2EEnv(t)
	target.deps.RestartPanel = func() {}
	seedLocalConfig(t, targetManager)
	if targetManager.Snapshot().Panel.Port == free {
		t.Fatalf("测试前提不成立：本机端口正好等于备份里的端口 %d", free)
	}

	rec := importBackup(t, target, backup)

	if rec.Code != http.StatusOK {
		t.Fatalf("导入失败: %d %s", rec.Code, rec.Body.String())
	}
	if got := targetManager.Snapshot().Panel.Port; got != free {
		t.Fatalf("面板端口是 %d，期望跟备份走用 %d", got, free)
	}
	if !importRestartRequired(t, rec) {
		t.Error("端口变了却没要求重启，前端不会提示用户")
	}
}
