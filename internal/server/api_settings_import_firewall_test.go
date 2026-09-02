package server

import (
	"bytes"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"

	"mantou/internal/config"
)

// 导入配置是入站防火墙策略的第二条入口，而且比保存设置那条更隐蔽：备份里那份策略是在
// **另一台机器**上定下的——"只允许局域网"在做备份的那台上完全成立，在这台上就可能等于
// "把正在导入的人关在门外"。落盘之后的下一个请求就按新策略判，用户看到的是"导入成功"，
// 然后再也打不开面板。
//
// 处置与面板端口那一支同口径（见 api_settings_import_panelport_test.go）：不回错，
// 保留本机现有策略、其余照常导入，并写一条日志。
//
// 这两个用例共用同一份备份，只改"提交导入的人从哪来"，因此它们一起钉住的是
// **判定依据是请求方而不是备份内容**——若哪天退化成"防火墙策略一律不导入"或
// "一律照导"，必有一条会红。

// importBackupFrom 与 importBackup 相同，只是可以指定请求对端地址。
//
// 需要它是因为这道兜底的判定完全取决于"提交导入的人从哪来"，而 httptest.NewRequest
// 造出来的对端固定是 192.0.2.1:1234，测不出局域网那一侧。
func importBackupFrom(t *testing.T, server *Server, backup []byte, remote string) *httptest.ResponseRecorder {
	t.Helper()
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	part, err := writer.CreateFormFile("file", "Mantou-backup.json")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := part.Write(backup); err != nil {
		t.Fatal(err)
	}
	fields := map[string]string{
		"account":      "admin",
		"password":     e2eAdminPassword,
		"authAccount":  server.deps.Config.Snapshot().Auth.Username,
		"authPassword": e2eLocalPassword,
	}
	for k, v := range fields {
		if err := writer.WriteField(k, v); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodPost, "/api/settings/import", &body)
	ctx.Request.Header.Set("Content-Type", writer.FormDataContentType())
	ctx.Request.RemoteAddr = remote
	server.handleImportConfig(ctx)
	return recorder
}

// backupFirewallRateLimit 备份里那份策略的限速值，取一个不会与默认值混淆的数。
// 用它判断"策略到底跟没跟备份走"，比只看 Mode 更准——Mode 只有两个取值。
const backupFirewallRateLimit = 77

// localFirewallRateLimit 目标机器本机那份策略的限速值。
const localFirewallRateLimit = 99

// exportWithLANFirewall 造一份"入站防火墙 = 启用 + 仅局域网"的加密备份。
func exportWithLANFirewall(t *testing.T) []byte {
	t.Helper()
	source, sourceManager, sourceDir := newE2EEnv(t)
	seedFullConfig(t, sourceManager, sourceDir)
	if err := sourceManager.Update(func(cfg *config.Config) {
		cfg.Settings.Security.Firewall = config.PanelFirewall{
			Enabled: true, Mode: config.FirewallModeLAN,
			RateLimit: backupFirewallRateLimit,
			AutoBan:   true, AutoBanThreshold: 20, AutoBanMinutes: 60,
		}
	}); err != nil {
		t.Fatal(err)
	}
	return exportBackup(t, source)
}

// seedLocalFirewall 给目标机器配一份可辨认的本机策略：不限来源。
// 否则"没被覆盖"与"被覆盖成了默认值"这两种结果长得一样。
func seedLocalFirewall(t *testing.T, manager *config.Manager) {
	t.Helper()
	if err := manager.Update(func(cfg *config.Config) {
		cfg.Settings.Security.Firewall = config.PanelFirewall{
			Enabled: true, Mode: config.FirewallModeAll,
			RateLimit: localFirewallRateLimit,
			AutoBan:   true, AutoBanThreshold: 20, AutoBanMinutes: 60,
		}
	}); err != nil {
		t.Fatal(err)
	}
}

// assertImported 确认这次导入确实生效了。
// 少了这一步，"策略没变"可能只是因为整份导入压根失败了。
func assertImported(t *testing.T, cfg *config.Config) {
	t.Helper()
	if len(cfg.Forwards) != 1 || cfg.Forwards[0].ID != "fwd-e2e" {
		t.Fatalf("测试前提不成立：备份没被导入，端口转发是 %+v", cfg.Forwards)
	}
}

// TestImportKeepsLocalFirewallWhenBackupPolicyLocksYouOut 从公网导入一份「仅局域网」的
// 备份：其余部分照常导入，防火墙策略保留本机现值。
func TestImportKeepsLocalFirewallWhenBackupPolicyLocksYouOut(t *testing.T) {
	gin.SetMode(gin.TestMode)
	t.Setenv("MANTOU_MASTER_KEY", "")

	backup := exportWithLANFirewall(t)

	target, targetManager, _ := newE2EEnv(t)
	target.deps.RestartPanel = func() {}
	seedLocalConfig(t, targetManager)
	seedLocalFirewall(t, targetManager)

	rec := importBackupFrom(t, target, backup, "203.0.113.9:5000")

	if rec.Code != http.StatusOK {
		t.Fatalf("导入失败: %d %s", rec.Code, rec.Body.String())
	}
	cfg := targetManager.Snapshot()
	assertImported(t, cfg)
	fw := cfg.Settings.Security.Firewall
	if fw.Mode != config.FirewallModeAll {
		t.Fatalf("防火墙模式成了 %q，期望保留本机的 %q——否则这次导入完就把导入的人关在门外了",
			fw.Mode, config.FirewallModeAll)
	}
	if fw.RateLimit != localFirewallRateLimit {
		t.Fatalf("限速成了 %d，期望保留本机现值 %d——整份策略应当一起保留，不能只留 Mode",
			fw.RateLimit, localFirewallRateLimit)
	}
}

// TestImportAppliesFirewallPolicyWhenItKeepsYouIn 反向钉住：同一份备份，改从局域网提交，
// 「仅局域网」不会切断这次访问，策略就该照常跟备份走。
//
// 没有这一条，上面那个用例可以被"防火墙策略永不导入"这种实现骗过去。
func TestImportAppliesFirewallPolicyWhenItKeepsYouIn(t *testing.T) {
	gin.SetMode(gin.TestMode)
	t.Setenv("MANTOU_MASTER_KEY", "")

	backup := exportWithLANFirewall(t)

	target, targetManager, _ := newE2EEnv(t)
	target.deps.RestartPanel = func() {}
	seedLocalConfig(t, targetManager)
	seedLocalFirewall(t, targetManager)

	rec := importBackupFrom(t, target, backup, "192.168.1.50:5000")

	if rec.Code != http.StatusOK {
		t.Fatalf("导入失败: %d %s", rec.Code, rec.Body.String())
	}
	cfg := targetManager.Snapshot()
	assertImported(t, cfg)
	fw := cfg.Settings.Security.Firewall
	if fw.Mode != config.FirewallModeLAN {
		t.Fatalf("防火墙模式是 %q，期望跟备份走用 %q", fw.Mode, config.FirewallModeLAN)
	}
	if fw.RateLimit != backupFirewallRateLimit {
		t.Fatalf("限速是 %d，期望跟备份走用 %d", fw.RateLimit, backupFirewallRateLimit)
	}
}
