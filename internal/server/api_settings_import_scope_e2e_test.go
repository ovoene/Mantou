package server

import (
	"bytes"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"

	"mantou/internal/auth"
	"mantou/internal/config"
)

// 本文件走真实接口验证「选择性导入」：一份完整备份，只把其中几个模块覆盖到本机，
// 其余模块保持本机现状。单元测试盯的是合并函数，这里盯的是整条链路
//（多段表单 → 解析范围 → 解密 → 迁移 → 合并 → 落盘），因为链路上任何一环
// 把 modules 丢掉，行为都会退回"整份替换"，而那正是最危险的静默失败：
// 用户以为只导了端口转发，实际连管理员账户都被换成了备份里的那一个。

// importBackupScoped 与 importBackup 相同，额外提交 modules 字段。
func importBackupScoped(t *testing.T, server *Server, backup []byte, modules string) *httptest.ResponseRecorder {
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
	// account/password 是**导出方**的凭据（备份的解密口令），与本机账户无关。
	// authAccount/authPassword 才是本机当前管理员那一套，用来过接口的身份校验。
	fields := map[string]string{
		"account":      "admin",
		"password":     e2eAdminPassword,
		"modules":      modules,
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
	server.handleImportConfig(ctx)
	return recorder
}

// seedLocalConfig 把目标机器也配上一份可辨认的本机数据，否则"没被覆盖"与
// "被覆盖成了默认值"这两种结果长得一样，测试就白做了。
func seedLocalConfig(t *testing.T, manager *config.Manager) {
	t.Helper()
	seedLocalAdmin(t, manager)
	if err := manager.Update(func(cfg *config.Config) {
		cfg.Settings.Language = "zh-CN"
		cfg.Settings.Appearance.ThemeMode = "light"
		cfg.Credentials = []config.Credential{{
			ID: "cred-local", Name: "本机凭证", Provider: "cloudflare",
			Secrets: map[string]string{"apiToken": "本机 token"},
		}}
		cfg.DDNS = []config.DDNSRule{{
			ID: "ddns-local", Name: "本机规则", Enabled: true, Stack: "ipv4", IntervalSec: 300,
			Source:  config.DDNSSource{Type: "public"},
			Targets: []config.DDNSTarget{{CredentialRef: "cred-local", Provider: "cloudflare", Domain: "local.test", Subdomains: []string{"a"}, RecordType: "A", TTL: 600}},
		}}
		cfg.Forwards = []config.ForwardRule{{
			ID: "fwd-local", Name: "本机转发", Enabled: true, Protocol: "tcp",
			ListenPort: 3333, TargetHost: "127.0.0.1", TargetPort: 33, Family: "dual",
		}}
		cfg.WOLDevices = []config.WOLDevice{{ID: "wol-local", Enabled: true, Name: "本机设备", MAC: "11:22:33:44:55:66", Broadcast: "192.168.9.255", Port: 9}}
		// 本机那份服务防护：档位与名单都与备份里的不同（备份是严格档 + 两张名单，
		// 见 seedFullConfig），这样"保留了本机的"与"被备份覆盖了"两种结果一眼可分。
		// 顺手规范化成不动点：合并结果落盘时 Config.Replace 内部会再跑一遍规范化，
		// 种子值若不是不动点，"没被改动"的断言会挂在规范化造成的差异上。
		cfg.GlobalFirewall = config.GlobalFirewall{
			Enabled: true, Level: config.GlobalFirewallLevelLoose, AutoBan: false,
			AllowIPs: []string{"192.168.9.0/24"},
			MemoryMB: config.DefaultGlobalFirewallMemoryMB,
		}
		config.NormalizeGlobalFirewall(&cfg.GlobalFirewall)
	}); err != nil {
		t.Fatal(err)
	}
}

// importedModules 从响应里取出后端**实际**导入的模块（含连带勾选的结果）。
func importedModules(t *testing.T, rec *httptest.ResponseRecorder) []string {
	t.Helper()
	var resp struct {
		Data struct {
			Modules []string `json:"modules"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("解析响应失败: %v (%s)", err, rec.Body.String())
	}
	return resp.Data.Modules
}

func TestPartialImportKeepsUnselectedModules(t *testing.T) {
	gin.SetMode(gin.TestMode)
	t.Setenv("MANTOU_MASTER_KEY", "")

	source, sourceManager, sourceDir := newE2EEnv(t)
	seedFullConfig(t, sourceManager, sourceDir)
	backup := exportBackup(t, source)

	target, targetManager, _ := newE2EEnv(t)
	seedLocalConfig(t, targetManager)

	rec := importBackupScoped(t, target, backup, "forward,wol")
	if rec.Code != http.StatusOK {
		t.Fatalf("导入失败: %d %s", rec.Code, rec.Body.String())
	}
	if got := importedModules(t, rec); len(got) != 2 || got[0] != "forward" || got[1] != "wol" {
		t.Fatalf("响应里的导入范围是 %v，期望 [forward wol]（这两个模块没有依赖，不该被扩大）", got)
	}

	cfg := targetManager.Snapshot()
	// 勾选的两项来自备份。
	if len(cfg.Forwards) != 1 || cfg.Forwards[0].ID != "fwd-e2e" {
		t.Fatalf("端口转发应被备份覆盖，实际 %+v", cfg.Forwards)
	}
	if len(cfg.WOLDevices) != 1 || cfg.WOLDevices[0].ID != "wol-e2e" {
		t.Fatalf("网络唤醒应被备份覆盖，实际 %+v", cfg.WOLDevices)
	}
	// 没勾的一律保持本机现状。凭证与 DDNS 尤其要看：它们是备份里有内容的模块，
	// 一旦合并基准取错（比如拿默认配置当底），这里会变成空列表。
	if len(cfg.DDNS) != 1 || cfg.DDNS[0].ID != "ddns-local" {
		t.Fatalf("DDNS 未勾选却被改动，实际 %+v", cfg.DDNS)
	}
	if len(cfg.Credentials) != 1 || cfg.Credentials[0].ID != "cred-local" {
		t.Fatalf("凭证未勾选却被改动，实际 %+v", cfg.Credentials)
	}
	if len(cfg.WebServices) != 0 {
		t.Fatalf("Web 服务未勾选却被写入了 %d 条", len(cfg.WebServices))
	}
	// 面板与设置是"不导入却被覆盖"后果最重的一段：管理员账户被换掉就等于交出面板。
	if cfg.Auth.Username != e2eLocalAccount {
		t.Fatalf("管理员账户被备份覆盖了: %s", cfg.Auth.Username)
	}
	if !auth.VerifyPassword(cfg.Auth.PasswordHash, e2eLocalPassword) {
		t.Fatal("管理员密码被备份覆盖了")
	}
	if cfg.Settings.Language != "zh-CN" || cfg.Settings.Appearance.ThemeMode != "light" {
		t.Fatalf("外观与语言未勾选却被改动: lang=%s theme=%s", cfg.Settings.Language, cfg.Settings.Appearance.ThemeMode)
	}
	// 服务防护是顶层字段，不在 Settings 里：上面那几条断言全都盖不到它。
	if cfg.GlobalFirewall.Level != config.GlobalFirewallLevelLoose {
		t.Fatalf("服务防护未勾选却被改动: %+v", cfg.GlobalFirewall)
	}
}

// 服务防护是独立一项，与「面板与设置」互不牵连。这两条断言互为反向：
// 一条证明它能单独导进来，一条证明导别的模块不会把它带上。
//
// 少了它们，最省事的实现（把 GlobalFirewall 塞进 panel 那一段）也能全绿，
// 而那种实现的代价是"想恢复一份 IP 名单就得连管理员账户一起换掉"。
func TestPartialImportGlobalFirewallTravelsAlone(t *testing.T) {
	gin.SetMode(gin.TestMode)
	t.Setenv("MANTOU_MASTER_KEY", "")

	source, sourceManager, sourceDir := newE2EEnv(t)
	seedFullConfig(t, sourceManager, sourceDir)
	backup := exportBackup(t, source)

	target, targetManager, _ := newE2EEnv(t)
	seedLocalConfig(t, targetManager)

	rec := importBackupScoped(t, target, backup, "globalfirewall")
	if rec.Code != http.StatusOK {
		t.Fatalf("导入失败: %d %s", rec.Code, rec.Body.String())
	}
	// 不该连带任何模块：它只是一份档位加两张 IP 名单，谁也不引用。
	if got := importedModules(t, rec); len(got) != 1 || got[0] != "globalfirewall" {
		t.Fatalf("响应里的导入范围是 %v，期望 [globalfirewall]（它没有依赖，不该被扩大）", got)
	}

	cfg := targetManager.Snapshot()
	gfw := cfg.GlobalFirewall
	if gfw.Level != config.GlobalFirewallLevelStrict || !gfw.AutoBan {
		t.Fatalf("服务防护应被备份覆盖，实际 %+v", gfw)
	}
	if len(gfw.DenyIPs) != 1 || gfw.DenyIPs[0] != "203.0.113.66" {
		t.Fatalf("服务防护的拒绝名单应来自备份，实际 %v", gfw.DenyIPs)
	}
	// 而「面板与设置」那一段一点没动——这正是把它从 panel 里拆出来的全部意义。
	if cfg.Auth.Username != e2eLocalAccount {
		t.Fatalf("只导服务防护却换掉了管理员账户: %s", cfg.Auth.Username)
	}
	if cfg.Settings.Language != "zh-CN" || cfg.Settings.Appearance.ThemeMode != "light" {
		t.Fatalf("只导服务防护却改动了外观: lang=%s theme=%s", cfg.Settings.Language, cfg.Settings.Appearance.ThemeMode)
	}
}

func TestPartialImportPanelLeavesGlobalFirewallAlone(t *testing.T) {
	gin.SetMode(gin.TestMode)
	t.Setenv("MANTOU_MASTER_KEY", "")

	source, sourceManager, sourceDir := newE2EEnv(t)
	seedFullConfig(t, sourceManager, sourceDir)
	backup := exportBackup(t, source)

	target, targetManager, _ := newE2EEnv(t)
	target.deps.RestartPanel = func() {}
	seedLocalConfig(t, targetManager)

	rec := importBackupScoped(t, target, backup, "panel")
	if rec.Code != http.StatusOK {
		t.Fatalf("导入失败: %d %s", rec.Code, rec.Body.String())
	}

	cfg := targetManager.Snapshot()
	// 前提：这次导入确实把「面板与设置」搬过来了。
	if cfg.Settings.Language != "en-US" {
		t.Fatalf("测试前提不成立：面板与设置没被导入，语言仍是 %s", cfg.Settings.Language)
	}
	// 服务防护不跟着面板走。
	if cfg.GlobalFirewall.Level != config.GlobalFirewallLevelLoose || cfg.GlobalFirewall.AutoBan {
		t.Fatalf("服务防护跟着「面板与设置」被一起换掉了: %+v", cfg.GlobalFirewall)
	}
	if len(cfg.GlobalFirewall.DenyIPs) != 0 {
		t.Fatalf("服务防护的拒绝名单跟着「面板与设置」进来了: %v", cfg.GlobalFirewall.DenyIPs)
	}
}

func TestPartialImportPullsInDependencyModules(t *testing.T) {
	gin.SetMode(gin.TestMode)
	t.Setenv("MANTOU_MASTER_KEY", "")

	source, sourceManager, sourceDir := newE2EEnv(t)
	seedFullConfig(t, sourceManager, sourceDir)
	backup := exportBackup(t, source)

	target, targetManager, _ := newE2EEnv(t)
	seedLocalConfig(t, targetManager)

	// 只勾 DDNS。它的目标按 credentialRef 指向凭证，凭证必须被连带导入，
	// 否则导入完成的那一刻规则就是坏的（鉴权拿不到 token）。
	rec := importBackupScoped(t, target, backup, "ddns")
	if rec.Code != http.StatusOK {
		t.Fatalf("导入失败: %d %s", rec.Code, rec.Body.String())
	}
	got := importedModules(t, rec)
	if len(got) != 2 || got[0] != "ddns" || got[1] != "credential" {
		t.Fatalf("响应里的导入范围是 %v，期望 [ddns credential]（凭证是连带项）", got)
	}

	cfg := targetManager.Snapshot()
	if len(cfg.DDNS) != 1 || cfg.DDNS[0].ID != "ddns-e2e" {
		t.Fatalf("DDNS 应被备份覆盖，实际 %+v", cfg.DDNS)
	}
	if len(cfg.Credentials) != 1 || cfg.Credentials[0].ID != "cred-e2e" {
		t.Fatalf("凭证应作为连带项被导入，实际 %+v", cfg.Credentials)
	}
	// 连带导入的凭证也要能用：备份里是明文，落盘要重新用本机 master.key 加密，
	// 读回来必须还是原值。
	if cfg.Credentials[0].Secrets["apiToken"] != e2eAPIToken {
		t.Fatalf("连带导入的凭证密钥不正确: %q", cfg.Credentials[0].Secrets["apiToken"])
	}
	// 引用链对上了：规则指向的凭证在配置里存在。
	if ref := cfg.DDNS[0].Targets[0].CredentialRef; ref != cfg.Credentials[0].ID {
		t.Fatalf("导入后 DDNS 的凭证引用悬空: %s", ref)
	}
	// 其余模块仍是本机的。
	if len(cfg.Forwards) != 1 || cfg.Forwards[0].ID != "fwd-local" {
		t.Fatalf("端口转发未勾选却被改动，实际 %+v", cfg.Forwards)
	}
	if cfg.Auth.Username != "local-admin" {
		t.Fatalf("管理员账户被备份覆盖了: %s", cfg.Auth.Username)
	}
}

func TestPartialImportRejectsEmptyAndUnknownScope(t *testing.T) {
	gin.SetMode(gin.TestMode)
	t.Setenv("MANTOU_MASTER_KEY", "")

	source, sourceManager, sourceDir := newE2EEnv(t)
	seedFullConfig(t, sourceManager, sourceDir)
	backup := exportBackup(t, source)

	target, targetManager, _ := newE2EEnv(t)
	seedLocalConfig(t, targetManager)

	for _, modules := range []string{",", "ddns,不存在的模块"} {
		rec := importBackupScoped(t, target, backup, modules)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("modules=%q 应被拒绝，实际 %d %s", modules, rec.Code, rec.Body.String())
		}
	}
	// 拒绝掉的请求不能留下半截改动。
	cfg := targetManager.Snapshot()
	if len(cfg.DDNS) != 1 || cfg.DDNS[0].ID != "ddns-local" || cfg.Auth.Username != "local-admin" {
		t.Fatal("被拒绝的导入改动了配置")
	}
}

// 不带 modules 字段的请求必须仍然是整份替换：这个接口在选择性导入之前就存在，
// 老页面缓存提交的导入不能静默变成部分导入。
func TestImportWithoutModulesFieldStillReplacesEverything(t *testing.T) {
	gin.SetMode(gin.TestMode)
	t.Setenv("MANTOU_MASTER_KEY", "")

	source, sourceManager, sourceDir := newE2EEnv(t)
	seedFullConfig(t, sourceManager, sourceDir)
	backup := exportBackup(t, source)

	target, targetManager, _ := newE2EEnv(t)
	seedLocalConfig(t, targetManager)

	if rec := importBackup(t, target, backup); rec.Code != http.StatusOK {
		t.Fatalf("导入失败: %d %s", rec.Code, rec.Body.String())
	}
	cfg := targetManager.Snapshot()
	if cfg.Auth.Username != "admin" {
		t.Fatalf("不带 modules 的导入应整份替换，管理员账户仍是 %s", cfg.Auth.Username)
	}
	if len(cfg.DDNS) != 1 || cfg.DDNS[0].ID != "ddns-e2e" {
		t.Fatalf("不带 modules 的导入应整份替换，DDNS 是 %+v", cfg.DDNS)
	}
}
