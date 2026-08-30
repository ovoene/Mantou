package server

import (
	"strings"
	"testing"

	"mantou/internal/config"
)

// 选择性导入的三条不变量：依赖闭包补齐、未选中模块保持现状、证书引用不留悬空。
// 这三条一旦破掉都不会立刻报错——不导入变成清空、或者面板重启后 HTTPS 起不来，
// 都是"下一次"才发现的问题，所以必须有测试钉住。

func TestParseImportScopeDefaultsToAll(t *testing.T) {
	for _, raw := range []string{"", "   "} {
		sc, err := parseImportScope(raw)
		if err != nil {
			t.Fatalf("modules=%q 应视为全选，实际报错 %v", raw, err)
		}
		if !sc.all() {
			t.Fatalf("modules=%q 应视为全选，实际 %v", raw, sc.keys())
		}
	}
}

func TestParseImportScopeRejectsBadInput(t *testing.T) {
	if _, err := parseImportScope("ddns,nosuchmodule"); err == nil {
		t.Fatal("未知模块标识应报错")
	}
	if _, err := parseImportScope(", ,"); err == nil {
		t.Fatal("一个模块都没选应报错")
	}
}

func TestParseImportScopePullsInDependencies(t *testing.T) {
	cases := []struct {
		raw  string
		want []importModule
	}{
		// 面板 → 证书 → 凭证：两层闭包都要补齐。
		{"panel", []importModule{modPanel, modCert, modCredential}},
		{"webservice", []importModule{modWebService, modCert, modCredential}},
		{"messageroute", []importModule{modMessage, modCert, modCredential}},
		{"cert", []importModule{modCert, modCredential}},
		{"ddns", []importModule{modDDNS, modCredential}},
		// 无引用的模块不该把别人拖进来——否则"只导一部分"就不存在了。
		{"forward", []importModule{modForward}},
		{"wol", []importModule{modWOL}},
		{"cron", []importModule{modCron}},
		{"credential", []importModule{modCredential}},
	}
	for _, c := range cases {
		sc, err := parseImportScope(c.raw)
		if err != nil {
			t.Fatalf("modules=%q: %v", c.raw, err)
		}
		want := make(map[importModule]bool, len(c.want))
		for _, m := range c.want {
			want[m] = true
		}
		for _, m := range importModules {
			if sc[m] != want[m] {
				t.Fatalf("modules=%q 解析为 %v，期望 %v", c.raw, sc.keys(), c.want)
			}
		}
	}
}

// baseConfig 造一份"本机现状"，每个模块都有一条可辨认的数据。
func baseConfig() *config.Config {
	c := config.Default()
	c.Panel.Port = 12345
	c.Auth.Username = "local"
	c.Auth.PasswordHash = "local-hash"
	c.Credentials = []config.Credential{{ID: "cred-local", Name: "本机凭证"}}
	c.DDNS = []config.DDNSRule{{ID: "ddns-local", Name: "本机 DDNS"}}
	c.WebServices = []config.WebService{{ID: "web-local", Name: "本机站点"}}
	c.Forwards = []config.ForwardRule{{ID: "fwd-local", Name: "本机转发"}}
	c.WOLDevices = []config.WOLDevice{{ID: "wol-local", Name: "本机唤醒"}}
	c.CronTasks = []config.CronTask{{ID: "cron-local", Name: "本机任务"}}
	c.Certs = []config.Certificate{{ID: "cert-local", Name: "本机证书"}}
	c.ACMEAccounts = []config.ACMEAccount{{ID: "acme-local", Email: "local@example.com"}}
	c.NotifyTargets = []config.NotifyTarget{{ID: "nt-local", Name: "本机目标"}}
	c.MessageTemplates = []config.MessageTemplate{{ID: "tpl-local", Name: "本机模板"}}
	c.WebhookReceivers = []config.WebhookReceiver{{ID: "rcv-local", Name: "本机接收器"}}
	return c
}

// importedConfig 造一份"备份里的东西"，ID 全部换成 -backup 后缀便于断言来源。
func importedConfig() *config.Config {
	c := config.Default()
	c.Panel.Port = 23456
	c.Auth.Username = "backup"
	c.Auth.PasswordHash = "backup-hash"
	c.Credentials = []config.Credential{{ID: "cred-backup", Name: "备份凭证"}}
	c.DDNS = []config.DDNSRule{{ID: "ddns-backup", Name: "备份 DDNS"}}
	c.WebServices = []config.WebService{{ID: "web-backup", Name: "备份站点"}}
	c.Forwards = []config.ForwardRule{{ID: "fwd-backup", Name: "备份转发"}}
	c.WOLDevices = []config.WOLDevice{{ID: "wol-backup", Name: "备份唤醒"}}
	c.CronTasks = []config.CronTask{{ID: "cron-backup", Name: "备份任务"}}
	c.Certs = []config.Certificate{{ID: "cert-backup", Name: "备份证书"}}
	c.ACMEAccounts = []config.ACMEAccount{{ID: "acme-backup", Email: "backup@example.com"}}
	c.NotifyTargets = []config.NotifyTarget{{ID: "nt-backup", Name: "备份目标"}}
	c.MessageTemplates = []config.MessageTemplate{{ID: "tpl-backup", Name: "备份模板"}}
	c.WebhookReceivers = []config.WebhookReceiver{{ID: "rcv-backup", Name: "备份接收器"}}
	return c
}

func TestMergeImportedConfigOnlyTouchesSelected(t *testing.T) {
	sc, err := parseImportScope("forward,wol")
	if err != nil {
		t.Fatal(err)
	}
	got := mergeImportedConfig(baseConfig(), importedConfig(), sc)

	// 选中的两个模块来自备份。
	if got.Forwards[0].ID != "fwd-backup" || got.WOLDevices[0].ID != "wol-backup" {
		t.Fatalf("选中的模块应来自备份，实际 forwards=%s wol=%s", got.Forwards[0].ID, got.WOLDevices[0].ID)
	}
	// 其余一律保持本机现状——尤其不能变成空列表：那样"不导入"就成了"删数据"。
	checks := []struct {
		name string
		got  string
	}{
		{"credentials", firstID(len(got.Credentials), func() string { return got.Credentials[0].ID })},
		{"ddns", firstID(len(got.DDNS), func() string { return got.DDNS[0].ID })},
		{"webServices", firstID(len(got.WebServices), func() string { return got.WebServices[0].ID })},
		{"cronTasks", firstID(len(got.CronTasks), func() string { return got.CronTasks[0].ID })},
		{"certs", firstID(len(got.Certs), func() string { return got.Certs[0].ID })},
		{"acmeAccounts", firstID(len(got.ACMEAccounts), func() string { return got.ACMEAccounts[0].ID })},
		{"notifyTargets", firstID(len(got.NotifyTargets), func() string { return got.NotifyTargets[0].ID })},
		{"messageTemplates", firstID(len(got.MessageTemplates), func() string { return got.MessageTemplates[0].ID })},
		{"webhookReceivers", firstID(len(got.WebhookReceivers), func() string { return got.WebhookReceivers[0].ID })},
	}
	for _, c := range checks {
		if !strings.HasSuffix(c.got, "-local") {
			t.Fatalf("%s 未选中却被改动：%s", c.name, c.got)
		}
	}
	if got.Panel.Port != 12345 || got.Auth.Username != "local" {
		t.Fatalf("面板与账户未选中却被改动：port=%d user=%s", got.Panel.Port, got.Auth.Username)
	}
}

func firstID(n int, get func() string) string {
	if n == 0 {
		return "<空列表>"
	}
	return get()
}

func TestMergeImportedConfigFullScopeEqualsReplace(t *testing.T) {
	got := mergeImportedConfig(baseConfig(), importedConfig(), fullImportScope())
	if got.Panel.Port != 23456 || got.Auth.Username != "backup" {
		t.Fatalf("全选时面板与账户应来自备份：port=%d user=%s", got.Panel.Port, got.Auth.Username)
	}
	for _, id := range []string{
		got.Credentials[0].ID, got.DDNS[0].ID, got.WebServices[0].ID, got.Forwards[0].ID,
		got.WOLDevices[0].ID, got.CronTasks[0].ID, got.Certs[0].ID, got.ACMEAccounts[0].ID,
		got.NotifyTargets[0].ID, got.MessageTemplates[0].ID, got.WebhookReceivers[0].ID,
	} {
		if !strings.HasSuffix(id, "-backup") {
			t.Fatalf("全选时所有模块都应来自备份，发现 %s", id)
		}
	}
}

// 反方向的坑：只勾证书，证书集被整体换掉，而**当前**面板 HTTPS 引用的那张证书
// 可能不在备份里。这种组合必须在落盘前被拒绝，否则下一次重启就进不去面板。
func TestCheckImportCertRefsCatchesReplacedCertStore(t *testing.T) {
	base := baseConfig()
	base.Panel.HTTPS.Enabled = true
	base.Panel.HTTPS.CertID = "cert-local"
	sc, err := parseImportScope("cert")
	if err != nil {
		t.Fatal(err)
	}
	merged := mergeImportedConfig(base, importedConfig(), sc)
	err = checkImportCertRefs(merged, sc)
	if err == nil {
		t.Fatal("面板 HTTPS 引用的证书已不存在，应拒绝导入")
	}
	// 错误信息必须点出该怎么办，否则用户只能猜。
	if !strings.Contains(err.Error(), "面板与设置") {
		t.Fatalf("错误信息应给出可操作的建议，实际：%v", err)
	}
}

func TestCheckImportCertRefsIgnoresDisabledHTTPS(t *testing.T) {
	base := baseConfig()
	base.Panel.HTTPS.Enabled = false
	base.Panel.HTTPS.CertID = "cert-gone"
	sc, err := parseImportScope("cert")
	if err != nil {
		t.Fatal(err)
	}
	merged := mergeImportedConfig(base, importedConfig(), sc)
	if err := checkImportCertRefs(merged, sc); err != nil {
		t.Fatalf("HTTPS 未启用时不该因为失效的 certId 拦下导入：%v", err)
	}
}

func TestCheckImportCertRefsPassesWhenCertTravelsAlong(t *testing.T) {
	imp := importedConfig()
	imp.Panel.HTTPS.Enabled = true
	imp.Panel.HTTPS.CertID = "cert-backup"
	sc, err := parseImportScope("panel")
	if err != nil {
		t.Fatal(err)
	}
	if !sc[modCert] {
		t.Fatal("勾选面板应连带勾选证书")
	}
	merged := mergeImportedConfig(baseConfig(), imp, sc)
	if err := checkImportCertRefs(merged, sc); err != nil {
		t.Fatalf("证书随面板一并导入时不该报错：%v", err)
	}
}

// 定时重启的执行记录不随备份走：它是防重启循环的凭据，一份来自时钟偏快机器的备份
// 会把它带到未来，之后定时重启永远不再触发。保存接口刻意不接受外部提交它
// （TestUpdateSettingsIgnoresClientSuppliedLastRunAt），导入这条路径必须同口径。
func TestMergeImportedConfigKeepsLocalRestartLastRunAt(t *testing.T) {
	base := baseConfig()
	base.Settings.Restart.LastRunAt = 1700000000
	imp := importedConfig()
	imp.Settings.Restart.Enabled = true
	imp.Settings.Restart.Hour = 5
	imp.Settings.Restart.LastRunAt = 4102444800 // 2100 年：足以让锚点永远追不上

	got := mergeImportedConfig(base, imp, fullImportScope())

	// 用户设的那几项该跟着备份走。
	if !got.Settings.Restart.Enabled || got.Settings.Restart.Hour != 5 {
		t.Fatalf("定时重启的设置项应来自备份：%+v", got.Settings.Restart)
	}
	// 执行记录不跟。
	if got.Settings.Restart.LastRunAt != 1700000000 {
		t.Fatalf("上次执行时间 = %d，期望保持本机的 1700000000", got.Settings.Restart.LastRunAt)
	}
}
