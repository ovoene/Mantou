package server

import (
	"reflect"
	"testing"

	"mantou/internal/config"
)

// 本文件只解决一件事：mergeImportedConfig 里那张"模块 → 配置字段"的对应表，
// 是这份代码里唯一知道二者关系的地方，而**没有任何东西强制它跟上新字段**。
//
// 漏掉的后果很轻微又很难发现：新字段永远不被导入（悄悄沿用本机现值），
// 恢复备份的人只会觉得"有一项设置没恢复过来"，不会有任何报错或日志。
// 所以这里用反射把 config.Config 的字段逐个点名，要求每个字段都被明确归类——
// 要么属于某个模块，要么写明为什么刻意不导入。加字段时测试会直接失败并说清该改哪里。

// importFieldOwners config.Config 的每个字段归属哪个模块。
// 必须与 mergeImportedConfig 里的赋值一致（下面的行为用例会逐字段对账）。
var importFieldOwners = map[string]importModule{
	"Panel":            modPanel,
	"Auth":             modPanel,
	"Settings":         modPanel,
	"Update":           modPanel,
	"Credentials":      modCredential,
	"DDNS":             modDDNS,
	"WebServices":      modWebService,
	"Forwards":         modForward,
	"WOLDevices":       modWOL,
	"CronTasks":        modCron,
	"Certs":            modCert,
	"ACMEAccounts":     modCert,
	"Webhook":          modMessage,
	"WebhookReceivers": modMessage,
	"NotifyTargets":    modMessage,
	"MessageTemplates": modMessage,
}

// importFieldsNotImported 刻意不随备份走的字段，以及原因。
// 写在这里而不是简单跳过：下一个人看到"这个字段没被导入"时，能直接读到是有意的。
var importFieldsNotImported = map[string]string{
	"Version": "配置版本号由 config.Migrate 决定；导入前备份已被迁移到当前版本，" +
		"把备份里的旧版本号带过来会让下一次启动重跑一遍迁移",
}

// 加字段忘了归类时，失败信息要能直接告诉人该改哪里。
func TestImportScopeClassifiesEveryConfigField(t *testing.T) {
	typ := reflect.TypeOf(config.Config{})
	for i := 0; i < typ.NumField(); i++ {
		f := typ.Field(i)
		if f.PkgPath != "" {
			continue // 非导出字段不进 JSON，也就不参与导入
		}
		_, owned := importFieldOwners[f.Name]
		_, skipped := importFieldsNotImported[f.Name]
		switch {
		case owned && skipped:
			t.Fatalf("config.Config.%s 同时出现在两张表里，归类必须唯一", f.Name)
		case !owned && !skipped:
			t.Fatalf("config.Config.%s 是新字段，尚未归类。请在 mergeImportedConfig 里把它"+
				"归到某个模块名下并同步 importFieldOwners；确实不该随备份走的，"+
				"写进 importFieldsNotImported 并说明原因。"+
				"不归类的后果是这个字段永远不被导入，且不会有任何报错。", f.Name)
		}
	}
}

// 反方向：表里写了 Config 上不存在的字段（改名 / 删字段后忘了同步）。
func TestImportFieldTablesHaveNoStaleEntries(t *testing.T) {
	typ := reflect.TypeOf(config.Config{})
	exists := func(name string) bool {
		_, ok := typ.FieldByName(name)
		return ok
	}
	for name := range importFieldOwners {
		if !exists(name) {
			t.Fatalf("importFieldOwners 里的 %s 已不是 config.Config 的字段", name)
		}
	}
	for name := range importFieldsNotImported {
		if !exists(name) {
			t.Fatalf("importFieldsNotImported 里的 %s 已不是 config.Config 的字段", name)
		}
	}
}

// 每个模块都得真的搬得动自己名下的字段。
// 光有一张表不够：表写对了、mergeImportedConfig 里漏了一行赋值，照样是"这一项没恢复过来"。
func TestMergeImportedConfigMovesEveryOwnedField(t *testing.T) {
	for _, m := range importModules {
		sc, err := parseImportScope(string(m))
		if err != nil {
			t.Fatalf("模块 %s: %v", m, err)
		}
		base, imp := importDiffConfigs()
		wantLocal, wantBackup := *base, *imp // 合并会就地改 base，先留一份合并前的值

		got := mergeImportedConfig(base, imp, sc)

		gv := reflect.ValueOf(*got)
		lv := reflect.ValueOf(wantLocal)
		bv := reflect.ValueOf(wantBackup)
		typ := gv.Type()
		for i := 0; i < typ.NumField(); i++ {
			name := typ.Field(i).Name
			owner, owned := importFieldOwners[name]
			if !owned {
				continue
			}
			want, from := lv.Field(i), "本机现值"
			if sc[owner] {
				want, from = bv.Field(i), "备份"
			}
			if !reflect.DeepEqual(gv.Field(i).Interface(), want.Interface()) {
				t.Fatalf("只勾选 %s（连带后 %v）时，字段 %s 应取%s，实际 %+v",
					m, sc.keys(), name, from, gv.Field(i).Interface())
			}
		}
	}
}

// importDiffConfigs 造一对**每个可导入字段都不一样**的配置。
//
// 不能直接用 baseConfig()/importedConfig()：它们只在列表类字段上有差异，
// Settings / Update / Webhook 三段两边完全相同，于是"未选中的字段没被改动"这类断言
// 会因为两边本来就相等而空跑过去——测试全绿，实际什么也没验证。
func importDiffConfigs() (base, imp *config.Config) {
	base, imp = baseConfig(), importedConfig()
	// Settings 段随便挑一个纯展示、不做规范化的字段来承载差异即可。
	// （原先用的是 Settings.Notify.WebhookURL，那个字段谁都不读，已删除。）
	base.Settings.Language = "zh-CN"
	imp.Settings.Language = "en-US"
	base.Update.GitHubRepo = "local/repo"
	imp.Update.GitHubRepo = "backup/repo"
	base.Webhook.Port = 18080
	imp.Webhook.Port = 28080
	// 定时重启的执行记录两边取同一个值：它是 Settings 里唯一**刻意不跟备份走**的字段
	//（见 TestMergeImportedConfigKeepsLocalRestartLastRunAt），
	// 在这里拉开差异只会让整段 Settings 的逐字段对账变成在考那一个例外。
	base.Settings.Restart.LastRunAt = 1700000000
	imp.Settings.Restart.LastRunAt = 1700000000
	return base, imp
}
