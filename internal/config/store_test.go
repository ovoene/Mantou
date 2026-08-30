package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestReplaceRestoresCurrentConfigWhenSaveFails(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	manager := NewManager(path)
	if err := manager.Load(); err != nil {
		t.Fatal(err)
	}
	before := manager.Get()
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}

	replacement := manager.Get()
	replacement.Panel.Port = 443
	if err := manager.Replace(replacement); err == nil {
		t.Fatal("expected save failure")
	}
	if got := manager.Get().Panel.Port; got != before.Panel.Port {
		t.Fatalf("expected current config to be restored, got port %d", got)
	}
}

func TestLoadMigratesLegacyPanelAllowedHosts(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	data := `{"version":1,"panel":{"listen":"0.0.0.0","port":25666,"https":{"enabled":true,"certId":"panel","allowedHosts":["panel.example.com","old.example.com"]}}}`
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	manager := NewManager(path)
	if err := manager.Load(); err != nil {
		t.Fatal(err)
	}
	https := manager.Get().Panel.HTTPS
	if https.Domain != "panel.example.com" {
		t.Fatalf("expected first legacy host, got %q", https.Domain)
	}
	if len(https.AllowedHosts) != 0 {
		t.Fatalf("expected legacy hosts to be cleared, got %#v", https.AllowedHosts)
	}
}

func TestLoadNormalizesLegacyWebServiceTLSMinVersion(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	data := `{"version":1,"panel":{"listen":"0.0.0.0","port":25666},"webServices":[{"id":"parent","name":"site","enabled":true,"port":443,"ipFamily":"both","children":[{"id":"child","enabled":true,"tls":true,"tlsMinVersion":""}]}]}`
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	manager := NewManager(path)
	if err := manager.Load(); err != nil {
		t.Fatal(err)
	}
	got := manager.Get().WebServices
	if len(got) != 1 || len(got[0].Children) != 1 {
		t.Fatalf("unexpected Web services: %#v", got)
	}
	if got[0].Children[0].TLSMinVersion != "1.2" {
		t.Fatalf("expected TLS 1.2, got %q", got[0].Children[0].TLSMinVersion)
	}
}

func TestLoadNormalizesMigratedFlatWebServiceTLSMinVersion(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	data := `{"version":1,"panel":{"listen":"0.0.0.0","port":25666},"webServices":[{"id":"legacy","name":"site","enabled":true,"listens":[{"port":443,"tls":true}],"domains":["example.com"],"type":"proxy","tlsMinVersion":""}]}`
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	manager := NewManager(path)
	if err := manager.Load(); err != nil {
		t.Fatal(err)
	}
	got := manager.Get().WebServices
	if len(got) != 1 || len(got[0].Children) != 1 {
		t.Fatalf("unexpected migrated Web services: %#v", got)
	}
	child := got[0].Children[0]
	if !child.TLS || child.TLSMinVersion != "1.2" {
		t.Fatalf("expected migrated HTTPS child with TLS 1.2, got %#v", child)
	}
}

func TestTruncateStatusKeepsShortTextAndCutsOnRuneBoundary(t *testing.T) {
	if got := TruncateStatus("短状态"); got != "短状态" {
		t.Fatalf("short text must be kept verbatim, got %q", got)
	}
	// 每字 3 字节的中文文本：300 恰好是 3 的整数倍，故此处正好切在第 100 个字之后；
	// 换成 2/4 字节字符时裁剪点会落在字符中间，由 utf8.RuneStart 回退保证不产出非法序列。
	long := strings.Repeat("错", 200)
	got := TruncateStatus(long)
	if !strings.HasSuffix(got, "…（已截断）") {
		t.Fatalf("expected truncation marker, got %q", got)
	}
	body := strings.TrimSuffix(got, "…（已截断）")
	if len(body) > MaxStatusMessageLen {
		t.Fatalf("truncated body exceeds limit: %d bytes", len(body))
	}
	if !utf8.ValidString(got) {
		t.Fatalf("truncated text is not valid UTF-8: %q", got)
	}
	if body != strings.Repeat("错", 100) {
		t.Fatalf("expected exactly 100 whole runes, got %d bytes", len(body))
	}

	// 4 字节字符（emoji）：300 % 4 != 0，裁剪点必然落在字符中间，用于验证回退逻辑。
	emoji := TruncateStatus(strings.Repeat("🚀", 200))
	if !utf8.ValidString(emoji) {
		t.Fatalf("multi-byte truncation produced invalid UTF-8: %q", emoji)
	}
	if emojiBody := strings.TrimSuffix(emoji, "…（已截断）"); emojiBody != strings.Repeat("🚀", 75) {
		t.Fatalf("expected cut back to the last whole rune (75 emoji), got %d bytes", len(emojiBody))
	}
}

func TestLoadTruncatesPersistedStatusMessages(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	bloat := strings.Repeat("x", 5000)
	data := `{"version":2,"panel":{"listen":"0.0.0.0","port":25666},` +
		`"ddns":[{"id":"r1","lastStatus":"` + bloat + `"}],` +
		`"cronTasks":[{"id":"t1","lastStatus":"` + bloat + `"}],` +
		`"certs":[{"id":"c1","issueStatus":{"message":"` + bloat + `"},"renewStatus":{"message":"` + bloat + `"}}]}`
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	manager := NewManager(path)
	if err := manager.Load(); err != nil {
		t.Fatal(err)
	}
	cfg := manager.Get()
	limit := MaxStatusMessageLen + 32 // 上限加上「…（已截断）」标记的余量
	// 网络唤醒的 lastResult 不在这张表里：它已经不是配置字段了（搬进了内存，
	// 见 internal/runstats）。那条路上的裁剪由 runstats 在入库时做一次，
	// 由 TestStatusTruncatedAtIngest 钉住。
	for name, got := range map[string]string{
		"ddns.lastStatus":      cfg.DDNS[0].LastStatus,
		"cron.lastStatus":      cfg.CronTasks[0].LastStatus,
		"cert.issueStatus.msg": cfg.Certs[0].IssueStatus.Message,
		"cert.renewStatus.msg": cfg.Certs[0].RenewStatus.Message,
	} {
		if len(got) > limit {
			t.Fatalf("%s was not truncated on load: %d bytes", name, len(got))
		}
	}
}

// TestLoadMigratesLegacyWOLRangeSchedule 验证「时间范围」语义改版的迁移。
// 旧语义是「在 [Start, End] 内均匀发送 Count 次」，新语义是「从 Start 到 End 每 IntervalSec 秒发一个包」。
// 不迁移的话，一条旧的 08:00–18:00 ×5 会按遗留的 IntervalSec（旧前端默认 5）被解读成
// 「每 5 秒一个包」，一天七千多个包，与用户当初的设置差三个数量级。
func TestLoadMigratesLegacyWOLRangeSchedule(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	data := `{"version":2,"panel":{"listen":"0.0.0.0","port":25666},` +
		`"wolDevices":[{"id":"w1","mac":"AA:BB:CC:DD:EE:FF","enabled":true,` +
		`"schedule":{"enabled":true,"mode":"range","start":"08:00","end":"18:00","count":5,"intervalSec":5}}]}`
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	manager := NewManager(path)
	if err := manager.Load(); err != nil {
		t.Fatal(err)
	}
	s := manager.Get().WOLDevices[0].Schedule
	// 5 次均匀铺在 10 小时（36000 秒）跨度上，相邻两次相隔 36000/(5-1)=9000 秒，
	// 换算后的触发时刻 08:00 / 10:30 / 13:00 / 15:30 / 18:00 与旧行为逐拍重合。
	if s.IntervalSec != 9000 {
		t.Fatalf("发送间隔应换算为 9000 秒，实际 %d", s.IntervalSec)
	}
	// 归零本身就是「已迁移」标记，必须落盘生效，否则每次启动都会再换算一次。
	if s.Count != 0 {
		t.Fatalf("迁移后发包次数应归零，实际 %d", s.Count)
	}
}

// TestMigrateMarksExistingWebhookModuleCreated 验证 v7 升级：模块设置那一页新增了
// 「已创建」标记，未创建时那一页是空列表、接收器也无法启用。
//
// 升级前那一行**一直**存在，所以必须无条件置真：按"端口/域名/备注填过没有"猜测，
// 会让"装好但还没配过消息路由"的用户在升级后突然发现那一行不见了。
func TestMigrateMarksExistingWebhookModuleCreated(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	// 一份最朴素的旧配置：消息路由一个字都没配过，各字段都是默认值。
	data := `{"version":6,"panel":{"listen":"0.0.0.0","port":25666},` +
		`"webhookReceivers":[{"id":"r1","name":"第三方系统","enabled":true,"path":"hook"}]}`
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	manager := NewManager(path)
	if err := manager.Load(); err != nil {
		t.Fatal(err)
	}
	cfg := manager.Get()
	if !cfg.Webhook.Created {
		t.Fatal("升级上来的配置里模块那一行本来就在，必须标成已创建")
	}
	// 顺带确认这个标记真的解锁了接收器：否则升级会把用户在跑的接收器全停掉。
	if !cfg.WebhookReceivers[0].Enabled {
		t.Fatal("升级不该把启用中的接收器停掉")
	}
	if cfg.Version != CurrentVersion {
		t.Fatalf("版本号应升到 %d，实际 %d", CurrentVersion, cfg.Version)
	}
}

// TestMigrateFillsSourceRetainDefault 验证 v8 升级：入站原文留存的额度变成了界面上
// 可调的一个数（webhook.sourceRetainMb），而在这之前它是代码里写死的 2 MiB。
//
// 这一条必须有版本块、不能靠 normalizeWebhook 补默认值，因为 0 在这个字段上是
// 「不留存」这个有效选择、不是「没填」。
//
// 要盯的是**导入**这条路，不是 Load：
//
//	Load      cfg := Default() 之后再 Unmarshal，缺的键保持默认值——这条路上 2 是
//	          Default() 给的，删掉版本块也照样是 2，拿它当断言什么都没钉住。
//	导入备份   DecryptBackup 往一个零值 config.Config 里解（见 config_crypt.go），
//	          旧备份里没有这个键 → 解出来是 0 → 只有 config.Migrate 的版本块能把它
//	          补回 2。少了这一块，导入一份旧备份会静默关掉原文留存。
//
// 反方向同样要钉：已经是当前版本、且明确写着 0 的配置，任何一次迁移都不能改回 2。
func TestMigrateFillsSourceRetainDefault(t *testing.T) {
	// migrated 模拟导入那条路：零值结构体 + Unmarshal + Migrate。
	migrated := func(t *testing.T, data string) *Config {
		t.Helper()
		var c Config
		if err := json.Unmarshal([]byte(data), &c); err != nil {
			t.Fatal(err)
		}
		Migrate(&c)
		return &c
	}

	// 旧备份：连 webhook 这一段都没有，更没有 sourceRetainMb 这个键。
	cfg := migrated(t, `{"version":7,"panel":{"listen":"0.0.0.0","port":25666}}`)
	if cfg.Webhook.SourceRetainMB != DefaultSourceRetainMB {
		t.Fatalf("v7 备份迁上来后留存额度是 %d MB，期望默认值 %d MB——"+
			"导入把原文留存静默关掉了", cfg.Webhook.SourceRetainMB, DefaultSourceRetainMB)
	}
	if cfg.Version != CurrentVersion {
		t.Fatalf("版本号应升到 %d，实际 %d", CurrentVersion, cfg.Version)
	}

	// 已经是当前版本、且用户明确选了不留存：迁多少次都得是 0。
	off := migrated(t, `{"version":`+strconv.Itoa(CurrentVersion)+`,"panel":{"listen":"0.0.0.0","port":25666},`+
		`"webhook":{"port":25667,"sourceRetainMb":0}}`)
	if off.Webhook.SourceRetainMB != 0 {
		t.Fatalf("用户选的「不留存」被改成了 %d MB：0 在这个字段上是有效取值，不是没填",
			off.Webhook.SourceRetainMB)
	}
	Migrate(off)
	if off.Webhook.SourceRetainMB != 0 {
		t.Fatalf("二次迁移把「不留存」改成了 %d MB", off.Webhook.SourceRetainMB)
	}

	// 从磁盘装载这条路也顺带走一遍：这里 2 由 Default() 给，与版本块无关，
	// 但它是实际的升级路径，要保证两条路的结果一致。
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(`{"version":7,"panel":{"listen":"0.0.0.0","port":25666}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	manager := NewManager(path)
	if err := manager.Load(); err != nil {
		t.Fatal(err)
	}
	if got := manager.Get().Webhook.SourceRetainMB; got != DefaultSourceRetainMB {
		t.Fatalf("v7 配置装载后留存额度是 %d MB，期望默认值 %d MB", got, DefaultSourceRetainMB)
	}
}

// TestMigrateFillsSessionIdleDefault 验证 v9 升级：会话新增「闲置超时」
// （auth.sessionIdleMinutes），旧配置与旧备份里都没有这个键。
//
// 与上面 v8 那条同构，理由也一样：0 在这个字段上是「不启用」这个有效选择、不是「没填」，
// 所以必须靠版本块补默认值，不能让下面的 clamp 去猜。要盯的同样是**导入**这条路——
// 从磁盘装载时 30 是 Default() 给的，删掉版本块也照样是 30，拿它当断言什么都没钉住；
// 而导入备份是往零值结构体里解，少了版本块就会静默把闲置超时关掉，
// 设置页上只显示一个 0，看不出发生过什么。
//
// 反方向同样要钉：已经是当前版本、且明确写着 0 的配置，任何一次迁移都不能改回 30。
func TestMigrateFillsSessionIdleDefault(t *testing.T) {
	migrated := func(t *testing.T, data string) *Config {
		t.Helper()
		var c Config
		if err := json.Unmarshal([]byte(data), &c); err != nil {
			t.Fatal(err)
		}
		Migrate(&c)
		return &c
	}

	// 旧备份：连 auth 这一段都没有，更没有 sessionIdleMinutes 这个键。
	cfg := migrated(t, `{"version":8,"panel":{"listen":"0.0.0.0","port":25666}}`)
	if cfg.Auth.SessionIdleMinutes != DefaultSessionIdleMinutes {
		t.Fatalf("v8 备份迁上来后闲置超时是 %d 分钟，期望默认值 %d 分钟——"+
			"导入把闲置超时静默关掉了", cfg.Auth.SessionIdleMinutes, DefaultSessionIdleMinutes)
	}
	if cfg.Version != CurrentVersion {
		t.Fatalf("版本号应升到 %d，实际 %d", CurrentVersion, cfg.Version)
	}

	// 已经是当前版本、且用户明确选了不启用：迁多少次都得是 0。
	off := migrated(t, `{"version":`+strconv.Itoa(CurrentVersion)+`,"panel":{"listen":"0.0.0.0","port":25666},`+
		`"auth":{"sessionHours":1,"sessionIdleMinutes":0}}`)
	if off.Auth.SessionIdleMinutes != 0 {
		t.Fatalf("用户选的「不启用」被改成了 %d 分钟：0 在这个字段上是有效取值，不是没填",
			off.Auth.SessionIdleMinutes)
	}
	Migrate(off)
	if off.Auth.SessionIdleMinutes != 0 {
		t.Fatalf("二次迁移把「不启用」改成了 %d 分钟", off.Auth.SessionIdleMinutes)
	}

	// 从磁盘装载这条路也走一遍：30 由 Default() 给，与版本块无关，
	// 但它是实际的升级路径，要保证两条路的结果一致。
	path2 := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path2, []byte(`{"version":8,"panel":{"listen":"0.0.0.0","port":25666}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	m2 := NewManager(path2)
	if err := m2.Load(); err != nil {
		t.Fatal(err)
	}
	if got := m2.Get().Auth.SessionIdleMinutes; got != DefaultSessionIdleMinutes {
		t.Fatalf("v8 配置装载后闲置超时是 %d 分钟，期望默认值 %d 分钟", got, DefaultSessionIdleMinutes)
	}
}

// TestMigrateClampsSessionIdle 验证越界的闲置超时被收拢：手改 config.json、
// 导入外部备份都可能带进负数或天文数字，而这个数直接决定会话多久作废。
//
// 关键一条是 -1 必须落到 0（不启用）而不是被翻译成默认值：把非法值当成「没填」，
// 用户就再也关不掉它了。上限与登录锁定时长同取 30 天。
func TestMigrateClampsSessionIdle(t *testing.T) {
	for _, tc := range []struct{ in, want int }{
		{in: -1, want: 0},         // 负数按「不启用」处理，不翻译成默认值
		{in: 0, want: 0},          // 0 原样留着：它是有效取值
		{in: 30, want: 30},        // 正常值不动
		{in: 999999, want: 43200}, // 往上夹到 30 天
	} {
		// 版本给足，避开 v9 版本块——这里要验的是 clamp 本身。
		c := &Config{Version: CurrentVersion, Auth: Auth{SessionIdleMinutes: tc.in}}
		Migrate(c)
		if got := c.Auth.SessionIdleMinutes; got != tc.want {
			t.Errorf("闲置超时 %d 规范化成 %d，期望 %d", tc.in, got, tc.want)
		}
	}
}

// TestNormalizeClampsSourceRetain 验证越界的留存额度被收拢：手改配置与导入旧备份
// 都可能带着任意数字进来，而这个数直接决定内存占用。
func TestNormalizeClampsSourceRetain(t *testing.T) {
	for _, tc := range []struct{ in, want int }{
		{in: 99, want: MaxSourceRetainMB}, // 往上夹：这是内存额度，不能由一个手打的数字决定
		{in: -5, want: 0},                 // 负数按「不留存」处理，而不是翻译成默认值
		{in: 0, want: 0},                  // 0 原样留着：它是有效取值
		{in: MaxSourceRetainMB, want: MaxSourceRetainMB},
	} {
		c := &Config{Webhook: WebhookServer{Port: DefaultWebhookPort, SourceRetainMB: tc.in}}
		normalizeWebhook(c)
		if got := c.Webhook.SourceRetainMB; got != tc.want {
			t.Errorf("额度 %d 规范化成 %d，期望 %d", tc.in, got, tc.want)
		}
		// 幂等：migrate 每次 Load 与每次 Replace 都会跑一遍。
		normalizeWebhook(c)
		if got := c.Webhook.SourceRetainMB; got != tc.want {
			t.Errorf("额度 %d 二次规范化被改成 %d，期望保持 %d", tc.in, got, tc.want)
		}
	}
}

func TestMigrateWOLClampsAndIsIdempotent(t *testing.T) {
	c := &Config{WOLDevices: []WOLDevice{
		// 旧「范围内均匀 5 次」→ 每 9000 秒一个包。
		{Schedule: WOLSchedule{Enabled: true, Mode: "range", Start: "08:00", End: "18:00", Count: 5, IntervalSec: 5}},
		// 固定时间：次数夹到上限，间隔不参与该模式、原样保留。
		{Schedule: WOLSchedule{Enabled: true, Mode: "fixed", Time: "08:00", Count: 1_000_000, IntervalSec: 7}},
		// 旧「范围内 1 次」= 只在 Start 发一次 → 间隔取「跨度+1」，使范围内只命中 Start 这一拍。
		{Schedule: WOLSchedule{Enabled: true, Mode: "range", Start: "08:00", End: "18:00", Count: 1, IntervalSec: 5}},
		// 时间字段非法：间隔回退 1 秒（调度器对非法时间本就当天不发送）。
		{Schedule: WOLSchedule{Enabled: true, Mode: "range", Start: "bad", End: "18:00", Count: 3}},
		// 负数间隔归零，避免把负值带进调度器。
		{Schedule: WOLSchedule{Enabled: true, Mode: "fixed", Time: "09:00", Count: 2, IntervalSec: -10}},
	}}
	migrateWOL(c)

	want := []WOLSchedule{
		{Enabled: true, Mode: "range", Start: "08:00", End: "18:00", Count: 0, IntervalSec: 9000},
		{Enabled: true, Mode: "fixed", Time: "08:00", Count: MaxWOLWakeCount, IntervalSec: 7},
		{Enabled: true, Mode: "range", Start: "08:00", End: "18:00", Count: 0, IntervalSec: 36001},
		{Enabled: true, Mode: "range", Start: "bad", End: "18:00", Count: 0, IntervalSec: 1},
		{Enabled: true, Mode: "fixed", Time: "09:00", Count: 2, IntervalSec: 0},
	}
	for i := range want {
		if got := c.WOLDevices[i].Schedule; got != want[i] {
			t.Fatalf("设备 %d 迁移结果为 %+v，期望 %+v", i, got, want[i])
		}
	}

	// 再跑一遍不应有任何改动。
	migrateWOL(c)
	for i := range want {
		if got := c.WOLDevices[i].Schedule; got != want[i] {
			t.Fatalf("设备 %d 二次迁移后被改动为 %+v，期望保持 %+v", i, got, want[i])
		}
	}
}
