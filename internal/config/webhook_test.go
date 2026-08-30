package config

import (
	"path/filepath"
	"strings"
	"testing"
)

// 这些常量同时充当测试数据与"明文有没有漏进 config.json"的搜索串。
const (
	testHookToken    = "hook-token-明文不得落盘-1A2B"
	testDingURL      = "https://oapi.dingtalk.com/robot/send?access_token=明文不得落盘-3C4D"
	testDingSecret   = "SEC明文不得落盘-5E6F"
	testNotifyHeader = "Bearer 明文不得落盘-7G8H"
)

// newWebhookTestManager 建一个带接收器与通知目标的实例。
func newWebhookTestManager(t *testing.T) (*Manager, string) {
	t.Helper()
	t.Setenv(masterKeyEnv, "")
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	manager := NewManager(path)
	if err := manager.Load(); err != nil {
		t.Fatal(err)
	}
	if err := manager.Update(func(cfg *Config) {
		cfg.WebhookReceivers = []WebhookReceiver{{
			ID:       "recv1",
			Name:     "第三方系统",
			Enabled:  true,
			Path:     "abcdef",
			AuthType: "token",
			Token:    testHookToken,
		}}
		cfg.NotifyTargets = []NotifyTarget{{
			ID:      "tg1",
			Name:    "企业钉钉群",
			Enabled: true,
			Type:    "dingtalk",
			URL:     testDingURL,
			Secret:  testDingSecret,
			Headers: map[string]string{"Authorization": testNotifyHeader},
		}}
	}); err != nil {
		t.Fatal(err)
	}
	return manager, path
}

// 核心断言：入站令牌、机器人地址、加签密钥与自定义请求头都不得以明文落盘，
// 而内存中必须仍是明文——否则投递时带出去的就是一段 enc:v1: 文本。
func TestWebhookSecretsEncryptedAndMemoryPlaintext(t *testing.T) {
	manager, path := newWebhookTestManager(t)

	raw := readRaw(t, path)
	for _, secret := range []string{testHookToken, testDingURL, testDingSecret, testNotifyHeader} {
		if strings.Contains(raw, secret) {
			t.Fatalf("敏感值以明文出现在 config.json 中: %q", secret)
		}
	}
	// Name / Type 保持明文：URL 整段加密之后，排障只能靠这两个字段定位条目。
	if !strings.Contains(raw, "企业钉钉群") || !strings.Contains(raw, "dingtalk") {
		t.Fatalf("通知目标的名称与类型应保持明文以便排障")
	}

	cfg := manager.Get()
	if cfg.WebhookReceivers[0].Token != testHookToken {
		t.Fatalf("内存中的入站令牌不是明文: %q", cfg.WebhookReceivers[0].Token)
	}
	if cfg.NotifyTargets[0].URL != testDingURL {
		t.Fatalf("内存中的机器人地址不是明文: %q", cfg.NotifyTargets[0].URL)
	}
	if cfg.NotifyTargets[0].Secret != testDingSecret {
		t.Fatalf("内存中的加签密钥不是明文")
	}
	if cfg.NotifyTargets[0].Headers["Authorization"] != testNotifyHeader {
		t.Fatalf("内存中的请求头不是明文: %q", cfg.NotifyTargets[0].Headers["Authorization"])
	}
}

// NotifyTarget.Headers 是 map（引用类型）：configForDisk 漏了克隆就会把内存中的请求头
// 原地换成密文，之后每次投递都带着一段 enc:v1: 出去，直到进程重启才恢复正常。
// 连续保存多次后重新加载，必须还能还原出原始明文（若被就地改动，这里会拿到二次加密的结果）。
func TestRepeatedSavesDoNotCorruptWebhookSecrets(t *testing.T) {
	manager, path := newWebhookTestManager(t)
	for i := 0; i < 3; i++ {
		if err := manager.Update(func(cfg *Config) { cfg.Update.About = strings.Repeat("x", i+1) }); err != nil {
			t.Fatal(err)
		}
		cfg := manager.Get()
		if got := cfg.NotifyTargets[0].Headers["Authorization"]; got != testNotifyHeader {
			t.Fatalf("第 %d 次保存后内存请求头被改动: %q", i+1, got)
		}
		if got := cfg.NotifyTargets[0].URL; got != testDingURL {
			t.Fatalf("第 %d 次保存后内存机器人地址被改动: %q", i+1, got)
		}
		if got := cfg.WebhookReceivers[0].Token; got != testHookToken {
			t.Fatalf("第 %d 次保存后内存入站令牌被改动: %q", i+1, got)
		}
	}

	t.Setenv(masterKeyEnv, "")
	reloaded := NewManager(path)
	if err := reloaded.Load(); err != nil {
		t.Fatal(err)
	}
	cfg := reloaded.Get()
	if cfg.NotifyTargets[0].Headers["Authorization"] != testNotifyHeader {
		t.Fatalf("重新加载后请求头不一致: %q", cfg.NotifyTargets[0].Headers["Authorization"])
	}
	if cfg.NotifyTargets[0].URL != testDingURL || cfg.NotifyTargets[0].Secret != testDingSecret {
		t.Fatalf("重新加载后通知目标凭证不一致")
	}
	if cfg.WebhookReceivers[0].Token != testHookToken {
		t.Fatalf("重新加载后入站令牌不一致")
	}
}

// 这里原先还有一个 TestWebhookRuntimeStateStaysOutOfConfigFile：它钉的是「通知目标的
// 投递条数与最近状态只进 state.json，不进 config.json」。那个性质现在被一个更强的用例
// 取代了——TestNotifyAndWakeStatsNeverReachDisk 要求这些数**两个文件都不进**，
// 只在内存里（见 internal/runstats）。留着旧用例就得给结构体留回那些字段，
// 而字段留着才是问题本身。

// 规范化必须幂等：migrate 在每次 Load 与每次 Replace 时都会跑，
// 同一份配置被反复规范化的结果必须完全一致（否则会出现"每次保存都产生一次无谓落盘"）。
func TestNormalizeWebhookIsIdempotent(t *testing.T) {
	cfg := &Config{
		Webhook: WebhookServer{Enabled: true, Port: 0, HTTPS: WebhookHTTPS{Enabled: true, Domain: " HOOK.Example.COM "}},
		WebhookReceivers: []WebhookReceiver{{
			ID:           "r1",
			Name:         "  来源  ",
			Path:         "/hook//abc/",
			Token:        "  t  ",
			RateLimit:    -5,
			MaxBodyKB:    99999,
			IPFilterMode: "白名单",
			AllowIPs:     []string{" 10.0.0.1 ", "", "  "},
			RootPath:     ".body.",
			SourceType:   "  TXT  ",
			Mappings:     []FieldMapping{{Name: " 消息类型 ", Path: " .body.biz "}},
			Rules: []WebhookRule{{
				ID:         "ru1",
				Match:      "",
				Conditions: []Condition{{Path: " .body.biz. ", Op: " EQ "}},
				Targets:    []string{" tg1 ", ""},
			}},
		}},
		NotifyTargets: []NotifyTarget{{
			ID:         "tg1",
			Type:       " DingTalk ",
			Method:     " put ",
			TimeoutSec: 0,
			Retry:      99,
			Headers:    map[string]string{"  X-A  ": "v", "": "dropped"},
			AtMobiles:  []string{" 138 ", ""},
		}},
		MessageTemplates: []MessageTemplate{{ID: "t1", Name: " 模板 ", Format: "html"}},
	}
	normalizeWebhook(cfg)
	first := *cfg
	firstRecv := cfg.WebhookReceivers[0]
	firstTarget := cfg.NotifyTargets[0]

	// 逐项确认规范化结果，而不是只比"跑两遍一样"——后者对"什么都没做"也成立。
	if cfg.Webhook.Port != DefaultWebhookPort {
		t.Fatalf("端口未回落默认值: %d", cfg.Webhook.Port)
	}
	// 域名从 https 里上移到了模块级（端口 80 共享时没有 HTTPS 也要靠域名分流），
	// normalizeWebhook 负责把旧字段折上去并清空，否则两处各存一份、谁说了算说不清。
	if cfg.Webhook.Domain != "hook.example.com" {
		t.Fatalf("域名未规范化: %q", cfg.Webhook.Domain)
	}
	if cfg.Webhook.HTTPS.Domain != "" {
		t.Fatalf("旧的 https.domain 应被清空，实际 %q", cfg.Webhook.HTTPS.Domain)
	}
	// 启用了 HTTPS 却没选证书：必须回落成明文，否则 TLS 监听拿不到证书会让所有来源静默失联。
	if cfg.Webhook.HTTPS.Enabled {
		t.Fatalf("未选证书时 HTTPS 应回落为关闭")
	}
	if firstRecv.Path != "hook/abc" {
		t.Fatalf("入站路径未折叠重复斜杠: %q", firstRecv.Path)
	}
	if firstRecv.AuthType != "token" {
		t.Fatalf("填了令牌却未按 token 处理: %q", firstRecv.AuthType)
	}
	if firstRecv.RateLimit != 0 || firstRecv.MaxBodyKB != MaxWebhookBodyKB {
		t.Fatalf("限流/体积上限未夹进区间: %d %d", firstRecv.RateLimit, firstRecv.MaxBodyKB)
	}
	if firstRecv.IPFilterMode != "deny" {
		t.Fatalf("认不出的过滤模式应归为黑名单: %q", firstRecv.IPFilterMode)
	}
	if len(firstRecv.AllowIPs) != 1 || firstRecv.AllowIPs[0] != "10.0.0.1" {
		t.Fatalf("IP 名单未整理: %+v", firstRecv.AllowIPs)
	}
	if firstRecv.RootPath != "body" || firstRecv.Mappings[0].Path != "body.biz" {
		t.Fatalf("取值路径未去掉首尾点号: %q %q", firstRecv.RootPath, firstRecv.Mappings[0].Path)
	}
	// 算子只去空白、不转小写：清单里有 notContains、countGt 这类驼峰名，
	// 一律小写会让它们通不过保存校验。大小写容错在 webhook.CanonicalOperator。
	if firstRecv.Rules[0].Match != "all" || firstRecv.Rules[0].Conditions[0].Op != "EQ" {
		t.Fatalf("规则未规范化: %+v", firstRecv.Rules[0])
	}
	if firstRecv.SourceType != "txt" {
		t.Fatalf("来源消息类型未规范化: %q", firstRecv.SourceType)
	}
	if firstTarget.Method != "PUT" || firstTarget.ContentType != "application/json" {
		t.Fatalf("HTTP 目标未规范化: %q %q", firstTarget.Method, firstTarget.ContentType)
	}
	if firstTarget.TimeoutSec != DefaultNotifyTimeoutSec || firstTarget.Retry != MaxNotifyRetry {
		t.Fatalf("超时/重试未夹进区间: %d %d", firstTarget.TimeoutSec, firstTarget.Retry)
	}
	if _, ok := firstTarget.Headers[""]; ok {
		t.Fatalf("空请求头名应被丢弃")
	}
	if _, ok := firstTarget.Headers["X-A"]; !ok {
		t.Fatalf("请求头名未去空白: %+v", firstTarget.Headers)
	}
	if cfg.MessageTemplates[0].Format != "text" {
		t.Fatalf("认不出的模板格式应归为 text: %q", cfg.MessageTemplates[0].Format)
	}

	normalizeWebhook(cfg)
	if cfg.Webhook != first.Webhook {
		t.Fatalf("模块级设置不幂等: %+v → %+v", first.Webhook, cfg.Webhook)
	}
	if cfg.WebhookReceivers[0].Path != firstRecv.Path {
		t.Fatalf("入站路径不幂等: %q → %q", firstRecv.Path, cfg.WebhookReceivers[0].Path)
	}
	if cfg.NotifyTargets[0].Method != firstTarget.Method || cfg.NotifyTargets[0].Retry != firstTarget.Retry {
		t.Fatalf("通知目标不幂等")
	}
}

// 路径为空的接收器永远收不到消息，且会与模块根冲撞：必须补一个随机路径。
func TestNormalizeWebhookFillsEmptyPath(t *testing.T) {
	cfg := &Config{WebhookReceivers: []WebhookReceiver{{ID: "r1"}, {ID: "r2", Path: "  /  "}}}
	normalizeWebhook(cfg)
	for _, r := range cfg.WebhookReceivers {
		if len(r.Path) != WebhookPathLen {
			t.Fatalf("接收器 %s 未补上随机路径: %q", r.ID, r.Path)
		}
	}
	if cfg.WebhookReceivers[0].Path == cfg.WebhookReceivers[1].Path {
		t.Fatalf("两条随机路径相同，随机源可能未生效")
	}
}

// 「已创建」与「已启用」不是同义词，但组合有限：启用中必然已创建。
// 这条折叠兜的是手改配置与旧配置——反过来（未创建却启用）会让模块设置那一页
// 显示"未创建"、端口上却真的在监听。
func TestNormalizeWebhookEnabledImpliesCreated(t *testing.T) {
	cfg := &Config{Webhook: WebhookServer{Enabled: true, Port: DefaultWebhookPort}}
	normalizeWebhook(cfg)
	if !cfg.Webhook.Created {
		t.Fatal("启用中的模块必然是已创建的")
	}
	// 反向不成立：创建了但没启用是完全正常的状态（配好了先不上线）。
	cfg = &Config{Webhook: WebhookServer{Created: true, Port: DefaultWebhookPort}}
	normalizeWebhook(cfg)
	if cfg.Webhook.Enabled {
		t.Fatal("创建不等于启用，不该自动把开关打开")
	}
}

// 模块没创建就没有监听、没有域名、没有可访问的地址：此时一个"启用中"的接收器
// 是纯粹的假象。接口层会拦下这种保存，这一句兜的是手改配置与导入。
func TestNormalizeWebhookDisablesReceiversWithoutModule(t *testing.T) {
	cfg := &Config{WebhookReceivers: []WebhookReceiver{
		{ID: "r1", Path: "hook", Enabled: true},
		{ID: "r2", Path: "hook2", Enabled: false},
	}}
	normalizeWebhook(cfg)
	for _, r := range cfg.WebhookReceivers {
		if r.Enabled {
			t.Fatalf("模块未创建时接收器 %s 不该是启用的", r.ID)
		}
	}
	// 配置本身**不动**：删掉模块不该顺手把接收器的配置也改了，只是不让它跑。
	if len(cfg.WebhookReceivers) != 2 {
		t.Fatalf("接收器不该被删掉：%d 个", len(cfg.WebhookReceivers))
	}

	// 模块建起来之后照原样启用——这正是"创建模块 → 接收器就能启用"那条路。
	cfg.Webhook.Created = true
	cfg.WebhookReceivers[0].Enabled = true
	normalizeWebhook(cfg)
	if !cfg.WebhookReceivers[0].Enabled {
		t.Fatal("模块已创建时不该再拦启用")
	}
}

// 来源消息类型认不出来时回到自动识别，而不是钉死成 json：
// 老配置里没有这个字段（留空），而"选死一种"正是那次 JSON 被按符号拆坏的起因。
func TestNormalizeReceiverSourceTypeDefaultsToAuto(t *testing.T) {
	for _, in := range []string{"", "   ", "xml", "JSON5"} {
		r := WebhookReceiver{Path: "hook", SourceType: in}
		NormalizeReceiver(&r)
		if r.SourceType != "auto" {
			t.Errorf("SourceType %q 应规范化成 auto，实际 %q", in, r.SourceType)
		}
	}
	// 四个正常值都要原样保留（大小写与空白照旧规范化）。
	for in, want := range map[string]string{" AUTO ": "auto", "json": "json", " KV ": "kv", "txt": "txt"} {
		r := WebhookReceiver{Path: "hook", SourceType: in}
		NormalizeReceiver(&r)
		if r.SourceType != want {
			t.Errorf("SourceType %q 应是 %q，实际 %q", in, want, r.SourceType)
		}
	}
}

// 字段映射名要直接出现在 {{.名字}} 里：空格、点号这类字符会让模板在解析期就失败，
// 必须在保存时拦下来，而不是等第一条消息进来才报错。汉字是合法的（text/template 用 unicode.IsLetter）。
func TestValidMappingName(t *testing.T) {
	ok := []string{"消息类型", "bizType", "biz_type", "_x", "消息编号2"}
	bad := []string{"", "业务 类型", "biz.type", "biz-type", "2biz", "biz(1)", strings.Repeat("字", 65)}
	for _, s := range ok {
		if !ValidMappingName(s) {
			t.Fatalf("%q 应被接受", s)
		}
	}
	for _, s := range bad {
		if ValidMappingName(s) {
			t.Fatalf("%q 应被拒绝", s)
		}
	}
}

// WebhookSharesWebServicePort 是**双方共用的唯一判据**：消息路由据此决定不绑端口、
// Web 服务据此决定多挂一条 Host 路由。它多算一次 = 端口没人监听（双方都以为对方绑），
// 少算一次 = 端口被抢（双方都绑，后绑的失败）。两种都是静默失联，所以逐个前提钉一条。
func TestWebhookSharesWebServicePort(t *testing.T) {
	// base 一份"正好成立"的配置：模块开着、有域名、端口上有个会起监听的 Web 服务。
	base := func() *Config {
		return &Config{
			Panel: Panel{Port: 25666},
			Webhook: WebhookServer{Enabled: true, Port: 443, Domain: "hook.example.com",
				HTTPS: WebhookHTTPS{Enabled: true, CertID: "c1"}},
			WebServices: []WebService{{ID: "ws1", Name: "官网", Enabled: true, Port: 443,
				Children: []WebChild{{ID: "ch1", Enabled: true, TLS: true,
					Domains: []string{"www.example.com"}}}}},
		}
	}
	if !base().WebhookSharesWebServicePort() {
		t.Fatal("前置条件：这份配置本应判定为共用")
	}

	cases := []struct {
		name string
		mut  func(*Config)
	}{
		{"模块关闭", func(c *Config) { c.Webhook.Enabled = false }},
		// 手改配置文件把域名删了也不能共用：域名是这条监听上唯一的分流依据。
		{"没有域名", func(c *Config) { c.Webhook.Domain = "" }},
		{"端口不同", func(c *Config) { c.Webhook.Port = 8443 }},
		{"Web 服务父项停用", func(c *Config) { c.WebServices[0].Enabled = false }},
		// 子项全关的父项不产生监听（见 webservice.Reload），那个端口是空着的，
		// 该由消息路由自己绑——判成共用就等于没人监听。
		{"子项全部停用", func(c *Config) { c.WebServices[0].Children[0].Enabled = false }},
		{"没有子项", func(c *Config) { c.WebServices[0].Children = nil }},
		// 撞面板端口时 Web 服务自己会跳过启动，同样不存在可共享的监听。
		{"撞面板端口", func(c *Config) { c.Panel.Port, c.Webhook.Port = 443, 443 }},
		{"端口为零", func(c *Config) { c.Webhook.Port = 0 }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := base()
			tc.mut(cfg)
			if cfg.WebhookSharesWebServicePort() {
				t.Fatal("不应判定为共用监听")
			}
		})
	}

	// nil 接收者：Snapshot 在极早期可能还没有配置，判据不能因此 panic。
	var nilCfg *Config
	if nilCfg.WebhookSharesWebServicePort() {
		t.Fatal("nil 配置不应判定为共用")
	}
}

// WebServiceListenerOnPort 回的 name / tlsOn 直接进用户看到的报错文案与协议一致性校验，
// 取错等于把用户指向另一个服务、或者放过一个 HTTP/HTTPS 混用的配置。
func TestWebServiceListenerOnPort(t *testing.T) {
	cfg := &Config{WebServices: []WebService{
		// 同端口上先摆一个不起监听的父项：查找必须跳过它，继续往后找。
		{ID: "ws0", Name: "空壳", Enabled: true, Port: 443},
		{ID: "ws1", Name: "官网", Enabled: true, Port: 443, Children: []WebChild{
			{ID: "ch0", Enabled: false, TLS: false},
			{ID: "ch1", Enabled: true, TLS: true},
		}},
		{ID: "ws2", Name: "内网", Enabled: true, Port: 8080, Children: []WebChild{
			{ID: "ch2", Enabled: true, TLS: false},
		}},
	}}

	name, tlsOn, ok := cfg.WebServiceListenerOnPort(443, "")
	if !ok || name != "官网" || !tlsOn {
		t.Fatalf("443 应回官网+TLS，实际 %q tls=%v ok=%v", name, tlsOn, ok)
	}
	// TLS 取的是首个**启用**子项：把停用子项算进来会得出相反的协议结论。
	if _, tlsOn, ok = cfg.WebServiceListenerOnPort(8080, ""); !ok || tlsOn {
		t.Fatalf("8080 应回非 TLS，实际 tls=%v ok=%v", tlsOn, ok)
	}
	if _, _, ok = cfg.WebServiceListenerOnPort(9999, ""); ok {
		t.Fatal("没有服务的端口不该报占用")
	}
	if _, _, ok = cfg.WebServiceListenerOnPort(0, ""); ok {
		t.Fatal("端口 0 不该报占用")
	}
	// 没填地址族 = 双栈，谁来问都招待得到。
	if _, _, ok = cfg.WebServiceListenerOnPort(443, "v4"); !ok {
		t.Fatal("双栈监听应能招待 IPv4")
	}
}

// 地址族必须参与判断：一个 IPv6-only 的 Web 服务不该让纯 IPv4 的消息路由以为
// 端口已经有人监听——那会让消息路由不绑自己的监听，全部来源静默失联。
func TestWebServiceListenerOnPortFamily(t *testing.T) {
	v6Only := &Config{WebServices: []WebService{
		{ID: "ws1", Name: "内网 v6", Enabled: true, Port: 443, IPFamily: "v6", Children: []WebChild{
			{ID: "ch1", Enabled: true, TLS: true},
		}},
	}}
	if _, _, ok := v6Only.WebServiceListenerOnPort(443, "v4"); ok {
		t.Fatal("IPv6-only 的监听不该算占用了 IPv4 那一侧")
	}
	if _, _, ok := v6Only.WebServiceListenerOnPort(443, "v6"); !ok {
		t.Fatal("IPv6-only 的监听应占用 IPv6 那一侧")
	}
	if _, _, ok := v6Only.WebServiceListenerOnPort(443, ""); !ok {
		t.Fatal("不限地址族时应算占用")
	}
	// 消息路由固定绑 0.0.0.0，于是它面对 IPv6-only 的 Web 服务时必须自己绑端口。
	v6Only.Webhook = WebhookServer{Enabled: true, Created: true, Port: 443, Listen: "0.0.0.0", Domain: "hook.example.com"}
	if v6Only.WebhookSharesWebServicePort() {
		t.Fatal("地址族对不上时不该判定为共用")
	}
	if fam := v6Only.WebhookListenFamily(); fam != "v4" {
		t.Fatalf("0.0.0.0 应判为 v4，实际 %q", fam)
	}

	// 同端口上并存 v4 与 both 两个父项时，取地址族完全相同的那个，
	// 结果不能随父项在列表里的先后变化。
	for _, order := range [][]WebService{
		{
			{ID: "a", Name: "双栈", Enabled: true, Port: 8080, IPFamily: "both", Children: []WebChild{{ID: "c1", Enabled: true}}},
			{ID: "b", Name: "仅 v4", Enabled: true, Port: 8080, IPFamily: "v4", Children: []WebChild{{ID: "c2", Enabled: true}}},
		},
		{
			{ID: "b", Name: "仅 v4", Enabled: true, Port: 8080, IPFamily: "v4", Children: []WebChild{{ID: "c2", Enabled: true}}},
			{ID: "a", Name: "双栈", Enabled: true, Port: 8080, IPFamily: "both", Children: []WebChild{{ID: "c1", Enabled: true}}},
		},
	} {
		cfg := &Config{WebServices: order}
		if name, _, ok := cfg.WebServiceListenerOnPort(8080, "v4"); !ok || name != "仅 v4" {
			t.Fatalf("应优先取地址族相同的父项，实际 %q ok=%v", name, ok)
		}
	}
}

// FamilyServes 是"端口能不能共用"的唯一判据，错一格就是端口被抢或者没人监听。
func TestFamilyServes(t *testing.T) {
	cases := []struct {
		listener, want string
		ok             bool
	}{
		{"both", "v4", true},
		{"both", "v6", true},
		{"both", "both", true},
		{"v4", "v4", true},
		{"v4", "v6", false},
		{"v4", "both", false},
		{"v6", "v6", true},
		{"v6", "v4", false},
		{"", "v4", true},    // 空串按双栈
		{"v4", "", false},   // 空串按双栈：v4 监听招待不到 IPv6
		{"垃圾值", "v4", true}, // 未知取值按双栈，不会把该起的监听判成起不来
	}
	for _, c := range cases {
		if got := FamilyServes(c.listener, c.want); got != c.ok {
			t.Fatalf("FamilyServes(%q, %q) = %v，期望 %v", c.listener, c.want, got, c.ok)
		}
	}
}
