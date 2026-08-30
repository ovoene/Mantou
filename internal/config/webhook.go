package config

import (
	"crypto/rand"
	"encoding/hex"
	"net"
	"strings"
)

// 本文件是消息路由（Webhook → 规则 → 模板 → 通知）配置的**规范化**入口。
//
// 为什么规范化必须在加载期做一遍，而不只在 API 保存时做：
// config.json 有三条写入路径——面板 API、整份导入（Replace）、以及用户手工编辑。
// 只在 API 侧兜底，等于把"手改配置"和"导入旧备份"这两条路上的非法值直接放进运行态；
// 而这个模块的非法值代价很实在：一个空的入站路径会让接收器永远收不到消息、
// 一个 0 的体积上限会让每条请求都被拒收，而界面上看不出任何异常。
//
// 这里的每一项都必须**幂等**：migrate 在每次 Load 与每次 Replace 时都会跑，
// 同一份配置被反复规范化的结果必须完全一致（见 store.go 的 migrate 说明）。

// RandomWebhookPath 生成一个不可枚举的随机入站路径（WebhookPathLen 个 hex 字符）。
//
// 随机源失败时退回一个带固定前缀的短路径而不是空串：空路径会让接收器落在模块根上、
// 与其它接收器互相冲撞，是比"路径熵不足"严重得多的故障。随机源在实践中不会失败，
// 这里只是不让一个理论上的错误变成静默的功能损坏。
func RandomWebhookPath() string {
	b := make([]byte, WebhookPathLen/2)
	if _, err := rand.Read(b); err != nil {
		return "hook-" + randomHex(4)
	}
	return hex.EncodeToString(b)
}

// NormalizeWebhookPath 规范化入站路径：去空白、去首尾斜杠、折叠重复斜杠。
//
// 折叠重复斜杠是必要的：用户很容易粘进 "/hook//abc"，而 net/http 的路由会把它
// 与 "/hook/abc" 当成两条不同的路径，于是"配置里明明有这条路径却 404"。
// 返回空串表示原值不含任何有效字符，由调用方决定是补随机值还是报错。
func NormalizeWebhookPath(p string) string {
	p = strings.TrimSpace(p)
	p = strings.Trim(p, "/")
	if p == "" {
		return ""
	}
	parts := strings.Split(p, "/")
	kept := make([]string, 0, len(parts))
	for _, seg := range parts {
		seg = strings.TrimSpace(seg)
		if seg != "" {
			kept = append(kept, seg)
		}
	}
	return strings.Join(kept, "/")
}

// ClampSourceRetainMB 把原文留存额度收进 [0, MaxSourceRetainMB]。
//
// 负数按 0（不留存）处理而不是按默认值：手改出一个负数，意思显然是"别留"，
// 而把它翻译成 2 MB 会让这些内容悄悄进内存。
//
// 单独拿出来是因为有两条路会写这个字段：配置从磁盘来时走 normalizeWebhook，
// 界面上保存时走 API（api_webhook.go），而 API 的保存路径不经过 normalizeWebhook。
// 两处各写一遍夹取，迟早会漂成"从界面能存进一个从磁盘读不出的数"。
func ClampSourceRetainMB(mb int) int {
	if mb < 0 {
		return 0
	}
	if mb > MaxSourceRetainMB {
		return MaxSourceRetainMB
	}
	return mb
}

// normalizeWebhook 规范化整个消息路由配置。由 migrate 在版本块之后无条件调用。
func normalizeWebhook(c *Config) {
	// ---- 模块级监听 ----
	// 「已创建」与「已启用」的关系只在这里折一次，两个方向各有其必要：
	//
	//	enabled=true 而 created=false  手改配置最容易写出的形态。按 created 为准会得到
	//	                               一个"配置里开着、界面上却连那一行都没有"的模块，
	//	                               谁都看不出问题在哪，故认作已创建。
	//	created=false 而 enabled=true  同一件事的反面：未创建的模块不该真的去绑端口。
	//
	// 折的方向是"补上 created"而不是"抹掉 enabled"：后者会让升级/导入静默停掉一个
	// 正在收消息的模块，代价比多出一行要大得多。
	if c.Webhook.Enabled {
		c.Webhook.Created = true
	}
	// 监听地址固定 0.0.0.0（与面板同口径，不在 UI 暴露）。
	if c.Webhook.Listen == "" {
		c.Webhook.Listen = "0.0.0.0"
	}
	if c.Webhook.Port <= 0 || c.Webhook.Port > 65535 {
		c.Webhook.Port = DefaultWebhookPort
	}
	c.Webhook.HTTPS.CertID = strings.TrimSpace(c.Webhook.HTTPS.CertID)
	c.Webhook.Note = strings.TrimSpace(c.Webhook.Note)
	c.Webhook.SourceRetainMB = ClampSourceRetainMB(c.Webhook.SourceRetainMB)
	// 域名从 HTTPS 里上移到了模块级（端口 80 共享时没有 HTTPS 也要靠域名分流）。
	// 折叠而不是只在版本块里迁移一次：手改配置和导入旧备份都可能只带着旧字段进来。
	if c.Webhook.Domain == "" {
		c.Webhook.Domain = c.Webhook.HTTPS.Domain
	}
	c.Webhook.HTTPS.Domain = ""
	c.Webhook.Domain = strings.ToLower(strings.TrimSpace(c.Webhook.Domain))
	// 启用 HTTPS 但没填证书：这不是一个能"带着跑"的状态——TLS 监听拿不到证书会直接握手失败，
	// 表现为所有来源同时静默失联。宁可回落成明文并留下配置原样（证书 ID 仍是空），
	// 由界面上的红色提示与启动日志把问题指出来。
	if c.Webhook.HTTPS.Enabled && c.Webhook.HTTPS.CertID == "" {
		c.Webhook.HTTPS.Enabled = false
	}

	// ---- 接收器 ----
	for i := range c.WebhookReceivers {
		NormalizeReceiver(&c.WebhookReceivers[i])
		// 模块没创建就没有监听、没有域名、没有可访问的地址：此时一个"启用中"的接收器
		// 是纯粹的假象，它永远收不到消息，而列表上那个绿色开关会让人以为它在工作。
		// 界面与接口都拦着这种组合（删除模块要求先停掉全部接收器），这一句兜的是手改配置。
		if !c.Webhook.Created {
			c.WebhookReceivers[i].Enabled = false
		}
	}

	// ---- 通知目标 ----
	for i := range c.NotifyTargets {
		NormalizeNotifyTarget(&c.NotifyTargets[i])
	}

	// ---- 模板 ----
	for i := range c.MessageTemplates {
		NormalizeMessageTemplate(&c.MessageTemplates[i])
	}
}

// WebhookSharesWebServicePort 判断消息路由是否与某个 Web 服务共用同一个监听。
//
// 这个判据只能有这一处：消息路由据此决定「不自己绑端口」，Web 服务据此决定
// 「在自己的监听上多挂一条 Host 路由」。两边各写一份判断，只要有一处口径不同，
// 结果就是端口被抢（双方都绑，后绑的失败）或者根本没人监听（双方都以为对方在绑）。
func (c *Config) WebhookSharesWebServicePort() bool {
	if c == nil || !c.Webhook.Enabled || c.Webhook.Port <= 0 {
		return false
	}
	// 没有域名就没有分流依据，只能各自独占端口（保存期已强制填，这里防手改配置）。
	if c.Webhook.Domain == "" {
		return false
	}
	// 撞面板端口时 Web 服务自己会跳过启动（见 webservice.Reload），此时不存在可共享的监听。
	if c.Webhook.Port == c.Panel.Port {
		return false
	}
	_, _, ok := c.WebServiceListenerOnPort(c.Webhook.Port, c.WebhookListenFamily())
	return ok
}

// NormalizeIPFamily 归一化监听地址族。只有 v4 / v6 两个确定值，其余（空串、未知取值、
// 手改配置里的错别字）一律按双栈算——这是最宽的那个，不会让一个本该起来的监听被判成"起不来"。
//
// 全项目只该有这一处定义：webservice 按它分组建监听、config 按它判断端口能不能共用，
// 两边口径差一点，结果就是端口被抢或者根本没人监听。
func NormalizeIPFamily(f string) string {
	switch strings.TrimSpace(f) {
	case "v4", "v6":
		return strings.TrimSpace(f)
	default:
		return "both"
	}
}

// FamilyServes 判断绑在 listener 这个地址族上的监听，能不能替 want 那一侧收到请求。
//
// 依据是实际的绑定方式（见 webservice 的 bindTarget）：v4 → tcp4/0.0.0.0（只有 IPv4
// 能连上）、v6 → tcp6/[::]（只有 IPv6）、both → tcp/:port（双栈）。所以双栈的监听谁都
// 招待得了，而 v4 与 v6 各自只管自己那一半，互相替不了。
func FamilyServes(listener, want string) bool {
	l, w := NormalizeIPFamily(listener), NormalizeIPFamily(want)
	return l == "both" || l == w
}

// WebhookListenFamily 消息路由自己绑监听时会照顾到哪个地址族。
//
// 它没有地址族开关（界面上不暴露 Listen，规范化后固定 0.0.0.0），而 0.0.0.0 在 Go 里
// 绑出来的是**纯 IPv4** 监听——这一点是下面判断"能不能与 Web 服务共用端口"的前提，
// 所以从实际的绑定地址推，而不是写死一个 "v4"。
//
// 空串与 "0.0.0.0" 同义：模块起监听时会把空的补成 0.0.0.0（见 webhook.listenHost），
// 这里必须跟着它，否则一份还没规范化过的配置会被判成双栈，结论正好相反。
func (c *Config) WebhookListenFamily() string {
	if c == nil {
		return "v4"
	}
	switch host := strings.TrimSpace(c.Webhook.Listen); host {
	case "", "0.0.0.0":
		return "v4"
	case "::", "[::]":
		// IPv6 通配在 network="tcp" 下绑的是双栈。
		return "both"
	default:
		ip := net.ParseIP(strings.Trim(host, "[]"))
		switch {
		case ip == nil:
			return "both" // 填的是主机名：解析结果未知，按最宽的算
		case ip.To4() != nil:
			return "v4"
		default:
			return "v6"
		}
	}
}

// WebServiceListenerOnPort 返回占用该端口、且真的会起监听的 Web 服务父项名与该监听是否 TLS。
//
// 「真的会起监听」= 父项启用且至少有一个启用子项：父项开着但子项全关时 Reload 不会建监听
// （见 webservice.Reload 的 len(g.bindings) == 0 分支），那种端口是空着的，不算占用。
// TLS 取首个启用子项的设置——同端口下启用子项的 TLS 必须一致，这由 validateWebService 保证。
//
// family 是要与它共存的那一侧的地址族，只有能招待到这一族的监听才算命中（见 FamilyServes）。
// 传空串表示不限，用于"这个端口上还有别人吗"这类纯排查用途。
//
// 地址族必须参与判断：同一个端口上可以并存一个 v4 父项与一个 v6 父项（唯一性约束是
// (端口, 地址族)），而消息路由是纯 IPv4 的。不看地址族的话，一个 IPv6-only 的 Web 服务
// 就会让消息路由认为"端口已经有人监听了，我挂条域名路由就行"，于是它不绑自己的
// IPv4 监听——结果是全部来源静默失联，而两个模块的状态都是绿的。
func (c *Config) WebServiceListenerOnPort(port int, family string) (name string, tlsOn bool, ok bool) {
	if c == nil || port <= 0 {
		return "", false, false
	}
	want := ""
	if strings.TrimSpace(family) != "" {
		want = NormalizeIPFamily(family)
	}
	// 命中多个时（同端口上并存 v4 与 both 两个父项）优先取地址族完全相同的那个，
	// 让结果只由配置内容决定，不受父项在列表里的先后影响。
	var fallback struct {
		name  string
		tlsOn bool
		ok    bool
	}
	for _, ws := range c.WebServices {
		if !ws.Enabled || ws.Port != port {
			continue
		}
		fam := NormalizeIPFamily(ws.IPFamily)
		if want != "" && !FamilyServes(fam, want) {
			continue
		}
		for _, ch := range ws.Children {
			if !ch.Enabled {
				continue
			}
			if want == "" || fam == want {
				return ws.Name, ch.TLS, true
			}
			if !fallback.ok {
				fallback.name, fallback.tlsOn, fallback.ok = ws.Name, ch.TLS, true
			}
			break
		}
	}
	return fallback.name, fallback.tlsOn, fallback.ok
}

// NormalizeMessageTemplate 规范化单个消息模板。同样被 API 保存路径复用。
func NormalizeMessageTemplate(t *MessageTemplate) {
	t.Name = strings.TrimSpace(t.Name)
	if t.Format != "markdown" {
		t.Format = "text"
	}
	// 取值不认就回到默认，而不是当成 none：老配置里这个字段本来就是空的，
	// 而"标题不出现在消息里"正是要修的那个问题。
	if !ValidMarkdownTitleStyle(t.TitleStyle) {
		t.TitleStyle = DefaultMarkdownTitleStyle
	}
}

// NormalizeReceiver 规范化单个接收器。也被 API 的保存路径复用（见 server.normalizeWebhookReceiver），
// 保证"界面保存"与"手改配置后加载"落到完全一样的结果。
func NormalizeReceiver(r *WebhookReceiver) {
	r.Name = strings.TrimSpace(r.Name)
	// 路径为空就补一个随机值：空路径的接收器永远收不到消息，而且会与模块根冲撞。
	if r.Path = NormalizeWebhookPath(r.Path); r.Path == "" {
		r.Path = RandomWebhookPath()
	}

	// 鉴权方式：只认三种取值。填了令牌却没选方式（手改配置的常见形态）按 token 处理，
	// 而不是静默降级成 none —— 后者等于把一个用户明确设了口令的入口对全网敞开。
	switch r.AuthType {
	case "token", "header", "none":
	default:
		if strings.TrimSpace(r.Token) != "" {
			r.AuthType = "token"
		} else {
			r.AuthType = "none"
		}
	}
	r.AuthHeader = strings.TrimSpace(r.AuthHeader)
	r.Token = strings.TrimSpace(r.Token)

	if r.RateLimit < 0 {
		r.RateLimit = 0
	}
	if r.MaxBodyKB <= 0 {
		r.MaxBodyKB = DefaultWebhookBodyKB
	} else if r.MaxBodyKB > MaxWebhookBodyKB {
		r.MaxBodyKB = MaxWebhookBodyKB
	}

	if r.IPFilterMode != "allow" {
		r.IPFilterMode = "deny"
	}
	r.AllowIPs = trimNonEmpty(r.AllowIPs)
	r.DenyIPs = trimNonEmpty(r.DenyIPs)

	if r.KeywordMode != "all" {
		r.KeywordMode = "any"
	}
	// 只去两端空白、不折大小写：关键词要原样显示回界面，比对那一步再折（见 compileReceiver）。
	r.Keywords = trimNonEmpty(r.Keywords)

	// 取值根路径按点号分段整理：用户很可能写成 ".body." 或 "body.data."。
	r.RootPath = strings.Trim(strings.TrimSpace(r.RootPath), ".")
	switch r.SourceType = strings.ToLower(strings.TrimSpace(r.SourceType)); r.SourceType {
	case "json", "kv", "txt":
	default:
		// 留空、以及任何存得下但不认识的值，一律回到自动识别：
		// 它对 JSON 的处理与 json 完全一致（json.Valid 说了算），
		// 对不是 JSON 的那些则比"当成 JSON 解不出退回字符串"更进一步——拆得出字段就拆。
		r.SourceType = "auto"
	}
	// 分隔符只属于「键值文本」：自动识别下由程序按候选符号投票（见 webhook.sniffKV），
	// 手填分隔符是"我知道这个来源长什么样"的显式模式。别的类型一律清空——
	// 留着会让界面上显示一组不起作用的设置，用户改了没反应，比看不见更糟。
	if r.SourceType == "kv" {
		r.PairSep = normalizeSep(r.PairSep)
		r.KVSep = normalizeSep(r.KVSep)
	} else {
		r.PairSep, r.KVSep = "", ""
	}
	r.DefaultTargets = trimNonEmpty(r.DefaultTargets)

	for i := range r.Mappings {
		m := &r.Mappings[i]
		m.Name = strings.TrimSpace(m.Name)
		m.Path = strings.Trim(strings.TrimSpace(m.Path), ".")
	}
	for i := range r.Rules {
		NormalizeRule(&r.Rules[i])
	}
}

// NormalizeRule 规范化单条发送规则。
//
// 单独拿出来是因为规则有两条保存路径：整个接收器一起存（NormalizeReceiver），
// 以及「发送规则」那一页按单条存（见 server/api_webhook_rules.go）。
// 两条路径必须落到同一份规范化，否则同一条规则从哪个入口存进去会长得不一样。
func NormalizeRule(ru *WebhookRule) {
	ru.Name = strings.TrimSpace(ru.Name)
	ru.TemplateRef = strings.TrimSpace(ru.TemplateRef)
	ru.Targets = trimNonEmpty(ru.Targets)
	ru.Match = normalizeMatch(ru.Match)
	normalizeConditions(ru.Conditions)
	for i := range ru.Branches {
		b := &ru.Branches[i]
		b.Name = strings.TrimSpace(b.Name)
		b.TemplateRef = strings.TrimSpace(b.TemplateRef)
		b.Targets = trimNonEmpty(b.Targets)
		b.Match = normalizeMatch(b.Match)
		normalizeConditions(b.Conditions)
	}
	// 一个分支都不剩时把切片抹成 nil：`"branches": []` 与"没有这一项"在运行期同义
	// （都走单输出那条老路），但存进 config.json 会多出一个空数组，
	// 让人以为这条规则是"分支模式、只是分支被删空了"。
	if len(ru.Branches) == 0 {
		ru.Branches = nil
	}
}

// MaxSepRunes 键值文本分隔符的长度上限。分隔符是符号，不是词——
// 允许一两个字符足够表达 &、|、\r\n、"::" 这类写法，再长的更像是用户填错了地方。
const MaxSepRunes = 8

// normalizeSep 规范化键值文本的分隔符输入。
//
// 刻意**不**去两端空白：制表符、空格本身就可能是那个分隔符（"a=1 b=2" 就是按空格拼的），
// TrimSpace 会把它抹成空串，于是配置看着填了、运行期却按自动识别走。
// 只处理两件事：把 \n \t 这类转义写成真字符（输入框里打不出来），以及卡长度。
func normalizeSep(s string) string {
	s = UnescapeSepInput(s)
	if r := []rune(s); len(r) > MaxSepRunes {
		return string(r[:MaxSepRunes])
	}
	return s
}

// UnescapeSepInput 把界面上输入的分隔符里的 \n \r \t \\ 转成真正的字符。
//
// 输入框里打不出换行和制表符，而"一行一个字段"是这类文本的常见形态，
// 用户能想到的写法就是 \n。这一步放在配置规范化里做一次，运行期拿到的就是真字符。
func UnescapeSepInput(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' || i+1 >= len(s) {
			b.WriteByte(s[i])
			continue
		}
		i++
		switch s[i] {
		case 'n':
			b.WriteByte('\n')
		case 'r':
			b.WriteByte('\r')
		case 't':
			b.WriteByte('\t')
		case '\\':
			b.WriteByte('\\')
		default:
			// 认不出的转义原样留着：分隔符本身可能就是个反斜杠。
			b.WriteByte('\\')
			b.WriteByte(s[i])
		}
	}
	return b.String()
}

// NormalizeNotifyTarget 规范化单个通知目标。同样被 API 保存路径复用。
func NormalizeNotifyTarget(t *NotifyTarget) {
	t.Name = strings.TrimSpace(t.Name)
	t.Type = strings.ToLower(strings.TrimSpace(t.Type))
	t.URL = strings.TrimSpace(t.URL)
	t.Secret = strings.TrimSpace(t.Secret)

	switch strings.ToUpper(strings.TrimSpace(t.Method)) {
	case "PUT":
		t.Method = "PUT"
	default:
		t.Method = "POST"
	}
	if strings.TrimSpace(t.ContentType) == "" {
		t.ContentType = "application/json"
	} else {
		t.ContentType = strings.TrimSpace(t.ContentType)
	}

	if t.TimeoutSec <= 0 {
		t.TimeoutSec = DefaultNotifyTimeoutSec
	} else if t.TimeoutSec > MaxNotifyTimeoutSec {
		t.TimeoutSec = MaxNotifyTimeoutSec
	}
	// Retry 的 0 是有意义的取值（不重试），故**不**替换成默认值，只夹上限。
	if t.Retry < 0 {
		t.Retry = 0
	} else if t.Retry > MaxNotifyRetry {
		t.Retry = MaxNotifyRetry
	}

	t.AtMobiles = trimNonEmpty(t.AtMobiles)
	// 请求头的键去空白；空键会被 net/http 拒绝，且没有任何意义。
	if len(t.Headers) > 0 {
		clean := make(map[string]string, len(t.Headers))
		for k, v := range t.Headers {
			if k = strings.TrimSpace(k); k != "" {
				clean[k] = v
			}
		}
		t.Headers = clean
	}
}

// normalizeMatch 条件组合方式只认 all / any，其余（含空）归为 all。
func normalizeMatch(m string) string {
	if m == "any" {
		return "any"
	}
	return "all"
}

// normalizeConditions 就地整理条件列表：路径去空白与首尾点号，算子只去空白。
//
// 算子**不做大小写改写**：清单里有 notContains、countGt 这类驼峰名，
// 统一转小写会让它们再也通不过保存校验（算子清单在 webhook 侧，是精确比对的）。
// 认不出的算子也不在这里纠正——那只会让该条件不命中，
// 而改写成某个"能跑"的算子等于悄悄改变用户配的判断逻辑。大小写的容错交给
// webhook.CanonicalOperator，那里有清单可比。
func normalizeConditions(cs []Condition) {
	for i := range cs {
		cs[i].Path = strings.Trim(strings.TrimSpace(cs[i].Path), ".")
		cs[i].Op = strings.TrimSpace(cs[i].Op)
	}
}

// trimNonEmpty 去掉每项首尾空白并丢弃空项；全空时返回 nil（不落盘一个空数组）。
func trimNonEmpty(in []string) []string {
	if len(in) == 0 {
		return in
	}
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
