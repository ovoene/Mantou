package server

import (
	"fmt"
	"sort"
	"strings"

	"mantou/internal/config"
)

// 本文件实现「选择性导入」：一份备份里带着全部模块的数据，但用户可以只把其中几个模块
// 覆盖到当前配置上，其余模块保持本机现状不动。
//
// 为什么不能简单地"只反序列化选中的字段"：备份解密出来的是一份完整 Config，
// 而配置的落盘入口 Config.Replace 是**整体替换**。所以做法是
//   当前配置的深拷贝  →  按选中模块逐段覆盖  →  Replace(合并结果)
// 也就是说"不导入"等于"用本机现在的那一段把备份里的那一段挡回去"，
// 而不是"清空"——后者会让取消勾选变成删数据，那是任何人都想不到的语义。
//
// 跨模块引用是这件事唯一的真正难点。配置里的引用关系是密的：
// 面板 HTTPS 与消息路由 HTTPS 按 certId 指向证书，证书按 credentialRef 指向凭证，
// DDNS 同样指向凭证，消息路由的规则按 templateRef 指向模板，计划任务的动作参数里
// 放着 DDNS / 唤醒 / 证书 / 通知目标的 ID。只覆盖一半就可能留下悬空引用。
// 两层处理：
//   一、硬依赖在勾选阶段就连带勾上（importDeps），前端把连带项置为选中且不可取消；
//   二、合并完成后再校验一遍证书引用（checkImportCertRefs）——它是唯一会造成
//      "面板自己起不来 HTTPS"的引用，必须拦在落盘之前；其余引用悬空只在下一次
//      续期 / 更新 / 投递时报错，记一条警告即可（warnDanglingRefs）。
//
// 第二层不是第一层的重复：连带勾选管不到反方向。只勾「SSL/TLS 证书」时证书集会被
// 整体换成备份里的那一套，而**当前**面板 HTTPS 引用的那张证书可能不在其中。

// importModule 导入范围里的模块标识。取值与前端复选框、面板左侧导航一一对应，
// 是接口契约的一部分（前端按这些字符串提交），改名等于改接口。
type importModule string

const (
	modDDNS           importModule = "ddns"
	modWebService     importModule = "webservice"
	modMessage        importModule = "messageroute"
	modForward        importModule = "forward"
	modWOL            importModule = "wol"
	modCron           importModule = "cron"
	modCert           importModule = "cert"
	modCredential     importModule = "credential"
	modGlobalFirewall importModule = "globalfirewall"
	modPanel          importModule = "panel"
)

// importModules 全部模块，顺序与面板左侧导航一致：错误信息与日志按这个顺序列举，
// 用户在界面上从上往下找得到对应那一行。
var importModules = []importModule{
	modDDNS, modWebService, modMessage, modForward, modWOL,
	modCron, modCert, modCredential, modGlobalFirewall, modPanel,
}

// importModuleNames 模块的中文名，只用于错误信息与日志。
var importModuleNames = map[importModule]string{
	modDDNS:           "动态域名 DDNS",
	modWebService:     "Web 服务",
	modMessage:        "消息路由",
	modForward:        "端口转发",
	modWOL:            "网络唤醒",
	modCron:           "计划任务",
	modCert:           "SSL/TLS 证书",
	modCredential:     "域名服务商凭证",
	modGlobalFirewall: "服务防护",
	modPanel:          "面板与设置",
}

// importDeps 硬依赖：勾选左边的模块，右边的模块必须一起导入。
//
//   - 证书 → 凭证：ACME 证书用 dns01 验证，续期要拿 credentialRef 指向的凭证去改解析。
//   - DDNS → 凭证：同理，没有凭证的 DDNS 规则一条也跑不动。
//   - Web 服务 → 证书：启用 TLS 的子项靠域名从证书集里挑证书（不存 certId），
//     证书没跟过来就等于站点握手不了。
//   - 消息路由 → 证书：webhook.https.certId 是硬引用。
//   - 面板与设置 → 证书：panel.https.certId 是硬引用，而且是唯一一个悬空就可能
//     让人进不去面板的引用，所以宁可多导一份证书。
//
// 刻意**不**给计划任务加依赖：它的动作参数里放的是 ID 字符串，指不到就是这一次动作
// 执行失败并记一条错误，代价可控；而按引用连带下去会把几乎所有模块都拖成必选，
// 那样"可以只导一部分"这个功能就不存在了。
//
// 服务防护同样不在表里，但理由不同：它压根不引用别的模块——一份档位 + 两张 IP 名单，
// 自我完备。所以它既不拖别人，也不被别人拖，是唯一能单独导入的安全策略。
var importDeps = map[importModule][]importModule{
	modCert:       {modCredential},
	modDDNS:       {modCredential},
	modWebService: {modCert},
	modMessage:    {modCert},
	modPanel:      {modCert},
}

// importScope 一次导入选中的模块集合。
type importScope map[importModule]bool

// fullImportScope 全选。备份接口的旧调用方（以及"全部勾选"这个默认状态）走这一条，
// 行为与选择性导入之前完全一致。
func fullImportScope() importScope {
	sc := make(importScope, len(importModules))
	for _, m := range importModules {
		sc[m] = true
	}
	return sc
}

// parseImportScope 解析表单里的 modules 字段（逗号分隔的模块标识）。
//
// 字段缺失或为空一律视为全选：这个接口在选择性导入之前就存在，不带该字段的请求
// 必须保持原来的语义（整体替换），否则升级面板后旧页面缓存提交的导入会静默变成部分导入。
// 反过来，"一个都不选"是明确的错误——它等于什么都不做，却会让用户以为导入成功了。
func parseImportScope(raw string) (importScope, error) {
	if strings.TrimSpace(raw) == "" {
		return fullImportScope(), nil
	}
	known := make(map[importModule]bool, len(importModules))
	for _, m := range importModules {
		known[m] = true
	}
	sc := make(importScope, len(importModules))
	for _, part := range strings.Split(raw, ",") {
		key := importModule(strings.TrimSpace(part))
		if key == "" {
			continue
		}
		if !known[key] {
			return nil, fmt.Errorf("未知的模块标识: %s", string(key))
		}
		sc[key] = true
	}
	if len(sc) == 0 {
		return nil, fmt.Errorf("至少选择一个要导入的模块")
	}
	sc.applyDeps()
	return sc, nil
}

// applyDeps 把 importDeps 的传递闭包补齐。
//
// 后端重算一遍而不是信任前端提交的集合：前端的连带勾选是给人看的（让用户知道为什么
// 那一项被锁上了），真正保证引用完整的是这里。绕过界面直接调接口也拿同一套规则。
func (sc importScope) applyDeps() {
	// 依赖图只有两层（… → 证书 → 凭证），但按闭包写死循环上界，将来加边也不用改这里。
	for round := 0; round < len(importModules); round++ {
		grew := false
		for _, m := range importModules {
			if !sc[m] {
				continue
			}
			for _, dep := range importDeps[m] {
				if !sc[dep] {
					sc[dep] = true
					grew = true
				}
			}
		}
		if !grew {
			return
		}
	}
}

// all 是否全选（等价于导入之前的整体替换）。
func (sc importScope) all() bool {
	for _, m := range importModules {
		if !sc[m] {
			return false
		}
	}
	return true
}

// names 返回选中模块的中文名，按导航顺序，用于日志与响应。
func (sc importScope) names() []string {
	out := make([]string, 0, len(sc))
	for _, m := range importModules {
		if sc[m] {
			out = append(out, importModuleNames[m])
		}
	}
	return out
}

// keys 返回选中模块的标识，按导航顺序（响应里回给前端，让它显示"实际导入了什么"）。
func (sc importScope) keys() []string {
	out := make([]string, 0, len(sc))
	for _, m := range importModules {
		if sc[m] {
			out = append(out, string(m))
		}
	}
	return out
}

// mergeImportedConfig 把 imp 中选中模块的字段覆盖到 base 上，就地修改并返回 base。
//
// base **必须是调用方独占的深拷贝**（Config.Get() 的返回值），不能是 Snapshot()：
// 快照是所有读者共享的不可变对象，就地改它等于在运行中的模块脚下换配置。
//
// 每个模块对应哪些字段，是这份代码里唯一"知道模块与配置字段如何对应"的地方。
// 往 Config 里加新字段时，如果不在这里归到某个模块名下，它就会**永远不被导入**
// （悄悄沿用本机现值），而且不会有任何报错或日志。
//
// 这条约束不靠自觉：import_scope_fields_test.go 用反射把 config.Config 的字段逐个点名，
// 新字段未归类会直接让测试失败；归类了但这里漏了赋值，同一个文件里的行为用例也会失败。
func mergeImportedConfig(base, imp *config.Config, sc importScope) *config.Config {
	if base == nil || imp == nil {
		return base
	}
	if sc[modPanel] {
		// 面板与设置：监听 / 访问前缀 / HTTPS、管理员账户与二次验证、外观与日志、更新源，
		// 以及面板入站防护（Settings.Security.Firewall——它管的是"谁能进面板"，
		// 因此归在面板这一段；连接层的服务防护是独立模块，见下方 modGlobalFirewall）。
		// Auth.JWTSecret 一并被覆盖，但 Config.Replace 会无条件丢弃它换回本机密钥
		//（防止有人拿一份"已知密钥"的备份换取伪造会话的能力），这里不必额外处理。
		//
		// Settings.Restart.LastRunAt 例外，要保留本机现值：它不是用户设的，是程序写的
		// 执行记录，也是防重启循环的唯一凭据。保存接口刻意不接受外部提交它，
		// 导入这条路径必须同口径——一份来自时钟偏快机器的备份会把它带到未来，
		// 从那以后定时重启永远不再触发，而设置页照样显示一个算得出来的"下次执行"。
		// 同机器恢复备份时这个值本来就是过去的，保留本机值不损失任何东西。
		lastRestartRun := base.Settings.Restart.LastRunAt
		base.Panel = imp.Panel
		base.Auth = imp.Auth
		base.Settings = imp.Settings
		base.Update = imp.Update
		base.Settings.Restart.LastRunAt = lastRestartRun
	}
	if sc[modGlobalFirewall] {
		// 服务防护（连接层）自成一个模块，既不跟着它保护的那两个模块走，也不跟着面板走。
		//
		// 不跟 Web 服务 / 消息路由：同一套档位与名单**同时**管着这两个模块，
		// 归到任一侧都会出现"只导 Web 服务，却把消息路由的防护也换掉了"。
		//
		// 不跟「面板与设置」：那一段里装着管理员账户与面板监听端口，是整份配置中
		// 覆盖代价最高的一段。把一份 IP 名单绑在它后面，等于"想恢复一份封禁名单，
		// 就得连管理员账户一起换掉"——反过来也一样别扭。它在左侧导航里本就是独立一页，
		// 导入范围里也该是独立一项。
		//
		// 名单与档位一起搬，不做逐字段挑选：这是一份**策略**，半新半旧的策略
		// （比如取了备份的严格档、留了本机的允许名单）谁也说不清实际拦的是什么。
		base.GlobalFirewall = imp.GlobalFirewall
	}
	if sc[modCredential] {
		base.Credentials = imp.Credentials
	}
	if sc[modDDNS] {
		base.DDNS = imp.DDNS
	}
	if sc[modWebService] {
		base.WebServices = imp.WebServices
	}
	if sc[modForward] {
		base.Forwards = imp.Forwards
	}
	if sc[modWOL] {
		base.WOLDevices = imp.WOLDevices
	}
	if sc[modCron] {
		base.CronTasks = imp.CronTasks
	}
	if sc[modCert] {
		base.Certs = imp.Certs
		base.ACMEAccounts = imp.ACMEAccounts
	}
	if sc[modMessage] {
		// 消息路由的四段是一个整体：接收器引用模板与通知目标，拆开导入必然留下悬空引用。
		base.Webhook = imp.Webhook
		base.WebhookReceivers = imp.WebhookReceivers
		base.NotifyTargets = imp.NotifyTargets
		base.MessageTemplates = imp.MessageTemplates
	}
	return base
}

// checkImportCertRefs 校验合并结果里"启用中的 HTTPS 是否还找得到它引用的证书"。
//
// 只看启用中的：关着的 HTTPS 留一个失效 certId 不影响任何事，拦下来只会让用户莫名其妙。
// 拦在落盘之前而不是事后提示：面板 HTTPS 的证书找不到，下一次重启就是"进不去面板"，
// 这类错误必须在还能拒绝的时候拒绝。
func checkImportCertRefs(merged *config.Config, sc importScope) error {
	if merged == nil {
		return nil
	}
	have := make(map[string]bool, len(merged.Certs))
	for i := range merged.Certs {
		have[merged.Certs[i].ID] = true
	}
	type ref struct {
		where  string
		certID string
		// owner 引用方属于哪个模块：据此给出"该勾哪一项"的建议。
		owner importModule
	}
	refs := []ref{
		{"面板 HTTPS", merged.Panel.HTTPS.CertID, modPanel},
		{"消息路由 HTTPS", merged.Webhook.HTTPS.CertID, modMessage},
	}
	if !merged.Panel.HTTPS.Enabled {
		refs[0].certID = ""
	}
	if !merged.Webhook.HTTPS.Enabled {
		refs[1].certID = ""
	}
	var problems []string
	for _, r := range refs {
		if r.certID == "" || have[r.certID] {
			continue
		}
		// 引用方与证书两侧，谁是"这次被换掉的那一侧"，建议就落在另一侧。
		advice := "请一并勾选「" + importModuleNames[modCert] + "」"
		if sc[modCert] && !sc[r.owner] {
			advice = "请一并勾选「" + importModuleNames[r.owner] + "」，或取消勾选「" + importModuleNames[modCert] + "」"
		}
		problems = append(problems, fmt.Sprintf("%s 引用的证书 %s 不在导入后的证书列表里（%s）", r.where, r.certID, advice))
	}
	if len(problems) == 0 {
		return nil
	}
	return fmt.Errorf("%s", strings.Join(problems, "；"))
}

// warnDanglingRefs 把合并后仍然悬空的"软引用"记进日志。
//
// 这些引用悬空不影响启动，只在真正用到时失败（证书续期拿不到凭证、DDNS 更新鉴权失败、
// 规则渲染找不到模板）。不拦：拦下来等于要求用户必须整份导入，那就没有选择性导入了。
// 但一定要说——否则用户会在几十天后的续期失败里才第一次知道这件事。
func (s *Server) warnDanglingRefs(merged *config.Config) {
	if merged == nil || s.deps.Log == nil {
		return
	}
	creds := make(map[string]bool, len(merged.Credentials))
	for i := range merged.Credentials {
		creds[merged.Credentials[i].ID] = true
	}
	tpls := make(map[string]bool, len(merged.MessageTemplates))
	for i := range merged.MessageTemplates {
		tpls[merged.MessageTemplates[i].ID] = true
	}
	// 按"缺什么"聚合再输出，避免几十条规则少同一个模板时刷出几十行日志。
	missing := map[string][]string{}
	note := func(kind, id, who string) {
		if id == "" {
			return
		}
		key := kind + " " + id
		missing[key] = append(missing[key], who)
	}
	for i := range merged.Certs {
		c := &merged.Certs[i]
		if c.Method == "acme" && c.CredentialRef != "" && !creds[c.CredentialRef] {
			note("凭证", c.CredentialRef, "证书 "+itemName(c.Name, c.ID))
		}
	}
	for i := range merged.DDNS {
		d := &merged.DDNS[i]
		// 凭证挂在目标上而不是规则上：一条规则可以同时更新多个域名，各用各的凭证。
		for j := range d.Targets {
			if ref := d.Targets[j].CredentialRef; ref != "" && !creds[ref] {
				note("凭证", ref, "DDNS 规则 "+itemName(d.Name, d.ID))
			}
		}
	}
	for i := range merged.WebhookReceivers {
		r := &merged.WebhookReceivers[i]
		for j := range r.Rules {
			rule := &r.Rules[j]
			if len(rule.Branches) == 0 {
				if rule.TemplateRef != "" && !tpls[rule.TemplateRef] {
					note("模板", rule.TemplateRef, "接收器 "+itemName(r.Name, r.ID))
				}
				continue
			}
			for k := range rule.Branches {
				if ref := rule.Branches[k].TemplateRef; ref != "" && !tpls[ref] {
					note("模板", ref, "接收器 "+itemName(r.Name, r.ID))
				}
			}
		}
	}
	if len(missing) == 0 {
		return
	}
	keys := make([]string, 0, len(missing))
	for k := range missing {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		users := dedupeStrings(missing[k])
		s.deps.Log.Warn("选择性导入后存在悬空引用，相关功能会在实际执行时失败",
			"missing", k, "usedBy", strings.Join(users, "、"))
	}
}

// itemName 条目的可读标识：有名字用名字，否则用 ID。只进日志。
func itemName(name, id string) string {
	if strings.TrimSpace(name) != "" {
		return name
	}
	return id
}

// dedupeStrings 去重并保序，最多留 8 项（日志一行不该无上界地长）。
func dedupeStrings(in []string) []string {
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if seen[s] {
			continue
		}
		seen[s] = true
		if len(out) == 8 {
			out = append(out, fmt.Sprintf("等共 %d 处", len(in)))
			break
		}
		out = append(out, s)
	}
	return out
}
