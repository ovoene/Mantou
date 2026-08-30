package server

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"mantou/internal/config"
	"mantou/internal/ipx"
	"mantou/internal/modules/notify"
	"mantou/internal/modules/webhook"
	"mantou/internal/strutil"
	"mantou/internal/tmplx"
)

// 本文件是消息路由模块的接口层：三套 CRUD（接收器 / 通知目标 / 消息模板）加若干动作。
//
// 入站 Webhook **不在这里**：它有自己的监听端口（见 config.WebhookServer 的说明），
// 因此不经过面板的会话校验与 CSRF 中间件，也不需要为它开任何豁免。
//
// 三套 CRUD 都挂在 /webhook 前缀下，且第二段全是静态名（receivers / targets / templates），
// 与同前缀的动作路由不会在 gin 的路由树上冲突。

// maskedSecret 列表接口里替代凭证的占位符。与凭证模块同一个值：
// 前端据此判断"这个字段用户没动过"，保存时原样回传，由 normalize 还原成已存储的真实值。
const maskedSecret = "******"

// dryRunBodyLimit 试运行样本载荷的大小上限。
// 比入站的 MaxWebhookBodyKB 小得多：试运行是人手贴一段样本，不是真实推送。
const dryRunBodyLimit = 256 << 10

// notifyTestBodyLimit 测试发送正文的上限。手打的一段话再长也到不了这里，
// 挡的是"把整份载荷粘进来"，那种内容各家通道自己也会拒。
const notifyTestBodyLimit = 16 << 10

func (s *Server) registerWebhookRoutes(g *gin.RouterGroup) {
	s.registerWebhookReceivers(g)
	s.registerWebhookRules(g)
	s.registerNotifyTargets(g)
	s.registerMessageTemplates(g)

	g.GET("/webhook/status", s.handleWebhookStatus)
	g.GET("/webhook/server", s.handleGetWebhookServer)
	g.PUT("/webhook/server", s.handleUpdateWebhookServer)
	g.DELETE("/webhook/server", s.handleDeleteWebhookServer)
	g.POST("/webhook/server/toggle", s.handleToggleWebhookServer)
	g.GET("/webhook/history", s.handleWebhookHistory)
	g.GET("/webhook/history/source", s.handleWebhookSource)
	g.GET("/webhook/history/source/stats", s.handleWebhookSourceStats)
	g.POST("/webhook/history/source/clear", s.handleWebhookSourceClear)
	g.GET("/webhook/meta", s.handleWebhookMeta)
	g.GET("/webhook/newpath", s.handleWebhookNewPath)
	g.POST("/webhook/receivers/:id/dryrun", s.handleWebhookDryRun)
	g.POST("/webhook/templates/preview", s.handleTemplatePreview)
	g.GET("/webhook/receivers/:id/testrun", s.handleTestRunState)
	g.POST("/webhook/receivers/:id/testrun/start", s.handleTestRunStart)
	g.POST("/webhook/receivers/:id/testrun/stop", s.handleTestRunStop)
	g.POST("/webhook/targets/:id/test", s.handleNotifyTest)
}

// ---- 接收器 ----

// receiverRow 是接收器列表返回的形状：配置里的字段，加上内存里的统计。
//
// 统计不在配置里（见 internal/runstats），所以只能在这一层拼上去。JSON 字段名与
// 搬走之前完全一致，前端不用改读法；rejectedCount 是这次新增的。
//
// 为什么统计要单独显示成两个数：原先「累计」把收下的和被挡掉的算在一起，于是一个
// 被人反复猜令牌的接收器会显示成「累计 8000 次」，看上去像收了八千条消息。
// 这两件事该做的处置完全不同，不能混成一个数。
type receiverRow struct {
	config.WebhookReceiver
	LastReceivedAt int64  `json:"lastReceivedAt"`
	LastStatus     string `json:"lastStatus"`
	ReceivedCount  int64  `json:"receivedCount"`
	RejectedCount  int64  `json:"rejectedCount"`
}

func (s *Server) registerWebhookReceivers(g *gin.RouterGroup) {
	registerCRUD(s, g, "webhook/receivers", resource[config.WebhookReceiver]{
		get:      func(c *config.Config) []config.WebhookReceiver { return c.WebhookReceivers },
		set:      func(c *config.Config, v []config.WebhookReceiver) { c.WebhookReceivers = v },
		id:       func(t *config.WebhookReceiver) string { return t.ID },
		setID:    func(t *config.WebhookReceiver, id string) { t.ID = id },
		maxCount: config.MaxWebhookReceivers,
		modLabel: "消息路由接收器",
		enabled:  func(t *config.WebhookReceiver) bool { return t.Enabled },
		// 列表里的开关只改这一项（POST …/:id/toggle），不回传整行——原因见 registerCRUD 里那段注释。
		setEnabled: func(t *config.WebhookReceiver, v bool) { t.Enabled = v },
		itemName:   func(t *config.WebhookReceiver) string { return t.Name },
		detail: func(t *config.WebhookReceiver) string {
			// 路径进审计日志是刻意的：它是这个接收器的唯一标识，
			// 出问题时要能从一条访问记录反查到是哪个接收器被改过。
			return fmt.Sprintf("（路径：%s，规则 %d 条）", t.Path, len(t.Rules))
		},
		list: func(source []config.WebhookReceiver) []config.WebhookReceiver {
			out := append([]config.WebhookReceiver(nil), source...)
			for i := range out {
				if out[i].Token != "" {
					out[i].Token = maskedSecret
				}
			}
			return out
		},
		rows: func(source []config.WebhookReceiver) any {
			out := make([]receiverRow, len(source))
			for i := range source {
				st := s.deps.Stats.Recv(source[i].ID)
				out[i] = receiverRow{
					WebhookReceiver: source[i],
					LastReceivedAt:  st.LastAt,
					LastStatus:      st.LastStatus,
					ReceivedCount:   st.Received,
					RejectedCount:   st.Rejected,
				}
			}
			return out
		},
		afterDelete: func(id string) { s.deps.Stats.Forget(id) },
		normalize: func(t *config.WebhookReceiver) {
			config.NormalizeReceiver(t)
			if t.Token == maskedSecret {
				t.Token = s.existingReceiverToken(t.ID)
			}
			// 规则不走这条路径改：它们归「发送规则」那一页独占（见 api_webhook_rules.go）。
			// 接收器弹窗里那份规则是打开弹窗那一刻读到的，用户完全可能在这中间去
			// 「发送规则」改过一条——原样写回就把那次修改无声无息地盖掉了，
			// 与列表开关不用整行 PUT 是同一个理由。
			// 新建（ID 为空）时照旧接受请求里带的规则：整份导入、以及外部脚本
			// "一次调用建好一个接收器"走的都是这条路。
			if t.ID != "" {
				t.Rules = s.existingReceiverRules(t.ID)
			}
		},
		validate: func(cfg *config.Config, t config.WebhookReceiver) error {
			return validateReceiver(cfg, t)
		},
	})
}

// existingReceiverRules 取已存储的规则列表，用于让接收器的保存路径绕过规则这一项。
// 找不到就返回 nil——那意味着这条接收器刚被删掉，此时保留一份规则也没有归属。
//
// 返回的是副本：Snapshot 与运行配置同底，把那条切片直接交出去，
// 后续任何就地改动都会写到别的读者眼皮底下。
func (s *Server) existingReceiverRules(id string) []config.WebhookRule {
	cfg := s.deps.Config.Snapshot()
	if rc := findWebhookReceiver(cfg, id); rc != nil {
		return append([]config.WebhookRule(nil), rc.Rules...)
	}
	return nil
}

// existingReceiverToken 取已存储的令牌明文，用于还原前端回传的脱敏占位。
// 找不到就返回空串——那意味着这是新建，占位符本身不该被当成令牌存下去。
func (s *Server) existingReceiverToken(id string) string {
	if id == "" {
		return ""
	}
	cfg := s.deps.Config.Snapshot()
	for i := range cfg.WebhookReceivers {
		if cfg.WebhookReceivers[i].ID == id {
			return cfg.WebhookReceivers[i].Token
		}
	}
	return ""
}

// validateReceiver 校验接收器。
//
// 这里挡下的每一条都是"存得下但跑不起来"的配置。运行期只能记一条警告然后
// 让规则失效（见 webhook 模块的 compileReceiver），用户看不到自己错在哪；
// 保存时拦住才能把错误还原成一句可以照着改的话。
func validateReceiver(cfg *config.Config, t config.WebhookReceiver) error {
	if t.Name == "" {
		return fmt.Errorf("名称不能为空")
	}
	// 没有模块就没有监听、没有域名、没有可访问的地址：此刻启用一个接收器只会得到
	// 一条永远收不到消息的配置，而列表上那个绿开关会让人以为它在工作。
	// 只拦启用这一侧——停用中的接收器要能照常编辑与保存（用户正是先配好再上线）。
	if t.Enabled && !cfg.Webhook.Created {
		return fmt.Errorf("消息路由模块还没创建，接收器无法启用：请先到「模块设置」新建模块（填好端口与访问域名），之后接收器会自动带上域名与随机路径")
	}
	if len(t.Path) > config.MaxWebhookPathLen {
		return fmt.Errorf("入站路径过长（上限 %d 字符）", config.MaxWebhookPathLen)
	}
	for _, r := range cfg.WebhookReceivers {
		if r.ID != t.ID && r.Path == t.Path {
			return fmt.Errorf("入站路径与接收器「%s」重复，两个接收器不能共用同一个地址", nameOrID(r.Name, r.ID))
		}
	}
	if (t.AuthType == "token" || t.AuthType == "header") && t.Token == "" {
		return fmt.Errorf("选择了鉴权方式，必须设置令牌")
	}
	if t.AuthType == "header" && t.AuthHeader == "" {
		return fmt.Errorf("请求头鉴权必须填写请求头名称")
	}
	if t.IPFilter {
		mode, list := "白名单", t.AllowIPs
		if t.IPFilterMode != "allow" {
			mode, list = "黑名单", t.DenyIPs
		}
		if len(list) == 0 {
			// 空白名单会把所有来源都拒掉，空黑名单则等于没开——两种都不是用户的本意。
			return fmt.Errorf("已开启 IP 过滤，%s不能为空", mode)
		}
		// 逐条校验而不是整批：ParseCIDRs 对认不出的条目是静默跳过的，
		// 整批比对只能说"有一条不对"，逐条才能把是哪一条指出来。
		for _, item := range list {
			if len(ipx.ParseCIDRs([]string{item})) == 0 {
				return fmt.Errorf("%s里的「%s」无法识别：支持单个 IP、CIDR（192.168.1.0/24）或范围（192.168.1.1-192.168.1.99）", mode, item)
			}
		}
	}

	// 关键词准入：开了却没词等于把这个接收器的全部来源拒死，而界面上看不出原因。
	// 运行期对这种配置是"记一条警告然后照常放行"（见 compileReceiver），
	// 因为静默全拒是更糟的失败；真正的保护就是这里——保存时不让它成立。
	if t.KeywordFilter {
		if len(t.Keywords) == 0 {
			return fmt.Errorf("已开启关键词准入，关键词不能为空：留空会把这个接收器收到的所有消息都拒掉")
		}
		if err := checkLimit("关键词", len(t.Keywords), config.MaxWebhookKeywords); err != nil {
			return err
		}
		for _, kw := range t.Keywords {
			if len([]rune(kw)) > config.MaxWebhookKeywordLen {
				return fmt.Errorf("关键词「%s」过长（上限 %d 字）", strutil.Truncate(kw, 16, "…"), config.MaxWebhookKeywordLen)
			}
		}
	}

	if err := checkLimit("字段映射", len(t.Mappings), config.MaxWebhookMappings); err != nil {
		return err
	}
	if err := checkLimit("消息规则", len(t.Rules), config.MaxWebhookRules); err != nil {
		return err
	}
	// SourceType 由 NormalizeReceiver 兜到 auto/json/kv/txt 之一，这里只挡"存得下但没意义"的第五种值——
	// 整份导入与手改 config.json 都绕不过 normalize，所以这条实际只在两者都改坏时触发。
	if t.SourceType != "auto" && t.SourceType != "json" && t.SourceType != "txt" && t.SourceType != "kv" {
		return fmt.Errorf("来源消息类型只支持 auto、json、kv 或 txt")
	}

	seen := map[string]bool{}
	for _, m := range t.Mappings {
		if !config.ValidMappingName(m.Name) {
			return fmt.Errorf("字段映射名「%s」不能用在模板里：只允许字母、数字、下划线与汉字，且不能以数字开头", m.Name)
		}
		if seen[m.Name] {
			return fmt.Errorf("字段映射名「%s」重复", m.Name)
		}
		seen[m.Name] = true
		for _, reserved := range webhook.ReservedFieldNames {
			if m.Name == reserved {
				return fmt.Errorf("字段映射名「%s」与内置字段冲突，请换一个名字", m.Name)
			}
		}
		if m.Path == "" {
			return fmt.Errorf("字段映射「%s」的取值路径不能为空", m.Name)
		}
	}

	tmplIDs := map[string]bool{}
	for _, mt := range cfg.MessageTemplates {
		tmplIDs[mt.ID] = true
	}
	targetIDs := map[string]bool{}
	for _, nt := range cfg.NotifyTargets {
		targetIDs[nt.ID] = true
	}
	if err := checkTargets("默认通知目标", t.DefaultTargets, targetIDs); err != nil {
		return err
	}
	for _, ru := range t.Rules {
		label := "规则「" + nameOrID(ru.Name, ru.ID) + "」"
		if ru.Name == "" {
			return fmt.Errorf("每条规则都要有名称")
		}
		if err := checkConditions(label, ru.Conditions); err != nil {
			return err
		}
		if err := checkLimit(label+"的输出分支", len(ru.Branches), config.MaxWebhookBranches); err != nil {
			return err
		}
		// 没配分支时校验规则自己的模板与目标；配了分支就逐个分支校验——
		// 那种情况下规则级的 templateRef / targets 不参与运行（见 config.WebhookRule.Branches），
		// 拿它们去卡人只会让用户改一个根本不生效的格子。
		if len(ru.Branches) == 0 {
			if err := checkOutput(label, ru.TemplateRef, ru.Targets, t.DefaultTargets, tmplIDs, targetIDs); err != nil {
				return err
			}
			continue
		}
		names := map[string]bool{}
		for _, b := range ru.Branches {
			if b.Name == "" {
				return fmt.Errorf("%s里每个输出分支都要有名称", label)
			}
			// 同名分支在执行历史里长得一模一样（都写成「规则名 / 分支名」），
			// 排查时就分不出是哪个出口发的。
			if names[b.Name] {
				return fmt.Errorf("%s里的输出分支名「%s」重复", label, b.Name)
			}
			names[b.Name] = true
			blabel := label + "的分支「" + b.Name + "」"
			if err := checkConditions(blabel, b.Conditions); err != nil {
				return err
			}
			if err := checkOutput(blabel, b.TemplateRef, b.Targets, t.DefaultTargets, tmplIDs, targetIDs); err != nil {
				return err
			}
		}
	}
	return nil
}

// checkOutput 校验一个输出（规则本体、或规则的一个分支）的模板与目标。
// 抽出来是因为单输出与分支两条路要落到同一份校验：分开写必然会漂，
// 于是"分支里没选模板"能存进去、上线后才在告警里冒出来。
func checkOutput(label, templateRef string, targets, defaults []string, tmplIDs, targetIDs map[string]bool) error {
	if templateRef == "" {
		return fmt.Errorf("%s未选择消息模板", label)
	}
	if !tmplIDs[templateRef] {
		return fmt.Errorf("%s引用的消息模板不存在", label)
	}
	if err := checkTargets(label+"的通知目标", targets, targetIDs); err != nil {
		return err
	}
	// 没配目标时会回落到接收器的默认目标；两处都空就是一条永远发不出去的规则。
	if len(targets) == 0 && len(defaults) == 0 {
		return fmt.Errorf("%s没有通知目标，且接收器也未设置默认目标", label)
	}
	return nil
}

// checkConditions 校验一组条件。
func checkConditions(label string, cs []config.Condition) error {
	if err := checkLimit(label+"的条件", len(cs), config.MaxWebhookConditions); err != nil {
		return err
	}
	for _, c := range cs {
		if !webhook.ValidOperator(c.Op) {
			return fmt.Errorf("%s里有不支持的判断方式「%s」", label, c.Op)
		}
		// 空取值路径在运行期取不到任何值，于是这条条件永远不成立（exists 永假、empty 永真），
		// 表现为"规则配了却不生效"，从界面上完全看不出原因——只能在保存时拦住。
		if c.Path == "" {
			return fmt.Errorf("%s里有条件没填取值路径，请填写要判断的字段，例如 body.消息类型", label)
		}
		op := webhook.CanonicalOperator(c.Op)
		if op == "regex" {
			if err := webhook.CheckRegex(c.Value); err != nil {
				return fmt.Errorf("%s的正则表达式无法编译：%w", label, err)
			}
		}
		// 数量比较的比较值必须是数字，否则这条条件永远不成立（见 matchCount）。
		if webhook.IsCountOperator(op) {
			if _, ok := tmplx.Num(c.Value); !ok {
				return fmt.Errorf("%s里「%s」的数量比较值必须是数字，当前填的是「%s」", label, c.Path, c.Value)
			}
		}
	}
	return nil
}

func checkTargets(label string, ids []string, valid map[string]bool) error {
	for _, id := range ids {
		if !valid[id] {
			return fmt.Errorf("%s里有已被删除的目标，请重新选择", label)
		}
	}
	return nil
}

func checkLimit(label string, n, max int) error {
	if n > max {
		return fmt.Errorf("%s数量超过上限 %d 条（当前 %d 条）", label, max, n)
	}
	return nil
}

// checkHTTPURL 校验一个「程序会主动去请求它」的地址：解析得开、scheme 是 http/https、带主机名。
//
// label 是这个字段在界面上的名字，拼在报错开头；example 是缺主机名时给的示范地址。
// 空串不在这里判——"能不能留空"各字段口径不同（通知目标必填，版本清单地址留空表示
// 不做在线检测），交给调用方决定。
//
// 判 Scheme 而不是判前缀，附带把 "HTTPS://example.com" 这种大写写法收下了：
// 它照样发得出去（url.Parse 会把 scheme 折成小写），判前缀却把它拦下来，属于白拦。
//
// 这一步**不**限制主机是谁——那是「内网防护」开关的事（见 config.Security 的说明），
// 而它默认关闭是为了兼容目标本就在内网的自建接收端。这里要的只是"有个主机名"。
func checkHTTPURL(label, raw, example string) error {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return fmt.Errorf("%s必须以 http:// 或 https:// 开头", label)
	}
	if u.Host == "" {
		return fmt.Errorf("%s里缺少主机名，例如 %s", label, example)
	}
	return nil
}

func nameOrID(name, id string) string {
	if name = strings.TrimSpace(name); name != "" {
		return name
	}
	return id
}

// ---- 通知目标 ----

func (s *Server) registerNotifyTargets(g *gin.RouterGroup) {
	registerCRUD(s, g, "webhook/targets", resource[config.NotifyTarget]{
		get:      func(c *config.Config) []config.NotifyTarget { return c.NotifyTargets },
		set:      func(c *config.Config, v []config.NotifyTarget) { c.NotifyTargets = v },
		id:       func(t *config.NotifyTarget) string { return t.ID },
		setID:    func(t *config.NotifyTarget, id string) { t.ID = id },
		maxCount: config.MaxNotifyTargets,
		modLabel: "消息路由通知目标",
		enabled:  func(t *config.NotifyTarget) bool { return t.Enabled },
		// 同接收器：列表开关只发 enabled。通知目标的地址整段是凭证，
		// 整行回传就得让 ****** 在网上来回跑一趟，能不跑就不跑。
		setEnabled: func(t *config.NotifyTarget, v bool) { t.Enabled = v },
		itemName:   func(t *config.NotifyTarget) string { return t.Name },
		detail:     func(t *config.NotifyTarget) string { return "（类型：" + t.Type + "）" },
		// URL 整段是凭证（钉钉与企业微信把 access_token 放在 query 里），
		// 因此列表接口连主机名都不给——排障靠 Name 与 Type 定位条目。
		list: func(source []config.NotifyTarget) []config.NotifyTarget {
			out := append([]config.NotifyTarget(nil), source...)
			for i := range out {
				if out[i].URL != "" {
					out[i].URL = maskedSecret
				}
				if out[i].Secret != "" {
					out[i].Secret = maskedSecret
				}
				if len(out[i].Headers) > 0 {
					masked := make(map[string]string, len(out[i].Headers))
					for k := range out[i].Headers {
						masked[k] = maskedSecret
					}
					out[i].Headers = masked
				}
			}
			return out
		},
		rows: func(source []config.NotifyTarget) any {
			out := make([]targetRow, len(source))
			for i := range source {
				st := s.deps.Stats.Send(source[i].ID)
				out[i] = targetRow{
					NotifyTarget: source[i],
					LastSentAt:   st.LastAt,
					LastStatus:   st.LastStatus,
					SentCount:    st.Sent,
					FailCount:    st.Fail,
				}
			}
			return out
		},
		afterDelete: func(id string) { s.deps.Stats.Forget(id) },
		normalize: func(t *config.NotifyTarget) {
			config.NormalizeNotifyTarget(t)
			s.restoreTargetSecrets(t)
		},
		validate: func(cfg *config.Config, t config.NotifyTarget) error {
			return validateNotifyTarget(t)
		},
	})
}

// targetRow 是通知目标列表返回的形状：配置里的字段，加上内存里的统计。
//
// 与接收器同一套做法（见 receiverRow）：统计不在配置里（见 internal/runstats），
// 只能在这一层拼上去。JSON 字段名与搬走之前完全一致，前端不用改读法。
type targetRow struct {
	config.NotifyTarget
	LastSentAt int64  `json:"lastSentAt"`
	LastStatus string `json:"lastStatus"`
	SentCount  int64  `json:"sentCount"`
	FailCount  int64  `json:"failCount"`
}

// restoreTargetSecrets 把前端回传的脱敏占位还原成已存储的真实值。
func (s *Server) restoreTargetSecrets(t *config.NotifyTarget) {
	if t.ID == "" {
		return
	}
	cfg := s.deps.Config.Snapshot()
	for i := range cfg.NotifyTargets {
		old := &cfg.NotifyTargets[i]
		if old.ID != t.ID {
			continue
		}
		if t.URL == maskedSecret {
			t.URL = old.URL
		}
		if t.Secret == maskedSecret {
			t.Secret = old.Secret
		}
		for k, v := range t.Headers {
			if v == maskedSecret {
				if ov, ok := old.Headers[k]; ok {
					t.Headers[k] = ov
				}
			}
		}
		return
	}
}

func validateNotifyTarget(t config.NotifyTarget) error {
	if t.Name == "" {
		return fmt.Errorf("名称不能为空")
	}
	if !notify.SupportedType(t.Type) {
		return fmt.Errorf("不支持的通知类型「%s」", t.Type)
	}
	// 脱敏占位符不能落库。这一步跑在 normalize（restoreTargetSecrets）之后，
	// 所以还留着占位符只意味着一件事：那个值在已存储的配置里找不到对应。
	//
	// 请求头是最容易撞上的一格：还原是按**键名**取旧值的，而键名恰恰是用户会改的东西——
	// 把 X-Token 改成 Authorization，值框里显示的还是占位符，于是取不到旧值。
	// 其次是「复制一条」出来的新条目（ID 为空，整个还原步骤直接跳过）。
	//
	// 必须拒绝而不是放过去：占位符照原样存下去之后，面板上看着一切正常
	// （脱敏显示与填对了长得一模一样），而出站请求带着一个错凭证被对方拒掉，
	// 用户只能从执行历史里的一串失败往回猜——而他刚改的明明只是一个名字。
	if err := checkNoMaskedLeftover(t); err != nil {
		return err
	}
	if t.URL == "" {
		return fmt.Errorf("地址不能为空")
	}
	// 地址要真的解析得开、且带着主机名。
	//
	// 原先只判前缀，于是 "http://" 这么一个串就能存进去：保存成功、界面上一切正常，
	// 而每一次投递都在 http.NewRequest 那里失败，报的还是一句看不出跟地址有关的话。
	// 钉钉那一侧更绕——dingSignedURL 会先解析一遍地址，解析不开的话连签都算不出来。
	//
	// 具体判法与"为什么不在这里拦内网地址"见 checkHTTPURL。
	if err := checkHTTPURL("地址", t.URL, "https://example.com/hook"); err != nil {
		return err
	}
	if t.Type == "dingtalk" && t.Secret != "" && !strings.HasPrefix(t.Secret, "SEC") {
		return fmt.Errorf("钉钉加签密钥应以 SEC 开头；若机器人未开启加签，请留空")
	}
	if err := checkNotifyHeaders(t.Headers); err != nil {
		return err
	}
	if err := checkLimit("@ 的手机号", len(t.AtMobiles), config.MaxNotifyAtMobiles); err != nil {
		return err
	}
	for _, m := range t.AtMobiles {
		if len(m) > config.MaxNotifyAtMobileLen {
			return fmt.Errorf("@ 的手机号「%s」过长（上限 %d 字节）", strutil.Truncate(m, 24, "…"), config.MaxNotifyAtMobileLen)
		}
	}
	// 长度先判、再编译：一份超长模板会让 tmplx.Compile 为它建一棵比源文本还大的语法树，
	// 而"它太长了"这个结论压根不取决于编译结果。
	// 不分通知类型：模板只有 type=http 会真的用上，但不管哪种类型它都照样存进
	// config.json、照样跟着每次快照复制一份，上限要挡的正是这个。
	if n := len(t.BodyTemplate); n > config.MaxNotifyBodyTemplateLen {
		return fmt.Errorf("请求体模板过长（上限 %d 字节，当前 %d 字节）", config.MaxNotifyBodyTemplateLen, n)
	}
	if t.Type == "http" && t.BodyTemplate != "" {
		if _, err := tmplx.Compile("body", t.BodyTemplate); err != nil {
			return fmt.Errorf("请求体模板有语法错误：%w", err)
		}
	}
	return nil
}

// checkNotifyHeaders 卡住附加请求头的条数与键值长度。
//
// 与模板同一个理由：不分通知类型都要判，因为占的是配置与内存，不是只有发出去才占。
//
// 按键名排序后再逐条判，与 map 的遍历顺序无关：否则同一份配置连着保存两次可能报出
// 不同的键名，用户会以为自己改的地方不对（与 checkNoMaskedLeftover 同一个理由）。
//
// 取值过长那句刻意**不**回显取值本身：请求头的值是加密落盘、界面上脱敏显示的
// （最常见的就是 Authorization），把它抄进错误消息等于让一个凭证经由响应体流出去。
// 报出键名与两个长度已经足够定位是哪一格填过头了。
func checkNotifyHeaders(h map[string]string) error {
	if err := checkLimit("附加请求头", len(h), config.MaxNotifyHeaders); err != nil {
		return err
	}
	keys := make([]string, 0, len(h))
	for k := range h {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	for _, k := range keys {
		if len(k) > config.MaxNotifyHeaderKeyLen {
			return fmt.Errorf("请求头名称「%s」过长（上限 %d 字节）", strutil.Truncate(k, 24, "…"), config.MaxNotifyHeaderKeyLen)
		}
		if n := len(h[k]); n > config.MaxNotifyHeaderValueLen {
			return fmt.Errorf("请求头「%s」的取值过长（上限 %d 字节，当前 %d 字节）", k, config.MaxNotifyHeaderValueLen, n)
		}
	}
	return nil
}

// checkNoMaskedLeftover 检查是否还有字段留着脱敏占位符。理由见调用处。
//
// 地址那一项单独报一句，不留给后面的 http:// 前缀校验去挡：那句话说的是格式，
// 而这里的实际情况是"这个值没能还原回来"，两回事。
//
// 请求头按键名排序后再报，与 map 的遍历顺序无关：同一次保存重试两遍应当得到同一句话，
// 否则用户会以为自己改的地方不对。
func checkNoMaskedLeftover(t config.NotifyTarget) error {
	if t.URL == maskedSecret {
		return fmt.Errorf("地址仍是脱敏占位符，请重新填写完整地址")
	}
	if t.Secret == maskedSecret {
		return fmt.Errorf("加签密钥仍是脱敏占位符，请重新填写")
	}
	keys := make([]string, 0, len(t.Headers))
	for k, v := range t.Headers {
		if v == maskedSecret {
			keys = append(keys, k)
		}
	}
	if len(keys) == 0 {
		return nil
	}
	slices.Sort(keys)
	return fmt.Errorf("请求头「%s」的值仍是脱敏占位符：改过请求头名称之后，需要重新填一次它的值", keys[0])
}

// ---- 消息模板 ----

func (s *Server) registerMessageTemplates(g *gin.RouterGroup) {
	registerCRUD(s, g, "webhook/templates", resource[config.MessageTemplate]{
		get:      func(c *config.Config) []config.MessageTemplate { return c.MessageTemplates },
		set:      func(c *config.Config, v []config.MessageTemplate) { c.MessageTemplates = v },
		id:       func(t *config.MessageTemplate) string { return t.ID },
		setID:    func(t *config.MessageTemplate, id string) { t.ID = id },
		maxCount: config.MaxMessageTemplates,
		modLabel: "消息路由模板",
		itemName: func(t *config.MessageTemplate) string { return t.Name },
		list: func(source []config.MessageTemplate) []config.MessageTemplate {
			out := append([]config.MessageTemplate(nil), source...)
			for i := range out {
				// 老配置里没有 TitleStyle 这个字段。运行期把空值当默认样式处理
				// （见 webhook.MarkdownTitled 的 default 分支），所以列表里也得如实
				// 报出那个默认值——否则面板上的下拉是空的，发出来的却带着三级标题。
				if !config.ValidMarkdownTitleStyle(out[i].TitleStyle) {
					out[i].TitleStyle = config.DefaultMarkdownTitleStyle
				}
			}
			return out
		},
		normalize: func(t *config.MessageTemplate) {
			config.NormalizeMessageTemplate(t)
			t.Updated = time.Now().Unix()
		},
		validate: func(cfg *config.Config, t config.MessageTemplate) error {
			if t.Name == "" {
				return fmt.Errorf("名称不能为空")
			}
			if strings.TrimSpace(t.Body) == "" {
				return fmt.Errorf("模板正文不能为空")
			}
			// 语法在保存时就编译一遍：留到运行期才发现，表现为消息静默发不出去。
			if _, err := tmplx.Compile("body", t.Body); err != nil {
				return fmt.Errorf("正文有语法错误：%w", err)
			}
			if t.Title != "" {
				if _, err := tmplx.Compile("title", t.Title); err != nil {
					return fmt.Errorf("标题有语法错误：%w", err)
				}
			}
			return nil
		},
	})
}

// ---- 模块设置（监听与 HTTPS）----

// 这套设置刻意**不**并进通用设置接口：它属于消息路由这一个模块，
// 放在模块自己的页面上（与 Web 服务的端口设在其父项里同一个思路），
// 用户不必为了改一个 Webhook 端口跑到通用设置里翻。

// webhookServerReq 模块监听设置。
type webhookServerReq struct {
	Enabled bool `json:"enabled"`
	Port    int  `json:"port"`
	// Domain 访问域名。已从 https 里提上来：端口 80 / 443 共用时没有 HTTPS 也要靠它分流。
	// 仍然接受 https.domain，只为兼容旧前端与外部脚本（见下面的取值处）。
	Domain string `json:"domain"`
	Note   string `json:"note"`
	// SourceRetainMB 入站原文留存的额度（MB，0 表示不留存）。
	//
	// 用指针而不是 int：0 在这个字段上是「不留存」这个有效选择，而旧前端与外部脚本
	// 发来的请求里根本没有这个键——值类型下两者都是 0，于是一次"只想改端口"的保存
	// 会把留存悄悄关掉。nil 表示这次请求没提这件事，保持原值不动。
	SourceRetainMB *int `json:"sourceRetainMb"`
	HTTPS          struct {
		Enabled bool   `json:"enabled"`
		CertID  string `json:"certId"`
		Domain  string `json:"domain"`
	} `json:"https"`
}

func (s *Server) handleGetWebhookServer(c *gin.Context) {
	cfg := s.deps.Config.Snapshot()
	respondOK(c, cfg.Webhook)
}

// handleUpdateWebhookServer 保存模块监听设置。
//
// 启用 HTTPS 的校验与面板完全同一套（存在、已启用、未过期、覆盖该域名）：
// 本模块启用 HTTPS 后**没有明文回落**，任一条不满足就是所有第三方来源同时静默失联，
// 因此必须在保存这一步拦下来，而不是等模块起不来才在状态栏里显示一行红字。
//
// 端口校验分三种情形：撞面板端口一律拒绝（面板抢不到端口会 restart 死循环）；
// 撞 Web 服务端口时按域名共用（webhookSharePort 判定）；其余情形本模块自己绑。
func (s *Server) handleUpdateWebhookServer(c *gin.Context) {
	var req webhookServerReq
	if err := c.ShouldBindJSON(&req); err != nil {
		respondError(c, http.StatusBadRequest, "请求参数无效")
		return
	}

	before := s.deps.Config.Snapshot()
	domain, certID, status, err := s.checkWebhookServerReq(before, req)
	if err != nil {
		respondError(c, status, err.Error())
		return
	}

	if err := s.deps.Config.Update(func(cfg *config.Config) {
		// 保存即创建：模块设置那一页在未创建时只有一个「新建」按钮，走的也是这条 PUT。
		// 用户填完端口域名点保存，那一行就该出现，不需要另有一个"创建"动作。
		cfg.Webhook.Created = true
		cfg.Webhook.Enabled = req.Enabled
		cfg.Webhook.Port = req.Port
		cfg.Webhook.Domain = domain
		cfg.Webhook.Note = strings.TrimSpace(req.Note)
		cfg.Webhook.HTTPS.Enabled = req.HTTPS.Enabled
		cfg.Webhook.HTTPS.CertID = certID
		// 没带这个键就不动原值（原因见 webhookServerReq.SourceRetainMB）。
		// 夹取在这里做，不能指望 normalizeWebhook：那个函数只在配置从磁盘装载时跑一遍，
		// 界面保存走的是这条路。少了这一句，一个手写的 99 会原样存进配置，
		// 下一次 setBudget 就照 99 MB 收内容——直到重启才被夹回 3。
		if req.SourceRetainMB != nil {
			cfg.Webhook.SourceRetainMB = config.ClampSourceRetainMB(*req.SourceRetainMB)
		}
		// 接收器的入站地址由「模块域名 + 自己的路径」拼成，模块一创建就该是可用的：
		// 补齐路径为空的那些（手改配置、或删除模块期间新建的），让用户回到接收器页
		// 直接就能启用，而不是先被"路径为空"挡一次。NormalizeReceiver 也做同一件事，
		// 这里显式再来一遍是因为下面要按 before/after 记审计。
		for i := range cfg.WebhookReceivers {
			if cfg.WebhookReceivers[i].Path == "" {
				cfg.WebhookReceivers[i].Path = config.RandomWebhookPath()
			}
		}
	}); err != nil {
		respondError(c, http.StatusInternalServerError, "保存失败")
		return
	}
	s.afterChange()
	if s.deps.Log != nil {
		verb := "禁用"
		if req.Enabled {
			verb = "启用"
		}
		action := "保存"
		if !before.Webhook.Created {
			action = "新建"
		}
		s.deps.Log.Info(fmt.Sprintf("%s 消息路由 模块设置（%s，端口 %d，HTTPS %v）", action, verb, req.Port, req.HTTPS.Enabled),
			"module", "消息路由", "port", req.Port, "https", req.HTTPS.Enabled)
	}

	// 重载是同步的，此时监听已经起好（或已确定起不来），把状态一并回给前端，
	// 用户点完保存就能看到"HTTPS 监听 0.0.0.0:25667"或失败原因，不用再手动刷新。
	respondOK(c, s.webhookServerResult())
}

// webhookServerResult 保存 / 开关的统一响应：带上刚重载出来的运行态。
func (s *Server) webhookServerResult() gin.H {
	out := gin.H{"ok": true}
	if s.deps.Webhook != nil {
		st := s.deps.Webhook.Status()
		out["message"] = st.Message
		out["healthy"] = st.Healthy
	}
	return out
}

// handleToggleWebhookServer 模块设置那一行里的开关：只改 enabled，别的设置一律沿用已存的那份。
// 与接收器 / 通知目标的开关同一个道理（见 registerCRUD 末尾那段注释），只是模块设置是单例、
// 不走通用 CRUD，所以单独写一个。
//
// 启用时照样过 checkWebhookServerReq——拨开关等于"就照现在这份配置上线"，该拦的一条不少；
// 禁用则一律放行：停用是用户从异常状态里退出来的唯一出口，不能被校验挡住。
func (s *Server) handleToggleWebhookServer(c *gin.Context) {
	var req struct {
		Enabled bool `json:"enabled"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		respondError(c, http.StatusBadRequest, "请求参数无效")
		return
	}
	before := s.deps.Config.Snapshot()
	cur := before.Webhook
	if req.Enabled {
		check := webhookServerReq{Enabled: true, Port: cur.Port, Domain: cur.Domain, Note: cur.Note}
		check.HTTPS.Enabled = cur.HTTPS.Enabled
		check.HTTPS.CertID = cur.HTTPS.CertID
		if _, _, status, err := s.checkWebhookServerReq(before, check); err != nil {
			respondError(c, status, err.Error())
			return
		}
	}
	if err := s.deps.Config.Update(func(cfg *config.Config) {
		cfg.Webhook.Enabled = req.Enabled
	}); err != nil {
		respondError(c, http.StatusInternalServerError, "保存失败")
		return
	}
	s.afterChange()
	// 动词是「启用/禁用」而非「保存」：列表上的操作不写保存日志。
	if s.deps.Log != nil {
		verb := "禁用"
		if req.Enabled {
			verb = "启用"
		}
		s.deps.Log.Info(fmt.Sprintf("%s 消息路由 模块设置（端口 %d）", verb, cur.Port),
			"module", "消息路由", "port", cur.Port)
	}
	out := s.webhookServerResult()
	out["enabled"] = req.Enabled
	respondOK(c, out)
}

// receiversUsingWebhookServer 返回仍在启用中的接收器名（最多列前几个）。
//
// 「引用」在这里就是「启用中」：接收器没有指向模块的外键，它靠的是模块那唯一一条监听
// ——模块一没，所有接收器同时失去入口。所以判据只能是启用状态，且必须与
// normalizeWebhook 里那句「未创建则强制停用」同口径，否则会出现
// "接口不让删、加载时却把它们全停了"这种自相矛盾。
func receiversUsingWebhookServer(cfg *config.Config) []string {
	var names []string
	for _, r := range cfg.WebhookReceivers {
		if r.Enabled {
			names = append(names, nameOrID(r.Name, r.ID))
		}
	}
	return names
}

// handleDeleteWebhookServer 删除模块设置那一行。
//
// 删除 = 停止监听 + 抹掉端口/域名/证书 + 那一页回到"未创建"。接收器、模板、目标、
// 规则一律**不动**：它们是用户真正花时间配出来的东西，而模块设置只是一个监听。
// 重新创建之后，这些配置照旧可用（路径也会补齐，见 handleUpdateWebhookServer）。
//
// 有启用中的接收器时拒绝删除：那些接收器此刻正在收生产消息，删掉监听等于让它们
// 集体静默失联，而列表上的开关还是绿的。要删就先把它们停掉——这一步必须由用户自己
// 做，接口替他停等于悄悄掐断一条生产链路。
func (s *Server) handleDeleteWebhookServer(c *gin.Context) {
	before := s.deps.Config.Snapshot()
	if !before.Webhook.Created {
		respondError(c, http.StatusNotFound, "消息路由模块尚未创建")
		return
	}
	if names := receiversUsingWebhookServer(before); len(names) > 0 {
		shown := names
		if len(shown) > 5 {
			shown = shown[:5]
		}
		extra := ""
		if len(names) > len(shown) {
			extra = fmt.Sprintf(" 等 %d 个", len(names))
		}
		respondError(c, http.StatusBadRequest,
			fmt.Sprintf("以下接收器仍在启用中：%s%s，无法删除模块。请先停用这些接收器——模块一旦删除，它们会立刻收不到任何消息",
				strings.Join(shown, "、"), extra))
		return
	}

	port := before.Webhook.Port
	if err := s.deps.Config.Update(func(cfg *config.Config) {
		// 整个换成一份干净的默认值，而不是只把 Created 置假：留着旧端口与旧证书 ID，
		// 下次点新建时表单里会冒出上一次的残留，看着像"没删干净"。
		cfg.Webhook = config.WebhookServer{Listen: "0.0.0.0", Port: config.DefaultWebhookPort}
	}); err != nil {
		respondError(c, http.StatusInternalServerError, "删除失败")
		return
	}
	s.afterChange()
	if s.deps.Log != nil {
		s.deps.Log.Info(fmt.Sprintf("删除 消息路由 模块设置（原端口 %d，接收器与模板等配置保留）", port),
			"module", "消息路由", "port", port)
	}
	respondOK(c, gin.H{"ok": true})
}

// checkWebhookServerReq 校验模块监听设置，返回归一化后的访问域名与证书 ID。
// status 是校验失败时该用的 HTTP 状态码（成功时为 0）。
//
// 保存与开关两条路径共用它：开关也能把一份"停用时存了一半"的配置推上线，
// 两边的判断必须逐字一致，否则会出现"点保存不让、拨开关却让"的分裂行为。
func (s *Server) checkWebhookServerReq(before *config.Config, req webhookServerReq) (string, string, int, error) {
	if req.Port <= 0 || req.Port > 65535 {
		return "", "", http.StatusBadRequest, fmt.Errorf("监听端口必须在 1-65535 之间")
	}
	if req.Enabled && req.Port == before.Panel.Port {
		return "", "", http.StatusBadRequest, fmt.Errorf("端口 %d 与面板管理端口冲突，请改用其他端口", req.Port)
	}

	// 域名先归一化：后面的端口共用判定、证书校验、域名查重都要用同一份小写结果。
	domain := ""
	rawDomain := strings.TrimSpace(req.Domain)
	if rawDomain == "" {
		rawDomain = strings.TrimSpace(req.HTTPS.Domain) // 兼容旧字段
	}
	if rawDomain != "" {
		var err error
		if err = checkRouteDomainSyntax(rawDomain); err != nil {
			return "", "", http.StatusBadRequest, err
		}
		if domain, err = normalizePanelDomain(rawDomain); err != nil {
			return "", "", http.StatusBadRequest, fmt.Errorf("访问域名格式无效：%w", err)
		}
	}

	certID := strings.TrimSpace(req.HTTPS.CertID)
	if req.Enabled {
		if req.HTTPS.Enabled && domain == "" {
			return "", "", http.StatusBadRequest, fmt.Errorf("启用 HTTPS 必须填写有效的访问域名")
		}
		if mustHaveDomainPort(req.Port) && domain == "" {
			return "", "", http.StatusBadRequest, fmt.Errorf("端口 %d 是面板、Web 服务、消息路由都可能用到的公共端口，必须填写访问域名，程序才能按域名分辨请求该给谁", req.Port)
		}
		if _, err := webhookSharePort(before, req.Port, domain, req.HTTPS.Enabled); err != nil {
			return "", "", http.StatusBadRequest, err
		}
		if err := checkPanelDomainReserved(before, domain, "消息路由"); err != nil {
			return "", "", http.StatusBadRequest, err
		}
		if err := checkPortDomainFree(before, req.Port, domain, "", true); err != nil {
			return "", "", http.StatusBadRequest, err
		}
	}

	if req.HTTPS.Enabled {
		if certID == "" {
			return "", "", http.StatusBadRequest, fmt.Errorf("启用 HTTPS 必须选择证书")
		}
		found, enabled := false, false
		for _, item := range before.Certs {
			if item.ID == certID {
				found, enabled = true, item.Enabled
				break
			}
		}
		if !found {
			return "", "", http.StatusBadRequest, fmt.Errorf("所选证书不存在")
		}
		if !enabled {
			return "", "", http.StatusBadRequest, fmt.Errorf("所选证书已被禁用，无法使用；请先到「证书」启用该证书")
		}
		if s.deps.Cert == nil {
			return "", "", http.StatusServiceUnavailable, fmt.Errorf("证书模块未就绪")
		}
		if err := s.deps.Cert.ValidateID(certID, time.Now()); err != nil {
			return "", "", http.StatusBadRequest, err
		}
		if err := s.deps.Cert.ValidateHostname(certID, domain); err != nil {
			return "", "", http.StatusBadRequest, err
		}
	}
	return domain, certID, 0, nil
}

// ---- 动作 ----

// handleWebhookStatus 返回模块运行态：监听情况与计数。
func (s *Server) handleWebhookStatus(c *gin.Context) {
	if s.deps.Webhook == nil {
		respondOK(c, gin.H{"enabled": false})
		return
	}
	st := s.deps.Webhook.Status()
	received, rejected, dropped := s.deps.Webhook.Metrics()
	out := gin.H{
		"message":  st.Message,
		"healthy":  st.Healthy,
		"total":    st.Total,
		"active":   st.Active,
		"received": received,
		"rejected": rejected,
		"dropped":  dropped,
	}
	if s.deps.Notify != nil {
		sent, failed, dropped, pending := s.deps.Notify.Metrics()
		out["sent"] = sent
		out["failed"] = failed
		out["sendDropped"] = dropped
		out["pending"] = pending
	}
	respondOK(c, out)
}

// handleWebhookHistory 返回执行历史，新的在前。
func (s *Server) handleWebhookHistory(c *gin.Context) {
	if s.deps.Webhook == nil {
		respondOK(c, []webhook.HistoryEntry{})
		return
	}
	limit := 200
	if n, err := strconv.Atoi(c.Query("limit")); err == nil && n > 0 && n <= 2000 {
		limit = n
	}
	// event 不认识时会筛出空列表，这里不做白名单校验：界面上的下拉框只给得出合法值，
	// 而手工构造一个拼错的值时"空列表"比"忽略筛选、摆出全部"更贴近实际发生的事。
	list := s.deps.Webhook.History(webhook.HistoryQuery{
		ReceiverID: c.Query("receiverId"),
		Event:      c.Query("event"),
		Limit:      limit,
	})
	if list == nil {
		list = []webhook.HistoryEntry{}
	}
	respondOK(c, list)
}

// handleWebhookSource 返回一条留存的入站原文（执行历史里点「来源」时取）。
//
// 找不到不是错误，而是常态：留存按内存预算淘汰，旧记录的原文早就被顶掉了，
// 而它对应的历史记录还在（历史 2000 条、留存 500 条）。所以这里回 200 + found:false，
// 让界面能说出"这条的原文已经不在内存里了"——回 404 的话，界面只能显示一个通用错误，
// 而那句话会被理解成"接口坏了"。
func (s *Server) handleWebhookSource(c *gin.Context) {
	if s.deps.Webhook == nil {
		respondOK(c, gin.H{"found": false})
		return
	}
	rec, ok := s.deps.Webhook.Source(c.Query("id"))
	if !ok {
		respondOK(c, gin.H{"found": false})
		return
	}
	respondOK(c, gin.H{"found": true, "record": rec})
}

// handleWebhookSourceStats 留存的用量与上限，供面板显示"留了多少条、占了多少"。
// 上限跟着后端常量走，不在前端写死：两处各写一份，改了后端就会在界面上说错话。
func (s *Server) handleWebhookSourceStats(c *gin.Context) {
	if s.deps.Webhook == nil {
		respondOK(c, gin.H{"count": 0, "bytes": 0})
		return
	}
	count, bytes := s.deps.Webhook.SourceStats()
	budget, bodyMax, maxEntries := s.deps.Webhook.SourceLimits()
	respondOK(c, gin.H{
		"count": count, "bytes": bytes,
		"budget": budget, "bodyMax": bodyMax, "maxEntries": maxEntries,
	})
}

// handleWebhookSourceClear 清空全部入站原文留存。
//
// 需要这个按钮，是因为这份数据别处删不掉：它只在内存里，不落盘，也不跟着任何一条
// 配置走——用户看完之后想让这些内容立刻消失（里面可能有姓名、手机号、内部地址），
// 除了重启整个程序、或者把额度调到 0 再调回来，没有别的办法。
//
// 清完不动额度：下一条消息照常留存。要"从此不再留"是另一件事，在模块设置里把额度调成 0。
func (s *Server) handleWebhookSourceClear(c *gin.Context) {
	if s.deps.Webhook == nil {
		respondError(c, http.StatusServiceUnavailable, "消息路由模块不可用")
		return
	}
	cleared := s.deps.Webhook.ClearSources()
	s.deps.Log.Info("入站原文留存已被手动清空", "cleared", cleared)
	respondOK(c, gin.H{"cleared": cleared})
}

// handleWebhookNewPath 生成一个新的随机入站路径，供界面上的"重新生成"按钮使用。
// 由后端生成而不是前端：随机路径是这个入口的主要保护，浏览器端的随机源
// 与"生成规则和后端一致"这两件事都不该由前端负责。
func (s *Server) handleWebhookNewPath(c *gin.Context) {
	respondOK(c, gin.H{"path": config.RandomWebhookPath()})
}

// handleWebhookMeta 返回界面配规则时要用的全部元数据。
//
// 由后端下发而不是前端硬编码：算子列表、模板函数、内置字段名都在 Go 侧定义，
// 两边各写一份必然会漂——用户会在下拉框里看到一个运行期并不认得的算子。
func (s *Server) handleWebhookMeta(c *gin.Context) {
	// countOperators 单独下发：这一组的比较值必须是数字，前端据此把输入框换成数字框，
	// 而不是靠在前端复写一份"哪些算子是数量比较"的名单。
	countOps := make([]string, 0, 5)
	for _, op := range webhook.Operators {
		if webhook.IsCountOperator(op) {
			countOps = append(countOps, op)
		}
	}
	respondOK(c, gin.H{
		"operators":      webhook.Operators,
		"countOperators": countOps,
		"sourceTypes":    []string{"auto", "json", "kv", "txt"},
		"templateFuncs":  tmplx.FuncNames(),
		"reservedFields": webhook.ReservedFieldNames,
		"targetTypes":    notify.SupportedTypes(),
		"titleStyles":    config.MarkdownTitleStyles,
		"limits": gin.H{
			"receivers":  config.MaxWebhookReceivers,
			"rules":      config.MaxWebhookRules,
			"mappings":   config.MaxWebhookMappings,
			"conditions": config.MaxWebhookConditions,
			"branches":   config.MaxWebhookBranches,
			"templates":  config.MaxMessageTemplates,
			"targets":    config.MaxNotifyTargets,
			"maxBodyKb":  config.MaxWebhookBodyKB,
			"maxRetry":   config.MaxNotifyRetry,
			"maxTimeout": config.MaxNotifyTimeoutSec,
			// 入站路径：上限用于校验，weakPathLen 用于提示"这条路径短到不足以当保护"。
			// 两个数都由后端下发，免得前端另写一份门槛、改了一边忘了另一边。
			"pathLen":     config.MaxWebhookPathLen,
			"weakPathLen": config.WeakWebhookPathLen,
			// 通知目标内部的几项。headers 界面上已经拦了（到上限就禁掉「添加请求头」，
			// 并在提示里写出这个数）；其余三项目前只在保存时拦，下发是为了将来要拦时
			// 前端不必再抄一遍数字——抄一遍就有两份，改了一边忘了另一边的话，
			// 界面上让你填、保存时被拒。
			"headers":         config.MaxNotifyHeaders,
			"headerKeyLen":    config.MaxNotifyHeaderKeyLen,
			"headerValueLen":  config.MaxNotifyHeaderValueLen,
			"bodyTemplateLen": config.MaxNotifyBodyTemplateLen,
			"atMobiles":       config.MaxNotifyAtMobiles,
		},
		"defaults": gin.H{
			"port":         config.DefaultWebhookPort,
			"bodyKb":       config.DefaultWebhookBodyKB,
			"timeout":      config.DefaultNotifyTimeoutSec,
			"retry":        config.DefaultNotifyRetry,
			"pathLen":      config.WebhookPathLen,
			"maxPathLen":   config.MaxWebhookPathLen,
			"testRunTtlS":  int(webhook.TestRunTTL / time.Second),
			"testRunPollS": 2,
			// 样本载荷（试运行抓包）在内存里的存活上限。前端本地缓存的那一份副本
			// 必须用同一个值过期，否则界面上会留着一份后端早已销毁的载荷。
			"sampleTtlS": int(webhook.CaptureTTL / time.Second),
		},
	})
}

// dryRunReq 试运行请求。
type dryRunReq struct {
	Body    string            `json:"body"`
	Headers map[string]string `json:"headers"`
	Query   string            `json:"query"`
}

// handleWebhookDryRun 用一段样本载荷跑完整条流水线，但不投递。
func (s *Server) handleWebhookDryRun(c *gin.Context) {
	if s.deps.Webhook == nil {
		respondError(c, http.StatusServiceUnavailable, "消息路由模块不可用")
		return
	}
	var req dryRunReq
	if err := c.ShouldBindJSON(&req); err != nil {
		respondError(c, http.StatusBadRequest, "请求参数无效")
		return
	}
	if len(req.Body) > dryRunBodyLimit {
		respondError(c, http.StatusBadRequest, "样本载荷过大，请截取其中一段")
		return
	}
	out, err := s.deps.Webhook.DryRun(c.Param("id"), []byte(req.Body), req.Headers, req.Query)
	if err != nil {
		respondError(c, http.StatusBadRequest, err.Error())
		return
	}
	respondOK(c, out)
}

// ---- 模板预览 ----
//
// 与试运行的分工：试运行回答"这条消息会不会命中规则、会发给谁"，预览回答"这个模板
// 渲染出来长什么样"。所以预览不需要规则、不需要通知目标，接收器也可以不选
//（见 webhook.PreviewTemplate）。
//
// 路由挂在 templates 下但**不带 :id**：预览的是编辑框里还没保存的草稿。
// 要求先保存再预览的话，用户为了试一版排版得先把一个错模板存进配置里。

// previewReq 模板预览请求：模板草稿 + 一段样本载荷。
type previewReq struct {
	// ReceiverID 借哪个接收器的字段映射与来源类型来解析样本。留空表示不借：
	// 别名会一律取不到值，界面据此提示用户选一个。
	ReceiverID string            `json:"receiverId"`
	Format     string            `json:"format"`
	Title      string            `json:"title"`
	TitleStyle string            `json:"titleStyle"`
	Body       string            `json:"body"`
	Sample     string            `json:"sample"`
	Headers    map[string]string `json:"headers"`
	Query      string            `json:"query"`
}

// previewTemplateLimit 模板草稿（标题 + 正文）的长度上限。
// 与渲染上限同值：比这更长的模板连渲染结果都装不下。
const previewTemplateLimit = tmplx.MaxRenderBytes

// handleTemplatePreview 渲染一份未保存的模板草稿，只读、无副作用。
func (s *Server) handleTemplatePreview(c *gin.Context) {
	if s.deps.Webhook == nil {
		respondError(c, http.StatusServiceUnavailable, "消息路由模块不可用")
		return
	}
	var req previewReq
	if err := c.ShouldBindJSON(&req); err != nil {
		respondError(c, http.StatusBadRequest, "请求参数无效")
		return
	}
	if len(req.Sample) > dryRunBodyLimit {
		respondError(c, http.StatusBadRequest, "样本载荷过大，请截取其中一段")
		return
	}
	if len(req.Body)+len(req.Title) > previewTemplateLimit {
		respondError(c, http.StatusBadRequest, "模板内容过长")
		return
	}
	respondOK(c, s.deps.Webhook.PreviewTemplate(req.ReceiverID, []byte(req.Sample), req.Headers, req.Query,
		webhook.TemplateSpec{
			Format: req.Format, Title: req.Title, Body: req.Body, TitleStyle: req.TitleStyle,
		}))
}

// ---- 实时试运行 ----
//
// 三个动作对应界面上的一个按钮加一次轮询：开始 → 轮询取抓包 → 停止。
//
// 试运行**只影响这一个接收器**，且期间它的消息不再真实转发（见 webhook/testrun.go）。
// 开始与停止都做写审计：这是一个能让生产消息暂时不发出去的开关，
// 事后要能回答"那段时间为什么没收到消息"。
//
// 状态放在模块的内存里、不落配置：它是"此刻正在调试"这种瞬时状态，
// 重启进程后本就该恢复正常转发，写进配置反而会让一个忘了关的开关跨重启存活。

func (s *Server) handleTestRunStart(c *gin.Context) {
	if s.deps.Webhook == nil {
		respondError(c, http.StatusServiceUnavailable, "消息路由模块不可用")
		return
	}
	id := c.Param("id")
	if err := s.deps.Webhook.TestRunStart(id); err != nil {
		respondError(c, http.StatusBadRequest, err.Error())
		return
	}
	if s.deps.Log != nil {
		s.deps.Log.Info("开始试运行 消息路由接收器（期间消息不会真实转发）",
			"module", "消息路由接收器", "id", id)
	}
	respondOK(c, s.deps.Webhook.TestRunState(id))
}

func (s *Server) handleTestRunStop(c *gin.Context) {
	if s.deps.Webhook == nil {
		respondError(c, http.StatusServiceUnavailable, "消息路由模块不可用")
		return
	}
	id := c.Param("id")
	// 不校验接收器是否存在：停止是幂等的收尾动作，接收器刚被删掉时也该能停干净。
	s.deps.Webhook.TestRunStop(id)
	if s.deps.Log != nil {
		s.deps.Log.Info("停止试运行 消息路由接收器（消息恢复真实转发）",
			"module", "消息路由接收器", "id", id)
	}
	respondOK(c, s.deps.Webhook.TestRunState(id))
}

func (s *Server) handleTestRunState(c *gin.Context) {
	if s.deps.Webhook == nil {
		respondOK(c, webhook.TestRunState{})
		return
	}
	respondOK(c, s.deps.Webhook.TestRunState(c.Param("id")))
}

// handleNotifyTest 往指定目标发一条测试消息。
//
// 走同步 Send 而不是入队：用户点了"测试"就是要立刻知道通不通，
// 入队会让按钮永远显示成功、真正的失败只出现在历史列表里。
//
// 正文、格式、标题都由面板传进来（都可以不传）：调通道时要看的往往不是
// "通不通"，而是"这条 markdown 在钉钉里长什么样"。测试消息不走模板，
// 也不做变量渲染——手填的就是最终发出去的内容。
func (s *Server) handleNotifyTest(c *gin.Context) {
	if s.deps.Notify == nil {
		respondError(c, http.StatusServiceUnavailable, "出站模块不可用")
		return
	}
	id := c.Param("id")
	var body struct {
		Message    string `json:"message"`
		Format     string `json:"format"`
		Title      string `json:"title"`
		TitleStyle string `json:"titleStyle"`
	}
	_ = c.ShouldBindJSON(&body)
	msg := strings.TrimSpace(body.Message)
	if msg == "" {
		msg = "这是一条来自 Mantou 的测试消息，收到说明该通知目标配置正确。"
	}
	if len(msg) > notifyTestBodyLimit {
		respondError(c, http.StatusBadRequest, "测试正文过长")
		return
	}
	title := strings.TrimSpace(body.Title)
	if title == "" {
		title = "Mantou 测试消息"
	}
	format := "text"
	if body.Format == "markdown" {
		format = "markdown"
		if !config.ValidMarkdownTitleStyle(body.TitleStyle) {
			body.TitleStyle = config.DefaultMarkdownTitleStyle
		}
		// 与真实投递走同一个拼法，否则用户用测试调出来的样式，真发时又变了。
		msg = webhook.MarkdownTitled(msg, title, body.TitleStyle)
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), time.Duration(config.MaxNotifyTimeoutSec)*time.Second)
	defer cancel()
	results, err := s.deps.Notify.Send(ctx, notify.Request{
		TargetIDs: []string{id},
		Title:     title,
		Message:   msg,
		Format:    format,
		Source:    "测试发送",
	})
	if err != nil {
		respondError(c, http.StatusBadRequest, err.Error())
		return
	}
	if len(results) == 0 {
		respondError(c, http.StatusBadRequest, "目标不存在或已停用")
		return
	}
	r := results[0]
	if !r.OK {
		respondError(c, http.StatusBadGateway, "发送失败："+r.Status)
		return
	}
	if s.deps.Log != nil {
		s.deps.Log.Info("测试发送 消息路由通知目标 下 "+r.TargetName, "module", "消息路由通知目标", "id", id)
	}
	// 回给界面的是状态码与耗时，失败时 r.Status 里还带着对方响应体的一小段摘要
	// （见 notify.interpret，截到 200 字节）。这构成一条出站探测反馈：
	// 已登录的管理员把目标指向任意 host:port，点一下测试就能从"通不通、多少毫秒、
	// 4xx 时对方回了什么"里读出内网信息。
	//
	// 摘要仍然保留，因为它换来的是排障能力：钉钉与企业微信在**业务失败时也返回 200**，
	// 真正的原因只在响应体的 errmsg 里（sign not match、机器人已停用、触发频率限制），
	// 去掉这段摘要，"配置全对但群里收不到"就退化成一句无从下手的"发送失败"。
	//
	// 这条探测通道的界不在这里，而在两处：一是这个接口要求已登录会话，
	// 二是「内网防护」开关（Settings.Security.BlockPrivateNetwork）——它一打开，
	// 目标解析到内网 / 保留地址时投递与测试一并被拒。它默认关闭是为了兼容
	// 接收端本就在内网的自建场景，那个取舍写在 config.Security 上，不在这里翻案。
	respondOK(c, gin.H{"ok": true, "costMs": r.CostMS, "status": r.Status})
}
