package server

import (
	"fmt"
	"net/http"
	"sort"
	"strings"

	"github.com/gin-gonic/gin"

	"mantou/internal/config"
)

// 本文件是「发送规则」那一页的接口层。
//
// 规则在配置里住在接收器下面（config.WebhookReceiver.Rules），但用户想的是"一条规则"：
// 哪条规则把哪种消息发到了哪个群。所以这里给它一套自己的增删改查，
// 而不是让界面把整个接收器读出来、改一改、再整份写回去。
//
// 整份写回的代价是实打实的，与 registerCRUD 里那个列表开关不用整行 PUT 是同一个理由：
// 界面手里那份接收器是打开弹窗那一刻的，这中间接收器可能已经在别处（另一个标签页、
// 直接调接口）被改过，写回就把那些改动一起盖掉；接收器的令牌在列表接口里还是脱敏的，
// 整份写回还得让 ****** 在网上来回跑一趟才不至于把令牌存成占位符。
// 与之对称的另一半在 registerWebhookReceivers 的 normalize 里：接收器的 PUT 不再改规则。
//
// 路由是两种形状：
//
//	GET    /webhook/rules                              跨接收器的扁平列表（那一页的表格）
//	POST   /webhook/receivers/:id/rules                在某个接收器下新建一条
//	PUT    /webhook/receivers/:id/rules/:rid           保存一条（可换接收器，见 ruleSaveReq）
//	POST   /webhook/receivers/:id/rules/:rid/toggle    列表里那个启用开关
//	DELETE /webhook/receivers/:id/rules/:rid           删除一条
//
// 列表扁平、增删改嵌套，是因为这两件事的自然单位不同：找规则时用户不关心它挂在谁下面，
// 改规则时"哪个接收器的哪条"才是唯一标识——规则 ID 只在接收器内唯一。
//
// 落盘一律沿用本项目的老规矩：改动放进 Config.Update 的回调里做，校验紧跟其后，
// 不过就地回滚（同 handleToggleWebServiceChild）。Update 是"克隆→改副本→写盘→替换"，
// 回滚成原样时连磁盘都不会碰（configEqual 短路），所以不存在写坏一半的中间态。

// ruleModLabel 审计日志里的模块名。与界面上那个页签同名，
// 这样从日志里看到的动作能直接对上用户点的地方。
const ruleModLabel = "消息路由发送规则"

// ruleItem 扁平列表里的一行：规则本体，加上它属于哪个接收器。
//
// 内嵌 config.WebhookRule 而不是重列一遍字段：规则以后加字段，这个接口自动跟上，
// 不会出现"配置里有、列表里看不到"的漏项。ReceiverEnabled 给界面用来提示
// "这条规则所在的接收器是停用的，它现在不会被执行"——规则自己开着并不代表它在跑。
type ruleItem struct {
	config.WebhookRule
	ReceiverID      string `json:"receiverId"`
	ReceiverName    string `json:"receiverName"`
	ReceiverEnabled bool   `json:"receiverEnabled"`
}

// ruleSaveReq 新建/保存一条规则的请求体。
//
// ReceiverID 是这条规则要归到哪个接收器，留空表示不动（就用路径里那个）。
// 允许改是因为编辑弹窗里那个「接收器」下拉框必须是能选的：一个选不动的下拉框在骗人，
// 而选错接收器之后唯一的出路不该是"删掉、去另一个接收器下把条件重配一遍"。
type ruleSaveReq struct {
	config.WebhookRule
	ReceiverID string `json:"receiverId"`
}

func (s *Server) registerWebhookRules(g *gin.RouterGroup) {
	g.GET("/webhook/rules", s.handleListWebhookRules)
	g.POST("/webhook/receivers/:id/rules", s.handleCreateWebhookRule)
	g.PUT("/webhook/receivers/:id/rules/:rid", s.handleUpdateWebhookRule)
	g.POST("/webhook/receivers/:id/rules/:rid/toggle", s.handleToggleWebhookRule)
	g.DELETE("/webhook/receivers/:id/rules/:rid", s.handleDeleteWebhookRule)
}

// handleListWebhookRules 列出全部接收器下的全部规则。
//
// 顺序是"接收器在配置里的顺序 → 规则的优先级"，与运行期真正的匹配顺序一致
// （见 webhook.compileReceiver 里那次按 Priority 的稳定排序）。列表照着这个顺序排，
// 用户才能顺着往下读出"同一个接收器里哪条先命中"——这正是 continue 开关的意义所在。
func (s *Server) handleListWebhookRules(c *gin.Context) {
	cfg := s.deps.Config.Snapshot()
	out := make([]ruleItem, 0, 16)
	for i := range cfg.WebhookReceivers {
		rc := &cfg.WebhookReceivers[i]
		start := len(out)
		for j := range rc.Rules {
			out = append(out, ruleItem{
				WebhookRule:     rc.Rules[j],
				ReceiverID:      rc.ID,
				ReceiverName:    rc.Name,
				ReceiverEnabled: rc.Enabled,
			})
		}
		sub := out[start:]
		sort.SliceStable(sub, func(a, b int) bool { return sub[a].Priority < sub[b].Priority })
	}
	respondOK(c, out)
}

// handleCreateWebhookRule 在指定接收器下新建一条规则。
func (s *Server) handleCreateWebhookRule(c *gin.Context) {
	rid := c.Param("id")
	var req ruleSaveReq
	if err := c.ShouldBindJSON(&req); err != nil {
		respondError(c, http.StatusBadRequest, "请求参数无效")
		return
	}
	newID, err := genID()
	if err != nil {
		respondError(c, http.StatusInternalServerError, "生成规则 ID 失败")
		return
	}

	cfg := s.deps.Config.Snapshot()
	rc := findWebhookReceiver(cfg, rid)
	if rc == nil {
		respondError(c, http.StatusNotFound, "接收器不存在，可能已被删除，请刷新页面")
		return
	}

	// ID 在服务端生成。前端自己编 ID 的话，两个标签页同时新建就可能撞车，
	// 而"规则 ID"是审计日志与执行历史里唯一能反查到这条规则的东西。
	ru := req.WebhookRule
	ru.ID = "r_" + newID
	config.NormalizeRule(&ru)
	if ru.Priority <= 0 {
		// 留空按"排在现有规则后面"补一个：优先级是给"先匹配谁"用的，
		// 全是 0 时顺序就退化成配置里的物理顺序，用户改了优先级却看不出效果。
		ru.Priority = (len(rc.Rules) + 1) * 10
	}

	var validErr error
	found := false
	if err := s.deps.Config.Update(func(cfg *config.Config) {
		i := webhookReceiverIndex(cfg, rid)
		if i < 0 {
			return
		}
		found = true
		orig := cfg.WebhookReceivers[i].Rules
		cfg.WebhookReceivers[i].Rules = putRule(orig, ru)
		if err := validateReceiver(cfg, cfg.WebhookReceivers[i]); err != nil {
			cfg.WebhookReceivers[i].Rules = orig
			validErr = err
		}
	}); err != nil {
		respondError(c, http.StatusInternalServerError, "保存失败")
		return
	}
	if !found {
		respondError(c, http.StatusNotFound, "接收器不存在，可能已被删除，请刷新页面")
		return
	}
	if validErr != nil {
		respondError(c, http.StatusBadRequest, validErr.Error())
		return
	}
	s.afterChange()
	s.logOp("新增", ruleModLabel, ru.ID, ruleAuditName(rc.Name, ru), ruleAuditDetail(ru))
	respondOK(c, ruleItem{WebhookRule: ru, ReceiverID: rc.ID, ReceiverName: rc.Name, ReceiverEnabled: rc.Enabled})
}

// handleUpdateWebhookRule 保存一条规则；请求体里的 receiverId 与路径不同时，顺带把它挪过去。
func (s *Server) handleUpdateWebhookRule(c *gin.Context) {
	from, rid := c.Param("id"), c.Param("rid")
	var req ruleSaveReq
	if err := c.ShouldBindJSON(&req); err != nil {
		respondError(c, http.StatusBadRequest, "请求参数无效")
		return
	}
	to := strings.TrimSpace(req.ReceiverID)
	if to == "" {
		to = from
	}

	cfg := s.deps.Config.Snapshot()
	src := findWebhookReceiver(cfg, from)
	if src == nil || ruleIndex(src.Rules, rid) < 0 {
		respondError(c, http.StatusNotFound, "规则不存在，可能已被删除，请刷新页面")
		return
	}
	dst := findWebhookReceiver(cfg, to)
	if dst == nil {
		respondError(c, http.StatusNotFound, "选择的接收器不存在，可能已被删除，请刷新页面")
		return
	}

	// ID 只认路径里那个：请求体里带来的 ID 若与路径不一致，按路径为准改那一条，
	// 而不是凭请求体去改另一条——后者会让一次"保存"悄悄落到用户没打开的规则上。
	ru := req.WebhookRule
	ru.ID = rid
	config.NormalizeRule(&ru)
	if ru.Priority <= 0 {
		ru.Priority = (len(dst.Rules) + 1) * 10
	}
	moved := to != from
	dstName, srcName := dst.Name, src.Name

	var validErr error
	found := false
	if err := s.deps.Config.Update(func(cfg *config.Config) {
		si, di := webhookReceiverIndex(cfg, from), webhookReceiverIndex(cfg, to)
		if si < 0 || di < 0 || ruleIndex(cfg.WebhookReceivers[si].Rules, rid) < 0 {
			return
		}
		found = true
		origSrc, origDst := cfg.WebhookReceivers[si].Rules, cfg.WebhookReceivers[di].Rules
		if si == di {
			cfg.WebhookReceivers[si].Rules = putRule(origSrc, ru)
			if err := validateReceiver(cfg, cfg.WebhookReceivers[si]); err != nil {
				cfg.WebhookReceivers[si].Rules = origSrc
				validErr = err
			}
			return
		}
		cfg.WebhookReceivers[si].Rules = dropRule(origSrc, rid)
		cfg.WebhookReceivers[di].Rules = putRule(origDst, ru)
		// 只校验目标接收器：源接收器少了一条规则，约束只会更松（同删除那条路径）。
		// 反过来校验源的话，源上另有一条早就不合法的规则会把这次搬迁一起挡住，
		// 而用户此刻要做的恰恰是把规则挪走。
		if err := validateReceiver(cfg, cfg.WebhookReceivers[di]); err != nil {
			cfg.WebhookReceivers[si].Rules = origSrc
			cfg.WebhookReceivers[di].Rules = origDst
			validErr = err
		}
	}); err != nil {
		respondError(c, http.StatusInternalServerError, "保存失败")
		return
	}
	if !found {
		respondError(c, http.StatusNotFound, "规则不存在，可能已被删除，请刷新页面")
		return
	}
	if validErr != nil {
		respondError(c, http.StatusBadRequest, validErr.Error())
		return
	}
	s.afterChange()
	extra := ruleAuditDetail(ru)
	if moved {
		// 搬迁单独记一句：一条规则换了接收器等于换了入站地址，
		// 只记"保存"的话，日后查"这条规则怎么突然不收消息了"根本查不出来。
		extra = "（从接收器「" + srcName + "」移到「" + dstName + "」）" + extra
	}
	s.logOp("保存", ruleModLabel, rid, ruleAuditName(dstName, ru), extra)
	respondOK(c, ruleItem{WebhookRule: ru, ReceiverID: to, ReceiverName: dstName, ReceiverEnabled: dst.Enabled})
}

// handleToggleWebhookRule 启用或禁用一条规则（列表里那个开关）。
//
// 与别处的开关同口径：只在启用这一侧校验。禁用必须永远走得通，
// 否则一条存得下却跑不起来的规则会把用户锁在"开着且报错"里，连关掉都做不到。
func (s *Server) handleToggleWebhookRule(c *gin.Context) {
	rid, ruleID := c.Param("id"), c.Param("rid")
	var req struct {
		Enabled bool `json:"enabled"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		respondError(c, http.StatusBadRequest, "请求参数无效")
		return
	}

	cfg := s.deps.Config.Snapshot()
	rc := findWebhookReceiver(cfg, rid)
	if rc == nil {
		respondError(c, http.StatusNotFound, "接收器不存在，可能已被删除，请刷新页面")
		return
	}
	k := ruleIndex(rc.Rules, ruleID)
	if k < 0 {
		respondError(c, http.StatusNotFound, "规则不存在，可能已被删除，请刷新页面")
		return
	}
	name, rcName := ruleAuditName(rc.Name, rc.Rules[k]), rc.Name

	var validErr error
	found := false
	if err := s.deps.Config.Update(func(cfg *config.Config) {
		i := webhookReceiverIndex(cfg, rid)
		if i < 0 {
			return
		}
		j := ruleIndex(cfg.WebhookReceivers[i].Rules, ruleID)
		if j < 0 {
			return
		}
		found = true
		next := append([]config.WebhookRule(nil), cfg.WebhookReceivers[i].Rules...)
		was := next[j].Enabled
		next[j].Enabled = req.Enabled
		orig := cfg.WebhookReceivers[i].Rules
		cfg.WebhookReceivers[i].Rules = next
		if req.Enabled {
			if err := validateReceiver(cfg, cfg.WebhookReceivers[i]); err != nil {
				next[j].Enabled = was
				cfg.WebhookReceivers[i].Rules = orig
				validErr = err
			}
		}
	}); err != nil {
		respondError(c, http.StatusInternalServerError, "保存失败")
		return
	}
	if !found {
		respondError(c, http.StatusNotFound, "规则不存在，可能已被删除，请刷新页面")
		return
	}
	if validErr != nil {
		respondError(c, http.StatusBadRequest, validErr.Error())
		return
	}
	s.afterChange()
	verb := "禁用"
	if req.Enabled {
		verb = "启用"
	}
	s.logOp(verb, ruleModLabel, ruleID, name, "（接收器："+rcName+"）")
	respondOK(c, gin.H{"id": ruleID, "receiverId": rid, "enabled": req.Enabled})
}

// handleDeleteWebhookRule 删除一条规则。
//
// 不做校验：删掉一条规则只会让接收器的约束更松。真正需要拦的是"删完这个接收器
// 一条规则都不剩"吗——不是。没有规则的接收器照样能启用、能收消息（收到就没人处理），
// 这是用户配置过程中的正常中间状态，保存时拦住它等于逼着用户先想好全部规则再动手。
func (s *Server) handleDeleteWebhookRule(c *gin.Context) {
	rid, ruleID := c.Param("id"), c.Param("rid")

	cfg := s.deps.Config.Snapshot()
	rc := findWebhookReceiver(cfg, rid)
	if rc == nil {
		respondError(c, http.StatusNotFound, "接收器不存在，可能已被删除，请刷新页面")
		return
	}
	k := ruleIndex(rc.Rules, ruleID)
	if k < 0 {
		respondError(c, http.StatusNotFound, "规则不存在，可能已被删除，请刷新页面")
		return
	}
	name, rcName := ruleAuditName(rc.Name, rc.Rules[k]), rc.Name

	found := false
	if err := s.deps.Config.Update(func(cfg *config.Config) {
		i := webhookReceiverIndex(cfg, rid)
		if i < 0 || ruleIndex(cfg.WebhookReceivers[i].Rules, ruleID) < 0 {
			return
		}
		found = true
		cfg.WebhookReceivers[i].Rules = dropRule(cfg.WebhookReceivers[i].Rules, ruleID)
	}); err != nil {
		respondError(c, http.StatusInternalServerError, "删除失败")
		return
	}
	if !found {
		respondError(c, http.StatusNotFound, "规则不存在，可能已被删除，请刷新页面")
		return
	}
	s.afterChange()
	s.logOp("删除", ruleModLabel, ruleID, name, "（接收器："+rcName+"）")
	respondOK(c, gin.H{"ok": true})
}

// ---- 小工具 ----

// findWebhookReceiver 在只读快照里按 ID 找接收器。
//
// 返回的指针指向共享配置，**只能读**：Snapshot 与运行中的配置同底（见 config.Manager.Snapshot），
// 就地改会写到别的读者眼皮底下。所有改动都放在 Config.Update 的回调里，那里拿到的是克隆。
func findWebhookReceiver(cfg *config.Config, id string) *config.WebhookReceiver {
	if i := webhookReceiverIndex(cfg, id); i >= 0 {
		return &cfg.WebhookReceivers[i]
	}
	return nil
}

func webhookReceiverIndex(cfg *config.Config, id string) int {
	for i := range cfg.WebhookReceivers {
		if cfg.WebhookReceivers[i].ID == id {
			return i
		}
	}
	return -1
}

func ruleIndex(list []config.WebhookRule, id string) int {
	for i := range list {
		if list[i].ID == id {
			return i
		}
	}
	return -1
}

// putRule 返回一份新切片：ID 已存在就替换那一条，否则追加。
//
// 一律复制而不是就地改，是因为调用方手里那条切片可能还被别人读着；
// 而"存在就替换"让新建、保存、搬迁三条路径共用一个函数，也顺手把重试变成幂等的
// ——同一次搬迁被重发两遍不会在目标接收器下留出两条同 ID 的规则。
func putRule(list []config.WebhookRule, ru config.WebhookRule) []config.WebhookRule {
	out := make([]config.WebhookRule, 0, len(list)+1)
	replaced := false
	for i := range list {
		if list[i].ID == ru.ID {
			out = append(out, ru)
			replaced = true
			continue
		}
		out = append(out, list[i])
	}
	if !replaced {
		out = append(out, ru)
	}
	return out
}

func dropRule(list []config.WebhookRule, id string) []config.WebhookRule {
	out := make([]config.WebhookRule, 0, len(list))
	for i := range list {
		if list[i].ID != id {
			out = append(out, list[i])
		}
	}
	return out
}

// ruleAuditName 审计日志里这条规则叫什么。
// 带上接收器名是刻意的：规则名只在接收器内有意义，两个接收器下各有一条「数值超限」很常见。
func ruleAuditName(receiverName string, ru config.WebhookRule) string {
	return nameOrID(receiverName, "接收器") + " 的规则 " + nameOrID(ru.Name, ru.ID)
}

// ruleAuditDetail 审计日志的补充上下文：这条规则往哪儿发。
// 出问题时要能从一条日志看出"那次改动把消息改发到了哪里"，光有规则名不够。
func ruleAuditDetail(ru config.WebhookRule) string {
	n := len(ru.Targets)
	if n == 0 {
		return "（通知目标：跟随接收器默认）"
	}
	return fmt.Sprintf("（通知目标 %d 个）", n)
}
