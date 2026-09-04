package server

import (
	"fmt"
	"net"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"mantou/internal/config"
	"mantou/internal/inboundfw"
)

// 服务防护（连接层）的接口层：配置读写 + 自动封禁名单的查看与解除。
// 判定逻辑在 internal/inboundfw，配置规则在 internal/config/firewall_global.go。

// gfwBanListLimit 「当前封禁」接口一次最多返回多少条。
//
// 封禁表按内存上限约束（见 config.DefaultGlobalFirewallMemoryMB），全量下发对一个只是想看看
// 谁被拦了的设置页没有意义。总数另行返回（total 字段），不会因为截断而看不出实际规模。
const gfwBanListLimit = 200

// handleGetGlobalFirewall 返回服务防护的当前配置、封禁名单与额度上限。
//
// 业务页（Web 服务 / 消息路由）只取其中的 config 渲染只读状态条，模块页取全量配置与 limits
// 渲染表单。一次接口同时满足两处，避免业务页多发一次请求。
//
// s.gfw 为 nil（运行态还没装配上来）时不报错，只是名单为空：这个接口的主要内容是**配置**，
// 而配置在 s.gfw 之前就已经可读了。为一份读得到的配置回 503，会让模块页整页打不开。
func (s *Server) handleGetGlobalFirewall(c *gin.Context) {
	cfg := s.deps.Config.Snapshot().GlobalFirewall

	bans := []inboundfw.BanView{}
	var banCount int
	if s.gfw != nil {
		// 一次取回列表与总数：分两次调用要抢两次锁，且两次之间表可能已经变了，
		// 于是界面上会出现"列表 3 条、总数 2 条"这种自相矛盾的展示。
		items, total := s.gfw.BanSnapshot(gfwBanListLimit)
		if items != nil {
			bans = items
		}
		banCount = total
	}

	respondOK(c, gin.H{
		"config": firewallGlobalConfig(cfg),
		"bans": gin.H{
			"items": bans,
			"total": banCount,
			"limit": gfwBanListLimit,
		},
		"memory": gin.H{
			// 每条记录的实测近似开销集中在 config.BanEntryBytes，不在这里另写一个数——
			// 折算容量用的 192（含余量）与报告占用用的实测值是两码事，混用会让
			// 界面上的"已用"永远等于"上限 × 占比"，看不出真实水位。
			"usedBytes": banCount * config.BanEntryBytes,
			"limitMB":   cfg.MemoryMB,
		},
		"limits": gin.H{
			"maxIps":           config.GlobalFirewallMaxIPs,
			"maxMemoryMB":      config.MaxGlobalFirewallMemoryMB,
			"maxBanMinutes":    config.MaxGlobalFirewallBanMinutes,
			"minWindowSeconds": config.MinGlobalFirewallWindowSeconds,
			"maxWindowSeconds": config.MaxGlobalFirewallWindowSeconds,
			"minLimit":         config.MinGlobalFirewallLimit,
			"maxLimit":         config.MaxGlobalFirewallLimit,
			"levels": []string{
				config.GlobalFirewallLevelLoose,
				config.GlobalFirewallLevelBalanced,
				config.GlobalFirewallLevelStrict,
				config.GlobalFirewallLevelCustom,
			},
			// presets 下发整张预设表，前端换档位时据此立刻把数值显示出来。
			// 不让前端自己抄一份三组数字：抄了就意味着两边可以各改各的，而且没人会发现。
			"presets": config.GlobalFirewallPresets(),
		},
	})
}

// handleUpdateGlobalFirewall 更新服务防护配置。
//
// 三步顺序同面板入站防护：先校验用户提交的原始值，再按加载期规则规范化，最后落盘。
// 落盘后 config.Manager 会整体替换快照指针，inboundfw 的名单缓存据此自动失效、下一次
// 判定即读到新值。
//
// 刻意**不**调 s.afterChange()：那会重建 Web 服务与消息路由的监听器，把所有在线连接
// 一并掐掉——而服务防护的设计恰恰是"不需要重启也能改"：监听器包装与 ErrorLog 回灌
// 都是无条件挂上的，启用与否每次现读快照（见 inboundfw.Wrap / WrapErrorLog 的说明）。
// 改一条名单就断开所有访客，代价与收益完全不成比例。
func (s *Server) handleUpdateGlobalFirewall(c *gin.Context) {
	var req globalFirewallReq
	if err := c.ShouldBindJSON(&req); err != nil {
		respondError(c, http.StatusBadRequest, "请求参数无效")
		return
	}

	cur := s.deps.Config.Snapshot().GlobalFirewall
	// 名单长度在规范化之前判：normalize 会把超长名单直接截断，截完 Valid 就看不到超限，
	// 用户会以为 300 条都存下了，实际后 44 条被无声丢掉。
	if req.AllowIPs != nil && len(*req.AllowIPs) > config.GlobalFirewallMaxIPs {
		respondError(c, http.StatusBadRequest, fmt.Sprintf("名单最多 %d 条", config.GlobalFirewallMaxIPs))
		return
	}
	if req.DenyIPs != nil && len(*req.DenyIPs) > config.GlobalFirewallMaxIPs {
		respondError(c, http.StatusBadRequest, fmt.Sprintf("名单最多 %d 条", config.GlobalFirewallMaxIPs))
		return
	}

	next := req.policy(cur)
	if verr := next.Valid(); verr != nil {
		respondError(c, http.StatusBadRequest, verr.Error())
		return
	}
	config.NormalizeGlobalFirewall(&next)

	if err := s.deps.Config.Update(func(cfg *config.Config) {
		cfg.GlobalFirewall = next
	}); err != nil {
		respondError(c, http.StatusInternalServerError, "保存配置失败")
		return
	}
	s.deps.Log.Info("服务防护配置已更新",
		"enabled", next.Enabled, "level", next.Level, "autoBan", next.AutoBan)
	respondOK(c, firewallGlobalConfig(next))
}

// handleGetGlobalFirewallBans 返回当前仍在生效的自动封禁（只读内存，不落盘）。
//
// s.gfw 为 nil 时回一份空列表而不是 503：与上面的配置 GET 同口径。
// "运行态还没装配好"对用户来说和"目前没人被封"是同一件事——没有任何可操作的差别，
// 而一个 503 会让设置页弹一次红色报错。
func (s *Server) handleGetGlobalFirewallBans(c *gin.Context) {
	items := []inboundfw.BanView{}
	total := 0
	if s.gfw != nil {
		list, n := s.gfw.BanSnapshot(gfwBanListLimit)
		if list != nil {
			items = list
		}
		total = n
	}
	respondOK(c, gin.H{
		"items": items,
		"total": total,
		"limit": gfwBanListLimit,
	})
}

// handleClearGlobalFirewallBans 解除自动封禁：带 ip 参数解除单个，不带则全部解除。
//
// 需要这个口子是因为自动封禁是机器下的判断，一定会有误伤（家里多人共用出口 IP、
// 某个客户端在重试风暴里刷爆握手）。没有解除入口的话，误伤只能等封禁自然到期，
// 而用户此刻多半正被挡在门外。
func (s *Server) handleClearGlobalFirewallBans(c *gin.Context) {
	if s.gfw == nil {
		respondError(c, http.StatusServiceUnavailable, "服务防护未就绪")
		return
	}
	var req struct {
		IP string `json:"ip"`
	}
	_ = c.ShouldBindJSON(&req)
	if req.IP != "" {
		if net.ParseIP(req.IP) == nil {
			respondError(c, http.StatusBadRequest, "IP 地址无效")
			return
		}
		ok := s.gfw.Unban(req.IP)
		s.deps.Log.Info("服务防护解除封禁", "ip", req.IP, "wasBanned", ok)
		respondOK(c, gin.H{"ok": true, "cleared": boolToInt(ok)})
		return
	}
	n := s.gfw.ClearBans()
	s.deps.Log.Info("服务防护清空封禁名单", "cleared", n)
	respondOK(c, gin.H{"ok": true, "cleared": n})
}

// handleDenyGlobalFirewallBans 把自动封禁里的来源升级成拒绝名单（永久、落盘）。
// 带 ip 升级单个；all=true 升级当前**全部**生效封禁。
//
// 为什么需要服务端的一条专用口子，而不是让前端读一份 denyIps、追加两条再 PUT 回来：
//
//   - PUT 的名单语义是「带了就整体替换」。前端手里那份 denyIps 是打开页面那一刻取的，
//     期间若有另一个管理员（或另一个标签页）加过条目，整体替换会把它们静默抹掉。
//     这里的读—改—写整段在 Config.Update 的写锁内完成，不存在这个窗口。
//   - 加入拒绝名单之后那条临时封禁就没有意义了：判定顺序是 拒绝名单 → …… → 自动封禁，
//     前者已经把它挡死。顺手解除封禁能腾出封禁表的位置（表是有容量上限的），
//     也让「自动封禁」页保持"当下正被机器盯着的那些"这一层语义。两步要么都做要么都不做，
//     放在一个请求里才不会出现"名单加上了、封禁还挂着"的中间态。
//   - 名单有 GlobalFirewallMaxIPs 条的硬上限，而封禁表能装上万条。截断必须被**报出来**：
//     悄悄丢掉后半截，用户会以为一键之后所有来源都封死了。
func (s *Server) handleDenyGlobalFirewallBans(c *gin.Context) {
	var req struct {
		IP  string `json:"ip"`
		All bool   `json:"all"`
	}
	_ = c.ShouldBindJSON(&req)

	// 目标地址。单个来自请求体，全部来自封禁表快照。
	// BanSnapshot(0) 不限条数：界面上只列 gfwBanListLimit 条，但"一键加入黑名单"说的是
	// 当前**全部**生效封禁——按界面那 200 条来办，用户看到的和实际发生的就不是一回事。
	var targets []string
	switch {
	case strings.TrimSpace(req.IP) != "":
		ip := strings.TrimSpace(req.IP)
		if net.ParseIP(ip) == nil {
			respondError(c, http.StatusBadRequest, "IP 地址无效")
			return
		}
		targets = []string{ip}
	case req.All:
		if s.gfw == nil {
			respondError(c, http.StatusServiceUnavailable, "服务防护未就绪")
			return
		}
		items, _ := s.gfw.BanSnapshot(0)
		targets = make([]string, 0, len(items))
		for _, b := range items {
			targets = append(targets, b.IP)
		}
	default:
		respondError(c, http.StatusBadRequest, "请指定要加入拒绝名单的来源")
		return
	}

	// applied 是"最终确实在拒绝名单里"的那些（新加的 + 本来就在的）。
	// 只有它们才该解除封禁：因名单满而没加进去的必须保留封禁，否则那些来源当场恢复访问。
	var added, skipped int
	var capped bool
	var applied []string
	var denyList []string
	if err := s.deps.Config.Update(func(cfg *config.Config) {
		// 每次进来都从当前值重算：Update 可能因写盘失败而整份丢弃，闭包外的计数器
		// 不能跨调用累加（gin 一个请求只调一次，这里是防御性写法，也让本函数可重入）。
		added, skipped, capped = 0, 0, false
		applied = applied[:0]

		cur := cfg.GlobalFirewall.DenyIPs
		seen := make(map[string]bool, len(cur)+len(targets))
		for _, s := range cur {
			seen[s] = true
		}
		next := make([]string, len(cur), len(cur)+len(targets))
		copy(next, cur)
		for _, ip := range targets {
			if seen[ip] {
				skipped++
				applied = append(applied, ip)
				continue
			}
			if len(next) >= config.GlobalFirewallMaxIPs {
				capped = true
				continue // 不 break：后面的地址可能已在名单里，那些仍应算 skipped 并解除封禁
			}
			seen[ip] = true
			next = append(next, ip)
			applied = append(applied, ip)
			added++
		}
		cfg.GlobalFirewall.DenyIPs = next
		// 与保存表单同一套规范化：写法不合法的条目丢掉、去重、按上限截断，
		// 于是"这条口子写进去的"与"加载后跑的"永远是同一份值。
		config.NormalizeGlobalFirewall(&cfg.GlobalFirewall)
		denyList = append([]string{}, cfg.GlobalFirewall.DenyIPs...)
	}); err != nil {
		respondError(c, http.StatusInternalServerError, "保存配置失败")
		return
	}

	// 解除封禁放在落盘**之后**：先解封再落盘的话，写盘失败就等于白白放走了一批来源。
	unbanned := 0
	if s.gfw != nil {
		for _, ip := range applied {
			if s.gfw.Unban(ip) {
				unbanned++
			}
		}
	}
	s.deps.Log.Info("服务防护封禁来源加入拒绝名单",
		"targets", len(targets), "added", added, "skipped", skipped,
		"capped", capped, "unbanned", unbanned, "denyTotal", len(denyList))

	respondOK(c, gin.H{
		"ok":       true,
		"added":    added,
		"skipped":  skipped,
		"capped":   capped,
		"maxIps":   config.GlobalFirewallMaxIPs,
		"unbanned": unbanned,
		// 回传整份名单：前端据此刷新「黑名单」页的文本框，不必自己猜服务端规范化后的结果。
		"denyIps": denyList,
	})
}

// globalFirewallReq 服务防护的提交体。
//
// **每个**字段都是指针，包括两张名单与档位字符串。理由是同一个：这个接口要能接受
// "只带我改了的那几个字段"的提交，而按值接收就分不出"没带这个字段"与"带了个零值"。
// 具体代价各不相同但都不小：
//
//   - 名单按值接收时，一次不带 allowIps 的提交会把用户攒了几十条的允许名单清空；
//   - 档位按值接收时，一次不带 level 的提交会让它变成空串，规范化再把它落到 balanced——
//     用户明明设的是 strict，改一次内存上限就被悄悄降回均衡档。
//
// 布尔字段同样用指针：开关的"关"本身就是有效提交，不能与"没带"混为一谈。
type globalFirewallReq struct {
	Enabled       *bool     `json:"enabled"`
	Level         *string   `json:"level"`
	AllowIPs      *[]string `json:"allowIps"`
	DenyIPs       *[]string `json:"denyIps"`
	AutoBan       *bool     `json:"autoBan"`
	WindowSeconds *int      `json:"windowSeconds"`
	WindowLimit   *int      `json:"windowLimit"`
	BurstSeconds  *int      `json:"burstSeconds"`
	BurstLimit    *int      `json:"burstLimit"`
	BanMinutes    *int      `json:"banMinutes"`
	MemoryMB      *int      `json:"memoryMB"`
}

// policy 把提交体转成配置结构。字段缺省时沿用 cur（当前生效值），
// 于是一次只带部分字段的提交不会把没带的那些重置掉。
func (r *globalFirewallReq) policy(cur config.GlobalFirewall) config.GlobalFirewall {
	out := cur
	if r.Enabled != nil {
		out.Enabled = *r.Enabled
	}
	if r.AutoBan != nil {
		out.AutoBan = *r.AutoBan
	}
	// 名单**带了就整体替换**：空数组表示清空，前端「删除全部」后保存即落空；
	// 没带则保持原样（见类型说明）。
	if r.AllowIPs != nil {
		out.AllowIPs = *r.AllowIPs
	}
	if r.DenyIPs != nil {
		out.DenyIPs = *r.DenyIPs
	}
	if r.Level != nil {
		out.Level = strings.TrimSpace(*r.Level)
	}
	if r.WindowSeconds != nil {
		out.WindowSeconds = *r.WindowSeconds
	}
	if r.WindowLimit != nil {
		out.WindowLimit = *r.WindowLimit
	}
	if r.BurstSeconds != nil {
		out.BurstSeconds = *r.BurstSeconds
	}
	if r.BurstLimit != nil {
		out.BurstLimit = *r.BurstLimit
	}
	if r.BanMinutes != nil {
		out.BanMinutes = *r.BanMinutes
	}
	if r.MemoryMB != nil {
		out.MemoryMB = *r.MemoryMB
	}
	return out
}

// firewallGlobalConfig 把配置结构转成接口所需的形状。
//
// 不再下发拼好的中文 summary：业务页的只读状态条改成用这几个结构化字段自己拼，
// 于是它显示的档位与阈值与模块页同源、也跟着界面语言走（原先那句话是硬编码中文，
// 英文界面上会突然冒出一行中文）。
func firewallGlobalConfig(gf config.GlobalFirewall) gin.H {
	allow := gf.AllowIPs
	if allow == nil {
		allow = []string{}
	}
	deny := gf.DenyIPs
	if deny == nil {
		deny = []string{}
	}
	return gin.H{
		"enabled":       gf.Enabled,
		"level":         gf.Level,
		"allowIps":      allow,
		"denyIps":       deny,
		"autoBan":       gf.AutoBan,
		"windowSeconds": gf.WindowSeconds,
		"windowLimit":   gf.WindowLimit,
		"burstSeconds":  gf.BurstSeconds,
		"burstLimit":    gf.BurstLimit,
		"banMinutes":    gf.BanMinutes,
		"memoryMB":      gf.MemoryMB,
	}
}
