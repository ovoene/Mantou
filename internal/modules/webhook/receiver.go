package webhook

import (
	"fmt"
	"net"
	"sort"
	"strings"
	"text/template"

	"mantou/internal/config"
	"mantou/internal/ipx"
	"mantou/internal/strutil"
	"mantou/internal/tmplx"
)

// 本文件把配置编译成运行态。
//
// 为什么要有这一层：条件匹配、字段映射、模板渲染都是**每请求**成本，而路径解析、
// 正则编译、模板解析都只依赖配置。一个接收器 50 条规则 × 20 个条件，
// 若在请求路径上现解析，每条消息就要做上千次 strings.Split 和若干次 regexp.Compile。
// 编译期做一次，请求期只做取值与比较。
//
// 编译期发现的问题（模板不存在、正则写错）一律**保留条目 + 记一条 warning**，
// 不静默丢弃：丢掉一条规则会让后续规则意外命中，把消息发到错误的群里。

// mappingRT 一条字段映射的运行态。
type mappingRT struct {
	name string
	segs []segment
	def  string
}

// requiredRT 已删除：必填校验取消了。缺字段交给模板处理（取不到就是空），
// 试运行页会把取不到值的路径高亮出来——那比一条 400 更能说明问题在哪。

// ruleRT 一条消息规则的运行态。
type ruleRT struct {
	cfg   config.WebhookRule
	conds condGroup
	// branches 输出分支，至少一个：单输出的规则（cfg.Branches 为空，也是所有老配置的
	// 形态）编译成一个"无附加条件"的分支。这样 process 只有一条代码路径，
	// 不必在每处都分"有分支/没分支"两种情况——那种分叉迟早会两边跑出不同的结果。
	branches []branchRT
}

// branchRT 一个输出分支的运行态。
type branchRT struct {
	cfg   config.RuleBranch
	conds condGroup
	body  *template.Template
	title *template.Template
	// format / titleStyle 来自这个分支引用的模板。分支各选各的模板，
	// 因此同一条规则的两个分支完全可以一个发纯文本、一个发 markdown。
	format     string
	titleStyle string
	// tmplName 引用的模板名，只给试运行面板显示"这一条是哪个模板渲染出来的"。
	// 两个分支的正文常常长得很像（同一批字段、不同措辞），只看渲染结果分不出
	// 是分支的条件筛错了还是模板选错了。
	tmplName string
	// err 模板缺失或解析失败的原因。只废掉**这一个**分支：同一条规则的其它分支是用户
	// 显式配的另一个出口，不该被邻居的错字连带掐掉。但出错之后不再往后比对**规则**
	// （见 process），理由与从前一样——跳过去等于把"模板配错了"变成"消息发到了别的群"。
	err error
}

// receiverRT 一个接收器的运行态。
type receiverRT struct {
	cfg     config.WebhookReceiver
	maxBody int64

	// rate 每秒允许的请求数，0 表示不限流。
	//
	// 桶表不在这里：它挂在模块上、被所有接收器共用（见 Module.limiter 与
	// ipx.IPLimiter 的说明）。放在运行态里的话，每个接收器各一张 8192 桶的表，
	// 那句"最多 0.9 MB"的保护就被接收器个数乘掉了。
	rate  float64
	allow *ipx.Matcher // nil 表示不启用白名单
	deny  *ipx.Matcher // nil 表示不启用黑名单

	// keywords 关键词准入的比对词，已折成小写；空表示不做这项检查。
	// keywordAll 为真时要求全部出现，否则任一命中即通过。
	keywords   []string
	keywordAll bool

	rootSegs []segment
	mappings []mappingRT
	rules    []ruleRT

	// warnings 编译期发现的配置问题，进模块状态与启动日志。
	warnings []string
}

// routeTable 路径到接收器的索引，Reload 时整体替换。
type routeTable struct {
	byPath map[string]*receiverRT
	// byPathAll 含**停用**接收器的路径索引，只给试运行用（见 testrun.go）。
	// 停用的接收器要能在界面上开试运行、对着真实推送把路径和模板调通，再启用——
	// 否则用户只能先把一个没调好的接收器挂到公网上去试。
	// 它不参与正常入站：serve 只在该接收器的试运行开着时才查这张表。
	byPathAll map[string]*receiverRT
	list      []*receiverRT // 按配置顺序（含停用），供状态展示与试运行查找
	total     int
	active    int
	warnings  int
}

// compileAll 把整份配置编译成路由表。不修改传入的 cfg（Reload 契约）。
func compileAll(cfg *config.Config) *routeTable {
	tmpls := make(map[string]config.MessageTemplate, len(cfg.MessageTemplates))
	for _, t := range cfg.MessageTemplates {
		tmpls[t.ID] = t
	}

	rt := &routeTable{
		byPath:    make(map[string]*receiverRT, len(cfg.WebhookReceivers)),
		byPathAll: make(map[string]*receiverRT, len(cfg.WebhookReceivers)),
	}
	rt.total = len(cfg.WebhookReceivers)
	for _, rc := range cfg.WebhookReceivers {
		r := compileReceiver(rc, tmpls)
		rt.list = append(rt.list, r)
		if _, dup := rt.byPathAll[rc.Path]; !dup {
			rt.byPathAll[rc.Path] = r
		}
		if !rc.Enabled {
			continue
		}
		// 路径撞车：先登记的赢。规范化不做去重（它只管单条的形态），
		// 而这里必须给出确定的结果——静默让后者覆盖前者会表现为"某个来源突然全部失联"。
		if prev, dup := rt.byPath[rc.Path]; dup {
			r.warnings = append(r.warnings,
				fmt.Sprintf("入站路径 %q 与接收器 %q 重复，本接收器不会收到任何消息", rc.Path, prev.cfg.Name))
		} else {
			rt.byPath[rc.Path] = r
		}
		rt.active++
		rt.warnings += len(r.warnings)
	}
	return rt
}

// compileReceiver 编译单个接收器。
func compileReceiver(rc config.WebhookReceiver, tmpls map[string]config.MessageTemplate) *receiverRT {
	r := &receiverRT{cfg: rc, rootSegs: parsePath(rc.RootPath)}

	kb := rc.MaxBodyKB
	if kb <= 0 {
		kb = config.DefaultWebhookBodyKB
	} else if kb > config.MaxWebhookBodyKB {
		kb = config.MaxWebhookBodyKB
	}
	r.maxBody = int64(kb) << 10

	if rc.RateLimit > 0 {
		r.rate = float64(rc.RateLimit)
	}
	if rc.IPFilter {
		// 与 webservice 同口径：只启用 IPFilterMode 指定的那一侧，
		// 避免"两份名单同时生效"这种没人能推理清楚的状态。
		if rc.IPFilterMode == "allow" {
			if m := ipx.NewMatcher(rc.AllowIPs); !m.Empty() {
				r.allow = m
			} else {
				r.warnings = append(r.warnings, "已开启 IP 白名单但名单里没有有效条目，过滤不会生效")
			}
		} else {
			if m := ipx.NewMatcher(rc.DenyIPs); !m.Empty() {
				r.deny = m
			} else {
				r.warnings = append(r.warnings, "已开启 IP 黑名单但名单里没有有效条目，过滤不会生效")
			}
		}
	}

	if rc.KeywordFilter {
		// 折小写放在编译期：每请求只折一次请求体，词表不用反复折。
		for _, kw := range rc.Keywords {
			if kw = strings.TrimSpace(kw); kw != "" {
				r.keywords = append(r.keywords, strings.ToLower(kw))
			}
		}
		r.keywordAll = rc.KeywordMode == "all"
		if len(r.keywords) == 0 {
			// 与 IP 名单同口径：失败开放 + 一条警告。这里若改成"全部拒收"，
			// 一份手改坏的配置就会让某个来源整体静默失联，而界面上只看到"没收到消息"。
			// 保存路径不允许这种配置成立（见 validateReceiver），所以这条只兜手改与旧配置。
			r.warnings = append(r.warnings, "已开启关键词准入但没有有效的关键词，该检查不会生效")
		}
	}

	for _, m := range rc.Mappings {
		if m.Name == "" || m.Path == "" {
			continue
		}
		if !config.ValidMappingName(m.Name) {
			r.warnings = append(r.warnings, fmt.Sprintf("字段映射名 %q 不能用在模板里，已忽略", m.Name))
			continue
		}
		r.mappings = append(r.mappings, mappingRT{name: m.Name, segs: parsePath(m.Path), def: m.Default})
	}

	r.rules = compileRules(rc, tmpls, &r.warnings)
	return r
}

// compileRules 按优先级升序编译启用的规则。
func compileRules(rc config.WebhookReceiver, tmpls map[string]config.MessageTemplate, warns *[]string) []ruleRT {
	// 必须先复制再排序：cfg 里的切片与配置管理器共享底层数组，
	// 就地排序会改动 Manager.lastGood 这份回滚基线（见 module.Module 契约）。
	src := make([]config.WebhookRule, 0, len(rc.Rules))
	for _, ru := range rc.Rules {
		if ru.Enabled {
			src = append(src, ru)
		}
	}
	sort.SliceStable(src, func(i, j int) bool { return src[i].Priority < src[j].Priority })

	out := make([]ruleRT, 0, len(src))
	for _, ru := range src {
		rt := ruleRT{cfg: ru}
		rt.conds = compileCondsWarn(fmt.Sprintf("规则 %q", ru.Name), ru.Match, ru.Conditions, warns)

		// 没有分支就把规则自己的模板与目标当成唯一那个分支（无附加条件 → 规则命中它就命中）。
		bs := ru.Branches
		if len(bs) == 0 {
			bs = []config.RuleBranch{{TemplateRef: ru.TemplateRef, Targets: ru.Targets}}
		}
		for _, b := range bs {
			label := fmt.Sprintf("规则 %q", ru.Name)
			if b.Name != "" {
				label = fmt.Sprintf("规则 %q 的分支 %q", ru.Name, b.Name)
			}
			rt.branches = append(rt.branches, compileBranch(label, b, tmpls, warns))
		}
		out = append(out, rt)
	}
	return out
}

// compileCondsWarn 编译一组条件，并把编译期发现的问题记成 warning。
// 规则本体与每个分支各调一次，label 已经带上"规则 X 的分支 Y"，
// 否则界面上只看到一句"正则无法编译"，根本不知道该去哪一格里改。
func compileCondsWarn(label, match string, cs []config.Condition, warns *[]string) condGroup {
	conds, errs := compileConds(match, cs)
	for _, err := range errs {
		*warns = append(*warns, fmt.Sprintf("%s的正则无法编译（该条件永不命中）：%v", label, err))
	}
	for _, c := range cs {
		if !ValidOperator(c.Op) {
			*warns = append(*warns, fmt.Sprintf("%s使用了未知算子 %q（该条件永不命中）", label, c.Op))
		}
	}
	return conds
}

// compileBranch 编译一个输出分支：附加条件 + 它引用的那个模板。
func compileBranch(label string, b config.RuleBranch, tmpls map[string]config.MessageTemplate, warns *[]string) branchRT {
	rt := branchRT{cfg: b, format: "text"}
	rt.conds = compileCondsWarn(label, b.Match, b.Conditions, warns)

	tpl, ok := tmpls[b.TemplateRef]
	switch {
	case b.TemplateRef == "":
		rt.err = fmt.Errorf("%s没有选择消息模板", label)
	case !ok:
		rt.err = fmt.Errorf("%s引用的模板已不存在", label)
	default:
		rt.format = tpl.Format
		rt.titleStyle = tpl.TitleStyle
		rt.tmplName = tpl.Name
		if t, err := tmplx.Compile("body:"+tpl.ID, tpl.Body); err != nil {
			rt.err = fmt.Errorf("模板 %q 正文语法错误：%w", tpl.Name, err)
		} else {
			rt.body = t
		}
		if rt.err == nil && tpl.Title != "" {
			if t, err := tmplx.Compile("title:"+tpl.ID, tpl.Title); err != nil {
				rt.err = fmt.Errorf("模板 %q 标题语法错误：%w", tpl.Name, err)
			} else {
				rt.title = t
			}
		}
	}
	if rt.err != nil {
		*warns = append(*warns, rt.err.Error())
	}
	return rt
}

// allowIP 判断来源 IP 是否放行，第二个返回值是拒绝原因（放行时为空）。
// ip 为 nil（解析不出对端地址）时放行：那只会在非 TCP 的测试传输上出现，
// 在这里拒绝会让"配了名单的接收器在某些环境下全挂"。
func (r *receiverRT) allowIP(ip net.IP) (bool, string) {
	if ip == nil || (r.allow == nil && r.deny == nil) {
		return true, ""
	}
	if r.deny != nil && r.deny.Match(ip) {
		return false, "命中 IP 黑名单"
	}
	if r.allow != nil && !r.allow.Match(ip) {
		return false, "不在 IP 白名单内"
	}
	return true, ""
}

// allowKeywords 关键词准入：第二个返回值是拒绝原因（放行时为空）。
//
// text 是**惰性**的：它拼出来的是"请求体原文 + 查询串的值"，那是一份完整载荷的拷贝
// （入站上限 4MB），而关键词准入是个可选功能，绝大多数接收器压根没配。
// 传值的话，每条入站请求都要白拷一份完整载荷，只为喂给一个下一行就返回 true 的判断。
// 传函数把这份拷贝推到"确实配了词"之后再做，判空这件事也就只留在这一处，
// 不必在两个调用点各写一遍（写两遍必然会漂）。
//
// 刻意不解析结构，也刻意不区分大小写——用户填的是"要求消息里带上的词"，
// 不是一条取值路径。词表在编译期就转成小写了（见 compileReceiver），
// 这里只需要折叠一次待检文本。
//
// 原因文案里带上词表：这条会进执行历史，用户看的时候要能立刻判断是"第三方改了措辞"
// 还是"自己的词填错了"。历史只在面板里看得到，响应体那边仍然只回一句通用文本
// （见 reject 对 403 的处理），不给探测者任何信号。
func (r *receiverRT) allowKeywords(text func() string) (bool, string) {
	if len(r.keywords) == 0 {
		return true, ""
	}
	hay := strings.ToLower(text())
	hit, miss := 0, ""
	for _, kw := range r.keywords {
		if strings.Contains(hay, kw) {
			hit++
		} else if miss == "" {
			miss = kw
		}
	}
	switch {
	case r.keywordAll && hit == len(r.keywords):
		return true, ""
	case !r.keywordAll && hit > 0:
		return true, ""
	case r.keywordAll:
		return false, "消息内容缺少要求的关键词「" + strutil.Truncate(miss, 32, "…") + "」"
	}
	return false, "消息内容不含任何要求的关键词（需含其一：" + strutil.Truncate(strings.Join(r.keywords, "、"), 96, "…") + "）"
}
