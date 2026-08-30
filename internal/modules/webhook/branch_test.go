package webhook

import (
	"strings"
	"testing"

	"mantou/internal/config"
)

// 输出分支（config.RuleBranch）的判定。测的是这一层存在的理由本身：
// 「同一批消息按细分条件发不同模板给不同的人」以前只能拆成多条规则，
// 于是公共条件要在两处各维护一遍，还要靠 Continue 才能都发出去。

func branch(name, tmplRef string, targets []string, conds ...config.Condition) config.RuleBranch {
	return config.RuleBranch{
		Name: name, Match: "all", Conditions: conds,
		TemplateRef: tmplRef, Targets: targets,
	}
}

// branchRule 一条只靠分支产出的规则：规则级的模板刻意留空，
// 顺便证明配了分支之后 TemplateRef 确实不参与运行。
func branchRule(id string, prio int, conds []config.Condition, bs ...config.RuleBranch) config.WebhookRule {
	ru := rule(id, prio, "", conds...)
	ru.Branches = bs
	return ru
}

func labels(res result) []string {
	out := make([]string, 0, len(res.Messages))
	for _, m := range res.Messages {
		out = append(out, m.Label())
	}
	return out
}

// 用户的原始诉求：全部满足 X → 模板A 发给一组；全部满足 XX → 模板C 发给另一组。
// 公共条件（"这是每日通知"）只写在规则上一遍，两个分支各自再筛一层。
func TestBranchesFanOutToDifferentTemplatesAndTargets(t *testing.T) {
	ru := branchRule("R", 10, []config.Condition{cond("body.消息类型", "contains", "每日")},
		branch("大额", "ta", []string{"g财务"}, cond("body.数值", "gt", "1000")),
		branch("含条目", "tb", []string{"g仓库"}, cond("body.items[*].名称", "countGte", "2")),
	)
	r := newRT(t, config.WebhookReceiver{Rules: []config.WebhookRule{ru}},
		tpl("ta", "财务:{{.body.消息编号}}"), tpl("tb", "仓库:{{.body.消息编号}}"))

	res := r.process(newEvent(t, r, sampleBody))
	if res.MatchedRules != 1 {
		t.Fatalf("规则本体只该命中 1 条：%d", res.MatchedRules)
	}
	// 默认是"命中的分支全都发"：两件事互不相干，不该互相抢。
	if len(res.Messages) != 2 {
		t.Fatalf("两个分支都命中就该发两条：%+v", res.Messages)
	}
	if got := labels(res); got[0] != "规则R / 大额" || got[1] != "规则R / 含条目" {
		t.Fatalf("消息顺序与标签应按分支顺序：%v", got)
	}
	if res.Messages[0].Body != "财务:MSG-2026-0001" || res.Messages[1].Body != "仓库:MSG-2026-0001" {
		t.Fatalf("每个分支该用自己的模板：%+v", res.Messages)
	}
	if res.Messages[0].Targets[0] != "g财务" || res.Messages[1].Targets[0] != "g仓库" {
		t.Fatalf("每个分支该发给自己的目标：%+v", res.Messages)
	}
}

// 分支的条件是在规则命中之后再筛一层：不成立的分支跳过，不影响别的分支。
func TestBranchConditionNarrowsWithinRule(t *testing.T) {
	ru := branchRule("R", 10, nil,
		branch("不成立", "ta", []string{"g1"}, cond("body.数值", "gt", "99999")),
		branch("成立", "tb", []string{"g2"}),
	)
	r := newRT(t, config.WebhookReceiver{Rules: []config.WebhookRule{ru}},
		tpl("ta", "A"), tpl("tb", "B"))

	msg := onlyMessage(t, r.process(newEvent(t, r, sampleBody)))
	if msg.Branch != "成立" || msg.Body != "B" {
		t.Fatalf("只有条件成立的分支该产出消息：%+v", msg)
	}
}

// FirstBranchOnly 是 IF/ELSE 那种写法：把无条件的分支放最后当兜底。
func TestFirstBranchOnlyStopsAtFirstHit(t *testing.T) {
	ru := branchRule("R", 10, nil,
		branch("大额", "ta", []string{"g1"}, cond("body.数值", "gt", "1000")),
		branch("其余", "tb", []string{"g2"}),
	)
	ru.FirstBranchOnly = true
	r := newRT(t, config.WebhookReceiver{Rules: []config.WebhookRule{ru}},
		tpl("ta", "大额"), tpl("tb", "其余"))

	msg := onlyMessage(t, r.process(newEvent(t, r, sampleBody)))
	if msg.Branch != "大额" {
		t.Fatalf("只发第一个命中的分支：%+v", msg)
	}

	// 同一份配置、数值不够时应落到兜底分支。
	res := r.process(newEvent(t, r, `{"消息类型":"每日汇总","数值":10}`))
	msg = onlyMessage(t, res)
	if msg.Branch != "其余" || msg.Body != "其余" {
		t.Fatalf("第一个不命中时该落到兜底分支：%+v", msg)
	}
}

// 规则命中、但所有分支的条件都不成立：这条规则没有出口，必须**继续**往后比对。
// 在这里 break 会让消息静默消失——「首个命中即停」的前提是这一条真的发了东西。
func TestRuleWithNoBranchHitFallsThroughToLaterRules(t *testing.T) {
	first := branchRule("R1", 10, []config.Condition{cond("body.消息类型", "contains", "每日")},
		branch("永不命中", "ta", []string{"g1"}, cond("body.数值", "gt", "99999")),
	)
	r := newRT(t, config.WebhookReceiver{
		Rules:          []config.WebhookRule{first, rule("R2", 20, "tb")},
		DefaultTargets: []string{"g9"},
	}, tpl("ta", "A"), tpl("tb", "B"))

	res := r.process(newEvent(t, r, sampleBody))
	msg := onlyMessage(t, res)
	if msg.RuleID != "R2" {
		t.Fatalf("没有分支命中的规则不该挡住后面的规则：%+v", msg)
	}
	// 规则本体确实命中了，只是没有出口——两件事要分别数得出来，
	// 否则界面上会让用户去改已经对了的那一层条件。
	if res.MatchedRules != 2 {
		t.Fatalf("规则本体的命中数应为 2：%d", res.MatchedRules)
	}
	if len(res.NoBranch) != 1 || res.NoBranch[0] != "规则R1" {
		t.Fatalf("应记下「命中但无分支命中」的规则名：%v", res.NoBranch)
	}
}

// 一个分支的模板配错了，只废掉这一个分支：其它分支是用户显式配的另一个出口。
// 但不再往后比对**规则**——跳过去等于把"模板配错了"变成"消息发到了别的群"。
func TestBrokenBranchKeepsSiblingsAndStopsLaterRules(t *testing.T) {
	first := branchRule("R1", 10, nil,
		branch("坏的", "不存在的模板", []string{"g1"}),
		branch("好的", "tb", []string{"g2"}),
	)
	first.Continue = true
	r := newRT(t, config.WebhookReceiver{
		Rules: []config.WebhookRule{first, rule("R2", 20, "tb")},
	}, tpl("tb", "B"))

	res := r.process(newEvent(t, r, sampleBody))
	if len(res.Messages) != 2 {
		t.Fatalf("坏分支记一条错误、好分支照样发：%+v", res.Messages)
	}
	bad, good := res.Messages[0], res.Messages[1]
	if bad.Err == nil || !strings.Contains(bad.Err.Error(), "模板已不存在") {
		t.Fatalf("坏分支应如实报错：%+v", bad)
	}
	if bad.Body != "" || len(bad.Targets) != 0 {
		t.Fatalf("出错的消息不该带正文或目标：%+v", bad)
	}
	if good.Branch != "好的" || good.Body != "B" {
		t.Fatalf("邻居的错字不该连带掐掉这个分支：%+v", good)
	}
	if res.MatchedRules != 1 {
		t.Fatalf("出错后不再往后比对规则（Continue 也不例外）：%d", res.MatchedRules)
	}
	// 编译期就该留痕，且要点名是哪个分支——只说"模板已不存在"没法让人找到那一格。
	if !hasWarn(r.warnings, `分支 "坏的"引用的模板已不存在`) {
		t.Fatalf("编译告警应点名分支：%v", r.warnings)
	}
}

// 分支没配目标时回落到接收器的默认目标，与规则级同口径。
func TestBranchTargetsFallBackToReceiverDefaults(t *testing.T) {
	ru := branchRule("R", 10, nil, branch("唯一", "ta", nil))
	r := newRT(t, config.WebhookReceiver{
		Rules: []config.WebhookRule{ru}, DefaultTargets: []string{"g默认"},
	}, tpl("ta", "A"))

	msg := onlyMessage(t, r.process(newEvent(t, r, sampleBody)))
	if len(msg.Targets) != 1 || msg.Targets[0] != "g默认" {
		t.Fatalf("应回落到接收器默认目标：%+v", msg.Targets)
	}
}

// 分支各选各的模板，所以格式也各自独立：一条规则可以一个出口发纯文本、
// 另一个出口发 markdown（两个群的展示能力本来就可能不同）。
func TestBranchesCarryTheirOwnTemplateFormat(t *testing.T) {
	ru := branchRule("R", 10, nil,
		branch("纯文本", "ta", []string{"g1"}),
		branch("markdown", "tb", []string{"g2"}),
	)
	md := tpl("tb", "正文")
	md.Format, md.Title, md.TitleStyle = "markdown", "标题", "h2"
	r := newRT(t, config.WebhookReceiver{Rules: []config.WebhookRule{ru}}, tpl("ta", "正文"), md)

	res := r.process(newEvent(t, r, sampleBody))
	if len(res.Messages) != 2 {
		t.Fatalf("两个分支都该产出：%+v", res.Messages)
	}
	if res.Messages[0].Format != "text" || res.Messages[1].Format != "markdown" {
		t.Fatalf("格式应各随自己的模板：%q %q", res.Messages[0].Format, res.Messages[1].Format)
	}
	// markdown 的标题要真正拼进正文（见 MarkdownTitled），这条路径不能因为分支化而丢掉。
	if !strings.HasPrefix(res.Messages[1].Body, "## 标题") {
		t.Fatalf("markdown 分支的标题应拼进正文：%q", res.Messages[1].Body)
	}
}

// 没配分支的规则（所有老配置的形态）走的是同一段代码：编译期被折成一个无条件分支，
// Label 里不该多出一个分隔符，历史与出站看到的仍然只是规则名。
func TestSingleOutputRuleHasNoBranchLabel(t *testing.T) {
	r := newRT(t, config.WebhookReceiver{
		Rules: []config.WebhookRule{rule("R", 10, "ta")}, DefaultTargets: []string{"g1"},
	}, tpl("ta", "A"))

	msg := onlyMessage(t, r.process(newEvent(t, r, sampleBody)))
	if msg.Branch != "" || msg.Label() != "规则R" {
		t.Fatalf("单输出规则的标签就是规则名：%q / %q", msg.Branch, msg.Label())
	}
	if len(r.rules[0].branches) != 1 {
		t.Fatalf("单输出规则应被折成一个分支：%d", len(r.rules[0].branches))
	}
}
