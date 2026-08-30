package webhook

import (
	"errors"
	"strings"

	"mantou/internal/tmplx"
)

// 本文件是流水线本体：条件命中 → 渲染 → 决定目标。
//
// 刻意做成**无副作用**的纯函数（不投递、不写日志、不改运行态）：
// 面板上的"试运行"与真实入站请求必须走同一段代码，否则试运行页说"会发给 A 群"、
// 实际发到了 B 群，这个功能就没有存在的价值了。投递与记账由调用方在拿到结果后完成。

// message 一条渲染完成、待投递的消息。
type message struct {
	RuleID   string
	RuleName string
	// Branch 产出这条消息的输出分支名。单输出的规则（没配分支）为空。
	Branch string
	// Template 渲染这条消息的模板名，只用于试运行面板的展示（投递不需要它）。
	Template string
	Title    string
	Body     string
	Format   string
	Targets  []string

	// Missing 模板里取不到值的字段数（tmplx 已把 <no value> 抹掉）。
	Missing int
	// Err 渲染或配置错误。Body 非空时仍会投递——一条不完整的告警胜过没有告警。
	Err error
}

// Label 这条消息的来源标签：配了分支时是「规则名 / 分支名」。
//
// 执行历史与出站请求里都用它，而不是光写规则名：一条规则有两个出口之后，
// 两条消息在历史里会长得一模一样，而"这个目标收到了、那个没收到"的排查
// 恰恰只靠这一点区分。
func (m message) Label() string {
	if m.Branch == "" {
		return m.RuleName
	}
	return m.RuleName + " / " + m.Branch
}

// result 一次处理的完整结果。
type result struct {
	Messages []message
	// MatchedRules 命中的规则数。为 0 时消息被丢弃，这是最常见的"配好了却收不到"故障，
	// 必须能在日志与试运行页里明确看到，而不是表现为"什么都没发生"。
	//
	// 它数的是**规则本体的条件**命中了几条。配了分支的规则可能命中、却没有任何分支
	// 的附加条件成立，于是这个数大于 0 而 Messages 是空的——那种规则记在 NoBranch 里。
	MatchedRules int
	// NoBranch 命中了规则、但没有任何分支的附加条件成立的规则名。
	//
	// 它是多分支专属的一种"配好了却收不到"：规则条件明明对了，用户在界面上却什么都看不到。
	// 把名字留下来，试运行页与执行历史才能直接说"命中了规则 X，但它的分支条件都不成立"，
	// 而不是让人从两层条件里自己猜是哪一层没过。
	NoBranch []string
	// Truncated 有消息因超长被截断。
	Truncated bool
}

// process 跑完整条流水线。
//
// 两层判定：规则本体的条件当粗筛，分支的附加条件当细分（见 config.RuleBranch）。
// 没配分支的规则在编译期已经被折成"一个无附加条件的分支"（compileRules），
// 所以这里只有一条代码路径。
func (r *receiverRT) process(ev *event) result {
	var res result
	for i := range r.rules {
		ru := &r.rules[i]
		if !ru.conds.match(ev.Root) {
			continue
		}
		res.MatchedRules++

		hit, failed := 0, false
		for j := range ru.branches {
			b := &ru.branches[j]
			if !b.conds.match(ev.Root) {
				continue
			}
			hit++

			msg := message{RuleID: ru.cfg.ID, RuleName: ru.cfg.Name, Branch: b.cfg.Name,
				Template: b.tmplName, Format: b.format}
			if b.err != nil {
				// 模板缺失 / 语法错误：如实记一条失败。只废掉这一个分支——同一条规则的
				// 其它分支是用户显式配的另一个出口，不该被邻居的错字连带掐掉；
				// 但整条流水线到此为止（见下面的 failed），理由与从前一样。
				msg.Err = b.err
				res.Messages = append(res.Messages, msg)
				failed = true
			} else {
				var truncated bool
				msg.Title, msg.Body, msg.Missing, truncated, msg.Err = renderBranch(ev, b)
				if truncated {
					res.Truncated = true
				}
				msg.Targets = r.targetsFor(b.cfg.Targets)
				res.Messages = append(res.Messages, msg)
			}

			if ru.cfg.FirstBranchOnly {
				break
			}
		}

		if failed {
			// 模板配错了就不再往后比对规则：继续试下一条会让消息发到一个用户没预期的
			// 模板与群里——那比"这条消息发不出去"更难排查。
			return res
		}
		if hit == 0 {
			// 规则命中了，但没有任何分支的条件成立，也就是这条规则没有出口。
			// 这里**继续**往后比对（不看 Continue）：「首个命中即停」的前提是这一条
			// 真的发出了东西，否则消息会在一条什么都没产出的规则上静默消失。
			res.NoBranch = append(res.NoBranch, ru.cfg.Name)
			continue
		}
		if !ru.cfg.Continue {
			break
		}
	}
	return res
}

// renderBranch 用一个输出分支已编译好的模板渲染出标题与正文。
//
// 单独抽出来是为了让「消息模板 → 预览」（preview.go）走同一段代码：预览里看到的
// 标题拼法、缺字段计数、截断标记必须与真正投递出去的那条消息一字不差，否则用户
// 照着预览调好模板，发出去又是另一个样子——与 process 无副作用同一个理由。
func renderBranch(ev *event, ru *branchRT) (title, body string, missing int, truncated bool, err error) {
	body, missing, rerr := tmplx.Render(ru.body, ev.Root)
	body = strings.TrimSpace(body)
	if errors.Is(rerr, tmplx.ErrTooLarge) {
		truncated = true
	} else if rerr != nil {
		err = rerr
	}
	if ru.title != nil {
		text, tmiss, terr := tmplx.Render(ru.title, ev.Root)
		title = strings.TrimSpace(text)
		missing += tmiss
		if terr != nil && err == nil && !errors.Is(terr, tmplx.ErrTooLarge) {
			err = terr
		}
	}
	// markdown 的标题要真正写进正文（钉钉的 markdown.title 只显示在会话列表里，
	// 企业微信连这个字段都没有）。样式由模板上的选项决定，见 MarkdownTitled。
	if ru.format == "markdown" {
		body = MarkdownTitled(body, title, ru.titleStyle)
	}
	if body == "" && err == nil {
		err = errors.New("模板渲染结果为空，未投递")
	}
	return title, body, missing, truncated, err
}

// MarkdownTitled 把标题按 style 拼到正文前面。
//
// 为什么这件事必须做：钉钉 markdown 消息的 title 只是会话列表里的那行预览，
// 消息气泡里看不到；企业微信的 markdown 根本没有 title 字段。用户在面板上
// 填了标题、发出去却没有，只能得出"标题没用"的结论。
//
// 已经自己在正文里写了标题的用户不能被加第二遍：那些人正是被上面这个坑逼着
// 手动补的。所以正文首行（去掉 #、* 与空白后）与标题相同就原样返回。
//
// 导出是为了「通知目标 → 测试发送」能走同一份拼法（见 api_webhook.go
// handleNotifyTest）：测试发出来的样子必须与真实投递一致，否则用户拿测试
// 调出来的样式，真发的时候又变了。
func MarkdownTitled(body, title, style string) string {
	// 正文为空时什么都不做：那是模板配错了，下面的"渲染结果为空，未投递"要能照旧拦住它，
	// 而不是变成一条只有标题、看不出哪里错了的消息。
	if body == "" || title == "" || style == "none" {
		return body
	}
	if sameTitleLine(body, title) {
		return body
	}
	var head string
	switch style {
	case "h1":
		head = "# " + title
	case "h2":
		head = "## " + title
	case "bold":
		head = "**" + title + "**"
	default:
		head = "### " + title
	}
	// 空行是必须的：钉钉与企业微信都按 markdown 解析，标题行后紧跟正文
	// 会被当成同一段，加粗与标题样式都不生效。
	return head + "\n\n" + body
}

// sameTitleLine 判断正文首行是否就是这个标题（忽略 markdown 标记与空白）。
func sameTitleLine(body, title string) bool {
	line := body
	if i := strings.IndexAny(body, "\r\n"); i >= 0 {
		line = body[:i]
	}
	return titleKey(line) == titleKey(title)
}

func titleKey(s string) string {
	return strings.Trim(strings.TrimSpace(s), "#*_ 　")
}

// targetsFor 规则未指定目标时回落到接收器的默认目标。
func (r *receiverRT) targetsFor(ruleTargets []string) []string {
	src := ruleTargets
	if len(src) == 0 {
		src = r.cfg.DefaultTargets
	}
	return dedupe(src)
}

// dedupe 去重并保持顺序。重复目标会让群里出现两条一样的消息，
// 而"规则目标"与"接收器默认目标"里填了同一个群是很常见的写法。
func dedupe(in []string) []string {
	if len(in) <= 1 {
		return in
	}
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s == "" {
			continue
		}
		if _, dup := seen[s]; dup {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}
