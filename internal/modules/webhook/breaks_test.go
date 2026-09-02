package webhook

import (
	"strings"
	"testing"

	"mantou/internal/config"
)

// autoZipBody 是这条 bug 的原始载荷（来源系统在 Windows 上跑，发的是 \r\n）。
// text 字段里五行内容靠 \r\n 分隔，模板只写 {{.body.text}}，
// 发到钉钉后整段挤成一行——这份样本就是为了盯住那个回归。
const autoZipBody = "{\"source\":\"AutoZip\",\"event\":\"EngineStopped\"," +
	"\"tag\":\"停止\",\"time\":\"10:40:38\",\"title\":\"【停止】\"," +
	"\"body\":\"备份程序已停止，不再监控目录。\\r\\n累计生成归档 0 个，共 0B，0 个文件。\\r\\n程序所在磁盘 D:：总 1.50T，可用 1.01T\"," +
	"\"text\":\"10:40:38\\r\\n【停止】\\r\\n备份程序已停止，不再监控目录。\\r\\n累计生成归档 0 个，共 0B，0 个文件。\\r\\n程序所在磁盘 D:：总 1.50T，可用 1.01T\"," +
	"\"machine\":\"ERP\",\"timestamp\":\"2026-09-02T02:40:38.2638644+00:00\"}"

func TestMarkdownBreaks(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		// 载荷自带的 \r\n：这就是这条 bug 的本体。
		{"CRLF 补空行", "第一行\r\n第二行", "第一行\n\n第二行"},
		{"LF 补空行", "第一行\n第二行", "第一行\n\n第二行"},
		// 老式 Mac 与某些设备只发 \r。不归一的话它在钉钉那侧连软换行都算不上。
		{"单独的 CR 也归一", "第一行\r第二行", "第一行\n\n第二行"},

		// 幂等：界面上「换行」按钮在 markdown 下插的就是 \n\n，
		// 已经调好的模板不能因为这次改动多出空行来。
		{"已有空行原样保留", "第一行\n\n第二行", "第一行\n\n第二行"},
		{"CRLF 写的空行同样保留", "第一行\r\n\r\n第二行", "第一行\n\n第二行"},
		{"跑两遍结果一致", "第一行\n\n第二行\n第三行", "第一行\n\n第二行\n\n第三行"},

		// 空行两侧不再叠加：三个连续换行说明用户想要的就是更大的间隔。
		{"三连换行不叠加", "第一行\n\n\n第二行", "第一行\n\n\n第二行"},
		// 只有空白的行也算空行——它在 markdown 那侧就是段落分隔。
		{"只有空白的行算空行", "第一行\n   \n第二行", "第一行\n   \n第二行"},

		// 没有换行的正文一个字节都不该动。
		{"单行原样返回", "就一行", "就一行"},
		{"空串", "", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := MarkdownBreaks(c.in)
			if got != c.want {
				t.Fatalf("MarkdownBreaks(%q)\n得到 %q\n期望 %q", c.in, got, c.want)
			}
			// 幂等性对每一个用例都成立，而不只是上面那几条：
			// 它是这个函数能与「换行」按钮共存的前提，值得逐例断言。
			if again := MarkdownBreaks(got); again != got {
				t.Fatalf("不幂等：再跑一遍 %q 变成了 %q", got, again)
			}
		})
	}
}

// 多行循环体（loopBlock 插出来的那种）在 markdown 下每条也要真的各占一行。
func TestMarkdownBreaksLoopOutput(t *testing.T) {
	got := MarkdownBreaks("- 馒头: 20\n- 花卷: 5\n- 包子: 3")
	want := "- 馒头: 20\n\n- 花卷: 5\n\n- 包子: 3"
	if got != want {
		t.Fatalf("循环产出的列表每条要各占一行：\n得到 %q\n期望 %q", got, want)
	}
}

// 纯文本格式一个字节都不许动：那边单个 \n 本来就是真换行，
// 补空行会让每条消息凭空多出一倍行距。
func TestProcessTextFormatKeepsRawNewlines(t *testing.T) {
	r := newRT(t, config.WebhookReceiver{
		Rules: []config.WebhookRule{rule("A", 10, "ta")},
	}, tpl("ta", "{{.body.text}}"))

	msg := onlyMessage(t, r.process(newEvent(t, r, autoZipBody)))
	if msg.Err != nil {
		t.Fatalf("渲染不该失败：%v", msg.Err)
	}
	if !strings.Contains(msg.Body, "10:40:38\r\n【停止】") {
		t.Fatalf("纯文本要保持载荷里的原始换行，实际 %q", msg.Body)
	}
	if strings.Contains(msg.Body, "\n\n") {
		t.Fatalf("纯文本不该被补空行，实际 %q", msg.Body)
	}
}

// markdown 格式下，载荷里带进来的换行要变成钉钉/企业微信真正认的换行。
// 这是用户报的那条 bug 的端到端断言。
func TestProcessMarkdownPromotesPayloadNewlines(t *testing.T) {
	md := tpl("ta", "{{.body.text}}")
	md.Format = "markdown"
	md.Title = "{{.body.source}}"
	md.TitleStyle = "h3"
	r := newRT(t, config.WebhookReceiver{Rules: []config.WebhookRule{rule("A", 10, "ta")}}, md)

	msg := onlyMessage(t, r.process(newEvent(t, r, autoZipBody)))
	if msg.Err != nil {
		t.Fatalf("渲染不该失败：%v", msg.Err)
	}
	// \r 必须已经被归一掉：留着它，钉钉那侧连"这里有个换行"都读不出来。
	if strings.Contains(msg.Body, "\r") {
		t.Fatalf("正文里不该再有 \\r：%q", msg.Body)
	}
	want := "### AutoZip\n\n" +
		"10:40:38\n\n" +
		"【停止】\n\n" +
		"备份程序已停止，不再监控目录。\n\n" +
		"累计生成归档 0 个，共 0B，0 个文件。\n\n" +
		"程序所在磁盘 D:：总 1.50T，可用 1.01T"
	if msg.Body != want {
		t.Fatalf("载荷里的换行要补成空行：\n得到 %q\n期望 %q", msg.Body, want)
	}
}

// 模板里手动写的空行（界面上「换行」按钮在 markdown 下插的就是这个）
// 不能被再加一遍——那些模板是用户已经照着预览调好的。
func TestProcessMarkdownKeepsManualBreaks(t *testing.T) {
	// 模板正文用 \n\n 分两段，正是 TemplateDialog.vue 里 br() 的产出。
	md := tpl("ta", "编号 {{.body.消息编号}}\n\n类型 {{.body.消息类型}}")
	md.Format = "markdown"
	r := newRT(t, config.WebhookReceiver{Rules: []config.WebhookRule{rule("A", 10, "ta")}}, md)

	msg := onlyMessage(t, r.process(newEvent(t, r, sampleBody)))
	if msg.Err != nil {
		t.Fatalf("渲染不该失败：%v", msg.Err)
	}
	want := "编号 MSG-2026-0001\n\n类型 每日汇总"
	if msg.Body != want {
		t.Fatalf("手动插的空行要原样保留、不叠加：\n得到 %q\n期望 %q", msg.Body, want)
	}
}

// 标题那一行的空行是 MarkdownTitled 自己加的，正文补换行不能把它变成三个换行。
// 顺序（先补换行、再拼标题）就是为了这一条。
func TestProcessMarkdownTitleSeparatorUnchanged(t *testing.T) {
	md := tpl("ta", "第一行\n第二行")
	md.Format = "markdown"
	md.Title = "标题"
	md.TitleStyle = "bold"
	r := newRT(t, config.WebhookReceiver{Rules: []config.WebhookRule{rule("A", 10, "ta")}}, md)

	msg := onlyMessage(t, r.process(newEvent(t, r, sampleBody)))
	want := "**标题**\n\n第一行\n\n第二行"
	if msg.Body != want {
		t.Fatalf("标题与正文之间仍是一个空行：\n得到 %q\n期望 %q", msg.Body, want)
	}
}

// 预览与真实投递必须一字不差——它们共用 renderBranch，这条测试盯住那个不变量。
// 用户报 bug 时之所以以为"预览是对的"，正是因为预览那一栏用 CSS white-space: pre-wrap
// 显示，它认单个 \n 而钉钉不认；字符串本身两边一直是同一份。
func TestPreviewMatchesDeliveryForPayloadNewlines(t *testing.T) {
	md := tpl("ta", "{{.body.text}}")
	md.Format = "markdown"
	md.Title = "{{.body.source}}"
	md.TitleStyle = "h3"
	r := newRT(t, config.WebhookReceiver{Rules: []config.WebhookRule{rule("A", 10, "ta")}}, md)

	delivered := onlyMessage(t, r.process(newEvent(t, r, autoZipBody)))

	h := newHarness(t, config.Config{})
	pv := h.m.PreviewTemplate("", []byte(autoZipBody),
		map[string]string{"Content-Type": "application/json"}, "",
		TemplateSpec{Format: md.Format, Title: md.Title, Body: md.Body, TitleStyle: md.TitleStyle})
	if pv.Error != "" {
		t.Fatalf("预览不该报错：%s", pv.Error)
	}
	if pv.Body != delivered.Body {
		t.Fatalf("预览与投递的正文必须一字不差：\n预览 %q\n投递 %q", pv.Body, delivered.Body)
	}
}
