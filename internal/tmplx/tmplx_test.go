package tmplx

import (
	"encoding/json"
	"strings"
	"testing"
)

// samplePayload 是一份带条目数组的载荷：一个对象头 + 一个数组。
// 条目数组是本包必须支持 {{range}} 的全部理由——用户原本要写
// data.items.forEach(...) 才能把它拼成消息。
const samplePayload = `{
  "body": {
    "消息类型": "每日汇总",
    "消息编号": "MSG-20260822-001",
    "客户": "某某贸易有限公司",
    "数值": 1234567.5,
    "备注": "",
    "items": [
      {"名称": "馒头-大", "数量": 120, "单位": "个"},
      {"名称": "馒头-小", "数量": 80,  "单位": "个"}
    ]
  }
}`

// mustData 走 DecodeJSON，与真实入站路径完全一致——数字必须是 json.Number，
// 否则测试验的就不是生产行为。
func mustData(t *testing.T, raw string) any {
	t.Helper()
	v, err := DecodeJSON([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func render(t *testing.T, tmpl string, data any) string {
	t.Helper()
	out, _, err := RenderText("t", tmpl, data)
	if err != nil {
		t.Fatalf("渲染 %q 失败: %v", tmpl, err)
	}
	return out
}

// 这是替代 n8n 里那段 items.forEach 的完整用例：一次渲染同时做
// 分支（有没有条目）、循环（每条一行）与聚合（数量求和）。
// 它跑通就意味着"不写代码也能拼出原来的消息"这件事成立。
func TestAggregatesItemLinesWithoutCode(t *testing.T) {
	data := mustData(t, samplePayload)
	const tmpl = `【{{.body.消息类型}}】{{.body.消息编号}}
客户：{{.body.客户}}
数值：{{fixed 2 .body.数值}}
备注：{{default "无" .body.备注}}
{{if .body.items}}条目（{{count .body.items}} 项）：
{{range .body.items}}- {{.名称}} × {{.数量}}{{.单位}}
{{end}}{{else}}（无条目）
{{end}}`
	got := render(t, tmpl, data)

	for _, want := range []string{
		"【每日汇总】MSG-20260822-001",
		"数值：1234567.50", // 不是 1.2345675e+06
		"备注：无",          // 空字符串走 default
		"条目（2 项）：",
		"- 馒头-大 × 120个",
		"- 馒头-小 × 80个",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("渲染结果缺少 %q：\n%s", want, got)
		}
	}
	if strings.Contains(got, "无条目") {
		t.Fatalf("有条目却走了 else 分支：\n%s", got)
	}
}

// 同一个模板遇到没带 items 的载荷（另一个系统推来的、结构不同的消息）
// 必须走 else 分支而不是报错——"消息来源不止一个系统"是本模块的前提。
func TestSameTemplateHandlesPayloadWithoutItems(t *testing.T) {
	data := mustData(t, `{"body":{"消息类型":"状态提醒","消息编号":"MSG-002"}}`)
	const tmpl = `{{.body.消息类型}}{{if .body.items}}有条目{{else}}（无条目）{{end}}`
	got := render(t, tmpl, data)
	if got != "状态提醒（无条目）" {
		t.Fatalf("缺少条目字段时结果不对: %q", got)
	}
}

// 核心健壮性断言，也是本包选 missingkey=default 的原因：
// 任意深度的缺失路径都不得中断渲染，否则一个可选的嵌套字段就能让整条告警发不出去。
// 缺失处渲染为空串（而不是 <no value>），同时以 missing 计数回报给调用方。
func TestMissingPathsNeverFailAndAreCounted(t *testing.T) {
	data := mustData(t, `{"body":{"a":"1"}}`)
	for _, tmpl := range []string{
		`[{{.body.缺失}}]`,
		`[{{.没有.这一层.更深}}]`,
		`[{{.body.a}}|{{.body.缺失}}|{{.没有.更深}}]`,
	} {
		out, missing, err := RenderText("t", tmpl, data)
		if err != nil {
			t.Fatalf("%q 不应报错: %v", tmpl, err)
		}
		if strings.Contains(out, "<no value>") {
			t.Fatalf("%q 的输出残留了 <no value>: %q", tmpl, out)
		}
		if missing == 0 {
			t.Fatalf("%q 应回报缺失字段数，实际为 0（输出 %q）", tmpl, out)
		}
	}

	// 存在的字段一个都不该被计入缺失。
	out, missing, err := RenderText("t", `{{.body.a}}`, data)
	if err != nil || out != "1" || missing != 0 {
		t.Fatalf("正常取值被误判: out=%q missing=%d err=%v", out, missing, err)
	}
}

// 上限必须挡住"外部推来一万条数据"：输出被截断、带标记、返回 ErrTooLarge，
// 但文本仍然可用——宁可发一条截断的告警，也不要什么都不发。
func TestRenderTruncatesRunawayOutput(t *testing.T) {
	items := make([]any, 5000)
	for i := range items {
		items[i] = map[string]any{"名称": strings.Repeat("馒", 20)}
	}
	out, _, err := RenderText("t", `{{range .items}}- {{.名称}}
{{end}}`, map[string]any{"items": items})
	if err == nil {
		t.Fatalf("超长输出应返回 ErrTooLarge")
	}
	if err != ErrTooLarge {
		t.Fatalf("错误类型不对: %v", err)
	}
	if len(out) > MaxRenderBytes+64 {
		t.Fatalf("截断后仍超出上限: %d 字节", len(out))
	}
	if !strings.Contains(out, "已截断") {
		t.Fatalf("截断后应带标记: %q", out[max(0, len(out)-80):])
	}
	if !strings.Contains(out, "馒") {
		t.Fatalf("截断后应保留已渲染的内容")
	}
}

// 汉字字段名必须能直接写进 {{.消息类型}}：这是"面板上照着字段树点一下就能用"的前提。
// text/template 的标识符规则用的是 unicode.IsLetter，因此汉字合法——
// 但这是本模块的依赖假设，值得有一个测试盯住它。
func TestCJKFieldNamesParse(t *testing.T) {
	data := map[string]any{"消息类型": "每日汇总", "消息编号2": "X-1", "_内部": "y"}
	got := render(t, `{{.消息类型}}/{{.消息编号2}}/{{._内部}}`, data)
	if got != "每日汇总/X-1/y" {
		t.Fatalf("汉字字段名解析结果不对: %q", got)
	}
}

// 数字格式化：encoding/json 默认把数字解成 float64，裸字段输出就会变成
// 1.2345675e+06；消息数值与编号恰恰全是数字，所以 DecodeJSON 必须用 UseNumber。
// 顺带盯住大整数精度：float64 只有 53 位有效整数位，19 位的长编号会被改写成另一个数。
func TestNumbersNeverRenderInScientificNotation(t *testing.T) {
	data := mustData(t, `{"数值":1234567.5,"数量":120,"编号":20260822001,"雪花ID":7234567890123456789}`)
	got := render(t, `{{.数值}}|{{.数量}}|{{.编号}}|{{fixed 2 .数值}}|{{.雪花ID}}`, data)
	if strings.Contains(got, "e+") {
		t.Fatalf("出现科学计数法: %q", got)
	}
	if got != "1234567.5|120|20260822001|1234567.50|7234567890123456789" {
		t.Fatalf("数字渲染结果不对: %q", got)
	}

	// 手工构造的数据（试运行、测试发送）经 Normalize 后必须与上面完全一致，
	// 否则同一个模板在面板里预览和真实收到消息时会输出两种格式。
	same := render(t, `{{.数值}}|{{.数量}}`, Normalize(map[string]any{"数值": 1234567.5, "数量": 120}))
	if same != "1234567.5|120" {
		t.Fatalf("Normalize 后与解码路径不一致: %q", same)
	}
}

// 自定义 HTTP 目标要把渲染好的消息塞进 JSON 请求体，而消息里必然有换行与引号。
// toJSON 负责加引号并转义；少了它，请求体一定是坏 JSON。
func TestToJSONEscapesForRequestBody(t *testing.T) {
	msg := "第一行\n第二行 \"引号\" 与 \\ 反斜杠"
	out := render(t, `{"text":{"content":{{toJSON .message}}}}`, map[string]any{"message": msg})
	var body struct {
		Text struct{ Content string } `json:"text"`
	}
	if err := json.Unmarshal([]byte(out), &body); err != nil {
		t.Fatalf("渲染结果不是合法 JSON: %v\n%s", err, out)
	}
	if body.Text.Content != msg {
		t.Fatalf("转义后内容不一致: %q", body.Text.Content)
	}
}

// 时间字段的形态不受本程序控制：Unix 秒、Unix 毫秒、RFC3339、无时区本地串都要认，
// 认不出的原样返回（比返回 1970 年有用）。
func TestFormatTimeAcceptsCommonShapes(t *testing.T) {
	const layout = "2006-01-02 15:04:05"
	cases := map[string]string{
		"1755820800":          "2025-08-22 08:00:00", // Unix 秒
		"1755820800000":       "2025-08-22 08:00:00", // Unix 毫秒
		"不是时间":                "不是时间",                // 原样返回
		"":                    "",
		"2026-08-22":          "2026-08-22 00:00:00",
		"2026-08-22 09:30:00": "2026-08-22 09:30:00",
	}
	for in, want := range cases {
		var v any = in
		if n, err := json.Number(in).Float64(); err == nil && in != "" {
			v = n
		}
		got := tplFormatTime(layout, v)
		if in == "1755820800" || in == "1755820800000" {
			// Unix 时间戳的期望值依赖本机时区，只断言"解析成了同一个时刻"。
			if tplFormatTime(layout, 1755820800.0) != tplFormatTime(layout, 1755820800000.0) {
				t.Fatalf("秒与毫秒未解析成同一时刻")
			}
			continue
		}
		if got != want {
			t.Fatalf("formatTime(%q) = %q，期望 %q", in, got, want)
		}
	}
}

// 安全红线的回归测试：模板里绝不能存在读环境变量 / 读文件 / 发请求的函数。
// 模板正文是面板上可编辑的内容，一个 env 就等于把 MANTOU_MASTER_KEY 交出去。
func TestNoDangerousFuncsExposed(t *testing.T) {
	for _, name := range []string{
		"env", "expandenv", "getHostByName", "readFile", "include", "exec", "os",
		"lookPath", "getenv", "shell", "http", "dial",
	} {
		if _, ok := funcMap[name]; ok {
			t.Fatalf("函数表中出现了危险函数 %q", name)
		}
	}
	// 即便有人在模板里写了它，也必须在解析期就失败，而不是静默渲染成空。
	if _, err := Compile("t", `{{env "MANTOU_MASTER_KEY"}}`); err == nil {
		t.Fatalf("未定义的函数应在解析期报错")
	}
}

// count 存在的意义：内置 len 对 nil 与非集合会直接让整次渲染失败，
// 而"这次没带这个数组"是完全正常的输入。
func TestCountToleratesMissingCollections(t *testing.T) {
	data := mustData(t, `{"a":[1,2,3],"b":"文字","c":{"x":1}}`)
	got := render(t, `{{count .a}}|{{count .b}}|{{count .c}}|{{count .缺失}}`, data)
	if got != "3|2|1|0" {
		t.Fatalf("count 结果不对: %q", got)
	}
}

// list 存在的意义：只有一条时，很多来源不发数组、直接发那个对象。
// 裸 {{range}} 遇到对象会去遍历它的值，{{.creator}} 直接报错、消息发不出去；
// 而模板作者无法预知对方这次发的是哪种。一份模板要同时吃下这两种形态。
func TestListMakesOneAndManyTheSame(t *testing.T) {
	const tmpl = `{{if .body.items}}{{range list .body.items}}由 {{.creator}} 创建：{{.code}}／超时 {{.keyField}} 天
{{end}}以上请及时跟进！{{else}}由 {{.body.creator}} 创建：{{.body.code}}／超时 {{.body.keyField}} 天，请及时跟进！{{end}}`

	cases := []struct{ name, raw, want string }{
		{
			"一批数据",
			`{"body":{"items":[{"creator":"张三","keyField":"33","code":"A26071442"},{"creator":"李四","keyField":"32","code":"A26071444，A26071447"}]}}`,
			"由 张三 创建：A26071442／超时 33 天\n由 李四 创建：A26071444，A26071447／超时 32 天\n以上请及时跟进！",
		},
		{
			// 同一个来源只有一条时发的是对象而不是数组，输出必须和一批时一致。
			"一条也不发数组",
			`{"body":{"items":{"creator":"张三","keyField":"33","code":"A26071442"}}}`,
			"由 张三 创建：A26071442／超时 33 天\n以上请及时跟进！",
		},
		{
			// 旧结构：根上直接是那条消息，没有 items。
			"没有 items 走单条",
			`{"body":{"creator":"李四","keyField":10,"code":"A26051351"}}`,
			"由 李四 创建：A26051351／超时 10 天，请及时跟进！",
		},
		{
			"空数组走单条",
			`{"body":{"items":[],"creator":"李四","keyField":10,"code":"A26051351"}}`,
			"由 李四 创建：A26051351／超时 10 天，请及时跟进！",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := render(t, tmpl, mustData(t, c.raw)); got != c.want {
				t.Fatalf("渲染结果不符：\n实际 %q\n期望 %q", got, c.want)
			}
		})
	}
}

func TestStringAndCollectionHelpers(t *testing.T) {
	data := mustData(t, `{"名单":["张三","李四"],"标题":"  测试消息  ","已确认":true}`)
	cases := map[string]string{
		`{{join "、" .名单}}`:                 "张三、李四",
		`{{trim .标题}}`:                     "测试消息",
		`{{first .名单}}`:                    "张三",
		`{{last .名单}}`:                     "李四",
		`{{if contains "测试" .标题}}是{{end}}`: "是",
		`{{upper "abc"}}{{lower "DEF"}}`:   "ABCdef",
		`{{replace "测试" "正式" .标题}}`:        "  正式消息  ",
		`{{truncate 6 "很长很长很长的文本"}}`:       "很长…",
		`{{coalesce .缺失 "" .标题}}`:          "  测试消息  ",
		`{{add 1 2}}|{{sub 5 2}}`:          "3|3",
		`{{str .已确认}}`:                     "true",
	}
	for tmpl, want := range cases {
		if got := render(t, tmpl, data); got != want {
			t.Fatalf("%s = %q，期望 %q", tmpl, got, want)
		}
	}
}

// 模板语法写错时必须在保存/编译期就报错，让面板能当场提示，
// 而不是等第一条真实消息进来才发现发不出去。
func TestCompileRejectsBrokenSyntax(t *testing.T) {
	for _, tmpl := range []string{`{{if .a}}少了 end`, `{{range}}`, `{{.a b c}}`, `{{`} {
		if _, err := Compile("t", tmpl); err == nil {
			t.Fatalf("%q 应在编译期报错", tmpl)
		}
	}
}
