package webhook

import (
	"encoding/json"
	"testing"

	"mantou/internal/config"
	"mantou/internal/tmplx"
)

// sampleRoot 模拟一个真实推来的载荷：数字型 ID、数值、条目数组、空字段都在里面。
// 走 tmplx.DecodeJSON（UseNumber）而不是 encoding/json 默认的 float64，
// 否则 19 位消息号会在测试里就被改写成科学计数法，测的就不是线上那份数据了。
func sampleRoot(t *testing.T) map[string]any {
	t.Helper()
	const raw = `{
	  "body": {
	    "消息编号": "MSG-2026-0001",
	    "消息类型": "每日汇总",
	    "数值": 1580.5,
	    "数量": 0,
	    "备注": "  ",
	    "内部编号": 1234567890123456789,
	    "审核": true,
	    "items": [
	      {"名称": "馒头", "数量": 20},
	      {"名称": "花卷", "数量": 5}
	    ],
	    "空列表": []
	  },
	  "headers": {"x-source": "sys-a"},
	  "query": {"env": "prod"}
	}`
	v, err := tmplx.DecodeJSON([]byte(raw))
	if err != nil {
		t.Fatalf("样本载荷解析失败: %v", err)
	}
	out, ok := v.(map[string]any)
	if !ok {
		t.Fatalf("样本载荷不是对象：%T", v)
	}
	return out
}

func cond(path, op, value string) config.Condition {
	return config.Condition{Path: path, Op: op, Value: value}
}

func evalOne(t *testing.T, root any, c config.Condition) bool {
	t.Helper()
	g, errs := compileConds("all", []config.Condition{c})
	if len(errs) > 0 && c.Op != "regex" {
		t.Fatalf("条件编译出错: %v", errs)
	}
	return g.match(root)
}

// ---------- 路径解析 ----------

func TestParsePath(t *testing.T) {
	cases := []struct {
		in   string
		want []segment
	}{
		{"", nil},
		{"body", []segment{{name: "body", idx: -1}}},
		{"body.消息编号", []segment{{name: "body", idx: -1}, {name: "消息编号", idx: -1}}},
		{"body.items[0]", []segment{{name: "body", idx: -1}, {name: "items", idx: 0}}},
		{"body.items[*].名称", []segment{{name: "body", idx: -1}, {name: "items", idx: -1, star: true}, {name: "名称", idx: -1}}},
		// 方括号里既不是 * 也不是下标：整段当普通字段名，
		// 载荷里真有 "a[b]" 这种字段名时不该被当成路径语法。
		{"body.a[b]", []segment{{name: "body", idx: -1}, {name: "a[b]", idx: -1}}},
		{"body.items[-1]", []segment{{name: "body", idx: -1}, {name: "items[-1]", idx: -1}}},
	}
	for _, tc := range cases {
		got := parsePath(tc.in)
		if len(got) != len(tc.want) {
			t.Fatalf("parsePath(%q) 段数 %d，期望 %d：%+v", tc.in, len(got), len(tc.want), got)
		}
		for i := range got {
			if got[i] != tc.want[i] {
				t.Fatalf("parsePath(%q)[%d] = %+v，期望 %+v", tc.in, i, got[i], tc.want[i])
			}
		}
	}
}

// collectPath 把 lookupVisit 访问到的值收成切片。
//
// 只在测试里这么收：取值本身刻意不落地一个平铺切片（见 lookupVisit 的说明），
// 而"取到了哪些值、什么顺序"仍然要能一眼看清。
func collectPath(root any, segs []segment) []any {
	var out []any
	lookupVisit(root, segs, func(v any) bool {
		out = append(out, v)
		return true
	})
	return out
}

func TestLookupVisit(t *testing.T) {
	root := sampleRoot(t)

	if got := collectPath(root, parsePath("body.消息编号")); len(got) != 1 || got[0] != "MSG-2026-0001" {
		t.Fatalf("普通字段取值不符：%v", got)
	}
	if got := collectPath(root, parsePath("body.items[1].名称")); len(got) != 1 || got[0] != "花卷" {
		t.Fatalf("按下标取值不符：%v", got)
	}
	// [*] 必须命中每个元素，写死下标就变成只看第一条。
	got := collectPath(root, parsePath("body.items[*].名称"))
	if len(got) != 2 || got[0] != "馒头" || got[1] != "花卷" {
		t.Fatalf("[*] 应展开全部元素：%v", got)
	}

	for _, miss := range []string{"body.不存在", "body.items[9].名称", "body.消息编号.再往下", "", "body.空列表[*]"} {
		if v := collectPath(root, parsePath(miss)); v != nil {
			t.Fatalf("路径 %q 应取不到值，实际 %v", miss, v)
		}
	}
}

func TestLookupOneTakesFirst(t *testing.T) {
	root := sampleRoot(t)
	// 字段映射与必填校验不需要多值语义，命中多个时取第一个。
	v, ok := lookupOne(root, parsePath("body.items[*].名称"))
	if !ok || v != "馒头" {
		t.Fatalf("lookupOne 应取第一个命中值，实际 %v ok=%v", v, ok)
	}
	if _, ok := lookupOne(root, parsePath("body.不存在")); ok {
		t.Fatal("取不到值时应返回 false")
	}
}

// ---------- 算子 ----------

func TestOperatorsCoverage(t *testing.T) {
	// 清单与 compare 的实现必须一一对应：漏一个就是"界面能选、运行时永不命中"。
	for _, op := range Operators {
		if !ValidOperator(op) {
			t.Fatalf("%q 在清单里却校验不通过", op)
		}
	}
	if ValidOperator("between") {
		t.Fatal("未实现的算子不应通过校验")
	}
	if len(Operators) != 19 {
		t.Fatalf("算子数量变了（%d），新增算子请同步补测试", len(Operators))
	}
}

// 数量算子：比"这条路径取到了几个值"，而不是比值本身。
// 用户的原话是"创建人大于 1"——他要的是个数，而普通 gt 会去比第一个人的名字。
func TestCountOperators(t *testing.T) {
	root := sampleRoot(t)
	cases := []struct {
		name string
		c    config.Condition
		want bool
	}{
		// [*] 展开成 N 个值
		{"countEq命中", cond("body.items[*].名称", "countEq", "2"), true},
		{"countEq不命中", cond("body.items[*].名称", "countEq", "3"), false},
		{"countGt命中", cond("body.items[*].名称", "countGt", "1"), true},
		{"countGt等值不命中", cond("body.items[*].名称", "countGt", "2"), false},
		{"countGte等值命中", cond("body.items[*].名称", "countGte", "2"), true},
		{"countLt命中", cond("body.items[*].名称", "countLt", "3"), true},
		{"countLte等值命中", cond("body.items[*].名称", "countLte", "2"), true},
		// 直接写字段名、值本身是数组：用户想问"多于一个吗"时不会想到补 [*]
		{"数组字段按长度算", cond("body.items", "countEq", "2"), true},
		{"数组字段大于1", cond("body.items", "countGt", "1"), true},
		{"空数组算0", cond("body.空列表", "countEq", "0"), true},
		// 单值字段是 1 个，不是"有/无"
		{"单值字段算1", cond("body.消息编号", "countEq", "1"), true},
		{"单值字段不大于1", cond("body.消息编号", "countGt", "1"), false},
		// 取不到值就是 0：这样"数量小于 1"能用来表达"这个字段没来"
		{"缺失字段算0", cond("body.没有这个字段", "countEq", "0"), true},
		{"缺失字段小于1", cond("body.没有这个字段", "countLt", "1"), true},
		// 比较值不是数字时不命中，而不是拿 0 去比——后者会让"数量大于 abc"莫名成立
		{"比较值非数字不命中", cond("body.items[*].名称", "countGt", "abc"), false},
		{"比较值留空不命中", cond("body.items[*].名称", "countGt", ""), false},
		{"取反", config.Condition{Path: "body.items", Op: "countEq", Value: "2", Not: true}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := evalOne(t, root, tc.c); got != tc.want {
				t.Fatalf("期望 %v，实际 %v", tc.want, got)
			}
		})
	}
}

func TestConditionOperators(t *testing.T) {
	root := sampleRoot(t)
	cases := []struct {
		name string
		c    config.Condition
		want bool
	}{
		{"eq命中", cond("body.消息类型", "eq", "每日汇总"), true},
		{"eq不命中", cond("body.消息类型", "eq", "状态提醒"), false},
		{"ne命中", cond("body.消息类型", "ne", "状态提醒"), true},
		{"contains命中", cond("body.消息类型", "contains", "汇总"), true},
		{"notContains命中", cond("body.消息类型", "notContains", "提醒"), true},
		{"prefix命中", cond("body.消息编号", "prefix", "MSG-"), true},
		{"suffix命中", cond("body.消息编号", "suffix", "0001"), true},
		{"in命中", cond("body.消息类型", "in", "状态提醒,每日汇总"), true},
		{"in中文逗号", cond("body.消息类型", "in", "状态提醒，每日汇总"), true},
		{"in换行分隔", cond("body.消息类型", "in", "状态提醒\n 每日汇总 \n"), true},
		{"in不命中", cond("body.消息类型", "in", "甲类,乙类"), false},
		{"regex命中", cond("body.消息编号", "regex", `^MSG-\d{4}-\d+$`), true},
		{"regex不命中", cond("body.消息编号", "regex", `^XX-`), false},
		{"exists命中", cond("body.消息编号", "exists", ""), true},
		{"exists不命中", cond("body.没有这个字段", "exists", ""), false},
		{"empty对空白字符串成立", cond("body.备注", "empty", ""), true},
		{"empty对缺失字段成立", cond("body.没有这个字段", "empty", ""), true},
		{"empty对空数组成立", cond("body.空列表", "empty", ""), true},
		{"empty对有值字段不成立", cond("body.消息编号", "empty", ""), false},
		// 数字 0 刻意不算空：否则"数量 为空"对 0 成立，规则为什么命中完全无法理解。
		{"empty对数字0不成立", cond("body.数量", "empty", ""), false},
		{"gt数字比较", cond("body.数值", "gt", "1000"), true},
		{"gt数字不命中", cond("body.数值", "gt", "2000"), false},
		{"gte等值命中", cond("body.数值", "gte", "1580.5"), true},
		{"lt数字比较", cond("body.数值", "lt", "2000"), true},
		{"lte等值命中", cond("body.数值", "lte", "1580.5"), true},
		// 两边有一个不是数字就退回字符串比，日期字符串因此也能比大小。
		{"gt字符串回退", cond("body.消息编号", "gt", "MSG-2026-0000"), true},
		{"gt字符串回退不命中", cond("body.消息编号", "gt", "MSG-2027"), false},
		// 松类型比较：对方发数字还是字符串，配规则的人不该需要先搞清楚。
		{"数字字段按字符串eq", cond("body.数值", "eq", "1580.5"), true},
		{"布尔按字符串eq", cond("body.审核", "eq", "true"), true},
		{"取反", config.Condition{Path: "body.消息类型", Op: "eq", Value: "每日汇总", Not: true}, false},
		{"取反缺失字段的exists", config.Condition{Path: "body.没有这个字段", Op: "exists", Not: true}, true},
		{"未知算子不命中", cond("body.消息类型", "weird", "每日汇总"), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := evalOne(t, root, tc.c); got != tc.want {
				t.Fatalf("期望 %v，实际 %v", tc.want, got)
			}
		})
	}
}

// 19 位消息号必须原样比对：走 float64 会被改写成 1.2345678901234568e+18，
// eq 就永远不命中——这类"规则明明配对了却不生效"最难查。
func TestBigIntegerCompare(t *testing.T) {
	root := sampleRoot(t)
	if !evalOne(t, root, cond("body.内部编号", "eq", "1234567890123456789")) {
		t.Fatal("19 位整数应能原样比对")
	}
}

// [*] 的语义是"任一元素满足"，而不是"第一个元素满足"。
func TestStarPathAnyElement(t *testing.T) {
	root := sampleRoot(t)
	if !evalOne(t, root, cond("body.items[*].名称", "eq", "花卷")) {
		t.Fatal("第二个元素满足也应算命中")
	}
	if evalOne(t, root, cond("body.items[*].名称", "eq", "面包")) {
		t.Fatal("没有元素满足时不该命中")
	}
	if !evalOne(t, root, cond("body.items[*].数量", "gt", "10")) {
		t.Fatal("任一元素数量大于 10 即应命中")
	}
	// notContains 配 [*] 是"存在某个元素不含该字串"，不是"全部都不含"——
	// 这层语义在界面上有提示，测试把它钉住，避免以后被"顺手改成全部"。
	if !evalOne(t, root, cond("body.items[*].名称", "notContains", "馒头")) {
		t.Fatal("存在一个不含该字串的元素即命中")
	}
}

// ---------- 组合与容错 ----------

func TestMatchAllVsAny(t *testing.T) {
	root := sampleRoot(t)
	list := []config.Condition{
		cond("body.消息类型", "eq", "每日汇总"),
		cond("body.数值", "gt", "9999"),
	}

	all, _ := compileConds("all", list)
	if all.match(root) {
		t.Fatal("all：有一条不满足就不该命中")
	}
	any, _ := compileConds("any", list)
	if !any.match(root) {
		t.Fatal("any：有一条满足就该命中")
	}

	// 条件为空表示无条件命中，用来做兜底规则——消息来源不止一家时
	// 靠它避免消息被静默丢弃。
	empty, _ := compileConds("all", nil)
	if !empty.match(root) {
		t.Fatal("空条件应无条件命中")
	}
	emptyAny, _ := compileConds("any", nil)
	if !emptyAny.match(root) {
		t.Fatal("空条件在 any 下也应命中")
	}
}

// 编译不了的正则必须表现为"这条条件永不命中"，而不是"这条条件不存在"：
// 后者会让规则意外命中，把消息发到错误的群里。
func TestBadRegexNeverMatches(t *testing.T) {
	root := sampleRoot(t)
	g, errs := compileConds("all", []config.Condition{cond("body.消息编号", "regex", "([")})
	if len(errs) != 1 {
		t.Fatalf("应报出 1 个正则编译错误，实际 %d", len(errs))
	}
	if g.match(root) {
		t.Fatal("坏正则不能命中")
	}
	// 取反也不能把它变成命中：否则一个写错的正则会让兜底规则全量放行。
	//
	// 这里的分寸是：Not 取反的是"求值结果"，而一条编译不了的正则**没有**求值结果。
	// 把它当成 false 再取反，就得到一条恒真条件——面板上写着"该条件永不命中"，
	// 实际却对任何载荷都命中，方向正好相反。
	gNot, _ := compileConds("all", []config.Condition{
		{Path: "body.消息编号", Op: "regex", Value: "([", Not: true},
	})
	if gNot.match(root) {
		t.Fatal("坏正则勾了取反后仍不能命中：否则一个写错的正则会让规则全量放行")
	}
	if err := CheckRegex("(["); err == nil {
		t.Fatal("CheckRegex 应在保存时就拦下坏正则")
	}
	if err := CheckRegex(`^MSG-\d+$`); err != nil {
		t.Fatalf("正常正则不应报错: %v", err)
	}
}

// 认不出的算子与编译不了的正则同一个口径：不命中，且不受取反影响（2.8-D）。
//
// 保存时已经拦下未知算子（api_webhook.checkConditions），所以这条路只有
// 手改 config.json 或整份导入才能走到——但那两条恰恰是没人盯着的路。
func TestUnknownOperatorNeverMatches(t *testing.T) {
	root := sampleRoot(t)

	g, errs := compileConds("all", []config.Condition{cond("body.消息类型", "between", "每日汇总")})
	if g.match(root) {
		t.Fatal("未知算子不能命中")
	}
	// 未知算子不能混进正则错误里：调用方（compileCondsWarn）把 errs 里的每一项都
	// 措辞成"的正则无法编译"，混进去就会给出一句对不上的提示。
	if len(errs) != 0 {
		t.Fatalf("未知算子不该记成正则编译错误，实际 %d 条：%v", len(errs), errs)
	}

	gNot, _ := compileConds("all", []config.Condition{
		{Path: "body.消息类型", Op: "between", Value: "每日汇总", Not: true},
	})
	if gNot.match(root) {
		t.Fatal("未知算子勾了取反后仍不能命中")
	}

	// any 组里也不能靠一条无法求值的条件把整组抬成命中。
	gAny, _ := compileConds("any", []config.Condition{
		{Path: "body.消息类型", Op: "between", Value: "每日汇总", Not: true},
		cond("body.消息类型", "eq", "对不上的值"),
	})
	if gAny.match(root) {
		t.Fatal("any 组里一条无法求值的条件不能让整组命中")
	}

	// 前提保证：Not 本身必须还是好的。少了这条，"eval 一律返回 false"这种改法
	// 也能让上面几条断言全绿，而那会让所有取反条件失效。
	gLive, _ := compileConds("all", []config.Condition{
		{Path: "body.消息类型", Op: "eq", Value: "对不上的值", Not: true},
	})
	if !gLive.match(root) {
		t.Fatal("算子正常时，取反必须照旧生效")
	}
}

func TestSplitList(t *testing.T) {
	got := splitList(" a , b，c \n d \r\n , ,")
	want := []string{"a", "b", "c", "d"}
	if len(got) != len(want) {
		t.Fatalf("拆分结果不符：%v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("拆分结果不符：%v", got)
		}
	}
	if len(splitList("  ")) != 0 {
		t.Fatal("全空白应拆出空列表")
	}
}

func TestIsBlank(t *testing.T) {
	cases := []struct {
		v    any
		want bool
	}{
		{nil, true},
		{"", true},
		{"  \t", true},
		{"x", false},
		{[]any{}, true},
		{[]any{1}, false},
		{map[string]any{}, true},
		{map[string]any{"a": 1}, false},
		{false, false},
		{json.Number("0"), false},
	}
	for _, tc := range cases {
		if got := isBlank(tc.v); got != tc.want {
			t.Errorf("isBlank(%#v) = %v，期望 %v", tc.v, got, tc.want)
		}
	}
}

// 条件求值发生在每个入站请求上，取不到值的路径必须安全地"不命中"而不是 panic：
// 多来源共用一个接收器时，某一家不带某个字段是常态。
func TestConditionsOnAlienPayloadDoNotPanic(t *testing.T) {
	alien := map[string]any{"body": []any{1, 2, 3}, "headers": nil}
	for _, op := range Operators {
		c := cond("body.items[*].名称", op, "x")
		_ = evalOne(t, alien, c)
		_ = evalOne(t, nil, c)
		_ = evalOne(t, "不是对象", c)
	}
}
