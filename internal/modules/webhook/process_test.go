package webhook

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"mantou/internal/config"
)

// sampleBody 一份带条目的消息载荷：备注里刻意含"测试"二字，
// 用来测那条最真实的目标改写——"渲染出来的文本里有关键字就改发到另一个群"。
const sampleBody = `{
  "消息编号": "MSG-2026-0001",
  "消息类型": "每日汇总",
  "数值": 1580.5,
  "备注": "这是测试消息",
  "items": [{"名称": "馒头", "数量": 20}, {"名称": "花卷", "数量": 5}]
}`

func tpl(id, body string) config.MessageTemplate {
	return config.MessageTemplate{ID: id, Name: "模板" + id, Format: "text", Body: body}
}

func rule(id string, prio int, tmplRef string, conds ...config.Condition) config.WebhookRule {
	return config.WebhookRule{
		ID: id, Name: "规则" + id, Enabled: true, Priority: prio,
		Match: "all", Conditions: conds, TemplateRef: tmplRef,
	}
}

// newRT 走真实的 compileReceiver。手搓 receiverRT 会把排序、回落、告警这些
// 编译期行为整段绕过去，而这几样恰恰是最容易被"顺手改坏"的部分。
func newRT(t *testing.T, rc config.WebhookReceiver, tmpls ...config.MessageTemplate) *receiverRT {
	t.Helper()
	if rc.Path == "" {
		rc.Path = "hook"
	}
	m := make(map[string]config.MessageTemplate, len(tmpls))
	for _, tp := range tmpls {
		m[tp.ID] = tp
	}
	return compileReceiver(rc, m)
}

// newEvent 用 buildEvent 造事件，而不是直接填 Root：RootPath 摊开、字段映射注入、
// json.Number 都在 buildEvent 里，绕过它测出来的流水线不是线上跑的那条。
func newEvent(t *testing.T, r *receiverRT, raw string) *event {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/"+r.cfg.Path+"?env=prod", nil)
	req.Header.Set("Content-Type", "application/json")
	return buildEvent(r, req, []byte(raw), "203.0.113.9")
}

func hasWarn(warns []string, sub string) bool {
	for _, w := range warns {
		if strings.Contains(w, sub) {
			return true
		}
	}
	return false
}

func onlyMessage(t *testing.T, res result) message {
	t.Helper()
	if len(res.Messages) != 1 {
		t.Fatalf("应只产出 1 条消息，实际 %d：%+v", len(res.Messages), res.Messages)
	}
	return res.Messages[0]
}

// ---------- 规则顺序与短路 ----------

// 优先级决定顺序，而不是配置里的书写顺序：界面上能拖动排序，
// 存下来的列表顺序未必等于用户看到的顺序。
func TestProcessFirstMatchWinsByPriority(t *testing.T) {
	r := newRT(t, config.WebhookReceiver{
		Rules: []config.WebhookRule{
			rule("B", 20, "tb", cond("body.消息类型", "eq", "每日汇总")),
			rule("A", 10, "ta", cond("body.消息类型", "contains", "每日")),
		},
		DefaultTargets: []string{"g1"},
	}, tpl("ta", "A:{{.body.消息编号}}"), tpl("tb", "B:{{.body.消息编号}}"))

	res := r.process(newEvent(t, r, sampleBody))
	if res.MatchedRules != 1 {
		t.Fatalf("首个命中即停，命中数应为 1，实际 %d", res.MatchedRules)
	}
	msg := onlyMessage(t, res)
	if msg.RuleID != "A" {
		t.Fatalf("应由优先级更小的规则胜出，实际 %q", msg.RuleID)
	}
	if msg.Body != "A:MSG-2026-0001" {
		t.Fatalf("渲染结果不符：%q", msg.Body)
	}
	if msg.Err != nil {
		t.Fatalf("不该有错误：%v", msg.Err)
	}
}

func TestProcessContinueEvaluatesLaterRules(t *testing.T) {
	first := rule("A", 10, "ta", cond("body.消息类型", "contains", "每日"))
	first.Continue = true
	r := newRT(t, config.WebhookReceiver{
		Rules:          []config.WebhookRule{first, rule("B", 20, "tb")},
		DefaultTargets: []string{"g1"},
	}, tpl("ta", "A"), tpl("tb", "B"))

	res := r.process(newEvent(t, r, sampleBody))
	if res.MatchedRules != 2 || len(res.Messages) != 2 {
		t.Fatalf("Continue=true 应继续比对后续规则：命中 %d 条 %d 消息", res.MatchedRules, len(res.Messages))
	}
	if res.Messages[0].Body != "A" || res.Messages[1].Body != "B" {
		t.Fatalf("消息顺序应与规则顺序一致：%+v", res.Messages)
	}
}

// 命中一条模板配错的规则时必须停下并如实报错。
// 跳过去试下一条 = 把"模板配错了"变成"消息发到了别的群"，后者更难查。
func TestProcessRuleErrorStopsIteration(t *testing.T) {
	broken := rule("A", 10, "不存在的模板")
	broken.Continue = true
	r := newRT(t, config.WebhookReceiver{
		Rules:          []config.WebhookRule{broken, rule("B", 20, "tb")},
		DefaultTargets: []string{"g1"},
	}, tpl("tb", "B"))

	res := r.process(newEvent(t, r, sampleBody))
	if res.MatchedRules != 1 {
		t.Fatalf("出错的规则算命中，且不再往后比对，实际命中 %d", res.MatchedRules)
	}
	msg := onlyMessage(t, res)
	if msg.Err == nil || !strings.Contains(msg.Err.Error(), "模板已不存在") {
		t.Fatalf("应报出模板缺失：%v", msg.Err)
	}
	if msg.Body != "" || len(msg.Targets) != 0 {
		t.Fatalf("出错的消息不该带正文或目标：%+v", msg)
	}
	// 编译期就该在状态里留痕，而不是等第一条消息进来才暴露。
	if !hasWarn(r.warnings, "模板已不存在") {
		t.Fatalf("编译告警缺失：%v", r.warnings)
	}
}

func TestProcessRuleWithoutTemplateRefIsError(t *testing.T) {
	r := newRT(t, config.WebhookReceiver{Rules: []config.WebhookRule{rule("A", 10, "")}})
	msg := onlyMessage(t, r.process(newEvent(t, r, sampleBody)))
	if msg.Err == nil || !strings.Contains(msg.Err.Error(), "没有选择消息模板") {
		t.Fatalf("未选模板应如实报错：%v", msg.Err)
	}
}

func TestProcessDisabledRuleIgnored(t *testing.T) {
	off := rule("A", 10, "ta")
	off.Enabled = false
	r := newRT(t, config.WebhookReceiver{
		Rules: []config.WebhookRule{off, rule("B", 20, "tb")},
	}, tpl("ta", "A"), tpl("tb", "B"))

	if len(r.rules) != 1 {
		t.Fatalf("停用的规则不该进运行态，实际 %d 条", len(r.rules))
	}
	if msg := onlyMessage(t, r.process(newEvent(t, r, sampleBody))); msg.Body != "B" {
		t.Fatalf("应由启用的规则渲染：%q", msg.Body)
	}
}

// 一条都没命中是最常见的"配好了却收不到"，必须表现为 MatchedRules == 0，
// 而不是产出一条空消息。
func TestProcessNoRuleMatched(t *testing.T) {
	r := newRT(t, config.WebhookReceiver{
		Rules: []config.WebhookRule{rule("A", 10, "ta", cond("body.消息类型", "eq", "状态提醒"))},
	}, tpl("ta", "A"))

	res := r.process(newEvent(t, r, sampleBody))
	if res.MatchedRules != 0 || len(res.Messages) != 0 {
		t.Fatalf("不该命中任何规则：%+v", res)
	}
}

// 无条件规则放在最后即是兜底：消息来源不止一家时靠它避免静默丢弃。
func TestProcessFallbackRuleCatchesAll(t *testing.T) {
	r := newRT(t, config.WebhookReceiver{
		Rules: []config.WebhookRule{
			rule("精确", 10, "ta", cond("body.消息类型", "eq", "状态提醒")),
			rule("兜底", 99, "tb"),
		},
	}, tpl("ta", "A"), tpl("tb", "兜底:{{.body.消息类型}}"))

	msg := onlyMessage(t, r.process(newEvent(t, r, sampleBody)))
	if msg.RuleID != "兜底" || msg.Body != "兜底:每日汇总" {
		t.Fatalf("兜底规则应命中：%+v", msg)
	}
}

// ---------- 渲染结果 ----------

func TestProcessEmptyRenderIsReportedAsError(t *testing.T) {
	r := newRT(t, config.WebhookReceiver{
		Rules: []config.WebhookRule{rule("A", 10, "ta")},
	}, tpl("ta", "{{.body.没有这个字段}}"))

	msg := onlyMessage(t, r.process(newEvent(t, r, sampleBody)))
	if msg.Err == nil || !strings.Contains(msg.Err.Error(), "模板渲染结果为空") {
		t.Fatalf("空正文应报错而不是静默投递空消息：%v", msg.Err)
	}
	if msg.Missing != 1 {
		t.Fatalf("取不到值的字段数应为 1，实际 %d", msg.Missing)
	}
}

func TestProcessMarkdownTitleAndMissingCount(t *testing.T) {
	md := tpl("ta", "编号 {{.body.消息编号}} / {{.body.缺一}} / {{.body.缺二}}")
	md.Format = "markdown"
	md.Title = "标题{{.body.缺三}}"
	r := newRT(t, config.WebhookReceiver{Rules: []config.WebhookRule{rule("A", 10, "ta")}}, md)

	msg := onlyMessage(t, r.process(newEvent(t, r, sampleBody)))
	if msg.Format != "markdown" {
		t.Fatalf("格式应取自模板，实际 %q", msg.Format)
	}
	if msg.Title != "标题" {
		t.Fatalf("标题也走模板渲染并抹掉取不到的值：%q", msg.Title)
	}
	// 正文 2 处 + 标题 1 处：试运行页据此提示"有 N 处字段取不到值"，
	// 少算标题会让用户在标题里写错路径时完全没有提示。
	if msg.Missing != 3 {
		t.Fatalf("缺失计数应含标题，期望 3，实际 %d", msg.Missing)
	}
	if msg.Err != nil {
		t.Fatalf("缺字段不该算失败：%v", msg.Err)
	}
}

// 超长只置 Truncated，不置 Err：宁可发一条被截断的告警，也不要什么都不发。
func TestProcessTruncatedIsNotFailure(t *testing.T) {
	r := newRT(t, config.WebhookReceiver{
		Rules: []config.WebhookRule{rule("A", 10, "ta")},
	}, tpl("ta", strings.Repeat("馒", 40000)))

	res := r.process(newEvent(t, r, sampleBody))
	if !res.Truncated {
		t.Fatal("超长应置 Truncated")
	}
	msg := onlyMessage(t, res)
	if msg.Err != nil {
		t.Fatalf("截断不该算失败：%v", msg.Err)
	}
	if !strings.Contains(msg.Body, "内容过长已截断") {
		t.Fatal("正文应带截断标记")
	}
}

// ---------- 通知目标 ----------

func TestTargetsForFallbackAndDedupe(t *testing.T) {
	r := newRT(t, config.WebhookReceiver{DefaultTargets: []string{"d1", "d2"}})

	got := r.targetsFor(nil)
	if len(got) != 2 || got[0] != "d1" || got[1] != "d2" {
		t.Fatalf("规则未指定目标时应回落到默认目标：%v", got)
	}
	got = r.targetsFor([]string{"a", "", "a", "b"})
	if len(got) != 2 || got[0] != "a" || got[1] != "b" {
		t.Fatalf("应去重并丢掉空目标：%v", got)
	}
}

func TestDedupeKeepsOrder(t *testing.T) {
	if got := dedupe(nil); got != nil {
		t.Fatalf("nil 应原样返回：%v", got)
	}
	got := dedupe([]string{"b", "a", "b", "", "c", "a"})
	want := []string{"b", "a", "c"}
	if len(got) != len(want) {
		t.Fatalf("去重结果不符：%v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("去重应保持首次出现的顺序：%v", got)
		}
	}
}

// ---------- 编译期 ----------

// 路径撞车必须给出确定结果：先登记的赢，后者留告警。
// 静默让后者覆盖前者会表现为"某个来源突然全部失联"。
func TestCompileAllDuplicatePathFirstWins(t *testing.T) {
	cfg := &config.Config{
		MessageTemplates: []config.MessageTemplate{tpl("ta", "x")},
		WebhookReceivers: []config.WebhookReceiver{
			{ID: "r1", Name: "先登记", Enabled: true, Path: "same"},
			{ID: "r2", Name: "后登记", Enabled: true, Path: "same"},
		},
	}
	rt := compileAll(cfg)
	if got := rt.byPath["same"]; got == nil || got.cfg.ID != "r1" {
		t.Fatalf("应由先登记的接收器占住路径：%+v", got)
	}
	if rt.active != 2 || rt.total != 2 {
		t.Fatalf("两个接收器都算启用：active=%d total=%d", rt.active, rt.total)
	}
	if rt.warnings != 1 || !hasWarn(rt.list[1].warnings, "不会收到任何消息") {
		t.Fatalf("后登记的那个应带告警：%d %v", rt.warnings, rt.list[1].warnings)
	}
}

func TestCompileAllSkipsDisabled(t *testing.T) {
	cfg := &config.Config{
		WebhookReceivers: []config.WebhookReceiver{
			{ID: "on", Enabled: true, Path: "a"},
			{ID: "off", Path: "b"},
		},
	}
	rt := compileAll(cfg)
	if rt.total != 2 || rt.active != 1 {
		t.Fatalf("total 应含停用的，active 只数启用的：total=%d active=%d", rt.total, rt.active)
	}
	if _, ok := rt.byPath["b"]; ok {
		t.Fatal("停用的接收器不该占住路径")
	}
	// 停用的也进 list 与 byPathAll：试运行要能对着一个还没启用的接收器调路径与模板，
	// 否则用户只能先把没调好的接收器挂到公网上去试（见 routeTable.byPathAll）。
	if len(rt.list) != 2 {
		t.Fatalf("列表含停用的，供状态展示与试运行查找：%d", len(rt.list))
	}
	if got := rt.byPathAll["b"]; got == nil || got.cfg.ID != "off" {
		t.Fatalf("停用的接收器应能被试运行按路径找到：%+v", got)
	}
}

func TestCompileReceiverClampsBodyLimit(t *testing.T) {
	cases := []struct {
		kb   int
		want int64
	}{
		{0, int64(config.DefaultWebhookBodyKB) << 10},
		{-5, int64(config.DefaultWebhookBodyKB) << 10},
		{512, 512 << 10},
		{config.MaxWebhookBodyKB + 1, int64(config.MaxWebhookBodyKB) << 10},
	}
	for _, tc := range cases {
		r := newRT(t, config.WebhookReceiver{MaxBodyKB: tc.kb})
		if r.maxBody != tc.want {
			t.Errorf("MaxBodyKB=%d 时上限应为 %d，实际 %d", tc.kb, tc.want, r.maxBody)
		}
	}
}

// 映射名进模板要当标识符用：带空格或点号会让整个模板解析失败，
// 因此编译期就丢掉它并留告警，而不是等第一条消息进来才炸。
func TestCompileReceiverMappingValidation(t *testing.T) {
	r := newRT(t, config.WebhookReceiver{
		Mappings: []config.FieldMapping{
			{Name: "消息类型", Path: "body.消息类型"},
			{Name: "带 空格", Path: "body.x"},
			{Name: "带.点", Path: "body.x"},
			{Name: "2开头", Path: "body.x"},
			{Name: "", Path: "body.x"},
			{Name: "无路径", Path: ""},
		},
	})
	if len(r.mappings) != 1 || r.mappings[0].name != "消息类型" {
		t.Fatalf("只应留下合法映射：%+v", r.mappings)
	}
	for _, bad := range []string{"带 空格", "带.点", "2开头"} {
		if !hasWarn(r.warnings, bad) {
			t.Errorf("非法映射名 %q 应留告警：%v", bad, r.warnings)
		}
	}
	// 名字或路径为空是"这一行还没填完"，属于正常中间状态，不该刷告警。
	if len(r.warnings) != 3 {
		t.Fatalf("未填完的映射不该产生告警：%v", r.warnings)
	}
}

// 排序必须在副本上做：cfg 里的切片与配置管理器共享底层数组，
// 就地排序会改动 Manager.lastGood 这份回滚基线。
func TestCompileRulesDoesNotReorderConfig(t *testing.T) {
	rc := config.WebhookReceiver{
		Rules: []config.WebhookRule{
			rule("B", 20, "ta"),
			rule("A", 10, "ta"),
		},
	}
	r := newRT(t, rc, tpl("ta", "x"))

	if rc.Rules[0].ID != "B" || rc.Rules[1].ID != "A" {
		t.Fatalf("传入的配置不该被就地排序：%v %v", rc.Rules[0].ID, rc.Rules[1].ID)
	}
	if r.rules[0].cfg.ID != "A" {
		t.Fatalf("运行态应已按优先级排好：%v", r.rules[0].cfg.ID)
	}
}

func TestCompileWarnsOnUnknownOperatorAndBadRegex(t *testing.T) {
	r := newRT(t, config.WebhookReceiver{
		Rules: []config.WebhookRule{
			rule("A", 10, "ta", cond("body.x", "between", "1"), cond("body.y", "regex", "([")),
		},
	}, tpl("ta", "x"))

	for _, want := range []string{"未知算子", "正则无法编译"} {
		if !hasWarn(r.warnings, want) {
			t.Errorf("告警里应含 %q：%v", want, r.warnings)
		}
	}
	// 有问题的条件保留但永不命中，规则本身不会被丢掉——
	// 丢规则会让后续规则意外命中。
	if len(r.rules) != 1 || r.rules[0].branches[0].err != nil {
		t.Fatalf("条件有问题不该让整条规则失效：%+v", r.rules)
	}
	if r.process(newEvent(t, r, sampleBody)).MatchedRules != 0 {
		t.Fatal("坏条件应永不命中")
	}
}

// ---------- IP 名单 ----------

func TestAllowIP(t *testing.T) {
	t.Run("白名单", func(t *testing.T) {
		r := newRT(t, config.WebhookReceiver{
			IPFilter: true, IPFilterMode: "allow", AllowIPs: []string{"10.0.0.0/8", "203.0.113.9"},
			// 黑名单同时填了值也不该生效：只启用 IPFilterMode 指定的那一侧，
			// 避免"两份名单同时生效"这种没人能推理清楚的状态。
			DenyIPs: []string{"203.0.113.9"},
		})
		if ok, _ := r.allowIP(net.ParseIP("10.1.2.3")); !ok {
			t.Fatal("CIDR 内应放行")
		}
		if ok, _ := r.allowIP(net.ParseIP("203.0.113.9")); !ok {
			t.Fatal("白名单模式下黑名单不该生效")
		}
		ok, reason := r.allowIP(net.ParseIP("198.51.100.7"))
		if ok || !strings.Contains(reason, "白名单") {
			t.Fatalf("名单外应拒绝：ok=%v reason=%q", ok, reason)
		}
	})

	t.Run("黑名单", func(t *testing.T) {
		r := newRT(t, config.WebhookReceiver{
			IPFilter: true, IPFilterMode: "deny", DenyIPs: []string{"198.51.100.0/24"},
		})
		if ok, _ := r.allowIP(net.ParseIP("203.0.113.9")); !ok {
			t.Fatal("名单外应放行")
		}
		ok, reason := r.allowIP(net.ParseIP("198.51.100.7"))
		if ok || !strings.Contains(reason, "黑名单") {
			t.Fatalf("名单内应拒绝：ok=%v reason=%q", ok, reason)
		}
	})

	t.Run("空名单只告警不生效", func(t *testing.T) {
		for _, mode := range []string{"allow", "deny"} {
			r := newRT(t, config.WebhookReceiver{IPFilter: true, IPFilterMode: mode})
			if !hasWarn(r.warnings, "过滤不会生效") {
				t.Errorf("%s 模式空名单应留告警：%v", mode, r.warnings)
			}
			if ok, _ := r.allowIP(net.ParseIP("198.51.100.7")); !ok {
				t.Errorf("%s 模式空名单不该拦人", mode)
			}
		}
	})

	t.Run("未开启与nil地址", func(t *testing.T) {
		off := newRT(t, config.WebhookReceiver{AllowIPs: []string{"10.0.0.0/8"}})
		if ok, _ := off.allowIP(net.ParseIP("198.51.100.7")); !ok {
			t.Fatal("总开关未开时名单不该生效")
		}
		on := newRT(t, config.WebhookReceiver{
			IPFilter: true, IPFilterMode: "allow", AllowIPs: []string{"10.0.0.0/8"},
		})
		// 取不到对端地址只会出现在非 TCP 的测试传输上，在这里拒绝
		// 会让"配了名单的接收器在某些环境下全挂"。
		if ok, _ := on.allowIP(nil); !ok {
			t.Fatal("解析不出 IP 时应放行")
		}
	})
}

// 限流的桶表是模块级的一张（见 Module.limiter），接收器运行态里只留"每秒几次"。
// 0 表示这个接收器根本不走限流那条分支。
func TestRateLimiterOnlyWhenConfigured(t *testing.T) {
	if r := newRT(t, config.WebhookReceiver{}); r.rate != 0 {
		t.Fatalf("未配限流时不该有速率，实际 %v", r.rate)
	}
	if r := newRT(t, config.WebhookReceiver{RateLimit: 5}); r.rate != 5 {
		t.Fatalf("配了每秒 5 次，实际 %v", r.rate)
	}
}
