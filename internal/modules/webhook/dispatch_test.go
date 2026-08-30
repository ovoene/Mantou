package webhook

import (
	"errors"
	"net/http"
	"strings"
	"testing"

	"mantou/internal/config"
)

// 本文件盯的是"请求已经通过全部校验之后"的行为：
// 派发的四种失败分支各自记成什么、调试留存的生命周期、试运行与真实路径是否一致。
//
// 这些分支在界面上只表现为历史列表里的一行字。写错不会有人报错，
// 只会让用户对着一条"已接收"却始终收不到消息。

// ---------- 派发 ----------

// 没有规则命中不是错误：一个接收器接了某个系统的全部推送、只对其中几种消息发消息，
// 是这个模块最常见的用法。它必须回 200，否则对方会判定推送失败并不停重推。
func TestDispatchNoRuleMatched(t *testing.T) {
	h := newHarness(t, hookCfg(recv(), okTpl()))
	code, body := h.post(t, "/hook", `{"消息编号":"MSG-1"}`)
	if code != http.StatusOK {
		t.Fatalf("无规则命中也应回 200，实际 %d：%s", code, body)
	}
	if _, matched := h.okBody(t, body); matched != 0 {
		t.Fatalf("命中数应为 0：%s", body)
	}
	if len(h.n.all()) != 0 {
		t.Fatal("不该派发任何消息")
	}

	e := h.last(t)
	if e.Event != EventDropped || e.Status != http.StatusOK {
		t.Fatalf("应记成 EventDropped：%+v", e)
	}
	// 已接收但没发出去要与"拒收"分开计数：前者是配置意图，后者是问题。
	if received, rejected, dropped := h.m.Metrics(); received != 1 || rejected != 0 || dropped != 1 {
		t.Fatalf("计数不符：%d %d %d", received, rejected, dropped)
	}
	if st := h.stats.Recv("r1"); st.LastStatus != "已接收，无规则命中" {
		t.Fatalf("运行态应说明原因：%q", st.LastStatus)
	}
}

func TestDispatchErrorBranches(t *testing.T) {
	// 规则命中却没有目标：这是纯配置疏漏，必须在历史里说清是"两处都没配"，
	// 否则用户会去查钉钉机器人为什么不响应。
	t.Run("没有通知目标", func(t *testing.T) {
		rc := recv(rule("a", 0, "t1"))
		rc.DefaultTargets = nil
		h := newHarness(t, hookCfg(rc, okTpl()))
		if code, _ := h.post(t, "/hook", "{}"); code != http.StatusOK {
			t.Fatalf("仍应回 200，实际 %d", code)
		}
		e := h.findEvent(t, EventError)
		if !strings.Contains(e.Reason, "没有通知目标") || e.Rule != "规则a" {
			t.Fatalf("原因应指向配置疏漏：%+v", e)
		}
		if st := h.stats.Recv("r1"); st.LastStatus != "已接收，但没有消息派发成功" {
			t.Fatalf("运行态不符：%q", st.LastStatus)
		}
	})

	t.Run("出站模块不可用", func(t *testing.T) {
		h := newHarnessNoNotifier(t, hitCfg(nil))
		if code, _ := h.post(t, "/hook", "{}"); code != http.StatusOK {
			t.Fatalf("仍应回 200，实际 %d", code)
		}
		if e := h.findEvent(t, EventError); !strings.Contains(e.Reason, "出站模块不可用") {
			t.Fatalf("原因不符：%+v", e)
		}
	})

	t.Run("入队失败", func(t *testing.T) {
		h := newHarness(t, hitCfg(nil))
		h.n.setErr(errors.New("队列已满"))
		if code, _ := h.post(t, "/hook", "{}"); code != http.StatusOK {
			t.Fatalf("仍应回 200，实际 %d", code)
		}
		e := h.findEvent(t, EventError)
		if !strings.Contains(e.Reason, "入队失败：队列已满") {
			t.Fatalf("应带上出站模块给的原因：%+v", e)
		}
	})

	// 渲染成空文本时不能入队：钉钉、企业微信都会拒收空消息，
	// 与其让用户去查对方的错误码，不如在这里就说清是模板的问题。
	t.Run("渲染为空", func(t *testing.T) {
		h := newHarness(t, hookCfg(recv(rule("a", 0, "t1")), tpl("t1", "{{.没有这个字段}}")))
		if code, _ := h.post(t, "/hook", "{}"); code != http.StatusOK {
			t.Fatalf("仍应回 200，实际 %d", code)
		}
		if len(h.n.all()) != 0 {
			t.Fatal("空消息不该入队")
		}
		if e := h.findEvent(t, EventError); !strings.Contains(e.Reason, "渲染结果为空") {
			t.Fatalf("原因应指向模板：%+v", e)
		}
	})
}

// 一条请求命中多条规则时，前一条的 Continue 决定还要不要继续：
// 同一消息往不同群发不同措辞是这个模块的基本用法。
func TestDispatchMultipleMessages(t *testing.T) {
	first := rule("一", 1, "t1")
	first.Continue = true
	second := rule("二", 2, "t1")
	second.Targets = []string{"g2"}

	h := newHarness(t, hookCfg(recv(first, second), okTpl()))
	if code, body := h.post(t, "/hook", "{}"); code != http.StatusOK {
		t.Fatalf("应回 200，实际 %d：%s", code, body)
	}
	reqs := h.n.all()
	if len(reqs) != 2 {
		t.Fatalf("应入队 2 条，实际 %d", len(reqs))
	}
	// 优先级数字小的先判断（界面上填 1 表示最先）。
	if reqs[0].RuleName != "规则一" || reqs[1].RuleName != "规则二" {
		t.Fatalf("顺序应按优先级：%q %q", reqs[0].RuleName, reqs[1].RuleName)
	}
	if reqs[0].TargetIDs[0] != "g1" || reqs[1].TargetIDs[0] != "g2" {
		t.Fatalf("规则自带目标应压过接收器默认目标：%v %v", reqs[0].TargetIDs, reqs[1].TargetIDs)
	}
	if st := h.stats.Recv("r1"); st.LastStatus != "已接收并派发" {
		t.Fatalf("有成功的就算派发成功：%q", st.LastStatus)
	}
}

// 规则出错会中断后续规则，即使它写了 Continue。
// 这是刻意的：出错说明配置已经不可信，继续往下发可能把本该只发给财务的内容发进运维群。
func TestDispatchRuleErrorStopsChain(t *testing.T) {
	broken := rule("坏", 1, "缺失的模板")
	broken.Continue = true
	fine := rule("好", 2, "t1")

	h := newHarness(t, hookCfg(recv(broken, fine), okTpl()))
	if code, _ := h.post(t, "/hook", "{}"); code != http.StatusOK {
		t.Fatal("应回 200")
	}
	if got := h.n.all(); len(got) != 0 {
		t.Fatalf("出错后不该继续派发后续规则：%+v", got)
	}
	if e := h.findEvent(t, EventError); !strings.Contains(e.Reason, "模板") {
		t.Fatalf("原因应指向模板：%+v", e)
	}
	if st := h.stats.Recv("r1"); st.LastStatus != "已接收，但没有消息派发成功" {
		t.Fatalf("运行态不符：%q", st.LastStatus)
	}
}

// ---------- 试运行 ----------

// 试运行与真实请求必须走同一条流水线。若这里另写一遍，
// 试运行页说"会发给运维群"而实际发到别处，这个功能就没有意义了。
func TestDryRun(t *testing.T) {
	h := newHarness(t, hookCfg(recv(rule("a", 0, "t1")), tpl("t1", "收到 {{.source}}／{{.body.消息编号}}")))

	if _, err := h.m.DryRun("不存在", []byte("{}"), nil, ""); !errors.Is(err, errNoReceiver) {
		t.Fatalf("未知接收器应返回 errNoReceiver，实际 %v", err)
	}

	out, err := h.m.DryRun("r1", []byte(`{"消息编号":"MSG-1"}`), map[string]string{"X-Source": "sys-a"}, "env=prod")
	if err != nil {
		t.Fatalf("试运行失败：%v", err)
	}
	if out.Matched != 1 || len(out.Messages) != 1 {
		t.Fatalf("应命中 1 条：%+v", out)
	}
	msg := out.Messages[0]
	if msg.Body != "收到 第三方系统／MSG-1" || msg.RuleName != "规则a" {
		t.Fatalf("渲染结果不符：%+v", msg)
	}
	// 界面要显示"会发给谁"，所以目标 ID 与人看得懂的名字都得给。
	if len(msg.Targets) != 1 || msg.Targets[0] != "g1" {
		t.Fatalf("目标不符：%v", msg.Targets)
	}
	if out.TargetName["g1"] != "运维群" {
		t.Fatalf("应带上目标名称供界面显示：%v", out.TargetName)
	}
	// 中间产物是"不写代码也能调通"的关键：用户据此判断路径写对了没有。
	if out.EventID == "" || out.Root["source"] != "第三方系统" {
		t.Fatalf("应返回事件信封：%+v", out.Root)
	}

	// 试运行**不投递**，也不该污染计数与历史。
	if len(h.n.all()) != 0 {
		t.Fatal("试运行不该真的入队")
	}
	if received, rejected, dropped := h.m.Metrics(); received != 0 || rejected != 0 || dropped != 0 {
		t.Fatalf("试运行不该改计数：%d %d %d", received, rejected, dropped)
	}
	if len(h.history(t)) != 0 {
		t.Fatal("试运行不该写执行历史")
	}
}

// 停用的接收器**也能**试运行：不这样的话，用户只能先把一个还没调通的接收器
// 挂到公网上去试。它仍然不参与真实入站（那条路径依旧 404）。
func TestDryRunOnDisabledReceiver(t *testing.T) {
	h := newHarness(t, hitCfg(func(rc *config.WebhookReceiver) { rc.Enabled = false }))
	out, err := h.m.DryRun("r1", []byte(`{"消息编号":"MSG-1"}`), nil, "")
	if err != nil {
		t.Fatalf("停用的接收器应允许试运行：%v", err)
	}
	if out.Matched != 1 {
		t.Fatalf("停用不影响流水线本身：%+v", out)
	}
	if len(h.n.all()) != 0 {
		t.Fatal("试运行不该真的入队")
	}
}

// 认不出的接收器 ID 才是 errNoReceiver——把"停用"和"不存在"分开，
// 否则界面无法区分"开关没开"与"这条已经被删了"。
func TestDryRunUnknownReceiver(t *testing.T) {
	h := newHarness(t, hitCfg(nil))
	if _, err := h.m.DryRun("不存在", []byte("{}"), nil, ""); !errors.Is(err, errNoReceiver) {
		t.Fatalf("应返回 errNoReceiver，实际 %v", err)
	}
}

// ---------- 历史 ----------

func TestHistoryFilterByReceiver(t *testing.T) {
	a := recv(rule("a", 0, "t1"))
	b := config.WebhookReceiver{ID: "r2", Name: "Grafana", Enabled: true, Path: "graf",
		Rules: []config.WebhookRule{rule("b", 0, "t1")}, DefaultTargets: []string{"g2"}}
	h := newHarness(t, config.Config{
		WebhookReceivers: []config.WebhookReceiver{a, b},
		MessageTemplates: []config.MessageTemplate{okTpl()},
	})

	h.post(t, "/hook", "{}")
	h.post(t, "/graf", "{}")
	h.post(t, "/graf", "{}")

	if got := len(h.history(t)); got != 3 {
		t.Fatalf("全部历史应有 3 条，实际 %d", got)
	}
	if got := h.m.History(HistoryQuery{ReceiverID: "r1", Limit: 100}); len(got) != 1 || got[0].Receiver != "第三方系统" {
		t.Fatalf("按接收器过滤不符：%+v", got)
	}
	if got := h.m.History(HistoryQuery{ReceiverID: "r2", Limit: 100}); len(got) != 2 {
		t.Fatalf("r2 应有 2 条，实际 %d", len(got))
	}
	// limit 截断留最新的：面板上默认只看最近若干条。
	if got := h.m.History(HistoryQuery{Limit: 1}); len(got) != 1 || got[0].ReceiverID != "r2" {
		t.Fatalf("limit 应保留最新一条：%+v", got)
	}
}

// ---------- 小工具 ----------

func TestHostMatches(t *testing.T) {
	cases := []struct {
		host, domain string
		want         bool
	}{
		{"any", "", true}, // 未填域名（未启用 HTTPS）时不校验
		{"hook.example.com", "hook.example.com", true},
		{"hook.example.com:25667", "hook.example.com", true},
		{"HOOK.Example.COM", "hook.example.com", true},
		{"  hook.example.com  ", "hook.example.com", true},
		{"other.example.com", "hook.example.com", false},
		{"192.0.2.10", "hook.example.com", false}, // 拿 IP 直连绕过域名的探测
		{"192.0.2.10:25667", "192.0.2.10", true},
		// IPv6 字面量在 Host 头里必须带括号，域名栏里两种写法都可能填。
		{"[2001:db8::1]", "2001:db8::1", true},
		{"[2001:db8::1]:25667", "2001:db8::1", true},
		{"[2001:db8::1]", "[2001:db8::1]", true},
		{"[2001:db8::2]", "2001:db8::1", false},
	}
	for _, c := range cases {
		if got := hostMatches(c.host, c.domain); got != c.want {
			t.Errorf("hostMatches(%q, %q) = %v，应为 %v", c.host, c.domain, got, c.want)
		}
	}
}

func TestAllowedMethod(t *testing.T) {
	for _, m := range []string{http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodGet} {
		if !allowedMethod(m) {
			t.Errorf("%s 应放行", m)
		}
	}
	for _, m := range []string{http.MethodHead, http.MethodOptions, http.MethodDelete, http.MethodTrace, ""} {
		if allowedMethod(m) {
			t.Errorf("%s 不该放行", m)
		}
	}
}

func TestSameSecret(t *testing.T) {
	cases := []struct {
		got, want string
		ok        bool
	}{
		{"abc", "abc", true},
		{"  abc  ", "abc", true}, // 对方多带的空白不该导致校验失败
		{"abc", "abcd", false},
		{"abcd", "abc", false},
		{"ABC", "abc", false},
		{"令牌", "令牌", true},
		// 空令牌相等——所以 checkAuth 必须在调用之前就挡住"选了鉴权但没填令牌"。
		// 这里显式钉住，避免有人把那个前置判断当成多余的代码删掉。
		{"", "", true},
	}
	for _, c := range cases {
		if got := sameSecret(c.got, c.want); got != c.ok {
			t.Errorf("sameSecret(%q, %q) = %v，应为 %v", c.got, c.want, got, c.ok)
		}
	}
}

func TestByteSizeAndItoa(t *testing.T) {
	for in, want := range map[int64]string{
		0: "0 KB", 1024: "1 KB", 2048: "2 KB", 1536: "1 KB",
		1 << 20: "1 MB", 5 << 20: "5 MB",
	} {
		if got := byteSize(in); got != want {
			t.Errorf("byteSize(%d) = %q，应为 %q", in, got, want)
		}
	}
	for in, want := range map[int]string{0: "0", 1: "1", 9: "9", 10: "10", 1234: "1234"} {
		if got := itoa(in); got != want {
			t.Errorf("itoa(%d) = %q，应为 %q", in, got, want)
		}
	}
}
