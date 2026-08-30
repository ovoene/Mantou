package webhook

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"mantou/internal/config"
	"mantou/internal/logx"
	"mantou/internal/modules/notify"
	"mantou/internal/runstats"
)

// 本文件是入站处理器测试的脚手架。
//
// 出站用假实现，统计用真库，但请求走真实的 m.handler()：检查顺序、状态码、
// 响应体泄不泄露原因、历史记进哪一类事件，全部必须是线上那条路径上的行为。
// Notifier 是接口正是为了这个——不必为测一次 400 就起 4 个投递 worker。

type fakeNotifier struct {
	mu    sync.Mutex
	err   error
	reqs  []notify.Request
	names map[string]string
	// hold 非 nil 时，入队前先等它关闭：用来把若干条请求同时按在"处理到一半"的位置，
	// 让它们真的同时占着并发名额（见 inflight_test.go）。
	hold chan struct{}
}

func (f *fakeNotifier) Enqueue(req notify.Request) error {
	f.mu.Lock()
	hold := f.hold
	f.mu.Unlock()
	// 刻意在锁外等：拿着锁等的话这把锁自己就把请求串起来了，也就没有并发可测。
	if hold != nil {
		<-hold
	}

	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return f.err
	}
	f.reqs = append(f.reqs, req)
	return nil
}

func (f *fakeNotifier) Targets() map[string]string { return f.names }

func (f *fakeNotifier) all() []notify.Request {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]notify.Request{}, f.reqs...)
}

func (f *fakeNotifier) setErr(err error) {
	f.mu.Lock()
	f.err = err
	f.mu.Unlock()
}

// setHold 让后续每次入队都先等 ch 关闭。传 nil 恢复原样。
func (f *fakeNotifier) setHold(ch chan struct{}) {
	f.mu.Lock()
	f.hold = ch
	f.mu.Unlock()
}

type harness struct {
	m     *Module
	n     *fakeNotifier
	srv   *httptest.Server
	stats *runstats.Store
}

// newHarness 起一个不占端口的模块（Webhook.Enabled 默认 false）加一个 httptest 服务。
// logPath 传空串：历史只进内存环，测试不该在磁盘上留文件。
func newHarness(t *testing.T, cfg config.Config) *harness { return buildHarness(t, cfg, true) }

// newHarnessNoNotifier 不注入出站能力，用来测"出站模块不可用"那条分支。
func newHarnessNoNotifier(t *testing.T, cfg config.Config) *harness {
	return buildHarness(t, cfg, false)
}

func buildHarness(t *testing.T, cfg config.Config, withNotifier bool) *harness {
	t.Helper()
	// 原文留存额度：从磁盘来的配置里这个字段一定有值（migrate 的 v8 块与 defaultConfig
	// 都会填），而 0 在它上面是「不留存」这个有效取值，不是「没填」。
	// 这里的 cfg 是测试手搭的结构体，不走 migrate，零值就等于把留存整个关掉——
	// 于是与留存无关的用例会以"因为根本没留所以没超预算"的方式假装通过。
	// 故在这一处补上默认值，与配置从磁盘来时保持一致。
	// 要测"不留存"的用例把它填 -1：setBudget 会把负数收成 0。
	if cfg.Webhook.SourceRetainMB == 0 {
		cfg.Webhook.SourceRetainMB = config.DefaultSourceRetainMB
	}
	h := &harness{
		n: &fakeNotifier{names: map[string]string{"g1": "运维群", "g2": "老板群"}},
		// 统计用真库而不是替身：它本来就只在内存里，起一份的代价与替身相同，
		// 而替身要照抄「截断」「拒收不动时刻」这些规则——照抄就会漏。
		stats: runstats.New(),
	}
	h.m = New(logx.New(logx.Options{}), h.stats, "")
	if withNotifier {
		h.m.SetNotifier(h.n)
	}
	if err := h.m.Reload(&cfg); err != nil {
		t.Fatalf("Reload 失败: %v", err)
	}
	t.Cleanup(func() { _ = h.m.Close() })
	h.srv = httptest.NewServer(h.m.handler())
	t.Cleanup(h.srv.Close)
	return h
}

// do 发一次请求，返回状态码与响应体。mut 可在发出前改请求（加头、改 Host）。
func (h *harness) do(t *testing.T, method, target, body string, mut func(*http.Request)) (int, string) {
	t.Helper()
	req, err := http.NewRequest(method, h.srv.URL+target, strings.NewReader(body))
	if err != nil {
		t.Fatalf("构造请求失败: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if mut != nil {
		mut(req)
	}
	resp, err := h.srv.Client().Do(req)
	if err != nil {
		t.Fatalf("请求失败: %v", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("读响应失败: %v", err)
	}
	return resp.StatusCode, string(raw)
}

func (h *harness) post(t *testing.T, target, body string) (int, string) {
	t.Helper()
	return h.do(t, http.MethodPost, target, body, nil)
}

// okBody 解析成功响应并断言 ok 字段。
func (h *harness) okBody(t *testing.T, body string) (eventID string, matched int) {
	t.Helper()
	var out struct {
		OK      bool   `json:"ok"`
		EventID string `json:"eventId"`
		Matched int    `json:"matched"`
	}
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		t.Fatalf("响应不是 JSON：%q", body)
	}
	if !out.OK {
		t.Fatalf("ok 应为 true：%q", body)
	}
	return out.EventID, out.Matched
}

func (h *harness) history(t *testing.T) []HistoryEntry {
	t.Helper()
	return h.m.History(HistoryQuery{Limit: 100})
}

// last 取最近一条历史（recent 是新的在前）。
func (h *harness) last(t *testing.T) HistoryEntry {
	t.Helper()
	all := h.history(t)
	if len(all) == 0 {
		t.Fatal("历史里应至少有一条记录")
	}
	return all[0]
}

func (h *harness) findEvent(t *testing.T, event string) HistoryEntry {
	t.Helper()
	all := h.history(t)
	for _, e := range all {
		if e.Event == event {
			return e
		}
	}
	t.Fatalf("历史里没有 %q 记录：%+v", event, all)
	return HistoryEntry{}
}

// hookCfg 组一份只含一个接收器的配置。
func hookCfg(rc config.WebhookReceiver, tmpls ...config.MessageTemplate) config.Config {
	return config.Config{
		WebhookReceivers: []config.WebhookReceiver{rc},
		MessageTemplates: tmpls,
	}
}

// recv 一个启用的接收器：路径 kd，默认目标 g1。
func recv(rules ...config.WebhookRule) config.WebhookReceiver {
	return config.WebhookReceiver{
		ID: "r1", Name: "第三方系统", Enabled: true, Path: "hook",
		Rules: rules, DefaultTargets: []string{"g1"},
	}
}
