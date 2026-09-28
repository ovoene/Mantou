package notify

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"mantou/internal/config"
)

// 排队与重试中的任务在投递前要换成当前的目标配置（见 refresh）。
//
// 原先任务一直拿着入队时那份目标快照：删掉或禁用的目标在重试链里继续收消息，
// 刚改对的地址用不上，刚打开的「禁止访问内网」也管不到这几条。
//
// 下面的用例都让对端在**首投的处理函数里**完成那次配置变更、再回一个失败：
// 首投必然看到旧配置、重投必然看到新配置，不依赖任何时序猜测。

// reloadOnFirstHit 起一个对端：第一次被投递时先把模块的配置换成 next(自己的地址)，再回 500；
// 之后的投递一律回成功。自己的地址从请求里取，免得处理函数去读测试协程后来才写的变量。
func reloadOnFirstHit(t *testing.T, mod *atomic.Pointer[Module], next func(self string) *config.Config) (url string, hits func() int) {
	t.Helper()
	var n atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		if n.Add(1) == 1 {
			if err := mod.Load().Reload(next("http://" + r.Host)); err != nil {
				t.Errorf("Reload: %v", err)
			}
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		_, _ = w.Write([]byte(`{"errcode":0}`))
	}))
	t.Cleanup(srv.Close)
	return srv.URL, func() int { return int(n.Load()) }
}

// 删掉的目标：重试链就此终止，记一条说明原因的最终失败，预算还回去。
func TestRetryStopsWhenTargetDeleted(t *testing.T) {
	shortRetry(t)
	var mod atomic.Pointer[Module]
	url, hits := reloadOnFirstHit(t, &mod, func(string) *config.Config { return &config.Config{} })
	m, _, results := newModule(t, config.NotifyTarget{
		ID: "d1", Name: "钉钉群", Type: "dingtalk", Enabled: true, URL: url, Retry: 3,
	})
	mod.Store(m)

	if err := m.Enqueue(Request{TargetIDs: []string{"d1"}, Message: "机密告警", Format: "text"}); err != nil {
		t.Fatalf("Enqueue: %v", err)
	}
	if first := waitResult(t, results); first.OK || !first.Retrying {
		t.Fatalf("首投应是失败但仍标记重试：%+v", first)
	}
	final := waitResult(t, results)
	if final.OK || final.Retrying || !strings.Contains(final.Status, "不存在") || final.Attempt != 2 {
		t.Fatalf("目标删掉后应就此放弃并说明原因：%+v", final)
	}
	if n := hits(); n != 1 {
		t.Fatalf("删掉的目标不该再收到投递，实际共 %d 次", n)
	}
	if _, failed, _, pending := m.Metrics(); failed != 1 || pending != 0 {
		t.Fatalf("应记 1 条最终失败且无在飞任务：failed=%d pending=%d", failed, pending)
	}
	if got := m.bytes.Load(); got != 0 {
		t.Fatalf("放弃后预算应归零，实际还占 %d 字节", got)
	}
}

// 禁用的目标：同上，原因写"已禁用"。
func TestRetryStopsWhenTargetDisabled(t *testing.T) {
	shortRetry(t)
	var mod atomic.Pointer[Module]
	url, hits := reloadOnFirstHit(t, &mod, func(self string) *config.Config {
		return &config.Config{NotifyTargets: []config.NotifyTarget{
			{ID: "d1", Name: "钉钉群", Type: "dingtalk", Enabled: false, URL: self, Retry: 3},
		}}
	})
	m, _, results := newModule(t, config.NotifyTarget{
		ID: "d1", Name: "钉钉群", Type: "dingtalk", Enabled: true, URL: url, Retry: 3,
	})
	mod.Store(m)

	if err := m.Enqueue(Request{TargetIDs: []string{"d1"}, Message: "x", Format: "text"}); err != nil {
		t.Fatalf("Enqueue: %v", err)
	}
	waitResult(t, results)
	final := waitResult(t, results)
	if final.OK || final.Retrying || !strings.Contains(final.Status, "已禁用") {
		t.Fatalf("目标禁用后应就此放弃：%+v", final)
	}
	if n := hits(); n != 1 {
		t.Fatalf("禁用的目标不该再收到投递，实际共 %d 次", n)
	}
}

// 改对了地址：重投走新地址，这是包注释承诺的行为。
func TestRetryUsesUpdatedURL(t *testing.T) {
	shortRetry(t)
	fixed, fixedCap := newServer(t, nil)
	var mod atomic.Pointer[Module]
	url, hits := reloadOnFirstHit(t, &mod, func(string) *config.Config {
		return &config.Config{NotifyTargets: []config.NotifyTarget{
			{ID: "d1", Name: "钉钉群", Type: "dingtalk", Enabled: true, URL: fixed.URL, Retry: 3},
		}}
	})
	m, _, results := newModule(t, config.NotifyTarget{
		ID: "d1", Name: "钉钉群", Type: "dingtalk", Enabled: true, URL: url, Retry: 3,
	})
	mod.Store(m)

	if err := m.Enqueue(Request{TargetIDs: []string{"d1"}, Message: "x", Format: "text"}); err != nil {
		t.Fatalf("Enqueue: %v", err)
	}
	waitResult(t, results)
	if second := waitResult(t, results); !second.OK {
		t.Fatalf("改对地址后重投应成功：%+v", second)
	}
	if n := hits(); n != 1 {
		t.Fatalf("旧地址只该收到首投那一次，实际 %d 次", n)
	}
	if _, _, _, _, n := fixedCap.snapshot(); n != 1 {
		t.Fatalf("新地址应收到重投，实际 %d 次", n)
	}
}

// 重试期间打开了「禁止访问内网」：重投要受它管，不能因为任务是开关打开之前入队的就放过去。
func TestRetryHonorsBlockPrivateTurnedOn(t *testing.T) {
	shortRetry(t)
	var mod atomic.Pointer[Module]
	url, hits := reloadOnFirstHit(t, &mod, func(self string) *config.Config {
		cfg := &config.Config{NotifyTargets: []config.NotifyTarget{
			{ID: "h1", Name: "内网自建", Type: "http", Enabled: true, URL: self, Retry: 1},
		}}
		cfg.Settings.Security.BlockPrivateNetwork = true
		return cfg
	})
	m, _, results := newModule(t, config.NotifyTarget{
		ID: "h1", Name: "内网自建", Type: "http", Enabled: true, URL: url, Retry: 1,
	})
	mod.Store(m)

	if err := m.Enqueue(Request{TargetIDs: []string{"h1"}, Message: "x", Format: "text"}); err != nil {
		t.Fatalf("Enqueue: %v", err)
	}
	waitResult(t, results)
	final := waitResult(t, results)
	if final.OK || !strings.Contains(final.Status, "内网防护") {
		t.Fatalf("开关打开之后的重投应被内网防护拦下：%+v", final)
	}
	if n := hits(); n != 1 {
		t.Fatalf("重投应在拨号阶段就被拦下，对端共收到 %d 次", n)
	}
}

// 请求体模板被改过：排队的那条是按旧模板渲染的、事件数据也已释放，只能放弃。
func TestRetryDropsWhenBodyTemplateChanged(t *testing.T) {
	shortRetry(t)
	var mod atomic.Pointer[Module]
	url, hits := reloadOnFirstHit(t, &mod, func(self string) *config.Config {
		return &config.Config{NotifyTargets: []config.NotifyTarget{
			{ID: "h1", Name: "自建", Type: "http", Enabled: true, URL: self, Retry: 3, BodyTemplate: `{"new":{{.messageJSON}}}`},
		}}
	})
	m, _, results := newModule(t, config.NotifyTarget{
		ID: "h1", Name: "自建", Type: "http", Enabled: true, URL: url, Retry: 3, BodyTemplate: `{"old":{{.messageJSON}}}`,
	})
	mod.Store(m)

	if err := m.Enqueue(Request{TargetIDs: []string{"h1"}, Message: "x", Format: "text"}); err != nil {
		t.Fatalf("Enqueue: %v", err)
	}
	waitResult(t, results)
	final := waitResult(t, results)
	if final.OK || final.Retrying || !strings.Contains(final.Status, "模板") {
		t.Fatalf("模板改过之后应放弃并说明原因：%+v", final)
	}
	if n := hits(); n != 1 {
		t.Fatalf("放弃的消息不该再发出去，对端共收到 %d 次", n)
	}
}

// 与投递无关的改动（例如改个名字）不影响重投，预渲染的请求体照常使用。
func TestRetryKeepsPreRenderedBodyAcrossUnrelatedReload(t *testing.T) {
	shortRetry(t)
	const tmpl = `{"no":"{{.消息编号}}"}`
	var mod atomic.Pointer[Module]
	var n atomic.Int64
	var retried atomic.Value // 重投时对端收到的请求体
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if n.Add(1) == 1 {
			_ = mod.Load().Reload(&config.Config{NotifyTargets: []config.NotifyTarget{
				{ID: "h1", Name: "改了名字", Type: "http", Enabled: true, URL: "http://" + r.Host, Retry: 3, BodyTemplate: tmpl},
			}})
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		retried.Store(string(body))
		_, _ = w.Write([]byte(`ok`))
	}))
	t.Cleanup(srv.Close)
	m, _, results := newModule(t, config.NotifyTarget{
		ID: "h1", Name: "自建", Type: "http", Enabled: true, URL: srv.URL, Retry: 3, BodyTemplate: tmpl,
	})
	mod.Store(m)

	if err := m.Enqueue(Request{
		TargetIDs: []string{"h1"}, Message: "x", Format: "text",
		Data: map[string]any{"消息编号": "SO-1"},
	}); err != nil {
		t.Fatalf("Enqueue: %v", err)
	}
	waitResult(t, results)
	second := waitResult(t, results)
	if !second.OK || second.TargetName != "改了名字" {
		t.Fatalf("重投应成功且用上新配置：%+v", second)
	}
	// 事件数据入队时就释放了，重投还能带着 SO-1，说明用的是入队时渲染好的那份。
	if got, _ := retried.Load().(string); got != `{"no":"SO-1"}` {
		t.Fatalf("重投应沿用入队时渲染好的请求体，实际 %q", got)
	}
}
