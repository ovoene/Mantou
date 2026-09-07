package ddns

import (
	"context"
	"sync"
	"testing"
	"time"

	"mantou/internal/config"
	"mantou/internal/logx"
)

// 取址方式填一个不认识的值时，detectIP 立刻返回错误且不碰网络（见 ipsource.go 的 default 分支）。
// 下面几个用例都拿它当"必然失败且瞬间返回"的探测来源：既不依赖外网，也不用等超时。
const badSource = "definitely-not-a-source-type"

func testRule(id string) config.DDNSRule {
	return config.DDNSRule{
		ID:          id,
		Name:        id,
		Enabled:     true,
		IntervalSec: 3600, // 只跑启动那一次，不要在测试期间被 ticker 再叫醒
		Source:      config.DDNSSource{Type: badSource},
	}
}

// fakeCfg 记下 UpdateState 被调了几次、最后一次写进去的运行状态是什么。
// 探测协程会并发调它，所以计数要上锁。
type fakeCfg struct {
	mu     sync.Mutex
	rules  []config.DDNSRule
	writes int
	last   config.DDNSRule
}

func (f *fakeCfg) Snapshot() *config.Config {
	f.mu.Lock()
	defer f.mu.Unlock()
	return &config.Config{DDNS: append([]config.DDNSRule(nil), f.rules...)}
}

func (f *fakeCfg) UpdateState(mutate func(c *config.Config)) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	c := &config.Config{DDNS: append([]config.DDNSRule(nil), f.rules...)}
	mutate(c)
	f.writes++
	if len(c.DDNS) > 0 {
		f.last = c.DDNS[0]
	}
	f.rules = c.DDNS
	return nil
}

func (f *fakeCfg) stats() (int, config.DDNSRule) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.writes, f.last
}

func quietLog() *logx.Logger { return logx.New(logx.Options{Levels: []string{"error"}}) }

// 总览页的 DDNS 那一行原先永远是 "N / N"：Active 直接取了 len(m.runners)，
// 一条规则连着失败也看不出来。Active 必须是"最近一轮成功的规则数"，与端口转发同口径。
func TestStatusCountsOnlyHealthyRunners(t *testing.T) {
	m := New(quietLog(), &fakeCfg{})
	m.runners = map[string]*ruleRunner{
		"ok1":  {lastOKVal: true},
		"bad":  {lastOKVal: false},
		"ok2":  {lastOKVal: true},
		"bad2": {lastOKVal: false},
	}

	st := m.Status()
	if st.Total != 4 {
		t.Errorf("Total 应为运行中的规则数 4，实际 %d", st.Total)
	}
	if st.Active != 2 {
		t.Errorf("Active 应为最近一轮成功的 2 条，实际 %d", st.Active)
	}
	if st.Healthy {
		t.Error("有规则失败时 Healthy 应为 false")
	}

	// 反向：全成功时必须是满血的 N / N，且 Healthy 为真。
	m.runners = map[string]*ruleRunner{"ok1": {lastOKVal: true}, "ok2": {lastOKVal: true}}
	st = m.Status()
	if st.Total != 2 || st.Active != 2 || !st.Healthy {
		t.Errorf("全部成功时应为 2/2 且健康，实际 %+v", st)
	}
}

// 被掐断的那一轮什么也没测出来，它的"失败"不该落进 state.json：
// 否则每次正常退出都会给当时在跑的规则留下一句「取址失败: context canceled」，
// 下次启动面板上就显示成一条出错的规则，而它其实好得很。
func TestExecuteSkipsStatusWriteWhenCanceled(t *testing.T) {
	fake := &fakeCfg{rules: []config.DDNSRule{testRule("r1")}}
	r := newRuleRunner(testRule("r1"), quietLog(), fake)
	defer r.stop()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := r.execute(ctx); err == nil {
		t.Fatal("取址方式不认识，execute 应当返回错误")
	}
	if n, _ := fake.stats(); n != 0 {
		t.Fatalf("已取消的那一轮不该回写状态，实际写了 %d 次", n)
	}

	// 反向：没被取消的失败是真实结果，必须写下来让用户看见——
	// 否则这道闸就成了"取址失败一律不记"。
	if _, err := r.execute(context.Background()); err == nil {
		t.Fatal("取址方式不认识，execute 应当返回错误")
	}
	n, last := fake.stats()
	if n != 1 {
		t.Fatalf("未被取消的失败应当回写一次状态，实际 %d 次", n)
	}
	if last.LastStatus == "" {
		t.Error("回写的状态文本不应为空")
	}
	if last.LastUpdateAt != 0 {
		t.Error("没有真正写入 DNS 记录时不该推进「最近更新」时间")
	}
}

// Close 只 cancel 不等的话，被掐断的那一轮会一边跑一边和配置管理器的最后一次落盘赛跑。
// 这里钉住：Close 会等探测协程退出（done 关闭），并且在宽限期内返回、把 runner 清空。
func TestCloseWaitsForRunners(t *testing.T) {
	fake := &fakeCfg{rules: []config.DDNSRule{testRule("r1")}}
	m := New(quietLog(), fake)

	if err := m.Reload(&config.Config{DDNS: []config.DDNSRule{testRule("r1")}}); err != nil {
		t.Fatalf("Reload 失败: %v", err)
	}
	m.mu.Lock()
	run := m.runners["r1"]
	m.mu.Unlock()
	if run == nil {
		t.Fatal("启用的规则应当建出 runner")
	}

	start := time.Now()
	if err := m.Close(); err != nil {
		t.Fatalf("Close 失败: %v", err)
	}
	if elapsed := time.Since(start); elapsed >= closeGrace {
		t.Errorf("探测协程会立刻退出，Close 不该耗到宽限期上限（%v），实际 %v", closeGrace, elapsed)
	}
	select {
	case <-run.done:
	default:
		t.Error("Close 返回时探测协程应当已经退出（done 已关闭）")
	}
	m.mu.Lock()
	left := len(m.runners)
	m.mu.Unlock()
	if left != 0 {
		t.Errorf("Close 后不该还留着 runner，实际 %d 个", left)
	}

	// 再关一次不能卡住也不能 panic：进程退出路径上重复调用是允许的。
	if err := m.Close(); err != nil {
		t.Errorf("重复 Close 应当无害，实际：%v", err)
	}
}

// RunOnceCtx 对未在运行的规则（已禁用/尚未加载）临时执行一次，便于用户在启用前验证配置。
// 这条路径上的临时 runner 不进 m.runners，也就没人等它的 done——只 stop 不等，不能挂住。
func TestRunOnceCtxOnStoppedRule(t *testing.T) {
	disabled := testRule("r1")
	disabled.Enabled = false
	fake := &fakeCfg{rules: []config.DDNSRule{disabled}}
	m := New(quietLog(), fake)

	done := make(chan struct{})
	go func() {
		defer close(done)
		if _, err := m.RunOnceCtx(context.Background(), "r1"); err == nil {
			t.Error("取址方式不认识，RunOnceCtx 应当返回错误")
		}
		if _, err := m.RunOnceCtx(context.Background(), "nope"); err == nil {
			t.Error("规则不存在时应当返回错误")
		}
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("RunOnceCtx 挂住了")
	}
}
