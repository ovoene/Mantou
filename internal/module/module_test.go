package module

import (
	"errors"
	"sync"
	"testing"

	"mantou/internal/config"
	"mantou/internal/logx"
)

// fakeModule 记录每次 Reload 收到的配置指针，并可按需让第 N 次 Reload 失败。
type fakeModule struct {
	name string
	mu   sync.Mutex
	// failOn 为 true 时 Reload 返回错误（回滚调用不受影响：回滚前会被置回 false）。
	failOn bool
	got    []*config.Config
	closes int
}

func (f *fakeModule) Name() string { return f.name }

func (f *fakeModule) Reload(cfg *config.Config) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.got = append(f.got, cfg)
	if f.failOn {
		f.failOn = false // 只失败一次，后续（含回滚）正常
		return errors.New("boom")
	}
	return nil
}

func (f *fakeModule) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closes++
	return nil
}

func (f *fakeModule) history() []*config.Config {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]*config.Config(nil), f.got...)
}

// TestReloadAllRollsBackFailedModule 模块重载失败后应被回滚到上一份成功配置，
// 且不影响其后模块应用新配置。
func TestReloadAllRollsBackFailedModule(t *testing.T) {
	log := logx.New(logx.Options{Levels: []string{"error"}})
	mgr := NewManager(log)
	a := &fakeModule{name: "a"}
	bad := &fakeModule{name: "bad"}
	c := &fakeModule{name: "c"}
	mgr.Register(a)
	mgr.Register(bad)
	mgr.Register(c)

	good := &config.Config{}
	mgr.ReloadAll(good)

	next := &config.Config{}
	bad.failOn = true
	mgr.ReloadAll(next)

	// 失败模块：第一次 good、第二次 next（失败）、第三次回滚到 good。
	h := bad.history()
	if len(h) != 3 {
		t.Fatalf("失败模块应被回滚一次，实际调用 %d 次", len(h))
	}
	if h[2] != good {
		t.Fatalf("回滚未使用上一份成功配置")
	}
	// 其余模块不受影响，正常拿到新配置。
	for _, mod := range []*fakeModule{a, c} {
		h := mod.history()
		if len(h) != 2 || h[1] != next {
			t.Fatalf("模块 %s 未应用新配置: %d 次调用", mod.name, len(h))
		}
	}
}

// TestReloadAllFirstFailureKeepsNoBaseline 首次重载即失败时没有可回滚的基线，不应重复调用。
func TestReloadAllFirstFailureKeepsNoBaseline(t *testing.T) {
	mgr := NewManager(logx.New(logx.Options{Levels: []string{"error"}}))
	bad := &fakeModule{name: "bad", failOn: true}
	mgr.Register(bad)
	mgr.ReloadAll(&config.Config{})
	if got := len(bad.history()); got != 1 {
		t.Fatalf("首次失败不应触发回滚，实际调用 %d 次", got)
	}
}

// TestCloseAllIdempotent CloseAll 可重复调用；关闭后的 ReloadAll 不再触达模块。
// 这条正是自更新失败路径（显式 CloseAll + defer CloseAll）会走到的场景。
func TestCloseAllIdempotent(t *testing.T) {
	mgr := NewManager(logx.New(logx.Options{Levels: []string{"error"}}))
	a := &fakeModule{name: "a"}
	mgr.Register(a)

	mgr.CloseAll()
	mgr.CloseAll()
	a.mu.Lock()
	closes := a.closes
	a.mu.Unlock()
	if closes != 1 {
		t.Fatalf("Close 应只被调用一次，实际 %d 次", closes)
	}

	mgr.ReloadAll(&config.Config{})
	if got := len(a.history()); got != 0 {
		t.Fatalf("关闭后不应再重载模块，实际调用 %d 次", got)
	}
}
