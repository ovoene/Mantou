package module

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"mantou/internal/config"
	"mantou/internal/logx"
)

// blockingModule 第一次 Reload 停在 gate 上，模拟"一次慢重载正在进行"。
type blockingModule struct {
	name    string
	gate    chan struct{}
	entered chan struct{}
	once    sync.Once
	mu      sync.Mutex
	got     []*config.Config
}

func (b *blockingModule) Name() string { return b.name }

func (b *blockingModule) Reload(cfg *config.Config) error {
	b.mu.Lock()
	b.got = append(b.got, cfg)
	b.mu.Unlock()
	first := false
	b.once.Do(func() { first = true })
	if first {
		close(b.entered)
		<-b.gate
	}
	return nil
}

func (b *blockingModule) Close() error { return nil }

func (b *blockingModule) last() *config.Config {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.got[len(b.got)-1]
}

// TestReloadLatestReadsConfigInsideLock 排在一次慢重载后面的那次，重载时用的必须是
// **轮到它时**的最新配置，而不是它排队之前取到的那份。
//
// 原先接口层是"先取配置、再调 ReloadAll 排队"：两次并发的保存若以相反顺序拿到锁，
// 带着旧配置的那次会在最后把模块改回去——磁盘上是新配置，模块跑的却是旧的。
func TestReloadLatestReadsConfigInsideLock(t *testing.T) {
	mgr := NewManager(logx.New(logx.Options{Levels: []string{"error"}}))
	mod := &blockingModule{name: "m", gate: make(chan struct{}), entered: make(chan struct{})}
	mgr.Register(mod)

	v1, v2, v3 := &config.Config{Version: 1}, &config.Config{Version: 2}, &config.Config{Version: 3}
	var current atomic.Pointer[config.Config]
	current.Store(v1)
	get := func() *config.Config { return current.Load() }

	// 第一次重载拿到 v1，停在模块里。
	done1 := make(chan struct{})
	go func() { mgr.ReloadLatest(get); close(done1) }()
	<-mod.entered

	// 此时配置变成 v2，第二次重载开始排队；随后又变成 v3（第三次保存落盘，但它的重载还没来）。
	current.Store(v2)
	done2 := make(chan struct{})
	go func() { mgr.ReloadLatest(get); close(done2) }()
	time.Sleep(20 * time.Millisecond) // 让第二次先排上队
	current.Store(v3)

	close(mod.gate)
	<-done1
	<-done2

	if got := mod.last(); got != v3 {
		t.Fatalf("排队的那次重载用的是 version=%d 的配置，期望轮到它时的最新配置 version=3", got.Version)
	}
}

// TestReloadLatestNilConfigSkips 取不到配置（nil）时不重载：模块继续跑上一份已知良好的配置。
func TestReloadLatestNilConfigSkips(t *testing.T) {
	mgr := NewManager(logx.New(logx.Options{Levels: []string{"error"}}))
	mod := &fakeModule{name: "m"}
	mgr.Register(mod)
	mgr.ReloadLatest(func() *config.Config { return nil })
	if n := len(mod.history()); n != 0 {
		t.Fatalf("配置为 nil 时不该重载，实际重载了 %d 次", n)
	}
}
