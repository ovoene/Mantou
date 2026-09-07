package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// 本文件盯的是 F-05 的前半段：临时文件名不能是固定的 `<文件名>.tmp`。
//
// 固定名字下，两个写入方开的是**同一个**文件：A 刚把几 KB 写进去，B 用 O_TRUNC 把它截成 0
// 再写自己的，A 接着 fsync 并 rename——rename 出去的是两份内容的混合物；更常见的是
// B 的 rename 落在 A 之后，源文件已经被 A 搬走，于是 B 那次保存直接报错。
// 进程内的 sync.RWMutex 挡不住这一条：它只在一个 Manager 里有效，而同一个数据目录
// 可以被第二个 Manager（或第二个进程）打开。
//
// 两条断言分工：下面第一条钉住"名字每次都不同、且仍以 .tmp 结尾"，
// 第二条用真实的并发保存把"不会互相截断 / 抢 rename"跑出来。

// tempLeftovers 列出目录里剩下的 *.tmp。
func tempLeftovers(t *testing.T, dir string) []string {
	t.Helper()
	matches, err := filepath.Glob(filepath.Join(dir, "*.tmp"))
	if err != nil {
		t.Fatal(err)
	}
	out := make([]string, 0, len(matches))
	for _, m := range matches {
		out = append(out, filepath.Base(m))
	}
	return out
}

// pickTempFor 从 fsync 记录里挑出属于 base 的那个临时文件路径。
func pickTempFor(t *testing.T, synced []string, base string) string {
	t.Helper()
	var found []string
	for _, p := range synced {
		name := filepath.Base(p)
		if strings.HasPrefix(name, base+".") && strings.HasSuffix(name, ".tmp") {
			found = append(found, p)
		}
	}
	if len(found) != 1 {
		t.Fatalf("期望 %s 恰好有一个临时文件被 fsync，实际 %v（全部记录 %v）", base, found, synced)
	}
	return found[0]
}

// TestAtomicWriteUsesUniqueTempName 每次保存都用一个新的临时文件名，且后缀仍是 .tmp。
//
// 后缀那一条同样重要：/api/storage 靠它把断电留下的残留列成"可清理"
// （见 server.storageLeftoverKind）。换个后缀不会有任何症状，只是那条清理路径从此瞎了。
func TestAtomicWriteUsesUniqueTempName(t *testing.T) {
	var synced []string
	onFsync = func(path string) { synced = append(synced, path) }
	t.Cleanup(func() { onFsync = nil })

	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	manager := NewManager(path)
	if err := manager.Load(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = manager.Close() })

	synced = nil
	if err := manager.Update(func(c *Config) { c.Panel.Port = 25701 }); err != nil {
		t.Fatal(err)
	}
	first := pickTempFor(t, synced, "config.json")

	synced = nil
	if err := manager.Update(func(c *Config) { c.Panel.Port = 25702 }); err != nil {
		t.Fatal(err)
	}
	second := pickTempFor(t, synced, "config.json")

	if first == second {
		t.Fatalf("两次保存用了同一个临时文件 %q：两个写入方会互相截断（见本文件顶部）", first)
	}
	if first == path+".tmp" || second == path+".tmp" {
		t.Fatalf("临时文件名仍是固定的 <文件名>.tmp：%q / %q", first, second)
	}
	for _, p := range []string{first, second} {
		name := filepath.Base(p)
		if !strings.HasSuffix(name, ".tmp") {
			t.Fatalf("临时文件 %q 不以 .tmp 结尾：/api/storage 再也认不出断电留下的残留", name)
		}
		if !strings.HasPrefix(name, "config.json.") {
			t.Fatalf("临时文件 %q 看不出属于哪个目标文件", name)
		}
	}
	// 成功的写入不留残留。
	if left := tempLeftovers(t, dir); len(left) > 0 {
		t.Fatalf("保存成功后仍留着临时文件 %v", left)
	}
}

// TestConcurrentManagersDoNotCorruptConfig 两个 Manager 同时保存，落盘的必须仍是一份
// 完整的配置，且每一次保存都要成功。
//
// 这里刻意不管"谁的改动最后留下"——那是丢更新，只有单实例锁（internal/lockfile）能管，
// 不是原子写的职责。这条只管一件事：不许出现半份配置，也不许有哪次保存因为撞车而失败。
//
// 用两个 Manager 而不是两个进程，是因为审计里那句话就是这么说的：单进程的 sync.RWMutex
// 拦不住第二个 Manager。这也让这条测试在两个平台上都能跑，不必编辅助二进制。
func TestConcurrentManagersDoNotCorruptConfig(t *testing.T) {
	const writers, rounds = 4, 25

	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	managers := make([]*Manager, writers)
	for i := range managers {
		m := NewManager(path)
		if err := m.Load(); err != nil {
			t.Fatal(err)
		}
		managers[i] = m
	}

	var wg sync.WaitGroup
	errs := make(chan error, writers*rounds)
	for i, m := range managers {
		wg.Add(1)
		go func(i int, m *Manager) {
			defer wg.Done()
			for r := 0; r < rounds; r++ {
				port := 25700 + i*100 + r
				if err := m.Update(func(c *Config) { c.Panel.Port = port }); err != nil {
					errs <- fmt.Errorf("第 %d 个 Manager 第 %d 轮保存失败: %w", i, r, err)
					return
				}
			}
		}(i, m)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	for i, m := range managers {
		if err := m.Close(); err != nil {
			t.Errorf("第 %d 个 Manager 关闭失败: %v", i, err)
		}
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("配置文件不见了: %v", err)
	}
	var got Config
	if err := json.Unmarshal(raw, &got); err != nil {
		head := raw
		if len(head) > 120 {
			head = head[:120]
		}
		t.Fatalf("并发保存后配置解不开（%v），共 %d 字节，开头是 %q", err, len(raw), head)
	}
	if got.Panel.Port == 0 {
		t.Fatalf("落盘的配置像是被截断过：面板端口是 0（共 %d 字节）", len(raw))
	}
	if left := tempLeftovers(t, dir); len(left) > 0 {
		t.Fatalf("并发保存后留下了临时文件 %v", left)
	}
}
