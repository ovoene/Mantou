package config

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// 本文件锁定运行态落盘的**单次成本**（频率由 state_flush_test.go 负责）。
//
// 三条性质，都是「按数据价值定价」这一决定的直接后果，且都容易在后续重构里被无声推翻：
//  1. config.json / master.key 仍然 fsync，state.json 不再 fsync；
//  2. state.json 是紧凑 JSON（无缩进），config.json 仍带缩进；
//  3. 脏位置上但序列化结果未变时，不写盘。

// 落盘策略必须按文件区分：配置与主密钥丢了要人工恢复，运行态丢了下个周期就重新写上来。
//
// 反向也要守住：不能"顺手"把 config.json 的 fsync 一起去掉。它是全部配置的唯一副本，
// 断电后拿到一个长度为 0 的 config.json 等于实例被清空（原因见 writeFileAtomic 的说明）。
func TestFsyncPolicyPerFile(t *testing.T) {
	var synced []string
	onFsync = func(path string) { synced = append(synced, path) }
	t.Cleanup(func() { onFsync = nil })

	manager, configPath, statePath := newStateTestManager(t, stateTestConfig, "")
	t.Cleanup(func() { _ = manager.Close() })

	// 配置写入：config.json 与 master.key（首次落盘时生成）都必须出现在 fsync 列表里。
	synced = nil
	if err := manager.Update(func(c *Config) { c.Panel.Port = 25667 }); err != nil {
		t.Fatal(err)
	}
	if !syncedAny(synced, filepath.Base(configPath)) {
		t.Fatalf("config.json 落盘时没有 fsync（实际同步过的路径 %v）："+
			"断电后可能留下长度为 0 的配置文件，等于丢掉全部配置", synced)
	}
	if !syncedAny(synced, masterKeyName) {
		t.Fatalf("master.key 落盘时没有 fsync（实际同步过的路径 %v）："+
			"它是解开配置中凭证字段的唯一钥匙", synced)
	}

	// 运行态写入：state.json 一次 fsync 都不该有。
	synced = nil
	if err := manager.UpdateState(func(c *Config) { c.DDNS[0].LastIP = "9.9.9.9" }); err != nil {
		t.Fatal(err)
	}
	if err := manager.FlushState(); err != nil {
		t.Fatal(err)
	}
	if syncedAny(synced, filepath.Base(statePath)) {
		t.Fatalf("state.json 落盘时仍在 fsync（实际同步过的路径 %v）："+
			"运行态是可丢数据，而它是本项目写入最频繁的文件——"+
			"一台每秒一拍的唤醒设备每天 1440 次落盘，在 SD 卡上是纯粹的寿命消耗", synced)
	}
	// 且内容确实写出去了：跳过 fsync 不等于跳过写入。
	if got := readState(t, statePath).DDNS["r1"].LastIP; got != "9.9.9.9" {
		t.Fatalf("state.json 未写出运行态: lastIP=%q", got)
	}
}

// syncedAny 判断 fsync 过的路径里是否有名字含 name 的。
func syncedAny(synced []string, name string) bool {
	for _, p := range synced {
		if strings.Contains(filepath.Base(p), name) {
			return true
		}
	}
	return false
}

// state.json 用紧凑 JSON，config.json 保持缩进。
//
// 这不是风格偏好：state.json 只在启动时被读一次，缩进纯属为最频繁的写入路径增加字节；
// 而 config.json 是设计上要给人看、必要时手工修的（见 secret.go 顶部对"值级而非整文件加密"
// 的说明），把它压成一行会把那条排障路径堵死。
func TestStateCompactConfigIndented(t *testing.T) {
	manager, configPath, statePath := newStateTestManager(t, stateTestConfig, "")
	t.Cleanup(func() { _ = manager.Close() })

	if err := manager.UpdateState(func(c *Config) { c.DDNS[0].LastIP = "9.9.9.9" }); err != nil {
		t.Fatal(err)
	}
	if err := manager.FlushState(); err != nil {
		t.Fatal(err)
	}
	stateRaw, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(stateRaw, []byte("\n")) {
		t.Fatalf("state.json 仍是缩进格式（含换行）：缩进对纯机器文件没有价值，"+
			"却给本项目写入最频繁的文件增加字节。内容:\n%s", stateRaw)
	}

	if err := manager.Update(func(c *Config) { c.Panel.Port = 25667 }); err != nil {
		t.Fatal(err)
	}
	configRaw, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(configRaw, []byte("\n  ")) {
		t.Fatal("config.json 丢掉了缩进：它是设计上要给人看、必要时手工修的文件")
	}
}

// 脏位置上、但序列化结果与磁盘上完全一致时不得写盘。
//
// 脏位的含义是"有人动过运行态"，不是"动出来的结果与磁盘不同"。二者会分叉：
// 状态文本被 TruncateStatus 截成同一个值、计数增减后回到原值、把字段设成它本来就有的值。
// 这类落盘是纯写放大。
//
// 用「删掉文件看它是否被重建」而不是比对 mtime：mtime 在部分文件系统上的粒度是秒级，
// 用它判断"这一次到底写没写"会得到假阴性。
// 附带说明一个可接受的后果：若有人在运行期把 state.json 删掉，程序不会立刻重建它，
// 要等下一次运行态真正变化。无妨——这个文件只在启动时读一次。
func TestFlushSkipsUnchangedState(t *testing.T) {
	manager, _, statePath := newStateTestManager(t, stateTestConfig, "")
	t.Cleanup(func() { _ = manager.Close() })

	// 先做一次真实变更并落盘，让 lastWritten 记上账。
	if err := manager.UpdateState(func(c *Config) { c.DDNS[0].LastIP = "9.9.9.9" }); err != nil {
		t.Fatal(err)
	}
	if err := manager.FlushState(); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(statePath); err != nil {
		t.Fatal(err)
	}

	// 只置脏位，不改任何内容：这一次落盘应当被跳过。
	// 直接调 markStateDirty 是因为 UpdateState 自己就有脏检查（configEqual），
	// 走它无法制造"脏位置上但内容没变"的处境。
	manager.markStateDirty()
	if err := manager.FlushState(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(statePath); err == nil {
		t.Fatal("运行态内容未变化却仍然写盘了：脏位与'内容确实不同'被当成了一回事")
	}

	// 反面：内容真变了就必须写。跳过的判据只能是内容，不能是别的。
	if err := manager.UpdateState(func(c *Config) { c.DDNS[0].LastIP = "8.8.8.8" }); err != nil {
		t.Fatal(err)
	}
	if err := manager.FlushState(); err != nil {
		t.Fatal(err)
	}
	if got := readState(t, statePath).DDNS["r1"].LastIP; got != "8.8.8.8" {
		t.Fatalf("运行态确有变化时未正确落盘: lastIP=%q", got)
	}
}
