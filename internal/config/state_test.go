package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// stateTestConfig 是一份"旧版本"配置：运行态（lastIP/lastStatus/nextRunAt…）仍存放在 config.json 里。
const stateTestConfig = `{"version":2,"panel":{"listen":"0.0.0.0","port":25666},` +
	`"auth":{"jwtSecret":"deadbeef","username":"admin"},` +
	`"ddns":[{"id":"r1","name":"规则","enabled":true,"lastIP":"1.2.3.4","lastStatus":"已更新","lastUpdateAt":111}],` +
	`"forwards":[{"id":"f1","lastError":"连接被拒绝"}],` +
	`"wolDevices":[{"id":"w1","lastResult":"已发送","lastWakeAt":222}],` +
	`"cronTasks":[{"id":"t1","lastStatus":"成功","lastRunAt":333,"nextRunAt":444}],` +
	`"certs":[{"id":"c1","enabled":true,"status":"valid","notAfter":555,"issueStatus":{"state":"success","message":"issue-success"}}]}`

// newStateTestManager 按给定 config.json（可选 state.json）内容初始化并加载一个 Manager。
func newStateTestManager(t *testing.T, configJSON, stateJSON string) (*Manager, string, string) {
	t.Helper()
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.json")
	statePath := filepath.Join(dir, "state.json")
	if err := os.WriteFile(configPath, []byte(configJSON), 0o600); err != nil {
		t.Fatal(err)
	}
	if stateJSON != "" {
		if err := os.WriteFile(statePath, []byte(stateJSON), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	manager := NewManager(configPath)
	if err := manager.Load(); err != nil {
		t.Fatal(err)
	}
	return manager, configPath, statePath
}

func readState(t *testing.T, path string) *State {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("读取 %s 失败: %v", path, err)
	}
	st := &State{}
	if err := json.Unmarshal(data, st); err != nil {
		t.Fatalf("解析 %s 失败: %v", path, err)
	}
	return st
}

// 首次从旧版本升级：state.json 不存在时，config.json 里已有的运行态必须被迁移过去，
// 且内存中的值不受影响（DDNS 依赖 lastIP 作为"是否首次同步"的基准）。
func TestLoadMigratesRuntimeStateFromLegacyConfig(t *testing.T) {
	manager, _, statePath := newStateTestManager(t, stateTestConfig, "")

	cfg := manager.Get()
	if cfg.DDNS[0].LastIP != "1.2.3.4" || cfg.DDNS[0].LastStatus != "已更新" || cfg.DDNS[0].LastUpdateAt != 111 {
		t.Fatalf("旧配置里的 DDNS 运行态未保留: %#v", cfg.DDNS[0])
	}
	if cfg.CronTasks[0].NextRunAt != 444 || cfg.Certs[0].IssueStatus.State != "success" {
		t.Fatal("旧配置里的计划任务/证书运行态未保留")
	}

	st := readState(t, statePath)
	if st.Version != StateVersion {
		t.Fatalf("state 版本应为 %d，实际 %d", StateVersion, st.Version)
	}
	if st.DDNS["r1"].LastIP != "1.2.3.4" || st.DDNS["r1"].LastUpdateAt != 111 {
		t.Fatalf("DDNS 运行态未迁移到 state.json: %#v", st.DDNS)
	}
	// WOL 不在这一行里：设备上已经没有任何要迁移的运行态了（唤醒记录搬进了内存，
	// 见 internal/runstats）。上面那份配置里仍留着 lastResult / lastWakeAt 两个旧键，
	// 是为了让这个用例走一遍"从旧版本升级上来"的真实路径——它们应该被静默丢掉，
	// 而"丢掉了没有"由 TestNotifyAndWakeStatsNeverReachDisk 按原始字节钉住。
	if st.Forwards["f1"].LastError != "连接被拒绝" ||
		st.Cron["t1"].NextRunAt != 444 || st.Certs["c1"].NotAfter != 555 {
		t.Fatalf("部分模块的运行态未迁移到 state.json: %#v", st)
	}
}

// state.json 是运行态的唯一权威来源：与 config.json 里的残留冲突时以它为准。
func TestLoadPrefersStateFileOverConfigRuntimeFields(t *testing.T) {
	stateJSON := `{"version":1,"ddns":{"r1":{"lastIP":"9.9.9.9","lastStatus":"来自 state","lastUpdateAt":999}}}`
	manager, _, _ := newStateTestManager(t, stateTestConfig, stateJSON)

	cfg := manager.Get()
	if cfg.DDNS[0].LastIP != "9.9.9.9" || cfg.DDNS[0].LastStatus != "来自 state" || cfg.DDNS[0].LastUpdateAt != 999 {
		t.Fatalf("state.json 未覆盖 config.json 的运行态残留: %#v", cfg.DDNS[0])
	}
	// state.json 中没有记录的条目，其运行态必须被清零而不是沿用 config.json 的残留，
	// 否则两个文件会各自持有一半的运行态。
	// 这里挑的是计划任务与证书：设备已经没有可清零的运行态字段了（见上一个用例的说明）。
	if cfg.CronTasks[0].NextRunAt != 0 || cfg.Certs[0].NotAfter != 0 {
		t.Fatal("state.json 未记录的条目运行态应被清零")
	}
}

// 写出 config.json 时必须清零运行态：同一份数据不能同时存在于两个文件。
func TestSaveConfigStripsRuntimeState(t *testing.T) {
	manager, configPath, _ := newStateTestManager(t, stateTestConfig, "")

	if err := manager.Update(func(c *Config) { c.Panel.Port = 30000 }); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, needle := range []string{"1.2.3.4", "已更新", "连接被拒绝", "issue-success"} {
		if strings.Contains(string(raw), needle) {
			t.Fatalf("config.json 仍含运行态 %q", needle)
		}
	}
	var onDisk Config
	if err := json.Unmarshal(raw, &onDisk); err != nil {
		t.Fatal(err)
	}
	if onDisk.DDNS[0].LastUpdateAt != 0 || onDisk.CronTasks[0].NextRunAt != 0 || onDisk.Certs[0].NotAfter != 0 {
		t.Fatal("config.json 的运行态时间戳未清零")
	}
	// 清零只发生在落盘副本上，内存里的运行态必须完好。
	if got := manager.Get().DDNS[0].LastIP; got != "1.2.3.4" {
		t.Fatalf("内存运行态被误清: %q", got)
	}
	if _, err := os.Stat(configPath + ".tmp"); !os.IsNotExist(err) {
		t.Fatalf("临时文件未清理: %v", err)
	}
}

// 面板保存表单走 PUT，会整体替换条目且不携带只读的运行态字段。
// Update 必须把运行态原样贴回，否则一次"改个名字"就会把最近状态抹掉。
func TestUpdatePreservesRuntimeStateAgainstFormOverwrite(t *testing.T) {
	manager, _, _ := newStateTestManager(t, stateTestConfig, "")

	if err := manager.Update(func(c *Config) {
		// 模拟前端提交：只带配置字段，运行态字段为零值。
		c.DDNS[0] = DDNSRule{ID: "r1", Name: "改名后", Enabled: true}
	}); err != nil {
		t.Fatal(err)
	}
	rule := manager.Get().DDNS[0]
	if rule.Name != "改名后" {
		t.Fatalf("配置字段未生效: %q", rule.Name)
	}
	if rule.LastIP != "1.2.3.4" || rule.LastStatus != "已更新" || rule.LastUpdateAt != 111 {
		t.Fatalf("运行态被表单提交抹掉: %#v", rule)
	}
}

// UpdateState 只改内存 + 合并落盘：不得触碰 config.json。
func TestUpdateStateLeavesConfigFileUntouchedAndFlushesToStateFile(t *testing.T) {
	manager, configPath, statePath := newStateTestManager(t, stateTestConfig, "")
	before, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}

	if err := manager.UpdateState(func(c *Config) {
		c.DDNS[0].LastIP = "5.6.7.8"
		c.DDNS[0].LastStatus = "新状态"
	}); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatal("UpdateState 不应改写 config.json")
	}
	if got := manager.Snapshot().DDNS[0].LastIP; got != "5.6.7.8" {
		t.Fatalf("运行态未在内存生效: %q", got)
	}

	// 合并窗口尚未到期，磁盘上仍是迁移时写下的旧值。
	if got := readState(t, statePath).DDNS["r1"].LastIP; got != "1.2.3.4" {
		t.Fatalf("落盘应被延迟合并，磁盘值为 %q", got)
	}
	// Close 等价于"立即刷盘"：退出路径不能丢状态。
	if err := manager.Close(); err != nil {
		t.Fatal(err)
	}
	st := readState(t, statePath)
	if st.DDNS["r1"].LastIP != "5.6.7.8" || st.DDNS["r1"].LastStatus != "新状态" {
		t.Fatalf("Close 未把运行态刷盘: %#v", st.DDNS)
	}
}

// 无变化的运行态回写（DDNS 轮询到相同 IP）不应产生落盘。
func TestUpdateStateSkipsUnchangedRuntimeState(t *testing.T) {
	manager, _, _ := newStateTestManager(t, stateTestConfig, "")
	if err := manager.UpdateState(func(c *Config) { c.DDNS[0].LastIP = "1.2.3.4" }); err != nil {
		t.Fatal(err)
	}
	manager.state.mu.Lock()
	dirty := manager.state.dirty
	manager.state.mu.Unlock()
	if dirty {
		t.Fatal("取值未变化时不应标记落盘")
	}
}

// 条目被删除后，其运行态应在下一次落盘时自然消失（extractState 只遍历当前配置）。
func TestFlushStateDropsRemovedEntries(t *testing.T) {
	manager, _, statePath := newStateTestManager(t, stateTestConfig, "")

	if err := manager.Update(func(c *Config) { c.DDNS = nil }); err != nil {
		t.Fatal(err)
	}
	// 删除条目本身不经过运行态路径，显式标记后刷盘（Replace/退出路径同理）。
	manager.markStateDirty()
	if err := manager.FlushState(); err != nil {
		t.Fatal(err)
	}
	if st := readState(t, statePath); len(st.DDNS) != 0 {
		t.Fatalf("已删除规则的运行态仍在 state.json 中: %#v", st.DDNS)
	}
}

// 导入备份不应带入他机的运行态，也不应清空本机仍在运行的规则状态。
func TestReplaceKeepsLocalRuntimeState(t *testing.T) {
	manager, _, _ := newStateTestManager(t, stateTestConfig, "")

	imported := manager.Get()
	imported.DDNS[0].LastIP = "8.8.8.8"
	imported.DDNS[0].LastStatus = "来自别的机器"
	imported.Panel.BasePath = "/mantou"
	if err := manager.Replace(imported); err != nil {
		t.Fatal(err)
	}
	cfg := manager.Get()
	if cfg.Panel.BasePath != "/mantou" {
		t.Fatalf("导入的配置字段未生效: %q", cfg.Panel.BasePath)
	}
	if cfg.DDNS[0].LastIP != "1.2.3.4" || cfg.DDNS[0].LastStatus != "已更新" {
		t.Fatalf("导入覆盖了本机运行态: %#v", cfg.DDNS[0])
	}
}

// 运行态文件损坏（断电留下半截 JSON）不得阻止启动。
func TestLoadToleratesCorruptStateFile(t *testing.T) {
	manager, _, statePath := newStateTestManager(t, stateTestConfig, `{"version":1,"ddns":{"r1":`)

	// 损坏文件按"不存在"处理：以 config.json 的残留为迁移源重写一份。
	if got := manager.Get().DDNS[0].LastIP; got != "1.2.3.4" {
		t.Fatalf("损坏 state.json 时应回退到 config.json 的运行态，实际 %q", got)
	}
	if got := readState(t, statePath).DDNS["r1"].LastIP; got != "1.2.3.4" {
		t.Fatalf("损坏的 state.json 未被重写: %q", got)
	}
}
