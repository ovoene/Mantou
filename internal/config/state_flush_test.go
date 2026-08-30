package config

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"
	"time"
)

// 本文件锁定运行态落盘的**频率**：谁能让 state.json 变忙，以及谁不该能。
//
// 起因（W-14）是「时间范围」模式的定时唤醒最快 1 秒一拍，每拍推进几个纯展示的计数，
// 脏位于是在整段时间范围内从不熄灭，5 秒的合并窗口退化成「每 5 秒雷打不动写一次盘」——
// 每天 17280 次重写、每次两次 fsync，全为了几个没有任何逻辑会读的数字。
//
// 当时的修法是给这类回写另开一个 60 秒的宽窗口；现在的修法是让它们**根本不落盘**
// （搬进内存，见 internal/runstats）。于是宽窗口连同它的用例一起没了，剩下的用例
// 分两类：
//   - 窗口本身的行为：该落的要落（TestUrgentStateWritesStillFlushInShortWindow）、
//     持续标脏不能把已排定的落盘推后（TestMarkNeverPostponesPendingFlush）。
//   - 边界：展示统计一个字节都不许进磁盘（TestWebhookStatsNeverReachDisk、
//     TestNotifyAndWakeStatsNeverReachDisk）——把字段搬回配置结构体是最省事的
//     "修法"，一旦有人这么做，落盘频率会重新交回给外部，而界面上完全看不出区别。

const (
	// 紧急窗口取 80 毫秒：足够短，让「本该发生的落盘」在用例的等待时间内一定发生；
	// 又足够长，不至于因 Windows 上的定时器精度而在标记之前就触发。
	testUrgentWindow = 80 * time.Millisecond
	// 轮询等待的上限。正常情况下 80 毫秒的窗口早就到期了，给到 5 秒纯粹是为了 CI 上的极端卡顿。
	testFlushWait = 5 * time.Second
)

// newFlushTestManager 建一个把落盘窗口换成测试值的 Manager。window 为 0 时用生产常量。
func newFlushTestManager(t *testing.T, window time.Duration) (*Manager, string) {
	t.Helper()
	manager, _, statePath := newStateTestManager(t, stateTestConfig, "")
	// Load 只做迁移写出，不经过标脏路径，所以此刻还没有排定任何定时器，改窗口是安全的。
	manager.state.mu.Lock()
	manager.state.windowOverride = window
	manager.state.mu.Unlock()
	// 停掉可能挂着的定时器：否则用例结束后它仍会触发，往已被删除的临时目录里写盘。
	t.Cleanup(func() { _ = manager.Close() })
	return manager, statePath
}

// tryReadState 读取 state.json，任何失败都返回 nil。
// 不用 readState 是因为轮询会撞上落盘过程中的原子替换（Windows 上表现为共享冲突），
// 那不是失败，只是"这一次没读到"。
func tryReadState(path string) *State {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	st := &State{}
	if err := json.Unmarshal(data, st); err != nil {
		return nil
	}
	return st
}

// waitForState 轮询等待磁盘上的运行态满足 want；超时返回 false。
//
// 轮询用 os.Stat（不开文件句柄）判断"是否又写过一次"，只在它变化后才真正读一次文件。
// 别改回"每几毫秒 ReadFile 一遍"：Windows 上打开的读句柄会让紧随其后的 os.Rename
// 报 Access is denied（writeFileAtomic 的替换动作被我们自己的轮询挡掉），
// 于是落盘失败、脏位被退回，用例反而等不到那次写入。产品侧不受影响——
// state.json 只在启动时读一次（loadStateLocked），运行期面板读的是内存。
func waitForState(path string, want func(*State) bool, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	var lastWrite time.Time
	for {
		if fi, err := os.Stat(path); err == nil && fi.ModTime() != lastWrite {
			lastWrite = fi.ModTime()
			// 让这一次替换彻底完成再读，缩短读句柄存在的时间窗。
			time.Sleep(20 * time.Millisecond)
			if st := tryReadState(path); st != nil && want(st) {
				return true
			}
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// hookFlushTestConfig 与 stateTestConfig 同构，另带一个消息路由接收器。
// 单开一份而不是往 stateTestConfig 里加：那个常量被本包多个用例按"有哪几段运行态"断言，
// 加一段会牵动无关的用例。
//
// 接收器上刻意保留 lastStatus / lastReceivedAt 这两个旧键——它们已经不在结构体里了，
// 留着是为了给下面的用例一个真实的"从旧版本升级上来"的起点。
const hookFlushTestConfig = `{"version":2,"panel":{"listen":"0.0.0.0","port":25666},` +
	`"auth":{"jwtSecret":"deadbeef","username":"admin"},` +
	`"ddns":[{"id":"r1","name":"规则","enabled":true,"lastIP":"1.2.3.4","lastStatus":"已更新","lastUpdateAt":111}],` +
	`"webhookReceivers":[{"id":"h1","name":"接收器","enabled":true,"path":"hook","lastStatus":"已接收","lastReceivedAt":222}]}`

// 接收器的统计一个字节都不该进磁盘（A7）。
//
// 这里原先钉的是「入站回写必须合并到宽窗口」。那条路已经不存在了：合并只是把写盘
// 摊薄，频率仍然由公网决定——外面推得越猛，磁盘就越忙，而写的全是没有任何逻辑读的
// 展示数字。现在这三个数搬进了内存（internal/runstats），重启归零。
//
// 换过来之后要钉的就是这件事本身，而且比原来那条更该钉：把字段搬回配置结构体是最省事的
// "修法"，一旦有人这么做，落盘频率会重新交回给公网，而界面上完全看不出区别。
// 断言直接读 state.json 的原始字节而不是解析成 State——因为 State 里已经没有对应字段了，
// 解析会把多出来的键悄悄丢掉，那样这个用例就永远是绿的。
func TestWebhookStatsNeverReachDisk(t *testing.T) {
	manager, configPath, statePath := newStateTestManager(t, hookFlushTestConfig, "")
	t.Cleanup(func() { _ = manager.Close() })

	// state.json 是刚从 config.json 迁移出来的。旧配置里带着 lastStatus / lastReceivedAt，
	// 迁移不该把它们抄过去。
	assertNoDisplayStats(t, statePath, "迁移出来的 state.json")

	// 触发一次配置写盘：旧 config.json 里残留的那两个键也不该被写回来。
	if err := manager.Update(func(c *Config) { c.WebhookReceivers[0].Name = "改个名字" }); err != nil {
		t.Fatal(err)
	}
	assertNoDisplayStats(t, configPath, "重写后的 config.json")

	// 退出路径会把攒下的运行态一次写出（DDNS 那份）；接收器统计仍然不该出现。
	if err := manager.Close(); err != nil {
		t.Fatal(err)
	}
	assertNoDisplayStats(t, statePath, "Close 之后的 state.json")
}

// statsFlushTestConfig 与 hookFlushTestConfig 同构，接收器换成通知目标与唤醒设备，
// 两者都带着旧版本的统计键。
const statsFlushTestConfig = `{"version":2,"panel":{"listen":"0.0.0.0","port":25666},` +
	`"auth":{"jwtSecret":"deadbeef","username":"admin"},` +
	`"ddns":[{"id":"r1","name":"规则","enabled":true,"lastIP":"1.2.3.4","lastStatus":"已更新","lastUpdateAt":111}],` +
	`"notifyTargets":[{"id":"t1","name":"目标","enabled":true,"type":"dingtalk",` +
	`"url":"https://example.com/hook","lastStatus":"已发送","lastSentAt":333,"sentCount":7,"failCount":2}],` +
	`"wolDevices":[{"id":"w1","name":"设备","mac":"AA:BB:CC:DD:EE:FF","port":9,` +
	`"lastResult":"已发送","lastWakeAt":444,"wakeCount":9}]}`

// 通知目标与唤醒设备的统计同样一个字节都不该进磁盘（A7 第二批）。
//
// 与接收器那条是同一个性质，但频率来源各不相同，所以分开钉：通知目标由**投递量**决定
// （一条入站消息扇出到 N 个目标就是 N 次），唤醒设备由**用户配的拍频**决定
// （「时间范围」模式最快 1 秒一拍、每台设备各一条协程）。三者的共同点是频率不由本程序
// 决定，而写的东西全项目只有列表页在看。
func TestNotifyAndWakeStatsNeverReachDisk(t *testing.T) {
	manager, configPath, statePath := newStateTestManager(t, statsFlushTestConfig, "")
	t.Cleanup(func() { _ = manager.Close() })

	assertNoDisplayStats(t, statePath, "迁移出来的 state.json")

	// 触发一次配置写盘：旧 config.json 里残留的那几个键不该被写回来。
	if err := manager.Update(func(c *Config) {
		c.NotifyTargets[0].Name = "改个名字"
		c.WOLDevices[0].Name = "也改个名字"
	}); err != nil {
		t.Fatal(err)
	}
	assertNoDisplayStats(t, configPath, "重写后的 config.json")

	// 退出路径写出整份运行态（DDNS 那段）；这几个数仍然不该出现。
	if err := manager.Close(); err != nil {
		t.Fatal(err)
	}
	assertNoDisplayStats(t, statePath, "Close 之后的 state.json")
}

// assertNoDisplayStats 检查文件里不含任何"只给列表页看"的统计字段。
//
// 一份清单管三个模块，而不是每个模块各写一份断言：这些字段的共同点不是"属于哪个模块"，
// 是"没有任何逻辑读它、却由外部决定写入频率"。将来再多一个这样的数，加进这个清单即可。
//
// 刻意**不**包含 lastStatus：DDNS 与证书的状态文本是合法的运行态（面板要显示上次结果，
// 而它由本程序自己的定时器决定频率），把它列进来会让这个用例在正确的行为上失败。
func assertNoDisplayStats(t *testing.T, path, what string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("读取 %s 失败: %v", path, err)
	}
	keys := []string{
		// 接收器
		"lastReceivedAt", "receivedCount", "rejectedCount",
		// 通知目标
		"lastSentAt", "sentCount", "failCount",
		// 唤醒设备
		"lastWakeAt", "wakeCount", "lastResult",
	}
	for _, k := range keys {
		if bytes.Contains(data, []byte(`"`+k+`"`)) {
			t.Fatalf("%s 里出现了列表页统计字段 %q：这些数只该待在内存里（internal/runstats），"+
				"落盘会让写盘频率重新由外部决定。文件内容：%s", what, k, data)
		}
	}
}

// 功能性运行态的落盘时效不受影响：仍按窗口（此处为测试窗口）落盘。
// 展示统计不落盘了，不能顺手把 DDNS 的 lastIP 一起拖慢——那个字段是"本轮是否需要
// 推送解析"的判断基准，丢了会多打一次上游 API。
func TestUrgentStateWritesStillFlushInShortWindow(t *testing.T) {
	manager, statePath := newFlushTestManager(t, testUrgentWindow)

	if err := manager.UpdateState(func(c *Config) {
		c.DDNS[0].LastIP = "5.6.7.8"
		c.DDNS[0].LastStatus = "已更新（新）"
	}); err != nil {
		t.Fatal(err)
	}
	if !waitForState(statePath, func(st *State) bool {
		return st.DDNS["r1"].LastIP == "5.6.7.8"
	}, testFlushWait) {
		t.Fatalf("DDNS 运行态在 %v 内未落盘：窗口被破坏了", testFlushWait)
	}
}

// 持续的标脏不得把已排定的落盘往后推。
//
// 守的是 markStateDirty 里「已有排定就复用、不重排」那一句。改成每次都 Reset 看着更
// 直观，代价是一个每秒标一次脏的调用方能让落盘无限期推迟：脏位一直在、盘一直不写，
// 而这类调用方（证书检查、计划任务、转发统计）本来就是成串到达的。
//
// 断言的形状很关键：**落盘必须发生在标脏还在继续的时候**。
// 这条用例的第一版是「标脏 300 毫秒，然后等最多 5 秒看盘落没落」——那个形状抓不住
// 上面说的错误：改成每次 Reset 之后，落盘只是从「第一次标脏 + 一个窗口」挪到
// 「最后一次标脏 + 一个窗口」，仍然远在 5 秒之内，用例照样绿。
// 现在窗口取 200 毫秒而标脏持续 2 秒：正确实现在第 200 毫秒左右就落一次盘（此时循环
// 还在跑），推后实现要到第 2.2 秒才落（循环已经结束）。两者相差十倍，不吃定时器精度。
func TestMarkNeverPostponesPendingFlush(t *testing.T) {
	const (
		window  = 200 * time.Millisecond
		marking = 2 * time.Second
	)
	manager, statePath := newFlushTestManager(t, window)

	// 第一次变更排定了一次落盘。
	if err := manager.UpdateState(func(c *Config) { c.DDNS[0].LastIP = "5.6.7.8" }); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	deadline := start.Add(marking)
	// 轮询只看 os.Stat 的修改时刻，不开文件句柄——原因见 waitForState 的说明。
	// 基准取自迁移时写下的那一份，之后任何一次变化都只可能来自落盘协程。
	var baseline time.Time
	if fi, err := os.Stat(statePath); err == nil {
		baseline = fi.ModTime()
	}
	flushedAt := time.Duration(-1)
	for i := 1; time.Now().Before(deadline); i++ {
		if err := manager.UpdateState(func(c *Config) {
			c.DDNS[0].LastUpdateAt = int64(2000 + i)
		}); err != nil {
			t.Fatal(err)
		}
		if flushedAt < 0 {
			if fi, err := os.Stat(statePath); err == nil && fi.ModTime() != baseline {
				flushedAt = time.Since(start)
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	if flushedAt < 0 {
		t.Fatalf("连续标脏 %v（落盘窗口 %v）期间一次盘都没落：每次标脏都把已排定的落盘推后了，"+
			"于是脏位一直在、盘一直不写", marking, window)
	}
	t.Logf("窗口 %v：第一次落盘发生在第 %v，此时标脏循环还在跑（共 %v）",
		window, flushedAt.Round(time.Millisecond), marking)

	// 落的那一盘必须真的是新值，否则上面数到的可能是别的写入。
	if !waitForState(statePath, func(st *State) bool {
		return st.DDNS["r1"].LastIP == "5.6.7.8"
	}, testFlushWait) {
		t.Fatalf("盘写过了，但里面不是新值（等了 %v）", testFlushWait)
	}
}

// TestStateFlushRateWithProductionWindow 用**生产常量**量一遍最坏情况下的落盘频率，
// 给报告里的「每天 17280 次」一个可复现的依据。跑一次约 12 秒，故默认跳过：
//
//	MANTOU_MEASURE_FLUSH=1 go test ./internal/config -run TestStateFlushRateWithProductionWindow -v
//
// 这里原先是两行对比（通用窗口 vs 60 秒宽窗口）。宽窗口没了，对比也就没了——
// 现在的重点不是"哪个窗口更省"，是"还有没有调用方能让脏位一直不熄灭"：
// 这个用例手动扮演那样一个调用方，量出的次数就是理论上限。真实调用方（DDNS 按规则
// 间隔、证书按天、计划任务按表达式）都远达不到每秒一次，所以实测频率会远低于它。
func TestStateFlushRateWithProductionWindow(t *testing.T) {
	if os.Getenv("MANTOU_MEASURE_FLUSH") == "" {
		t.Skip("落盘频率测量（约 12 秒），需 MANTOU_MEASURE_FLUSH=1 开启")
	}
	const tick = time.Second // 最坏情况：每秒一次功能性运行态变更
	window := stateFlushInterval
	observe := 2*window + 2*time.Second

	manager, statePath := newFlushTestManager(t, 0) // 0 = 用生产常量
	stop := make(chan struct{})
	writes := make(chan int, 1)
	// 用 os.Stat 数写入次数：不开文件句柄，不会挡住 writeFileAtomic 的原子替换。
	go func() {
		count, last := 0, time.Time{}
		if fi, err := os.Stat(statePath); err == nil {
			last = fi.ModTime()
		}
		for {
			select {
			case <-stop:
				writes <- count
				return
			default:
			}
			if fi, err := os.Stat(statePath); err == nil && fi.ModTime().After(last) {
				last = fi.ModTime()
				count++
			}
			time.Sleep(20 * time.Millisecond)
		}
	}()

	deadline := time.Now().Add(observe)
	for i := 1; time.Now().Before(deadline); i++ {
		if err := manager.UpdateState(func(c *Config) { c.DDNS[0].LastUpdateAt = int64(3000 + i) }); err != nil {
			t.Fatal(err)
		}
		time.Sleep(tick)
	}
	close(stop)
	n := <-writes
	// 稳态频率按窗口算，而不是拿这段观测去外推：脏位若从不熄灭，每个窗口恰好落盘一次，
	// 每天的次数就是 86400/窗口秒数。
	t.Logf("生产窗口 %v：%v 内实测落盘 %d 次；若有调用方每秒标一次脏，稳态为每天 %.0f 次，每次两次 fsync",
		window, observe, n, 86400/window.Seconds())
	if err := manager.Close(); err != nil {
		t.Fatal(err)
	}
}
