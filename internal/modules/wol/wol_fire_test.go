package wol

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"mantou/internal/config"
	"mantou/internal/logx"
)

// 本文件补齐报告第八节点出的最后一处覆盖缺口：**一拍之内**的行为。
//
// 已有用例（wol_lifecycle_test.go 等）覆盖的是「调度层」——什么时候该起一拍、
// 取消之后不许再起一拍。而一拍内部的契约从未被验证过：
//   - 连发 N 个包只回写一次统计（回写频率是 W-3/W-14 两处修复的落点，必须钉住）；
//   - 计数按「拍」而不是按「包」增长；
//   - N 个包均匀铺在 1 秒内，而不是背靠背瞬时打出；
//   - 途中被取消要提前收尾，但已经发生的事实照样落账；
//   - 设备在这一拍执行期间被删掉时，回写不得牵连到别的设备。
//
// 与其他 WOL 用例的关键差别：这里在回环地址上开一个真的 UDP 端口收包，
// 断言的是**到达对端 socket 的字节**，而不是「WakeDevice 没报错」。
// 顺带填掉报告第九节自陈的一条局限——魔术包的线上字节此前从未做过端到端验证。
//
// 另外三条用例分别守 W-13 的日志量、runPlanDay 的兜底夹取，
// 以及 W-10 的「跨零点退化必须说出来」（TestRunPlanDayLogsPerRunNotPerTick /
// TestRunPlanDayGuardsZeroInterval / TestRunScheduleWarnsOnDegradedRange）。

// udpSink 在回环地址上监听 UDP，返回端口号、已收包计数、以及第一个包的内容。
//
// 之所以能这样数包：Broadcast 填具体地址时 Wake 走的是「内核按目的地选路」那条分支，
// 每次 WakeDevice 恰好一个 datagram（iface 为空时 srcForIface 返回 nil，不绑源地址），
// 不会像自动模式那样一张网卡发两个包。
func udpSink(t *testing.T) (port int, got *atomic.Int64, first chan []byte) {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("回环 UDP 端口监听失败: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	got = &atomic.Int64{}
	first = make(chan []byte, 1)
	go func() {
		buf := make([]byte, 2048)
		for {
			n, _, err := conn.ReadFromUDP(buf)
			if err != nil {
				return // 端口已关闭：用例结束
			}
			select {
			case first <- append([]byte(nil), buf[:n]...):
			default:
			}
			got.Add(1)
		}
	}()
	return conn.LocalAddr().(*net.UDPAddr).Port, got, first
}

// waitPackets 等待 sink 收够 want 个包。UDP 无序无回执，发出与收到之间有一小段延迟，
// 直接读计数会偶发少一个。
func waitPackets(t *testing.T, got *atomic.Int64, want int64, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		if n := got.Load(); n >= want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("回环端口只收到 %d 个魔术包，应为 %d 个", got.Load(), want)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// 这里原先还有一个 stateSpy：它比 spyStats 多记一件事——每次回写时 mutate 的**返回值**。
// 那个返回值曾是「设备在这一拍执行期间被删掉」这条路径的全部可观测行为（返回 false 才不会
// 白换一次配置指针、涨一次 rev、标一次脏）。统计搬进内存之后回写不再经过配置，
// 那个机制连同它要防的代价一起没有了，于是这个替身也跟着删掉，剩下的用例统一用 spyStats。

const sinkMAC = "AA:BB:CC:DD:EE:FF"

// sinkDevice 一台把魔术包发往回环 sink 的设备。
func sinkDevice(id string, port int) config.WOLDevice {
	return config.WOLDevice{
		ID:        id,
		Name:      id,
		Enabled:   true,
		MAC:       sinkMAC,
		Broadcast: "127.0.0.1",
		Port:      port,
	}
}

// wantMagicPacket 按 WOL 规范手写一遍期望字节：6 个 0xFF + 目标 MAC 重复 16 次 = 102 字节。
// 刻意不复用 buildMagicPacket——那等于拿实现验证实现。
func wantMagicPacket(mac [6]byte) []byte {
	out := bytes.Repeat([]byte{0xFF}, 6)
	for i := 0; i < 16; i++ {
		out = append(out, mac[:]...)
	}
	return out
}

// 一拍连发 N 个包：只回写一次运行态，计数只涨 1，且包真的均匀铺在 1 秒内发完。
//
// 三条断言各对应一个已修复的缺陷面：
//   - 「恰好 1 次回写」——回写是 config 的写锁 + 落盘脏位，按包回写就是 10 倍代价（W-3/W-14）；
//   - 「计数涨 1」——面板上的「唤醒次数」语义是拍数，按包计数会让固定时间模式的数字凭空翻 N 倍；
//   - 「耗时 ≥ 800 毫秒」——连发被刻意铺开（背靠背突发更容易被交换机整片丢弃）。
func TestFireScheduledWritesStateOncePerBurst(t *testing.T) {
	const burst = 10
	port, got, first := udpSink(t)
	d := sinkDevice("d1", port)
	spy := newSpyStats(0)
	m := New(testLogger(), spy)

	start := time.Now()
	sent, err := m.fireScheduled(context.Background(), d, burst)
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("发往回环端口不该失败: %v", err)
	}
	if sent != burst {
		t.Fatalf("应发出 %d 个包，实际 %d 个", burst, sent)
	}
	if n := spy.n.Load(); n != 1 {
		t.Fatalf("一拍 %d 个包触发了 %d 次运行态回写，应恰好 1 次："+
			"按包回写会把配置写锁与落盘脏位的代价放大 %d 倍", burst, n, burst)
	}
	waitPackets(t, got, burst, 2*time.Second)

	// 铺开而不是背靠背：gap = 1 秒 / burst，首包立即发，故名义耗时是 (burst-1)*gap = 900 毫秒。
	if elapsed < 800*time.Millisecond {
		t.Fatalf("%d 个包只用了 %v 就发完，说明是背靠背瞬时打出，而非均匀铺在 1 秒内", burst, elapsed)
	}
	if elapsed > 3*time.Second {
		t.Fatalf("%d 个包耗时 %v，远超「1 秒内发完」的语义", burst, elapsed)
	}

	st := spy.Wake("d1")
	if st.Count != 1 {
		t.Fatalf("唤醒次数应按拍计（+1），实际 %d：按包计会让面板数字凭空翻 %d 倍", st.Count, burst)
	}
	if want := fmt.Sprintf("已发送 %d 次（1 秒内）", burst); st.LastText != want {
		t.Fatalf("最近结果 = %q，应为 %q", st.LastText, want)
	}
	if st.LastAt == 0 {
		t.Fatal("最近唤醒时刻未写入")
	}

	// 线上字节：这是本项目第一次真的检查发出去的是什么。
	select {
	case p := <-first:
		if want := wantMagicPacket([6]byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF}); !bytes.Equal(p, want) {
			t.Fatalf("魔术包字节不符：长度 %d（应 %d），内容 %x", len(p), len(want), p)
		}
	default:
		t.Fatal("没有捕获到任何一个包")
	}
}

// 连发途中被取消：提前收尾，但已经发出的包必须落账（且仍然只回写一次）。
//
// 「照常回写」不是可有可无的收尾动作：Close 之后面板上仍要能看到「刚才发过」，
// 否则关服务前的最后一拍在界面上等于没发生。
func TestFireScheduledCancelMidBurstStillWritesStateOnce(t *testing.T) {
	const burst = 20 // gap = 50 毫秒
	port, _, _ := udpSink(t)
	d := sinkDevice("d1", port)
	spy := newSpyStats(0)
	m := New(testLogger(), spy)

	ctx, cancel := context.WithTimeout(context.Background(), 220*time.Millisecond)
	defer cancel()

	start := time.Now()
	sent, err := m.fireScheduled(ctx, d, burst)
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("提前收尾不算失败: %v", err)
	}
	if sent < 1 || sent >= burst {
		t.Fatalf("取消发生在第 220 毫秒（gap 50 毫秒），应发出 1~%d 个包，实际 %d 个", burst-1, sent)
	}
	if elapsed > 700*time.Millisecond {
		t.Fatalf("取消后耗时 %v 才返回，未提前收尾（名义 1 秒）", elapsed)
	}
	if n := spy.n.Load(); n != 1 {
		t.Fatalf("提前收尾时回写了 %d 次，应恰好 1 次（既不能漏，也不能按包写）", n)
	}
	st := spy.Wake("d1")
	if st.Count != 1 {
		t.Fatalf("提前收尾时唤醒次数 = %d，应为 1", st.Count)
	}
	if want := fmt.Sprintf("已发送 %d 次（1 秒内）", sent); st.LastText != want {
		t.Fatalf("最近结果 = %q，应为 %q（写的必须是实际发出的数量）", st.LastText, want)
	}
}

// 单包一拍必须立即完成，且结果文案不带「N 次」——burst<1 由兜底夹到 1，走的是同一条路。
// 定时唤醒的默认形态就是这个，它若被连发的铺开逻辑拖上 1 秒，每拍都白等一秒。
func TestFireScheduledSinglePacketIsImmediate(t *testing.T) {
	for _, burst := range []int{0, 1} {
		t.Run(fmt.Sprintf("burst=%d", burst), func(t *testing.T) {
			port, got, _ := udpSink(t)
			d := sinkDevice("d1", port)
			spy := newSpyStats(0)
			m := New(testLogger(), spy)

			start := time.Now()
			sent, err := m.fireScheduled(context.Background(), d, burst)
			elapsed := time.Since(start)

			if err != nil {
				t.Fatalf("发往回环端口不该失败: %v", err)
			}
			if sent != 1 {
				t.Fatalf("burst=%d 应发出 1 个包，实际 %d 个", burst, sent)
			}
			if elapsed > 300*time.Millisecond {
				t.Fatalf("单包一拍耗时 %v，不该有任何等待", elapsed)
			}
			waitPackets(t, got, 1, 2*time.Second)
			if n := spy.n.Load(); n != 1 {
				t.Fatalf("回写了 %d 次，应为 1 次", n)
			}
			if st := spy.Wake("d1"); st.LastText != "已发送" {
				t.Fatalf("最近结果 = %q，单包时不该带「N 次」后缀", st.LastText)
			}
		})
	}
}

// 设备在这一拍执行期间被删掉：包照发（事实已经发生），统计也照记，但只能记在它自己那个键上。
//
// 这条用例换过一次断言。统计还在配置里的时候，被删设备的可观测行为是「回写的 mutate 返回
// false」——那是为了不白换一次配置指针、不涨一次 rev、不标一次脏。搬进内存之后回写只是
// 往一张 map 里塞一条，那三样代价都不存在了，于是剩下唯一还值得钉的性质是**不牵连**：
// 一条无主的记录不该改到别的设备的数字上。它自己那条键由删除时的 Forget 收走，
// 收不到也会在满表时按「最久没动静」淘汰（见 wol.go 里 Woke 调用处的说明），
// 而这两条退路由 runstats 自己的用例钉住（TestForgetClearsAllKinds / TestTableStopsGrowingAndEvictsOldest）。
func TestFireScheduledDeletedDeviceMakesNoChange(t *testing.T) {
	port, got, _ := udpSink(t)
	gone := sinkDevice("gone", port)
	spy := newSpyStats(0)
	m := New(testLogger(), spy)

	// 先给一台在册设备记一笔，作为「不该被牵连」的对照。
	spy.Woke("alive", 1_700_000_000, "已发送")
	baseline := spy.Wake("alive")

	sent, err := m.fireScheduled(context.Background(), gone, 1)
	if err != nil {
		t.Fatalf("发送本身不该失败: %v", err)
	}
	if sent != 1 {
		t.Fatalf("包应照发，实际发出 %d 个", sent)
	}
	waitPackets(t, got, 1, 2*time.Second)

	if n := spy.n.Load(); n != 2 { // 对照那一笔 + 这一拍
		t.Fatalf("回写调用次数 = %d，应为 2（这一拍仍要照常记一次）", n)
	}
	if st := spy.Wake("gone"); st.Count != 1 || st.LastText != "已发送" {
		t.Fatalf("被删设备这一拍应记在它自己的键上，实际 %#v", st)
	}
	if st := spy.Wake("alive"); st != baseline {
		t.Fatalf("别的设备被连带改动了: %#v → %#v", baseline, st)
	}
}

// 一整天的节拍只留下常数条日志，而不是每拍一条。
//
// 守的是 W-13：日志环的容量就是「访问日志最大条数」，范围模式一天几千拍，
// 逐拍写日志会把环整个挤满，其他模块的记录全被冲掉。
// 这里用 100+ 拍在毫秒级复现那个比例。
func TestRunPlanDayLogsPerRunNotPerTick(t *testing.T) {
	cases := []struct {
		name string
		// mac 为空表示用能发通的设备；否则填一个非法 MAC，让每拍都失败。
		badMAC string
		want   map[string]int
	}{
		{
			name: "全部成功：首拍一条 + 当日汇总一条",
			want: map[string]int{"已发送定时网络唤醒": 1, "定时网络唤醒当日结束": 1},
		},
		{
			// 每拍的错误文案完全相同，因此只该记一条：失败日志按「成败变化」去重，
			// 而不是按拍。否则一台配错 MAC 的设备会独占整个日志环。
			name:   "全部失败：去重成一条 + 当日汇总一条",
			badMAC: "not-a-mac",
			want:   map[string]int{"定时网络唤醒失败": 1, "定时网络唤醒当日结束": 1},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			port, _, _ := udpSink(t)
			d := sinkDevice("d1", port)
			if c.badMAC != "" {
				d.MAC = c.badMAC
			}
			spy := newSpyStats(0)
			lg := testLogger()
			m := New(lg, spy)

			const interval = 5 * time.Millisecond
			start := time.Now()
			p := wakePlan{start: start, end: start.Add(500 * time.Millisecond), interval: interval, burst: 1}
			if !m.runPlanDay(context.Background(), d, p) {
				t.Fatal("未被取消时 runPlanDay 应返回 true")
			}

			counts := map[string]int{}
			var ticks any
			for _, e := range lg.Recent(2 * logx.MinLogEntries) {
				counts[e.Message]++
				if e.Message == "定时网络唤醒当日结束" {
					ticks = e.Fields.Get("ticks")
				}
			}
			// 回写次数即拍数，与日志条数形成对照：拍很多，日志很少。
			t.Logf("%d 拍（汇总里记的 ticks=%v）共产生 %d 条日志: %v", spy.n.Load(), ticks, len(lg.Recent(2*logx.MinLogEntries)), counts)

			if spy.n.Load() < 10 {
				t.Fatalf("只跑了 %d 拍，拍数太少，撑不起「逐拍写日志会挤满日志环」的对照", spy.n.Load())
			}
			for msg, want := range c.want {
				if counts[msg] != want {
					t.Fatalf("日志 %q 出现 %d 条，应为 %d 条：逐拍记录会把日志环整个挤满", msg, counts[msg], want)
				}
			}
			if got := len(lg.Recent(2 * logx.MinLogEntries)); got != len(c.want) {
				t.Fatalf("一整段范围共产生 %d 条日志，应恰好 %d 条: %v", got, len(c.want), counts)
			}
		})
	}
	// 说明：「定时网络唤醒已恢复」那条分支（失败之后又成功）在此不可达——
	// 成败由真实的 socket 发送决定，同一台设备无法在同一段范围内先失败再成功。
	// 要覆盖它得把发送层做成可注入的；那是改产品代码的形状去迁就测试，故明确留白而不是绕路。
}

// interval 为 0 时 runPlanDay 必须靠兜底夹取活下来。
//
// 这一拍的时刻推进是 at = at.Add(interval)：interval 为 0 则 at 永不前进，
// 循环条件永远成立——表现为原地死转（CPU 打满、按微秒不停发包），
// 或者在重新对齐分支上除零 panic。两者都不是「测试失败」而是「测试卡死/崩掉」，
// 所以这里只能用超时来判定，不能用返回值。
func TestRunPlanDayGuardsZeroInterval(t *testing.T) {
	port, _, _ := udpSink(t)
	d := sinkDevice("d1", port)
	spy := newSpyStats(0)
	m := New(testLogger(), spy)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel() // 兜底失效时让死转的协程有机会退出，不至于拖着整个测试进程

	// 刻意把这一拍放在刚刚过去的时刻，而不是写 start = time.Now()：兜底夹取会把 interval 补成
	// 1 秒，落后 300 毫秒稳稳在「不足一整拍算抖动」的范围内，协程什么时候被调度起来都照发。
	// 用 time.Now() 则是拿时钟粒度赌运气——本机背靠背两次 time.Now() 有 999/1000 的概率相同，
	// 于是平时都过，整仓并行、机器有负载时偶尔越过一格就报「实际 0 拍」。
	at := time.Now().Add(-300 * time.Millisecond)
	done := make(chan bool, 1)
	go func() {
		done <- m.runPlanDay(ctx, d, wakePlan{start: at, end: at, interval: 0, burst: 1})
	}()

	select {
	case ok := <-done:
		if !ok {
			t.Fatal("未被取消时应返回 true")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("interval 为 0 时 runPlanDay 原地死转：兜底夹取失效")
	}
	if n := spy.n.Load(); n != 1 {
		t.Fatalf("start == end 应恰好发一拍，实际 %d 拍", n)
	}
}

// 一拍制的计划落后超过一整拍就该整拍丢掉：魔术包幂等，迟到的唤醒没有意义（面板重启到
// 半夜才拉起来，不该把白天错过的那次唤醒补发出去）。
// 它是上面那条用例的另一半——只有两条都在，首拍的宽容度才被夹在「容忍抖动」和
// 「不补发」之间，日后把宽容度不小心放大成「多晚都补一发」才会被这里挡住。
func TestRunPlanDaySkipsLongPastSingleTick(t *testing.T) {
	port, _, _ := udpSink(t)
	d := sinkDevice("d1", port)
	spy := newSpyStats(0)
	m := New(testLogger(), spy)

	at := time.Now().Add(-time.Hour) // 远超兜底夹取的 1 秒间隔，怎么调度都算「错过」
	if !m.runPlanDay(context.Background(), d, wakePlan{start: at, end: at, interval: 0, burst: 1}) {
		t.Fatal("未被取消时应返回 true")
	}
	if n := spy.n.Load(); n != 0 {
		t.Fatalf("落后一小时的一拍应被丢弃，实际发了 %d 拍", n)
	}
}

// 单包一拍在线上是什么字节：6 个 0xFF + 目标 MAC 重复 16 次，共 102 字节。
// 报告第九节自陈「魔术包的端到端投递未做验证」，这条用例把它补上。
func TestWakeDeviceSendsMagicPacketOnTheWire(t *testing.T) {
	port, got, first := udpSink(t)
	d := sinkDevice("d1", port)
	d.MAC = "01:02:03:04:05:06"

	if err := WakeDevice(d); err != nil {
		t.Fatalf("WakeDevice 失败: %v", err)
	}
	waitPackets(t, got, 1, 2*time.Second)
	if n := got.Load(); n != 1 {
		t.Fatalf("指定具体目标地址时应恰好一个 datagram，实际 %d 个", n)
	}

	p := <-first
	want := wantMagicPacket([6]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06})
	if len(p) != 102 {
		t.Fatalf("魔术包长度 %d，应为 102 字节（6 + 16×6）", len(p))
	}
	if !bytes.Equal(p, want) {
		t.Fatalf("魔术包内容不符:\n实际 %x\n期望 %x", p, want)
	}
}

// Name 是模块注册表的键，改动会静默改掉配置里的模块标识。
func TestModuleName(t *testing.T) {
	if got := New(testLogger(), nil).Name(); got != "wol" {
		t.Fatalf("模块名 = %q，应为 \"wol\"", got)
	}
}

// W-10：时间范围不支持跨零点，退化为「每天只在开始时刻发一拍」。这个退化本身是有意的口径
// （原因见 planForDay 里那段说明），但它此前在服务端**完全无声**——
// 面板编辑时会提示，手工编辑 config.json 或整份导入的配置绕过前端，
// 而症状（「每天只在 22:00 发一个包」）在日志里与正常的固定时间模式毫无区别。
// 这条用例钉住那句提醒：退化时必须说出来，且要带上可行的替代做法。
func TestRunScheduleWarnsOnDegradedRange(t *testing.T) {
	const warnMsg = "时间范围的结束时刻不晚于开始时刻，每天只在开始时刻发一拍；跨零点请拆成两条设备（如 22:00–23:59 与 00:00–06:00）"

	cases := []struct {
		name     string
		start    string
		end      string
		wantWarn bool
	}{
		{"跨零点的夜间时段", "22:00", "06:00", true},
		{"开始与结束相同", "22:00", "22:00", true},
		{"正常的一天内时段", "08:00", "18:00", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			port, _, _ := udpSink(t)
			d := sinkDevice("d1", port)
			d.Schedule = config.WOLSchedule{
				Enabled:     true,
				Mode:        "range",
				Start:       c.start,
				End:         c.end,
				IntervalSec: 3600,
			}
			spy := newSpyStats(0)
			lg := testLogger()
			m := New(lg, spy)

			ctx, cancel := context.WithCancel(context.Background())
			m.wg.Add(1) // runSchedule 自己 Done，调用方负责 Add
			go m.runSchedule(ctx, d)

			// 提醒是在推导出当日安排之后立刻记的，微秒级就该出现；
			// 给到 2 秒纯粹是为了 CI 上的调度卡顿。
			found := false
			deadline := time.Now().Add(2 * time.Second)
			for time.Now().Before(deadline) {
				for _, e := range lg.Recent(logx.MinLogEntries) {
					if e.Message == warnMsg {
						found = true
					}
				}
				if found || !c.wantWarn {
					break
				}
				time.Sleep(10 * time.Millisecond)
			}
			// 反例分支上没有可同步的信号（正常范围什么都不记），只能给一段固定的宽限时间。
			// 正例分支已经证明这段代码确实会跑到，因此这里不会变成「因为没跑到所以没记」的假通过。
			if !c.wantWarn {
				time.Sleep(300 * time.Millisecond)
				for _, e := range lg.Recent(logx.MinLogEntries) {
					if e.Message == warnMsg {
						found = true
					}
				}
			}
			cancel()
			m.wg.Wait()

			if found != c.wantWarn {
				t.Fatalf("%s–%s：记提醒 = %v，应为 %v（退化必须说出来，正常范围不该刷这条）",
					c.start, c.end, found, c.wantWarn)
			}
			if c.wantWarn {
				// 提醒必须带上是哪台设备、什么时段，否则多设备时用户不知道该改哪一条。
				for _, e := range lg.Recent(logx.MinLogEntries) {
					if e.Message != warnMsg {
						continue
					}
					if e.Fields.Get("device") != d.Name || e.Fields.Get("start") != c.start || e.Fields.Get("end") != c.end {
						t.Fatalf("提醒缺少定位信息: %#v", e.Fields)
					}
				}
			}
		})
	}
}
