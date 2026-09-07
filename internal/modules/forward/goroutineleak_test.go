package forward

import (
	"fmt"
	"net"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"mantou/internal/config"
	"mantou/internal/logx"
)

// 本文件是全套测试里第一条 goroutine 数断言（审计 R-01）。
//
// 从前没有任何一条：模块的启停正确性全靠"行为对不对"来测（连得上、回包对、名额还回来了），
// 而 goroutine 泄漏恰好在这些断言里全部看不见——泄漏的协程不占名额、不影响回包，
// 只是每保存一次配置就多留几个下来。面板的配置保存是高频动作（每改一条规则一次
// ReloadAll），一轮泄漏 3 个协程，跑上几个月就是几万个连同它们各自的栈与被它们
// 钉住的连接对象一起留在内存里，而唯一的现象是"用久了内存莫名变高"。
//
// 选在 forward 这个包，因为它是全仓库协程启动点最密的一处（acceptTCP、handleTCP、
// serveUDP、UDP 空闲清扫、udpReturn），而且**每一个都登记在 r.wg 上**、runner.stop()
// 是 cancel + 关监听 + wg.Wait()。有这个所有权约定在，"回到基线"才是个确定的断言，
// 而不是碰运气。
//
// 钉住的是两条：Reload 撤掉规则那条路（与 Close 不是同一段代码）和 Close 那条路，
// 都必须把自己起的协程收干净。

const (
	// leakCycles 反复启停的轮数。要多于 1 轮才能把"每轮泄漏"与"常驻开销"分开：
	// 常驻的那些只在第一轮出现，而每轮泄漏会随轮数线性增长，藏不进固定余量里。
	leakCycles = 8
	// leakSlack 允许的余量。运行时自己会随负载增减工作协程（GC、计时器），
	// 所以不能要求严格相等；但余量必须显著小于 leakCycles，否则每轮漏一个也能过。
	leakSlack = 4
)

// waitGoroutinesAtMost 等 goroutine 数回落到 limit 以内，返回最后读到的值。
//
// 只能轮询：收尾全在别的协程里（handleTCP 的 defer、udpReturn 的退出清理、
// 后端 echo 那侧 io.Copy 的返回），固定时长的 sleep 在慢机器上就是随机失败。
func waitGoroutinesAtMost(limit int) int {
	deadline := time.Now().Add(10 * time.Second)
	for {
		n := runtime.NumGoroutine()
		if n <= limit || time.Now().After(deadline) {
			return n
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// settleGoroutines 等 goroutine 数连续几次读数不变，返回那个稳定读数。
//
// 取基线不能只读一次：热身那轮刚结束时收尾协程还在退，读到的是个偏高的瞬时值，
// 基线偏高会把后面真正的泄漏一起吃掉（那才是最坏的失败方式——测试绿着，缺陷在）。
func settleGoroutines() int {
	deadline := time.Now().Add(10 * time.Second)
	last, stable := -1, 0
	for {
		n := runtime.NumGoroutine()
		if n == last {
			if stable++; stable >= 5 {
				return n
			}
		} else {
			last, stable = n, 0
		}
		if time.Now().After(deadline) {
			return n
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// pushTCPThrough 经转发端口走一趟 TCP 往返。
//
// 必须真的把回包读回来：连上但不发数据的话 handleTCP 里那两个 cp 协程根本不会开始搬运，
// 这条断言就退化成只测了监听协程。
func pushTCPThrough(t *testing.T, port int) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 5*time.Second)
	if err != nil {
		t.Fatalf("连 TCP 转发端口 %d 失败：%v", port, err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatalf("写入 TCP 转发端口失败：%v", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 8)
	if _, err := conn.Read(buf); err != nil {
		t.Fatalf("读 TCP 回包失败：%v", err)
	}
}

// pushUDPThrough 经转发端口走一趟 UDP 往返。
// 一笔往返会让 serveUDP 建出一个会话（上游连接 + udpReturn 协程），正是要看它收不收得干净。
func pushUDPThrough(t *testing.T, port int) {
	t.Helper()
	conn, err := net.Dial("udp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatalf("连 UDP 转发端口 %d 失败：%v", port, err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatalf("写入 UDP 转发端口失败：%v", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 8)
	if _, err := conn.Read(buf); err != nil {
		t.Fatalf("读 UDP 回包失败：%v", err)
	}
}

// leakRules 造一条 TCP 规则和一条 UDP 规则（两条路的协程启动点不同，都要走到）。
func leakRules(t *testing.T, tcpTarget, udpTarget int) []config.ForwardRule {
	t.Helper()
	return []config.ForwardRule{
		{
			ID: "leak-tcp", Name: "泄漏检查 TCP", Enabled: true, Protocol: "tcp",
			Bind: "127.0.0.1", ListenPort: freePort(t),
			TargetHost: "127.0.0.1", TargetPort: tcpTarget,
		},
		{
			ID: "leak-udp", Name: "泄漏检查 UDP", Enabled: true, Protocol: "udp",
			Bind: "127.0.0.1", ListenPort: freeUDPPort(t),
			TargetHost: "127.0.0.1", TargetPort: udpTarget,
		},
	}
}

// runLeakCycle 完整走一轮：起两条规则 → 各推一笔流量 → Reload 撤掉规则 → Close。
//
// 借来的端口在"探测完放开"到"Reload 真去 bind"之间有一段空档，别的进程可能占掉其中一个；
// 占掉的表现是少起一个运行项，与真缺陷不好区分，所以整轮重试（与
// TestReloadSharesOneGateAcrossRunners 同一个套路）：真缺陷每轮都少，重试多少次都过不去。
func runLeakCycle(t *testing.T, log *logx.Logger, tcpTarget, udpTarget int) {
	t.Helper()
	for try := 0; ; try++ {
		m := New(log, nil)
		rules := leakRules(t, tcpTarget, udpTarget)
		if err := m.Reload(&config.Config{Forwards: rules}); err != nil {
			t.Fatalf("Reload 失败：%v", err)
		}
		if got := m.Status().Total; got != len(rules) {
			_ = m.Close()
			if try >= 9 {
				t.Fatalf("应起 %d 个运行项，实际 %d", len(rules), got)
			}
			continue
		}

		pushTCPThrough(t, rules[0].ListenPort)
		pushUDPThrough(t, rules[1].ListenPort)

		// 先走"配置里删掉规则"这条路：Reload 停运行项与 Close 停运行项是两段代码，
		// 只测 Close 会漏掉前者——而前者才是面板上每次保存都会走的那一条。
		if err := m.Reload(&config.Config{}); err != nil {
			t.Fatalf("撤掉规则的 Reload 失败：%v", err)
		}
		if got := m.Status().Total; got != 0 {
			t.Fatalf("规则已从配置里删掉，运行项应清零，实际 %d", got)
		}
		if err := m.Close(); err != nil {
			t.Fatalf("Close 失败：%v", err)
		}
		return
	}
}

// TestReloadAndCloseDoNotLeakGoroutines 反复启停之后 goroutine 数必须回到基线。
func TestReloadAndCloseDoNotLeakGoroutines(t *testing.T) {
	tcpTarget, tcpSeen := echoTCP(t)
	udpTarget, udpSeen := echoUDP(t)
	log := logx.New(logx.Options{})

	// 热身一轮再取基线：第一轮会带起一批只出现一次的常驻协程（net 内部的 netpoll/
	// 解析器、logx、后端 echo 的 accept 循环）。把它们算成泄漏就是个必然失败的断言。
	runLeakCycle(t, log, tcpTarget, udpTarget)
	baseline := settleGoroutines()

	for i := 0; i < leakCycles; i++ {
		runLeakCycle(t, log, tcpTarget, udpTarget)
	}

	// 流量真的走通了才算这条断言有效：一轮都没连上的话，下面"没有泄漏"是空对空。
	assertSeen(t, tcpSeen, leakCycles+1, "TCP 后端接受的连接数")
	assertSeen(t, udpSeen, leakCycles+1, "UDP 后端收到的数据报数")

	if got := waitGoroutinesAtMost(baseline + leakSlack); got > baseline+leakSlack {
		// 泄漏了就把现场打出来：栈里重复出现的那个函数就是没收干净的那个。
		buf := make([]byte, 1<<16)
		n := runtime.Stack(buf, true)
		t.Fatalf("启停 %d 轮之后 goroutine 数 %d，基线 %d（允许 +%d）。当前协程栈：\n%s",
			leakCycles, got, baseline, leakSlack, buf[:n])
	}
}

// assertSeen 后端至少收到过 want 笔——证明这些轮次真的建立了连接。
func assertSeen(t *testing.T, seen *atomic.Int64, want int, what string) {
	t.Helper()
	if got := seen.Load(); got < int64(want) {
		t.Fatalf("%s = %d，至少应有 %d 笔（流量没走通，泄漏断言就无从谈起）", what, got, want)
	}
}
