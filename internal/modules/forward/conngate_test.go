package forward

import (
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"mantou/internal/config"
	"mantou/internal/logx"
)

// 本文件盯的是模块级连接总闸（3-D）。
//
// maxConnsPerRunner 守的是"每个监听端口"，而一条规则可以写成 20000-21000 这样的端口范围、
// 展开出 1000 个 runner——那句保护于是被端口数乘掉了。总闸把这个乘法变回加法。
//
// 要钉住的是：
//   1. 全部 runner 共用**同一个**闸（这一条最要紧：给每个 runner 各发一个闸能编译、
//      单条规则的行为也全对，而 3-D 原封不动地回来了）；
//   2. TCP 与 UDP 两条路都占名额、都还名额——尤其是还名额：泄漏够 maxConnsTotal 个之后
//      整个模块再也接不进新连接，且没有任何报错；
//   3. 名额满时新连接被立刻关掉，不是挂着，也不是转给后端。

// freePort 借一个当前空闲的本机端口。
func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	return port
}

// freePortRange 借 n 个连号的空闲端口，返回起点。
// 连号是重点：3-D 的场景正是"一条规则写成端口范围、展开出许多 runner"。
func freePortRange(t *testing.T, n int) int {
	t.Helper()
	for try := 0; try < 20; try++ {
		base := freePort(t)
		var lns []net.Listener
		ok := true
		for i := 0; i < n; i++ {
			ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", base+i))
			if err != nil {
				ok = false
				break
			}
			lns = append(lns, ln)
		}
		for _, ln := range lns {
			_ = ln.Close()
		}
		if ok {
			return base
		}
	}
	t.Fatalf("借不到 %d 个连号的空闲端口", n)
	return 0
}

// echoTCP 起一个原样回写的 TCP 后端，返回端口与已接受的连接数。
// 连接数是用来证否的：被总闸拒掉的连接绝不该出现在后端这一侧。
func echoTCP(t *testing.T) (int, *atomic.Int64) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	var n atomic.Int64
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			n.Add(1)
			go func() { defer c.Close(); _, _ = io.Copy(c, c) }()
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port, &n
}

// echoUDP 起一个原样回写的 UDP 后端，返回端口与已收到的数据报数。
func echoUDP(t *testing.T) (int, *atomic.Int64) {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	var n atomic.Int64
	go func() {
		buf := make([]byte, 2048)
		for {
			cnt, from, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			n.Add(1)
			_, _ = conn.WriteToUDP(buf[:cnt], from)
		}
	}()
	return conn.LocalAddr().(*net.UDPAddr).Port, &n
}

// startRunner 起一条转发规则，返回 runner 与它的监听端口。
func startRunner(t *testing.T, gate *connGate, proto string, targetPort int) (*runner, int) {
	t.Helper()
	rule := config.ForwardRule{
		ID: "rule-" + proto, Name: "测试规则", Enabled: true, Protocol: proto,
		ListenPort: freePort(t), TargetHost: "127.0.0.1", TargetPort: targetPort,
		Bind: "127.0.0.1",
	}
	run := newRunner(rule, logx.New(logx.Options{}), gate)
	if err := run.start(); err != nil {
		t.Fatalf("规则启动失败: %v", err)
	}
	t.Cleanup(run.stop)
	return run, rule.ListenPort
}

// fillGate 把总闸占满，返回还原函数。
func fillGate(t *testing.T, g *connGate) func() {
	t.Helper()
	for i := 0; i < maxConnsTotal; i++ {
		if !g.enter() {
			t.Fatalf("占第 %d 个名额就失败了，上限是 %d", i+1, maxConnsTotal)
		}
	}
	return func() {
		for i := 0; i < maxConnsTotal; i++ {
			g.leave()
		}
	}
}

// waitCur 等占用数变成 want。
// 连接收尾是异步的（handleTCP 的 defer、serveUDP 的退出清理都在别的 goroutine 里），
// 所以只能轮询；固定时长的 sleep 在慢机器上就是随机失败。
func waitCur(t *testing.T, g *connGate, want int64, what string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if got := g.cur.Load(); got == want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s：等了 5 秒占用数仍是 %d，期望 %d", what, g.cur.Load(), want)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// 闸自己的计数：正好放进 maxConnsTotal 个，下一个被挡，还一个能再进一个。
func TestConnGateCapAndRelease(t *testing.T) {
	var g connGate
	restore := fillGate(t, &g)
	if g.enter() {
		t.Fatalf("第 %d 个应被挡住", maxConnsTotal+1)
	}
	// 被挡住时不许把计数留在虚高的位置：enter 是"先加再判"，加上去的那一下必须退回来，
	// 否则每被拒一次上限就永久少一个。
	if got := g.cur.Load(); got != int64(maxConnsTotal) {
		t.Fatalf("被拒之后占用数应仍是 %d，实际 %d", maxConnsTotal, got)
	}
	g.leave()
	if !g.enter() {
		t.Fatal("还回一个之后应能再进一个")
	}
	restore()
	if got := g.cur.Load(); got != 0 {
		t.Fatalf("全部还回之后应归零，实际 %d", got)
	}
}

// 一条端口范围规则展开出的全部 runner 必须共用同一个闸。
//
// 这是 3-D 本身：给每个 runner 各发一个闸能编译、单条连接的行为也全对，
// 而"上限被端口数乘掉"这件事原封不动地回来了，且没有任何现象能看出来。
func TestReloadSharesOneGateAcrossRunners(t *testing.T) {
	const ports = 3
	// 借端口只能"先探再放"，放开到 Reload 真去 bind 之间有一段空档，期间别的进程可能占掉其中一个。
	// 占掉的表现是少起一个运行项，和"展开数不对"一模一样——所以整段重试，
	// 把偶发的抢占与真正的缺陷分开：真缺陷每一轮都少，重试多少次都过不去。
	var m *Module
	for try := 0; ; try++ {
		base := freePortRange(t, ports)
		m = &Module{log: logx.New(logx.Options{}), runners: map[string]*runner{}}
		cfg := &config.Config{Forwards: []config.ForwardRule{{
			ID: "r1", Name: "端口范围", Enabled: true, Protocol: "tcp",
			ListenPort: base, ListenPortEnd: base + ports - 1,
			TargetHost: "127.0.0.1", TargetPort: freePort(t), Bind: "127.0.0.1",
		}}}
		if err := m.Reload(cfg); err != nil {
			t.Fatalf("Reload 失败: %v", err)
		}
		if len(m.runners) == ports {
			t.Cleanup(func() { _ = m.Close() })
			break
		}
		got := len(m.runners)
		_ = m.Close()
		if try >= 9 {
			t.Fatalf("应展开出 %d 个运行项，实际 %d", ports, got)
		}
	}

	for key, run := range m.runners {
		if run.conns != &m.conns {
			t.Fatalf("运行项 %s 用的不是模块那一个闸——上限又被端口数乘掉了", key)
		}
	}
}

// 总闸满时，新的 TCP 连接要被立刻关掉，且一个字节都不许送到后端。
func TestTCPRefusedWhenTotalCapFull(t *testing.T) {
	backend, accepted := echoTCP(t)
	var g connGate
	run, port := startRunner(t, &g, "tcp", backend)
	restore := fillGate(t, &g)
	defer restore()

	conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		// 名额满时监听仍在 accept，所以握手通常是成功的；但连接随即被关，
		// 个别平台上这一步就报错也算被拒。
		return
	}
	defer conn.Close()
	_, _ = conn.Write([]byte("ping"))
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 8)
	n, err := conn.Read(buf)
	if err == nil {
		t.Fatalf("被拒的连接不该有回包，却读到 %q", buf[:n])
	}
	// 区分"被关掉"和"挂着不管"：后者读会超时，而挂着的连接照样占着 fd 与内存，
	// 那道闸就只是把问题从内存挪到了句柄上。
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		t.Fatalf("连接既没回数据也没被关掉：%v", err)
	}
	if got := accepted.Load(); got != 0 {
		t.Fatalf("后端不该收到任何连接，实际 %d 条", got)
	}
	if got := g.cur.Load(); got != int64(maxConnsTotal) {
		t.Fatalf("被拒的连接不该改变占用数，实际 %d", got)
	}
	// 本端口那道闸的计数也要退回来：accept 里是先给本端口加 1、再问总闸，
	// 总闸不给就必须把那 1 退掉。漏掉的话每被总闸拒一次，本端口的上限就永久少一个。
	if got := run.activeConns.Load(); got != 0 {
		t.Fatalf("本端口的计数也应退回 0，实际 %d", got)
	}
}

// 正常并发不该被总闸挡住。
//
// 上限定多少是个判断题，定得太低就把这道内存护栏变成了吞吐瓶颈——而那种退化在
// 逐条连接的测试里完全看不出来（每条都已经把名额还回去了）。这一条同时开着 64 条
// 连接，要求全部能正常往返。
func TestTotalCapAllowsNormalConcurrency(t *testing.T) {
	const concurrent = 64
	if concurrent > maxConnsTotal {
		t.Fatalf("总上限 %d 低于正常并发量 %d", maxConnsTotal, concurrent)
	}
	backend, _ := echoTCP(t)
	var g connGate
	_, port := startRunner(t, &g, "tcp", backend)

	addr := fmt.Sprintf("127.0.0.1:%d", port)
	conns := make([]net.Conn, 0, concurrent)
	defer func() {
		for _, c := range conns {
			_ = c.Close()
		}
	}()
	for i := 0; i < concurrent; i++ {
		conn, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatalf("第 %d 条连不上：%v", i+1, err)
		}
		conns = append(conns, conn)
		// 每条都真的走一次往返：只建连不发数据的话，连接可能还没进 handleTCP。
		msg := fmt.Sprintf("p%03d", i)
		if _, err := conn.Write([]byte(msg)); err != nil {
			t.Fatalf("第 %d 条写不进去：%v", i+1, err)
		}
		_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		buf := make([]byte, len(msg))
		if _, err := io.ReadFull(conn, buf); err != nil {
			t.Fatalf("第 %d 条读不到回包：%v——正常并发被闸住了", i+1, err)
		}
		if string(buf) != msg {
			t.Fatalf("第 %d 条回包不对：%q", i+1, buf)
		}
	}
	// 全部还开着，所以名额应当全被占着。
	waitCur(t, &g, concurrent, "全部连接建立后")
}

// 正常转发一条 TCP 连接：期间占着一个名额，收尾后还回来。
func TestTCPTakesAndReleasesTotalSlot(t *testing.T) {
	backend, accepted := echoTCP(t)
	var g connGate
	_, port := startRunner(t, &g, "tcp", backend)

	conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatalf("连不上转发端口: %v", err)
	}
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatalf("写不进去: %v", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 4)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("读不到回包: %v", err)
	}
	if string(buf) != "ping" {
		t.Fatalf("回包不对: %q", buf)
	}
	waitCur(t, &g, 1, "转发中")
	if got := accepted.Load(); got != 1 {
		t.Fatalf("后端应收到 1 条连接，实际 %d", got)
	}

	_ = conn.Close()
	waitCur(t, &g, 0, "连接关闭后")
}

// UDP 会话同样占名额，且退出清理会把名额还回来。
//
// 会话的删除有三处，这一条走的是"监听关闭时的整表清理"那一处——
// 它最容易被漏掉，因为进程退出时看不出有什么不对。
func TestUDPSessionTakesAndReleasesTotalSlot(t *testing.T) {
	backend, got := echoUDP(t)
	var g connGate
	run, port := startRunner(t, &g, "udp", backend)

	client, err := net.Dial("udp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatalf("连不上转发端口: %v", err)
	}
	defer client.Close()
	if _, err := client.Write([]byte("ping")); err != nil {
		t.Fatalf("写不进去: %v", err)
	}
	waitCur(t, &g, 1, "会话建立后")

	_ = client.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 16)
	if n, err := client.Read(buf); err != nil {
		t.Fatalf("读不到回包: %v", err)
	} else if string(buf[:n]) != "ping" {
		t.Fatalf("回包不对: %q", buf[:n])
	}
	if n := got.Load(); n != 1 {
		t.Fatalf("后端应收到 1 个数据报，实际 %d", n)
	}

	run.stop()
	waitCur(t, &g, 0, "监听关闭后")
}

// 总闸满时不许建新的 UDP 会话：数据报直接丢掉，不拨号、不进后端。
func TestUDPRefusedWhenTotalCapFull(t *testing.T) {
	backend, got := echoUDP(t)
	var g connGate
	_, port := startRunner(t, &g, "udp", backend)
	restore := fillGate(t, &g)
	defer restore()

	client, err := net.Dial("udp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatalf("连不上转发端口: %v", err)
	}
	defer client.Close()
	if _, err := client.Write([]byte("ping")); err != nil {
		t.Fatalf("写不进去: %v", err)
	}

	// 这一条要证的是"什么都没发生"，只能等一小会儿再看。
	// UDP 没有握手，客户端这一侧本来就区分不出被丢弃与被转发。
	time.Sleep(300 * time.Millisecond)
	if n := got.Load(); n != 0 {
		t.Fatalf("后端不该收到数据报，实际 %d 个", n)
	}
	if cur := g.cur.Load(); cur != int64(maxConnsTotal) {
		t.Fatalf("被丢弃的数据报不该改变占用数，实际 %d", cur)
	}
}

// 拨号失败时占过的名额要还回来。
//
// 这条路径专门盯"名额已经占了、会话却没建起来"：会话表里没有它，
// 三处删除都不会经过它，所以只能在拨号失败的那一行就地还掉。
// 漏掉的话，后端地址写错的规则每收到一个数据报就泄一个名额——而这正是最容易
// 反复收数据报的情形（对面在重发），泄够 maxConnsTotal 个之后整个模块就哑了。
//
// 目标主机名里带 `!`：Go 的解析器直接判定它不是合法域名、压根不发 DNS 查询，
// 所以这条测试不依赖本机 DNS，也不会慢。
//
// 要紧的是**先等到确实拨过号了再看占用数**：数据报是异步处理的，直接看的话
// 一进来就读到 0——那时候 runner 还没碰过它，这条测试也就什么都没钉住。
// 所以从日志里数"转发连接失败"的条数，够数了再断言。
func TestUDPDialFailureReleasesTotalSlot(t *testing.T) {
	const datagrams = 5
	fails := &countingWriter{want: "转发连接失败"}
	var g connGate
	rule := config.ForwardRule{
		ID: "rule-bad", Name: "目标写错的规则", Enabled: true, Protocol: "udp",
		ListenPort: freePort(t), TargetHost: "bad_host!", TargetPort: 53,
		Bind: "127.0.0.1",
	}
	run := newRunner(rule, logx.New(logx.Options{FileWriter: fails}), &g)
	if err := run.start(); err != nil {
		t.Fatalf("规则启动失败: %v", err)
	}
	t.Cleanup(run.stop)

	client, err := net.Dial("udp", fmt.Sprintf("127.0.0.1:%d", rule.ListenPort))
	if err != nil {
		t.Fatalf("连不上转发端口: %v", err)
	}
	defer client.Close()
	// 发几个：一个数据报泄一个名额，多发几个才能把"泄漏"与"时序没对上"区分开。
	for i := 0; i < datagrams; i++ {
		if _, err := client.Write([]byte("ping")); err != nil {
			t.Fatalf("第 %d 个数据报写不进去: %v", i+1, err)
		}
	}

	deadline := time.Now().Add(10 * time.Second)
	for fails.count() < datagrams {
		if time.Now().After(deadline) {
			t.Fatalf("等了 10 秒只看到 %d 次拨号失败，期望 %d 次（UDP 允许丢包，"+
				"但本机回环上连着丢 %d 个数据报说明是别的问题）",
				fails.count(), datagrams, datagrams-fails.count())
		}
		time.Sleep(2 * time.Millisecond)
	}
	if cur := g.cur.Load(); cur != 0 {
		t.Fatalf("%d 次拨号全失败后占用数应归零，实际 %d——每失败一次泄一个名额", datagrams, cur)
	}
}

// countingWriter 数日志里含 want 的条数。用来等"某件事确实发生过了"。
type countingWriter struct {
	want string
	n    atomic.Int64
}

func (w *countingWriter) Write(p []byte) (int, error) {
	if strings.Contains(string(p), w.want) {
		w.n.Add(1)
	}
	return len(p), nil
}

func (w *countingWriter) count() int { return int(w.n.Load()) }
