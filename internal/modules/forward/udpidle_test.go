package forward

import (
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"mantou/internal/config"
	"mantou/internal/logx"
)

// 本文件盯的是 UDP 会话"空闲"的口径：任一方向有数据就算活着，两个方向都安静了才摘掉。
//
// 原先只有客户端发来的数据报会刷新会话，于是出过两种坏结果：
//   - 客户端发一个请求、之后由后端持续往回推（订阅一类的推送）：客户端一安静，
//     会话在推送途中被当成空闲摘掉，后面的推送全部丢失；
//   - 只往后端送、后端从不回话（日志、指标上报）：回包那一侧读超时就拆会话，
//     每个空闲周期重建一次，后端看到的来源端口随之跳变。
//
// 空闲超时在线上是 60 秒，这里调成 200ms，否则一条用例要等好几分钟。

const testUDPIdle = 200 * time.Millisecond

// startShortIdleUDPRunner 起一条空闲超时调短了的 UDP 规则。
func startShortIdleUDPRunner(t *testing.T, gate *connGate, targetPort int) int {
	t.Helper()
	rule := config.ForwardRule{
		ID: "rule-udp-idle", Name: "空闲测试", Enabled: true, Protocol: "udp",
		ListenPort: freeUDPPort(t), TargetHost: "127.0.0.1", TargetPort: targetPort,
		Bind: "127.0.0.1",
	}
	run := newRunner(rule, logx.New(logx.Options{}), gate)
	run.udpIdle = testUDPIdle
	if err := run.start(); err != nil {
		t.Fatalf("规则启动失败: %v", err)
	}
	t.Cleanup(run.stop)
	return rule.ListenPort
}

// 后端持续往回推、客户端只发过一个数据报：推送持续期间会话不能被摘掉。
func TestUDPSessionKeptAliveByBackendTraffic(t *testing.T) {
	backend, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		buf := make([]byte, 64)
		_, from, err := backend.ReadFromUDP(buf)
		if err != nil {
			return
		}
		// 收到"订阅"之后每 40ms 推一个，客户端不再发任何东西。
		tick := time.NewTicker(40 * time.Millisecond)
		defer tick.Stop()
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			case <-tick.C:
				_, _ = backend.WriteToUDP([]byte(fmt.Sprintf("push-%d", i)), from)
			}
		}
	}()

	var g connGate
	port := startShortIdleUDPRunner(t, &g, backend.LocalAddr().(*net.UDPAddr).Port)
	client, err := net.Dial("udp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if _, err := client.Write([]byte("subscribe")); err != nil {
		t.Fatal(err)
	}

	// 收满 5 个空闲周期：旧实现在一到两个周期后就把会话摘了，之后一个包都收不到。
	buf := make([]byte, 64)
	deadline := time.Now().Add(5 * testUDPIdle)
	var last time.Time
	for time.Now().Before(deadline) {
		_ = client.SetReadDeadline(time.Now().Add(testUDPIdle))
		if _, err := client.Read(buf); err != nil {
			t.Fatalf("推送进行到 %s 时断了（会话被当成空闲摘掉）：%v",
				time.Since(deadline.Add(-5*testUDPIdle)).Round(time.Millisecond), err)
		}
		last = time.Now()
	}
	if last.IsZero() {
		t.Fatal("一个推送都没收到")
	}
}

// 只往后端送、后端从不回话：会话要一直是同一条，后端看到的来源地址不能跳。
func TestUDPSessionKeptAliveByClientTraffic(t *testing.T) {
	sink, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer sink.Close()
	var mu sync.Mutex
	sources := map[string]int{}
	go func() {
		buf := make([]byte, 64)
		for {
			_, from, err := sink.ReadFromUDP(buf)
			if err != nil {
				return
			}
			mu.Lock()
			sources[from.String()]++
			mu.Unlock()
		}
	}()

	var g connGate
	port := startShortIdleUDPRunner(t, &g, sink.LocalAddr().(*net.UDPAddr).Port)
	client, err := net.Dial("udp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	// 每 40ms 上报一次，持续 5 个空闲周期。
	end := time.Now().Add(5 * testUDPIdle)
	sent := 0
	for time.Now().Before(end) {
		if _, err := client.Write([]byte("metric")); err != nil {
			t.Fatal(err)
		}
		sent++
		time.Sleep(40 * time.Millisecond)
	}
	time.Sleep(50 * time.Millisecond) // 让最后一个数据报落地

	mu.Lock()
	defer mu.Unlock()
	if len(sources) != 1 {
		t.Fatalf("后端应始终看到同一个来源地址（同一条会话），实际 %d 个：%v", len(sources), sources)
	}
	if cur := g.cur.Load(); cur != 1 {
		t.Fatalf("上报期间应始终只占 1 个名额，实际 %d", cur)
	}
}

// 两个方向都安静了一个周期：会话照样被摘掉、名额还回来——放宽口径不能变成永不回收。
func TestUDPSessionDroppedWhenBothSidesIdle(t *testing.T) {
	sink, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer sink.Close()

	var g connGate
	port := startShortIdleUDPRunner(t, &g, sink.LocalAddr().(*net.UDPAddr).Port)
	client, err := net.Dial("udp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if _, err := client.Write([]byte("once")); err != nil {
		t.Fatal(err)
	}
	waitCur(t, &g, 1, "会话建立后")
	waitCur(t, &g, 0, "两头都空闲之后")
}
