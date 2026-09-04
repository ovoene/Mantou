package webhook

import (
	"net"
	"strconv"
	"strings"
	"testing"

	"mantou/internal/config"
	"mantou/internal/logx"
	"mantou/internal/runstats"
)

// 本文件盯的是端口的交接：80 / 443 上面板、Web 服务、消息路由都想监听，
// 而一个端口只能被一个 net.Listener 持有，于是有了「Web 服务持有监听、
// 本模块出让端口并交出 Handler」这条路。
//
// 交接错了不会有人报错，只会静默地没有监听：
// 松手松错了端口 → 该转发的没转、原来那条也被关掉；
// 共用时仍自己去绑 → 绑不上，Status 说"启动失败"，用户去查证书和防火墙。

// listenModule 起一个不注入出站能力的模块，只用来观察监听的启停。
func listenModule(t *testing.T) *Module {
	t.Helper()
	m := New(logx.New(logx.Options{}), runstats.New(), "")
	t.Cleanup(func() { _ = m.Close() })
	return m
}

// holdsListener 直接看 m.srv：判断"这个端口到底在谁手里"不该依赖 Status 的措辞。
func holdsListener(m *Module) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.srv != nil
}

func lastErrOf(m *Module) string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.lastErr
}

// bindFreePort 让模块真在一个内核挑的空闲端口上起监听，返回该端口与用上的配置。
//
// 探测（listen :0 后立刻 close）与模块自己绑之间有一个极小的抢占窗口，
// 抢到了就换个端口重试——"端口恰好被别人占了"不该表现成用例失败。
// 绑 127.0.0.1 而不是 0.0.0.0：不惊动防火墙，也不暴露到局域网。
func bindFreePort(t *testing.T, m *Module) (int, *config.Config) {
	t.Helper()
	for i := 0; i < 5; i++ {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		port := ln.Addr().(*net.TCPAddr).Port
		_ = ln.Close()

		cfg := &config.Config{
			Panel:   config.Panel{Port: 25666},
			Webhook: config.WebhookServer{Enabled: true, Listen: "127.0.0.1", Port: port},
		}
		if err := m.Reload(cfg); err != nil {
			t.Fatalf("Reload 不该整体失败（绑不上只记 lastErr）：%v", err)
		}
		if holdsListener(m) {
			return port, cfg
		}
	}
	t.Fatal("连续 5 次都没能在空闲端口上起监听")
	return 0, nil
}

// ReleasePort 是 Web 服务在绑定前发来的一问：只有"我确实正持着这个端口"才该松手。
// 认错了端口就是白关一条好监听——而调用方拿到 true 会以为端口已经腾出来了。
func TestReleasePortOnlyWhenHolding(t *testing.T) {
	m := listenModule(t)
	port, cfg := bindFreePort(t, m)

	if m.ReleasePort(port + 1) {
		t.Fatal("被问到别的端口时不该答应")
	}
	if !holdsListener(m) {
		t.Fatal("问错端口不该动本模块的监听")
	}

	if !m.ReleasePort(port) {
		t.Fatal("正持着这个端口时应答应让出")
	}
	if holdsListener(m) {
		t.Fatal("答应了就必须真的把监听关掉")
	}
	// 端口必须真的空出来，否则 Web 服务紧接着的绑定还是失败。
	probe, err := net.Listen("tcp", net.JoinHostPort(cfg.Webhook.Listen, strconv.Itoa(port)))
	if err != nil {
		t.Fatalf("让出后端口应可被别人绑：%v", err)
	}
	_ = probe.Close()

	// 已经让出来了再问一次要答 false：Web 服务每轮重载都会问，
	// 答 true 会让日志上出现一次不存在的"让出端口"。
	if m.ReleasePort(port) {
		t.Fatal("手里没有监听时不该答应")
	}

	// 让出端口只是这一轮的临时状态。若配置其实并不共用（这里就没有 Web 服务），
	// 本模块随后的重载必须把监听拿回来，否则端口就一直空着没人听。
	if err := m.Reload(cfg); err != nil {
		t.Fatalf("Reload 失败: %v", err)
	}
	if !holdsListener(m) {
		t.Fatalf("配置未共用，重载应重新监听，lastErr=%q", lastErrOf(m))
	}
}

// 用户把 Web 服务也配到同一个端口（典型就是 443）时，端口的持有者要从本模块
// 换成 Web 服务：本模块必须自己先松手并且不再去绑，只留下 Handler 等着被转发。
func TestSharedPortReleasesOwnListen(t *testing.T) {
	m := listenModule(t)
	port, cfg := bindFreePort(t, m)

	cfg.Webhook.Domain = "hook.example.com"
	cfg.WebServices = []config.WebService{{
		ID: "ws1", Name: "官网", Enabled: true, Port: port, IPFamily: "v4",
		Children: []config.WebChild{{
			ID: "ch1", Enabled: true, Type: "redirect", Domains: []string{"www.example.com"},
			Redirect: config.WebRedirect{Target: "https://example.com"},
		}},
	}}
	if !cfg.WebhookSharesWebServicePort() {
		t.Fatal("这份配置应判定为共用端口，否则本用例测不到那条路")
	}
	if err := m.Reload(cfg); err != nil {
		t.Fatalf("Reload 失败: %v", err)
	}

	if holdsListener(m) {
		t.Fatal("共用端口时本模块不该自己持有监听")
	}
	if e := lastErrOf(m); e != "" {
		t.Fatalf("共用不是错误，不该留下 lastErr：%q", e)
	}
	// 端口留给 Web 服务：它的重载排在本模块之前，这时端口必须已经是空的。
	probe, err := net.Listen("tcp", net.JoinHostPort(cfg.Webhook.Listen, strconv.Itoa(port)))
	if err != nil {
		t.Fatalf("共用后端口应归 Web 服务绑：%v", err)
	}
	_ = probe.Close()

	// 没有自己的 Listener，健康判断不能按"在不在监听"算——那会一直报不健康。
	st := m.Status()
	if !st.Healthy {
		t.Fatalf("共用端口不该判为不健康：code=%q args=%v", st.Code, st.Args)
	}
	// 断言的是键名与参数，不是拼好的句子：句子由前端按当前语言拼（见 module.Status.Code）。
	// 参数得逐个查——少一个 domain，界面上就成了"与 Web 服务共用，域名 "，
	// 而这恰恰是共用这条路上用户唯一需要知道的东西。
	if st.Code != "shared" {
		t.Fatalf("共用端口的状态键应为 shared，实际 %q", st.Code)
	}
	if got := st.Args["domain"]; got != cfg.Webhook.Domain {
		t.Fatalf("状态里应说明按哪个域名分流，domain=%v 期望 %q", got, cfg.Webhook.Domain)
	}
	if got, ok := st.Args["addr"].(string); !ok || !strings.Contains(got, strconv.Itoa(port)) {
		t.Fatalf("状态里应说明共用哪个地址，addr=%v 期望含端口 %d", st.Args["addr"], port)
	}
	// Handler 是共用这条路上唯一的入口，取不到就等于收不到任何消息。
	if m.Handler() == nil {
		t.Fatal("共用端口时必须能取到入站处理器")
	}
}
