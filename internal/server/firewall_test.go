package server

import (
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"mantou/internal/config"
	"mantou/internal/logx"
)

// 本文件钉住入站防火墙的判定语义。这些用例存在的理由不是"覆盖率"，
// 而是这道逻辑一旦悄悄走偏，症状要么是"防了个寂寞"，要么是"把人锁在门外"——
// 两种都不会在日常使用里暴露出来。

// firewallOff 把入站防火墙关掉，供那些"验的是别的东西"的用例在建路由前调用。
//
// 新装默认是"仅局域网"，而 httptest.NewRequest 造出来的对端固定是 192.0.2.1:1234
// （RFC 5737 的文档地址段，按外网算），于是所有沿用它的既有用例都会先吃一个 403。
// 把这些 fixture 显式关掉，比让它们隐式依赖某个默认值更清楚；防火墙自身的判定在本文件
// 逐条验，它在中间件链上的位置由 TestFirewallGuardInMiddlewareChain 验。
func firewallOff(t *testing.T, m *config.Manager) {
	t.Helper()
	if err := m.Update(func(cfg *config.Config) {
		cfg.Settings.Security.Firewall.Enabled = false
	}); err != nil {
		t.Fatal(err)
	}
}

func newTestFirewall(t *testing.T, fw config.PanelFirewall) *panelFirewall {
	t.Helper()
	m := config.NewManager(filepath.Join(t.TempDir(), "config.json"))
	if err := m.Load(); err != nil {
		t.Fatal(err)
	}
	if err := m.Update(func(cfg *config.Config) {
		cfg.Settings.Security.Firewall = fw
	}); err != nil {
		t.Fatal(err)
	}
	return newPanelFirewall(m, logx.New(logx.Options{}))
}

// TestFirewallDecideOrder 判定顺序是这份设计的核心，逐条钉死。
func TestFirewallDecideOrder(t *testing.T) {
	cases := []struct {
		name string
		fw   config.PanelFirewall
		ip   string
		want fwVerdict
	}{
		{
			name: "关闭时一律放行",
			fw:   config.PanelFirewall{Enabled: false, Mode: config.FirewallModeLAN},
			ip:   "203.0.113.5",
			want: fwPass,
		},
		{
			name: "仅局域网：外网被拒",
			fw:   config.PanelFirewall{Enabled: true, Mode: config.FirewallModeLAN},
			ip:   "203.0.113.5",
			want: fwDenyScope,
		},
		{
			name: "仅局域网：私有地址放行",
			fw:   config.PanelFirewall{Enabled: true, Mode: config.FirewallModeLAN},
			ip:   "192.168.1.20",
			want: fwPass,
		},
		{
			name: "不限来源：外网放行",
			fw:   config.PanelFirewall{Enabled: true, Mode: config.FirewallModeAll},
			ip:   "203.0.113.5",
			want: fwPass,
		},
		{
			// 允许名单先于 Mode——「只允许局域网 + 放行我的办公室 IP」必须是可表达的策略。
			name: "允许名单越过仅局域网",
			fw: config.PanelFirewall{
				Enabled: true, Mode: config.FirewallModeLAN,
				AllowIPs: []string{"203.0.113.5"},
			},
			ip:   "203.0.113.5",
			want: fwPass,
		},
		{
			// 拒绝优先于允许：两张名单矛盾时，拦下是那个可以事后放开的选择。
			name: "拒绝名单压过允许名单",
			fw: config.PanelFirewall{
				Enabled: true, Mode: config.FirewallModeAll,
				AllowIPs: []string{"203.0.113.5"},
				DenyIPs:  []string{"203.0.113.5"},
			},
			ip:   "203.0.113.5",
			want: fwDenyList,
		},
		{
			// 回环是最后的自救通道，不受 Mode 影响。
			name: "回环在仅局域网下放行",
			fw:   config.PanelFirewall{Enabled: true, Mode: config.FirewallModeLAN},
			ip:   "127.0.0.1",
			want: fwPass,
		},
		{
			// 但它救不了"用户明确把它写进了拒绝名单"——那是人做的决定。
			name: "回环仍受拒绝名单约束",
			fw: config.PanelFirewall{
				Enabled: true, Mode: config.FirewallModeAll,
				DenyIPs: []string{"127.0.0.1"},
			},
			ip:   "127.0.0.1",
			want: fwDenyList,
		},
		{
			name: "CIDR 拒绝名单",
			fw: config.PanelFirewall{
				Enabled: true, Mode: config.FirewallModeAll,
				DenyIPs: []string{"203.0.113.0/24"},
			},
			ip:   "203.0.113.77",
			want: fwDenyList,
		},
		{
			// 运营商级 NAT 不算局域网：那是 ISP 的地址池，算进来等于对一整批订户开门。
			name: "CGNAT 不算局域网",
			fw:   config.PanelFirewall{Enabled: true, Mode: config.FirewallModeLAN},
			ip:   "100.64.0.9",
			want: fwDenyScope,
		},
		{
			name: "IPv6 私有地址算局域网",
			fw:   config.PanelFirewall{Enabled: true, Mode: config.FirewallModeLAN},
			ip:   "fd00::1",
			want: fwPass,
		},
		{
			name: "IPv6 公网地址被拒",
			fw:   config.PanelFirewall{Enabled: true, Mode: config.FirewallModeLAN},
			ip:   "2001:db8::1",
			want: fwDenyScope,
		},
		{
			// ::ffff: 前缀是同一个地址的另一种写法，不能靠它绕过范围判定。
			name: "IPv4 映射地址按 IPv4 判定",
			fw:   config.PanelFirewall{Enabled: true, Mode: config.FirewallModeLAN},
			ip:   "::ffff:203.0.113.5",
			want: fwDenyScope,
		},
		{
			name: "IPv4 映射的私有地址仍算局域网",
			fw:   config.PanelFirewall{Enabled: true, Mode: config.FirewallModeLAN},
			ip:   "::ffff:192.168.1.20",
			want: fwPass,
		},
		{
			// 认不出的 Mode 必须落到更严的那一侧。规范化保证只存 lan / all，但
			// config.Manager.Update 不跑 migrate，这条不变量靠每个写入方自觉；
			// 一旦有人漏了，按 == lan 写就会让整道范围判定静默失效（见 decide 的注释）。
			name: "认不出的 Mode 按仅局域网处理",
			fw:   config.PanelFirewall{Enabled: true, Mode: "wide-open"},
			ip:   "203.0.113.5",
			want: fwDenyScope,
		},
		{
			name: "空 Mode 同样按仅局域网处理",
			fw:   config.PanelFirewall{Enabled: true, Mode: ""},
			ip:   "203.0.113.5",
			want: fwDenyScope,
		},
		{
			// 认不出的 Mode 只收紧范围，不该顺带把局域网也拦了。
			name: "认不出的 Mode 不影响局域网来源",
			fw:   config.PanelFirewall{Enabled: true, Mode: "wide-open"},
			ip:   "192.168.1.20",
			want: fwPass,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newTestFirewall(t, tc.fw)
			got := f.decide(f.current(), net.ParseIP(tc.ip))
			if got != tc.want {
				t.Fatalf("decide(%s) = %v, want %v", tc.ip, got.reason(), tc.want.reason())
			}
		})
	}
}

// TestFirewallDecideFailsClosed 对端地址解析不出来时必须拒绝。
// 放行的话，一个畸形 RemoteAddr 就等于把整道防火墙绕过去。
func TestFirewallDecideFailsClosed(t *testing.T) {
	f := newTestFirewall(t, config.PanelFirewall{Enabled: true, Mode: config.FirewallModeAll})
	if got := f.decide(f.current(), nil); got != fwDenyNoIP {
		t.Fatalf("nil IP 应被拒绝，实际 %v", got.reason())
	}
}

// TestFirewallAutoBan 攒够阈值才封，封后 decide 立刻拒绝。
func TestFirewallAutoBan(t *testing.T) {
	f := newTestFirewall(t, config.PanelFirewall{
		Enabled: true, Mode: config.FirewallModeAll,
		AutoBan: true, AutoBanThreshold: 3, AutoBanMinutes: 10,
	})
	lists := f.current()
	ip := net.ParseIP("203.0.113.5")

	for i := 1; i < 3; i++ {
		if f.strike(lists, ip, ip.String()) {
			t.Fatalf("第 %d 次超限就封禁了，阈值是 3", i)
		}
		if f.decide(lists, ip) != fwPass {
			t.Fatalf("第 %d 次超限后不应被拒", i)
		}
	}
	if !f.strike(lists, ip, ip.String()) {
		t.Fatal("达到阈值应产生封禁")
	}
	if got := f.decide(lists, ip); got != fwDenyBanned {
		t.Fatalf("封禁后 decide = %v，应为 auto-ban", got.reason())
	}
	if n := f.banCount(); n != 1 {
		t.Fatalf("生效封禁数 = %d，应为 1", n)
	}
	// 已封禁期间再超限不应重复产生"新封禁"（否则告警会按请求数刷屏）。
	if f.strike(lists, ip, ip.String()) {
		t.Fatal("封禁期间不应重复报告新封禁")
	}
}

// TestFirewallAutoBanSkipsAllowAndLoopback 明示压过推测：
// 加白的来源与本机永不被机器关在门外。
func TestFirewallAutoBanSkipsAllowAndLoopback(t *testing.T) {
	f := newTestFirewall(t, config.PanelFirewall{
		Enabled: true, Mode: config.FirewallModeAll,
		AllowIPs: []string{"203.0.113.5"},
		AutoBan:  true, AutoBanThreshold: 1, AutoBanMinutes: 10,
	})
	lists := f.current()
	for _, raw := range []string{"203.0.113.5", "127.0.0.1", "::1"} {
		ip := net.ParseIP(raw)
		if f.strike(lists, ip, raw) {
			t.Fatalf("%s 不应被自动封禁", raw)
		}
	}
	if n := f.banCount(); n != 0 {
		t.Fatalf("封禁数 = %d，应为 0", n)
	}
}

// TestFirewallAutoBanExpires 封禁到期后自动失效——机器的误判必须能自愈。
func TestFirewallAutoBanExpires(t *testing.T) {
	f := newTestFirewall(t, config.PanelFirewall{
		Enabled: true, Mode: config.FirewallModeAll,
		AutoBan: true, AutoBanThreshold: 1, AutoBanMinutes: 10,
	})
	lists := f.current()
	ip := net.ParseIP("203.0.113.5")
	if !f.strike(lists, ip, ip.String()) {
		t.Fatal("阈值为 1，一次超限即应封禁")
	}
	// 直接把到期时间拨到过去，避免让测试真的等下去。
	f.mu.Lock()
	for _, e := range f.bans {
		e.until = time.Now().Add(-time.Second)
	}
	f.mu.Unlock()
	if got := f.decide(lists, ip); got != fwPass {
		t.Fatalf("封禁到期后应放行，实际 %v", got.reason())
	}
	if n := f.banCount(); n != 0 {
		t.Fatalf("到期后生效封禁数 = %d，应为 0", n)
	}
}

// TestFirewallBanTableBounded 封禁表的键由攻击者决定，条目数必须有硬上限。
func TestFirewallBanTableBounded(t *testing.T) {
	f := newTestFirewall(t, config.PanelFirewall{
		Enabled: true, Mode: config.FirewallModeAll,
		AutoBan: true, AutoBanThreshold: 1, AutoBanMinutes: 60,
	})
	lists := f.current()
	// 造出远多于上限的来源；IPv6 下这在现实中毫无成本。
	for i := 0; i < fwBanMaxEntries+500; i++ {
		ip := net.ParseIP("2001:db8::1")
		ip = ip.To16()
		ip[14] = byte(i >> 8)
		ip[15] = byte(i)
		f.strike(lists, ip, ip.String())
	}
	f.mu.Lock()
	n := len(f.bans)
	f.mu.Unlock()
	if n > fwBanMaxEntries {
		t.Fatalf("封禁表条目数 = %d，超过上限 %d", n, fwBanMaxEntries)
	}
}

// TestFirewallBanTableDrainsAfterAttack 攻击停下来之后，封禁表要能自己排空。
//
// 清扫原本只挂在 strike 上，而 strike 只在"有人被限速拦下"时才跑。攻击一停就没人再调它，
// 于是过期条目会一直留在表里、size 永远大于零，此后**每个正常请求**（以及每次 Accept）
// 都要为一张全是死条目的表抢一次锁——一次扫描留下的代价会长期挂在常态路径上。
func TestFirewallBanTableDrainsAfterAttack(t *testing.T) {
	f := newTestFirewall(t, config.PanelFirewall{
		Enabled: true, Mode: config.FirewallModeAll,
		AutoBan: true, AutoBanThreshold: 1, AutoBanMinutes: 10,
	})
	lists := f.current()
	for i := 0; i < 50; i++ {
		ip := net.ParseIP("2001:db8::1").To16()
		ip[15] = byte(i)
		f.strike(lists, ip, ip.String())
	}
	if n := f.size.Load(); n == 0 {
		t.Fatal("测试前提不成立：封禁表是空的")
	}

	// 让全部封禁与计数窗口都过期，并把清扫的最小间隔拨到过去（否则要等一分钟）。
	past := time.Now().Add(-2 * time.Hour)
	f.mu.Lock()
	for _, e := range f.bans {
		e.until = past
		e.firstHit = past
	}
	f.lastSweep = past
	f.mu.Unlock()

	// 攻击停了：此后只有正常请求，走的是 decide → isBanned，再也不会碰 strike。
	if got := f.decide(lists, net.ParseIP("198.51.100.4")); got != fwPass {
		t.Fatalf("正常来源应放行，实际 %v", got.reason())
	}
	if n := f.size.Load(); n != 0 {
		t.Fatalf("封禁表仍有 %d 条过期条目，常态路径会一直为它抢锁", n)
	}
	if n := f.banCount(); n != 0 {
		t.Fatalf("生效封禁数 = %d，应为 0", n)
	}
}

// TestFirewallUnbanAndClear 误伤必须能被解除。
func TestFirewallUnbanAndClear(t *testing.T) {
	f := newTestFirewall(t, config.PanelFirewall{
		Enabled: true, Mode: config.FirewallModeAll,
		AutoBan: true, AutoBanThreshold: 1, AutoBanMinutes: 60,
	})
	lists := f.current()
	a, b := net.ParseIP("203.0.113.5"), net.ParseIP("203.0.113.6")
	f.strike(lists, a, a.String())
	f.strike(lists, b, b.String())
	if n := f.banCount(); n != 2 {
		t.Fatalf("封禁数 = %d，应为 2", n)
	}
	if !f.unban("203.0.113.5") {
		t.Fatal("解除应报告该地址此前被封")
	}
	if got := f.decide(lists, a); got != fwPass {
		t.Fatalf("解除后应放行，实际 %v", got.reason())
	}
	if n := f.clearBans(); n != 1 {
		t.Fatalf("清空报告解除 %d 条，应为 1", n)
	}
	if got := f.decide(lists, b); got != fwPass {
		t.Fatalf("清空后应放行，实际 %v", got.reason())
	}
}

// TestFirewallRateLimit 限速按来源计量，0 表示不限。
func TestFirewallRateLimit(t *testing.T) {
	f := newTestFirewall(t, config.PanelFirewall{
		Enabled: true, Mode: config.FirewallModeAll, RateLimit: 3,
	})
	lists := f.current()
	allowed := 0
	for i := 0; i < 20; i++ {
		if f.allowRate(lists, "203.0.113.5") {
			allowed++
		}
	}
	if allowed == 0 || allowed >= 20 {
		t.Fatalf("放行 %d/20 次，限速看起来没有生效", allowed)
	}
	// 另一个来源不受牵连——按来源分桶，一个人刷不该把别人挡住。
	if !f.allowRate(lists, "203.0.113.6") {
		t.Fatal("其他来源不应受影响")
	}

	off := newTestFirewall(t, config.PanelFirewall{
		Enabled: true, Mode: config.FirewallModeAll, RateLimit: 0,
	})
	offLists := off.current()
	for i := 0; i < 100; i++ {
		if !off.allowRate(offLists, "203.0.113.5") {
			t.Fatal("RateLimit=0 应表示不限速")
		}
	}
}

// TestFirewallConfigHotReload 改设置立刻生效，不需要重启面板。
func TestFirewallConfigHotReload(t *testing.T) {
	m := config.NewManager(filepath.Join(t.TempDir(), "config.json"))
	if err := m.Load(); err != nil {
		t.Fatal(err)
	}
	if err := m.Update(func(cfg *config.Config) {
		cfg.Settings.Security.Firewall = config.PanelFirewall{Enabled: true, Mode: config.FirewallModeAll}
	}); err != nil {
		t.Fatal(err)
	}
	f := newPanelFirewall(m, logx.New(logx.Options{}))
	ip := net.ParseIP("203.0.113.5")
	if got := f.decide(f.current(), ip); got != fwPass {
		t.Fatalf("初始应放行，实际 %v", got.reason())
	}
	if err := m.Update(func(cfg *config.Config) {
		cfg.Settings.Security.Firewall.Mode = config.FirewallModeLAN
	}); err != nil {
		t.Fatal(err)
	}
	if got := f.decide(f.current(), ip); got != fwDenyScope {
		t.Fatalf("改为仅局域网后应拒绝，实际 %v", got.reason())
	}
}

// TestCheckFirewallLockout 自锁校验：拦下会切断自己的改动，但不拦不会的。
func TestCheckFirewallLockout(t *testing.T) {
	cases := []struct {
		name    string
		fw      config.PanelFirewall
		remote  string
		wantErr bool
	}{
		{
			name:    "外网改仅局域网会锁死自己",
			fw:      config.PanelFirewall{Enabled: true, Mode: config.FirewallModeLAN},
			remote:  "203.0.113.5:5000",
			wantErr: true,
		},
		{
			name: "外网但已加入允许名单",
			fw: config.PanelFirewall{
				Enabled: true, Mode: config.FirewallModeLAN,
				AllowIPs: []string{"203.0.113.5"},
			},
			remote:  "203.0.113.5:5000",
			wantErr: false,
		},
		{
			name: "把自己写进拒绝名单",
			fw: config.PanelFirewall{
				Enabled: true, Mode: config.FirewallModeAll,
				DenyIPs: []string{"192.168.1.20"},
			},
			remote:  "192.168.1.20:5000",
			wantErr: true,
		},
		{
			name:    "局域网内改仅局域网没问题",
			fw:      config.PanelFirewall{Enabled: true, Mode: config.FirewallModeLAN},
			remote:  "192.168.1.20:5000",
			wantErr: false,
		},
		{
			name:    "本机操作永远不会被锁",
			fw:      config.PanelFirewall{Enabled: true, Mode: config.FirewallModeLAN},
			remote:  "127.0.0.1:5000",
			wantErr: false,
		},
		{
			name:    "防火墙关闭时不校验",
			fw:      config.PanelFirewall{Enabled: false, Mode: config.FirewallModeLAN},
			remote:  "203.0.113.5:5000",
			wantErr: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPut, "/api/settings", nil)
			r.RemoteAddr = tc.remote
			err := checkFirewallLockout(tc.fw, r)
			if tc.wantErr && err == nil {
				t.Fatal("应当拦下这次改动")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("不应拦下：%v", err)
			}
		})
	}
}

// TestFirewallListenerRejects 连接层拦截：被拒的连接被关掉，且**不能**把错误
// 抛给 http.Server——那会让整个服务退出。
func TestFirewallListenerRejects(t *testing.T) {
	f := newTestFirewall(t, config.PanelFirewall{
		Enabled: true, Mode: config.FirewallModeAll,
		DenyIPs: []string{"127.0.0.1", "::1"},
	})
	base, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer base.Close()
	ln := f.wrapListener(base)

	accepted := make(chan net.Conn, 1)
	go func() {
		c, aerr := ln.Accept()
		if aerr != nil {
			close(accepted)
			return
		}
		accepted <- c
	}()

	c, err := net.Dial("tcp", base.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	select {
	case got, ok := <-accepted:
		if ok {
			got.Close()
			t.Fatal("来自拒绝名单的连接不应被 Accept 返回")
		}
		t.Fatal("Accept 不应返回错误——那会让 http.Server 退出")
	case <-time.After(300 * time.Millisecond):
		// 期望路径：连接被静默关掉，Accept 仍在等下一个。
	}
}

// TestFirewallGuardInMiddlewareChain 验的不是判定本身（上面逐条验过了），而是这道闸
// 确实接在 New 构建出来的那条中间件链上、且接在鉴权之前：
//
//   - 外网对端连登录页都摸不到，拿到的是 403，而不是登录页或 401；
//   - 回环对端照常往下走，不会被这道闸误伤。
//
// 之所以要单独钉这一条：其余 fixture 为了验别的东西都调了 firewallOff，
// 若少了这一条，"防火墙从中间件链里掉出去"就没有任何用例会红。
func TestFirewallGuardInMiddlewareChain(t *testing.T) {
	manager := config.NewManager(filepath.Join(t.TempDir(), "config.json"))
	if err := manager.Load(); err != nil {
		t.Fatal(err)
	}
	// 不调 firewallOff：这里要的就是新装默认（启用 + 仅局域网）。
	if fw := manager.Get().Settings.Security.Firewall; !fw.Enabled || fw.Mode != config.FirewallModeLAN {
		t.Fatalf("测试前提不成立：新装默认应为启用 + 仅局域网，实际 enabled=%v mode=%q", fw.Enabled, fw.Mode)
	}
	s := New(Deps{Config: manager, Log: logx.New(logx.Options{})})
	engine, ok := s.http.Handler.(*gin.Engine)
	if !ok {
		t.Fatalf("面板 Handler 不是 *gin.Engine，而是 %T", s.http.Handler)
	}

	// 未初始化的面板：装机接口是全站唯一匿名可达的写接口，正好用来验"闸在鉴权之前"。
	for _, tc := range []struct {
		name   string
		remote string
		want   bool // true = 应当被防火墙拦下
	}{
		{name: "外网对端被拦", remote: "203.0.113.5:40001", want: true},
		{name: "httptest 默认对端也算外网", remote: "", want: true},
		{name: "回环对端放行", remote: "127.0.0.1:40002", want: false},
		{name: "局域网对端放行", remote: "192.168.1.20:40003", want: false},
		// 带 %zone 的链路本地对端：连接层拿 TCPAddr.IP（不带 zone）判成局域网放行，
		// 请求层若解析不出地址就会按失败关闭回 403——两层判得不一样。见 ipx.stripZone。
		{name: "带 zone 的链路本地对端放行", remote: "[fe80::1%eth0]:40004", want: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/api/init/status", nil)
			if tc.remote != "" {
				req.RemoteAddr = tc.remote
			}
			rec := httptest.NewRecorder()
			engine.ServeHTTP(rec, req)
			blocked := rec.Code == http.StatusForbidden
			if blocked != tc.want {
				t.Fatalf("期望拦下=%v，实际状态码 %d，body=%s", tc.want, rec.Code, rec.Body.String())
			}
		})
	}
}
