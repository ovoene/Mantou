package inboundfw

import (
	"bytes"
	"fmt"
	"log"
	"net"
	"path/filepath"
	"testing"
	"time"

	"mantou/internal/config"
	"mantou/internal/ipx"
	"mantou/internal/logx"
)

// 本文件钉住服务防护（连接层）的运行态语义。这些用例存在的理由不是覆盖率，
// 而是这道逻辑走偏之后的两种症状——"防了个寂寞"与"把人锁在门外"——在日常使用里
// 都不会暴露：前者没有任何日志，后者的表现是"连不上"，跟服务没起来一模一样。
//
// 优先钉的是**已经犯过的错**：
//   - Note → ban → logBan → BanCount 自锁（sync.Mutex 不可重入，当场永久死锁，
//     卡住的是所有入站连接的判定路径）→ TestNoteBanDoesNotDeadlock
//   - IPv6 握手行解析出 "[2001" 然后静默失败，整个地址族的自动封禁失效 → TestParseHandshakeIP
//   - WrapErrorLog 把"是否启用"焊死在监听器创建的那一刻 → TestWrapErrorLogNoEnableLatch
//   - BanList 在锁内跑 O(n²) 插入排序，打开一次业务页就让入站停顿数秒 → TestBanSnapshot*

// newTestFW 造一个带指定策略的防火墙。返回的 Manager 供用例在运行中改配置，
// 用来验"设置一保存就生效、不需要重启监听器"这条设计主张。
func newTestFW(t *testing.T, gf config.GlobalFirewall) (*Firewall, *config.Manager) {
	t.Helper()
	m := config.NewManager(filepath.Join(t.TempDir(), "config.json"))
	if err := m.Load(); err != nil {
		t.Fatal(err)
	}
	setPolicy(t, m, gf)
	return New(m, logx.New(logx.Options{})), m
}

func setPolicy(t *testing.T, m *config.Manager, gf config.GlobalFirewall) {
	t.Helper()
	if err := m.Update(func(cfg *config.Config) { cfg.GlobalFirewall = gf }); err != nil {
		t.Fatal(err)
	}
}

// policy 一份"开着、自动封禁开着、走自定义档位"的基准策略。
//
// 刻意用 custom 档位：预设档位下数值由服务端重写（那正是 config 层的设计），
// 而这里要验的是运行态怎么用这些数值，因此必须能精确指定它们。
//
// 两个窗口默认都给到"够不着"的阈值，各用例只放开自己要验的那一个——
// 否则一次 Note 同时喂两个窗口，测出来的是哪个先触发全靠数字巧合。
func policy() config.GlobalFirewall {
	return config.GlobalFirewall{
		Enabled: true, Level: config.GlobalFirewallLevelCustom, AutoBan: true,
		WindowSeconds: 60, WindowLimit: config.MaxGlobalFirewallLimit,
		BurstSeconds: 3, BurstLimit: config.MaxGlobalFirewallLimit,
		BanMinutes: 10, MemoryMB: config.DefaultGlobalFirewallMemoryMB,
	}
}

// ip 便捷解析，测试里地址都是写死的字面量。
func ip(s string) net.IP {
	p := net.ParseIP(s)
	if p == nil {
		panic("测试用例里的 IP 写错了: " + s)
	}
	return p
}

// banNow 直接往封禁表里塞一条已生效的封禁，供只关心"判定/展示"的用例用。
// 走 Note 需要凑够阈值，与被验的东西无关。
func banNow(f *Firewall, raw string, until time.Time, rounds int) {
	p := ip(raw)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.bans[ipx.Key(p)] = &entry{
		ip: p.String(), firstHit: time.Now(), burstAt: time.Now(),
		bannedAt: until.Add(-time.Minute), until: until, banRound: rounds,
	}
	f.size.Store(int32(len(f.bans)))
}

// ---------------------------------------------------------------------------
// 死锁回归
// ---------------------------------------------------------------------------

// TestNoteBanDoesNotDeadlock 产生一条新封禁的 Note 必须能返回。
//
// 这是那个 P0 的回归防线：原先 ban() 在持有 f.mu 时调 logBan，而 logBan 要读
// "当前生效条数"（BanCount，自己也取 f.mu）。sync.Mutex 不可重入，于是**第一次
// 触发封禁**就当场永久死锁，f.mu 再也放不开——之后每一个 Accept 的 isBanned 都会
// 挂在上面，Web 服务与消息路由的入站连接一起停摆。
//
// 用例必须带自己的超时：死锁下 Note 永不返回，没有超时的话表现是整个 go test 挂住
// 十分钟然后被框架 panic 掉，看不出是哪一条。
func TestNoteBanDoesNotDeadlock(t *testing.T) {
	gf := policy()
	gf.BurstLimit = 2 // 两次握手异常即封
	f, _ := newTestFW(t, gf)

	done := make(chan bool, 1)
	go func() {
		f.Note(ip("203.0.113.9"), "tls-handshake")
		done <- f.Note(ip("203.0.113.9"), "tls-handshake") // 这一次会触发封禁 + 打日志
	}()

	select {
	case banned := <-done:
		if !banned {
			t.Fatal("第二次 Note 应触发封禁并返回 true")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Note 在触发封禁时没有返回——极可能是 f.mu 自锁（logBan 在锁内读 BanCount）")
	}

	// 封禁真的落下了，而不是"返回了 true 但表里什么都没有"。
	if !f.isBanned(ip("203.0.113.9")) {
		t.Fatal("Note 报告了封禁，但封禁表里查不到")
	}
	if n := f.BanCount(); n != 1 {
		t.Fatalf("生效封禁数 = %d，应为 1", n)
	}
}

// TestBanCountAndSnapshotAfterBanDoNotDeadlock 打完日志之后这两个读接口仍能拿到锁。
// 死锁的另一种可能形态是"锁被泄漏"：Note 返回了，但 f.mu 没放回来。
func TestBanCountAndSnapshotAfterBanDoNotDeadlock(t *testing.T) {
	gf := policy()
	gf.BurstLimit = 1
	f, _ := newTestFW(t, gf)
	f.Note(ip("203.0.113.10"), "tls-handshake")

	done := make(chan int, 1)
	go func() {
		_, total := f.BanSnapshot(10)
		done <- total + f.BanCount()
	}()
	select {
	case got := <-done:
		if got != 2 { // 1（快照总数）+ 1（计数）
			t.Fatalf("封禁读接口结果 = %d，应为 2", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Note 之后 f.mu 没有被释放")
	}
}

// ---------------------------------------------------------------------------
// 判定顺序
// ---------------------------------------------------------------------------

// TestDecideOrder 判定顺序是这份设计的核心，逐条钉死：
// 拒绝名单 → 局域网/回环豁免 → 允许名单 → 自动封禁 → 放行。
func TestDecideOrder(t *testing.T) {
	cases := []struct {
		name   string
		mut    func(*config.GlobalFirewall)
		ip     string
		banned string // 非空则预先把这个 IP 塞进封禁表
		want   gfVerdict
	}{
		{
			name: "关闭时一律放行",
			mut:  func(g *config.GlobalFirewall) { g.Enabled = false; g.DenyIPs = []string{"203.0.113.5"} },
			ip:   "203.0.113.5",
			want: gfPass,
		},
		{
			name: "命中拒绝名单",
			mut:  func(g *config.GlobalFirewall) { g.DenyIPs = []string{"203.0.113.0/24"} },
			ip:   "203.0.113.5",
			want: gfDenyList,
		},
		{
			// 拒绝名单压过局域网豁免：它是用户明确写下的"这个不许进"，
			// 任何自动规则都不该把它推翻。
			name: "拒绝名单压过局域网豁免",
			mut:  func(g *config.GlobalFirewall) { g.DenyIPs = []string{"192.168.1.7"} },
			ip:   "192.168.1.7",
			want: gfDenyList,
		},
		{
			name: "拒绝名单压过回环豁免",
			mut:  func(g *config.GlobalFirewall) { g.DenyIPs = []string{"127.0.0.1"} },
			ip:   "127.0.0.1",
			want: gfDenyList,
		},
		{
			// 局域网豁免跳过自动封禁：内网的探活/健康检查/未配好证书的客户端天然
			// 会持续制造握手失败，封掉它们的后果是整站从负载均衡里消失（见 decide 第 2 条）。
			name: "局域网豁免自动封禁",
			mut:  func(g *config.GlobalFirewall) {},
			ip:   "10.1.2.3", banned: "10.1.2.3",
			want: gfPass,
		},
		{
			name: "回环豁免自动封禁",
			mut:  func(g *config.GlobalFirewall) {},
			ip:   "127.0.0.1", banned: "127.0.0.1",
			want: gfPass,
		},
		{
			// 明示压过推测：加白之后仍被机器关在门外是最难自查的一种故障。
			name: "允许名单压过自动封禁",
			mut:  func(g *config.GlobalFirewall) { g.AllowIPs = []string{"203.0.113.5"} },
			ip:   "203.0.113.5", banned: "203.0.113.5",
			want: gfPass,
		},
		{
			name: "命中自动封禁",
			mut:  func(g *config.GlobalFirewall) {},
			ip:   "203.0.113.5", banned: "203.0.113.5",
			want: gfDenyBanned,
		},
		{
			name: "干净的外网地址放行",
			mut:  func(g *config.GlobalFirewall) {},
			ip:   "198.51.100.7",
			want: gfPass,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gf := policy()
			tc.mut(&gf)
			f, _ := newTestFW(t, gf)
			if tc.banned != "" {
				banNow(f, tc.banned, time.Now().Add(time.Hour), 1)
			}
			if got := f.decide(f.current(), ip(tc.ip)); got != tc.want {
				t.Fatalf("decide(%s) = %s，应为 %s", tc.ip, got.reason(), tc.want.reason())
			}
		})
	}
}

// TestDecideNoIPFailsClosed 拿不到对端 IP 时必须拒绝。
// 放行的话，一个畸形的 RemoteAddr 就等于把整道防火墙绕过去。
func TestDecideNoIPFailsClosed(t *testing.T) {
	f, _ := newTestFW(t, policy())
	if got := f.decide(f.current(), nil); got != gfDenyNoIP {
		t.Fatalf("对端 IP 为 nil 时 = %s，应为失败关闭", got.reason())
	}
	// 但关闭状态下连这一条也不该拦：关掉就是关掉。
	gf := policy()
	gf.Enabled = false
	off, _ := newTestFW(t, gf)
	if got := off.decide(off.current(), nil); got != gfPass {
		t.Fatalf("关闭状态下 nil IP = %s，应放行", got.reason())
	}
}

// TestConfigChangeTakesEffectWithoutRestart 改配置立刻生效，不需要重建防火墙。
// 这是"不重启监听器也能改"这条设计主张的直接验证（名单缓存靠快照指针失效）。
func TestConfigChangeTakesEffectWithoutRestart(t *testing.T) {
	f, m := newTestFW(t, policy())
	if got := f.decide(f.current(), ip("203.0.113.5")); got != gfPass {
		t.Fatalf("初始应放行，实际 %s", got.reason())
	}
	gf := policy()
	gf.DenyIPs = []string{"203.0.113.5"}
	setPolicy(t, m, gf)
	if got := f.decide(f.current(), ip("203.0.113.5")); got != gfDenyList {
		t.Fatalf("加入拒绝名单后应拦下，实际 %s——名单缓存没跟着快照失效", got.reason())
	}
	gf.Enabled = false
	setPolicy(t, m, gf)
	if got := f.decide(f.current(), ip("203.0.113.5")); got != gfPass {
		t.Fatalf("关掉开关后应放行，实际 %s", got.reason())
	}
}

// ---------------------------------------------------------------------------
// 计数与封禁
// ---------------------------------------------------------------------------

// TestNoteGates Note 的四道前置闸门：总开关、自动封禁开关、局域网、允许名单。
// 任何一道漏掉都不会报错，只会让一批不该被封的地址进入计数。
func TestNoteGates(t *testing.T) {
	cases := []struct {
		name string
		mut  func(*config.GlobalFirewall)
		ip   string
	}{
		{"总开关关闭", func(g *config.GlobalFirewall) { g.Enabled = false }, "203.0.113.5"},
		{"自动封禁关闭", func(g *config.GlobalFirewall) { g.AutoBan = false }, "203.0.113.5"},
		{"局域网地址", func(g *config.GlobalFirewall) {}, "192.168.1.7"},
		{"回环地址", func(g *config.GlobalFirewall) {}, "127.0.0.1"},
		{"允许名单内", func(g *config.GlobalFirewall) { g.AllowIPs = []string{"203.0.113.5"} }, "203.0.113.5"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gf := policy()
			gf.BurstLimit = 1 // 一次就该封——除非闸门拦住了
			tc.mut(&gf)
			f, _ := newTestFW(t, gf)
			for i := 0; i < 5; i++ {
				if f.Note(ip(tc.ip), "tls-handshake") {
					t.Fatalf("%s 不该产生封禁", tc.name)
				}
			}
			f.mu.Lock()
			n := len(f.bans)
			f.mu.Unlock()
			if n != 0 {
				t.Fatalf("%s 不该在封禁表里留下计数条目，实际 %d 条", tc.name, n)
			}
		})
	}
}

// TestNoteNilIP nil IP 不计数也不 panic（错误回灌那条链路解析失败时会传 nil）。
func TestNoteNilIP(t *testing.T) {
	f, _ := newTestFW(t, policy())
	if f.Note(nil, "tls-handshake") {
		t.Fatal("nil IP 不该产生封禁")
	}
}

// TestNoteBurstWindow 突发窗口：短时间内攒够 BurstLimit 次即封。
func TestNoteBurstWindow(t *testing.T) {
	gf := policy()
	gf.BurstLimit = 3
	f, _ := newTestFW(t, gf)
	for i := 1; i <= 2; i++ {
		if f.Note(ip("203.0.113.5"), "tls-handshake") {
			t.Fatalf("第 %d 次就封禁了，阈值是 3", i)
		}
	}
	if !f.Note(ip("203.0.113.5"), "tls-handshake") {
		t.Fatal("第 3 次应触发封禁")
	}
}

// TestNoteRegularWindow 常规窗口：慢速枚举靠它兜住（突发阈值够不着时）。
func TestNoteRegularWindow(t *testing.T) {
	gf := policy()
	gf.WindowLimit = 3
	f, _ := newTestFW(t, gf)
	l := f.current()
	now := time.Now()
	// 每次间隔超过突发窗口，于是突发计数每次都被重置，只有常规窗口在累积。
	for i := 1; i <= 2; i++ {
		if f.note(l, ip("203.0.113.5"), now.Add(time.Duration(i)*10*time.Second)) {
			t.Fatalf("第 %d 次就封禁了，常规阈值是 3", i)
		}
	}
	if !f.note(l, ip("203.0.113.5"), now.Add(30*time.Second)) {
		t.Fatal("常规窗口内第 3 次应触发封禁")
	}
}

// TestNoteWindowResets 窗口是**滑动重置**而不是滑动窗口：距上次计数起点超过窗口就从头再数。
// 少了这一条，一个每小时失败一次的老客户端攒够几天也会被封。
func TestNoteWindowResets(t *testing.T) {
	gf := policy()
	gf.WindowLimit = 3
	gf.WindowSeconds = 60
	f, _ := newTestFW(t, gf)
	l := f.current()
	now := time.Now()
	f.note(l, ip("203.0.113.5"), now)                     // strikes=1
	f.note(l, ip("203.0.113.5"), now.Add(10*time.Second)) // strikes=2
	f.note(l, ip("203.0.113.5"), now.Add(2*time.Minute))  // 超过窗口 → 重置为 1
	if f.note(l, ip("203.0.113.5"), now.Add(2*time.Minute+10*time.Second)) {
		t.Fatal("窗口过期后计数应从头再数，不该在这一次就封禁")
	}
}

// TestNoteWhileBannedRefreshesCounters 已经封着时继续踩不再重复封禁，但会刷新计数窗口，
// 好让解封后紧接着的下一轮不必继承旧的起点。
func TestNoteWhileBannedRefreshesCounters(t *testing.T) {
	gf := policy()
	gf.BurstLimit = 2
	f, _ := newTestFW(t, gf)
	l := f.current()
	now := time.Now()
	f.note(l, ip("203.0.113.5"), now)
	if !f.note(l, ip("203.0.113.5"), now.Add(time.Second)) {
		t.Fatal("第 2 次应触发封禁")
	}
	if f.note(l, ip("203.0.113.5"), now.Add(2*time.Second)) {
		t.Fatal("封禁期内不该再产生一条新封禁")
	}
	f.mu.Lock()
	e := f.bans[ipx.Key(ip("203.0.113.5"))]
	strikes, burst := e.strikes, e.burst
	f.mu.Unlock()
	if strikes != 0 || burst != 0 {
		t.Fatalf("封禁期内的计数应被清零，实际 strikes=%d burst=%d", strikes, burst)
	}
}

// TestBanRoundsIncrement 惯犯的累计次数要涨：界面靠它区分"误伤一次"与"一直在敲门"。
func TestBanRoundsIncrement(t *testing.T) {
	gf := policy()
	gf.BurstLimit = 1
	gf.BanMinutes = 1
	// 计数窗口给足一小时：封禁到期（1 分钟）之后条目仍在计数窗口内，于是清扫不会把它删掉，
	// 累计次数才有得涨。窗口比封禁时长短的话，"惯犯"这个概念本身就不成立。
	gf.WindowSeconds = 3600
	f, _ := newTestFW(t, gf)
	l := f.current()
	now := time.Now()
	f.note(l, ip("203.0.113.5"), now)
	f.note(l, ip("203.0.113.5"), now.Add(2*time.Minute)) // 上一轮已过期，再封一次
	f.mu.Lock()
	e := f.bans[ipx.Key(ip("203.0.113.5"))]
	f.mu.Unlock()
	if e == nil {
		t.Fatal("条目被清扫掉了，累计次数无从累积")
	}
	if e.banRound != 2 {
		t.Fatalf("累计封禁次数 = %d，应为 2", e.banRound)
	}
}

// TestIsBannedExpires 封禁到期即自然放行——这是"任何误判都会自己愈合"的兜底。
func TestIsBannedExpires(t *testing.T) {
	f, _ := newTestFW(t, policy())
	banNow(f, "203.0.113.5", time.Now().Add(-time.Second), 1) // 已过期
	if f.isBanned(ip("203.0.113.5")) {
		t.Fatal("已过期的封禁不该继续拦人")
	}
	if got := f.decide(f.current(), ip("203.0.113.5")); got != gfPass {
		t.Fatalf("已过期的封禁 decide = %s，应放行", got.reason())
	}
}

// TestIsBannedEmptyTable 表空时的快速路径：不该 panic，也不该报封禁。
func TestIsBannedEmptyTable(t *testing.T) {
	f, _ := newTestFW(t, policy())
	if f.size.Load() != 0 {
		t.Fatalf("新建的封禁表应为空，实际 size=%d", f.size.Load())
	}
	if f.isBanned(ip("203.0.113.5")) {
		t.Fatal("空表不该报封禁")
	}
}

// TestSweepFromIsBanned 到期条目要能被 isBanned 顺手清掉。
//
// 清扫原先只挂在 Note 上，而 Note 只在"有来源产生握手异常"时才跑：攻击停了以后
// 没人再调它，于是过期条目一直留在表里、size 永远大于零，之后**每一个连接**都要
// 为一张全是死条目的表抢一次锁。
func TestSweepFromIsBanned(t *testing.T) {
	gf := policy()
	gf.WindowSeconds = 1 // 计数窗口也要过期，条目才够格被删
	f, _ := newTestFW(t, gf)
	banNow(f, "203.0.113.5", time.Now().Add(-time.Hour), 1)
	f.mu.Lock()
	f.bans[ipx.Key(ip("203.0.113.5"))].firstHit = time.Now().Add(-time.Hour)
	f.lastSweep = time.Now().Add(-2 * gfBanSweepInterval) // 让最小间隔不挡路
	f.mu.Unlock()

	f.isBanned(ip("198.51.100.1")) // 查一个不相关的地址，只为触发清扫
	if n := f.size.Load(); n != 0 {
		t.Fatalf("清扫后表内仍有 %d 条死条目", n)
	}
}

// TestNewSeedsLastSweep lastSweep 必须播成"现在"。留零值的话，启动后第一个连接
// 就满足"距上次清扫超过一分钟"，要为一张空表白跑一遍全表扫描 + ShrinkSparse。
func TestNewSeedsLastSweep(t *testing.T) {
	f, _ := newTestFW(t, policy())
	if f.lastSweep.IsZero() {
		t.Fatal("New 没有播 lastSweep，启动后第一个连接会为空表白跑一次全表清扫")
	}
}

// ---------------------------------------------------------------------------
// 名单展示
// ---------------------------------------------------------------------------

// TestBanSnapshotOrderAndTotal 排序、截断、总数三件事一次验完。
//
// 总数必须是**截断前**的条数：界面显示"仅显示前 200 条，共 N 条"，N 跟着截断走的话
// 就永远等于 200，看不出真实规模。排序要稳定（同秒到期按 IP 定序），否则每次刷新
// 顺序都在跳。
func TestBanSnapshotOrderAndTotal(t *testing.T) {
	f, _ := newTestFW(t, policy())
	base := time.Now().Add(time.Hour).Truncate(time.Second)
	banNow(f, "203.0.113.1", base.Add(10*time.Second), 1)
	banNow(f, "203.0.113.2", base.Add(30*time.Second), 2)
	banNow(f, "198.51.100.9", base.Add(30*time.Second), 1) // 与上一条同秒到期
	banNow(f, "203.0.113.4", base.Add(5*time.Second), 1)

	items, total := f.BanSnapshot(0)
	if total != 4 {
		t.Fatalf("总数 = %d，应为 4", total)
	}
	want := []string{"198.51.100.9", "203.0.113.2", "203.0.113.1", "203.0.113.4"}
	if len(items) != len(want) {
		t.Fatalf("返回 %d 条，应为 %d 条", len(items), len(want))
	}
	for i := range want {
		if items[i].IP != want[i] {
			t.Fatalf("排序 = %v，应为 %v（到期时间倒序，同秒按 IP 升序）", ipsOf(items), want)
		}
	}

	// 截断只影响返回条数，总数照旧。
	items, total = f.BanSnapshot(2)
	if len(items) != 2 || total != 4 {
		t.Fatalf("limit=2 时返回 %d 条 / 总数 %d，应为 2 / 4", len(items), total)
	}
	if items[0].IP != "198.51.100.9" || items[1].IP != "203.0.113.2" {
		t.Fatalf("截断应保留最近封的两条，实际 %v", ipsOf(items))
	}
	// 展示字段要能用：到期时间与累计次数都得如实带出来。
	if items[1].Rounds != 2 {
		t.Errorf("累计次数 = %d，应为 2", items[1].Rounds)
	}
	if items[1].Until != base.Add(30*time.Second).Unix() {
		t.Errorf("到期时间 = %d，应为 %d", items[1].Until, base.Add(30*time.Second).Unix())
	}
}

// TestBanSnapshotSkipsInactive 只在计数、以及封禁已过期的条目都不该出现在名单里。
// 前者会让界面显示一批"其实还能正常访问"的地址，用户会以为自己封了一堆人。
func TestBanSnapshotSkipsInactive(t *testing.T) {
	f, _ := newTestFW(t, policy())
	banNow(f, "203.0.113.1", time.Now().Add(time.Hour), 1)  // 生效
	banNow(f, "203.0.113.2", time.Now().Add(-time.Hour), 1) // 已过期
	f.mu.Lock()
	// 只在计数、从未被封：until 是零值。
	p := ip("203.0.113.3")
	f.bans[ipx.Key(p)] = &entry{ip: p.String(), firstHit: time.Now(), burstAt: time.Now(), strikes: 2}
	f.size.Store(int32(len(f.bans)))
	f.mu.Unlock()

	items, total := f.BanSnapshot(0)
	if total != 1 || len(items) != 1 || items[0].IP != "203.0.113.1" {
		t.Fatalf("只应列出生效中的那一条，实际 %v（总数 %d）", ipsOf(items), total)
	}
	if n := f.BanCount(); n != 1 {
		t.Fatalf("BanCount = %d，应为 1", n)
	}
}

// TestBanListDelegates BanList 与 BanSnapshot 必须给出同一份列表（前者只是省掉总数）。
func TestBanListDelegates(t *testing.T) {
	f, _ := newTestFW(t, policy())
	banNow(f, "203.0.113.1", time.Now().Add(time.Hour), 1)
	banNow(f, "203.0.113.2", time.Now().Add(2*time.Hour), 1)
	items, _ := f.BanSnapshot(0)
	list := f.BanList(0)
	if len(list) != len(items) {
		t.Fatalf("BanList %d 条 / BanSnapshot %d 条", len(list), len(items))
	}
	for i := range items {
		if list[i].IP != items[i].IP {
			t.Fatalf("两者顺序不一致：%v vs %v", ipsOf(list), ipsOf(items))
		}
	}
}

func ipsOf(items []BanView) []string {
	out := make([]string, 0, len(items))
	for _, it := range items {
		out = append(out, it.IP)
	}
	return out
}

// ---------------------------------------------------------------------------
// 解除封禁
// ---------------------------------------------------------------------------

// TestUnban 解除单个：返回值必须如实反映"它此前是否真的被封着"。
// 界面靠这个值告诉用户"已解除"还是"它本来就没被封"。
func TestUnban(t *testing.T) {
	f, _ := newTestFW(t, policy())
	banNow(f, "203.0.113.5", time.Now().Add(time.Hour), 1)
	banNow(f, "203.0.113.6", time.Now().Add(-time.Hour), 1) // 只剩计数，封禁已过期

	if !f.Unban("203.0.113.5") {
		t.Error("解除一个正被封的地址应返回 true")
	}
	if f.isBanned(ip("203.0.113.5")) {
		t.Error("解除之后不该还被封着")
	}
	if f.Unban("203.0.113.6") {
		t.Error("封禁已过期的地址应返回 false（它本来就进得来）")
	}
	if f.Unban("198.51.100.1") {
		t.Error("表里没有的地址应返回 false")
	}
	if f.Unban("不是个地址") {
		t.Error("非法 IP 应返回 false 而不是 panic")
	}
	if n := f.size.Load(); n != 0 {
		t.Errorf("两条都被删掉后 size 应为 0，实际 %d", n)
	}
}

// TestClearBans 全部解除：返回的是**生效中**的条数（用户看到的那个数），
// 但表要清空干净——只在计数的条目留着的话，解除之后对方仍在攒下一次封禁。
func TestClearBans(t *testing.T) {
	f, _ := newTestFW(t, policy())
	banNow(f, "203.0.113.1", time.Now().Add(time.Hour), 1)
	banNow(f, "203.0.113.2", time.Now().Add(time.Hour), 1)
	banNow(f, "203.0.113.3", time.Now().Add(-time.Hour), 1) // 已过期，不计入返回值
	if n := f.ClearBans(); n != 2 {
		t.Fatalf("解除条数 = %d，应为 2（只数生效中的）", n)
	}
	if n := f.size.Load(); n != 0 {
		t.Fatalf("清空后 size = %d，应为 0", n)
	}
	if items, total := f.BanSnapshot(0); len(items) != 0 || total != 0 {
		t.Fatalf("清空后名单应为空，实际 %v", ipsOf(items))
	}
}

// ---------------------------------------------------------------------------
// 容量
// ---------------------------------------------------------------------------

// TestMaxEntriesFollowsMemoryQuota 表容量必须由配置里的内存额度折算，且与 config 同一份换算。
// 两边各算一份的话，界面上填的额度与表实际能装多少就会对不上。
func TestMaxEntriesFollowsMemoryQuota(t *testing.T) {
	for _, mb := range []int{1, config.DefaultGlobalFirewallMemoryMB, config.MaxGlobalFirewallMemoryMB} {
		gf := policy()
		gf.MemoryMB = mb
		f, _ := newTestFW(t, gf)
		want := config.BanEntriesForMemoryMB(mb)
		if got := f.maxEntries(f.current()); got != want {
			t.Errorf("MemoryMB=%d 时容量 = %d，应为 %d", mb, got, want)
		}
	}
}

// TestBanTableCapped 表满之后不再增长。封禁表的键是**攻击者选的**地址，
// 无上限等于把内存分配权交给对方（一个 IPv6 /64 就有 1.8e19 个来源）。
func TestBanTableCapped(t *testing.T) {
	gf := policy()
	gf.MemoryMB = 1
	gf.BurstLimit = config.MaxGlobalFirewallLimit // 只让它计数，不要真封
	f, _ := newTestFW(t, gf)
	l := f.current()
	limit := f.maxEntries(l)
	now := time.Now()
	for i := 0; i < limit+64; i++ {
		// 每个来源一个不同的地址。这里直接走 note 而不是 Note：后者会豁免局域网与允许名单，
		// 而这个用例要的是"表被不同来源填满"，跟闸门无关。
		f.note(l, net.IPv4(203, byte(i>>16), byte(i>>8), byte(i)), now)
	}
	f.mu.Lock()
	n := len(f.bans)
	f.mu.Unlock()
	if n != limit {
		t.Fatalf("表内 %d 条，应正好填到上限 %d（既不能超，也不能提前拒收）", n, limit)
	}
}

// ---------------------------------------------------------------------------
// TLS 握手错误回灌
// ---------------------------------------------------------------------------

// TestParseHandshakeIP 从标准库那行日志里取来源 IP。
//
// IPv6 那几条是回归用例：早先的实现是"找第一个冒号，取它前面的部分"，对 IPv4 恰好正确，
// 对 IPv6 会切出 "[2001" 然后解析失败——于是**所有 IPv6 来源的握手异常都不计数**，
// 自动封禁对着一个如今相当常见的地址族完全失效，而且不留任何痕迹（解析失败是静默的）。
func TestParseHandshakeIP(t *testing.T) {
	cases := []struct {
		name string
		line string
		want string // 空表示应解析不出
	}{
		{"IPv4", "http: TLS handshake error from 1.2.3.4:5678: EOF", "1.2.3.4"},
		{
			"IPv6",
			"http: TLS handshake error from [2001:db8::dead]:44322: EOF",
			"2001:db8::dead",
		},
		{
			// 带 zone 的链路本地地址：ipx.RemoteHost 负责剥掉 %eth0。
			"IPv6 带 zone",
			"http: TLS handshake error from [fe80::1%eth0]:443: remote error: tls: bad certificate",
			"fe80::1",
		},
		{
			// 真实链路上前面还有 log 包加的时间戳与前缀，后面还有换行。
			"带前缀与换行",
			"2026/09/03 12:00:00 http: TLS handshake error from 198.51.100.7:1234: tls: first record does not look like a TLS handshake\n",
			"198.51.100.7",
		},
		{"其他错误行", "http: Accept error: accept tcp: too many open files", ""},
		{"标记后为空", "http: TLS handshake error from ", ""},
		{"地址不是 IP", "http: TLS handshake error from not-an-ip:443: EOF", ""},
		{"空行", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := parseHandshakeIP(tc.line)
			if tc.want == "" {
				if got != nil {
					t.Fatalf("应解析不出，实际 %s", got)
				}
				return
			}
			if got == nil {
				t.Fatalf("应解析出 %s，实际什么都没拿到", tc.want)
			}
			if !got.Equal(ip(tc.want)) {
				t.Fatalf("解析出 %s，应为 %s", got, tc.want)
			}
		})
	}
}

// TestWrapErrorLogNoEnableLatch 关着的时候包装、之后从界面打开——回灌必须照样工作。
//
// 这是那个"焊死"回归：原先 WrapErrorLog 在包装时判一次 Enabled，关着就原样返回 base。
// 于是"启动时防火墙关着，之后从界面打开"这条最常见的路径下，回灌永远挂不上去，
// 自动封禁表一条也不会长，而界面显示"已启用"、判定逻辑也确实在跑名单——看不出少了什么。
// 要恢复只能重启进程。
func TestWrapErrorLogNoEnableLatch(t *testing.T) {
	gf := policy()
	gf.Enabled = false // 起服务时是关着的
	f, m := newTestFW(t, gf)

	var buf bytes.Buffer
	wrapped := f.WrapErrorLog(log.New(&buf, "prefix: ", 0))
	if wrapped == nil {
		t.Fatal("WrapErrorLog 返回了 nil")
	}

	// 关着时写一行：不该计数。
	wrapped.Print("http: TLS handshake error from 203.0.113.5:1234: EOF")
	if f.size.Load() != 0 {
		t.Fatal("防火墙关着时不该计数")
	}

	// 从界面打开（等价于一次配置保存），一次都不重启。
	on := policy()
	on.BurstLimit = 2
	setPolicy(t, m, on)

	wrapped.Print("http: TLS handshake error from 203.0.113.5:1234: EOF")
	wrapped.Print("http: TLS handshake error from 203.0.113.5:1234: EOF")
	if !f.isBanned(ip("203.0.113.5")) {
		t.Fatal("打开开关后回灌没有生效——WrapErrorLog 把启用状态焊死在了包装那一刻")
	}
}

// TestWrapErrorLogPassesBytesThrough 顺带做的计数出任何岔子都不该让一行日志消失。
// 这条链路首先是日志链路，其次才是防火墙的信号源。
func TestWrapErrorLogPassesBytesThrough(t *testing.T) {
	f, _ := newTestFW(t, policy())
	var buf bytes.Buffer
	base := log.New(&buf, "webtls: ", 0)
	wrapped := f.WrapErrorLog(base)
	if got, want := wrapped.Prefix(), base.Prefix(); got != want {
		t.Errorf("前缀 = %q，应与 base 一致（%q）", got, want)
	}
	if got, want := wrapped.Flags(), base.Flags(); got != want {
		t.Errorf("Flags = %d，应与 base 一致（%d）", got, want)
	}
	for _, line := range []string{
		"http: TLS handshake error from 203.0.113.5:1234: EOF",
		"http: Accept error: accept tcp: too many open files",
		"这一行里根本没有 IP",
	} {
		wrapped.Print(line)
		if !bytes.Contains(buf.Bytes(), []byte(line)) {
			t.Fatalf("日志行没有原样透传：%q", line)
		}
	}
}

// TestWrapNilSafe 防火墙未注入（nil）时两个包装函数都原样返回，等于不拦截。
// 模块装配顺序出岔子时，代价应该是"没有防护"，而不是"服务起不来"。
func TestWrapNilSafe(t *testing.T) {
	var f *Firewall
	ln := &fakeListener{}
	if got := f.Wrap(ln); got != net.Listener(ln) {
		t.Error("nil 防火墙的 Wrap 应原样返回监听器")
	}
	base := log.New(&bytes.Buffer{}, "", 0)
	if got := f.WrapErrorLog(base); got != base {
		t.Error("nil 防火墙的 WrapErrorLog 应原样返回 logger")
	}
	live, _ := newTestFW(t, policy())
	if got := live.WrapErrorLog(nil); got != nil {
		t.Error("base 为 nil 时应原样返回 nil")
	}
}

// fakeListener 只为验 nil 包装的原样返回，不需要真的能接受连接。
type fakeListener struct{}

func (*fakeListener) Accept() (net.Conn, error) { return nil, net.ErrClosed }
func (*fakeListener) Close() error              { return nil }
func (*fakeListener) Addr() net.Addr            { return &net.TCPAddr{} }

// ---------------------------------------------------------------------------
// 连接层拦截
// ---------------------------------------------------------------------------

// TestListenerRejectsWithoutBreakingServe 被拒的连接必须对上层**完全不可见**。
//
// http.Server.Serve 见到非临时错误就会退出整个服务，因此 Accept 只能默默关掉连接
// 继续循环，绝不能把"这个连接被拦了"当成错误返回——那等于一次拦截就把整个站点停掉。
//
// 用回环地址走拒绝名单：回环本身是豁免的，而拒绝名单压过豁免，正好用一条规则
// 同时验"名单优先级"与"拒绝对上层不可见"。
func TestListenerRejectsWithoutBreakingServe(t *testing.T) {
	gf := policy()
	gf.DenyIPs = []string{"127.0.0.1"}
	f, m := newTestFW(t, gf)

	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("环境不允许监听回环端口：%v", err)
	}
	defer raw.Close()
	ln := f.Wrap(raw)

	type acceptResult struct {
		remote string
		err    error
	}
	got := make(chan acceptResult, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			got <- acceptResult{err: err}
			return
		}
		got <- acceptResult{remote: c.RemoteAddr().String()}
		c.Close()
	}()

	// 第一次连接会被拒：Accept 应当继续等下一个，而不是返回。
	c1, err := net.Dial("tcp", raw.Addr().String())
	if err != nil {
		t.Fatalf("拨号失败：%v", err)
	}
	c1.Close()
	select {
	case r := <-got:
		t.Fatalf("被拒的连接漏给了上层（remote=%q err=%v）——Serve 会因此退出", r.remote, r.err)
	case <-time.After(300 * time.Millisecond):
	}

	// 把拒绝名单去掉（一次配置保存），同一个监听器立刻放行——启用状态不该被焊在创建那一刻。
	setPolicy(t, m, policy())
	c2, err := net.Dial("tcp", raw.Addr().String())
	if err != nil {
		t.Fatalf("拨号失败：%v", err)
	}
	defer c2.Close()
	select {
	case r := <-got:
		if r.err != nil {
			t.Fatalf("Accept 返回了错误：%v", r.err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("移出拒绝名单后连接仍进不来——监听器把名单焊死在了创建那一刻")
	}
}

// TestConnIP 从连接取 IP：TCPAddr 走类型断言，其余走字符串解析。
func TestConnIP(t *testing.T) {
	if got := connIP(&fakeConn{addr: &net.TCPAddr{IP: ip("203.0.113.5"), Port: 1}}); !got.Equal(ip("203.0.113.5")) {
		t.Errorf("TCPAddr 取到 %v", got)
	}
	if got := connIP(&fakeConn{addr: nil}); got != nil {
		t.Errorf("地址为 nil 时应返回 nil，实际 %v", got)
	}
	// 非 TCPAddr（例如被中间层包过一次的地址）走 host:port 解析。
	if got := connIP(&fakeConn{addr: strAddr("198.51.100.7:443")}); !got.Equal(ip("198.51.100.7")) {
		t.Errorf("字符串地址取到 %v", got)
	}
	if got := remoteAddrOf(&fakeConn{addr: nil}); got != "unknown" {
		t.Errorf("地址为 nil 时展示值 = %q，应为 unknown", got)
	}
}

type strAddr string

func (strAddr) Network() string  { return "tcp" }
func (a strAddr) String() string { return string(a) }

// fakeConn 只实现取地址所需的部分。
type fakeConn struct {
	net.Conn
	addr net.Addr
}

func (c *fakeConn) RemoteAddr() net.Addr { return c.addr }

// ---------------------------------------------------------------------------
// 日志抑制
// ---------------------------------------------------------------------------

// TestLogBanSuppression 「新增封禁」告警必须限速，否则防火墙自己就成了新的日志洪水源
// （一次分布式扫描能在一分钟内封掉上千个地址），而这个功能的初衷恰恰是让日志安静下来。
// 被压掉的条数要累计进下一条，不能凭空消失。
func TestLogBanSuppression(t *testing.T) {
	f, _ := newTestFW(t, policy())
	f.logBan("203.0.113.1", 10) // 第一条：放过去
	f.logBan("203.0.113.2", 10) // 紧接着的都被压掉
	f.logBan("203.0.113.3", 10)
	f.logMu.Lock()
	skipped := f.banSkipped
	f.logMu.Unlock()
	if skipped != 2 {
		t.Fatalf("被压掉的条数 = %d，应为 2", skipped)
	}

	// 抑制窗口过去之后，下一条要把攒下的数字带出来并归零。
	f.logMu.Lock()
	f.lastBanLog = time.Now().Add(-2 * gfBanLogInterval)
	f.logMu.Unlock()
	f.logBan("203.0.113.4", 10)
	f.logMu.Lock()
	skipped = f.banSkipped
	f.logMu.Unlock()
	if skipped != 0 {
		t.Fatalf("输出一条之后累计数应归零，实际 %d", skipped)
	}
}

// TestVerdictReasons 每种判定都要有可读的原因串——它是日志里唯一能区分"为什么被拦"的字段。
func TestVerdictReasons(t *testing.T) {
	for v, want := range map[gfVerdict]string{
		gfPass:       "pass",
		gfDenyList:   "deny-list",
		gfDenyBanned: "auto-ban",
		gfDenyNoIP:   "no-ip",
	} {
		if got := v.reason(); got != want {
			t.Errorf("判定 %d 的原因 = %q，应为 %q", v, got, want)
		}
	}
}

// TestNoteConcurrent 并发调用不该出现竞争或 panic（真实链路上每条出错的连接都会走一次）。
// 配 -race 跑才有意义，但即便不带 -race，它也能抓住"锁没放回来"这类问题（会超时）。
func TestNoteConcurrent(t *testing.T) {
	gf := policy()
	gf.BurstLimit = 3
	f, _ := newTestFW(t, gf)

	done := make(chan struct{})
	go func() {
		defer close(done)
		var wg [8]chan struct{}
		for i := range wg {
			wg[i] = make(chan struct{})
			go func(n int) {
				defer close(wg[n])
				addr := fmt.Sprintf("203.0.113.%d", n+1)
				for j := 0; j < 50; j++ {
					f.Note(ip(addr), "tls-handshake")
					f.decide(f.current(), ip(addr))
					f.BanSnapshot(10)
					f.BanCount()
				}
			}(i)
		}
		for i := range wg {
			<-wg[i]
		}
	}()

	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("并发读写没有在 30 秒内完成——极可能有锁没被释放")
	}
	// 八个来源各踩 50 次、阈值 3，应当全部被封。
	if n := f.BanCount(); n != 8 {
		t.Fatalf("生效封禁数 = %d，应为 8", n)
	}
}
