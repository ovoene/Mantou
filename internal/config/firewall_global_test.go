package config

import (
	"fmt"
	"testing"
)

// 服务防护（连接层）的数据层规则。这一层是唯一的兜底：配置有三条写入路径
// （模块页保存、整份导入、手改 config.json），只有第一条经过接口校验，
// 而加载期不能因为一份不合理的设置就拒绝启动，只能夹住。
//
// 本文件里最要紧的一条是 TestGlobalFirewallPresetsDiffer / TestNormalizeAppliesLevelPreset：
// 「换档位却什么都不变」曾经是这个功能实际存在过的毛病（原先只在数值全为零时才套预设，
// 而前端提交的表单必然带着上一次的数值，于是那个分支永远走不到）。

func TestDefaultGlobalFirewall(t *testing.T) {
	g := Default().GlobalFirewall
	// 默认关闭是这份设计的主张（理由见 defaultGlobalFirewall 的注释）：
	// 它拦的是连接，误伤在浏览器里长得和"服务没起来"一模一样。
	// 一旦有人把默认值改成开启，这里必须先红。
	if g.Enabled {
		t.Error("全新安装应默认关闭服务防护——误伤表现为无法连接，不该由默认值带来")
	}
	if g.Level != GlobalFirewallLevelBalanced {
		t.Errorf("默认档位 = %q，应为 %q", g.Level, GlobalFirewallLevelBalanced)
	}
	if !g.AutoBan {
		t.Error("默认应开启自动封禁（开关关着时它不影响任何行为）")
	}
	if g.MemoryMB != DefaultGlobalFirewallMemoryMB {
		t.Errorf("默认内存上限 = %d，应为 %d", g.MemoryMB, DefaultGlobalFirewallMemoryMB)
	}
	// 关着也要是一组能直接用的值：用户进模块页打开开关时，看到的不该是一排 0。
	if g.WindowSeconds != gfwBalancedWindowSeconds || g.WindowLimit != gfwBalancedWindowLimit ||
		g.BurstSeconds != gfwBalancedBurstSeconds || g.BurstLimit != gfwBalancedBurstLimit ||
		g.BanMinutes != gfwBalancedBanMinutes {
		t.Errorf("默认数值未按均衡档填好：%+v", g)
	}
	// 默认不该预置任何名单：预置任何一条都是替用户做他没做过的决定。
	if len(g.AllowIPs) != 0 || len(g.DenyIPs) != 0 {
		t.Errorf("默认名单应为空，实际 allow=%v deny=%v", g.AllowIPs, g.DenyIPs)
	}
}

// TestGlobalFirewallPresetsDiffer 三个预设档位必须**两两不同**。
//
// 这是"点了档位却什么都不变"的回归防线。三档写成同一组数字并不会让任何代码出错，
// 界面照样能存能读——只是档位这个选择彻底失去意义，而没有任何测试会因此变红。
func TestGlobalFirewallPresetsDiffer(t *testing.T) {
	ps := GlobalFirewallPresets()
	if len(ps) != 3 {
		t.Fatalf("预设档位应有 3 个，实际 %d", len(ps))
	}
	seen := map[string]string{}
	for _, p := range ps {
		key := fmt.Sprintf("%d/%d/%d/%d/%d", p.WindowSeconds, p.WindowLimit, p.BurstSeconds, p.BurstLimit, p.BanMinutes)
		if other, dup := seen[key]; dup {
			t.Fatalf("档位 %s 与 %s 的数值完全相同（%s）——换档位在界面上不会有任何变化", p.Level, other, key)
		}
		seen[key] = p.Level
	}
	// 顺序即界面上的排列顺序，且必须是"越往后越严"：窗口更短、阈值更低、封得更久。
	// 排反了的话，界面上写着"严格"的那一档实际最松，而这件事没有任何别的地方会暴露。
	for i := 1; i < len(ps); i++ {
		prev, cur := ps[i-1], ps[i]
		if cur.WindowSeconds >= prev.WindowSeconds || cur.WindowLimit >= prev.WindowLimit ||
			cur.BurstLimit >= prev.BurstLimit || cur.BanMinutes <= prev.BanMinutes {
			t.Errorf("档位 %s 并不比 %s 更严：%+v vs %+v", cur.Level, prev.Level, cur, prev)
		}
	}
}

// TestGlobalFirewallPresetsCopied 下发给前端的是副本，调用方改不到内部那张表。
func TestGlobalFirewallPresetsCopied(t *testing.T) {
	a := GlobalFirewallPresets()
	a[0].WindowLimit = 99999
	if b := GlobalFirewallPresets(); b[0].WindowLimit == 99999 {
		t.Fatal("GlobalFirewallPresets 返回了内部表本身，调用方能改到预设")
	}
}

// TestNormalizeAppliesLevelPreset 选中预设档位时，数值一律被重写成该档位的预设——
// **不管用户提交了什么**。这正是"换档位不生效"那个 bug 的反面。
func TestNormalizeAppliesLevelPreset(t *testing.T) {
	for _, p := range GlobalFirewallPresets() {
		t.Run(p.Level, func(t *testing.T) {
			// 带着一组"上一次的数值"提交，模拟前端表单的真实行为。
			g := GlobalFirewall{
				Enabled: true, Level: p.Level, AutoBan: true,
				WindowSeconds: 777, WindowLimit: 777,
				BurstSeconds: 777, BurstLimit: 777, BanMinutes: 777,
				MemoryMB: DefaultGlobalFirewallMemoryMB,
			}
			normalizeGlobalFirewall(&g)
			if g.WindowSeconds != p.WindowSeconds || g.WindowLimit != p.WindowLimit ||
				g.BurstSeconds != p.BurstSeconds || g.BurstLimit != p.BurstLimit ||
				g.BanMinutes != p.BanMinutes {
				t.Fatalf("档位 %s 未套用预设：得到 %d/%d/%d/%d/%d，应为 %d/%d/%d/%d/%d",
					p.Level,
					g.WindowSeconds, g.WindowLimit, g.BurstSeconds, g.BurstLimit, g.BanMinutes,
					p.WindowSeconds, p.WindowLimit, p.BurstSeconds, p.BurstLimit, p.BanMinutes)
			}
		})
	}
}

// TestNormalizeKeepsCustomNumbers custom 档位下手填的数值必须原样保留（只夹越界）。
// 少了这一条，"自定义"就只是个换了名字的均衡档。
func TestNormalizeKeepsCustomNumbers(t *testing.T) {
	g := GlobalFirewall{
		Enabled: true, Level: GlobalFirewallLevelCustom, AutoBan: true,
		WindowSeconds: 45, WindowLimit: 9, BurstSeconds: 4, BurstLimit: 6, BanMinutes: 30,
		MemoryMB: DefaultGlobalFirewallMemoryMB,
	}
	normalizeGlobalFirewall(&g)
	if g.Level != GlobalFirewallLevelCustom {
		t.Fatalf("custom 档位被改成了 %q", g.Level)
	}
	if g.WindowSeconds != 45 || g.WindowLimit != 9 || g.BurstSeconds != 4 || g.BurstLimit != 6 || g.BanMinutes != 30 {
		t.Fatalf("custom 档位的手填数值被改动：%+v", g)
	}
}

func TestNormalizeGlobalFirewallClamps(t *testing.T) {
	cases := []struct {
		name string
		in   GlobalFirewall
		want GlobalFirewall
	}{
		{
			// 认不出的档位落到均衡：未知取值往"适中"落而不是往极端落，
			// 避免一份手改的配置把防护强度悄悄推到最松或最严。
			name: "档位拼错落到均衡",
			in:   GlobalFirewall{Level: "ballanced", MemoryMB: DefaultGlobalFirewallMemoryMB},
			want: GlobalFirewall{
				Level:         GlobalFirewallLevelBalanced,
				WindowSeconds: gfwBalancedWindowSeconds, WindowLimit: gfwBalancedWindowLimit,
				BurstSeconds: gfwBalancedBurstSeconds, BurstLimit: gfwBalancedBurstLimit,
				BanMinutes: gfwBalancedBanMinutes, MemoryMB: DefaultGlobalFirewallMemoryMB,
			},
		},
		{
			name: "档位为空落到均衡",
			in:   GlobalFirewall{MemoryMB: 3},
			want: GlobalFirewall{
				Level:         GlobalFirewallLevelBalanced,
				WindowSeconds: gfwBalancedWindowSeconds, WindowLimit: gfwBalancedWindowLimit,
				BurstSeconds: gfwBalancedBurstSeconds, BurstLimit: gfwBalancedBurstLimit,
				BanMinutes: gfwBalancedBanMinutes, MemoryMB: 3,
			},
		},
		{
			// custom 档位的越界数值被夹住，而不是回落到某个默认值：
			// 用户明确填了一个方向（"我要非常短的窗口"），夹到边界仍在那个方向上。
			name: "custom 越界数值被夹住",
			in: GlobalFirewall{
				Level:         GlobalFirewallLevelCustom,
				WindowSeconds: 0, WindowLimit: -5,
				BurstSeconds: 1 << 30, BurstLimit: 1 << 30, BanMinutes: 1 << 30,
				MemoryMB: DefaultGlobalFirewallMemoryMB,
			},
			want: GlobalFirewall{
				Level:         GlobalFirewallLevelCustom,
				WindowSeconds: MinGlobalFirewallWindowSeconds, WindowLimit: MinGlobalFirewallLimit,
				BurstSeconds: MaxGlobalFirewallWindowSeconds, BurstLimit: MaxGlobalFirewallLimit,
				BanMinutes: MaxGlobalFirewallBanMinutes, MemoryMB: DefaultGlobalFirewallMemoryMB,
			},
		},
		{
			// 内存上限的 0 是"取默认"，不是"不限"——封禁表必须有硬上限。
			name: "内存 0 回落默认",
			in:   GlobalFirewall{Level: GlobalFirewallLevelLoose, MemoryMB: 0},
			want: GlobalFirewall{
				Level:         GlobalFirewallLevelLoose,
				WindowSeconds: gfwLooseWindowSeconds, WindowLimit: gfwLooseWindowLimit,
				BurstSeconds: gfwLooseBurstSeconds, BurstLimit: gfwLooseBurstLimit,
				BanMinutes: gfwLooseBanMinutes, MemoryMB: DefaultGlobalFirewallMemoryMB,
			},
		},
		{
			name: "内存超上限被夹住",
			in:   GlobalFirewall{Level: GlobalFirewallLevelStrict, MemoryMB: 1 << 30},
			want: GlobalFirewall{
				Level:         GlobalFirewallLevelStrict,
				WindowSeconds: gfwStrictWindowSeconds, WindowLimit: gfwStrictWindowLimit,
				BurstSeconds: gfwStrictBurstSeconds, BurstLimit: gfwStrictBurstLimit,
				BanMinutes: gfwStrictBanMinutes, MemoryMB: MaxGlobalFirewallMemoryMB,
			},
		},
		{
			name: "内存为负回落默认",
			in:   GlobalFirewall{Level: GlobalFirewallLevelStrict, MemoryMB: -1},
			want: GlobalFirewall{
				Level:         GlobalFirewallLevelStrict,
				WindowSeconds: gfwStrictWindowSeconds, WindowLimit: gfwStrictWindowLimit,
				BurstSeconds: gfwStrictBurstSeconds, BurstLimit: gfwStrictBurstLimit,
				BanMinutes: gfwStrictBanMinutes, MemoryMB: DefaultGlobalFirewallMemoryMB,
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			g := tc.in
			normalizeGlobalFirewall(&g)
			if fmt.Sprintf("%+v", g) != fmt.Sprintf("%+v", tc.want) {
				t.Fatalf("规范化后 = %+v\n应为         %+v", g, tc.want)
			}
		})
	}
}

// TestNormalizeGlobalFirewallIdempotent 加载期每次启动都会跑一遍，不幂等就等于
// "每次重启都把用户的设置改一点"。
func TestNormalizeGlobalFirewallIdempotent(t *testing.T) {
	for _, g := range []GlobalFirewall{
		{Enabled: true, Level: "bogus", MemoryMB: -1,
			AllowIPs: []string{" 203.0.113.5 ", "203.0.113.5", "写错的地址"},
			DenyIPs:  []string{"198.51.100.0/24"}},
		{Enabled: true, Level: GlobalFirewallLevelCustom, WindowSeconds: 0, BurstLimit: 1 << 30},
		{Enabled: true, Level: GlobalFirewallLevelStrict, WindowSeconds: 777},
	} {
		v := g
		normalizeGlobalFirewall(&v)
		once := fmt.Sprintf("%+v", v)
		normalizeGlobalFirewall(&v)
		if twice := fmt.Sprintf("%+v", v); once != twice {
			t.Fatalf("规范化不幂等：\n第一次 %s\n第二次 %s", once, twice)
		}
	}
}

func TestGlobalFirewallValid(t *testing.T) {
	base := func() GlobalFirewall {
		return GlobalFirewall{
			Enabled: true, Level: GlobalFirewallLevelBalanced, AutoBan: true,
			WindowSeconds: 60, WindowLimit: 12, BurstSeconds: 3, BurstLimit: 4,
			BanMinutes: 120, MemoryMB: DefaultGlobalFirewallMemoryMB,
		}
	}
	if err := base().Valid(); err != nil {
		t.Fatalf("一份正常设置不该报错：%v", err)
	}

	// 关闭状态一律放过：拦下来只会让用户没法"先关掉再慢慢改"。
	off := base()
	off.Enabled = false
	off.Level = "bogus"
	off.MemoryMB = -100
	if err := off.Valid(); err != nil {
		t.Errorf("关闭状态不该校验：%v", err)
	}

	// 预设档位下，用户提交的数值根本不作数（服务端会重写），不该拿它挡住保存。
	preset := base()
	preset.WindowSeconds = -1
	preset.BurstLimit = 1 << 30
	preset.BanMinutes = 0
	if err := preset.Valid(); err != nil {
		t.Errorf("预设档位不该校验那几个不会生效的数值：%v", err)
	}

	// custom 档位下同样的数值必须被拦下——那时它们是真的会生效的。
	bad := []struct {
		name string
		mut  func(*GlobalFirewall)
	}{
		{"档位无效", func(g *GlobalFirewall) { g.Level = "very-strict" }},
		{"常规窗口为 0", func(g *GlobalFirewall) { g.Level = GlobalFirewallLevelCustom; g.WindowSeconds = 0 }},
		{"常规窗口超上限", func(g *GlobalFirewall) {
			g.Level = GlobalFirewallLevelCustom
			g.WindowSeconds = MaxGlobalFirewallWindowSeconds + 1
		}},
		{"常规阈值为 0", func(g *GlobalFirewall) { g.Level = GlobalFirewallLevelCustom; g.WindowLimit = 0 }},
		{"常规阈值超上限", func(g *GlobalFirewall) {
			g.Level = GlobalFirewallLevelCustom
			g.WindowLimit = MaxGlobalFirewallLimit + 1
		}},
		{"突发窗口为 0", func(g *GlobalFirewall) { g.Level = GlobalFirewallLevelCustom; g.BurstSeconds = 0 }},
		{"突发阈值为 0", func(g *GlobalFirewall) { g.Level = GlobalFirewallLevelCustom; g.BurstLimit = 0 }},
		{"封禁时长为 0", func(g *GlobalFirewall) { g.Level = GlobalFirewallLevelCustom; g.BanMinutes = 0 }},
		{"封禁时长超上限", func(g *GlobalFirewall) {
			g.Level = GlobalFirewallLevelCustom
			g.BanMinutes = MaxGlobalFirewallBanMinutes + 1
		}},
		// 内存上限与档位无关，两种档位都要校验。
		{"内存为负", func(g *GlobalFirewall) { g.MemoryMB = -1 }},
		{"内存超上限", func(g *GlobalFirewall) { g.MemoryMB = MaxGlobalFirewallMemoryMB + 1 }},
		{"允许名单超长", func(g *GlobalFirewall) { g.AllowIPs = make([]string, GlobalFirewallMaxIPs+1) }},
		{"拒绝名单超长", func(g *GlobalFirewall) { g.DenyIPs = make([]string, GlobalFirewallMaxIPs+1) }},
	}
	for _, tc := range bad {
		t.Run(tc.name, func(t *testing.T) {
			g := base()
			tc.mut(&g)
			if err := g.Valid(); err == nil {
				t.Fatalf("%s 应被拦下", tc.name)
			}
		})
	}

	// 自动封禁关着时，custom 档位的阈值填成什么都不影响行为，不该拦。
	noBan := base()
	noBan.Level = GlobalFirewallLevelCustom
	noBan.AutoBan = false
	noBan.WindowSeconds = 0
	noBan.BanMinutes = 0
	if err := noBan.Valid(); err != nil {
		t.Errorf("自动封禁关闭时不该校验其参数：%v", err)
	}
}

// TestGlobalFirewallMaxIPsMatchesNormalizer 校验上限与整理时的截断上限必须是同一个数。
// 各写一份字面量的话，改动其中一个就会出现"校验说 256 条合法、整理时截到 200 条"这种静默丢数据。
func TestGlobalFirewallMaxIPsMatchesNormalizer(t *testing.T) {
	if GlobalFirewallMaxIPs != MaxFirewallIPs {
		t.Fatalf("GlobalFirewallMaxIPs=%d 与 normalizeIPList 的截断上限 MaxFirewallIPs=%d 不一致",
			GlobalFirewallMaxIPs, MaxFirewallIPs)
	}
}

// TestBanEntriesForMemoryMB 折算容量的边界。
func TestBanEntriesForMemoryMB(t *testing.T) {
	// 0 与负数回落默认额度，不能算出 0——算出 0 意味着表一满就永远拒绝计数，
	// 自动封禁静默失效。
	if got := BanEntriesForMemoryMB(0); got != BanEntriesForMemoryMB(DefaultGlobalFirewallMemoryMB) {
		t.Errorf("0 MB 应回落默认额度，实际 %d", got)
	}
	if got := BanEntriesForMemoryMB(-3); got != BanEntriesForMemoryMB(DefaultGlobalFirewallMemoryMB) {
		t.Errorf("负数应回落默认额度，实际 %d", got)
	}
	// 极小额度有下限，防"表一满就拒计数"。
	if got := BanEntriesForMemoryMB(1); got < 1024 {
		t.Errorf("1 MB 折算 = %d，应不低于 1024", got)
	}
	// 手改到离谱的额度有上限，防吃穿地址空间。
	if got := BanEntriesForMemoryMB(1 << 20); got != 1<<22 {
		t.Errorf("超大额度折算 = %d，应夹到 %d", got, 1<<22)
	}
	// 额度越大装得越多，这个单调性是界面上"内存上限"这个旋钮有意义的前提。
	if BanEntriesForMemoryMB(MaxGlobalFirewallMemoryMB) <= BanEntriesForMemoryMB(DefaultGlobalFirewallMemoryMB) {
		t.Error("额度调大后容量没变大")
	}
}

// TestNormalizeGlobalFirewallNilSafe 导入路径可能传进 nil，不该 panic。
func TestNormalizeGlobalFirewallNilSafe(t *testing.T) {
	NormalizeGlobalFirewall(nil)
}

// TestMigrateFillsGlobalFirewall 升级上来的旧配置必须拿到一整份可用的默认值。
//
// 关键是 AutoBan：它是布尔值，旧配置里没有这个键，反序列化后是 false，
// 而 normalizeGlobalFirewall 分不出"没填"与"用户主动关了它"。少了这个迁移块，
// 全新安装拿到 AutoBan=true、升级上来的拿到 false，两批用户的行为不一致，
// 而这件事在界面上看不出来（开关显示的就是那个 false）。
func TestMigrateFillsGlobalFirewall(t *testing.T) {
	c := Default()
	c.Version = 10                      // 升级前的版本
	c.GlobalFirewall = GlobalFirewall{} // 旧配置里没有这一段，反序列化后是零值
	Migrate(c)

	g := c.GlobalFirewall
	// 升级也不该自动开启：它拦的是连接，突然给一批线上用户带上一道会掐连接的防护，
	// 而他们并不知道面板里多了这个功能。
	if g.Enabled {
		t.Fatal("升级上来的配置不应自动开启服务防护")
	}
	if !g.AutoBan {
		t.Error("迁移后 AutoBan 应为 true，否则升级用户与全新安装的行为不一致")
	}
	if g.Level != GlobalFirewallLevelBalanced {
		t.Errorf("迁移后档位 = %q，应为 %q", g.Level, GlobalFirewallLevelBalanced)
	}
	// 其余字段要填成能直接用的值：用户打开开关时看到的不该是一排 0。
	if g.WindowSeconds == 0 || g.WindowLimit == 0 || g.BurstSeconds == 0 ||
		g.BurstLimit == 0 || g.BanMinutes == 0 || g.MemoryMB == 0 {
		t.Errorf("迁移后仍有字段为 0：%+v", g)
	}
	if c.Version != CurrentVersion {
		t.Errorf("迁移后版本 = %d，应为 %d", c.Version, CurrentVersion)
	}
}

// TestMigrateKeepsExistingGlobalFirewall 已经是当前版本的配置再迁移一次不该被改动。
// Migrate 在每次加载时都会跑，不幂等就等于"每次重启都把用户的选择改回去"。
func TestMigrateKeepsExistingGlobalFirewall(t *testing.T) {
	c := Default()
	c.GlobalFirewall = GlobalFirewall{
		Enabled: true, Level: GlobalFirewallLevelCustom, AutoBan: false,
		AllowIPs:      []string{"203.0.113.5"},
		DenyIPs:       []string{"198.51.100.0/24"},
		WindowSeconds: 45, WindowLimit: 9, BurstSeconds: 4, BurstLimit: 6,
		BanMinutes: 30, MemoryMB: 8,
	}
	want := fmt.Sprintf("%+v", c.GlobalFirewall)
	Migrate(c)
	Migrate(c) // 跑两次：加载期会反复调用
	if got := fmt.Sprintf("%+v", c.GlobalFirewall); got != want {
		t.Fatalf("迁移改动了已有设置：\n%s\n→ %s", want, got)
	}
}
