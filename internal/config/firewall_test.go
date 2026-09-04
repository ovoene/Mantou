package config

import (
	"fmt"
	"testing"
)

// 面板入站防护的数据层规则。这一层是唯一的兜底：配置有三条写入路径
// （面板保存、整份导入、手改 config.json），只有第一条经过接口校验，
// 而加载期不能因为一份不合理的设置就拒绝启动，只能夹住。

func TestDefaultPanelFirewall(t *testing.T) {
	c := Default()
	fw := c.Settings.Security.Firewall
	// 默认开启且仅局域网是这份设计的主张（理由见 defaultPanelFirewall 的注释）。
	// 一旦有人把默认值改松，这里必须先红。
	if !fw.Enabled {
		t.Error("全新安装应默认开启入站防护")
	}
	if fw.Mode != FirewallModeLAN {
		t.Errorf("默认访问范围 = %q，应为 %q", fw.Mode, FirewallModeLAN)
	}
	if fw.RateLimit != DefaultFirewallRateLimit {
		t.Errorf("默认限速 = %d，应为 %d", fw.RateLimit, DefaultFirewallRateLimit)
	}
	if !fw.AutoBan {
		t.Error("默认应开启自动封禁")
	}
	if fw.AutoBanThreshold != DefaultFirewallAutoBanThreshold || fw.AutoBanMinutes != DefaultFirewallAutoBanMinutes {
		t.Errorf("默认阈值/时长 = %d/%d，应为 %d/%d",
			fw.AutoBanThreshold, fw.AutoBanMinutes, DefaultFirewallAutoBanThreshold, DefaultFirewallAutoBanMinutes)
	}
	// 默认不该预置任何名单：预置任何一条都是替用户做他没做过的决定。
	if len(fw.AllowIPs) != 0 || len(fw.DenyIPs) != 0 {
		t.Errorf("默认名单应为空，实际 allow=%v deny=%v", fw.AllowIPs, fw.DenyIPs)
	}
}

// TestMigrateDisablesFirewallForOldConfig 升级上来的旧配置必须**关着**防火墙。
//
// 这是整个功能里唯一"默认值不等于迁移值"的地方，也是最容易在后续重构中被"统一成
// 调 defaultPanelFirewall 就好"抹平的地方。抹平的后果：一个正从公网管理面板的用户
// 升级一次版本就被锁在外面，而他此刻没有任何入口可以改回来。
func TestMigrateDisablesFirewallForOldConfig(t *testing.T) {
	c := Default()
	c.Version = 9                                  // 升级前的版本
	c.Settings.Security.Firewall = PanelFirewall{} // 旧配置里没有这一段，反序列化后是零值
	Migrate(c)

	fw := c.Settings.Security.Firewall
	if fw.Enabled {
		t.Fatal("升级上来的配置不应自动开启防火墙——那会把公网管理的用户锁在门外")
	}
	// 其余字段仍要填成可用的默认值：用户到界面上一开开关就该是一份合理的策略，
	// 而不是"开了之后阈值是 0、限速是 0"。
	if fw.Mode != FirewallModeLAN {
		t.Errorf("迁移后访问范围 = %q，应为 %q", fw.Mode, FirewallModeLAN)
	}
	if fw.RateLimit != DefaultFirewallRateLimit {
		t.Errorf("迁移后限速 = %d，应为 %d", fw.RateLimit, DefaultFirewallRateLimit)
	}
	if fw.AutoBanThreshold != DefaultFirewallAutoBanThreshold || fw.AutoBanMinutes != DefaultFirewallAutoBanMinutes {
		t.Errorf("迁移后阈值/时长 = %d/%d，应为 %d/%d",
			fw.AutoBanThreshold, fw.AutoBanMinutes, DefaultFirewallAutoBanThreshold, DefaultFirewallAutoBanMinutes)
	}
}

// TestMigrateKeepsExistingFirewall 已经带着 v10 设置的配置再迁移一次不该被改动。
// migrate 会在每次加载时跑，不幂等就等于"每次重启都把用户的选择改回去"。
func TestMigrateKeepsExistingFirewall(t *testing.T) {
	c := Default()
	c.Settings.Security.Firewall = PanelFirewall{
		Enabled: true, Mode: FirewallModeAll,
		AllowIPs:  []string{"203.0.113.5"},
		DenyIPs:   []string{"198.51.100.0/24"},
		RateLimit: 5, AutoBan: true, AutoBanThreshold: 3, AutoBanMinutes: 15,
	}
	want := c.Settings.Security.Firewall
	Migrate(c)
	Migrate(c) // 跑两次：加载期会反复调用
	got := c.Settings.Security.Firewall
	if got.Enabled != want.Enabled || got.Mode != want.Mode ||
		got.RateLimit != want.RateLimit || got.AutoBan != want.AutoBan ||
		got.AutoBanThreshold != want.AutoBanThreshold || got.AutoBanMinutes != want.AutoBanMinutes ||
		len(got.AllowIPs) != 1 || got.AllowIPs[0] != "203.0.113.5" ||
		len(got.DenyIPs) != 1 || got.DenyIPs[0] != "198.51.100.0/24" {
		t.Fatalf("迁移改动了已有设置：%+v → %+v", want, got)
	}
}

func TestNormalizePanelFirewallMode(t *testing.T) {
	// 认不出的取值一律落到最严的那一档。反过来（落到 all）意味着把 mode 手改成
	// 一个错别字就等于把范围限制整个关掉，而界面上看不出任何异常。
	for _, raw := range []string{"", "LAN", "wan", "全部", "all "} {
		f := PanelFirewall{Enabled: true, Mode: raw}
		normalizePanelFirewall(&f)
		if f.Mode != FirewallModeLAN {
			t.Errorf("Mode=%q 规范化后 = %q，应为 %q", raw, f.Mode, FirewallModeLAN)
		}
	}
	for _, raw := range []string{FirewallModeLAN, FirewallModeAll} {
		f := PanelFirewall{Enabled: true, Mode: raw}
		normalizePanelFirewall(&f)
		if f.Mode != raw {
			t.Errorf("Mode=%q 不应被改动，实际 %q", raw, f.Mode)
		}
	}
}

func TestNormalizePanelFirewallNumbers(t *testing.T) {
	cases := []struct {
		name                     string
		in                       PanelFirewall
		rate, threshold, minutes int
	}{
		{
			// 0 在限速上是"不限速"这个有效选择，必须原样留下。
			name: "限速 0 表示不限，保持原值",
			in:   PanelFirewall{RateLimit: 0, AutoBanThreshold: 5, AutoBanMinutes: 5},
			rate: 0, threshold: 5, minutes: 5,
		},
		{
			name: "负数限速夹到 0",
			in:   PanelFirewall{RateLimit: -7, AutoBanThreshold: 5, AutoBanMinutes: 5},
			rate: 0, threshold: 5, minutes: 5,
		},
		{
			name: "超大限速夹到上限",
			in:   PanelFirewall{RateLimit: 1 << 30, AutoBanThreshold: 5, AutoBanMinutes: 5},
			rate: MaxFirewallRateLimit, threshold: 5, minutes: 5,
		},
		{
			// 阈值/时长的 0 **不是**"关闭"（关闭是 AutoBan 开关），夹到 0 的后果分别是
			// "一次超限就封"和"封了立刻过期"，两个都不是用户想表达的意思。
			name: "阈值 0 回落默认而不是夹成 0",
			in:   PanelFirewall{RateLimit: 60, AutoBanThreshold: 0, AutoBanMinutes: 0},
			rate: 60, threshold: DefaultFirewallAutoBanThreshold, minutes: DefaultFirewallAutoBanMinutes,
		},
		{
			name: "阈值/时长负数回落默认",
			in:   PanelFirewall{RateLimit: 60, AutoBanThreshold: -3, AutoBanMinutes: -1},
			rate: 60, threshold: DefaultFirewallAutoBanThreshold, minutes: DefaultFirewallAutoBanMinutes,
		},
		{
			name: "阈值/时长超上限被夹住",
			in:   PanelFirewall{RateLimit: 60, AutoBanThreshold: 1 << 30, AutoBanMinutes: 1 << 30},
			rate: 60, threshold: MaxFirewallAutoBanThreshold, minutes: MaxFirewallAutoBanMinutes,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := tc.in
			f.Enabled = true
			normalizePanelFirewall(&f)
			if f.RateLimit != tc.rate {
				t.Errorf("RateLimit = %d，应为 %d", f.RateLimit, tc.rate)
			}
			if f.AutoBanThreshold != tc.threshold {
				t.Errorf("AutoBanThreshold = %d，应为 %d", f.AutoBanThreshold, tc.threshold)
			}
			if f.AutoBanMinutes != tc.minutes {
				t.Errorf("AutoBanMinutes = %d，应为 %d", f.AutoBanMinutes, tc.minutes)
			}
		})
	}
}

// TestNormalizePanelFirewallIdempotent 加载期每次启动都会跑一遍，不幂等就等于
// "每次重启都把用户的设置改一点"。
func TestNormalizePanelFirewallIdempotent(t *testing.T) {
	f := PanelFirewall{
		Enabled: true, Mode: "bogus",
		AllowIPs:  []string{" 203.0.113.5 ", "203.0.113.5", "写错的地址"},
		DenyIPs:   []string{"198.51.100.0/24"},
		RateLimit: -1, AutoBanThreshold: 0, AutoBanMinutes: 1 << 30,
	}
	normalizePanelFirewall(&f)
	once := fmt.Sprintf("%+v", f)
	normalizePanelFirewall(&f)
	if twice := fmt.Sprintf("%+v", f); once != twice {
		t.Fatalf("规范化不幂等：\n第一次 %s\n第二次 %s", once, twice)
	}
}

func TestNormalizeIPList(t *testing.T) {
	// 去空白、去重（按 trim 后的原文）、丢掉解析不出来的条目、不排序。
	in := []string{
		"  203.0.113.5  ",
		"203.0.113.5", // 与上一条 trim 后相同 → 去重
		"10.0.0.0/8",
		"192.168.1.1-192.168.1.4",
		"",
		"   ",
		"not-an-ip",   // 丢掉
		"10.0.0.0/99", // 前缀非法 → 丢掉
		"1.2.3.4-",    // 范围不完整 → 丢掉
		"2001:db8::1",
	}
	got := normalizeIPList(in)
	want := []string{"203.0.113.5", "10.0.0.0/8", "192.168.1.1-192.168.1.4", "2001:db8::1"}
	if len(got) != len(want) {
		t.Fatalf("整理后 = %v，期望 %v", got, want)
	}
	for i := range want {
		// 顺序必须保持：名单是手写的，顺序里可能有用户自己的分组含义。
		if got[i] != want[i] {
			t.Fatalf("整理后 = %v，期望 %v", got, want)
		}
	}

	// 全是废条目时回 nil，而不是一个空切片——"名单为空"在 Matcher 那边是有语义的。
	if got := normalizeIPList([]string{"", "  ", "nonsense"}); got != nil {
		t.Errorf("全为无效条目时应返回 nil，实际 %v", got)
	}
	if got := normalizeIPList(nil); got != nil {
		t.Errorf("nil 应返回 nil，实际 %v", got)
	}
}

func TestNormalizeIPListCapped(t *testing.T) {
	var in []string
	for i := 0; i < MaxFirewallIPs+100; i++ {
		in = append(in, fmt.Sprintf("10.%d.%d.1", i/256, i%256))
	}
	got := normalizeIPList(in)
	if len(got) != MaxFirewallIPs {
		t.Fatalf("整理后 %d 条，应被夹到 %d", len(got), MaxFirewallIPs)
	}
}

func TestPanelFirewallValid(t *testing.T) {
	base := func() PanelFirewall {
		return PanelFirewall{
			Enabled: true, Mode: FirewallModeLAN,
			RateLimit: 60, AutoBan: true,
			AutoBanThreshold: 20, AutoBanMinutes: 60,
		}
	}
	if err := base().Valid(); err != nil {
		t.Fatalf("一份正常设置不该报错：%v", err)
	}

	// 关闭状态一律放过：拦下来只会让用户没法"先关掉再慢慢改"。
	off := base()
	off.Enabled = false
	off.Mode = "bogus"
	off.RateLimit = -100
	off.AutoBanThreshold = -1
	if err := off.Valid(); err != nil {
		t.Errorf("关闭状态不该校验：%v", err)
	}

	bad := []struct {
		name string
		mut  func(*PanelFirewall)
	}{
		{"模式无效", func(f *PanelFirewall) { f.Mode = "wan" }},
		{"模式为空", func(f *PanelFirewall) { f.Mode = "" }},
		{"限速为负", func(f *PanelFirewall) { f.RateLimit = -1 }},
		{"限速超上限", func(f *PanelFirewall) { f.RateLimit = MaxFirewallRateLimit + 1 }},
		{"阈值为 0", func(f *PanelFirewall) { f.AutoBanThreshold = 0 }},
		{"阈值超上限", func(f *PanelFirewall) { f.AutoBanThreshold = MaxFirewallAutoBanThreshold + 1 }},
		{"时长为 0", func(f *PanelFirewall) { f.AutoBanMinutes = 0 }},
		{"时长超上限", func(f *PanelFirewall) { f.AutoBanMinutes = MaxFirewallAutoBanMinutes + 1 }},
		{"允许名单超长", func(f *PanelFirewall) { f.AllowIPs = make([]string, MaxFirewallIPs+1) }},
		{"拒绝名单超长", func(f *PanelFirewall) { f.DenyIPs = make([]string, MaxFirewallIPs+1) }},
	}
	for _, tc := range bad {
		t.Run(tc.name, func(t *testing.T) {
			f := base()
			tc.mut(&f)
			if err := f.Valid(); err == nil {
				t.Fatalf("%s 应被拦下", tc.name)
			}
		})
	}

	// 自动封禁关着时，阈值与时长填成什么都不影响行为，不该拦。
	noBan := base()
	noBan.AutoBan = false
	noBan.AutoBanThreshold = 0
	noBan.AutoBanMinutes = 0
	if err := noBan.Valid(); err != nil {
		t.Errorf("自动封禁关闭时不该校验其参数：%v", err)
	}
}

// TestNormalizePanelFirewallNilSafe 导入路径可能传进 nil，不该 panic。
func TestNormalizePanelFirewallNilSafe(t *testing.T) {
	NormalizePanelFirewall(nil)
}
