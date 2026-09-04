package ipx

import (
	"net"
	"testing"
)

// countAddrs 返回一组网络覆盖的地址总数（仅用于小范围断言）。
func countAddrs(nets []*net.IPNet) uint64 {
	var total uint64
	for _, n := range nets {
		ones, bits := n.Mask.Size()
		total += uint64(1) << uint(bits-ones)
	}
	return total
}

// TestParseRangeCoversWholeSpan 是 A-3 的回归测试：大范围必须被**完整**覆盖。
//
// 旧实现把 a-b 展开成单 IP 并在第 4097 条静默截断，于是 1.0.0.0-2.0.0.0 实际只覆盖到
// 1.0.15.255。对拒绝名单来说这是「以为整段被拒、其实只拒了开头一小段」，且界面无告警。
func TestParseRangeCoversWholeSpan(t *testing.T) {
	m := NewMatcher([]string{"1.0.0.0-2.0.0.0"})
	for _, s := range []string{
		"1.0.0.0",       // 起点
		"1.0.15.255",    // 旧实现的截断边界
		"1.0.16.0",      // 紧随截断边界之后：旧实现在这里开始漏
		"1.128.0.0",     // 区间中部
		"1.255.255.255", // 终点前一个
		"2.0.0.0",       // 终点（闭区间）
	} {
		if !m.Match(net.ParseIP(s)) {
			t.Errorf("%s 应命中 1.0.0.0-2.0.0.0", s)
		}
	}
	for _, s := range []string{"0.255.255.255", "2.0.0.1", "3.0.0.0"} {
		if m.Match(net.ParseIP(s)) {
			t.Errorf("%s 不应命中 1.0.0.0-2.0.0.0", s)
		}
	}
}

// TestParseRangeExactCoverage 校验分解结果既不多覆盖也不少覆盖。
func TestParseRangeExactCoverage(t *testing.T) {
	cases := []struct {
		item string
		want uint64 // 区间内地址数
	}{
		{"192.168.5.1-192.168.5.4", 4},
		{"192.168.5.0-192.168.5.255", 256},
		{"10.0.0.7-10.0.0.7", 1},
		{"172.16.0.5-172.16.3.200", 964}, // (3*256+200) - 5 + 1
	}
	for _, tc := range cases {
		nets := ParseCIDRs([]string{tc.item})
		if got := countAddrs(nets); got != tc.want {
			t.Errorf("%s 覆盖 %d 个地址，期望 %d（分解为 %d 块）", tc.item, got, tc.want, len(nets))
		}
	}
}

// TestParseRangeBoundaries 逐地址核对小范围的命中/不命中边界。
func TestParseRangeBoundaries(t *testing.T) {
	m := NewMatcher([]string{"192.168.5.3-192.168.5.9"})
	for i := 0; i <= 12; i++ {
		ip := net.IPv4(192, 168, 5, byte(i))
		want := i >= 3 && i <= 9
		if got := m.Match(ip); got != want {
			t.Errorf("192.168.5.%d 命中=%v，期望 %v", i, got, want)
		}
	}
}

// TestParseRangeRejectsInverted 起点大于终点应整条作废。
//
// 旧实现在这里不会停：cur 递增永远等不到 end，于是一路走到 4096 条封顶，
// 往名单里塞进 4096 个与用户意图无关的地址（对拒绝名单是误封，对允许名单是误放）。
func TestParseRangeRejectsInverted(t *testing.T) {
	for _, item := range []string{
		"192.168.5.9-192.168.5.3",
		"2.0.0.0-1.0.0.0",
		"2001:db8::9-2001:db8::1",
	} {
		if nets := ParseCIDRs([]string{item}); len(nets) != 0 {
			t.Errorf("%s 应视为无效，实际解析出 %d 条", item, len(nets))
		}
	}
}

// TestParseRangeRejectsMixedFamily 起止协议族不一致应整条作废。
func TestParseRangeRejectsMixedFamily(t *testing.T) {
	for _, item := range []string{"192.168.1.1-2001:db8::1", "2001:db8::1-192.168.1.1"} {
		if nets := ParseCIDRs([]string{item}); len(nets) != 0 {
			t.Errorf("%s 应视为无效，实际解析出 %d 条", item, len(nets))
		}
	}
}

// TestParseRangeBlockCountBounded 分解块数必须有上界：任意闭区间不超过 2*bitLen-2 块。
// 这是「不再需要条数封顶」这个结论的依据——若没有上界，就得回到截断或拒绝的取舍上。
func TestParseRangeBlockCountBounded(t *testing.T) {
	cases := []struct {
		item string
		max  int
	}{
		{"0.0.0.1-255.255.255.254", 62},                      // IPv4 最坏情况
		{"1.0.0.0-2.0.0.0", 62},                              // 用户会真的这么填
		{"::1-ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffe", 254}, // IPv6 最坏情况
	}
	for _, tc := range cases {
		nets := ParseCIDRs([]string{tc.item})
		if len(nets) == 0 {
			t.Errorf("%s 应解析出至少一条", tc.item)
			continue
		}
		if len(nets) > tc.max {
			t.Errorf("%s 分解成 %d 块，超过上界 %d", tc.item, len(nets), tc.max)
		}
	}
}

// TestParseRangeFullSpace 整个地址空间应折成单条默认路由，而不是天量条目。
func TestParseRangeFullSpace(t *testing.T) {
	cases := []struct{ item, want string }{
		{"0.0.0.0-255.255.255.255", "0.0.0.0/0"},
		{"::-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "::/0"},
	}
	for _, tc := range cases {
		nets := ParseCIDRs([]string{tc.item})
		if len(nets) != 1 || nets[0].String() != tc.want {
			t.Errorf("%s 应解析为单条 %s，实际 %v", tc.item, tc.want, nets)
		}
	}
}

// TestParseRangeIPv6 IPv6 范围同样要精确覆盖。
func TestParseRangeIPv6(t *testing.T) {
	m := NewMatcher([]string{"2001:db8::-2001:db8:0:ffff:ffff:ffff:ffff:ffff"})
	for _, s := range []string{"2001:db8::", "2001:db8::1", "2001:db8:0:ffff::", "2001:db8:0:ffff:ffff:ffff:ffff:ffff"} {
		if !m.Match(net.ParseIP(s)) {
			t.Errorf("%s 应命中", s)
		}
	}
	for _, s := range []string{"2001:db8:1::", "2001:db7:ffff::ffff"} {
		if m.Match(net.ParseIP(s)) {
			t.Errorf("%s 不应命中", s)
		}
	}
}
