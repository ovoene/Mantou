package ipx

import (
	"net"
	"testing"
)

// TestIPMatcherSplitsHostsAndNets 单主机条目应进精确匹配表，只有带前缀的网段才留在线性扫描表里。
// 这正是 M-28 的要点：范围写法会展开成大量单 IP，若全部线性扫，每个请求都要遍历整表。
func TestIPMatcherSplitsHostsAndNets(t *testing.T) {
	m := NewMatcher([]string{
		"203.0.113.7",             // 单 IP → hosts
		"10.0.0.0/8",              // 前缀 → nets
		"192.168.5.1-192.168.5.4", // 范围 → 展开 4 个单 IP → hosts
		"2001:db8::1",             // IPv6 单 IP → hosts
		"2001:db8:1::/48",         // IPv6 前缀 → nets
	})
	if len(m.hosts) != 6 {
		t.Errorf("精确匹配表应有 6 条，实际 %d", len(m.hosts))
	}
	if len(m.nets) != 2 {
		t.Errorf("网段表应有 2 条，实际 %d", len(m.nets))
	}
}

// TestIPMatcherMatch 覆盖三类写法的命中与不命中。
func TestIPMatcherMatch(t *testing.T) {
	m := NewMatcher([]string{
		"203.0.113.7",
		"10.0.0.0/8",
		"192.168.5.1-192.168.5.4",
		"2001:db8::1",
		"2001:db8:1::/48",
	})
	hit := []string{
		"203.0.113.7",   // 单 IP
		"10.1.2.3",      // /8 之内
		"192.168.5.1",   // 范围下界
		"192.168.5.3",   // 范围中间
		"192.168.5.4",   // 范围上界
		"2001:db8::1",   // IPv6 单 IP
		"2001:db8:1::9", // IPv6 /48 之内
	}
	for _, s := range hit {
		if !m.Match(net.ParseIP(s)) {
			t.Errorf("%s 应命中名单", s)
		}
	}
	miss := []string{
		"203.0.113.8",   // 与单 IP 相邻
		"11.0.0.1",      // /8 之外
		"192.168.5.0",   // 范围下界之外
		"192.168.5.5",   // 范围上界之外
		"2001:db8::2",   // 与 IPv6 单 IP 相邻
		"2001:db8:2::1", // IPv6 /48 之外
	}
	for _, s := range miss {
		if m.Match(net.ParseIP(s)) {
			t.Errorf("%s 不应命中名单", s)
		}
	}
}

// TestIPMatcherKeyNormalizesIPv4Forms net.IP 有 4 字节与 IPv4-in-IPv6 两种表示，
// 精确匹配表若不归一，同一个地址会因表示形式不同而漏匹配。
func TestIPMatcherKeyNormalizesIPv4Forms(t *testing.T) {
	m := NewMatcher([]string{"198.51.100.9"})
	four := net.ParseIP("198.51.100.9").To4()
	if four == nil {
		t.Fatal("To4 应成功")
	}
	if !m.Match(four) {
		t.Errorf("4 字节表示应命中")
	}
	if !m.Match(four.To16()) {
		t.Errorf("16 字节表示应命中")
	}
	if !m.Match(net.ParseIP("::ffff:198.51.100.9")) {
		t.Errorf("IPv4 映射写法应命中")
	}
}

// TestIPMatcherEmpty 空白与非法条目不应产生任何有效规则——否则「允许名单非空」的判断会误判，
// 把一份写错的白名单变成「谁都进不来」。
func TestIPMatcherEmpty(t *testing.T) {
	for _, items := range [][]string{
		nil,
		{},
		{"", "   "},
		{"not-an-ip", "10.0.0.0/99", "1.2.3.4-", "-1.2.3.4", "1.2.3.4-::1"},
	} {
		if m := NewMatcher(items); !m.Empty() {
			t.Errorf("%v 应解析为空名单，实际 hosts=%d nets=%d", items, len(m.hosts), len(m.nets))
		}
	}
	if NewMatcher([]string{"0.0.0.0/0"}).Empty() {
		t.Errorf("0.0.0.0/0 是有效规则（放行全部），不应视为空名单")
	}
}
