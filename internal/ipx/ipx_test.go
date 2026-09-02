package ipx

import (
	"net"
	"net/http"
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

// TestIsLAN 钉住「哪些来源算局域网」。
//
// 这个判断是面板入站防火墙默认策略的全部内容，判宽一格就等于对一批本不该进来的
// 来源开门，而症状（"防火墙开着，但外面还是连得上"）不会有任何报错。
func TestIsLAN(t *testing.T) {
	lan := []string{
		"127.0.0.1",           // 回环
		"::1",                 // IPv6 回环
		"10.1.2.3",            // 10/8
		"172.16.0.1",          // 172.16/12 下界
		"172.31.255.254",      // 172.16/12 上界
		"192.168.1.20",        // 192.168/16
		"169.254.10.10",       // IPv4 链路本地（APIPA）
		"fd00::1",             // IPv6 ULA
		"fe80::1",             // IPv6 链路本地
		"::ffff:192.168.1.20", // IPv4 映射的私有地址
		"::ffff:127.0.0.1",    // IPv4 映射的回环
	}
	for _, s := range lan {
		if !IsLAN(net.ParseIP(s)) {
			t.Errorf("%s 应算局域网", s)
		}
	}

	wan := []string{
		"203.0.113.5",        // 公网
		"8.8.8.8",            // 公网
		"172.15.0.1",         // 172.16/12 之下，是公网
		"172.32.0.1",         // 172.16/12 之上，是公网
		"2001:db8::1",        // IPv6 文档地址，按公网处理
		"::ffff:203.0.113.5", // IPv4 映射的公网地址，不能靠写法绕过
		"0.0.0.0",            // 未指定地址不是"局域网内的某台机器"
		"::",                 // 同上
		"224.0.0.1",          // 组播不是单播来源
		"100.64.0.9",         // 运营商级 NAT（CGNAT）——见下方说明
		"100.127.255.255",    // CGNAT 段内另一个地址
	}
	for _, s := range wan {
		if IsLAN(net.ParseIP(s)) {
			t.Errorf("%s 不应算局域网", s)
		}
	}

	// CGNAT（100.64.0.0/10）刻意排除在外：那是 ISP 的共享地址池，把它算进局域网
	// 等于对一整批同运营商订户开门。注意这与 netguard.IsPrivateOrReserved 的取向相反——
	// 那个函数判断的是**出站目标**，宁可多拦（防 SSRF）；这里判断的是**入站来源**，
	// 必须宁可少放。两处方向不同不是不一致，而是各自都在往安全的一侧偏。
	if IsLAN(nil) {
		t.Error("nil 应按失败关闭处理，不算局域网")
	}
}

// TestClientIPStripsIPv6Zone 链路本地对端带 %zone，必须仍能解析出地址。
//
// 这一条钉的是一个真实缺陷：内核给的 sin6_scope_id 会进到 net.TCPAddr.Zone，
// RemoteAddr 于是长成 `[fe80::1%eth0]:1234`，而 net.ParseIP 对带 zone 的字面量返回 nil。
// 所有按来源做的判定都会把这个合法的局域网对端当成"地址解析不出来"处理——
// 面板入站防火墙在连接层放行（那里拿的是 TCPAddr.IP，不带 zone）、在请求层却按
// 失败关闭回 403，同一个来源在两层上判得不一样。
func TestClientIPStripsIPv6Zone(t *testing.T) {
	cases := []struct {
		remote string
		want   string
	}{
		{remote: "[fe80::1%eth0]:1234", want: "fe80::1"},
		{remote: "[fe80::abcd%25]:443", want: "fe80::abcd"},
		{remote: "[::1]:8080", want: "::1"},
		{remote: "192.168.1.20:1234", want: "192.168.1.20"},
	}
	for _, tc := range cases {
		r := &http.Request{RemoteAddr: tc.remote}
		got := ClientIP(r)
		if got == nil {
			t.Errorf("ClientIP(%q) = nil，应解析出 %s", tc.remote, tc.want)
			continue
		}
		if !got.Equal(net.ParseIP(tc.want)) {
			t.Errorf("ClientIP(%q) = %v，应为 %s", tc.remote, got, tc.want)
		}
		if host := RemoteHost(tc.remote); host != tc.want {
			t.Errorf("RemoteHost(%q) = %q，应为 %q——它当限流分桶键用，必须与 ClientIP 同口径",
				tc.remote, host, tc.want)
		}
	}
	// 带 zone 的链路本地地址要能走到"算局域网"这一步，否则仅局域网模式会把它挡在外面。
	if ip := ClientIP(&http.Request{RemoteAddr: "[fe80::1%eth0]:1234"}); !IsLAN(ip) {
		t.Error("带 zone 的链路本地对端应算局域网")
	}
}
