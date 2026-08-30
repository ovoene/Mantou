package ddns

import (
	"net"
	"strings"
	"testing"
	"unicode/utf8"
)

// ULA（fc00::/7）与文档段（2001:db8::/32）在 IsGlobalUnicast() 下均为 true，
// 若不显式排除就会把纯内网地址写进公网 DNS，界面还显示"更新成功"。
func TestRoutableIPv6RejectsNonPublicAddresses(t *testing.T) {
	cases := []struct {
		ip   string
		want bool
	}{
		{"2400:8902::f03c:91ff:fe0a:1", true},
		{"2001:19f0:5:28c8::1", true},
		{"fd12:3456:789a::1", false}, // ULA（最常见的内网 IPv6）
		{"fc00::1", false},           // ULA 段首
		{"fdff:ffff:ffff:ffff::1", false},
		{"2001:db8::1", false}, // 文档示例段
		{"fe80::1", false},     // 链路本地
		{"::1", false},         // 回环
		{"ff02::1", false},     // 组播
		{"::", false},          // 未指定
		{"203.0.113.7", false}, // IPv4 不走这条判定
		{"::ffff:203.0.113.7", false},
	}
	for _, c := range cases {
		ip := net.ParseIP(c.ip)
		if ip == nil {
			t.Fatalf("测试数据本身不是合法 IP: %s", c.ip)
		}
		if got := routableIPv6(ip); got != c.want {
			t.Errorf("routableIPv6(%s) = %v，期望 %v", c.ip, got, c.want)
		}
	}
}

// 同一组候选地址必须得到同一个结果：否则隐私扩展（RFC 4941）下临时地址轮换
// 会让取址结果来回跳变，DDNS 反复改写同一条记录。
func TestStableIPPicksSameAddressRegardlessOfOrder(t *testing.T) {
	parse := func(list ...string) []net.IP {
		out := make([]net.IP, 0, len(list))
		for _, s := range list {
			ip := net.ParseIP(s)
			if ip == nil {
				t.Fatalf("测试数据本身不是合法 IP: %s", s)
			}
			out = append(out, ip)
		}
		return out
	}

	const want = "2001:db8:1::5" // 三者中字节序最小的那个
	orders := [][]net.IP{
		parse("2001:db8:1::5", "2001:db8:1::a", "2001:db8:9::1"),
		parse("2001:db8:9::1", "2001:db8:1::5", "2001:db8:1::a"),
		parse("2001:db8:1::a", "2001:db8:9::1", "2001:db8:1::5"),
	}
	for i, ips := range orders {
		if got := stableIP(ips).String(); got != want {
			t.Errorf("第 %d 种输入顺序得到 %s，期望 %s（结果必须与顺序无关）", i, got, want)
		}
	}

	// 单个候选时原样返回。
	if got := stableIP(parse("2001:db8::7")).String(); got != "2001:db8::7" {
		t.Errorf("单候选应原样返回，实际 %s", got)
	}
}

// 取址端点的返回值直接决定写入 DNS 的记录内容：明文 HTTP 下中间人可把域名指向任意地址。
func TestPublicEndpointsUseHTTPS(t *testing.T) {
	for _, ep := range append(append([]string{}, publicV4Endpoints...), publicV6Endpoints...) {
		if !strings.HasPrefix(ep, "https://") {
			t.Errorf("取址端点必须是 HTTPS: %s", ep)
		}
	}
}

// 截断必须切在字符边界：中文每字符 3 字节，按字节直接切有 2/3 概率产生非法 UTF-8，
// 这段文本会写进 LastStatus 并随接口返回前端，显示成乱码。
// 上限的单位是字节（见 strutil.Truncate 的说明）：真正要限制的是这段外部文本占多少内存。
func TestTruncateCutsOnRuneBoundary(t *testing.T) {
	const s = "返回内容不是合法的公网地址，请检查取址端点"
	got := truncate(s, 5)
	if !utf8.ValidString(got) {
		t.Fatalf("截断结果不是合法 UTF-8: %q", got)
	}
	// 5 字节只装得下 1 个汉字（3 字节），第 2 个字会被回退掉。
	if want := "返" + "…"; got != want {
		t.Fatalf("截断结果 = %q，期望 %q", got, want)
	}
	// 不超长时原样返回，且不追加省略号。
	if got := truncate(s, 192); got != s {
		t.Fatalf("未超长时应原样返回，实际 %q", got)
	}
	if got := truncate("", 4); got != "" {
		t.Fatalf("空串应原样返回，实际 %q", got)
	}
}
