package netguard

import (
	"errors"
	"net"
	"testing"
	"time"
)

// TestIsPrivateOrReservedBlocks 覆盖各类不可作为出站目标的地址，
// 重点是 net.IP 内置谓词覆盖不到、需靠 reservedNets 兜住的几段。
func TestIsPrivateOrReservedBlocks(t *testing.T) {
	cases := []struct{ ip, why string }{
		{"127.0.0.1", "回环"},
		{"10.1.2.3", "私有 A"},
		{"172.16.0.1", "私有 B"},
		{"192.168.1.1", "私有 C"},
		{"0.0.0.0", "未指定"},
		{"169.254.1.1", "链路本地"},
		{"224.0.0.1", "多播"},
		{"100.64.0.1", "运营商级 NAT"},
		{"100.127.255.255", "运营商级 NAT 上界"},
		{"192.0.0.8", "IETF 协议专用"},
		{"192.88.99.1", "废弃的 6to4 中继任播"},
		{"198.18.0.1", "基准测试"},
		{"198.19.255.255", "基准测试上界"},
		{"240.0.0.1", "保留未分配"},
		{"255.255.255.255", "受限广播（落在 240.0.0.0/4 内）"},
		{"::1", "IPv6 回环"},
		{"fd00::1", "IPv6 私有"},
		{"fe80::1", "IPv6 链路本地"},
		{"::ffff:192.168.1.1", "IPv4 映射的私有地址"},
		{"::ffff:100.64.0.1", "IPv4 映射的运营商级 NAT"},
		{"64:ff9b::c0a8:101", "NAT64 内嵌 192.168.1.1"},
		{"2002:c0a8:101::1", "6to4 内嵌 192.168.1.1"},
	}
	for _, c := range cases {
		ip := net.ParseIP(c.ip)
		if ip == nil {
			t.Fatalf("测试用例地址非法: %s", c.ip)
		}
		if !IsPrivateOrReserved(ip) {
			t.Errorf("%s (%s) 应被判定为内网 / 保留地址", c.ip, c.why)
		}
	}
	if !IsPrivateOrReserved(nil) {
		t.Errorf("nil 应按不安全处理")
	}
}

// TestIsPrivateOrReservedAllowsPublic 公网地址不得被误拦——误拦会让 DDNS 直接失效。
func TestIsPrivateOrReservedAllowsPublic(t *testing.T) {
	for _, s := range []string{
		"8.8.8.8",
		"1.1.1.1",
		"223.5.5.5",
		"100.63.255.255",  // 紧邻 100.64.0.0/10 下界之外
		"100.128.0.1",     // 紧邻 100.64.0.0/10 上界之外
		"192.0.1.1",       // 紧邻 192.0.0.0/24 之外
		"198.17.255.255",  // 紧邻 198.18.0.0/15 之外
		"198.20.0.1",      // 紧邻 198.18.0.0/15 之外
		"239.255.255.255", // 多播上界之内，交由 IsMulticast 处理，此处仅确认 240/4 不越界
		"2001:4860:4860::8888",
		"2606:4700::1111",
		"2003::1", // 紧邻 2002::/16 之外
	} {
		ip := net.ParseIP(s)
		if ip == nil {
			t.Fatalf("测试用例地址非法: %s", s)
		}
		blocked := IsPrivateOrReserved(ip)
		if s == "239.255.255.255" {
			// 该地址确属多播，应被拦；此处只是防止 240.0.0.0/4 的边界写错而波及多播段判定路径。
			if !blocked {
				t.Errorf("%s 属多播，应被拦", s)
			}
			continue
		}
		if blocked {
			t.Errorf("%s 是公网地址，不应被拦", s)
		}
	}
}

// TestControlBlockPrivateRejects Control 钩子应对内网目标与无法解析的地址返回 ErrBlocked。
func TestControlBlockPrivateRejects(t *testing.T) {
	if err := controlBlockPrivate("tcp", "192.168.1.1:80", nil); !errors.Is(err, ErrBlocked) {
		t.Errorf("内网目标应被拦截，实际: %v", err)
	}
	// 拨号层拿到的必然是已解析的 IP；出现域名说明解析路径异常，按不安全处理。
	if err := controlBlockPrivate("tcp", "example.com:80", nil); !errors.Is(err, ErrBlocked) {
		t.Errorf("无法解析的目标应被拦截，实际: %v", err)
	}
	if err := controlBlockPrivate("tcp", "8.8.8.8:443", nil); err != nil {
		t.Errorf("公网目标不应被拦截，实际: %v", err)
	}
}

// TestHTTPClientReusesTransport 连接池必须跨调用复用：这是 IO-11 的全部意义所在。
// 同时确认防护开 / 关两条路径各用独立 Transport，不会共享连接。
func TestHTTPClientReusesTransport(t *testing.T) {
	a := HTTPClient(false, 0)
	b := HTTPClient(false, 10*time.Second)
	if a.Transport != b.Transport {
		t.Errorf("同一 enabled 取值应复用同一 Transport")
	}
	if a.Transport == HTTPClient(true, 0).Transport {
		t.Errorf("防护开 / 关不应共享 Transport")
	}
	if b.Timeout != 10*time.Second {
		t.Errorf("客户端级超时未生效: %v", b.Timeout)
	}
	// 防护路径不设 Proxy（见 newTransport 注释），普通路径应尊重环境变量代理。
	if guardedTransport().Proxy != nil {
		t.Errorf("防护路径不应经代理，否则 Control 钩子失效")
	}
	if plainTransport().Proxy == nil {
		t.Errorf("普通路径应尊重环境变量代理")
	}
}
