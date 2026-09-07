package ipx

import (
	"net"
	"testing"
)

// IsLocalHost / IsLocalIP 的边界。这两个判定被端口转发的保存校验与运行期防御共用
// （审计 NEW-1），判错的后果分两侧：错判成"是本机"会把一条合法规则挡在门外，
// 错判成"不是"则少拦一次误配置。文件头说明了为什么往后者倒。
//
// 这里钉的是**解析**这一层：方括号、%zone、根点、大小写、以及"不查 DNS"这条刻意的边界。
// 网卡地址那一支单列在 TestIsLocalIPKnowsOwnInterfaceAddrs。
func TestIsLocalHost(t *testing.T) {
	cases := []struct {
		host string
		want bool
	}{
		// 回环与未指定：不查任何表就能定。
		{"127.0.0.1", true},
		{"127.0.0.53", true}, // 整个 127/8 都是回环
		{"::1", true},
		{"[::1]", true},     // 浏览器地址栏复制过来就是这个形状
		{"[::1%lo0]", true}, // 方括号 + zone
		{"0.0.0.0", true},   // 作为拨号目标会落到本机
		{"::", true},
		{"[::]", true},

		// RFC 6761：localhost 必然指向回环，不查 DNS 也知道。
		{"localhost", true},
		{"LOCALHOST", true},
		{"LocalHost", true},
		{"localhost.", true},
		{"panel.localhost", true},
		{"a.b.localhost.", true},
		{" localhost ", true}, // 前后空白由调用方（配置里的手输值）带进来

		// 不查 DNS：普通主机名一律 false。理由见文件头——保存那一刻的解析结果
		// 不构成运行期保证（DNS 重绑定），真要靠它得在每次拨号时再查一遍。
		{"example.com", false},
		{"localhost.example.com", false}, // 后缀在中间，不是 .localhost
		{"notlocalhost", false},
		{"my-localhost", false},

		// 远端地址。
		{"203.0.113.9", false},
		{"8.8.8.8", false},
		{"2001:db8::1", false},

		// 空与垃圾输入。
		{"", false},
		{"   ", false},
		{"[", false},
		{"[]", false},
		{"1.2.3", false},
	}

	for _, c := range cases {
		t.Run(c.host, func(t *testing.T) {
			if got := IsLocalHost(c.host); got != c.want {
				t.Fatalf("IsLocalHost(%q) = %v，应为 %v", c.host, got, c.want)
			}
		})
	}
}

// TestIsLocalIPKnowsOwnInterfaceAddrs 本机网卡上的地址算本机。
//
// 这是审计 NEW-1 里"弱化版"那种写法要走的路径：目标写本机的局域网地址时，
// 回环豁免不生效，但面板防护的「仅局域网」照样被绕过、所有来源仍塌成同一个 IP。
func TestIsLocalIPKnowsOwnInterfaceAddrs(t *testing.T) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		t.Skipf("枚举本机网卡失败，跳过：%v", err)
	}
	checked := 0
	for _, a := range addrs {
		ipnet, ok := a.(*net.IPNet)
		if !ok || ipnet.IP == nil {
			continue
		}
		if !IsLocalIP(ipnet.IP) {
			t.Errorf("%s 在本机网卡上，IsLocalIP 应为 true", ipnet.IP)
		}
		// 字符串形状也要认（IPv6 走方括号写法）。
		host := ipnet.IP.String()
		if ipnet.IP.To4() == nil {
			host = "[" + host + "]"
		}
		if !IsLocalHost(host) {
			t.Errorf("IsLocalHost(%q) 应为 true", host)
		}
		checked++
	}
	if checked == 0 {
		t.Skip("本机没有可判定的网卡地址，跳过")
	}
}

// TestIsLocalIPNil nil 不算本机（而不是 panic）。
// 调用方拿到的是 net.ParseIP 的结果，解析失败就是 nil，这条路必须是安全的。
func TestIsLocalIPNil(t *testing.T) {
	if IsLocalIP(nil) {
		t.Fatal("IsLocalIP(nil) 应为 false")
	}
}

// TestURLTargetsLocalPort 反代上游"指向本机面板端口"的判定。
//
// 这条判定被保存校验（api_resources.validateWebService）与运行期跳过
// （webservice.Reload）共用，两侧必须给出同一个答案，否则会出现"保存得进去、
// 运行期却被跳过"的哑规则。所以口径只有这一处，测试也钉在这一处。
//
// 重点在**默认端口**那几行：面板跑在 80/443 上时，用户写的上游几乎一定是
// http://127.0.0.1 这种不带端口的形状。
func TestURLTargetsLocalPort(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		port int
		want bool
	}{
		// 显式端口命中。
		{"回环显式端口", "http://127.0.0.1:8080", 8080, true},
		{"localhost 显式端口", "http://localhost:8080", 8080, true},
		{"IPv6 回环方括号", "http://[::1]:8080", 8080, true},
		{"https 显式端口", "https://127.0.0.1:8443", 8443, true},
		// 端口不同：这是反代的正常用法，绝不能拦。
		{"端口不同", "http://127.0.0.1:3000", 8080, false},
		// scheme 默认端口——不带端口的写法必须能被认出来。
		{"http 默认 80", "http://127.0.0.1", 80, true},
		{"https 默认 443", "https://127.0.0.1", 443, true},
		{"http 默认端口不等于面板端口", "http://127.0.0.1", 8080, false},
		{"https 不能被当成 80", "https://127.0.0.1", 80, false},
		{"http 不能被当成 443", "http://127.0.0.1", 443, false},
		// 主机不指向本机：端口撞上也无关。
		{"外部主机同端口", "http://example.com:8080", 8080, false},
		{"外部 IP 同端口", "http://203.0.113.9:8080", 8080, false},
		// 不做 DNS：普通主机名一律不算本机，即使它其实解析到回环。
		{"普通主机名不查 DNS", "http://my-nas.lan:8080", 8080, false},
		// .localhost 后缀按 RFC 6761 必然回环。
		{"localhost 后缀", "http://api.localhost:8080", 8080, true},
		// 未指定地址作为拨号目标会落到本机。
		{"未指定地址", "http://0.0.0.0:8080", 8080, true},
		// 失败一律不算本机。
		{"空串", "", 8080, false},
		{"无主机", "http://", 8080, false},
		{"只有路径", "/api", 8080, false},
		{"端口非数字", "http://127.0.0.1:abc", 8080, false},
		{"认不出的 scheme", "tcp://127.0.0.1", 80, false},
		// 面板端口未知时不做任何判定。
		{"端口为零", "http://127.0.0.1:8080", 0, false},
		{"端口为负", "http://127.0.0.1:8080", -1, false},
		// 首尾空白：表单里粘贴出来常带。
		{"带空白", "  http://127.0.0.1:8080  ", 8080, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := URLTargetsLocalPort(tc.raw, tc.port); got != tc.want {
				t.Fatalf("URLTargetsLocalPort(%q, %d) = %v，期望 %v", tc.raw, tc.port, got, tc.want)
			}
		})
	}
}
