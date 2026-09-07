package netguard

import (
	"errors"
	"net"
	"strings"
	"testing"
)

// BlockLinkLocal 是挂在**反向代理**拨号路上的那道窄拦截，性质与本包其余部分正好相反：
// 那些是用户可以开关的「内网防护」，这一道无条件生效，且必须**放过内网地址**——
// 把 192.168.1.10:8080 发布到公网正是 Web 服务这个功能存在的理由。
//
// 于是这条测试要同时钉住两个方向，缺一个都是坏的：
//   - 拦住 169.254.0.0/16 与 fe80::/10（各家云的实例元数据端点就在前者上，
//     上面挂着这台机器的临时凭证。一条指向它的反代后端等于把云凭证接口发布到公网，
//     而它在界面上与一条正常的内网反代长得一模一样）；
//   - 放过私有地址、ULA、公网地址（拦掉任何一类都等于把功能弄坏，
//     而这种坏法会表现成"所有反代都 502"，比漏拦更显眼但同样是回归）。
//
// ULA（fd00::/8）单列一条：AWS 的 IPv6 元数据端点 fd00:ec2::254 就在那一段里，
// 但整个 fc00::/7 同时也是自建内网大量在用的地址段，所以这里刻意不拦——
// 那件事归用户自己开启的内网防护管。这条用例在于把"刻意"钉成规则，
// 免得往后有人顺手把它一并加进来。

// controlErr 走一遍 Control 钩子，返回它的判断。
func controlErr(t *testing.T, address string) error {
	t.Helper()
	return BlockLinkLocal("tcp", address, nil)
}

func TestBlockLinkLocalBlocks(t *testing.T) {
	cases := []struct {
		name string
		addr string
	}{
		{"云元数据端点", "169.254.169.254:80"},
		{"链路本地其它地址", "169.254.1.2:8080"},
		{"IPv4 映射写法", "[::ffff:169.254.169.254]:80"},
		{"IPv6 链路本地", "[fe80::1]:80"},
		{"IPv6 链路本地带 zone", "[fe80::1%eth0]:80"},
		// 没有端口的形态：Control 钩子拿到的总是 ip:port，但判定不该依赖这一点。
		{"裸地址无端口", "169.254.169.254"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := controlErr(t, tc.addr)
			if err == nil {
				t.Fatalf("%s 应被拦下", tc.addr)
			}
			if !errors.Is(err, ErrLinkLocalBlocked) {
				t.Fatalf("错误应可用 errors.Is 认出 ErrLinkLocalBlocked，实际 %v", err)
			}
			// 拦下的原因会进访问日志的 Reason 字段，得能看出是哪个地址。
			if !strings.Contains(err.Error(), "链路本地") {
				t.Fatalf("错误文案里应说明原因，实际 %q", err.Error())
			}
		})
	}
}

func TestBlockLinkLocalAllows(t *testing.T) {
	cases := []struct {
		name string
		addr string
	}{
		// 反代内网服务是这个功能的正当用途，一个都不能拦。
		{"私有 A 段", "10.0.0.5:8080"},
		{"私有 B 段", "172.16.3.4:8080"},
		{"私有 C 段", "192.168.1.10:8080"},
		{"回环", "127.0.0.1:3000"},
		{"IPv6 回环", "[::1]:3000"},
		// ULA：AWS 的 IPv6 元数据在这一段，但自建内网也在这一段，刻意放过。
		{"ULA（含 AWS v6 元数据）", "[fd00:ec2::254]:80"},
		{"ULA 自建内网", "[fd12:3456::1]:8080"},
		// 公网后端。
		{"公网 IPv4", "203.0.113.9:443"},
		{"公网 IPv6", "[2001:4860:4860::8888]:443"},
		// 运营商级 NAT：属于内网防护要管的范围，不属于这一道。
		{"CGNAT", "100.64.0.1:8080"},
		// 认不出的地址形态放过（与 controlBlockPrivate 相反，理由见 BlockLinkLocal 注释）。
		{"不是 IP", "backend.internal:8080"},
		{"空串", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := controlErr(t, tc.addr); err != nil {
				t.Fatalf("%s 不该被拦：%v", tc.addr, err)
			}
		})
	}
}

// TestZonedLinkLocalReachesBothHooks 带 %zone 的链路本地地址在两个钩子里都被正确归类。
//
// net.ParseIP 不认 fe80::1%eth0 这种写法，而链路本地地址在拨号时恰恰经常带着 zone。
// 不剥掉 zone 的话：窄拦截那边"认不出就放过"，等于对这一整类写法漏拦（这条测试写出来
// 时就是红的）；内网防护那边虽然照样拒绝，但报的是"无法解析目标地址"，
// 排查的人会以为是地址写错了而不是被策略拦下。
func TestZonedLinkLocalReachesBothHooks(t *testing.T) {
	const addr = "[fe80::1%eth0]:80"
	if err := BlockLinkLocal("tcp", addr, nil); !errors.Is(err, ErrLinkLocalBlocked) {
		t.Fatalf("窄拦截应认出带 zone 的链路本地地址，实际 %v", err)
	}
	err := controlBlockPrivate("tcp", addr, nil)
	if !errors.Is(err, ErrBlocked) {
		t.Fatalf("内网防护也应拦下带 zone 的链路本地地址，实际 %v", err)
	}
	if strings.Contains(err.Error(), "无法解析") {
		t.Fatalf("应报出具体原因而不是「无法解析」：%q", err.Error())
	}
}

// TestIsLinkLocalNil nil 不算链路本地。
//
// 注意这与 IsPrivateOrReserved(nil)==true 是相反的取值，且两者都对：那个用在
// fail-closed 的策略拦截上（拿不准就拒绝），这个用在无条件生效的窄拦截上
// （拿不准就放过，否则会拦坏合法的反代）。两条断言并列摆着，免得有人来"统一"它们。
func TestIsLinkLocalNil(t *testing.T) {
	if IsLinkLocal(nil) {
		t.Fatal("IsLinkLocal(nil) 应为 false")
	}
	if !IsPrivateOrReserved(nil) {
		t.Fatal("IsPrivateOrReserved(nil) 应为 true（两者取值刻意相反）")
	}
}

// TestIsLinkLocalMulticastNotBlocked 链路本地**多播**（224.0.0.0/24、ff02::/16）不在此列。
//
// 拦的是"连到元数据端点"，而多播地址不是 TCP 连接的目标。多播归 IsPrivateOrReserved 管。
func TestIsLinkLocalMulticastNotBlocked(t *testing.T) {
	for _, s := range []string{"224.0.0.1", "ff02::1"} {
		ip := net.ParseIP(s)
		if ip == nil {
			t.Fatalf("%s 解析失败", s)
		}
		if IsLinkLocal(ip) {
			t.Errorf("%s 是链路本地多播，不该被这道窄拦截认领", s)
		}
		if !IsPrivateOrReserved(ip) {
			t.Errorf("%s 应属于内网防护的范围", s)
		}
	}
}
