package server

import (
	"net"
	"strings"
	"testing"

	"mantou/internal/config"
)

// 端口转发的目标不得是**本机的面板端口**（审计 NEW-1）。
//
// 这一条拦的是「把面板套在一次本机跳转之后」：一条 `8443 → 127.0.0.1:面板端口` 的规则
// 让面板收到的每个连接对端都变成本机地址，于是入站防护的来源判定（仅局域网 / 拒绝名单 /
// 自动封禁）、登录限流的分桶、审计日志里的来源**同时**失效——三件事共用「连接对端 IP」
// 这一个依据（SetTrustedProxies(nil) + ipx.ClientIP，刻意不看任何代理头）。
//
// 这组用例盯三处最容易在日后退化的地方：
//
//  1. **不只是回环**。目标写本机的局域网地址是同一形状的弱化版（回环豁免不生效，
//     但「仅局域网」照样被绕过、所有来源仍塌成一个 IP），所以判的是 ipx.IsLocalHost。
//  2. **端口范围要逐个算**。`20000-21000 → 127.0.0.1:8995` 这种"范围里恰好有一个落在
//     面板端口上"的写法必须拦住——那是最不容易被用户自己发现的一种。算法必须跟
//     forward.expandRule 同一口径，两边一旦分叉，这里先红。
//  3. **不能拦过头**。远端主机的同一端口号、本机的其他端口、普通主机名都得放行；
//     把这条校验写成"凡是回环一律拒绝"会打死一大片合法用法（本机跑的服务才是端口转发
//     最常见的目标）。
func TestValidateForwardRejectsPanelTarget(t *testing.T) {
	const panelPort = 9000
	cfg := &config.Config{}
	cfg.Panel.Port = panelPort

	// base 能通过其余所有校验；各用例只改与「目标是否指向本机面板端口」有关的字段。
	base := config.ForwardRule{Protocol: "tcp", ListenPort: 8443, TargetHost: "127.0.0.1", TargetPort: panelPort}

	cases := []struct {
		name    string
		mod     func(r *config.ForwardRule)
		wantErr bool
	}{
		// —— 必须拒绝 ——
		{"回环 IPv4 + 面板端口", func(r *config.ForwardRule) {}, true},
		{"回环网段的其他地址", func(r *config.ForwardRule) { r.TargetHost = "127.0.0.53" }, true},
		{"localhost", func(r *config.ForwardRule) { r.TargetHost = "localhost" }, true},
		{"localhost 大写", func(r *config.ForwardRule) { r.TargetHost = "LocalHost" }, true},
		{"localhost 带根点", func(r *config.ForwardRule) { r.TargetHost = "localhost." }, true},
		{".localhost 后缀（RFC 6761 必然回环）", func(r *config.ForwardRule) { r.TargetHost = "panel.localhost" }, true},
		{"回环 IPv6", func(r *config.ForwardRule) { r.TargetHost = "::1" }, true},
		{"回环 IPv6 方括号写法", func(r *config.ForwardRule) { r.TargetHost = "[::1]" }, true},
		{"未指定地址 IPv4", func(r *config.ForwardRule) { r.TargetHost = "0.0.0.0" }, true},
		{"未指定地址 IPv6", func(r *config.ForwardRule) { r.TargetHost = "::" }, true},
		{"目标地址前后带空格", func(r *config.ForwardRule) { r.TargetHost = "  127.0.0.1  " }, true},
		{
			// 递增映射：20000→8995, 20001→8996, …, 20005→9000（撞上），…
			"端口范围里有一个落在面板端口上",
			func(r *config.ForwardRule) {
				r.ListenPort = 20000
				r.ListenPortEnd = 20010
				r.TargetPort = panelPort - 5
			},
			true,
		},
		{
			"多对一范围的共用目标就是面板端口",
			func(r *config.ForwardRule) {
				r.ListenPort = 20000
				r.ListenPortEnd = 20010
				r.SameTargetPort = true
			},
			true,
		},

		// —— 必须放行 ——
		{"远端主机的同一端口号", func(r *config.ForwardRule) { r.TargetHost = "203.0.113.9" }, false},
		{"本机的其他端口", func(r *config.ForwardRule) { r.TargetPort = panelPort + 1 }, false},
		{
			// 不查 DNS 是刻意的（见 ipx.IsLocalHost 的文件头）：保存那一刻的解析结果
			// 不构成运行期保证，真要靠它得在拨号时再查一遍。
			"普通主机名（本校验不查 DNS）",
			func(r *config.ForwardRule) { r.TargetHost = "example.com" },
			false,
		},
		{
			// 边界：范围恰好从面板端口的下一个开始（9001..9011），一个都不该撞上。
			"端口范围整段避开面板端口",
			func(r *config.ForwardRule) {
				r.ListenPort = 20000
				r.ListenPortEnd = 20010
				r.TargetPort = panelPort + 1
			},
			false,
		},
		{
			// 边界：多对一时不加偏移，所以起点差一个就永远撞不上。
			"多对一范围的共用目标差一个",
			func(r *config.ForwardRule) {
				r.ListenPort = 20000
				r.ListenPortEnd = 20010
				r.TargetPort = panelPort - 1
				r.SameTargetPort = true
			},
			false,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := base
			c.mod(&r)
			err := validateForward(cfg, r)
			if (err != nil) != c.wantErr {
				t.Fatalf("validateForward 返回 err=%v，wantErr=%v", err, c.wantErr)
			}
			if c.wantErr && !strings.Contains(err.Error(), "面板") {
				// 拒是拒了，但如果是被别的校验拦下的，这条用例就没测到东西。
				t.Fatalf("拒绝理由里没提到面板端口，可能被其他校验提前拦下：%v", err)
			}
		})
	}
}

// TestValidateForwardRejectsOwnInterfaceIP 目标写本机某个网卡的**局域网**地址同样要拒。
//
// 单列一条是因为它走的是 ipx.IsLocalIP 里查网卡地址表的那一支（前一组用例全都在
// 回环/未指定这条捷径上就返回了）。这也是审计 NEW-1 里"弱化版"那种写法：
// 回环豁免不生效，但「仅局域网」照样被绕过、所有来源仍塌成同一个 IP。
func TestValidateForwardRejectsOwnInterfaceIP(t *testing.T) {
	const panelPort = 9100
	cfg := &config.Config{}
	cfg.Panel.Port = panelPort

	addrs, err := net.InterfaceAddrs()
	if err != nil {
		t.Skipf("枚举本机网卡失败，跳过：%v", err)
	}
	var own net.IP
	for _, a := range addrs {
		ipnet, ok := a.(*net.IPNet)
		if !ok || ipnet.IP == nil || ipnet.IP.IsLoopback() || ipnet.IP.IsUnspecified() {
			continue
		}
		own = ipnet.IP
		break
	}
	if own == nil {
		t.Skip("本机除回环外没有其他地址，跳过")
	}

	host := own.String()
	if own.To4() == nil {
		host = "[" + host + "]" // IPv6 按用户会从地址栏复制的形状写
	}
	r := config.ForwardRule{Protocol: "tcp", ListenPort: 8443, TargetHost: host, TargetPort: panelPort}
	if err := validateForward(cfg, r); err == nil {
		t.Fatalf("目标 %s:%d 指向本机网卡上的地址与面板端口，应当被拒", host, panelPort)
	}
}

// TestValidateForwardPanelPortUnsetPassesThrough 面板端口缺失时这条校验不生效。
//
// 钉住它是为了说明 cfg == nil / Panel.Port == 0 不是漏洞而是明确的边界：接口层永远传
// s.deps.Config.Snapshot()（见 registerCRUD 里 r.validate 的三处调用），那份配置的
// Panel.Port 由 config 的默认值兜底，不可能是 0；而"没有面板端口"这个前提下本就无从判断
// 撞不撞，此时拒绝反而会把合法规则挡在门外。
func TestValidateForwardPanelPortUnsetPassesThrough(t *testing.T) {
	r := config.ForwardRule{Protocol: "tcp", ListenPort: 8443, TargetHost: "127.0.0.1", TargetPort: 9000}
	if err := validateForward(nil, r); err != nil {
		t.Fatalf("cfg 为 nil 时不应因面板端口被拒：%v", err)
	}
	empty := &config.Config{} // Panel.Port == 0
	if err := validateForward(empty, r); err != nil {
		t.Fatalf("面板端口为 0 时不应被拒：%v", err)
	}
}
