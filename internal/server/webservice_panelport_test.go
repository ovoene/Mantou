package server

import (
	"strings"
	"testing"

	"mantou/internal/config"
)

// 反代后端指向本机面板管理端口，保存期就要拒绝。
//
// 这是「把面板套在一次本机跳转之后」的最后一个入口。端口转发那边早就两层都拦住了
// （forwardTargetsPanel + forward 模块的运行期跳过），Web 服务的**监听端口**也拦住了，
// 唯独反代**后端**没有：一条 `后端 = http://127.0.0.1:面板端口` 的规则一存，
// 面板收到的每个请求都成了本机来源——回环无条件放行、拒绝名单与自动封禁认不出人、
// 「仅局域网」形同虚设、审计日志里所有来源塌成 127.0.0.1。
//
// 运行期那一层在 internal/modules/webservice（panelport_test.go），拦的是绕过保存期
// 的配置：导入的备份、手改的 config.json、旧版本迁移上来的数据。
//
// 本文件同时钉住几条刻意的边界，它们都是"少拦"的方向，写下来免得被当成漏洞补掉：
// 跳转目标不拦（302 让浏览器自己再连，客户端 IP 原样保留）、停用子项不拦
// （否则一份手改坏的配置连关掉都做不到）、端口不同不拦（反代本机服务是正常用法）。

// panelPortWS 造一个后端指向 upstream 的启用子项，父项端口固定用一个不与面板冲突的值。
func panelPortWS(upstream, childType string) config.WebService {
	return config.WebService{
		ID: "svc", Name: "站点", Enabled: true, Port: 18443, IPFamily: "ipv4",
		Children: []config.WebChild{{
			ID: "ch", Enabled: true, Type: childType, TLSMinVersion: "1.2",
			Upstreams: []config.WebUpstream{{URL: upstream}},
		}},
	}
}

func TestValidateWebServiceRejectsUpstreamOnPanelPort(t *testing.T) {
	const panelPort = 9443
	cases := []struct {
		name     string
		upstream string
	}{
		{"回环显式端口", "http://127.0.0.1:9443"},
		{"localhost", "http://localhost:9443"},
		{"IPv6 回环", "http://[::1]:9443"},
		{"未指定地址", "http://0.0.0.0:9443"},
		{"https 也算", "https://127.0.0.1:9443"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &config.Config{}
			cfg.Panel.Port = panelPort
			err := validateWebService(cfg, panelPortWS(tc.upstream, "proxy"), t.TempDir())
			if err == nil {
				t.Fatalf("后端 %s 指向面板端口，应当被拒绝", tc.upstream)
			}
			// 错误要能自解释：说清是哪条后端、撞的是哪个端口、以及怎么绕开这条限制。
			for _, want := range []string{"面板管理端口", "设置 → 面板"} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("错误里应包含 %q，实际 %q", want, err.Error())
				}
			}
		})
	}
}

// TestValidateWebServiceRejectsUpstreamOnDefaultPanelPort 面板跑在 80/443 时，
// 不带端口的后端地址也要拦住。
//
// 这一条是最容易被漏掉的形态：用户写后端时几乎不会给 80/443 显式补上端口，
// 而只比对显式端口的实现对这种写法完全睁眼瞎。
func TestValidateWebServiceRejectsUpstreamOnDefaultPanelPort(t *testing.T) {
	cases := []struct {
		panelPort int
		upstream  string
	}{
		{80, "http://127.0.0.1"},
		{443, "https://127.0.0.1"},
	}
	for _, tc := range cases {
		cfg := &config.Config{}
		cfg.Panel.Port = tc.panelPort
		if err := validateWebService(cfg, panelPortWS(tc.upstream, "proxy"), t.TempDir()); err == nil {
			t.Errorf("面板在 %d 端口时，后端 %s 应当被拒绝（scheme 默认端口）", tc.panelPort, tc.upstream)
		}
	}
}

func TestValidateWebServiceAllowsNormalUpstreams(t *testing.T) {
	const panelPort = 9443
	cases := []struct {
		name     string
		upstream string
	}{
		// 反代本机的另一个服务：这个功能最常见的用法。
		{"本机其它端口", "http://127.0.0.1:3000"},
		// 内网服务：这个功能存在的理由。
		{"局域网地址", "http://192.168.1.10:9443"},
		{"公网地址", "http://203.0.113.9:9443"},
		// 普通主机名不查 DNS（理由见 internal/ipx/local.go 文件头）：
		// 即便它其实解析到本机，保存期也放过——运行期那一层才是不能绕的。
		{"主机名", "http://backend.internal:9443"},
		// 面板端口未知时不做判定。
		{"面板端口未配置时不拦", "http://127.0.0.1:9443"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &config.Config{}
			if tc.name != "面板端口未配置时不拦" {
				cfg.Panel.Port = panelPort
			}
			if err := validateWebService(cfg, panelPortWS(tc.upstream, "proxy"), t.TempDir()); err != nil {
				t.Fatalf("后端 %s 应当被接受，实际被拒：%v", tc.upstream, err)
			}
		})
	}
}

// TestValidateWebServiceAllowsRedirectToPanelPort 跳转目标指向面板端口不拦。
//
// 302 是让浏览器自己再连一次，客户端 IP 原样保留，来源塌缩只发生在进程内那一跳上。
// "把 80 端口的访问跳到面板"是一条完全正当的规则，拦掉它是误伤。
func TestValidateWebServiceAllowsRedirectToPanelPort(t *testing.T) {
	cfg := &config.Config{}
	cfg.Panel.Port = 9443
	ws := config.WebService{
		ID: "svc", Name: "跳面板", Enabled: true, Port: 18443, IPFamily: "ipv4",
		Children: []config.WebChild{{
			ID: "ch", Enabled: true, Type: "redirect", TLSMinVersion: "1.2",
			Redirect: config.WebRedirect{Target: "https://127.0.0.1:9443", Code: 302},
		}},
	}
	if err := validateWebService(cfg, ws, t.TempDir()); err != nil {
		t.Fatalf("跳转到面板端口应当被接受，实际被拒：%v", err)
	}
}

// TestValidateWebServiceAllowsDisabledChildOnPanelPort 停用的子项不拦。
//
// 与后端地址协议白名单同一个理由：保存与启停走的是同一个校验，一份已经存在的、
// 后端指向面板端口的配置若在这里被无条件拒绝，用户连把它关掉都做不到。
// 它停着就不会被装配，运行期那一层还兜着。
func TestValidateWebServiceAllowsDisabledChildOnPanelPort(t *testing.T) {
	cfg := &config.Config{}
	cfg.Panel.Port = 9443
	ws := panelPortWS("http://127.0.0.1:9443", "proxy")
	ws.Children[0].Enabled = false
	if err := validateWebService(cfg, ws, t.TempDir()); err != nil {
		t.Fatalf("停用子项应当被接受，实际被拒：%v", err)
	}
}

// TestValidateWebServiceRejectsUntypedUpstreamOnPanelPort Type 为空串的子项也要拦。
//
// handler.go 的分发里只有 static / redirect 两个 case，其余全走反代（default），
// 所以空串、以及任何没人认识的 Type，运行期都是一个真会去拨 Upstreams 的代理。
// 校验若写成 Type == "proxy" 就会漏掉这一整类——而旧配置、手写配置、导入的备份
// 里空串恰恰是最常见的形态。
func TestValidateWebServiceRejectsUntypedUpstreamOnPanelPort(t *testing.T) {
	cfg := &config.Config{}
	cfg.Panel.Port = 9443
	for _, typ := range []string{"", "unknown-future-type"} {
		if err := validateWebService(cfg, panelPortWS("http://127.0.0.1:9443", typ), t.TempDir()); err == nil {
			t.Errorf("Type=%q 运行期走反代，应当被拒绝", typ)
		}
	}
}
