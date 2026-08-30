package server

import (
	"net/http"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"mantou/internal/config"
)

// 本文件盯的是域名归属：同一个端口上，一个域名只能属于一件东西。
//
// 这条规则的分寸很窄，两边都会出事：
// 管得太松 → 端口 443 上两处都说 example.com 归我，请求落到哪一边取决于配置顺序；
// 管得太严（比如全局唯一）→ "端口 80 跳 HTTPS + 端口 443 真站点"这种最常见的配置直接保存不了。
// 所以下面既有该拒的用例，也有必须放过的用例，后者一样是回归保护。

// wsChild 造一个启用的重定向子项。TLSMinVersion 显式给：这些用例直接调
// validateWebService，不经过 normalizeWebService 那一步的补默认值。
func wsChild(id string, tls bool, domains ...string) config.WebChild {
	return config.WebChild{
		ID: id, Enabled: true, Type: "redirect", Domains: domains,
		TLS: tls, TLSMinVersion: "1.2",
		Redirect: config.WebRedirect{Target: "https://example.com", Code: 301},
	}
}

// wsParent 造一个启用的父项。
func wsParent(id string, port int, children ...config.WebChild) config.WebService {
	return config.WebService{ID: id, Name: "站点" + id, Enabled: true, Port: port,
		IPFamily: "v4", Children: children}
}

// domainCfg 一份只有面板的配置：面板端口 25666、面板域名 panel.example.com。
func domainCfg() *config.Config {
	return &config.Config{Panel: config.Panel{Port: 25666,
		HTTPS: config.PanelHTTPS{Enabled: true, Domain: "panel.example.com"}}}
}

func TestValidateWebServiceDomainOwnership(t *testing.T) {
	cases := []struct {
		name string
		cfg  func(*config.Config)
		ws   config.WebService
		want string // 期望错误里出现的字样；空串=必须通过
	}{{
		name: "同一父项内两个子项撞同一个域名（大小写不算区别）",
		ws:   wsParent("ws1", 8443, wsChild("a", true, "site.example.com"), wsChild("b", true, "SITE.Example.com")),
		want: "重复",
	}, {
		name: "停用的子项不参与查重：留着一份备用配置是正常用法",
		ws: config.WebService{ID: "ws1", Enabled: true, Port: 8443, IPFamily: "v4", Children: []config.WebChild{
			wsChild("a", true, "site.example.com"),
			func() config.WebChild { c := wsChild("b", true, "site.example.com"); c.Enabled = false; return c }(),
		}},
	}, {
		name: "跨父项、同端口撞域名",
		// 另一个父项刻意用 v6：同（地址族, 端口）只允许一个启用父项，那条更早的规则
		// 会先拦下来，用例就测不到域名这一条了。域名查重本身不分地址族——
		// 同一个域名同时解析到 A 和 AAAA 是常态，两边都声明它一样是分不清。
		cfg: func(c *config.Config) {
			old := wsParent("old", 8443, wsChild("a", true, "site.example.com"))
			old.IPFamily = "v6"
			c.WebServices = []config.WebService{old}
		},
		ws:   wsParent("new", 8443, wsChild("b", true, "site.example.com")),
		want: "已被 Web 服务",
	}, {
		name: "同域名换端口是最常见的配置（80 跳 HTTPS + 443 站点），必须放过",
		cfg: func(c *config.Config) {
			c.WebServices = []config.WebService{wsParent("old", 443, wsChild("a", true, "site.example.com"))}
		},
		ws: wsParent("new", 80, wsChild("b", false, "site.example.com")),
	}, {
		name: "停用的父项不产生监听，它的域名不算被占",
		cfg: func(c *config.Config) {
			old := wsParent("old", 8443, wsChild("a", true, "site.example.com"))
			old.Enabled = false
			c.WebServices = []config.WebService{old}
		},
		ws: wsParent("new", 8443, wsChild("b", true, "site.example.com")),
	}, {
		name: "编辑自己时，自己的旧域名不算冲突（否则任何一次改名都保存不了）",
		cfg: func(c *config.Config) {
			c.WebServices = []config.WebService{wsParent("ws1", 8443, wsChild("a", true, "site.example.com"))}
		},
		ws: wsParent("ws1", 8443, wsChild("a", true, "site.example.com")),
	}, {
		name: "面板域名在任何端口上都被保留",
		ws:   wsParent("ws1", 8443, wsChild("a", true, "panel.example.com")),
		want: "面板",
	}, {
		name: "撞消息路由在同一端口上的域名",
		cfg: func(c *config.Config) {
			c.Webhook = config.WebhookServer{Enabled: true, Port: 8443, Domain: "hook.example.com",
				HTTPS: config.WebhookHTTPS{Enabled: true}}
		},
		ws:   wsParent("ws1", 8443, wsChild("a", true, "hook.example.com")),
		want: "已被消息路由",
	}, {
		name: "消息路由在别的端口上用同一个域名，互不相干",
		cfg: func(c *config.Config) {
			c.Webhook = config.WebhookServer{Enabled: true, Port: 8444, Domain: "hook.example.com",
				HTTPS: config.WebhookHTTPS{Enabled: true}}
		},
		ws: wsParent("ws1", 8443, wsChild("a", true, "hook.example.com")),
	}}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := domainCfg()
			if tc.cfg != nil {
				tc.cfg(cfg)
			}
			err := validateWebService(cfg, tc.ws, "")
			assertErrContains(t, err, tc.want)
		})
	}
}

// 共用端口的两个前提（有域名、HTTPS 口径一致）在 Web 服务这一侧也要拦。
// 先配消息路由、后配 Web 服务的用户如果这里不拦，看到的就只有运行期日志里
// 一行"地址已被占用"——列表上那个服务看起来是启用的，实际一个请求也进不来。
func TestValidateWebServiceWebhookShare(t *testing.T) {
	hook := func(port int, domain string, https bool) func(*config.Config) {
		return func(c *config.Config) {
			c.Webhook = config.WebhookServer{Enabled: true, Port: port, Domain: domain,
				HTTPS: config.WebhookHTTPS{Enabled: https}}
		}
	}
	noChildParent := config.WebService{ID: "ws1", Name: "空壳", Enabled: true, Port: 443, IPFamily: "v4"}

	cases := []struct {
		name string
		cfg  func(*config.Config)
		ws   config.WebService
		want string
	}{{
		name: "消息路由占着这个端口但没填域名：没有分流依据",
		cfg:  hook(443, "", true),
		ws:   wsParent("ws1", 443, wsChild("a", true, "site.example.com")),
		want: "填写访问域名",
	}, {
		name: "域名有了但协议口径不一致：监听的 TLS 只有一份，改不了",
		cfg:  hook(443, "hook.example.com", false),
		ws:   wsParent("ws1", 443, wsChild("a", true, "site.example.com")),
		want: "HTTPS 开关",
	}, {
		name: "两个前提都满足，共用成立",
		cfg:  hook(443, "hook.example.com", true),
		ws:   wsParent("ws1", 443, wsChild("a", true, "site.example.com")),
	}, {
		name: "没有任何启用子项的父项不产生监听，端口仍归消息路由自己绑",
		cfg:  hook(443, "", true),
		ws:   noChildParent,
	}, {
		name: "消息路由没启用，端口没人抢",
		cfg:  func(c *config.Config) { c.Webhook = config.WebhookServer{Port: 443} },
		ws:   wsParent("ws1", 443, wsChild("a", true, "site.example.com")),
	}}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := domainCfg()
			tc.cfg(cfg)
			assertErrContains(t, validateWebService(cfg, tc.ws, ""), tc.want)
		})
	}
}

// 列表里的启用开关走的是另一条轻量路径（不重发整份配置），共用端口的前提在那里
// 同样要拦，否则"点一下开关"就能绕过保存时的校验，把服务开成一个绑不上端口的状态。
func TestToggleWebServiceChecksWebhookShare(t *testing.T) {
	gin.SetMode(gin.TestMode)
	manager := config.NewManager(t.TempDir() + "/config.json")
	if err := manager.Load(); err != nil {
		t.Fatal(err)
	}
	if err := manager.Update(func(c *config.Config) {
		c.Webhook = config.WebhookServer{Enabled: true, Port: 8443, HTTPS: config.WebhookHTTPS{Enabled: true}}
		ws := wsParent("ws1", 8443, wsChild("a", true, "site.example.com"))
		ws.Enabled = false
		c.WebServices = []config.WebService{ws}
	}); err != nil {
		t.Fatal(err)
	}

	s := &Server{deps: Deps{Config: manager}}
	router := gin.New()
	router.POST("/webservices/:id/toggle", s.handleToggleWebService)

	w := performJSONRequest(router, http.MethodPost, "/webservices/ws1/toggle", `{"enabled":true}`)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("消息路由没填域名时不该允许启用，实际 %d：%s", w.Code, w.Body.String())
	}
	if manager.Get().WebServices[0].Enabled {
		t.Fatal("被拒的一次启用不该落盘")
	}

	// 补上域名后共用成立，同一个开关就该能开。
	if err := manager.Update(func(c *config.Config) { c.Webhook.Domain = "hook.example.com" }); err != nil {
		t.Fatal(err)
	}
	if w := performJSONRequest(router, http.MethodPost, "/webservices/ws1/toggle", `{"enabled":true}`); w.Code != http.StatusOK {
		t.Fatalf("共用前提满足后应允许启用，实际 %d：%s", w.Code, w.Body.String())
	}
	if !manager.Get().WebServices[0].Enabled {
		t.Fatal("启用应已落盘")
	}
}

// 没填访问域名的子项接管这个端口上所有对不上域名的请求，这样的启用子项只能有一个。
// 有两个时运行期只有最后装载的那个能被访问到，另一个像不存在——而两边配置页上都是绿的。
func TestValidateWebServiceSingleDefaultSite(t *testing.T) {
	blank := func(id string) config.WebChild {
		ch := wsChild(id, true)
		ch.Domains = []string{"  "} // 看起来填了、其实是空白：运行期同样当默认站点
		return ch
	}
	cases := []struct {
		name string
		ws   config.WebService
		want string
	}{{
		name: "两个都没填域名",
		ws:   wsParent("ws1", 8443, wsChild("a", true), wsChild("b", true)),
		want: "没填访问域名",
	}, {
		name: "一个没填、一个填的是空白",
		ws:   wsParent("ws1", 8443, wsChild("a", true), blank("b")),
		want: "没填访问域名",
	}, {
		name: "只有一个没填域名：这是正常的默认站点",
		ws:   wsParent("ws1", 8443, wsChild("a", true), wsChild("b", true, "site.example.com")),
	}, {
		name: "第二个没填域名的子项是停用的，不产生默认站点",
		ws: wsParent("ws1", 8443, wsChild("a", true), func() config.WebChild {
			ch := wsChild("b", true)
			ch.Enabled = false
			return ch
		}()),
	}, {
		name: "父项停用：不建监听，也就没有默认站点之争",
		ws: func() config.WebService {
			p := wsParent("ws1", 8443, wsChild("a", true), wsChild("b", true))
			p.Enabled = false
			return p
		}(),
	}}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assertErrContains(t, validateWebService(domainCfg(), tc.ws, ""), tc.want)
		})
	}
}

// 写法校验的意义在于"存得下但永远命中不了"这一类配置：路由是精确查表，
// 下面这些写法一条都匹配不上，而配置本身看不出毛病，用户只会看到"配好了却收不到"。
func TestCheckRouteDomainSyntax(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		// 通配符是最容易混的一件事：它只在证书那一侧有意义，路由这边没有这回事。
		{"*.example.com", "通配符"},
		{"*", "通配符"},
		{"http://example.com", "协议前缀"},
		{"https://example.com/", "协议前缀"},
		{"example.com/hook", "路径"},
		{"example.com?a=1", "路径"},
		{"example.com#x", "路径"},
		{`example.com\hook`, "路径"},
		{"a.example.com b.example.com", "空格"},
		{"example.com:8443", "端口"},
		// 留空是有意义的取值（默认站点 / 不按域名分流），调用方各有判断，这里不管。
		{"", ""},
		{"example.com", ""},
		{"  example.com  ", ""},
		{"a.b.c.example.com", ""},
		{"192.168.1.10", ""},
		// IPv6 字面量本身含冒号，不能被"不要带端口"那条误伤。
		{"[fe80::1]", ""},
		{"fe80::1", ""},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			assertErrContains(t, checkRouteDomainSyntax(tc.in), tc.want)
		})
	}
}

// 三条保存路径都要拦：Web 服务子项、消息路由的访问域名（见 api_webhook_server_test.go）、
// 面板 HTTPS 域名（见 api_overview_test.go）。这里管第一条。
//
// 子项停用与否都要查：写错的域名不该因为子项当时是停用的就存进配置——
// 它一旦被启用就是个死键，而那时用户已经不记得自己填过什么了。
func TestValidateWebServiceRejectsUnroutableDomain(t *testing.T) {
	cases := []struct {
		name string
		ws   config.WebService
	}{{
		name: "启用子项填了通配符",
		ws:   wsParent("ws1", 8443, wsChild("a", true, "*.example.com")),
	}, {
		name: "停用子项填了通配符",
		ws: config.WebService{ID: "ws1", Enabled: true, Port: 8443, IPFamily: "v4", Children: []config.WebChild{
			func() config.WebChild { c := wsChild("a", true, "*.example.com"); c.Enabled = false; return c }(),
		}},
	}, {
		name: "多个域名挤在一条里",
		ws:   wsParent("ws1", 8443, wsChild("a", true, "a.example.com b.example.com")),
	}, {
		name: "带了协议前缀",
		ws:   wsParent("ws1", 8443, wsChild("a", true, "https://site.example.com")),
	}}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assertErrContains(t, validateWebService(domainCfg(), tc.ws, ""), "域名")
		})
	}
}

// assertErrContains want 为空串时要求无错误，否则要求错误里出现 want。
func assertErrContains(t *testing.T, err error, want string) {
	t.Helper()
	switch {
	case want == "" && err != nil:
		t.Fatalf("这份配置应通过校验，实际被拒：%v", err)
	case want != "" && err == nil:
		t.Fatalf("应因%q被拒，实际通过了", want)
	case want != "" && !strings.Contains(err.Error(), want):
		t.Fatalf("错误里应说明%q，实际 %q", want, err.Error())
	}
}
