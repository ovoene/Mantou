package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"mantou/internal/config"
	"mantou/internal/logx"
	"mantou/internal/modules/webhook"
	"mantou/internal/runstats"
)

// 本文件盯的是消息路由的两个接口面：
//
//  1. PUT /webhook/server —— 监听端口与 HTTPS。启用 HTTPS 后本模块**没有明文回落**，
//     证书或域名不对就是所有第三方来源同时静默失联，所以必须在保存这一步拦住。
//  2. 接收器 CRUD 的令牌脱敏往返 —— 列表里回的是占位符，用户没改令牌时原样提交，
//     这时必须还原成原令牌，而不是把 "******" 当成新令牌存下去。

// newWebhookAPITest 用**线上那份** registerWebhookRoutes 搭路由，
// 从而连"校验有没有真的接到 CRUD 上"一并验证。
func newWebhookAPITest(t *testing.T) (*config.Manager, *gin.Engine) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	manager := config.NewManager(filepath.Join(t.TempDir(), "config.json"))
	if err := manager.Load(); err != nil {
		t.Fatal(err)
	}
	// 模板与通知目标是接收器校验的前提，先塞进去。
	// 模块也标成已创建：没有模块就没有监听、没有域名，启用接收器会被 validateReceiver 拦下
	//（那一条单独在 api_webhook_validate_test.go 里盯着）。
	if err := manager.Update(func(cfg *config.Config) {
		cfg.Webhook.Created = true
		cfg.MessageTemplates = []config.MessageTemplate{{ID: "t1", Name: "汇总模板", Format: "text", Body: "收到"}}
		cfg.NotifyTargets = []config.NotifyTarget{{ID: "g1", Name: "运维群", Enabled: true, Type: "dingtalk"}}
	}); err != nil {
		t.Fatal(err)
	}
	s := &Server{deps: Deps{Config: manager}}
	router := gin.New()
	s.registerWebhookRoutes(router.Group(""))
	return manager, router
}

// serverBody 组一份模块设置请求。域名走旧的 https.domain 字段，
// 顺带盯住"旧前端 / 外部脚本按老结构提交也要能存进新的模块级域名"。
func serverBody(enabled bool, port int, https bool, certID, domain string) string {
	return fmt.Sprintf(`{"enabled":%t,"port":%d,"https":{"enabled":%t,"certId":%q,"domain":%q}}`,
		enabled, port, https, certID, domain)
}

// serverBodyFull 组一份带模块级域名与备注的请求（当前前端的提交形态）。
func serverBodyFull(enabled bool, port int, domain, note string, https bool, certID string) string {
	return fmt.Sprintf(`{"enabled":%t,"port":%d,"domain":%q,"note":%q,"https":{"enabled":%t,"certId":%q}}`,
		enabled, port, domain, note, https, certID)
}

// ---------- 监听端口 ----------

func TestUpdateWebhookServerPortRange(t *testing.T) {
	_, router := newWebhookAPITest(t)
	for _, port := range []int{0, -1, 65536, 99999} {
		w := performJSONRequest(router, http.MethodPut, "/webhook/server", serverBody(true, port, false, "", ""))
		if w.Code != http.StatusBadRequest {
			t.Errorf("端口 %d 应被拒，实际 %d：%s", port, w.Code, w.Body.String())
		}
	}
	// 边界两端都要能存下。
	for _, port := range []int{1, 65535} {
		w := performJSONRequest(router, http.MethodPut, "/webhook/server", serverBody(true, port, false, "", ""))
		if w.Code != http.StatusOK {
			t.Errorf("端口 %d 应放行，实际 %d：%s", port, w.Code, w.Body.String())
		}
	}
}

// ---------- 原文留存额度 ----------

// 这个字段与其它数值字段不是一个口径：0 在它上面是「不留存」这个有效选择，
// 于是"没带这个键"与"带了个 0"必须分开处理；而夹取又不能指望 normalizeWebhook，
// 那个函数只在配置从磁盘装载时跑。三件事都在这条保存路径上，一起盯。
func TestUpdateWebhookServerSourceRetain(t *testing.T) {
	manager, router := newWebhookAPITest(t)
	body := func(mb string) string {
		// mb 为空表示请求里根本没有这个键（旧前端与外部脚本的形态）。
		extra := ""
		if mb != "" {
			extra = `,"sourceRetainMb":` + mb
		}
		return `{"enabled":false,"port":25777,"domain":"","note":""` + extra +
			`,"https":{"enabled":false,"certId":""}}`
	}
	put := func(t *testing.T, mb string) {
		t.Helper()
		if w := performJSONRequest(router, http.MethodPut, "/webhook/server", body(mb)); w.Code != http.StatusOK {
			t.Fatalf("保存应成功（sourceRetainMb=%q），实际 %d：%s", mb, w.Code, w.Body.String())
		}
	}
	get := func() int { return manager.Get().Webhook.SourceRetainMB }

	if got := get(); got != config.DefaultSourceRetainMB {
		t.Fatalf("前置条件：装载后额度应为默认值 %d，实际 %d", config.DefaultSourceRetainMB, got)
	}

	// 越界的数字要在这一步夹住。少了夹取，一个手写的 99 会原样存进配置，
	// setBudget 就照 99 MB 收内容——直到重启才被夹回 3。
	put(t, "99")
	if got := get(); got != config.MaxSourceRetainMB {
		t.Fatalf("99 应被夹到 %d，实际 %d", config.MaxSourceRetainMB, got)
	}
	put(t, "-5")
	if got := get(); got != 0 {
		t.Fatalf("负数应按 0（不留存）处理，实际 %d", got)
	}

	// 显式的 0 要真的存成 0：这是用户在界面上选的「不留存」。
	put(t, "2")
	put(t, "0")
	if got := get(); got != 0 {
		t.Fatalf("显式 0 应存成 0，实际 %d", got)
	}

	// 不带这个键的保存不能动它——那是一次"只想改端口"的提交，
	// 值类型下会把用户选的「不留存」悄悄换回 2，反过来也把 2 换成不留存。
	put(t, "")
	if got := get(); got != 0 {
		t.Fatalf("请求没带这个键时应保持原值 0，实际 %d", got)
	}
	put(t, "3")
	put(t, "")
	if got := get(); got != config.MaxSourceRetainMB {
		t.Fatalf("请求没带这个键时应保持原值 %d，实际 %d", config.MaxSourceRetainMB, got)
	}
}

// 与面板端口冲突时必须拦住：真的起在同一个端口上，面板会失联，
// 而用户此刻正在面板里操作，那是一条自己把自己锁在门外的路。
func TestUpdateWebhookServerRejectsPanelPort(t *testing.T) {
	manager, router := newWebhookAPITest(t)
	panelPort := manager.Get().Panel.Port
	if panelPort <= 0 {
		t.Fatalf("前置条件：面板端口应有默认值，实际 %d", panelPort)
	}

	w := performJSONRequest(router, http.MethodPut, "/webhook/server", serverBody(true, panelPort, false, "", ""))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("与面板端口冲突应被拒，实际 %d：%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "面板") {
		t.Fatalf("错误应说明冲突对象是面板：%s", w.Body.String())
	}
	if got := manager.Get().Webhook.Port; got == panelPort {
		t.Fatal("被拒的请求不该改动配置")
	}

	// 但模块本身关着的时候允许存：端口不会真的被占用，
	// 而用户可能就是想先把端口改回来再启用。
	if w := performJSONRequest(router, http.MethodPut, "/webhook/server",
		serverBody(false, panelPort, false, "", "")); w.Code != http.StatusOK {
		t.Fatalf("未启用时应允许保存，实际 %d：%s", w.Code, w.Body.String())
	}
}

// 与 Web 服务同端口不再是一律拒绝：80 / 443 是面板、Web 服务、消息路由都想要的公共端口，
// 一个端口只能被一个进程绑定，所以改成"有域名才让共用"——那条监听上挂着别人的站点，
// 域名是唯一能把请求分给消息路由的依据。
func TestUpdateWebhookServerSharesWebServicePortOnlyWithDomain(t *testing.T) {
	manager, router := newWebhookAPITest(t)
	if err := manager.Update(func(cfg *config.Config) {
		cfg.WebServices = []config.WebService{
			{ID: "ws1", Name: "官网", Enabled: true, Port: 8443, Children: []config.WebChild{
				{ID: "c1", Enabled: true, Domains: []string{"www.example.com"}},
			}},
			{ID: "ws2", Name: "停用的站", Enabled: false, Port: 8444, Children: []config.WebChild{
				{ID: "c2", Enabled: true, Domains: []string{"old.example.com"}},
			}},
		}
	}); err != nil {
		t.Fatal(err)
	}

	// 没填域名：共用没有分流依据，必须拦，并且要点出是哪个站占着，
	// 否则用户得自己去翻一遍 Web 服务列表。
	w := performJSONRequest(router, http.MethodPut, "/webhook/server", serverBody(true, 8443, false, "", ""))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("同端口且没有域名应被拒，实际 %d：%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "官网") || !strings.Contains(w.Body.String(), "域名") {
		t.Fatalf("错误应指出占用者并要求域名：%s", w.Body.String())
	}

	// 填了域名、协议口径也一致：允许共用，且配置要被判定成共用监听。
	if w := performJSONRequest(router, http.MethodPut, "/webhook/server",
		serverBodyFull(true, 8443, "hook.example.com", "对接第三方", false, "")); w.Code != http.StatusOK {
		t.Fatalf("有域名应允许共用，实际 %d：%s", w.Code, w.Body.String())
	}
	got := manager.Get()
	if got.Webhook.Domain != "hook.example.com" || got.Webhook.Note != "对接第三方" {
		t.Fatalf("域名与备注未存下：%+v", got.Webhook)
	}
	if !got.WebhookSharesWebServicePort() {
		t.Fatal("同端口且有域名时应判定为与 Web 服务共用监听")
	}

	// 域名撞上同一条监听上已有的站点：同一端口上一个域名只能指向一处，
	// 否则程序分不清这个请求是找站点还是找消息路由。
	w = performJSONRequest(router, http.MethodPut, "/webhook/server",
		serverBodyFull(true, 8443, "www.example.com", "", false, ""))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("域名与同端口的站点重复应被拒，实际 %d：%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "重复") {
		t.Fatalf("错误应说明域名重复：%s", w.Body.String())
	}

	// 协议口径不一致：那条监听的 TLS 已经定了，改不了，只能在保存这一步说清楚。
	w = performJSONRequest(router, http.MethodPut, "/webhook/server",
		serverBodyFull(true, 8443, "hook.example.com", "", true, "c1"))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("协议口径不一致应被拒，实际 %d：%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "HTTP") {
		t.Fatalf("错误应说明协议不一致：%s", w.Body.String())
	}

	// 停用的 Web 服务不占端口，不该拦。
	if w := performJSONRequest(router, http.MethodPut, "/webhook/server",
		serverBody(true, 8444, false, "", "")); w.Code != http.StatusOK {
		t.Fatalf("停用的 Web 服务不该造成冲突，实际 %d：%s", w.Code, w.Body.String())
	}
}

// 端口 80 / 443 必须填域名：这两个端口是浏览器与第三方系统的默认端口，
// 面板、Web 服务、消息路由都可能想要，没有域名就没法分辨请求该给谁。
func TestUpdateWebhookServerRequiresDomainOnPublicPorts(t *testing.T) {
	for _, port := range []int{80, 443} {
		manager, router := newWebhookAPITest(t)
		w := performJSONRequest(router, http.MethodPut, "/webhook/server", serverBody(true, port, false, "", ""))
		if w.Code != http.StatusBadRequest {
			t.Fatalf("端口 %d 没填域名应被拒，实际 %d：%s", port, w.Code, w.Body.String())
		}
		if !strings.Contains(w.Body.String(), "域名") {
			t.Fatalf("端口 %d 的错误应要求域名：%s", port, w.Body.String())
		}
		// 填上域名就能存（这一步没有 Web 服务占着，模块自己绑 80）。
		if w := performJSONRequest(router, http.MethodPut, "/webhook/server",
			serverBodyFull(true, port, "hook.example.com", "", false, "")); w.Code != http.StatusOK {
			t.Fatalf("端口 %d 填了域名应放行，实际 %d：%s", port, w.Code, w.Body.String())
		}
		if got := manager.Get().Webhook.Domain; got != "hook.example.com" {
			t.Fatalf("端口 %d 的域名未存下：%q", port, got)
		}

		// 模块关着时不校验：用户可能就是想先把端口改回来再启用。
		if w := performJSONRequest(router, http.MethodPut, "/webhook/server",
			serverBody(false, port, false, "", "")); w.Code != http.StatusOK {
			t.Fatalf("未启用时端口 %d 应允许保存，实际 %d：%s", port, w.Code, w.Body.String())
		}
	}
}

// 面板的访问域名任何端口上都不给别人用：把同一个名字同时指向面板和消息路由，
// 用户敲那个域名落到哪一边取决于端口，看起来就像面板坏了。
func TestUpdateWebhookServerRejectsPanelDomain(t *testing.T) {
	manager, router := newWebhookAPITest(t)
	if err := manager.Update(func(cfg *config.Config) {
		cfg.Panel.HTTPS.Domain = "panel.example.com"
	}); err != nil {
		t.Fatal(err)
	}
	w := performJSONRequest(router, http.MethodPut, "/webhook/server",
		serverBodyFull(true, 25667, "Panel.Example.com", "", false, ""))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("撞面板域名应被拒，实际 %d：%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "面板") {
		t.Fatalf("错误应说明冲突对象是面板：%s", w.Body.String())
	}
}

// 通配符域名要在保存这一步拦住。它存得下、看着也像配好了，但域名路由是精确查表，
// 这个键一个请求也匹配不上——用户看到的只是"明明配了域名却收不到消息"。
// 通配符只在证书那一侧有意义（SNI 拿实际域名去命中证书里的 *.example.com），
// 两件事很容易被混成一件，所以错误里要把这句说清楚。
func TestUpdateWebhookServerRejectsUnroutableDomain(t *testing.T) {
	for _, domain := range []string{"*.example.com", "http://hook.example.com", "hook.example.com:8443", "a.example.com b.example.com"} {
		t.Run(domain, func(t *testing.T) {
			manager, router := newWebhookAPITest(t)
			w := performJSONRequest(router, http.MethodPut, "/webhook/server",
				serverBodyFull(true, 25667, domain, "", false, ""))
			if w.Code != http.StatusBadRequest {
				t.Fatalf("域名 %s 应被拒，实际 %d：%s", domain, w.Code, w.Body.String())
			}
			if got := manager.Get().Webhook.Domain; got != "" {
				t.Fatalf("被拒的域名不该落盘，实际 %q", got)
			}
		})
	}
	// 通配符的错误必须点明"通配符只能填在证书里"，只回一句"格式无效"用户改不动。
	_, router := newWebhookAPITest(t)
	w := performJSONRequest(router, http.MethodPut, "/webhook/server",
		serverBodyFull(true, 25667, "*.example.com", "", false, ""))
	if !strings.Contains(w.Body.String(), "证书") {
		t.Fatalf("通配符的错误应说明它只能填在证书里：%s", w.Body.String())
	}
}

// ---------- HTTPS ----------

func TestUpdateWebhookServerHTTPSValidation(t *testing.T) {
	cases := []struct {
		name         string
		certs        []config.Certificate
		certID       string
		domain       string
		wantCode     int
		wantContains string
	}{
		{"没选证书", nil, "", "hook.example.com", http.StatusBadRequest, "必须选择证书"},
		{"没填域名", []config.Certificate{{ID: "c1", Enabled: true}}, "c1", "", http.StatusBadRequest, "访问域名"},
		{"域名只有空白", []config.Certificate{{ID: "c1", Enabled: true}}, "c1", "   ", http.StatusBadRequest, "访问域名"},
		{"证书不存在", nil, "c1", "hook.example.com", http.StatusBadRequest, "证书不存在"},
		// 证书被停用时不能启用 HTTPS：模块会起不来，而且没有明文回落。
		{"证书已停用", []config.Certificate{{ID: "c1", Enabled: false}}, "c1", "hook.example.com",
			http.StatusBadRequest, "已被禁用"},
		// 证书模块没起来时宁可 503 也不能存下一份"启用了 HTTPS 但没人能验证证书"的配置。
		{"证书模块未就绪", []config.Certificate{{ID: "c1", Enabled: true}}, "c1", "hook.example.com",
			http.StatusServiceUnavailable, "证书模块"},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			manager, router := newWebhookAPITest(t)
			if c.certs != nil {
				if err := manager.Update(func(cfg *config.Config) { cfg.Certs = c.certs }); err != nil {
					t.Fatal(err)
				}
			}
			w := performJSONRequest(router, http.MethodPut, "/webhook/server",
				serverBody(true, 25667, true, c.certID, c.domain))
			if w.Code != c.wantCode {
				t.Fatalf("状态码应为 %d，实际 %d：%s", c.wantCode, w.Code, w.Body.String())
			}
			if !strings.Contains(w.Body.String(), c.wantContains) {
				t.Fatalf("错误应包含 %q：%s", c.wantContains, w.Body.String())
			}
			if manager.Get().Webhook.HTTPS.Enabled {
				t.Fatal("被拒的请求不该把 HTTPS 存成启用")
			}
		})
	}
}

// 关闭 HTTPS 时不校验证书与域名：用户可能正是因为证书没了才要关掉它。
func TestUpdateWebhookServerHTTPSDisabledSkipsChecks(t *testing.T) {
	manager, router := newWebhookAPITest(t)
	w := performJSONRequest(router, http.MethodPut, "/webhook/server",
		serverBody(true, 25667, false, "已经不存在的证书", "hook.example.com"))
	if w.Code != http.StatusOK {
		t.Fatalf("关闭 HTTPS 应放行，实际 %d：%s", w.Code, w.Body.String())
	}
	got := manager.Get().Webhook
	if got.Enabled != true || got.Port != 25667 || got.HTTPS.Enabled {
		t.Fatalf("保存结果不符：%+v", got)
	}
	// 域名不再随 HTTPS 开关清空：端口 80 共用 Web 服务的监听时没有 HTTPS 也要靠它分流，
	// 清掉等于用户每次关一下 HTTPS 就得重填一遍。旧的 https.domain 则必须是空的。
	if got.Domain != "hook.example.com" {
		t.Fatalf("关闭 HTTPS 不该清掉域名，实际 %q", got.Domain)
	}
	if got.HTTPS.Domain != "" {
		t.Fatalf("域名只该存在模块级字段里，https.domain 应为空，实际 %q", got.HTTPS.Domain)
	}
}

// ---------- 模块的创建与删除 ----------

// 保存即创建：模块设置那一页在未创建时只有一个「新建」按钮，走的也是这条 PUT。
// 创建的同时要把路径为空的接收器补齐——用户建完模块回到接收器那一页，
// 地址栏里应该已经是可用的，而不是一个待填的空格。
func TestUpdateWebhookServerMarksCreatedAndFillsPaths(t *testing.T) {
	manager, router := newWebhookAPITest(t)
	if err := manager.Update(func(cfg *config.Config) {
		cfg.Webhook = config.WebhookServer{Listen: "0.0.0.0", Port: config.DefaultWebhookPort}
		// 手工塞一个路径为空的接收器：正常保存路径会补，这里绕开它以还原"模块建之前"的状态。
		cfg.WebhookReceivers = []config.WebhookReceiver{{ID: "r1", Name: "第三方系统"}}
	}); err != nil {
		t.Fatal(err)
	}
	// 前置条件：normalizeWebhook 自己也会补路径，这里只确认它确实没被标成已创建。
	if manager.Get().Webhook.Created {
		t.Fatal("前置条件：此刻模块应是未创建的")
	}

	w := performJSONRequest(router, http.MethodPut, "/webhook/server",
		serverBodyFull(true, 25667, "hook.example.com", "", false, ""))
	if w.Code != http.StatusOK {
		t.Fatalf("保存应成功，实际 %d：%s", w.Code, w.Body.String())
	}
	cfg := manager.Get()
	if !cfg.Webhook.Created {
		t.Fatal("保存即创建，Created 应为真")
	}
	if len(cfg.WebhookReceivers[0].Path) != config.WebhookPathLen {
		t.Fatalf("接收器应带上随机路径，实际 %q", cfg.WebhookReceivers[0].Path)
	}
}

// 删除模块 = 停止监听 + 那一页回到"未创建"，但接收器、模板、目标一律不动：
// 用户删的是"这台机器上的入站监听"，不是他配了半天的路由规则。
func TestDeleteWebhookServer(t *testing.T) {
	manager, router := newWebhookAPITest(t)
	if err := manager.Update(func(cfg *config.Config) {
		cfg.Webhook.Enabled, cfg.Webhook.Port, cfg.Webhook.Domain = true, 25667, "hook.example.com"
		cfg.WebhookReceivers = []config.WebhookReceiver{{ID: "r1", Name: "第三方系统", Path: "hook"}}
	}); err != nil {
		t.Fatal(err)
	}

	w := performJSONRequest(router, http.MethodDelete, "/webhook/server", "")
	if w.Code != http.StatusOK {
		t.Fatalf("删除应成功，实际 %d：%s", w.Code, w.Body.String())
	}
	cfg := manager.Get()
	if cfg.Webhook.Created || cfg.Webhook.Enabled || cfg.Webhook.Domain != "" {
		t.Fatalf("删除后应回到一份干净的默认值：%+v", cfg.Webhook)
	}
	if cfg.Webhook.Port != config.DefaultWebhookPort {
		t.Fatalf("端口应回默认值，实际 %d", cfg.Webhook.Port)
	}
	if len(cfg.WebhookReceivers) != 1 || cfg.WebhookReceivers[0].Path != "hook" {
		t.Fatalf("接收器不该被动：%+v", cfg.WebhookReceivers)
	}
	// 再删一次：那一行已经不在了，报 404 而不是默默成功——界面据此知道该刷新了。
	if w := performJSONRequest(router, http.MethodDelete, "/webhook/server", ""); w.Code != http.StatusNotFound {
		t.Fatalf("重复删除应回 404，实际 %d：%s", w.Code, w.Body.String())
	}
}

// 有接收器还开着就不能删：模块一没，它们立刻收不到任何消息，而列表上那个绿开关
// 仍然亮着。错误里必须点名是谁挡着，否则用户面对一堆接收器不知道该停哪个。
func TestDeleteWebhookServerBlockedByEnabledReceivers(t *testing.T) {
	manager, router := newWebhookAPITest(t)
	if err := manager.Update(func(cfg *config.Config) {
		cfg.Webhook.Enabled = true
		cfg.WebhookReceivers = []config.WebhookReceiver{
			{ID: "r1", Name: "第三方系统", Path: "hook", Enabled: true},
			{ID: "r2", Name: "已停用的", Path: "hook2"},
		}
	}); err != nil {
		t.Fatal(err)
	}

	w := performJSONRequest(router, http.MethodDelete, "/webhook/server", "")
	if w.Code != http.StatusBadRequest {
		t.Fatalf("应被拒，实际 %d：%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "第三方系统") {
		t.Fatalf("错误应点名挡着的接收器：%s", w.Body.String())
	}
	if strings.Contains(w.Body.String(), "已停用的") {
		t.Fatalf("停用的接收器不该出现在拦截理由里：%s", w.Body.String())
	}
	if !manager.Get().Webhook.Created {
		t.Fatal("被拒的删除不该落盘")
	}

	// 停掉那一个之后就能删了——这正是错误文案指的下一步。
	if err := manager.Update(func(cfg *config.Config) {
		cfg.WebhookReceivers[0].Enabled = false
	}); err != nil {
		t.Fatal(err)
	}
	if w := performJSONRequest(router, http.MethodDelete, "/webhook/server", ""); w.Code != http.StatusOK {
		t.Fatalf("停用之后应能删，实际 %d：%s", w.Code, w.Body.String())
	}
}

// 模块没创建时接收器无法启用；建了之后就能——这是用户唯一会走的顺序。
func TestReceiverEnableRequiresModule(t *testing.T) {
	manager, router := newWebhookAPITest(t)
	if err := manager.Update(func(cfg *config.Config) {
		cfg.Webhook = config.WebhookServer{Listen: "0.0.0.0", Port: config.DefaultWebhookPort}
	}); err != nil {
		t.Fatal(err)
	}
	const body = `{"name":"第三方系统","enabled":true,"path":"hook","defaultTargets":["g1"],
		"rules":[{"id":"ru1","name":"全部","enabled":true,"templateRef":"t1"}]}`

	w := performJSONRequest(router, http.MethodPost, "/webhook/receivers", body)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("模块未创建时不该允许启用，实际 %d：%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "模块设置") {
		t.Fatalf("错误应指出去哪儿建模块：%s", w.Body.String())
	}
	// 停用的照存不误：用户常常是先配好接收器、再去建模块。
	off := strings.Replace(body, `"enabled":true,"path"`, `"enabled":false,"path"`, 1)
	if w := performJSONRequest(router, http.MethodPost, "/webhook/receivers", off); w.Code != http.StatusOK {
		t.Fatalf("停用的接收器应能存下，实际 %d：%s", w.Code, w.Body.String())
	}

	// 建模块之后再启用就通了。
	if w := performJSONRequest(router, http.MethodPut, "/webhook/server",
		serverBodyFull(true, 25667, "hook.example.com", "", false, "")); w.Code != http.StatusOK {
		t.Fatalf("建模块应成功：%s", w.Body.String())
	}
	id := manager.Get().WebhookReceivers[0].ID
	if w := performJSONRequest(router, http.MethodPost, "/webhook/receivers/"+id+"/toggle",
		`{"enabled":true}`); w.Code != http.StatusOK {
		t.Fatalf("建完模块应能启用，实际 %d：%s", w.Code, w.Body.String())
	}
	if !manager.Get().WebhookReceivers[0].Enabled {
		t.Fatal("启用应真的落盘")
	}
}

// ---------- 令牌脱敏往返 ----------

// 令牌不能出现在任何一个读接口里，而"用户没改令牌"必须能原样提交回来。
// 这两条合起来才是可用的：只做脱敏会让每次保存都把令牌清成占位符字面量。
func TestReceiverTokenMaskRoundTrip(t *testing.T) {
	manager, router := newWebhookAPITest(t)
	const token = "第三方系统专用令牌"
	create := fmt.Sprintf(`{"name":"第三方系统","enabled":true,"path":"hook","authType":"token","token":%q,
		"defaultTargets":["g1"],
		"rules":[{"id":"ru1","name":"每日汇总","enabled":true,"templateRef":"t1"}]}`, token)

	w := performJSONRequest(router, http.MethodPost, "/webhook/receivers", create)
	if w.Code != http.StatusOK {
		t.Fatalf("新建应成功，实际 %d：%s", w.Code, w.Body.String())
	}
	rcs := manager.Get().WebhookReceivers
	if len(rcs) != 1 || rcs[0].Token != token {
		t.Fatalf("令牌应原样存下：%+v", rcs)
	}
	id := rcs[0].ID

	// 列表里只回占位符。
	list := performJSONRequest(router, http.MethodGet, "/webhook/receivers", "")
	if strings.Contains(list.Body.String(), token) {
		t.Fatalf("列表接口泄露了令牌：%s", list.Body.String())
	}
	if !strings.Contains(list.Body.String(), maskedSecret) {
		t.Fatalf("列表应回占位符：%s", list.Body.String())
	}

	// 用户没动令牌，原样把占位符提交回来 → 必须还原成原令牌。
	back := fmt.Sprintf(`{"id":%q,"name":"第三方系统改名","enabled":true,"path":"hook","authType":"token","token":%q,
		"defaultTargets":["g1"],
		"rules":[{"id":"ru1","name":"每日汇总","enabled":true,"templateRef":"t1"}]}`, id, maskedSecret)
	if w := performJSONRequest(router, http.MethodPut, "/webhook/receivers/"+id, back); w.Code != http.StatusOK {
		t.Fatalf("回传占位符应成功，实际 %d：%s", w.Code, w.Body.String())
	}
	after := manager.Get().WebhookReceivers[0]
	if after.Token != token {
		t.Fatalf("回传占位符不该改动令牌，实际 %q", after.Token)
	}
	if after.Name != "第三方系统改名" {
		t.Fatalf("其余字段应正常保存，实际 %q", after.Name)
	}

	// 真的换了令牌就要存新的。
	renew := strings.Replace(back, maskedSecret, "新令牌", 1)
	if w := performJSONRequest(router, http.MethodPut, "/webhook/receivers/"+id, renew); w.Code != http.StatusOK {
		t.Fatalf("换令牌应成功，实际 %d：%s", w.Code, w.Body.String())
	}
	if got := manager.Get().WebhookReceivers[0].Token; got != "新令牌" {
		t.Fatalf("新令牌应存下，实际 %q", got)
	}
}

// 新建时把占位符当令牌提交（复制粘贴另一个接收器的配置就会这样）：
// 还原不出任何令牌，必须被校验拦住，而不是把 "******" 存成真令牌。
func TestReceiverMaskedTokenOnCreateIsRejected(t *testing.T) {
	manager, router := newWebhookAPITest(t)
	create := fmt.Sprintf(`{"name":"第三方系统","enabled":true,"path":"hook","authType":"token","token":%q,
		"defaultTargets":["g1"],
		"rules":[{"id":"ru1","name":"每日汇总","enabled":true,"templateRef":"t1"}]}`, maskedSecret)

	w := performJSONRequest(router, http.MethodPost, "/webhook/receivers", create)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("应被校验拦住，实际 %d：%s", w.Code, w.Body.String())
	}
	if got := manager.Get().WebhookReceivers; len(got) != 0 {
		t.Fatalf("不该存下任何接收器：%+v", got)
	}
}

// 保存时的路径重复校验必须真的接在 CRUD 上——validateReceiver 单测过不代表接上了。
func TestReceiverDuplicatePathRejectedThroughAPI(t *testing.T) {
	manager, router := newWebhookAPITest(t)
	body := func(name, path string) string {
		return fmt.Sprintf(`{"name":%q,"enabled":true,"path":%q,"defaultTargets":["g1"],
			"rules":[{"id":"ru1","name":"全部","enabled":true,"templateRef":"t1"}]}`, name, path)
	}
	if w := performJSONRequest(router, http.MethodPost, "/webhook/receivers", body("第三方系统", "hook")); w.Code != http.StatusOK {
		t.Fatalf("第一个应成功：%s", w.Body.String())
	}
	w := performJSONRequest(router, http.MethodPost, "/webhook/receivers", body("Grafana", "hook"))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("重复路径应被拒，实际 %d：%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "第三方系统") {
		t.Fatalf("错误应指出占用者：%s", w.Body.String())
	}
	if got := len(manager.Get().WebhookReceivers); got != 1 {
		t.Fatalf("被拒的新增不该落盘，实际 %d 个", got)
	}
}

// 随机路径生成：这是"不写死逻辑"之外的另一层保护——路径本身是凭证，
// 必须够长、够随机，且每次都不一样。
func TestWebhookNewPath(t *testing.T) {
	_, router := newWebhookAPITest(t)
	seen := map[string]bool{}
	for i := 0; i < 8; i++ {
		w := performJSONRequest(router, http.MethodGet, "/webhook/newpath", "")
		if w.Code != http.StatusOK {
			t.Fatalf("应返回 200，实际 %d：%s", w.Code, w.Body.String())
		}
		var out struct {
			Data struct{ Path string } `json:"data"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
			t.Fatalf("响应不是预期的 JSON：%s", w.Body.String())
		}
		path := out.Data.Path
		if len(path) != config.WebhookPathLen {
			t.Fatalf("路径长度应为 %d，实际 %d（%q）", config.WebhookPathLen, len(path), path)
		}
		// 只含 hex：路径要能直接贴进第三方系统的 URL 栏，不该出现需要转义的字符。
		if strings.TrimLeft(path, "0123456789abcdef") != "" {
			t.Fatalf("路径应只含小写 hex：%q", path)
		}
		if seen[path] {
			t.Fatalf("两次生成了相同的路径：%q", path)
		}
		seen[path] = true
	}
}

// ---------- 实时试运行 ----------
//
// 这三个接口是界面上那一个按钮加一次轮询的全部依托：开始 → 轮询取抓包 → 停止。
// 它们只是模块状态的薄壳，所以必须连着**真模块**测——否则"开始之后 running
// 有没有真的变"这件事一个断言也覆盖不到，而它错了的表现是按钮一直点不亮。

// newTestRunAPI 搭一份带真实消息路由模块的接口环境，接收器 r1 已启用。
func newTestRunAPI(t *testing.T) (*gin.Engine, *webhook.Module) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	manager := config.NewManager(filepath.Join(t.TempDir(), "config.json"))
	if err := manager.Load(); err != nil {
		t.Fatal(err)
	}
	if err := manager.Update(func(cfg *config.Config) {
		cfg.MessageTemplates = []config.MessageTemplate{{ID: "t1", Name: "汇总模板", Format: "text", Body: "收到 {{.source}}"}}
		cfg.NotifyTargets = []config.NotifyTarget{{ID: "g1", Name: "运维群", Enabled: true, Type: "dingtalk"}}
		cfg.WebhookReceivers = []config.WebhookReceiver{{
			ID: "r1", Name: "第三方系统", Enabled: true, Path: "hook", SourceType: "json",
			DefaultTargets: []string{"g1"},
			Rules:          []config.WebhookRule{{ID: "ru1", Name: "全部", Enabled: true, TemplateRef: "t1"}},
		}}
	}); err != nil {
		t.Fatal(err)
	}
	// Webhook.Enabled 默认 false：模块不监听端口，只有状态机在跑。
	stats := runstats.New()
	mod := webhook.New(logx.New(logx.Options{}), stats, "")
	if err := mod.Reload(manager.Get()); err != nil {
		t.Fatalf("模块 Reload 失败：%v", err)
	}
	t.Cleanup(func() { _ = mod.Close() })

	s := &Server{deps: Deps{Config: manager, Webhook: mod, Stats: stats}}
	router := gin.New()
	s.registerWebhookRoutes(router.Group(""))
	return router, mod
}

// testRunCall 发一次试运行请求并解出状态。
func testRunCall(t *testing.T, router *gin.Engine, method, path string, wantCode int) webhook.TestRunState {
	t.Helper()
	w := performJSONRequest(router, method, path, "")
	if w.Code != wantCode {
		t.Fatalf("%s %s 应回 %d，实际 %d：%s", method, path, wantCode, w.Code, w.Body.String())
	}
	var out struct {
		Data webhook.TestRunState `json:"data"`
	}
	if wantCode == http.StatusOK {
		if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
			t.Fatalf("响应不是预期的 JSON：%s", w.Body.String())
		}
	}
	return out.Data
}

func TestTestRunEndpoints(t *testing.T) {
	router, mod := newTestRunAPI(t)

	// 没开过就轮询不该报错：界面进页面时会先拉一次状态定按钮的颜色。
	if st := testRunCall(t, router, http.MethodGet, "/webhook/receivers/r1/testrun", http.StatusOK); st.Running {
		t.Fatalf("没开过不该是运行中：%+v", st)
	}

	st := testRunCall(t, router, http.MethodPost, "/webhook/receivers/r1/testrun/start", http.StatusOK)
	if !st.Running || st.StartedAt == 0 || st.ExpiresAt <= st.StartedAt {
		t.Fatalf("开始后应回运行中与倒计时：%+v", st)
	}
	// 接口回的状态必须和模块里的是同一份，否则界面显示的是另一回事。
	if !mod.TestRunState("r1").Running {
		t.Fatal("模块里也应处在试运行中")
	}
	if got := testRunCall(t, router, http.MethodGet, "/webhook/receivers/r1/testrun", http.StatusOK); !got.Running {
		t.Fatalf("轮询应回运行中：%+v", got)
	}

	if got := testRunCall(t, router, http.MethodPost, "/webhook/receivers/r1/testrun/stop", http.StatusOK); got.Running {
		t.Fatalf("停止后不该还是运行中：%+v", got)
	}
	if mod.TestRunState("r1").Running {
		t.Fatal("模块里也应已停止")
	}
	// 停止是幂等的收尾动作：重复点、或接收器刚被删掉，都该能停干净。
	testRunCall(t, router, http.MethodPost, "/webhook/receivers/r1/testrun/stop", http.StatusOK)
	testRunCall(t, router, http.MethodPost, "/webhook/receivers/不存在/testrun/stop", http.StatusOK)

	// 开始则要认接收器：按钮就挂在那一行，报错等于告诉用户这条配置刚被别人删了。
	testRunCall(t, router, http.MethodPost, "/webhook/receivers/不存在/testrun/start", http.StatusBadRequest)
}

// 模块没起来时（消息路由整个关掉）：开始与停止如实报 503，
// 而轮询回一份空状态——界面上那个按钮显示成未开始，而不是一直转圈。
func TestTestRunEndpointsWithoutModule(t *testing.T) {
	_, router := newWebhookAPITest(t)
	for _, path := range []string{
		"/webhook/receivers/r1/testrun/start",
		"/webhook/receivers/r1/testrun/stop",
	} {
		if w := performJSONRequest(router, http.MethodPost, path, ""); w.Code != http.StatusServiceUnavailable {
			t.Fatalf("%s 应回 503，实际 %d：%s", path, w.Code, w.Body.String())
		}
	}
	if st := testRunCall(t, router, http.MethodGet, "/webhook/receivers/r1/testrun", http.StatusOK); st.Running {
		t.Fatalf("没有模块时应回空状态：%+v", st)
	}
}
