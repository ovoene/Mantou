package server

import (
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"mantou/internal/config"
)

// 本文件盯的是"证书正被使用时不能停用"这条互锁，重点是其中的**消息路由**一支。
//
// 消息路由启用 HTTPS 后没有明文回落：证书一旦被停用，模块起不来，
// 所有第三方来源同时静默失联——而用户此刻做的动作只是在证书页上关了个开关，
// 界面上不会有任何东西提示这两件事有关。所以拦截点只能在保存证书这一步。

// certCfg 一份只有一张证书的配置，供各用例按需加引用方。
func certCfg(mut func(*config.Config)) *config.Config {
	cfg := &config.Config{
		Certs: []config.Certificate{{ID: "c1", Name: "通配证书", Enabled: true,
			Domains: []string{"*.example.com"}}},
	}
	if mut != nil {
		mut(cfg)
	}
	return cfg
}

func TestCertInUse(t *testing.T) {
	cases := []struct {
		name string
		mut  func(*config.Config)
		want []string // 期望列出的模块名，nil 表示"没有人在用"
	}{
		{"没有人引用", nil, nil},
		{"消息路由引用", func(c *config.Config) {
			c.Webhook.HTTPS.Enabled, c.Webhook.HTTPS.CertID = true, "c1"
		}, []string{"消息路由"}},
		// 关掉 HTTPS 之后 CertID 常常还留在配置里（界面上只是取消勾选）。
		// 那时证书已经不再被真正使用，不能再拦着用户停用它。
		{"消息路由关闭HTTPS后不算引用", func(c *config.Config) {
			c.Webhook.HTTPS.Enabled, c.Webhook.HTTPS.CertID = false, "c1"
		}, nil},
		{"消息路由指向别的证书", func(c *config.Config) {
			c.Webhook.HTTPS.Enabled, c.Webhook.HTTPS.CertID = true, "c2"
		}, []string{}},
		{"面板引用", func(c *config.Config) {
			c.Panel.HTTPS.Enabled, c.Panel.HTTPS.CertID = true, "c1"
		}, []string{"面板服务"}},
		// 两个模块同时引用时要都列出来：只报一个会让用户改完一处又被拦一次。
		{"面板与消息路由同时引用", func(c *config.Config) {
			c.Panel.HTTPS.Enabled, c.Panel.HTTPS.CertID = true, "c1"
			c.Webhook.HTTPS.Enabled, c.Webhook.HTTPS.CertID = true, "c1"
		}, []string{"面板服务", "消息路由"}},
		// Web 服务按域名覆盖判断（这里靠通配匹配），与前两者的 CertID 直连不同。
		{"Web服务按域名覆盖", func(c *config.Config) {
			c.WebServices = []config.WebService{{ID: "ws1", Name: "官网", Enabled: true,
				Children: []config.WebChild{{ID: "ch1", Enabled: true, TLS: true,
					Domains: []string{"www.example.com"}}}}}
		}, []string{"Web 服务「官网」"}},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			used, mods := certInUse(certCfg(c.mut), "c1")
			if used != (len(c.want) > 0) {
				t.Fatalf("是否在用应为 %v，实际 %v（%v）", len(c.want) > 0, used, mods)
			}
			if len(mods) != len(c.want) {
				t.Fatalf("模块列表应为 %v，实际 %v", c.want, mods)
			}
			for i := range c.want {
				if mods[i] != c.want[i] {
					t.Fatalf("模块列表应为 %v，实际 %v", c.want, mods)
				}
			}
		})
	}
}

// 只有"停用"这个动作要被拦。改名、换域名、续期都必须能存下去——
// 否则一张正在服役的证书将永远无法编辑。
func TestValidateCertOnlyBlocksDisable(t *testing.T) {
	cfg := certCfg(func(c *config.Config) {
		c.Webhook.HTTPS.Enabled, c.Webhook.HTTPS.CertID = true, "c1"
	})

	live := cfg.Certs[0]
	live.Name = "改个名字"
	if err := validateCert(cfg, live); err != nil {
		t.Fatalf("启用中的证书应可正常保存：%v", err)
	}

	off := cfg.Certs[0]
	off.Enabled = false
	err := validateCert(cfg, off)
	if err == nil {
		t.Fatal("正被消息路由使用的证书不应允许停用")
	}
	// 错误里必须点出是谁在用：用户在证书页上完全看不出消息路由与这张证书的关系。
	if !strings.Contains(err.Error(), "消息路由") {
		t.Fatalf("错误应指出使用方：%q", err.Error())
	}

	// 没有人引用时可以随便停用。
	if err := validateCert(certCfg(nil), off); err != nil {
		t.Fatalf("无人引用时应可停用：%v", err)
	}
}

// 校验必须真的接在证书 CRUD 上：validateCert 单测通过不代表接上了。
// 这里走线上那份 registerResourceRoutes。
func newCertAPITest(t *testing.T) (*config.Manager, *gin.Engine) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	manager := config.NewManager(filepath.Join(t.TempDir(), "config.json"))
	if err := manager.Load(); err != nil {
		t.Fatal(err)
	}
	if err := manager.Update(func(cfg *config.Config) {
		cfg.Certs = []config.Certificate{{ID: "c1", Name: "通配证书", Enabled: true,
			Domains: []string{"*.example.com"}}}
		cfg.Webhook.HTTPS.Enabled = true
		cfg.Webhook.HTTPS.CertID = "c1"
		cfg.Webhook.Domain = "hook.example.com"
	}); err != nil {
		t.Fatal(err)
	}
	s := &Server{deps: Deps{Config: manager}}
	router := gin.New()
	s.registerResourceRoutes(router.Group(""))
	return manager, router
}

func TestDisableCertUsedByWebhookThroughAPI(t *testing.T) {
	manager, router := newCertAPITest(t)

	body := func(enabled bool) string {
		return fmt.Sprintf(`{"id":"c1","name":"通配证书","enabled":%t,"domains":["*.example.com"]}`, enabled)
	}

	w := performJSONRequest(router, http.MethodPut, "/certs/c1", body(false))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("停用在用的证书应被拒，实际 %d：%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "消息路由") {
		t.Fatalf("错误应指出使用方：%s", w.Body.String())
	}
	if !manager.Get().Certs[0].Enabled {
		t.Fatal("被拒的请求不该把证书改成停用")
	}

	// 先关掉消息路由的 HTTPS，再停用证书——这是用户唯一能走通的顺序，必须走得通。
	if err := manager.Update(func(cfg *config.Config) { cfg.Webhook.HTTPS.Enabled = false }); err != nil {
		t.Fatal(err)
	}
	if w := performJSONRequest(router, http.MethodPut, "/certs/c1", body(false)); w.Code != http.StatusOK {
		t.Fatalf("解除引用后应可停用，实际 %d：%s", w.Code, w.Body.String())
	}
	if manager.Get().Certs[0].Enabled {
		t.Fatal("停用应已落盘")
	}
}

// ---------- 删除 ----------

// 删除与停用共用同一套判定，但**不看** Enabled：一张已经停用的证书仍可能被
// 引用（引用方是靠 CertID / 域名连过来的，与证书自己的开关无关），
// 删掉它同样会让对方下次启动找不到证书。
func TestValidateCertDelete(t *testing.T) {
	cfg := certCfg(func(c *config.Config) {
		c.Webhook.HTTPS.Enabled, c.Webhook.HTTPS.CertID = true, "c1"
	})

	err := validateCertDelete(cfg, cfg.Certs[0])
	if err == nil {
		t.Fatal("正被消息路由使用的证书不应允许删除")
	}
	if !strings.Contains(err.Error(), "消息路由") {
		t.Fatalf("错误应指出使用方：%q", err.Error())
	}
	// 用户在证书页上看不出该去哪里解除引用，错误里得把出路说清楚。
	if !strings.Contains(err.Error(), "关闭 HTTPS") {
		t.Fatalf("错误应给出可执行的下一步：%q", err.Error())
	}

	off := cfg.Certs[0]
	off.Enabled = false
	if err := validateCertDelete(cfg, off); err == nil {
		t.Fatal("已停用但仍被引用的证书也不该允许删除")
	}

	if err := validateCertDelete(certCfg(nil), cfg.Certs[0]); err != nil {
		t.Fatalf("无人引用时应可删除：%v", err)
	}
}

// 只拦停用而不拦删除的话，被「无法禁用」挡住的用户点一下删除就绕过去了。
// 这条走线上那份 registerResourceRoutes，确认钩子真的接在 DELETE 上。
func TestDeleteCertUsedByWebhookThroughAPI(t *testing.T) {
	manager, router := newCertAPITest(t)

	w := performJSONRequest(router, http.MethodDelete, "/certs/c1", "")
	if w.Code != http.StatusBadRequest {
		t.Fatalf("删除在用的证书应被拒，实际 %d：%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "消息路由") {
		t.Fatalf("错误应指出使用方：%s", w.Body.String())
	}
	if len(manager.Get().Certs) != 1 {
		t.Fatal("被拒的请求不该把证书删掉")
	}

	// 不存在的 ID 仍然是 404，不能因为多了道校验就变成 400——
	// 前端靠这个区分「已经被别人删了」和「不许删」。
	if w := performJSONRequest(router, http.MethodDelete, "/certs/不存在", ""); w.Code != http.StatusNotFound {
		t.Fatalf("删除不存在的证书应回 404，实际 %d：%s", w.Code, w.Body.String())
	}

	// 解除引用后必须删得掉，否则这张证书就永远留在列表里了。
	if err := manager.Update(func(cfg *config.Config) { cfg.Webhook.HTTPS.Enabled = false }); err != nil {
		t.Fatal(err)
	}
	if w := performJSONRequest(router, http.MethodDelete, "/certs/c1", ""); w.Code != http.StatusOK {
		t.Fatalf("解除引用后应可删除，实际 %d：%s", w.Code, w.Body.String())
	}
	if len(manager.Get().Certs) != 0 {
		t.Fatal("删除应已落盘")
	}
}

// 没挂 validateDelete 的资源不受影响：这个钩子是逐个资源挂上去的，
// 一旦写成"所有资源都要过一遍"，任何一个资源都可能被顺带拦住。
func TestDeleteWithoutValidateHookStillWorks(t *testing.T) {
	manager, router := newCertAPITest(t)
	if err := manager.Update(func(cfg *config.Config) {
		cfg.ACMEAccounts = []config.ACMEAccount{{ID: "a1", Name: "Let's Encrypt"}}
	}); err != nil {
		t.Fatal(err)
	}
	if w := performJSONRequest(router, http.MethodDelete, "/acme-accounts/a1", ""); w.Code != http.StatusOK {
		t.Fatalf("没挂删除校验的资源应照常删除，实际 %d：%s", w.Code, w.Body.String())
	}
	if len(manager.Get().ACMEAccounts) != 0 {
		t.Fatal("删除应已落盘")
	}
}
