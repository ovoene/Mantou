package server

import (
	"net/http"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"mantou/internal/config"
)

// 父项的大部分约束只在"父项启用"时生效：同一（地址族, 端口）只许一个启用父项、跨父项 TLS 一致、
// 域名在同一端口上的归属、面板域名保留、"默认站点"只能有一个。原先列表里的父项开关只查了
// 端口撞面板与消息路由共用两件事，于是"先存成停用、再点一下开关"就能把保存时会被拒的配置
// 开起来。下面钉住：开关与保存走同一套校验，校验不过就不落盘；而关掉永远走得通。

// newToggleTestServer 装好一份配置，返回挂着父项开关路由的 router。
func newToggleTestServer(t *testing.T, services ...config.WebService) (*config.Manager, http.Handler) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	manager := config.NewManager(t.TempDir() + "/config.json")
	if err := manager.Load(); err != nil {
		t.Fatal(err)
	}
	if err := manager.Update(func(c *config.Config) {
		c.Panel.Port = 25666
		c.WebServices = services
	}); err != nil {
		t.Fatal(err)
	}
	s := &Server{deps: Deps{Config: manager}}
	router := gin.New()
	router.POST("/webservices/:id/toggle", s.handleToggleWebService)
	return manager, router
}

// TestToggleWebServiceRejectsDuplicatePort 同一（地址族, 端口）上已有一个启用的父项：
// 另一个停用中的父项不能靠列表开关启用。
func TestToggleWebServiceRejectsDuplicatePort(t *testing.T) {
	a := wsParent("ws-a", 8443, wsChild("a", true, "a.example.com"))
	b := wsParent("ws-b", 8443, wsChild("b", true, "b.example.com"))
	b.Enabled = false
	manager, router := newToggleTestServer(t, a, b)

	w := performJSONRequest(router, http.MethodPost, "/webservices/ws-b/toggle", `{"enabled":true}`)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("同端口已有启用父项时不该允许启用，实际 %d：%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "已被另一个启用的服务占用") {
		t.Fatalf("报错应说明端口被占用，实际：%s", w.Body.String())
	}
	for _, ws := range manager.Get().WebServices {
		if ws.ID == "ws-b" && ws.Enabled {
			t.Fatal("被拒的一次启用不该落盘")
		}
	}
}

// TestToggleWebServiceRejectsPanelDomain 子项占用面板域名的父项，同样不能靠开关启用。
func TestToggleWebServiceRejectsPanelDomain(t *testing.T) {
	ws := wsParent("ws1", 8443, wsChild("a", true, "panel.example.com"))
	ws.Enabled = false
	manager, router := newToggleTestServer(t, ws)
	if err := manager.Update(func(c *config.Config) {
		c.Panel.HTTPS = config.PanelHTTPS{Enabled: true, Domain: "panel.example.com"}
	}); err != nil {
		t.Fatal(err)
	}

	w := performJSONRequest(router, http.MethodPost, "/webservices/ws1/toggle", `{"enabled":true}`)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("占用面板域名的服务不该允许启用，实际 %d：%s", w.Code, w.Body.String())
	}
	if manager.Get().WebServices[0].Enabled {
		t.Fatal("被拒的一次启用不该落盘")
	}
}

// TestToggleWebServiceDisableAlwaysWorks 已经处在冲突状态的配置（手改、导入进来的）也必须能关掉。
func TestToggleWebServiceDisableAlwaysWorks(t *testing.T) {
	a := wsParent("ws-a", 8443, wsChild("a", true, "a.example.com"))
	b := wsParent("ws-b", 8443, wsChild("b", true, "b.example.com")) // 两个都开着：本身就是冲突
	manager, router := newToggleTestServer(t, a, b)

	w := performJSONRequest(router, http.MethodPost, "/webservices/ws-b/toggle", `{"enabled":false}`)
	if w.Code != http.StatusOK {
		t.Fatalf("关掉服务必须永远走得通，实际 %d：%s", w.Code, w.Body.String())
	}
	for _, ws := range manager.Get().WebServices {
		if ws.ID == "ws-b" && ws.Enabled {
			t.Fatal("关闭没有落盘")
		}
	}
}

// TestToggleWebServiceUnknownID 不存在的父项回 404。
func TestToggleWebServiceUnknownID(t *testing.T) {
	_, router := newToggleTestServer(t)
	if w := performJSONRequest(router, http.MethodPost, "/webservices/nope/toggle", `{"enabled":true}`); w.Code != http.StatusNotFound {
		t.Fatalf("不存在的服务应当 404，实际 %d：%s", w.Code, w.Body.String())
	}
}
