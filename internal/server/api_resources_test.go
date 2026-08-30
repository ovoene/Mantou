package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"mantou/internal/config"
	"mantou/internal/logx"
)

func newWebServiceCRUDTest(t *testing.T) (*config.Manager, *gin.Engine) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	manager := config.NewManager(t.TempDir() + "/config.json")
	if err := manager.Load(); err != nil {
		t.Fatal(err)
	}
	s := &Server{deps: Deps{Config: manager}}
	router := gin.New()
	registerCRUD(s, router.Group(""), "webservices", resource[config.WebService]{
		get:       func(c *config.Config) []config.WebService { return c.WebServices },
		set:       func(c *config.Config, v []config.WebService) { c.WebServices = v },
		id:        func(ws *config.WebService) string { return ws.ID },
		setID:     func(ws *config.WebService, id string) { ws.ID = id },
		normalize: normalizeWebService,
		validate: func(cfg *config.Config, ws config.WebService) error {
			return validateWebService(cfg, ws, s.deps.DataDir)
		},
	})
	return manager, router
}

func performJSONRequest(router http.Handler, method, target, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	return w
}

func TestWebServiceCRUDNormalizesTLSMinVersion(t *testing.T) {
	manager, router := newWebServiceCRUDTest(t)
	body := `{"name":"site","enabled":true,"port":8443,"ipFamily":"both","children":[{"id":"a","enabled":true,"tls":true,"tlsMinVersion":""}]}`
	w := performJSONRequest(router, http.MethodPost, "/webservices", body)
	if w.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d: %s", http.StatusOK, w.Code, w.Body.String())
	}
	got := manager.Get().WebServices
	if len(got) != 1 || got[0].Children[0].TLSMinVersion != "1.2" {
		t.Fatalf("expected normalized TLS 1.2, got %#v", got)
	}
	var response struct {
		Data config.WebService `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.Data.Children[0].TLSMinVersion != "1.2" {
		t.Fatalf("expected response TLS 1.2, got %q", response.Data.Children[0].TLSMinVersion)
	}
}

func TestWebServiceCRUDRejectsMixedEnabledProtocols(t *testing.T) {
	manager, router := newWebServiceCRUDTest(t)
	body := `{"name":"site","enabled":true,"port":8443,"ipFamily":"both","children":[{"id":"http","enabled":true,"tls":false,"tlsMinVersion":"1.2"},{"id":"https","enabled":true,"tls":true,"tlsMinVersion":"1.2"}]}`
	w := performJSONRequest(router, http.MethodPost, "/webservices", body)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected status %d, got %d: %s", http.StatusBadRequest, w.Code, w.Body.String())
	}
	if len(manager.Get().WebServices) != 0 {
		t.Fatal("invalid Web service must not be saved")
	}
}

func TestWebServiceCRUDAllowsDisabledProtocolMismatch(t *testing.T) {
	_, router := newWebServiceCRUDTest(t)
	body := `{"name":"site","enabled":true,"port":8443,"ipFamily":"both","children":[{"id":"http","enabled":true,"tls":false,"tlsMinVersion":"1.2"},{"id":"https","enabled":false,"tls":true,"tlsMinVersion":"1.3"}]}`
	w := performJSONRequest(router, http.MethodPost, "/webservices", body)
	if w.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d: %s", http.StatusOK, w.Code, w.Body.String())
	}
}

func TestWebServiceCRUDRejectsInvalidTLSVersionOnUpdate(t *testing.T) {
	manager, router := newWebServiceCRUDTest(t)
	if err := manager.Update(func(cfg *config.Config) {
		cfg.WebServices = []config.WebService{{ID: "existing", Name: "old", Port: 8080}}
	}); err != nil {
		t.Fatal(err)
	}
	body := `{"name":"new","enabled":true,"port":8443,"ipFamily":"both","children":[{"id":"a","enabled":true,"tls":true,"tlsMinVersion":"1.4"}]}`
	w := performJSONRequest(router, http.MethodPut, "/webservices/existing", body)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected status %d, got %d: %s", http.StatusBadRequest, w.Code, w.Body.String())
	}
	if got := manager.Get().WebServices[0].Name; got != "old" {
		t.Fatalf("invalid update changed stored service to %q", got)
	}
}

// TestAuditUpdateUsesExplicitEnabledAccessor 锁住审计日志对「启用/禁用」的判定。
// 这段逻辑原先靠反射查找名为 Enabled 的布尔字段，改成 resource.enabled 显式闭包后，
// 「有开关的资源要记启用/禁用」和「没开关的资源一律记保存」都必须保持原样——
// 少配一个 enabled 闭包不会编译报错，只会让某个模块的启停从审计日志里悄悄消失。
func TestAuditUpdateUsesExplicitEnabledAccessor(t *testing.T) {
	type ruleWithSwitch struct {
		ID      string
		Name    string
		Enabled bool
	}
	type ruleNoSwitch struct {
		ID   string
		Name string
	}

	withSwitch := resource[ruleWithSwitch]{
		modLabel: "有开关的模块",
		itemName: func(t *ruleWithSwitch) string { return t.Name },
		enabled:  func(t *ruleWithSwitch) bool { return t.Enabled },
	}
	noSwitch := resource[ruleNoSwitch]{
		modLabel: "无开关的模块",
		itemName: func(t *ruleNoSwitch) string { return t.Name },
	}

	cases := []struct {
		name string
		run  func(s *Server)
		want string
	}{
		{
			name: "关到开记启用",
			run: func(s *Server) {
				auditUpdate(s, withSwitch, "r1",
					&ruleWithSwitch{ID: "r1", Name: "规则", Enabled: false},
					&ruleWithSwitch{ID: "r1", Name: "规则", Enabled: true})
			},
			want: "启用 有开关的模块 下 规则",
		},
		{
			name: "开到关记禁用",
			run: func(s *Server) {
				auditUpdate(s, withSwitch, "r1",
					&ruleWithSwitch{ID: "r1", Name: "规则", Enabled: true},
					&ruleWithSwitch{ID: "r1", Name: "规则", Enabled: false})
			},
			want: "禁用 有开关的模块 下 规则",
		},
		{
			name: "开关未变记保存",
			run: func(s *Server) {
				auditUpdate(s, withSwitch, "r1",
					&ruleWithSwitch{ID: "r1", Name: "规则", Enabled: true},
					&ruleWithSwitch{ID: "r1", Name: "改名后", Enabled: true})
			},
			want: "保存 有开关的模块 下 改名后",
		},
		{
			name: "无开关的资源一律记保存",
			run: func(s *Server) {
				auditUpdate(s, noSwitch, "c1",
					&ruleNoSwitch{ID: "c1", Name: "凭证"},
					&ruleNoSwitch{ID: "c1", Name: "凭证"})
			},
			want: "保存 无开关的模块 下 凭证",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			log := logx.New(logx.Options{})
			c.run(&Server{deps: Deps{Log: log}})
			entries := log.Recent(0)
			if len(entries) != 1 {
				t.Fatalf("期望恰好 1 条审计日志，实际 %d 条", len(entries))
			}
			if entries[0].Message != c.want {
				t.Fatalf("审计日志 = %q，期望 %q", entries[0].Message, c.want)
			}
		})
	}
}
