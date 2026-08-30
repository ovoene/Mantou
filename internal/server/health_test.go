package server

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"mantou/internal/config"
	"mantou/internal/logx"
)

// 本文件钉住的是一个「不存在」：面板**没有**健康检查端点，也不对外提供任何
// 免鉴权就能拿到内容的接口。
//
// 曾经有过一个 /api/health：免鉴权、返回 200 与两个字节 "ok"，给容器 HEALTHCHECK
// 和 `mantou --healthcheck` 探活用。它连带开了三处例外——TLS 握手放行「回环 + 空 SNI」、
// HTTPS 域名守卫放行回环来源、访问日志跳过成功的探测。整套已移除：这个面板不需要
// 向任何人证明自己活着，未鉴权的可达面应当为零。
//
// 所以这里的断言全是反向的。有人要把探活加回来时，会先撞上这几条，
// 从而看到上面那段理由，而不是默默地重新开出一个匿名可达的端点。

// newRouteEnv 用真实的 New() 建一台面板：含完整中间件链与路由表。
//
// DataDir 必须给：/uploads 那条路由只在有数据目录时才注册，不给就等于让
// TestNoAnonymousAPIRoutes 悄悄漏掉它——而它恰好是本轮从"公开可读"收进登录之后的那条。
// 顺带在 uploads 里放一个名叫 probe 的文件：concretePath 会把 *filepath 替换成 probe，
// 目录空着的话那条请求只会得到 404，于是"这条路由有没有鉴权"根本测不出来。
func newRouteEnv(t *testing.T, basePath string) (http.Handler, string) {
	t.Helper()
	dir := t.TempDir()
	manager := config.NewManager(filepath.Join(dir, "config.json"))
	if err := manager.Load(); err != nil {
		t.Fatal(err)
	}
	if basePath != "" {
		if err := manager.Update(func(cfg *config.Config) { cfg.Panel.BasePath = basePath }); err != nil {
			t.Fatal(err)
		}
	}
	uploads := filepath.Join(dir, "uploads")
	if err := os.MkdirAll(uploads, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(uploads, "probe"), []byte("probe"), 0o644); err != nil {
		t.Fatal(err)
	}
	s := New(Deps{Config: manager, Log: logx.New(logx.Options{}), DataDir: dir})
	return s.http.Handler, basePath
}

// TestHealthEndpointIsGone 明确钉住健康检查端点已不存在：
// 前缀之下、根路径两种形式都不可达，且响应体里不会出现那个 "ok"。
func TestHealthEndpointIsGone(t *testing.T) {
	cases := []struct {
		name     string
		basePath string
		paths    []string
	}{
		{name: "无前缀", basePath: "", paths: []string{"/api/health"}},
		// 当年为了让镜像里写死的探测命令不受前缀影响，根路径上额外挂了一份。
		// 两处都必须没有。
		{name: "有前缀", basePath: "/mantou", paths: []string{"/mantou/api/health", "/api/health"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h, _ := newRouteEnv(t, tc.basePath)
			for _, p := range tc.paths {
				rec := httptest.NewRecorder()
				h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, p, nil))
				if rec.Code == http.StatusOK {
					t.Errorf("GET %s 返回了 200——健康检查端点又被加回来了：%s", p, rec.Body.String())
				}
				if strings.TrimSpace(rec.Body.String()) == "ok" {
					t.Errorf("GET %s 回了 %q，这个面板不该向匿名请求确认自己活着", p, rec.Body.String())
				}
			}
		})
	}
}

// anonymousAllowed 是 /api 之下允许匿名访问的**完整**白名单（相对访问路径前缀）。
// 这三条都是登录流程本身必需的：没有它们就没法完成首次设置、也没法登录。
// 往这里加东西之前请想清楚：任何一条都是公网上无需凭证即可触达的面。
var anonymousAllowed = map[string]bool{
	"GET /api/init/status": true,
	"POST /api/init/setup": true,
	"POST /api/auth/login": true,
}

// TestNoAnonymousAPIRoutes 遍历真实路由表，逐条用未鉴权请求打一遍：
// 除白名单三条之外，/api 与 /uploads 之下任何路由都不许返回 2xx。
//
// 这条比单独盯着 /api/health 更有用——它拦的是"下一个被顺手加上的匿名端点"，
// 不管那个端点将来叫什么名字。
func TestNoAnonymousAPIRoutes(t *testing.T) {
	for _, basePath := range []string{"", "/mantou"} {
		name := "无前缀"
		if basePath != "" {
			name = "有前缀"
		}
		t.Run(name, func(t *testing.T) {
			h, prefix := newRouteEnv(t, basePath)
			engine, ok := h.(*gin.Engine)
			if !ok {
				t.Fatalf("拿不到 *gin.Engine，实际类型 %T——本测试依赖路由表", h)
			}
			checked := 0
			for _, rt := range engine.Routes() {
				rel := strings.TrimPrefix(rt.Path, prefix)
				// /api 之外只剩两类路由：前端页面必须匿名可取（否则登录页自己都打不开），
				// 而 /uploads 下的用户上传资源已收进登录之后，要一并盯住。
				if !strings.HasPrefix(rel, "/api/") && !strings.HasPrefix(rel, "/uploads/") {
					continue
				}
				if anonymousAllowed[rt.Method+" "+rel] {
					continue
				}
				checked++
				req := httptest.NewRequest(rt.Method, concretePath(rt.Path), nil)
				rec := httptest.NewRecorder()
				h.ServeHTTP(rec, req)
				if rec.Code >= 200 && rec.Code < 300 {
					t.Errorf("%s %s 未鉴权就返回了 %d——这是一个匿名可达的接口：%s",
						rt.Method, rt.Path, rec.Code, clipBody(rec.Body.String()))
				}
			}
			// 路由表没被扫到（New 内部结构变了、或前缀拼接方式变了）时，上面的循环
			// 会一条都不检查而"通过"。给个下限，让这种静默失效暴露出来。
			if checked < 20 {
				t.Fatalf("只检查了 %d 条 /api 路由，远少于预期——本测试可能已经失效", checked)
			}
		})
	}
}

// concretePath 把路由模板里的 :param / *any 换成具体值，好让请求真正落到处理器上。
func concretePath(p string) string {
	segs := strings.Split(p, "/")
	for i, seg := range segs {
		if strings.HasPrefix(seg, ":") || strings.HasPrefix(seg, "*") {
			segs[i] = "probe"
		}
	}
	return strings.Join(segs, "/")
}

func clipBody(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > 120 {
		return s[:120] + "…"
	}
	return s
}

// newHTTPSGuardEnv 造一台"已启用面板 HTTPS 且限定域名"的服务器，只挂域名校验中间件。
func newHTTPSGuardEnv(t *testing.T) http.Handler {
	t.Helper()
	dir := t.TempDir()
	manager := config.NewManager(filepath.Join(dir, "config.json"))
	if err := manager.Load(); err != nil {
		t.Fatal(err)
	}
	if err := manager.Update(func(cfg *config.Config) {
		cfg.Panel.HTTPS.Enabled = true
		cfg.Panel.HTTPS.Domain = "panel.example.com"
	}); err != nil {
		t.Fatal(err)
	}
	s := &Server{
		deps:       Deps{Config: manager, Log: logx.New(logx.Options{})},
		panelHTTPS: true,
	}
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(s.requirePanelCertificateHost())
	// 两条路径都存在且都不需要鉴权，这样测出来的差别只可能来自域名守卫本身。
	r.GET("/api/health", func(c *gin.Context) { c.String(http.StatusOK, "ok") })
	r.GET("/api/overview", func(c *gin.Context) { c.String(http.StatusOK, "overview") })
	return r
}

// TestPanelHostGuardHasNoLoopbackExemption 钉住域名守卫不给任何来源、任何路径开例外。
//
// 这里曾经有一条豁免：健康路径 + 回环来源直接放行，因为探测只能连 127.0.0.1，
// Host 头必然是"127.0.0.1:端口"而不是配置域名。探测移除后这条豁免一并收回——
// 本机进程与外部请求现在受同一条规则约束。
func TestPanelHostGuardHasNoLoopbackExemption(t *testing.T) {
	h := newHTTPSGuardEnv(t)
	cases := []struct {
		name   string
		path   string
		host   string
		remote string
		want   int
	}{
		// 回环来源不再有任何特殊待遇，连当年那条健康路径也一样被拦。
		{name: "回环访问旧健康路径", path: "/api/health", host: "127.0.0.1:25666", remote: "127.0.0.1:41234", want: http.StatusForbidden},
		{name: "回环 IPv6 访问旧健康路径", path: "/api/health", host: "[::1]:25666", remote: "[::1]:41235", want: http.StatusForbidden},
		{name: "回环访问其它接口", path: "/api/overview", host: "127.0.0.1:25666", remote: "127.0.0.1:41236", want: http.StatusForbidden},
		{name: "外部访问旧健康路径", path: "/api/health", host: "evil.example.com", remote: "203.0.113.9:5000", want: http.StatusForbidden},
		// 用正确域名访问时一切正常——守卫不是把所有请求都拦掉了。
		{name: "正确域名访问", path: "/api/overview", host: "panel.example.com", remote: "203.0.113.9:5001", want: http.StatusOK},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tc.path, nil)
			req.Host = tc.host
			req.RemoteAddr = tc.remote
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != tc.want {
				t.Errorf("期望状态码 %d，实际 %d：%s", tc.want, rec.Code, rec.Body.String())
			}
		})
	}
}

// TestAccessLogHasNoSkipList 钉住访问日志不再对任何路径网开一面。
//
// 原先成功的健康探测被直接丢弃（每分钟一条会把环形缓冲里真正有用的访问挤掉）。
// 探测没了，这个跳过分支也删了——否则它就是一条"某个特定路径的访问不留痕"的规则，
// 而那正是攻击者会想要的性质。
func TestAccessLogHasNoSkipList(t *testing.T) {
	log := logx.New(logx.Options{Levels: []string{"debug", "info", "warn", "error"}, MaxEntries: logx.MinLogEntries})
	s := &Server{deps: Deps{Log: log}}
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(s.requestLogger())
	r.GET("/api/health", func(c *gin.Context) { c.String(http.StatusOK, "ok") })
	r.GET("/api/overview", func(c *gin.Context) { c.String(http.StatusOK, "overview") })

	for _, p := range []string{"/api/health", "/api/overview"} {
		r.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, p, nil))
	}
	if got := len(log.Recent(16)); got != 2 {
		t.Fatalf("两条请求都应留下访问日志，实际 %d 条——日志里还有按路径跳过的规则", got)
	}
}
