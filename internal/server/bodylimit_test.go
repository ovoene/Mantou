package server

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"mantou/internal/config"
	"mantou/internal/logx"
)

// panelEngine 取 New 真正构建出来的那套中间件与路由（而不是测试里临时拼的），
// 这样"上限有没有接上"与"路由是不是那条路由"一起被验证。
func panelEngine(t *testing.T, basePath string) (*Server, *gin.Engine) {
	t.Helper()
	manager := config.NewManager(filepath.Join(t.TempDir(), "config.json"))
	if err := manager.Load(); err != nil {
		t.Fatal(err)
	}
	if basePath != "" {
		if err := manager.Update(func(cfg *config.Config) { cfg.Panel.BasePath = basePath }); err != nil {
			t.Fatal(err)
		}
	}
	s := New(Deps{Config: manager, Log: logx.New(logx.Options{})})
	engine, ok := s.http.Handler.(*gin.Engine)
	if !ok {
		t.Fatalf("面板 Handler 不是 *gin.Engine，而是 %T", s.http.Handler)
	}
	return s, engine
}

// 未鉴权就能到达的接口也必须受上限约束——这是这条修复的全部意义。
//
// 用"格式完全正确、只是很大"的请求体来验：没有上限时它会被完整解析，登录逻辑照常往下走
// （未初始化的面板回 409）；有上限时读到一半就断，绑定失败回 400。
// 若换成一段坏 JSON，两种情况都是 400，测试就成了空跑。
func TestRequestBodyLimitRejectsOversizedLogin(t *testing.T) {
	for _, basePath := range []string{"", "/mymantou"} {
		_, engine := panelEngine(t, basePath)
		body := `{"username":"` + strings.Repeat("a", panelBodyLimit) + `","password":"x"}`

		req := httptest.NewRequest(http.MethodPost, basePath+"/api/auth/login", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		engine.ServeHTTP(rec, req)

		if rec.Code != http.StatusBadRequest {
			t.Fatalf("basePath=%q：超限的登录请求 = %d，期望 400（请求体应当读不完）：%s",
				basePath, rec.Code, rec.Body.String())
		}

		// 正常大小的同一条请求必须照旧走完（上限不能把常规请求一起挡住）。
		req = httptest.NewRequest(http.MethodPost, basePath+"/api/auth/login",
			strings.NewReader(`{"username":"admin","password":"x"}`))
		req.Header.Set("Content-Type", "application/json")
		rec = httptest.NewRecorder()
		engine.ServeHTTP(rec, req)
		if rec.Code == http.StatusBadRequest {
			t.Fatalf("basePath=%q：正常大小的登录请求也被拦了：%s", basePath, rec.Body.String())
		}
	}
}

// 上传型路由必须走 registerUpload 登记上限，且登记的值不能小于处理器自己的文件上限。
//
// 这张表是照抄的，所以它要防的正是"照抄之后各自漂移"：
// 谁把 registerUpload 换回 authed.POST，或者改了路径、改了文件上限却没动这里，都会失败。
func TestUploadRoutesRegisterTheirOwnBodyLimit(t *testing.T) {
	for _, basePath := range []string{"", "/mymantou"} {
		s, engine := panelEngine(t, basePath)
		want := map[string]int64{
			basePath + "/api/settings/background": maxBackgroundImageBytes + bodyLimitSlack,
			basePath + "/api/settings/import":     maxBackupFileSize + bodyLimitSlack,
			basePath + "/api/meta/self-update":    maxUpdatePackageBytes + maxUpdateSignatureBytes + bodyLimitSlack,
		}
		if len(s.bodyLimits) != len(want) {
			t.Fatalf("basePath=%q：登记了 %d 条上传路由上限，期望 %d 条：%v",
				basePath, len(s.bodyLimits), len(want), s.bodyLimits)
		}
		registered := make(map[string]bool)
		for _, r := range engine.Routes() {
			if r.Method == http.MethodPost {
				registered[r.Path] = true
			}
		}
		for path, limit := range want {
			got, ok := s.bodyLimits[path]
			if !ok {
				t.Fatalf("basePath=%q：%s 没有登记请求体上限，它会退回默认的 %d 字节，"+
					"上传超过这个体积的文件会失败。请用 registerUpload 注册这条路由。",
					basePath, path, panelBodyLimit)
			}
			if got != limit {
				t.Fatalf("basePath=%q：%s 的上限 = %d，期望 %d", basePath, path, got, limit)
			}
			if got <= panelBodyLimit {
				t.Fatalf("basePath=%q：%s 的上限 %d 不比默认值大，登记它就没有意义", basePath, path, got)
			}
			if !registered[path] {
				t.Fatalf("basePath=%q：登记了 %s 的上限，但这条 POST 路由不存在（路径写错或已改名）",
					basePath, path)
			}
		}
	}
}

// 中间件本身：默认按 panelBodyLimit 截断，登记过的路由按自己的上限。
// 不经过鉴权，所以能直接读到"到底收下了多少字节"。
func TestLimitRequestBodyAppliesPerRoute(t *testing.T) {
	const big = 3 << 20
	s := &Server{bodyLimits: map[string]int64{"/large": big}}
	r := gin.New()
	r.Use(s.limitRequestBody())
	read := func(c *gin.Context) {
		n, err := io.Copy(io.Discard, c.Request.Body)
		if err != nil {
			c.String(http.StatusRequestEntityTooLarge, "%d", n)
			return
		}
		c.String(http.StatusOK, "%d", n)
	}
	r.POST("/normal", read)
	r.POST("/large", read)

	payload := bytes.Repeat([]byte("x"), 2<<20)

	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/normal", bytes.NewReader(payload)))
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("默认路由读 2 MiB 应当失败，得到 %d（已读 %s 字节）", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/large", bytes.NewReader(payload)))
	if rec.Code != http.StatusOK || rec.Body.String() != "2097152" {
		t.Fatalf("登记了 %d 字节上限的路由应当收下整个 2 MiB，得到 %d / %s 字节",
			big, rec.Code, rec.Body.String())
	}
}

// 处理器自己那几个上限必须都待在入口上限**以下**（2.14-B）。
//
// 入口的 http.MaxBytesReader 在 ShouldBindJSON 之前就把请求体截住了，所以处理器里
// 那几句「样本载荷过大，请截取其中一段」「模板内容过长」只有在对应的字段上限
// 小于入口上限时才说得出来。一旦谁把 dryRunBodyLimit 调到 panelBodyLimit 以上，
// 超出的那一段会先被中间件掐掉，用户看到的变成笼统的「请求参数无效」——
// 提示还在代码里，只是再也走不到，而这种失效没有任何报错会提醒。
//
// 模板预览那条路上 Sample、Body、Title 是同一份 JSON 里的三个字段，所以看的是它们的**和**。
func TestHandlerLimitsFitInsideEntryLimit(t *testing.T) {
	if dryRunBodyLimit >= panelBodyLimit {
		t.Fatalf("样本载荷上限 %d 不小于入口上限 %d，「样本载荷过大」这句提示已走不到",
			dryRunBodyLimit, panelBodyLimit)
	}
	if previewTemplateLimit >= panelBodyLimit {
		t.Fatalf("模板草稿上限 %d 不小于入口上限 %d，「模板内容过长」这句提示已走不到",
			previewTemplateLimit, panelBodyLimit)
	}
	// 预览请求同时带着样本与模板草稿，两者之和也得装得下，
	// 否则一个正好卡在各自上限的请求会被入口先拒掉。
	if dryRunBodyLimit+previewTemplateLimit >= panelBodyLimit {
		t.Fatalf("样本 %d + 模板 %d 不小于入口上限 %d，两者都填满的预览请求进不来",
			dryRunBodyLimit, previewTemplateLimit, panelBodyLimit)
	}
}
