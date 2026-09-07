package server

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/gin-gonic/gin"

	"mantou/internal/config"
	"mantou/internal/logx"
)

// 本文件盯的是「入口页发出去之后，浏览器会去哪里取资源」这一件事。
//
// 前端产物里的资源引用是相对路径（./assets/xxx.js，Vite 的 base:'./' 决定的），
// 没有 <base> 时浏览器按当前地址所在目录解析它们。访问 /a/b/c 这类多段未知路径时，
// 前端路由的兜底最终会改道到 /overview，但那份 HTML 是在改道之前就发出去的，于是
// 浏览器先去取 /a/b/assets/xxx.js —— 而那条路径既命中不了文件、又被单页应用兜底
// 回了一份 index.html。浏览器拿 HTML 当模块脚本解析，表现是整页空白、控制台只有
// 一句 MIME 报错，看不出因果。
//
// 两道修复各自独立，都要钉住：
//   - 入口页始终带 <base>（根路径下是 href="/"），资源引用与地址层级彻底脱钩；
//   - 取不到的**资源**回 404，不再回 index.html —— 否则连报错都指不到真正的原因上。

// webFSWithBasePath 造一台带前端 FS 的面板，并指定访问路径前缀（空串即根路径）。
func webFSWithBasePath(t *testing.T, basePath string) (*Server, *gin.Engine) {
	t.Helper()
	web := fstest.MapFS{
		"index.html":                &fstest.MapFile{Data: []byte("<html><head></head><body>mantou</body></html>")},
		"assets/index-CzWb1vaS.js":  &fstest.MapFile{Data: []byte("console.log('mantou')")},
		"assets/index-VdriqJxg.css": &fstest.MapFile{Data: []byte(".mantou{color:#333}")},
		"favicon.ico":               &fstest.MapFile{Data: []byte("\x00\x00\x01\x00icon")},
	}
	manager := config.NewManager(filepath.Join(t.TempDir(), "config.json"))
	if err := manager.Load(); err != nil {
		t.Fatal(err)
	}
	if basePath != "" {
		if err := manager.Update(func(cfg *config.Config) { cfg.Panel.BasePath = basePath }); err != nil {
			t.Fatal(err)
		}
	}
	firewallOff(t, manager)
	s := New(Deps{Config: manager, Log: logx.New(logx.Options{}), WebFS: web})
	engine, ok := s.http.Handler.(*gin.Engine)
	if !ok {
		t.Fatalf("面板 Handler 不是 *gin.Engine，而是 %T", s.http.Handler)
	}
	return s, engine
}

func fetch(engine *gin.Engine, path string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	engine.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	return rec
}

// 入口页在**任何**部署方式下都要带 <base>：根路径下也不能省。
// 省掉它，多段路径下的资源引用就会跟着地址一起漂走。
func TestIndexAlwaysCarriesBaseTag(t *testing.T) {
	cases := []struct {
		basePath string
		want     string
	}{
		{basePath: "", want: `<base href="/">`},
		{basePath: "/mymantou", want: `<base href="/mymantou/">`},
		{basePath: "/a/b", want: `<base href="/a/b/">`},
	}
	for _, c := range cases {
		_, engine := webFSWithBasePath(t, c.basePath)
		rec := fetch(engine, c.basePath+"/")
		if rec.Code != http.StatusOK {
			t.Fatalf("basePath=%q：取入口页应当 200，实际 %d", c.basePath, rec.Code)
		}
		if !strings.Contains(rec.Body.String(), c.want) {
			t.Errorf("basePath=%q：入口页里没有 %s\n实际内容：%s", c.basePath, c.want, rec.Body.String())
		}
		// <base> 必须在 <head> 里、且在任何资源引用之前才有效。这份假 index.html
		// 里没有资源引用，所以只验它落在 <head> 之后。
		if idx := strings.Index(rec.Body.String(), c.want); idx >= 0 {
			if head := strings.Index(rec.Body.String(), "<head>"); head < 0 || idx < head {
				t.Errorf("basePath=%q：<base> 没落在 <head> 里面", c.basePath)
			}
		}
	}
}

// 多段未知路径仍然交回单页应用（由它自己的兜底路由改道），并且这份 HTML 里
// 带着写死的 <base> —— 这才是「不再白屏」的原因。
func TestDeepUnknownRouteGetsIndexWithRootBase(t *testing.T) {
	_, engine := webFSWithBasePath(t, "")
	for _, path := range []string{"/nope", "/definitely-not-a-route/deep/path"} {
		rec := fetch(engine, path)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s：像前端路由的路径应当回入口页（200），实际 %d", path, rec.Code)
		}
		if !strings.Contains(rec.Body.String(), `<base href="/">`) {
			t.Errorf("%s：回的入口页没带 <base href=\"/\">，浏览器会按当前地址去取资源", path)
		}
		if got := rec.Result().Header.Get("Cache-Control"); got != "no-store" {
			t.Errorf("%s：入口页必须 no-store，实际 %q", path, got)
		}
	}
}

// 取不到的资源要回 404，绝不能回一份 index.html。
//
// 这一条是上面那个白屏故障的第二道防线：即使 <base> 哪天又丢了，
// 浏览器至少会拿到一个 404 —— 报错直接指向「这个文件不存在」，
// 而不是让人对着一句 MIME 报错猜半天。旧版页面被缓存住、指向已改名的 chunk 时同理。
func TestMissingAssetGets404NotIndex(t *testing.T) {
	_, engine := webFSWithBasePath(t, "")
	for _, path := range []string{
		// 名字换掉了的 chunk（旧页面被缓存住时就会取这个）
		"/assets/index-DoesNotExist.js",
		// 按错误的基址去取一个真实存在的资源
		"/definitely-not-a-route/deep/assets/index-CzWb1vaS.js",
		"/nope/favicon.ico",
		"/robots.txt",
	} {
		rec := fetch(engine, path)
		if rec.Code != http.StatusNotFound {
			t.Errorf("%s：取不到的资源应当回 404，实际 %d", path, rec.Code)
		}
		// 这条 404 不许被缓存：改名过的 chunk 在下一次发布后就存在了，
		// 缓存住 404 的表现是「已经修好了但用户那边还是白屏」。
		if got := rec.Result().Header.Get("Cache-Control"); got != "no-store" {
			t.Errorf("%s：资源 404 必须 no-store，实际 %q", path, got)
		}
		// 入口页的判据用 <base>：它现在是每一份入口页都有、且只有入口页才有的标记。
		if strings.Contains(rec.Body.String(), "<base href=") {
			t.Errorf("%s：回了一份入口页，浏览器会拿 HTML 当脚本解析", path)
		}
	}
	// 真实存在的资源不受影响。
	for _, path := range []string{"/assets/index-CzWb1vaS.js", "/assets/index-VdriqJxg.css", "/favicon.ico"} {
		if rec := fetch(engine, path); rec.Code != http.StatusOK {
			t.Errorf("%s：真实资源应当 200，实际 %d", path, rec.Code)
		}
	}
}

// 带访问前缀部署时，两条规则都要照样成立。
func TestAssetFallbackUnderBasePath(t *testing.T) {
	_, engine := webFSWithBasePath(t, "/mymantou")

	if rec := fetch(engine, "/mymantou/some/spa/route"); rec.Code != http.StatusOK {
		t.Errorf("前缀内像路由的路径应当回入口页，实际 %d", rec.Code)
	}
	if rec := fetch(engine, "/mymantou/assets/gone-abc.js"); rec.Code != http.StatusNotFound {
		t.Errorf("前缀内取不到的资源应当 404，实际 %d", rec.Code)
	}
	if rec := fetch(engine, "/assets/index-CzWb1vaS.js"); rec.Code != http.StatusNotFound {
		t.Errorf("前缀之外的请求应当 404，实际 %d", rec.Code)
	}
}

// normalizeBasePath 是这段字符串进入 gin 路由组与 <base href> 之前的最后一道关。
// 手改过的配置文件也不能把非法值带进去。
func TestNormalizeBasePathRejectsUnsafe(t *testing.T) {
	cases := []struct{ in, want string }{
		{"", ""},
		{"/", ""},
		{"//", ""},
		{"  ", ""},
		{"/mantou", "/mantou"},
		{"mantou", "/mantou"},   // 补上开头的斜杠
		{"/mantou/", "/mantou"}, // 去掉末尾的斜杠
		{"/a/b/c", "/a/b/c"},    // 多级
		{"/Man-tou_1.0~x", "/Man-tou_1.0~x"},
		// 下面这些必须被打回根路径。
		{`/a"><script>alert(1)</script>`, ""}, // 从 <base href> 属性里逃出去
		{"/a'onload='x", ""},
		{"/../etc", ""},    // 把整页资源引用挪到上一层
		{"/a/../../b", ""}, //
		{"/a//b", ""},      // 空段：前缀失去确定含义
		{"/:id", ""},       // gin 路由组里的通配符语法
		{"/*any", ""},      //
		{"/a b", ""},       // 空格：浏览器会编码，与路由组里的原始字节对不上
		{"/a\tb", ""},      //
		{"/馒头", ""},        // 非 ASCII 同理
		{"/a%2fb", ""},     // 百分号编码同理
		{"/a?x=1", ""},     // 查询串不属于前缀
		{"/a#frag", ""},    //
		{"/a\nb", ""},      // 换行：注入到 HTML 里能起一行新标签
		{"/a\\b", ""},      // 反斜杠：Windows 上会被当成路径分隔符
	}
	for _, c := range cases {
		if got := normalizeBasePath(c.in); got != c.want {
			t.Errorf("normalizeBasePath(%q) = %q，期望 %q", c.in, got, c.want)
		}
	}
}

// 非法的访问前缀要在保存时就被拒（400），而不是靠 normalizeBasePath 悄悄归零——
// 那样界面上显示保存成功、前缀却没生效，用户只会以为是重启没生效。
func TestSettingsRejectsUnsafeBasePath(t *testing.T) {
	for _, bad := range []string{`/a"><script>alert(1)</script>`, "/../etc", "/a//b", "/:id", "/a b", "/馒头"} {
		s, cfg := panelPortEnv(t)
		rec := putSettings(t, s, `{"panel":{"basePath":`+jsonStr(bad)+`}}`)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%q 应被拒，实际 %d：%s", bad, rec.Code, rec.Body.String())
			continue
		}
		if got := cfg.Snapshot().Panel.BasePath; got != "" {
			t.Errorf("%q 被拒了却还是落了盘：%q", bad, got)
		}
	}
	// 合法值照样能存，且存的是规范化之后的形态。
	for _, ok := range []struct{ in, want string }{
		{"/mantou", "/mantou"},
		{"mantou/", "/mantou"},
		{"/a/b", "/a/b"},
		{"", ""},
		{"/", ""},
	} {
		s, cfg := panelPortEnv(t)
		rec := putSettings(t, s, `{"panel":{"basePath":`+jsonStr(ok.in)+`}}`)
		if rec.Code != http.StatusOK {
			t.Errorf("%q 应能保存，实际 %d：%s", ok.in, rec.Code, rec.Body.String())
			continue
		}
		if got := cfg.Snapshot().Panel.BasePath; got != ok.want {
			t.Errorf("%q 存下来是 %q，期望 %q", ok.in, got, ok.want)
		}
	}
}

// looksLikeStaticFile 只看最后一段有没有点。前端路由都是不含点的单段标识符。
func TestLooksLikeStaticFile(t *testing.T) {
	yes := []string{"favicon.ico", "assets/index-abc.js", "a/b/c.css", ".gitkeep", "x/.env"}
	no := []string{"overview", "settings", "some/spa/route", "a.b/c", "", "login"}
	for _, p := range yes {
		if !looksLikeStaticFile(p) {
			t.Errorf("%q 该被判成静态文件", p)
		}
	}
	for _, p := range no {
		if looksLikeStaticFile(p) {
			t.Errorf("%q 不该被判成静态文件", p)
		}
	}
}
