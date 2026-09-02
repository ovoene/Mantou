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

// panelEngineWithWeb 取 New 真正构建出来的那套引擎，并给它一个假的前端 FS。
// 文件名刻意照着 Vite 的产物形状：带内容哈希的进 assets/，不带哈希的留在根上。
func panelEngineWithWeb(t *testing.T, extra map[string][]byte) (*Server, *gin.Engine) {
	t.Helper()
	web := fstest.MapFS{
		"index.html":                &fstest.MapFile{Data: []byte("<html><head></head><body>mantou</body></html>")},
		"assets/index-CzWb1vaS.js":  &fstest.MapFile{Data: []byte(strings.Repeat("console.log('mantou');\n", 200))},
		"assets/index-VdriqJxg.css": &fstest.MapFile{Data: []byte(strings.Repeat(".mantou{color:#333}\n", 200))},
		"favicon.ico":               &fstest.MapFile{Data: []byte("\x00\x00\x01\x00icon-bytes")},
	}
	for name, data := range extra {
		web[name] = &fstest.MapFile{Data: data}
	}
	manager := config.NewManager(filepath.Join(t.TempDir(), "config.json"))
	if err := manager.Load(); err != nil {
		t.Fatal(err)
	}
	firewallOff(t, manager)
	s := New(Deps{Config: manager, Log: logx.New(logx.Options{}), WebFS: web})
	engine, ok := s.http.Handler.(*gin.Engine)
	if !ok {
		t.Fatalf("面板 Handler 不是 *gin.Engine，而是 %T", s.http.Handler)
	}
	return s, engine
}

// 内容哈希命名的资源要拿到一年的强缓存 + immutable，还要有 ETag。
// 三个校验符原来一个都没有（审计四 4-A）：Cache-Control 与 ETag 没人设，
// Last-Modified 则是嵌入 FS 的 ModTime() 返回零值、ServeContent 直接跳过。
func TestHashedAssetsGetImmutableCacheHeaders(t *testing.T) {
	_, engine := panelEngineWithWeb(t, nil)

	req := httptest.NewRequest(http.MethodGet, "/assets/index-CzWb1vaS.js", nil)
	rec := httptest.NewRecorder()
	engine.ServeHTTP(rec, req)
	res := rec.Result()

	if res.StatusCode != http.StatusOK {
		t.Fatalf("取资源应当 200，实际 %d", res.StatusCode)
	}
	if got := res.Header.Get("Cache-Control"); got != immutableCacheControl {
		t.Errorf("内容哈希命名的资源应当强缓存，实际 Cache-Control=%q", got)
	}
	if got := res.Header.Get("ETag"); got == "" {
		t.Error("必须给出 ETag，否则强制刷新时只能整份重传")
	} else if !strings.HasPrefix(got, `"`) || !strings.HasSuffix(got, `"`) {
		t.Errorf("ETag 必须是带引号的强校验符，实际 %q", got)
	}
	if got := res.Header.Get("Vary"); !strings.Contains(got, "Accept-Encoding") {
		t.Errorf("按 Accept-Encoding 分键，实际 Vary=%q", got)
	}
	if rec.Body.Len() == 0 {
		t.Error("首次请求应当返回文件内容")
	}
}

// 带上 ETag 再来一次要换回 304：只有响应头，没有响应体。
// 这条是整条修复的实际收益所在——原来这条路径根本不存在。
func TestAssetConditionalRequestReturnsNotModified(t *testing.T) {
	_, engine := panelEngineWithWeb(t, nil)

	const path = "/assets/index-VdriqJxg.css"
	first := httptest.NewRecorder()
	engine.ServeHTTP(first, httptest.NewRequest(http.MethodGet, path, nil))
	tag := first.Result().Header.Get("ETag")
	if tag == "" {
		t.Fatal("测试前提不成立：首次响应没有 ETag")
	}

	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.Header.Set("If-None-Match", tag)
	rec := httptest.NewRecorder()
	engine.ServeHTTP(rec, req)
	res := rec.Result()

	if res.StatusCode != http.StatusNotModified {
		t.Fatalf("校验符一致应当回 304，实际 %d", res.StatusCode)
	}
	if rec.Body.Len() != 0 {
		t.Errorf("304 不许带响应体，实际 %d 字节", rec.Body.Len())
	}
	if got := res.Header.Get("Cache-Control"); got != immutableCacheControl {
		t.Errorf("304 也要带上缓存策略，实际 %q", got)
	}
	// 304 按规范要带上 200 时会给的 Vary。压缩中间件在这条路上不执行（非 200 不压），
	// 所以它只能来自资源处理器本身。
	if got := res.Header.Get("Vary"); !strings.Contains(got, "Accept-Encoding") {
		t.Errorf("304 也要带 Vary: Accept-Encoding，实际 %q", got)
	}
}

// 校验符不一致时必须回完整内容，否则改了版本的浏览器会一直拿旧文件。
func TestAssetStaleETagGetsFullBody(t *testing.T) {
	_, engine := panelEngineWithWeb(t, nil)

	req := httptest.NewRequest(http.MethodGet, "/assets/index-VdriqJxg.css", nil)
	req.Header.Set("If-None-Match", `"this-is-not-the-current-hash"`)
	rec := httptest.NewRecorder()
	engine.ServeHTTP(rec, req)

	if rec.Result().StatusCode != http.StatusOK {
		t.Fatalf("校验符不一致应当回 200，实际 %d", rec.Result().StatusCode)
	}
	if rec.Body.Len() == 0 {
		t.Error("校验符不一致时必须回完整内容")
	}
}

// 不带内容哈希的文件（favicon 等）只能"每次校验"，不能一年强缓存：
// 换过的图标会被钉住一年，而这类文件改了名字不变，浏览器无从知晓。
func TestUnhashedAssetRevalidates(t *testing.T) {
	_, engine := panelEngineWithWeb(t, nil)

	rec := httptest.NewRecorder()
	engine.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/favicon.ico", nil))
	res := rec.Result()

	if res.StatusCode != http.StatusOK {
		t.Fatalf("取 favicon 应当 200，实际 %d", res.StatusCode)
	}
	if got := res.Header.Get("Cache-Control"); got != revalidateCacheControl {
		t.Errorf("没有内容哈希的文件不能强缓存，实际 Cache-Control=%q", got)
	}
	if strings.Contains(res.Header.Get("Cache-Control"), "immutable") {
		t.Error("没有内容哈希的文件绝不能标 immutable")
	}
	if res.Header.Get("ETag") == "" {
		t.Error("这类文件全靠 ETag 换 304，必须有校验符")
	}
}

// 入口页必须保持 no-store，且不能有 ETag——它按当前访问前缀动态注入基址变量，
// 任何形式的复用都会让前端拿着旧基址继续发 API 请求。
func TestIndexPageStaysNoStore(t *testing.T) {
	for _, path := range []string{"/", "/index.html", "/some/spa/route"} {
		_, engine := panelEngineWithWeb(t, nil)
		rec := httptest.NewRecorder()
		engine.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		res := rec.Result()

		if got := res.Header.Get("Cache-Control"); got != "no-store" {
			t.Errorf("%s：入口页必须 no-store，实际 %q", path, got)
		}
		if got := res.Header.Get("ETag"); got != "" {
			t.Errorf("%s：入口页不该有 ETag（内容随访问前缀变），实际 %q", path, got)
		}
	}
}

// buildAssetETags 必须给每个文件一个各不相同的校验符。
// 若哪天写成了常量或按文件名而非内容算，所有资源会共用一个 ETag——
// 那时改了内容的文件也会被判成"没变"，浏览器一直用旧的，比没有 ETag 更糟。
func TestBuildAssetETagsAreContentDerived(t *testing.T) {
	same := []byte("identical content")
	fsys := fstest.MapFS{
		"a.js":        &fstest.MapFile{Data: []byte("alpha")},
		"b.js":        &fstest.MapFile{Data: []byte("beta")},
		"dir/c.js":    &fstest.MapFile{Data: []byte("gamma")},
		"dup1.js":     &fstest.MapFile{Data: same},
		"dir/dup2.js": &fstest.MapFile{Data: same},
	}
	tags := buildAssetETags(fsys)

	if len(tags) != len(fsys) {
		t.Fatalf("每个文件都该有校验符：%d 个文件算出 %d 个", len(fsys), len(tags))
	}
	distinct := map[string]string{}
	for name := range fsys {
		tag := tags[name]
		if tag == "" {
			t.Errorf("%s 没有校验符", name)
			continue
		}
		if prev, ok := distinct[tag]; ok {
			// 内容相同的两个文件共用校验符是对的（ETag 标识的是内容，不是路径）；
			// 内容不同还撞在一起才是错的。
			if string(fsys[name].Data) != string(fsys[prev].Data) {
				t.Errorf("内容不同的 %s 与 %s 撞了同一个校验符 %s", name, prev, tag)
			}
			continue
		}
		distinct[tag] = name
	}
	// 三份不同内容 + 一份重复内容 = 4 个不同的校验符。
	if len(distinct) != 4 {
		t.Errorf("应当有 4 个不同的校验符，实际 %d 个", len(distinct))
	}
	if got := buildAssetETags(nil); got != nil {
		t.Errorf("没有前端 FS 时应当返回 nil，实际 %v", got)
	}
}

// Vary 只能有一份。资源处理器为了让 304 也带上它会先自己设好，
// 压缩中间件那边若无条件 Add，同一个响应上就会出现两个 Vary 头。
func TestAssetVaryHeaderNotDuplicated(t *testing.T) {
	_, engine := panelEngineWithWeb(t, nil)

	req := httptest.NewRequest(http.MethodGet, "/assets/index-CzWb1vaS.js", nil)
	req.Header.Set("Accept-Encoding", "gzip") // 走压缩分支，两处都会碰 Vary
	rec := httptest.NewRecorder()
	engine.ServeHTTP(rec, req)
	res := rec.Result()

	if got := res.Header.Get("Content-Encoding"); got != "gzip" {
		t.Fatalf("测试前提不成立：这个响应没走压缩分支（Content-Encoding=%q）", got)
	}
	if vals := res.Header.Values("Vary"); len(vals) != 1 {
		t.Errorf("Vary 应当只有一份，实际 %d 份：%q", len(vals), vals)
	}
}

// 带访问路径前缀部署时，缓存头同样要生效——剥前缀之后的相对路径才是查校验符的键。
func TestAssetCacheHeadersUnderBasePath(t *testing.T) {
	manager := config.NewManager(filepath.Join(t.TempDir(), "config.json"))
	if err := manager.Load(); err != nil {
		t.Fatal(err)
	}
	if err := manager.Update(func(cfg *config.Config) { cfg.Panel.BasePath = "/mymantou" }); err != nil {
		t.Fatal(err)
	}
	firewallOff(t, manager)
	web := fstest.MapFS{
		"index.html":               &fstest.MapFile{Data: []byte("<html><head></head><body></body></html>")},
		"assets/index-CzWb1vaS.js": &fstest.MapFile{Data: []byte("console.log(1)")},
	}
	s := New(Deps{Config: manager, Log: logx.New(logx.Options{}), WebFS: web})
	engine := s.http.Handler.(*gin.Engine)

	rec := httptest.NewRecorder()
	engine.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/mymantou/assets/index-CzWb1vaS.js", nil))
	res := rec.Result()

	if res.StatusCode != http.StatusOK {
		t.Fatalf("子路径下取资源应当 200，实际 %d", res.StatusCode)
	}
	if got := res.Header.Get("Cache-Control"); got != immutableCacheControl {
		t.Errorf("子路径下也要强缓存，实际 %q", got)
	}
	if got := res.Header.Get("ETag"); got != s.assetETags["assets/index-CzWb1vaS.js"] {
		t.Errorf("校验符该按剥掉前缀后的相对路径查，实际 %q", got)
	}
}
