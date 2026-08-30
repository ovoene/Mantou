package webservice

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"mantou/internal/config"
	"mantou/internal/logx"
)

// 本文件钉住静态站点这一层的四件事，都是审计翻出来的实际问题：
//   - 路径穿越不再能当"这个绝对路径在宿主机上存不存在"的探针；
//   - 目录默认不列清单；
//   - 点开头的文件默认不发，.well-known 例外；
//   - 配置里那个 Index 文件名真正生效。
//
// 前两条原先的成因都在同一处：请求被整个交给 http.FileServer，SPA 回退那步则是
// os.Stat(root + r.URL.Path)。

const outsideSecret = "站点之外的文件内容"

// siteTree 造一棵静态站点目录树，返回站点根。上一级放一个真实存在的文件，
// 供穿越测试有真实目标可打——没有目标的话，"穿越被挡住了"根本测不出来。
//
//	base/outside.txt     ← 穿越目标，确实存在
//	base/site/           ← 站点根
//	     index.html
//	     hello.txt
//	     main.html       ← 自定义 Index 用
//	     sub/inner.txt
//	     .git/config
//	     .well-known/probe.txt
func siteTree(t *testing.T) string {
	t.Helper()
	base := t.TempDir()
	root := filepath.Join(base, "site")
	write := func(rel, body string) {
		p := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(base, "outside.txt"), []byte(outsideSecret), 0o600); err != nil {
		t.Fatal(err)
	}
	write("index.html", "<html>index</html>")
	write("hello.txt", "hello, 馒头")
	write("main.html", "<html>main</html>")
	write("sub/inner.txt", "inner")
	write(".git/config", "[core]\n\turl = "+outsideSecret)
	write(".well-known/probe.txt", "well-known probe")
	return root
}

// siteHandler 只取文件服务这一层（不含压缩与统一错误页），测的差别才只可能来自这一层。
func siteHandler(root string, st config.WebStatic) http.Handler {
	st.Root = root
	return staticHandler(config.WebChild{ID: "ch-static", Type: "static", Static: st})
}

func getPath(h http.Handler, target string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, target, nil))
	return rec
}

// 穿越请求不许透出"目标存不存在"。
//
// 原先：SPA 站上 /../outside.txt（存在）走 fs 得 404，/../nope（不存在）走
// http.ServeFile 得 400，两者一比就知道那个绝对路径在宿主机上有没有东西。
// 现在两者必须完全同一个出口。
func TestStaticTraversalGivesNoExistenceOracle(t *testing.T) {
	root := siteTree(t)
	for _, spa := range []bool{false, true} {
		name := "SPA 回退关"
		if spa {
			name = "SPA 回退开"
		}
		t.Run(name, func(t *testing.T) {
			h := siteHandler(root, config.WebStatic{Index: "index.html", SPAFallback: spa})
			var first *httptest.ResponseRecorder
			for _, target := range []string{
				"/../outside.txt",       // 存在
				"/../nope-not-here.txt", // 不存在
				"/%2e%2e/outside.txt",
				"/..%2foutside.txt",
				"/sub/../../outside.txt",
				"/....//outside.txt",
				"/..\\outside.txt",
			} {
				rec := getPath(h, target)
				if strings.Contains(rec.Body.String(), outsideSecret) {
					t.Fatalf("%s 把站点外的文件内容发出去了", target)
				}
				if rec.Code >= 200 && rec.Code < 300 && !spa {
					t.Errorf("%s 返回了 %d——非 SPA 站上穿越只能是 404", target, rec.Code)
				}
				if first == nil {
					first = rec
					continue
				}
				// 存在与不存在必须同码。差一个码就是一次可用的探测。
				if rec.Code != first.Code {
					t.Errorf("%s 返回 %d，而第一条返回 %d——状态码泄露了目标存不存在",
						target, rec.Code, first.Code)
				}
			}
		})
	}
}

// 目录默认不列清单。SPA 开关两种都测：关时应当 404，开时回首页，
// 两种情况下都不许出现目录里的文件名。
func TestStaticDirectoryListingOffByDefault(t *testing.T) {
	root := siteTree(t)
	for _, spa := range []bool{false, true} {
		h := siteHandler(root, config.WebStatic{Index: "index.html", SPAFallback: spa})
		rec := getPath(h, "/sub/")
		if strings.Contains(rec.Body.String(), "inner.txt") {
			t.Errorf("SPAFallback=%v：/sub/ 列出了目录内容", spa)
		}
		if !spa && rec.Code != http.StatusNotFound {
			t.Errorf("SPAFallback=false：/sub/ 应当 404，实际 %d", rec.Code)
		}
		if spa && rec.Code != http.StatusOK {
			t.Errorf("SPAFallback=true：/sub/ 应当回首页（200），实际 %d", rec.Code)
		}
	}
}

// 开了「目录列表」才列。这条测的是那个开关真的接上了——只测"默认不列"的话，
// 把 lister 那一段整个删掉测试照样通过。
func TestStaticDirectoryListingOptIn(t *testing.T) {
	root := siteTree(t)
	h := siteHandler(root, config.WebStatic{Index: "index.html", DirList: true})
	rec := getPath(h, "/sub/")
	if rec.Code != http.StatusOK {
		t.Fatalf("开了目录列表后 /sub/ 应当 200，实际 %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "inner.txt") {
		t.Errorf("响应里没有 inner.txt，目录列表没生效：%s", rec.Body.String())
	}
}

// 点开头的文件不发，.well-known 例外。静态根常常就是一个项目目录，
// .git/config 与 .env 都在里面。
func TestStaticHidesDotfiles(t *testing.T) {
	root := siteTree(t)
	// 连目录列表一起开：即便开了列表，点开头的东西也不该露出来。
	h := siteHandler(root, config.WebStatic{Index: "index.html", DirList: true})

	for _, target := range []string{"/.git/config", "/.git/", "/.git"} {
		rec := getPath(h, target)
		if rec.Code >= 200 && rec.Code < 300 {
			t.Errorf("%s 返回了 %d：点开头的路径不该有正常响应", target, rec.Code)
		}
		if strings.Contains(rec.Body.String(), outsideSecret) {
			t.Errorf("%s 把 .git/config 的内容发出去了", target)
		}
	}
	rec := getPath(h, "/.well-known/probe.txt")
	if rec.Code != http.StatusOK {
		t.Fatalf(".well-known 下的文件应当正常可取，实际 %d", rec.Code)
	}
	if got := rec.Body.String(); got != "well-known probe" {
		t.Errorf(".well-known 文件内容不对：%q", got)
	}
}

// 配置里的 Index 文件名要真正生效。http.FileServer 只认死了的 index.html，
// 所以原先填 main.html 是不起作用的（同目录还有 index.html 时更看不出来）。
func TestStaticCustomIndexIsUsed(t *testing.T) {
	root := siteTree(t)
	h := siteHandler(root, config.WebStatic{Index: "main.html"})
	rec := getPath(h, "/")
	if rec.Code != http.StatusOK {
		t.Fatalf("根路径应当 200，实际 %d", rec.Code)
	}
	if got := rec.Body.String(); !strings.Contains(got, "main") {
		t.Errorf("根路径没回 main.html：%q", got)
	}
}

// 目录少了尾斜杠仍要跳一次，否则页面内的相对链接会少拼一层。
func TestStaticDirectoryRedirectsToSlash(t *testing.T) {
	root := siteTree(t)
	h := siteHandler(root, config.WebStatic{Index: "index.html", SPAFallback: true})
	rec := getPath(h, "/sub?a=1")
	if rec.Code != http.StatusMovedPermanently {
		t.Fatalf("/sub 应当 301，实际 %d", rec.Code)
	}
	if got := rec.Header().Get("Location"); got != "/sub/?a=1" {
		t.Errorf("Location 应为 /sub/?a=1，实际 %q", got)
	}
}

// 正常访问一个字节不变，Range 也还能用（改成自己开文件 + ServeContent 之后
// 这两件事都由本函数盯着）。
func TestStaticServesFileUnchanged(t *testing.T) {
	root := siteTree(t)
	h := siteHandler(root, config.WebStatic{Index: "index.html", SPAFallback: true})

	rec := getPath(h, "/hello.txt")
	if rec.Code != http.StatusOK {
		t.Fatalf("/hello.txt 应当 200，实际 %d", rec.Code)
	}
	if got := rec.Body.String(); got != "hello, 馒头" {
		t.Errorf("文件内容不一致：%q", got)
	}

	req := httptest.NewRequest(http.MethodGet, "/hello.txt", nil)
	req.Header.Set("Range", "bytes=0-4")
	part := httptest.NewRecorder()
	h.ServeHTTP(part, req)
	if part.Code != http.StatusPartialContent {
		t.Errorf("Range 请求应当 206，实际 %d", part.Code)
	}
	if got := part.Body.String(); got != "hello" {
		t.Errorf("Range 取到的内容不对：%q", got)
	}

	// SPA 回退仍然管用：不存在的前端路由回首页而不是 404。
	spa := getPath(h, "/some/frontend/route")
	if spa.Code != http.StatusOK || !strings.Contains(spa.Body.String(), "index") {
		t.Errorf("SPA 回退失效：%d %q", spa.Code, spa.Body.String())
	}
}

// 保存期校验之外还有一道防御性校验（配置文件被手改、旧配置迁移进来）：
// 根目录是系统根时该子项对访客一律 500，不提供文件。
// Windows 那几种写法一并测：filepath.Clean("/") 在那里是 `\`，只和 "/" 比等于这道闸没生效。
func TestStaticRejectsSystemRoot(t *testing.T) {
	roots := []string{"", "   ", "/", ".", "..", "/data", "/data/certs"}
	if runtime.GOOS == "windows" {
		roots = append(roots, `C:\`, "C:", `\`, `\data`)
	}
	for _, root := range roots {
		h := staticHandler(config.WebChild{ID: "ch", Type: "static",
			Static: config.WebStatic{Root: root, Index: "index.html", SPAFallback: true}})
		rec := getPath(h, "/hello.txt")
		if rec.Code != http.StatusInternalServerError {
			t.Errorf("root=%q 应当 500，实际 %d", root, rec.Code)
		}
	}
}

// 上游代理声明的协议默认不采信。X-Forwarded-Proto 与 CF-Visitor 任何客户端都能自己填，
// 无条件采信等于让请求方自己决定「强制 HTTPS」要不要生效——填一个头就免于跳转了。
func TestForwardedProtoNotTrustedByDefault(t *testing.T) {
	for _, hdr := range []struct{ name, value string }{
		{"X-Forwarded-Proto", "https"},
		{"X-Forwarded-Proto", "https, http"},
		{"CF-Visitor", `{"scheme":"https"}`},
	} {
		for _, trust := range []bool{false, true} {
			ch := config.WebChild{ID: "ch", RedirectHTTPS: true, HSTS: true, TrustProxyHeaders: trust}
			h := withSecurityHeaders(ch, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			}))
			req := httptest.NewRequest(http.MethodGet, "http://site.example.com/x", nil)
			req.Header.Set(hdr.name, hdr.value)
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)

			if !trust {
				if rec.Code != http.StatusTemporaryRedirect {
					t.Errorf("%s: %s 不采信时仍应跳转，实际 %d", hdr.name, hdr.value, rec.Code)
				}
				if got := rec.Header().Get("Strict-Transport-Security"); got != "" {
					t.Errorf("%s: 不采信时不该发 HSTS，实际 %q", hdr.name, got)
				}
				continue
			}
			if rec.Code != http.StatusOK {
				t.Errorf("%s: 采信时应视为已是 HTTPS 而放行，实际 %d", hdr.name, rec.Code)
			}
			if got := rec.Header().Get("Strict-Transport-Security"); got == "" {
				t.Error("采信时应当发 HSTS")
			}
		}
	}
}

// 白名单只能往关的方向失败：解不出对端 IP 时按"不在名单里"处理。
// 原先那段是 if ip != nil { ...检查... }，于是一个畸形的 RemoteAddr
// （Unix 域套接字、被中间层改写过的地址）就等于把整份白名单绕过去了。
func TestIPAllowListFailsClosed(t *testing.T) {
	m := New(logx.New(logx.Options{}))
	ch := config.WebChild{ID: "ch", Access: config.WebAccess{
		IPFilter: true, IPFilterMode: "allow", AllowIPs: []string{"203.0.113.0/24"},
	}}
	h := withIPFilter(m, "站点", ch, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	for _, tc := range []struct {
		remote string
		want   int
	}{
		{remote: "203.0.113.7:5000", want: http.StatusOK},         // 在白名单里
		{remote: "198.51.100.7:5000", want: http.StatusForbidden}, // 不在白名单里
		{remote: "", want: http.StatusForbidden},                  // 解不出 IP
		{remote: "@", want: http.StatusForbidden},                 // Unix 域套接字
		{remote: "not-an-address", want: http.StatusForbidden},
	} {
		req := httptest.NewRequest(http.MethodGet, "/x", nil)
		req.RemoteAddr = tc.remote
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != tc.want {
			t.Errorf("RemoteAddr=%q 期望 %d，实际 %d", tc.remote, tc.want, rec.Code)
		}
	}
}
