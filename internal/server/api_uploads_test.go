package server

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"mantou/internal/auth"
	"mantou/internal/config"
	"mantou/internal/logx"
)

// /uploads 这条路径原先公开可读。收到登录之后的理由与做法见 registerRoutes 里的注释；
// 本文件钉住四件事，任何一条回退都会被这里拦住：
//   - 未登录取不到文件（此前 200 + 文件内容）；
//   - 目录路径不再回索引页（此前 `GET /uploads/` 匿名列出全部已上传文件名）；
//   - 穿越取不到数据目录里的其它文件；
//   - 已登录时功能不变：内容逐字节一致，且带 nosniff 与 Cache-Control: private。

// uploadsEnv 造一个"已初始化 + 有 data/uploads"的真实面板，返回引擎与一条可直接塞进
// Cookie 头的会话。会话走真实登录接口取得，不手工签令牌——否则中间件里任何一层
// （账户主体比对、服务端会话表）被绕过都测不出来。
func uploadsEnv(t *testing.T, basePath string, files map[string][]byte) (*gin.Engine, string) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	dir := t.TempDir()
	upload := filepath.Join(dir, "uploads")
	if err := os.MkdirAll(upload, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(upload, name), body, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	manager := config.NewManager(filepath.Join(dir, "config.json"))
	if err := manager.Load(); err != nil {
		t.Fatal(err)
	}
	hash, err := auth.HashPassword(testLoginPass)
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.Update(func(cfg *config.Config) {
		cfg.Panel.BasePath = basePath
		cfg.Auth.Initialized = true
		cfg.Auth.Username = testLoginUser
		cfg.Auth.PasswordHash = hash
	}); err != nil {
		t.Fatal(err)
	}
	s := New(Deps{Config: manager, Log: logx.New(logx.Options{}), DataDir: dir})
	engine, ok := s.http.Handler.(*gin.Engine)
	if !ok {
		t.Fatalf("面板 Handler 不是 *gin.Engine，而是 %T", s.http.Handler)
	}
	t.Cleanup(s.sessions.close)
	ck := loginCookie(t, engine, basePath)
	return engine, ck.Name + "=" + ck.Value
}

// 未登录取背景图必须失败。断言反着写：不许 2xx，且响应体里不许出现文件内容。
func TestUploadsRejectAnonymous(t *testing.T) {
	const secret = "mantou-background-bytes"
	for _, basePath := range []string{"", "/mantou"} {
		name := "无前缀"
		if basePath != "" {
			name = "有前缀"
		}
		t.Run(name, func(t *testing.T) {
			engine, _ := uploadsEnv(t, basePath, map[string][]byte{"bg.png": []byte(secret)})

			req := httptest.NewRequest(http.MethodGet, basePath+"/uploads/bg.png", nil)
			rec := httptest.NewRecorder()
			engine.ServeHTTP(rec, req)

			if rec.Code >= 200 && rec.Code < 300 {
				t.Fatalf("未登录取背景图返回了 %d——这条路径又变成匿名可读了", rec.Code)
			}
			if rec.Code != http.StatusUnauthorized {
				t.Errorf("应当是 401（而不是 %d）：这条路径挂的就是 authRequired", rec.Code)
			}
			if strings.Contains(rec.Body.String(), secret) {
				t.Errorf("响应体里出现了文件内容：%s", clipBody(rec.Body.String()))
			}
		})
	}
}

// 目录路径不许回索引页。这是取消健康检查那轮审计翻出来的实际问题：
// http.FileServer 对目录会回一页 HTML 索引，于是 `GET /uploads/` 把所有已上传文件名
// 都列出来。改成自己开文件 + ServeContent 之后，目录只能是 404。
//
// 登录与否都测：未登录被 authRequired 拦下，已登录则要靠 IsDir 判断拦下。
// 只测未登录的话，把 IsDir 那一段删掉测试照样通过，盯不住东西。
func TestUploadsDirectoryListingGone(t *testing.T) {
	files := map[string][]byte{"bg-1755000000000000000.png": []byte("x"), "notes.txt": []byte("y")}
	engine, cookie := uploadsEnv(t, "", files)

	for _, tc := range []struct {
		name   string
		cookie string
	}{
		{name: "未登录", cookie: ""},
		{name: "已登录", cookie: cookie},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, p := range []string{"/uploads/", "/uploads"} {
				req := httptest.NewRequest(http.MethodGet, p, nil)
				if tc.cookie != "" {
					req.Header.Set("Cookie", tc.cookie)
				}
				rec := httptest.NewRecorder()
				engine.ServeHTTP(rec, req)

				if rec.Code >= 200 && rec.Code < 300 {
					t.Errorf("%s 返回了 %d：目录不该有正常响应", p, rec.Code)
				}
				body := rec.Body.String()
				for name := range files {
					if strings.Contains(body, name) {
						t.Errorf("%s 的响应里列出了文件名 %q：目录索引又回来了", p, name)
					}
				}
			}
		})
	}
}

// 穿越取不到数据目录里的其它东西。config.json 就在 uploads 的上一级、且确实存在
// （NewManager + Load 会落盘），所以这条测试有真实目标可打，不是空跑。
func TestUploadsPathTraversalBlocked(t *testing.T) {
	engine, cookie := uploadsEnv(t, "", map[string][]byte{"bg.png": []byte("x")})

	// 带上有效会话再打：穿越防护必须自己站得住，不能靠"反正未登录进不来"。
	for _, p := range []string{
		"/uploads/../config.json",
		"/uploads/%2e%2e/config.json",
		"/uploads/..%2fconfig.json",
		"/uploads/....//config.json",
		"/uploads/..\\config.json",
	} {
		req := httptest.NewRequest(http.MethodGet, p, nil)
		req.Header.Set("Cookie", cookie)
		rec := httptest.NewRecorder()
		engine.ServeHTTP(rec, req)

		if rec.Code >= 200 && rec.Code < 300 {
			t.Errorf("%s 返回了 %d：%s", p, rec.Code, clipBody(rec.Body.String()))
		}
		// 配置里必然有这个键；出现即说明真的把 config.json 读出来了。
		if strings.Contains(rec.Body.String(), "jwtSecret") {
			t.Errorf("%s 读到了配置文件内容", p)
		}
	}
}

// 已登录时功能不变：内容逐字节一致，两个响应头都在。
// 子路径部署一并验——访问前缀由 gin 在匹配时吃掉，处理器里拿到的应当只有 /bg.png。
func TestUploadsServesFileForSignedIn(t *testing.T) {
	body := bytes.Repeat([]byte("\x89PNG\r\n\x1a\n"), 64)
	for _, basePath := range []string{"", "/mantou"} {
		name := "无前缀"
		if basePath != "" {
			name = "有前缀"
		}
		t.Run(name, func(t *testing.T) {
			engine, cookie := uploadsEnv(t, basePath, map[string][]byte{"bg.png": body})

			req := httptest.NewRequest(http.MethodGet, basePath+"/uploads/bg.png", nil)
			req.Header.Set("Cookie", cookie)
			rec := httptest.NewRecorder()
			engine.ServeHTTP(rec, req)

			if rec.Code != http.StatusOK {
				t.Fatalf("已登录取背景图应当 200，实际 %d：%s", rec.Code, clipBody(rec.Body.String()))
			}
			if !bytes.Equal(rec.Body.Bytes(), body) {
				t.Errorf("响应体与原文件不一致（%d → %d 字节）", len(body), rec.Body.Len())
			}
			if got := rec.Header().Get("X-Content-Type-Options"); got != "nosniff" {
				t.Errorf("nosniff 丢了（实际 %q）：它是存储型 XSS 的第二道防线", got)
			}
			// private：内容现在带鉴权，中途的共享缓存不能存下来再发给别人。
			if got := rec.Header().Get("Cache-Control"); !strings.Contains(got, "private") {
				t.Errorf("Cache-Control 应含 private，实际 %q", got)
			}
		})
	}
}
