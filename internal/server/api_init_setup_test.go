package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"mantou/internal/auth"
	"mantou/internal/config"
	"mantou/internal/logx"
)

// /api/init/setup 是免鉴权的，它是这个面板上唯一一个「不带任何凭据就能改掉管理员账户」
// 的接口，所以它的放行条件值得单独钉一遍。
//
// 曾经的判定只看 Auth.Initialized 这一个布尔值。那个值为假而账户仍在时，任何人都能走
// 一遍初始化向导，把用户名与口令哈希整个换成自己的——一次完整的接管，且不需要凭据。
// config.migrate 已经在「加载」与「导入」两条路上把这个不一致状态补掉了，但一个免鉴权
// 入口不该把安全性全押在别处的补齐上，所以接口自己也判一次（见 panelHasAdmin）。
//
// 这一组同时测正反两侧：该拦的拦住，而**真正的首次安装**必须照旧能装上——
// 拦过头等于面板谁都装不了，那比漏拦更容易被立刻发现，但同样是回退。

// initSetupEnv 造一个走真实路由的面板，并按 auth 参数决定账户处于哪种状态。
func initSetupEnv(t *testing.T, mutate func(cfg *config.Config)) (*config.Manager, http.Handler) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	manager := config.NewManager(filepath.Join(t.TempDir(), "config.json"))
	if err := manager.Load(); err != nil {
		t.Fatal(err)
	}
	if mutate != nil {
		// Update 刻意不跑 migrate，所以这里能造出「标记为假但账户仍在」这种
		// 只有外部配置才带得进来的状态——否则这个测试根本没有被测对象。
		if err := manager.Update(mutate); err != nil {
			t.Fatal(err)
		}
	}
	s := New(Deps{Config: manager, Log: logx.New(logx.Options{})})
	t.Cleanup(s.sessions.close)
	return manager, s.http.Handler
}

// postInitSetup 以匿名身份提交一次初始化。
func postInitSetup(t *testing.T, h http.Handler, username, password string) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(map[string]string{"username": username, "password": password})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/init/setup", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// 标记为假、账户仍在：必须拒绝，且原账户一个字节都不能被改。
func TestInitSetupRefusedWhenAdminExists(t *testing.T) {
	hash, err := auth.HashPassword(testLoginPass)
	if err != nil {
		t.Fatal(err)
	}
	manager, h := initSetupEnv(t, func(cfg *config.Config) {
		cfg.Auth.Username = testLoginUser
		cfg.Auth.PasswordHash = hash
		cfg.Auth.Initialized = false
	})
	// 前提校验：这一格要的就是那个不一致状态，被谁顺手补齐了的话下面全是假通过。
	if manager.Snapshot().Auth.Initialized {
		t.Fatal("测试前提不成立：这里需要「标记为假但账户仍在」的状态")
	}

	rec := postInitSetup(t, h, "somebody-else", "another-password")
	if rec.Code != http.StatusConflict {
		t.Fatalf("已有管理员账户时初始化必须被拒（409），得到 %d：%s", rec.Code, rec.Body.String())
	}

	after := manager.Snapshot().Auth
	if after.Username != testLoginUser || after.PasswordHash != hash {
		t.Fatalf("原管理员账户被匿名请求改掉了：username=%q", after.Username)
	}
}

// 正常已初始化的面板同样要拒（这条早就成立，一起钉住，防止改判定时把它漏掉）。
func TestInitSetupRefusedWhenInitialized(t *testing.T) {
	hash, err := auth.HashPassword(testLoginPass)
	if err != nil {
		t.Fatal(err)
	}
	_, h := initSetupEnv(t, func(cfg *config.Config) {
		cfg.Auth.Username = testLoginUser
		cfg.Auth.PasswordHash = hash
		cfg.Auth.Initialized = true
	})
	if rec := postInitSetup(t, h, "somebody-else", "another-password"); rec.Code != http.StatusConflict {
		t.Fatalf("已初始化的面板上初始化必须被拒（409），得到 %d：%s", rec.Code, rec.Body.String())
	}
}

// 反方向的正面用例：真正的首次安装必须能装上。
// 少了这一条，「把判定改严」这类改动可以在全绿的情况下让面板彻底装不上。
func TestInitSetupSucceedsOnFreshInstall(t *testing.T) {
	manager, h := initSetupEnv(t, nil)
	if manager.Snapshot().Auth.Username != "" {
		t.Fatal("测试前提不成立：全新安装不该已有账户")
	}

	rec := postInitSetup(t, h, testLoginUser, testLoginPass)
	if rec.Code != http.StatusOK {
		t.Fatalf("首次安装应当能完成初始化，得到 %d：%s", rec.Code, rec.Body.String())
	}

	after := manager.Snapshot().Auth
	if after.Username != testLoginUser {
		t.Fatalf("初始化后用户名应为 %q，实际 %q", testLoginUser, after.Username)
	}
	if !after.Initialized {
		t.Fatal("初始化后标记必须为真")
	}
	if !auth.VerifyPassword(after.PasswordHash, testLoginPass) {
		t.Fatal("初始化后应当能用刚设的密码验证通过")
	}
}
