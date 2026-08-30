package server

import (
	"bytes"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"mantou/internal/auth"
	"mantou/internal/config"
)

// 导入除了要有"解开这份备份的口令"，还要再验一次"本机当前管理员"的身份。
// 两者证明的不是同一件事：备份口令由做备份的人自己定（见 config_crypt.go 的 deriveKey），
// 拿一份自造的备份想填什么填什么；而导入会把管理员账户本身也一起换掉，
// 所以那一步必须证明"我是这台面板当前的管理员"（见 handleImportConfig）。
//
// 界面上那个认证弹窗只是把失败提前，绕过它直接调接口是最平常的事，所以这一档钉在接口上。

// importBackupWithAuth 提交一次导入，authAccount / authPassword 由调用方指定。
// 传空串表示**不提交**该字段——与提交空值在接口那里是同一个结果（本机账户名不可能为空）。
// token 非空时作为会话 Cookie 带上，供"导入后会话怎么处置"那几条断言用。
func importBackupWithAuth(t *testing.T, server *Server, backup []byte, authAccount, authPassword, token string) *httptest.ResponseRecorder {
	t.Helper()
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	part, err := writer.CreateFormFile("file", "Mantou-backup.json")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := part.Write(backup); err != nil {
		t.Fatal(err)
	}
	// 这一对是备份自己的解密口令，恒定填对：要测的是身份那一道，不能被"口令也错了"混淆。
	fields := map[string]string{"account": "admin", "password": e2eAdminPassword}
	if authAccount != "" {
		fields["authAccount"] = authAccount
	}
	if authPassword != "" {
		fields["authPassword"] = authPassword
	}
	for k, v := range fields {
		if err := writer.WriteField(k, v); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodPost, "/api/settings/import", &body)
	ctx.Request.Header.Set("Content-Type", writer.FormDataContentType())
	if token != "" {
		ctx.Request.AddCookie(&http.Cookie{Name: sessionCookie, Value: token})
	}
	server.handleImportConfig(ctx)
	return recorder
}

// TestImportRejectsWrongCurrentAdminCredentials 身份不对的导入一律 403，且配置一个字节都不动。
func TestImportRejectsWrongCurrentAdminCredentials(t *testing.T) {
	gin.SetMode(gin.TestMode)
	t.Setenv("MANTOU_MASTER_KEY", "")

	source, sourceManager, sourceDir := newE2EEnv(t)
	seedFullConfig(t, sourceManager, sourceDir)
	backup := exportBackup(t, source)

	target, targetManager, _ := newE2EEnv(t)
	seedLocalConfig(t, targetManager)

	for _, tc := range []struct {
		name     string
		account  string
		password string
	}{
		{name: "两个字段都不提交", account: "", password: ""},
		{name: "只提交账户", account: e2eLocalAccount, password: ""},
		{name: "账户对密码错", account: e2eLocalAccount, password: e2eLocalPassword + "x"},
		{name: "密码对账户错", account: "admin", password: e2eLocalPassword},
		// 最要紧的一条：备份自己的那对凭据顶不了身份验证。
		// 攻击者手上有的正是这一对（他自己造的备份，口令自己定），如果它能过，这道闸就是空的。
		{name: "填的是备份的口令", account: "admin", password: e2eAdminPassword},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := importBackupWithAuth(t, target, backup, tc.account, tc.password, "")
			if rec.Code != http.StatusForbidden {
				t.Fatalf("状态码是 %d，期望 403（%s）", rec.Code, rec.Body.String())
			}
			// 403 而不是 401：401 会被前端拦截器当成会话失效、把人强制登出。
			if !strings.Contains(rec.Body.String(), "当前账户或密码不正确") {
				t.Fatalf("响应是 %s", rec.Body.String())
			}
			cfg := targetManager.Snapshot()
			if cfg.Auth.Username != e2eLocalAccount || !auth.VerifyPassword(cfg.Auth.PasswordHash, e2eLocalPassword) {
				t.Fatalf("被拒的导入改动了管理员账户: %s", cfg.Auth.Username)
			}
			if len(cfg.Forwards) != 1 || cfg.Forwards[0].ID != "fwd-local" {
				t.Fatalf("被拒的导入改动了其它模块: %+v", cfg.Forwards)
			}
		})
	}

	// 反向钉住：同一份备份、同一台机器，身份填对就该导得进去，
	// 否则上面那五条绿灯也可能只是因为导入整体坏掉了。
	rec := importBackupWithAuth(t, target, backup, e2eLocalAccount, e2eLocalPassword, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("身份正确却导入失败: %d %s", rec.Code, rec.Body.String())
	}
	if got := targetManager.Snapshot().Forwards; len(got) != 1 || got[0].ID != "fwd-e2e" {
		t.Fatalf("导入没生效，端口转发是 %+v", got)
	}
}

// TestImportRejectsPlaintextBeforeCheckingIdentity 明文文件仍旧回它原来那句 400。
//
// 次序是刻意的：明文备份被拒与身份无关（是文件本身不对），换一句 403 会把人引到
// 密码上去查。反过来，身份这道闸必须挡在 60 万次 PBKDF2 之前，不给未授权请求白跑的机会。
func TestImportRejectsPlaintextBeforeCheckingIdentity(t *testing.T) {
	gin.SetMode(gin.TestMode)
	t.Setenv("MANTOU_MASTER_KEY", "")

	target, targetManager, _ := newE2EEnv(t)
	seedLocalConfig(t, targetManager)

	plaintext := []byte(`{"auth":{"initialized":true,"username":"attacker","passwordHash":"known-hash"}}`)
	rec := importBackupWithAuth(t, target, plaintext, "", "", "")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("状态码是 %d，期望 400（%s）", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "不允许导入未加密的配置文件") {
		t.Fatalf("响应是 %s", rec.Body.String())
	}
}

// TestImportRevokesSessionsWhenCredentialsChanged 导入把管理员凭据换掉之后，会话要跟着处置。
//
// 不处置会留下一个很难查的状态：刚用**当前**密码通过了身份验证，导入完凭据已经是备份里那一套，
// 而会话还活着、界面一切正常，于是毫无察觉；直到下次登录才发现进不去。
func TestImportRevokesSessionsWhenCredentialsChanged(t *testing.T) {
	gin.SetMode(gin.TestMode)
	t.Setenv("MANTOU_MASTER_KEY", "")

	source, sourceManager, sourceDir := newE2EEnv(t)
	seedFullConfig(t, sourceManager, sourceDir)
	backup := exportBackup(t, source)

	// seedFullConfig 里的管理员叫 admin，本机也叫 admin 但密码不同 → 只有密码被换掉。
	t.Run("只换了密码：别处的会话失效，当前这台换发新令牌", func(t *testing.T) {
		target, targetManager, _ := newE2EEnv(t)
		seedLocalAdmin(t, targetManager)
		hash, err := auth.HashPassword(e2eLocalPassword)
		if err != nil {
			t.Fatal(err)
		}
		if err := targetManager.Update(func(cfg *config.Config) {
			cfg.Auth.Username = "admin" // 与备份里同名
			cfg.Auth.PasswordHash = hash
			cfg.Auth.SessionHours = 72
		}); err != nil {
			t.Fatal(err)
		}
		mine, other := "token-当前这台", "token-另一台"
		target.sessions.add(mine, "admin", time.Hour)
		target.sessions.add(other, "admin", time.Hour)

		rec := importBackupWithAuth(t, target, backup, "admin", e2eLocalPassword, mine)
		if rec.Code != http.StatusOK {
			t.Fatalf("导入失败: %d %s", rec.Code, rec.Body.String())
		}
		if !importCredentialsChanged(t, rec) {
			t.Fatal("响应里的 credentialsChanged 是 false，前端不会提示用户重新登录")
		}
		if _, ok := target.sessions.valid(other, "admin", true, 0); ok {
			t.Error("别处的会话还活着")
		}
		if _, ok := target.sessions.valid(mine, "admin", true, 0); ok {
			t.Error("当前这台的旧令牌还活着（应换发一条新的，旧值连同副本一起作废）")
		}
		if !strings.Contains(rec.Header().Get("Set-Cookie"), sessionCookie+"=") {
			t.Errorf("没给当前浏览器换发会话 Cookie: %q", rec.Header().Values("Set-Cookie"))
		}
	})

	t.Run("换了账户名：全部失效，包括当前这台", func(t *testing.T) {
		target, targetManager, _ := newE2EEnv(t)
		seedLocalConfig(t, targetManager) // 本机叫 local-admin，备份里叫 admin
		mine := "token-当前这台"
		target.sessions.add(mine, e2eLocalAccount, time.Hour)

		rec := importBackupWithAuth(t, target, backup, e2eLocalAccount, e2eLocalPassword, mine)
		if rec.Code != http.StatusOK {
			t.Fatalf("导入失败: %d %s", rec.Code, rec.Body.String())
		}
		if !importCredentialsChanged(t, rec) {
			t.Fatal("响应里的 credentialsChanged 是 false，前端不会提示用户重新登录")
		}
		if _, ok := target.sessions.valid(mine, e2eLocalAccount, true, 0); ok {
			t.Error("换了账户名，当前这台的会话也该一并作废")
		}
		// 换名字这一支是登出而不是换发：Cookie 必须被清掉，不能留一个已经不认的令牌。
		if !strings.Contains(rec.Header().Get("Set-Cookie"), sessionCookie+"=;") {
			t.Errorf("会话 Cookie 没被清除: %q", rec.Header().Values("Set-Cookie"))
		}
		if got := targetManager.Snapshot().Auth.Username; got != "admin" {
			t.Fatalf("测试前提不成立：导入后管理员账户是 %s，期望跟备份走用 admin", got)
		}
	})

	t.Run("凭据没变：会话不受影响", func(t *testing.T) {
		target, targetManager, _ := newE2EEnv(t)
		// 本机凭据与备份里**完全一致**——这就是"在同一台机器上重新导入自己的备份"，
		// 那一步不该把人踢下线。
		//
		// 密码哈希直接从源机器抄过来，不是重新 HashPassword 一遍：bcrypt 每次带新盐，
		// 同一个密码算出来的哈希也不同，而这里比的是哈希（导入侧手上只有哈希，没有密码）。
		// 也就是说"换台机器、密码碰巧一样"会被当成凭据变了、走一遍会话处置——
		// 宁可多踢一次，不能漏。
		src := sourceManager.Snapshot().Auth
		if err := targetManager.Update(func(cfg *config.Config) {
			cfg.Auth.Username = src.Username
			cfg.Auth.PasswordHash = src.PasswordHash
			cfg.Auth.Initialized = true
		}); err != nil {
			t.Fatal(err)
		}
		mine := "token-当前这台"
		target.sessions.add(mine, "admin", time.Hour)

		rec := importBackupWithAuth(t, target, backup, "admin", e2eAdminPassword, mine)
		if rec.Code != http.StatusOK {
			t.Fatalf("导入失败: %d %s", rec.Code, rec.Body.String())
		}
		if importCredentialsChanged(t, rec) {
			t.Error("凭据没变却报了 credentialsChanged")
		}
		if _, ok := target.sessions.valid(mine, "admin", true, 0); !ok {
			t.Error("凭据没变却把当前会话踢了")
		}
	})
}

// importCredentialsChanged 取导入响应里的 credentialsChanged。
func importCredentialsChanged(t *testing.T, rec *httptest.ResponseRecorder) bool {
	t.Helper()
	var resp struct {
		Data struct {
			CredentialsChanged bool `json:"credentialsChanged"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("解析导入响应失败: %v（%s）", err, rec.Body.String())
	}
	return resp.Data.CredentialsChanged
}

// TestHandleVerifyIdentity 身份预校验：只回"对/不对"，不改任何东西。
//
// 它只是把失败提前到界面那一步（免得范围与备份口令都填完了才被打回来），
// 不是任何操作的安全边界——真正的闸在各接口里（见上面那几条）。
func TestHandleVerifyIdentity(t *testing.T) {
	gin.SetMode(gin.TestMode)
	t.Setenv("MANTOU_MASTER_KEY", "")

	server, manager, _ := newE2EEnv(t)
	seedLocalAdmin(t, manager)

	call := func(t *testing.T, body string) *httptest.ResponseRecorder {
		t.Helper()
		rec := httptest.NewRecorder()
		ctx, _ := gin.CreateTestContext(rec)
		ctx.Request = httptest.NewRequest(http.MethodPost, "/api/auth/verify", strings.NewReader(body))
		ctx.Request.Header.Set("Content-Type", "application/json")
		server.handleVerifyIdentity(ctx)
		return rec
	}

	for _, tc := range []struct {
		name string
		body string
		code int
	}{
		{name: "账户密码都对", body: `{"account":"` + e2eLocalAccount + `","password":"` + e2eLocalPassword + `"}`, code: http.StatusOK},
		{name: "账户名两侧的空白不算错", body: `{"account":"  ` + e2eLocalAccount + `  ","password":"` + e2eLocalPassword + `"}`, code: http.StatusOK},
		{name: "密码错", body: `{"account":"` + e2eLocalAccount + `","password":"错的"}`, code: http.StatusForbidden},
		{name: "账户错", body: `{"account":"someone-else","password":"` + e2eLocalPassword + `"}`, code: http.StatusForbidden},
		{name: "两个都空", body: `{}`, code: http.StatusForbidden},
		{name: "不是 JSON", body: `not json`, code: http.StatusBadRequest},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := call(t, tc.body)
			if rec.Code != tc.code {
				t.Fatalf("状态码是 %d，期望 %d（%s）", rec.Code, tc.code, rec.Body.String())
			}
		})
	}

	// 这个接口不改任何东西，跑完一轮配置必须原样。
	cfg := manager.Snapshot()
	if cfg.Auth.Username != e2eLocalAccount || !auth.VerifyPassword(cfg.Auth.PasswordHash, e2eLocalPassword) {
		t.Fatalf("身份预校验改动了管理员账户: %s", cfg.Auth.Username)
	}
}
