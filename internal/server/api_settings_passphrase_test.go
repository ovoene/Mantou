package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"mantou/internal/auth"
	"mantou/internal/config"
)

// 导出接口原来只有一条路：备份口令**就是**登录密码。那让两件事被迫绑在一起——
// 把备份交给别人保管，等于把面板密码交给别人；而备份里存的是明文凭证
//（见 config_crypt.go 文件头），拿到的人不只能登面板，还能读到 DDNS、Webhook、
// 证书私钥全套。反过来，改了登录密码也不会让旧备份换口令，那些文件仍旧用当时的密码
// 加密着，而人会记成"我的密码是新的那个"，等到要恢复时才发现解不开。
//
// 于是加了可选的独立口令。这组测试钉住三件事，缺一件这条路就不成立：
//   - 不填时行为**一个字都不变**（备份仍用登录密码加密，老备份、老习惯都不受影响）；
//   - 填了时登录密码**解不开**这份备份（否则等于什么都没隔开，只是多了个输入框）；
//   - 填了它也换不掉身份校验（口令是给文件用的，不是给"我是管理员"用的）。

// passphraseTestAdmin 是这组测试里的管理员账户名。
const passphraseTestAdmin = "admin"

// seedExportAdmin 只装一个可导出的管理员：不放证书（deps.Cert 为 nil 时有证书会直接 503），
// 也不放上传文件，把这组测试收在"口令怎么用"这一件事上。
func seedExportAdmin(t *testing.T, manager *config.Manager) {
	t.Helper()
	hash, err := auth.HashPassword(e2eAdminPassword)
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.Update(func(cfg *config.Config) {
		cfg.Auth.Initialized = true
		cfg.Auth.Username = passphraseTestAdmin
		cfg.Auth.PasswordHash = hash
	}); err != nil {
		t.Fatal(err)
	}
}

// postExport 调一次导出接口。req 直接按 JSON 发出去，好让"不带 passphrase 字段"
// 与"带一个空的 passphrase"都能被表达出来。
func postExport(t *testing.T, server *Server, req map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	ctx.Request = httptest.NewRequest(http.MethodPost, "/api/settings/export", bytes.NewReader(body))
	ctx.Request.Header.Set("Content-Type", "application/json")
	server.handleExportConfig(ctx)
	return w
}

// exportOK 导出并断言成功，返回备份字节。
func exportOK(t *testing.T, server *Server, req map[string]string) []byte {
	t.Helper()
	w := postExport(t, server, req)
	if w.Code != http.StatusOK {
		t.Fatalf("导出应成功，实际 %d：%s", w.Code, w.Body.String())
	}
	return w.Body.Bytes()
}

// TestExportWithoutPassphraseUsesLoginPassword 不填独立口令时，备份仍用登录密码加密。
//
// 这是默认路径，也是所有现存备份与文档说的那一条，不能因为新增了可选项而变味。
func TestExportWithoutPassphraseUsesLoginPassword(t *testing.T) {
	server, manager, _ := newE2EEnv(t)
	seedExportAdmin(t, manager)

	backup := exportOK(t, server, map[string]string{
		"account": passphraseTestAdmin, "password": e2eAdminPassword,
	})
	if !IsEncryptedEnvelope(backup) {
		t.Fatal("导出的应当是加密信封")
	}
	if _, _, _, err := DecryptBackup(backup, passphraseTestAdmin, e2eAdminPassword); err != nil {
		t.Fatalf("不填独立口令时应能用登录密码解开，实际 %v", err)
	}
}

// TestExportPassphraseReplacesLoginPassword 填了独立口令：只有它能解开，登录密码解不开。
//
// 后半句是这条路存在的全部意义。若登录密码仍能解开，那就只是多了一个输入框，
// "备份可以交给别人保管"这件事一点都没成立。
func TestExportPassphraseReplacesLoginPassword(t *testing.T) {
	const passphrase = "另一条足够长的备份口令-B@ckup"
	server, manager, _ := newE2EEnv(t)
	seedExportAdmin(t, manager)

	backup := exportOK(t, server, map[string]string{
		"account": passphraseTestAdmin, "password": e2eAdminPassword, "passphrase": passphrase,
	})
	if _, _, _, err := DecryptBackup(backup, passphraseTestAdmin, passphrase); err != nil {
		t.Fatalf("应能用独立口令解开，实际 %v", err)
	}
	if _, _, _, err := DecryptBackup(backup, passphraseTestAdmin, e2eAdminPassword); err == nil {
		t.Fatal("登录密码不该还能解开这份备份——那样等于没隔开任何东西")
	}
	// 账户名仍绑在密钥里（deriveKey 把它拼进派生材料），换个账户名一样解不开。
	// 这条顺带说明导入时那栏「账户名」要填的还是管理员账户名，不是别的东西。
	if _, _, _, err := DecryptBackup(backup, "someone-else", passphrase); err == nil {
		t.Fatal("换掉账户名后不该解得开")
	}
}

// TestExportPassphraseLengthBounds 独立口令的长度边界。
//
// 下限比登录密码的 6 位严：登录有限流器挡着，而备份文件是离线的、可以不限次数地猜
// （理由写在 minBackupPassphraseLen 那里）。上下限各测"刚好过"与"差一点"两侧，
// 只测中间值的话把 < 写成 <= 都测不出来。
func TestExportPassphraseLengthBounds(t *testing.T) {
	cases := []struct {
		name string
		n    int
		want int
	}{
		{"比下限少一个字节", minBackupPassphraseLen - 1, http.StatusBadRequest},
		{"刚好到下限", minBackupPassphraseLen, http.StatusOK},
		{"刚好到上限", maxBackupPassphraseLen, http.StatusOK},
		{"比上限多一个字节", maxBackupPassphraseLen + 1, http.StatusBadRequest},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server, manager, _ := newE2EEnv(t)
			seedExportAdmin(t, manager)
			pass := strings.Repeat("a", tc.n)
			w := postExport(t, server, map[string]string{
				"account": passphraseTestAdmin, "password": e2eAdminPassword, "passphrase": pass,
			})
			if w.Code != tc.want {
				t.Fatalf("%d 字节的口令应得 %d，实际 %d：%s", tc.n, tc.want, w.Code, w.Body.String())
			}
			if tc.want != http.StatusOK {
				// 被拒时不能顺手把备份也吐出来。
				if IsEncryptedEnvelope(w.Body.Bytes()) {
					t.Fatal("口令不合规时不该产出备份")
				}
				return
			}
			if _, _, _, err := DecryptBackup(w.Body.Bytes(), passphraseTestAdmin, pass); err != nil {
				t.Fatalf("边界值的口令应可用于解密，实际 %v", err)
			}
		})
	}
}

// TestExportShortLoginPasswordNeedsPassphrase 登录密码短于备份口令下限时，不填独立口令导不出（审计 S-01）。
//
// 少了这一条，「不填独立口令」就是绕过下限的那条路：登录密码的下限只有 6
// （api_auth.go 的 minPasswordLen），于是整份备份——含全部凭证明文——的 KDF 输入
// 可以只有 6 字节，而下限本来就是为"备份文件离线、可不限次数猜"定的。
//
// 后半段同样要钉住：这条路必须留着出口。填一个够长的独立口令就能导出，
// 否则一个用 6 位密码的用户会被卡在"导不出来、也没法导出来再改"的死角里。
func TestExportShortLoginPasswordNeedsPassphrase(t *testing.T) {
	// 6 个 ASCII 字节：过得了登录密码的下限，够不到备份口令的下限。
	const shortPass = "abc123"
	if len(shortPass) >= minBackupPassphraseLen {
		t.Fatalf("这条用例要求 %q 短于备份口令下限 %d", shortPass, minBackupPassphraseLen)
	}

	server, manager, _ := newE2EEnv(t)
	hash, err := auth.HashPassword(shortPass)
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.Update(func(cfg *config.Config) {
		cfg.Auth.Initialized = true
		cfg.Auth.Username = passphraseTestAdmin
		cfg.Auth.PasswordHash = hash
	}); err != nil {
		t.Fatal(err)
	}

	w := postExport(t, server, map[string]string{
		"account": passphraseTestAdmin, "password": shortPass,
	})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("登录密码只有 %d 字节又不填独立口令，应得 400，实际 %d：%s",
			len(shortPass), w.Code, w.Body.String())
	}
	if IsEncryptedEnvelope(w.Body.Bytes()) {
		t.Fatal("口令不合规却产出了备份")
	}

	// 出口：填一个够长的独立口令，同一个账号照样导得出来。
	const passphrase = "够长的独立备份口令-B@ckup"
	backup := exportOK(t, server, map[string]string{
		"account": passphraseTestAdmin, "password": shortPass, "passphrase": passphrase,
	})
	if _, _, _, err := DecryptBackup(backup, passphraseTestAdmin, passphrase); err != nil {
		t.Fatalf("应能用独立口令解开，实际 %v", err)
	}
}

// TestExportPassphraseDoesNotBypassIdentity 独立口令换不掉身份校验。
//
// 口令是给**文件**用的，"我是这台面板的管理员"仍旧只由登录密码证明。少了这条，
// 任何拿到一条会话的人（比如一次 XSS 借来的 Cookie）都能自带口令导走全部凭证。
func TestExportPassphraseDoesNotBypassIdentity(t *testing.T) {
	server, manager, _ := newE2EEnv(t)
	seedExportAdmin(t, manager)

	w := postExport(t, server, map[string]string{
		"account": passphraseTestAdmin, "password": "错误的登录密码", "passphrase": "足够长的备份口令-XYZ",
	})
	if w.Code != http.StatusForbidden {
		t.Fatalf("登录密码不对应当 403，实际 %d：%s", w.Code, w.Body.String())
	}
	if IsEncryptedEnvelope(w.Body.Bytes()) {
		t.Fatal("身份校验没过却产出了备份")
	}
}
