package server

import (
	"bytes"
	"encoding/json"
	"mime/multipart"
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

// 本文件把一条硬性要求钉住：**导出配置 → 换到全新环境 → 直接导入 → 立即可用且设置一模一样**，
// 不需要任何额外配置（不需要搬 master.key、不需要重设背景/皮肤、不需要重填凭证）。
//
// 这条要求与"凭证在磁盘上加密"（internal/config/secret.go）天然对立：
// 磁盘加密的密钥 master.key 是**本机**的东西，如果备份里存的是它加密出来的密文，
// 换台机器就成了一堆解不开的乱码。因此备份里存的是内存中的明文，
// 由备份口令整体加密（internal/server/config_crypt.go），导入方再用**自己的** master.key 重新加密落盘。
// 一旦有人"顺手"把磁盘密文写进备份，本测试立刻失败。

const (
	// 导出接口用管理员密码同时做身份校验与备份加密口令，因此两者是同一个值。
	e2eAdminPassword = "管理员密码-P@ss"
	e2eAPIToken      = "cf-token-导出后必须还在-4B71"
	e2eACMEKey       = "-----BEGIN EC PRIVATE KEY-----\ne2e-acme-key\n-----END EC PRIVATE KEY-----\n"
	e2eBackgroundPNG = "\x89PNG\r\n\x1a\n假的背景图字节"

	// e2eLocalAccount / e2eLocalPassword 是**导入目标机器**上那套本机管理员凭据，
	// 与备份里的（e2eAdminPassword）刻意取成不同的值：导入会改写管理员账户本身，
	// 接口因此要求先证明"我是这台面板当前的管理员"（见 handleImportConfig）。
	// 两个导入 helper 就是拿这一对去填 authAccount/authPassword，
	// 所以每台准备接收导入的"机器"都要先由 seedLocalAdmin 装上它。
	e2eLocalAccount  = "local-admin"
	e2eLocalPassword = "本机密码-L@cal"
)

// newE2EEnv 造一个独立的"机器"：自己的数据目录、自己的 config.json、自己的 master.key。
//
// 会话表是真的而不是留 nil：导入替换了管理员凭据时要作废既有会话（见 handleImportConfig），
// 留 nil 会在那一支上直接崩，而那正是最该被测到的一支。
func newE2EEnv(t *testing.T) (*Server, *config.Manager, string) {
	t.Helper()
	dataDir := t.TempDir()
	manager := config.NewManager(filepath.Join(dataDir, "config.json"))
	if err := manager.Load(); err != nil {
		t.Fatal(err)
	}
	server := &Server{
		deps: Deps{
			Config:  manager,
			Log:     logx.New(logx.Options{}),
			DataDir: dataDir,
		},
		sessions: newSessionRegistry(),
	}
	t.Cleanup(server.sessions.close)
	return server, manager, dataDir
}

// seedLocalAdmin 给"机器"装上一套可登录的本机管理员。
//
// 现实里的全新环境也不是没有账户的：导入是已鉴权操作，能点到它就说明初始化设置已经做完、
// 人已经登进来了。所以准备接收导入的环境都要先过这一步，否则测的是一个不存在的状态。
func seedLocalAdmin(t *testing.T, manager *config.Manager) {
	t.Helper()
	hash, err := auth.HashPassword(e2eLocalPassword)
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.Update(func(cfg *config.Config) {
		cfg.Auth.Username = e2eLocalAccount
		cfg.Auth.PasswordHash = hash
		cfg.Auth.Initialized = true
	}); err != nil {
		t.Fatal(err)
	}
}

// seedFullConfig 把"用户已经把面板配满了"的状态写进配置：外观（背景图 + 皮肤色）、
// 各模块的规则、凭证与 ACME 私钥、全局设置。证书不在此列——它随备份走的是 PEM 文件，
// 由 restoreBackupResources 负责，且需要真实的证书模块，另有测试覆盖。
func seedFullConfig(t *testing.T, manager *config.Manager, dataDir string) {
	t.Helper()
	hash, err := auth.HashPassword(e2eAdminPassword)
	if err != nil {
		t.Fatal(err)
	}
	uploads := filepath.Join(dataDir, "uploads")
	if err := os.MkdirAll(uploads, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(uploads, "bg.png"), []byte(e2eBackgroundPNG), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := manager.Update(func(cfg *config.Config) {
		cfg.Auth.Username = "admin"
		cfg.Auth.PasswordHash = hash
		cfg.Auth.Initialized = true
		cfg.Auth.SessionHours = 72
		cfg.Auth.LoginMaxFails = 7
		cfg.Auth.LoginLockMinutes = 15

		// 外观：背景图 + 皮肤（主题色/卡片/字体/布局）。
		app := &cfg.Settings.Appearance
		app.ThemeMode = "dark"
		app.Colors = config.AppearanceColors{Primary: "#FF6600", Accent: "#00C2FF", Success: "#12B76A", Warning: "#F79009", Danger: "#F04438"}
		app.Background = config.AppearanceBackground{Type: "image", Value: "/uploads/bg.png", Blur: 12, OverlayOpacity: 0.35, Fit: "cover", Position: "center"}
		app.Card.Opacity = 0.72
		cfg.Settings.Language = "en-US"
		cfg.Settings.Notify = config.Notify{Enabled: true}
		cfg.Update.About = "我的自定义说明"

		// 凭证与 ACME 账户私钥：这两样在磁盘上是密文，在备份里必须是明文。
		cfg.Credentials = []config.Credential{{
			ID: "cred-e2e", Name: "我的 Cloudflare", Provider: "cloudflare",
			Secrets: map[string]string{"apiToken": e2eAPIToken},
		}}
		cfg.ACMEAccounts = []config.ACMEAccount{{ID: "acc-e2e", Email: "me@example.com", PrivateKeyPEM: e2eACMEKey}}

		// 各模块的设置。
		cfg.DDNS = []config.DDNSRule{{
			ID: "ddns-e2e", Name: "家里", Enabled: true, Stack: "ipv4", IntervalSec: 300,
			Source: config.DDNSSource{Type: "public"},
			Targets: []config.DDNSTarget{{
				CredentialRef: "cred-e2e", Provider: "cloudflare", Domain: "example.com",
				Subdomains: []string{"home"}, RecordType: "A", TTL: 600,
			}},
		}}
		cfg.Forwards = []config.ForwardRule{{
			ID: "fwd-e2e", Name: "内网 SSH", Enabled: true, Protocol: "tcp",
			ListenPort: 2222, TargetHost: "192.168.1.20", TargetPort: 22, Family: "dual",
		}}
		cfg.WOLDevices = []config.WOLDevice{{ID: "wol-e2e", Enabled: true, Name: "台式机", MAC: "AA:BB:CC:DD:EE:FF", Broadcast: "192.168.1.255", Port: 9}}
		cfg.CronTasks = []config.CronTask{{
			ID: "cron-e2e", Name: "每天刷新 DDNS", Enabled: true, Cron: "0 3 * * *",
			Schedule: config.CronSchedule{Type: "daily", Hour: 3, Minute: 0},
			Action:   config.CronAction{Type: "ddns.refresh", Params: map[string]string{"targetId": "ddns-e2e"}},
		}}
		cfg.WebServices = []config.WebService{{
			ID: "web-e2e", Name: "站点", Enabled: true, Port: 8443, IPFamily: "both",
			// 显式给出探测间隔：留 0 时导入侧的 migrate 会补成 60（运行时两者等价，
			// 见 normalizeProbeInterval），但会让下面的整份比对出现纯粹是规范化造成的差异。
			ProbeInterval: 60,
			Children: []config.WebChild{{
				ID: "child-e2e", Enabled: true, Type: "proxy", Domains: []string{"a.example.com"},
				Upstreams: []config.WebUpstream{{URL: "http://127.0.0.1:3000", Weight: 1}},
				TLS:       true, TLSMinVersion: "1.2", RedirectHTTPS: true,
			}},
		}}
	}); err != nil {
		t.Fatal(err)
	}
}

// exportBackup 走真实的导出接口拿到加密备份字节。
func exportBackup(t *testing.T, server *Server) []byte {
	t.Helper()
	body, err := json.Marshal(map[string]string{"account": "admin", "password": e2eAdminPassword})
	if err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodPost, "/api/settings/export", bytes.NewReader(body))
	ctx.Request.Header.Set("Content-Type", "application/json")
	server.handleExportConfig(ctx)
	if recorder.Code != http.StatusOK {
		t.Fatalf("导出失败: %d %s", recorder.Code, recorder.Body.String())
	}
	return recorder.Body.Bytes()
}

// importBackup 走真实的导入接口，返回响应记录供调用方断言。
//
// 表单里有两对凭据，别混：account/password 是解开这份**备份**的口令（做备份的人自己定），
// authAccount/authPassword 是**本机当前**管理员的账户与密码，用来过接口那道身份校验。
// 账户名从目标机器的配置里现读，免得与 seedLocalAdmin 各写一份、改一处对不上。
func importBackup(t *testing.T, server *Server, backup []byte) *httptest.ResponseRecorder {
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
	if err := writer.WriteField("account", "admin"); err != nil {
		t.Fatal(err)
	}
	if err := writer.WriteField("password", e2eAdminPassword); err != nil {
		t.Fatal(err)
	}
	if err := writer.WriteField("authAccount", server.deps.Config.Snapshot().Auth.Username); err != nil {
		t.Fatal(err)
	}
	if err := writer.WriteField("authPassword", e2eLocalPassword); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodPost, "/api/settings/import", &body)
	ctx.Request.Header.Set("Content-Type", writer.FormDataContentType())
	server.handleImportConfig(ctx)
	return recorder
}

func TestBackupRestoresEverythingInAFreshEnvironment(t *testing.T) {
	gin.SetMode(gin.TestMode)
	t.Setenv("MANTOU_MASTER_KEY", "") // 两台"机器"各自生成 master.key，不受开发机环境变量干扰

	// ---------- 旧环境：配满、导出 ----------
	oldServer, oldManager, oldDir := newE2EEnv(t)
	seedFullConfig(t, oldManager, oldDir)
	backup := exportBackup(t, oldServer)

	// 备份里不得出现磁盘密文，也不得夹带 master.key——否则换机器就解不开了。
	oldKey, err := os.ReadFile(oldManager.KeyPath())
	if err != nil {
		t.Fatalf("旧环境应已生成 master.key: %v", err)
	}
	if bytes.Contains(backup, bytes.TrimSpace(oldKey)) {
		t.Fatal("备份文件里夹带了 master.key")
	}
	if bytes.Contains(backup, []byte("enc:v1:")) {
		t.Fatal("备份文件里出现了磁盘密文（enc:v1:），换环境后将无法解开")
	}
	// 旧环境的磁盘上凭证必须是密文（这条由 config 包的测试细化，这里只做交叉确认）。
	oldRaw, err := os.ReadFile(oldManager.Path())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(oldRaw), e2eAPIToken) {
		t.Fatal("旧环境的 config.json 里凭证是明文")
	}

	// ---------- 新环境：只有这份备份，什么都没配 ----------
	// 除了管理员账户：初始化设置是登录的前提，而导入要先验一次当前管理员的身份。
	newServer, newManager, newDir := newE2EEnv(t)
	seedLocalAdmin(t, newManager)
	recorder := importBackup(t, newServer, backup)
	if recorder.Code != http.StatusOK {
		t.Fatalf("导入失败: %d %s", recorder.Code, recorder.Body.String())
	}

	before := oldManager.Get()
	after := newManager.Get()

	// 会话签名密钥是唯一被刻意排除的字段：导入的备份一律沿用本机密钥，
	// 否则拿到一份备份就能伪造该实例的管理员令牌（见 config.Manager.Replace）。
	// 代价是导入后需要重新登录，这不属于"设置"。
	if after.Auth.JWTSecret == before.Auth.JWTSecret {
		t.Fatal("导入不应沿用备份里的会话签名密钥")
	}
	if after.Auth.JWTSecret == "" {
		t.Fatal("导入后必须有可用的会话签名密钥")
	}
	after.Auth.JWTSecret = before.Auth.JWTSecret

	beforeJSON, err := json.MarshalIndent(before, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	afterJSON, err := json.MarshalIndent(after, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(beforeJSON, afterJSON) {
		t.Fatalf("导入后的配置与导出前不一致。\n导出前:\n%s\n导入后:\n%s", beforeJSON, afterJSON)
	}

	// 逐项点名几个关键设置，让失败信息直接指出是哪一类丢了（而不是让人去读上面的大段 diff）。
	if after.Settings.Appearance.Background.Value != "/uploads/bg.png" || after.Settings.Appearance.Background.Blur != 12 {
		t.Fatalf("背景设置丢失: %+v", after.Settings.Appearance.Background)
	}
	if after.Settings.Appearance.Colors.Primary != "#FF6600" || after.Settings.Appearance.ThemeMode != "dark" {
		t.Fatalf("皮肤设置丢失: %+v", after.Settings.Appearance)
	}
	if got := after.Credentials[0].Secrets["apiToken"]; got != e2eAPIToken {
		t.Fatalf("凭证丢失或不可用: %q", got)
	}
	if after.ACMEAccounts[0].PrivateKeyPEM != e2eACMEKey {
		t.Fatal("ACME 账户私钥丢失（会导致证书续期重新注册账户）")
	}
	if len(after.DDNS) != 1 || len(after.Forwards) != 1 || len(after.WOLDevices) != 1 ||
		len(after.CronTasks) != 1 || len(after.WebServices) != 1 {
		t.Fatal("模块规则数量不一致")
	}
	if after.WebServices[0].Children[0].Upstreams[0].URL != "http://127.0.0.1:3000" {
		t.Fatal("Web 服务子项设置丢失")
	}

	// 背景图文件本身也要落到新环境（不然设置在、图没了，界面是一片空白）。
	restored, err := os.ReadFile(filepath.Join(newDir, "uploads", "bg.png"))
	if err != nil {
		t.Fatalf("背景图未恢复: %v", err)
	}
	if string(restored) != e2eBackgroundPNG {
		t.Fatal("恢复的背景图内容不一致")
	}

	// 新环境用**自己的** master.key 重新加密落盘：不需要搬旧机器的密钥。
	newKey, err := os.ReadFile(newManager.KeyPath())
	if err != nil {
		t.Fatalf("新环境应已生成自己的 master.key: %v", err)
	}
	if bytes.Equal(bytes.TrimSpace(newKey), bytes.TrimSpace(oldKey)) {
		t.Fatal("两个环境的 master.key 相同，测试没有真正验证跨环境")
	}
	newRaw, err := os.ReadFile(newManager.Path())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(newRaw), e2eAPIToken) {
		t.Fatal("新环境的 config.json 里凭证是明文")
	}
	if !strings.Contains(string(newRaw), "enc:v1:") {
		t.Fatal("新环境的 config.json 未加密凭证")
	}

	// 最关键的一步：重启新环境（重新加载磁盘）后依然可用——凭证解得开、设置还在。
	restarted := config.NewManager(newManager.Path())
	if err := restarted.Load(); err != nil {
		t.Fatalf("新环境重启加载失败: %v", err)
	}
	reloaded := restarted.Get()
	if got := reloaded.Credentials[0].Secrets["apiToken"]; got != e2eAPIToken {
		t.Fatalf("重启后凭证解不开: %q", got)
	}
	if reloaded.Settings.Appearance.Background.Value != "/uploads/bg.png" {
		t.Fatal("重启后外观设置丢失")
	}
	if reloaded.Auth.Username != "admin" || !auth.VerifyPassword(reloaded.Auth.PasswordHash, e2eAdminPassword) {
		t.Fatal("重启后管理员账户不可用")
	}
}
