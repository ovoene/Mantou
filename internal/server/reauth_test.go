package server

import (
	"bytes"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"mantou/internal/auth"
	"mantou/internal/config"
	"mantou/internal/logx"
)

// 本文件钉住 reauth.go 那份共享失败计数的五条性质：
//
//  1. **是共享的**：六条「已登录后再验一次当前密码」的路（改账户、加密导出、导入前的身份
//     校验、敏感操作预检、打开「允许未验签的更新包」、上传未验签的更新包）失败次数记在一起。
//     每条各自失败两三次、没有一条自己够 15 次，照样会锁——如果哪天有谁把计数改成按路由
//     分开，这一条立刻失败，而那种改法的效果是攻击者换个接口接着猜（reauth.go 文件头的
//     那句「要么一起限，要么都不限」）。
//  2. **按会话记**：被锁的是那条会话自己。同一来源的另一条令牌不受影响——否则任何能
//     故意失败几次的人都能把真正的管理员挡在敏感操作外面。
//  3. **一次正确的密码清零**：打错几次字不该留下永久债务。
//  4. **与登录限流互不相通**：两个方向都钉。会话那侧被锁不能连带把人锁在登录页外面
//     （那是管理员唯一的恢复入口），登录那侧被锁也不该让手上这条好会话做不了事。
//  5. **只包住真的验密码那一支**：设置接口保存的是整页设置、更新接口配了公钥时不问密码，
//     这两条在被锁期间必须照常能用——闸要是提到处理器开头，"猜错几次密码"就会变成
//     "整页设置都存不了"，那是一道自己造出来的拒绝服务。
//
// 更新包上传那一条只在非 Windows 上进表：handleSelfUpdate 第一行就按平台回 501
//（Windows 换不掉正在运行的可执行文件），本机跑不到它那道复核（adminCredentialsOK 的
// 注释里记着同一件事）。CI 在 ubuntu 上跑，那一条在那里进表。
//
// 另外，这里的 Server 是手拼的壳子、**故意不填 reauthLimiter**：New 之外的构造路径也必须
// 拿得到一个真的计数器（见 Server.reauth）。哪天那个惰性创建被去掉，本文件会整片 nil panic。

// reauthFakeEnvelope 一份「长得像加密备份」的最小信封。
//
// 导入路径上的身份校验排在 IsEncryptedEnvelope 之后、DecryptBackup 之前（见
// handleImportConfig），所以要走到那一支，文件只需要过 encrypted+cipher 这两个字段的探测，
// 密文本身不必是真的——省掉一次真备份的导出与 60 万次 PBKDF2。
const reauthFakeEnvelope = `{"encrypted":true,"cipher":"AAAA"}`

// reauthTestLoginMaxFails 本文件那台面板的登录锁定次数。harness 与断言共用一个数，
// 免得哪天有人调了 harness 却让「登录该锁了」那条断言在别的次数上空跑。
const reauthTestLoginMaxFails = 5

// newReauthTestServer 造一个足以跑通那几条路 + handleLogin 的壳子。
func newReauthTestServer(t *testing.T) *Server {
	t.Helper()
	gin.SetMode(gin.TestMode)
	manager := config.NewManager(filepath.Join(t.TempDir(), "config.json"))
	if err := manager.Load(); err != nil {
		t.Fatal(err)
	}
	hash, err := auth.HashPassword(testLoginPass)
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.Update(func(c *config.Config) {
		c.Auth.Initialized = true
		c.Auth.Username = testLoginUser
		c.Auth.PasswordHash = hash
	}); err != nil {
		t.Fatal(err)
	}
	s := &Server{
		deps: Deps{Config: manager, Log: logx.New(logx.Options{}), DataDir: t.TempDir()},
		// 登录限流**开着**（5 次即锁），性质 4 那两条才有内容：关掉它的话，
		// 无论两份计数有没有串味，登录都不会返回 429，断言会变成假通过。
		limiter:  newLoginLimiter(reauthTestLoginMaxFails, time.Minute, time.Minute),
		sessions: newSessionRegistry(),
	}
	t.Cleanup(s.sessions.close)
	return s
}

// callWithSession 用指定会话令牌调一次处理函数。token 为空表示不带 Cookie。
func callWithSession(t *testing.T, h gin.HandlerFunc, path, contentType, body, token string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("Content-Type", contentType)
	return sendWithSession(t, h, req, token)
}

// sendWithSession 把一个已经造好的请求按指定会话令牌送进处理函数。
// 更新包上传那条路的请求体借现成的 newUpdateUploadRequest 造（字段顺序有讲究），
// 所以这里收的是整个请求而不是几个零件。
//
// 令牌值必须是纯 ASCII，函数里当场验一遍：http.Request.AddCookie 会**静默丢掉**
// Cookie 值里的非法字节（非 ASCII 一律算），于是 "令牌-甲" 和 "令牌-乙" 会同时塌成 "-"。
// 那样"两条不同会话"的断言就变成了同一条会话，看起来还照样通过。
func sendWithSession(t *testing.T, h gin.HandlerFunc, req *http.Request, token string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(rec)
	ctx.Request = req
	if token != "" {
		req.AddCookie(&http.Cookie{Name: sessionCookie, Value: token})
		if got := req.Header.Get("Cookie"); !strings.Contains(got, sessionCookie+"="+token) {
			t.Fatalf("会话令牌 %q 被 AddCookie 改写成了 %q，测试前提不成立（令牌值只能用 ASCII）", token, got)
		}
	}
	h(ctx)
	return rec
}

// setUnsignedWindow 开/关「允许未验签的更新包」的有效窗口。
//
// 表里那两条更新相关的路要的状态正好相反：设置那条只在「从没有有效窗口到有」的那一次提交上
// 验密码（窗口已经开着就不再问），上传那条则要窗口开着才走得到密码这一步（否则
// unsignedUpdateBlocked 先把它挡了）。所以谁也不能依赖初始状态，各自发请求之前自己摆一次。
func setUnsignedWindow(t *testing.T, s *Server, open bool) {
	t.Helper()
	if err := s.deps.Config.Update(func(c *config.Config) {
		c.Update.AllowUnsignedUpdate = open
		if open {
			c.Update.AllowUnsignedSince = freshWindowStart()
		} else {
			c.Update.AllowUnsignedSince = 0
		}
	}); err != nil {
		t.Fatal(err)
	}
}

// reauthImportBody 拼一份导入请求体：文件是假信封，authAccount/authPassword 由调用方给。
func reauthImportBody(t *testing.T, authAccount, authPassword string) (string, string) {
	t.Helper()
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	part, err := w.CreateFormFile("file", "Mantou-backup.json")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := part.Write([]byte(reauthFakeEnvelope)); err != nil {
		t.Fatal(err)
	}
	for k, v := range map[string]string{"authAccount": authAccount, "authPassword": authPassword} {
		if err := w.WriteField(k, v); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return w.FormDataContentType(), buf.String()
}

// reauthRoute 是「已登录后再验一次当前密码」的一条路。
// send 发一次注定失败的请求，wantFail 是它没被锁时该给的状态码。
//
// 这几条路的失败码刻意不统一（改账户 401、其余 403），这里如实抄下来：
// 加计数这件事不许顺手改动任何一处原有的状态码与文案，那会牵动前端拦截器的行为。
type reauthRoute struct {
	name     string
	send     func(t *testing.T, s *Server, token string) *httptest.ResponseRecorder
	wantFail int
}

// reauthRoutes 共用这份计数的几条路。失败原因尽量取「账户名不对」而不是「密码不对」：
// 那一支在 bcrypt 之前就短路了，跑一轮 15 次不必付 15 次哈希的代价。
// 改账户没有账户名这一栏，只能走真的 bcrypt——顺带让这一轮里至少有一次是真验密码。
func reauthRoutes() []reauthRoute {
	routes := []reauthRoute{
		{name: "预检", wantFail: http.StatusForbidden, send: func(t *testing.T, s *Server, token string) *httptest.ResponseRecorder {
			return callWithSession(t, s.handleVerifyIdentity, "/api/auth/verify", "application/json",
				`{"account":"不是这台面板的账户","password":"随便"}`, token)
		}},
		{name: "加密导出", wantFail: http.StatusForbidden, send: func(t *testing.T, s *Server, token string) *httptest.ResponseRecorder {
			return callWithSession(t, s.handleExportConfig, "/api/settings/export", "application/json",
				`{"account":"不是这台面板的账户","password":"随便"}`, token)
		}},
		{name: "改账户", wantFail: http.StatusUnauthorized, send: func(t *testing.T, s *Server, token string) *httptest.ResponseRecorder {
			return callWithSession(t, s.handleChangeAccount, "/api/auth/account", "application/json",
				`{"oldPassword":"不是当前密码","newPassword":"新密码-够长了"}`, token)
		}},
		{name: "导入", wantFail: http.StatusForbidden, send: func(t *testing.T, s *Server, token string) *httptest.ResponseRecorder {
			ct, body := reauthImportBody(t, "不是这台面板的账户", "随便")
			return callWithSession(t, s.handleImportConfig, "/api/settings/import", ct, body, token)
		}},
		{name: "开未验签开关", wantFail: http.StatusForbidden, send: func(t *testing.T, s *Server, token string) *httptest.ResponseRecorder {
			setUnsignedWindow(t, s, false) // 窗口开着的话这次提交不算"打开"，根本不验密码
			return callWithSession(t, s.handleUpdateSettings, "/api/settings", "application/json",
				`{"update":{"allowUnsignedUpdate":true,"account":"不是这台面板的账户","password":"随便"}}`, token)
		}},
	}
	// 未验签的更新包上传：Windows 上处理器第一行就回 501，进不了表（见文件头）。
	if runtime.GOOS != "windows" {
		routes = append(routes, reauthRoute{name: "未验签上传", wantFail: http.StatusForbidden,
			send: func(t *testing.T, s *Server, token string) *httptest.ResponseRecorder {
				setUnsignedWindow(t, s, true) // 与上一条相反：窗口得开着才走得到密码那一步
				req := newUpdateUploadRequest(t, "不是真的更新包",
					updateUploadField{"account", "不是这台面板的账户"}, updateUploadField{"password", "随便"})
				return sendWithSession(t, s.handleSelfUpdate, req, token)
			}})
	}
	return routes
}

// wantLocked 断言这条响应是被计数拦下的 429，且带了一个能用的 Retry-After。
//
// 429 而不是 401/403 是刻意的（见 reauthAllowed）：401 会被前端拦截器当成会话失效、
// 把人强制登出，而这里的会话是好的；403 会被读成"密码又错了"，于是用户一直重试，
// 把锁定时间白白耗过去。
func wantLocked(t *testing.T, rec *httptest.ResponseRecorder, where string) {
	t.Helper()
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("%s：状态码是 %d，期望 429（%s）", where, rec.Code, rec.Body.String())
	}
	raw := rec.Header().Get("Retry-After")
	if retry, err := strconv.Atoi(raw); err != nil || retry <= 0 {
		t.Fatalf("%s：Retry-After 是 %q，期望一个正整数秒数（%v）", where, raw, err)
	}
}

// TestReauthCounterIsSharedAcrossPasswordChecks 这几条路共用一份计数，且锁的是会话本身。
func TestReauthCounterIsSharedAcrossPasswordChecks(t *testing.T) {
	s := newReauthTestServer(t)
	const token = "token-current-session"
	s.sessions.add(token, testLoginUser, time.Hour)

	routes := reauthRoutes()
	// 轮着来：15 次摊到五六条路上，每条最多 3 次，没有哪一条自己够 15 次。
	// 计数若按路由分开，这一轮跑完一次都不会锁。
	for i := 0; i < reauthMaxFails; i++ {
		r := routes[i%len(routes)]
		rec := r.send(t, s, token)
		if rec.Code != r.wantFail {
			t.Fatalf("第 %d 次（%s）状态码是 %d，期望 %d（%s）", i+1, r.name, rec.Code, r.wantFail, rec.Body.String())
		}
	}
	// 第 15 次就是触发锁定那一次，此后这几条路一起闭门。
	for _, r := range routes {
		wantLocked(t, r.send(t, s, token), "锁定后的"+r.name)
	}
	// 顺带钉住这道闸在导入路径上的位置：请求体连 multipart 都不是，锁着的时候仍该是 429。
	// 哪天 reauthAllowed 被挪到 readImportUpload 之后，这里会变成 400——那意味着一条
	// 已经被锁住的会话还能先把 128 MB 传上来（见 handleImportConfig 顶部那句注释）。
	wantLocked(t, callWithSession(t, s.handleImportConfig, "/api/settings/import",
		"application/json", "根本不是 multipart", token), "锁定后的导入（坏请求体）")

	// 按会话记：换一条令牌，这几条路照旧给各自的失败码。
	// 若键取的是账户名或来源 IP，这里会跟着变成 429——那样任何能故意失败几次的人
	// 都能把真正的管理员挡在敏感操作外面。
	const other = "token-another-session"
	s.sessions.add(other, testLoginUser, time.Hour)
	for _, r := range routes {
		rec := r.send(t, s, other)
		if rec.Code != r.wantFail {
			t.Fatalf("另一条会话的%s状态码是 %d，期望 %d（%s）", r.name, rec.Code, r.wantFail, rec.Body.String())
		}
	}
}

// TestReauthCounterClearedByCorrectPassword 一次正确的密码把这条会话的失败史清掉。
func TestReauthCounterClearedByCorrectPassword(t *testing.T) {
	s := newReauthTestServer(t)
	const token = "token-typo-session"
	s.sessions.add(token, testLoginUser, time.Hour)
	routes := reauthRoutes()

	failTimes := func(n int, tag string) {
		t.Helper()
		for i := 0; i < n; i++ {
			r := routes[i%len(routes)]
			rec := r.send(t, s, token)
			if rec.Code != r.wantFail {
				t.Fatalf("%s第 %d 次（%s）状态码是 %d，期望 %d（%s）", tag, i+1, r.name, rec.Code, r.wantFail, rec.Body.String())
			}
		}
	}
	// 差一次就锁。
	failTimes(reauthMaxFails-1, "清零前")
	rec := callWithSession(t, s.handleVerifyIdentity, "/api/auth/verify", "application/json",
		`{"account":"`+testLoginUser+`","password":"`+testLoginPass+`"}`, token)
	if rec.Code != http.StatusOK {
		t.Fatalf("正确密码的预检状态码是 %d，期望 200（%s）", rec.Code, rec.Body.String())
	}
	// 账真清了：又是 14 次都不该锁。没清的话这一轮的第 1 次就凑满 15、
	// 第 2 次起就是 429，跑不到头。
	failTimes(reauthMaxFails-1, "清零后")
	// 而第 15 次照旧锁——清零清的是账，不是规则。
	last := routes[(reauthMaxFails-1)%len(routes)]
	if rec := last.send(t, s, token); rec.Code != last.wantFail {
		t.Fatalf("第 %d 次（%s）状态码是 %d，期望 %d（%s）", reauthMaxFails, last.name, rec.Code, last.wantFail, rec.Body.String())
	}
	wantLocked(t, routes[0].send(t, s, token), "清零后又打满的预检")
}

// TestReauthLockDoesNotLockOutLogin 会话那侧被锁，不许连带把人挡在登录页外面。
func TestReauthLockDoesNotLockOutLogin(t *testing.T) {
	s := newReauthTestServer(t)
	const token = "token-stolen-session"
	s.sessions.add(token, testLoginUser, time.Hour)

	routes := reauthRoutes()
	for i := 0; i < reauthMaxFails; i++ {
		routes[i%len(routes)].send(t, s, token)
	}
	wantLocked(t, routes[0].send(t, s, token), "打满之后的预检")

	// 那 15 次不许记进登录限流。记进去了的话下面这次会是 429（登录那侧 5 次就锁），
	// 于是一条被盗的会话就能把真正的管理员挡在登录页外面——而面板往往是他恢复访问的唯一入口。
	rec := callWithSession(t, s.handleLogin, "/api/auth/login", "application/json",
		`{"username":"猜错的账户","password":"猜错的密码"}`, "")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("失败登录的状态码是 %d，期望 401（%s）", rec.Code, rec.Body.String())
	}
	// 正门也照旧开着：管理员退出再登一次就是一条新会话、一份干净的计数。
	rec = callWithSession(t, s.handleLogin, "/api/auth/login", "application/json", testLoginBody, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("正确凭据登录的状态码是 %d，期望 200（%s）", rec.Code, rec.Body.String())
	}
}

// TestLoginLockDoesNotBlockReauth 反方向也不许串：登录被锁住，手上这条好会话照样能做敏感操作。
func TestLoginLockDoesNotBlockReauth(t *testing.T) {
	s := newReauthTestServer(t)
	const token = "token-admin-session"
	s.sessions.add(token, testLoginUser, time.Hour)

	// 把登录那侧打到锁定。账户名取个错的：那一支在 bcrypt 之前就短路。
	for i := 0; i < reauthTestLoginMaxFails; i++ {
		rec := callWithSession(t, s.handleLogin, "/api/auth/login", "application/json",
			`{"username":"猜错的账户","password":"猜错的密码"}`, "")
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("第 %d 次登录的状态码是 %d，期望 401（%s）", i+1, rec.Code, rec.Body.String())
		}
	}
	rec := callWithSession(t, s.handleLogin, "/api/auth/login", "application/json", testLoginBody, "")
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("登录锁定后的状态码是 %d，期望 429（%s）", rec.Code, rec.Body.String())
	}
	rec = callWithSession(t, s.handleVerifyIdentity, "/api/auth/verify", "application/json",
		`{"account":"`+testLoginUser+`","password":"`+testLoginPass+`"}`, token)
	if rec.Code != http.StatusOK {
		t.Fatalf("登录被锁期间的预检状态码是 %d，期望 200（%s）", rec.Code, rec.Body.String())
	}
}

// TestReauthLockLeavesUnrelatedPathsAlone 被锁只锁"真的在验密码"那一支。
//
// 后加进这份计数的两条路都住在一个还管着别的事的处理器里：设置接口保存的是整页设置，
// 更新接口配了签名公钥时根本不问密码。闸要是从那两处的 if 里挪到处理器开头，
// "在某一处猜错 15 次密码"就会变成"整页设置都存不了、已配公钥的推包全失败"——
// 一道自己造出来的拒绝服务，而且它拦住的是本人（攻击者手上那条会话反正已经锁了）。
//
// 关掉未验签开关这一条尤其要紧：那是在收紧，任何时候都必须做得到。
func TestReauthLockLeavesUnrelatedPathsAlone(t *testing.T) {
	s := newReauthTestServer(t)
	const token = "token-locked-session"
	s.sessions.add(token, testLoginUser, time.Hour)

	routes := reauthRoutes()
	for i := 0; i < reauthMaxFails; i++ {
		routes[i%len(routes)].send(t, s, token)
	}
	wantLocked(t, routes[0].send(t, s, token), "打满之后的预检")

	// 同一个设置接口、同一个字段，但这次是关掉它：不验密码，也就不该被这份计数拦。
	rec := callWithSession(t, s.handleUpdateSettings, "/api/settings", "application/json",
		`{"update":{"allowUnsignedUpdate":false}}`, token)
	if rec.Code != http.StatusOK {
		t.Fatalf("被锁期间关闭未验签开关的状态码是 %d，期望 200（%s）", rec.Code, rec.Body.String())
	}
	if s.deps.Config.Snapshot().Update.AllowUnsignedUpdate {
		t.Fatal("接口回了 200，开关却还是开着")
	}

	// 配了公钥的更新包上传同理：那条路不问密码。它会一路走到解包
	//（那段假内容当然解不开），只要不是 429 就说明闸没拦它。
	if runtime.GOOS != "windows" {
		if err := s.deps.Config.Update(func(c *config.Config) { c.Update.SignKey = "dGVzdA==" }); err != nil {
			t.Fatal(err)
		}
		req := newUpdateUploadRequest(t, "不是真的更新包")
		if rec := sendWithSession(t, s.handleSelfUpdate, req, token); rec.Code == http.StatusTooManyRequests {
			t.Fatalf("配了公钥的上传被这份计数拦下了（%s）——那条路根本不问密码", rec.Body.String())
		}
	}
}
