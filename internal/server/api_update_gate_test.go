package server

import (
	"bytes"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"mantou/internal/auth"
	"mantou/internal/config"
	"mantou/internal/logx"
)

// 上传更新包的结果是面板拿一个新二进制把自己换掉。没有验签就没有任何环节能分辨
// 那个包是不是用户自己的，所以公钥留空时默认不收——想跳过验签得先自己在设置里
// 打开「允许未验签的更新包」（见 5-H）。
//
// 那个开关本身又是三道限制：打开要当场验密码、只在一段窗口内有效（过期自动失效）、
// 窗口内每次上传未验签的包还要再验一次密码；三件事各自都留了审计记录。
// 下面这组测试把这四样逐条钉住。

const (
	updateTestUser = "admin"
	updateTestPass = "correct-horse-battery-staple"
)

// updateTestHash 一份 bcrypt 哈希算一次就够：DefaultCost 下每次几十毫秒，
// 而这个文件里要造十几台测试面板，逐台算一遍够跑掉大半秒。
var updateTestHash = sync.OnceValue(func() string {
	h, err := auth.HashPassword(updateTestPass)
	if err != nil {
		panic(err)
	}
	return h
})

// newUpdateGateServer 造一台带管理员账户的测试面板，并按 mutate 调整「在线更新」那一段配置。
// 只注入 Config 与 Log：这批用例走到的几条路径不碰别的依赖。
func newUpdateGateServer(t *testing.T, mutate func(u *config.UpdateConfig)) *Server {
	t.Helper()
	gin.SetMode(gin.TestMode)
	cfg := config.NewManager(filepath.Join(t.TempDir(), "config.json"))
	if err := cfg.Load(); err != nil {
		t.Fatal(err)
	}
	if err := cfg.Update(func(c *config.Config) {
		c.Auth.Initialized = true
		c.Auth.Username = updateTestUser
		c.Auth.PasswordHash = updateTestHash()
		if mutate != nil {
			mutate(&c.Update)
		}
	}); err != nil {
		t.Fatal(err)
	}
	return &Server{deps: Deps{Config: cfg, Log: logx.New(logx.Options{})}}
}

// 造窗口用的两个时刻：刚打开（窗口有效）与早已过期。
// 过期那个多减一分钟，免得踩在边界上让用例的结论取决于这一次跑得多快。
func freshWindowStart() int64 {
	return time.Now().Add(-time.Minute).Unix()
}

func expiredWindowStart() int64 {
	return time.Now().Add(-config.AllowUnsignedUpdateTTL - time.Minute).Unix()
}

// updateUploadField 上传请求里的一个表单字段。
type updateUploadField struct{ name, value string }

// newUpdateUploadRequest 造一个与前端一致的 multipart 上传请求（文件字段名 file）。
//
// 字段一律写在 file **之前**：后端是流式消费 multipart 的（不把整个包收进内存），
// 取到 file 那一部分就开始解包，排在它后面的字段读不到——见 multipartFilePartFields。
// 前端 About.vue 里的 append 顺序与这里一致，两边必须同时是这个顺序，
// 所以这个 helper 不提供"把字段写在后面"的选项：那种请求根本不该被造出来当成合法输入。
func newUpdateUploadRequest(t *testing.T, content string, fields ...updateUploadField) *http.Request {
	t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	for _, f := range fields {
		if err := mw.WriteField(f.name, f.value); err != nil {
			t.Fatal(err)
		}
	}
	part, err := mw.CreateFormFile("file", "mantou.tar.gz")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := part.Write([]byte(content)); err != nil {
		t.Fatal(err)
	}
	if err := mw.Close(); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/meta/self-update", &buf)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	return req
}

// adminUploadFields 一对正确的管理员凭据，按上传接口要的字段名给出。
func adminUploadFields() []updateUploadField {
	return []updateUploadField{{"account", updateTestUser}, {"password", updateTestPass}}
}

// postSelfUpdate 把一次上传请求送进处理器，返回状态码与响应体。
func postSelfUpdate(t *testing.T, s *Server, content string, fields ...updateUploadField) (int, string) {
	t.Helper()
	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	ctx.Request = newUpdateUploadRequest(t, content, fields...)
	s.handleSelfUpdate(ctx)
	return w.Code, w.Body.String()
}

// settingsUpdateSection 读一次设置，返回响应体里 update 那一段。
func settingsUpdateSection(t *testing.T, s *Server) map[string]any {
	t.Helper()
	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	ctx.Request = httptest.NewRequest(http.MethodGet, "/settings", nil)
	s.handleGetSettings(ctx)
	if w.Code != http.StatusOK {
		t.Fatalf("读设置失败（%d）：%s", w.Code, w.Body.String())
	}
	return jsonSection(t, w.Body.Bytes(), "update")
}

// jsonSection 从 respondOK 的 {"data":{…}} 信封里取出一段对象。
func jsonSection(t *testing.T, body []byte, key string) map[string]any {
	t.Helper()
	var envelope struct {
		Data map[string]json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		t.Fatalf("响应不是合法 JSON：%v（%s）", err, body)
	}
	raw, ok := envelope.Data[key]
	if !ok {
		t.Fatalf("响应里没有 %q 这一段：%s", key, body)
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("%q 这一段不是对象：%v", key, err)
	}
	return out
}

// jsonNum 取一个数值字段（encoding/json 把 JSON 数字解成 float64）。
func jsonNum(t *testing.T, m map[string]any, key string) int64 {
	t.Helper()
	v, ok := m[key]
	if !ok {
		t.Fatalf("响应里没有 %q 字段：%v", key, m)
	}
	f, ok := v.(float64)
	if !ok {
		t.Fatalf("%q 不是数值，而是 %T", key, v)
	}
	return int64(f)
}

// jsonBool 取一个布尔字段。
func jsonBool(t *testing.T, m map[string]any, key string) bool {
	t.Helper()
	v, ok := m[key]
	if !ok {
		t.Fatalf("响应里没有 %q 字段：%v", key, m)
	}
	b, ok := v.(bool)
	if !ok {
		t.Fatalf("%q 不是布尔值，而是 %T", key, v)
	}
	return b
}

// findLogEntry 在最近的日志里找第一条消息含 want 的记录。
// 审计记录要真的断言，不能只看接口返回：这几条日志是事后排查时唯一的线索，
// 而"忘了记"与"记漏一个字段"都不会让任何接口失败。
func findLogEntry(l *logx.Logger, want string) (logx.Entry, bool) {
	for _, e := range l.Recent(200) {
		if strings.Contains(e.Message, want) {
			return e, true
		}
	}
	return logx.Entry{}, false
}

// logFieldStr 取一条日志里某个字段的字符串值。
func logFieldStr(e logx.Entry, key string) (string, bool) {
	for _, f := range e.Fields {
		if f.Key != key {
			continue
		}
		s, ok := f.Val.(string)
		return s, ok
	}
	return "", false
}

// mustLogEntry 断言存在这样一条日志，并顺带核对级别。
func mustLogEntry(t *testing.T, l *logx.Logger, want, level string) logx.Entry {
	t.Helper()
	e, ok := findLogEntry(l, want)
	if !ok {
		t.Fatalf("没有记下含 %q 的日志，事后无从排查", want)
	}
	if !strings.EqualFold(e.Level, level) {
		t.Fatalf("含 %q 的那条日志级别是 %s，期望 %s", want, e.Level, level)
	}
	return e
}

// TestUnsignedUpdateBlockedStates 各种「公钥 × 开关 × 窗口」的组合各该是什么结论，
// 以及拒收时对用户说的那句话该指向哪儿——两种拒绝的下一步动作不同，
// 一个是"去打开"，一个是"再打开一次"，措辞混了用户就照着错的那条去做。
func TestUnsignedUpdateBlockedStates(t *testing.T) {
	now := time.Now()
	cases := []struct {
		name        string
		u           config.UpdateConfig
		wantBlocked bool
		wantMsg     string
	}{
		// 这一条是默认状态：全新装起来的面板收不了更新包。
		{"公钥留空、开关关闭", config.UpdateConfig{}, true, "未配置更新包签名公钥"},
		{"公钥留空、窗口有效", config.UpdateConfig{
			AllowUnsignedUpdate: true, AllowUnsignedSince: freshWindowStart(),
		}, false, ""},
		// 过期与从未打开分开措辞：这条要让用户知道去重新打开，而不是以为自己没配公钥。
		{"公钥留空、窗口已过期", config.UpdateConfig{
			AllowUnsignedUpdate: true, AllowUnsignedSince: expiredWindowStart(),
		}, true, "有效期"},
		// 开关为真但没有起点：一份手改过或从旧版本导入的配置就是这个样子，按不放行处理。
		{"公钥留空、开关开着但没记起点", config.UpdateConfig{AllowUnsignedUpdate: true}, true, "未配置更新包签名公钥"},
		{"配了公钥、开关关闭", config.UpdateConfig{SignKey: "dGVzdA=="}, false, ""},
		// 配了公钥时这个开关与窗口都不起作用：有公钥就一律验签，窗口只管"没有公钥怎么办"。
		{"配了公钥、窗口有效", config.UpdateConfig{
			SignKey: "dGVzdA==", AllowUnsignedUpdate: true, AllowUnsignedSince: freshWindowStart(),
		}, false, ""},
		{"配了公钥、窗口已过期", config.UpdateConfig{
			SignKey: "dGVzdA==", AllowUnsignedUpdate: true, AllowUnsignedSince: expiredWindowStart(),
		}, false, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			blocked, msg := unsignedUpdateBlocked(tc.u, now)
			if blocked != tc.wantBlocked {
				t.Fatalf("期望 blocked=%v，实际 %v（%s）", tc.wantBlocked, blocked, msg)
			}
			if !blocked {
				if msg != "" {
					t.Fatalf("放行时不该给拒绝理由，实际 %q", msg)
				}
				return
			}
			if !strings.Contains(msg, tc.wantMsg) {
				t.Fatalf("拒绝理由应包含 %q，实际 %q", tc.wantMsg, msg)
			}
		})
	}
}

// TestUnsignedUpdateBlockedTreatsBlankKeyAsUnset 只有空白字符的公钥算没填。
//
// 与 handleSelfUpdate 里那次 TrimSpace 是同一个口径：一串空格通不过验签
// （base64 解不出 32 字节），若在这里算"填了"，就会走进"必须验签"的分支，
// 结果是任何包都被拒，而用户看到的是一句签名校验失败——查不到原因。
func TestUnsignedUpdateBlockedTreatsBlankKeyAsUnset(t *testing.T) {
	blocked, msg := unsignedUpdateBlocked(config.UpdateConfig{SignKey: "   \t\n"}, time.Now())
	if !blocked {
		t.Fatal("只有空白字符的公钥应视为没填，默认不接收更新包")
	}
	if !strings.Contains(msg, "未配置更新包签名公钥") {
		t.Fatalf("拒绝理由应指向没配公钥，实际 %q", msg)
	}
}

// TestAdminCredentialsOK 两处复核共用的那道判断。
//
// 单独测它是因为上传那条路在 Windows 上跑不到（handleSelfUpdate 第一行就返回 501），
// 而这道判断是那条路上唯一的第二因素——它错了整个开关的限制就形同不存在。
func TestAdminCredentialsOK(t *testing.T) {
	a := config.Auth{Username: updateTestUser, PasswordHash: updateTestHash()}
	cases := []struct {
		name     string
		a        config.Auth
		account  string
		password string
		want     bool
	}{
		{"账户与密码都对", a, updateTestUser, updateTestPass, true},
		// 账户名首尾的空格是误触，不该因此拒绝；密码里的空格是密码本身的一部分，碰不得。
		{"账户名带首尾空格", a, "  " + updateTestUser + "\t", updateTestPass, true},
		{"密码带首尾空格", a, updateTestUser, " " + updateTestPass, false},
		{"密码不对", a, updateTestUser, "wrong-pass", false},
		{"账户不对", a, "root", updateTestPass, false},
		{"两个都空", a, "", "", false},
		// 尚未初始化的配置（用户名与哈希都是空串）一律不放行：否则空账户空密码就能过。
		{"配置尚未初始化", config.Auth{}, "", "", false},
		{"哈希是空串", config.Auth{Username: updateTestUser}, updateTestUser, "", false},
		// 配置里存的不是哈希而是明文（手改过 config.json）：也不能放行，
		// 否则一份被改坏的配置会变成一个后门。
		{"哈希位置存的是明文", config.Auth{
			Username: updateTestUser, PasswordHash: updateTestPass,
		}, updateTestUser, updateTestPass, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := adminCredentialsOK(tc.a, tc.account, tc.password); got != tc.want {
				t.Fatalf("期望 %v，实际 %v", tc.want, got)
			}
		})
	}
}

// TestUpdateAuditRecord「即将覆盖二进制」那条记录的级别、措辞与字段。
//
// 走到调用它那一行需要一个真能跑起来的同架构二进制和一次真的文件覆盖，
// 单元测试里做不到；而这条记录少任何一项，都要等到某次事后排查时才会发现"当初没记下来"。
func TestUpdateAuditRecord(t *testing.T) {
	const (
		op     = "admin"
		ip     = "203.0.113.9"
		exe    = "mantou"
		digest = "0f1e2d3c"
		arch   = "amd64"
	)
	for _, tc := range []struct {
		sigState  string
		wantWarn  bool
		wantInMsg string
	}{
		// 验签通过是常规路径，记 Info；未验签是一次主动放宽，在日志里该更显眼。
		{updateSigVerified, false, "已通过签名校验"},
		{updateSigUnsigned, true, "未验签"},
	} {
		t.Run(tc.sigState, func(t *testing.T) {
			warn, msg, args := updateAuditRecord(op, ip, exe, digest, tc.sigState, arch)
			if warn != tc.wantWarn {
				t.Fatalf("期望 warn=%v，实际 %v", tc.wantWarn, warn)
			}
			if !strings.Contains(msg, tc.wantInMsg) {
				t.Fatalf("消息应包含 %q，实际 %q", tc.wantInMsg, msg)
			}
			// 一条日志要能独立回答「谁、从哪、装了什么、验没验签」四个问题——
			// 事后翻日志的人手上只有这一行。
			want := map[string]string{
				"exe": exe, "operator": op, "ip": ip,
				"sha256": digest, "signature": tc.sigState, "arch": arch,
			}
			if len(args) != len(want)*2 {
				t.Fatalf("字段数不对：%v", args)
			}
			for i := 0; i+1 < len(args); i += 2 {
				key, _ := args[i].(string)
				exp, ok := want[key]
				if !ok {
					t.Fatalf("多了一个字段 %q", key)
				}
				if got, _ := args[i+1].(string); got != exp {
					t.Fatalf("字段 %s 的值是 %q，期望 %q", key, got, exp)
				}
				delete(want, key)
			}
			if len(want) != 0 {
				t.Fatalf("这些字段没记：%v", want)
			}
		})
	}
}

// skipOnWindows 上传那条路在 Windows 上第一行就返回 501，本机跑不到后面的判断。
// 那些判断本身另有平台无关的用例（TestUnsignedUpdateBlockedStates、
// TestAdminCredentialsOK），这里只是不在 Windows 上重复走一遍处理器。
func skipOnWindows(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("Windows 不支持在线覆盖更新")
	}
}

// TestSelfUpdateRefusedWithoutSignKey 默认配置下上传更新包被拒，且拒在读请求体之前。
func TestSelfUpdateRefusedWithoutSignKey(t *testing.T) {
	skipOnWindows(t)
	s := newUpdateGateServer(t, nil)
	// 前提：默认配置就是"公钥留空、开关关闭"。
	if snap := s.deps.Config.Snapshot(); snap.Update.SignKey != "" || snap.Update.AllowUnsignedUpdate {
		t.Fatalf("测试前提不成立：默认配置已经允许未验签更新（signKey=%q allow=%v）",
			snap.Update.SignKey, snap.Update.AllowUnsignedUpdate)
	}

	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	ctx.Request = newUpdateUploadRequest(t, "不是真的更新包")
	bodyLen := ctx.Request.ContentLength
	if bodyLen <= 0 {
		t.Fatalf("测试前提不成立：请求体长度是 %d，下面那条断言就没有意义了", bodyLen)
	}

	s.handleSelfUpdate(ctx)

	if w.Code != http.StatusForbidden {
		t.Fatalf("期望 %d，实际 %d：%s", http.StatusForbidden, w.Code, w.Body.String())
	}
	// 报的必须是"没配公钥"，不能是"解析失败"。
	if body := w.Body.String(); !strings.Contains(body, "签名公钥") {
		t.Fatalf("拒绝原因应指向签名公钥，实际：%s", body)
	}
	// 请求体必须一个字节都没被读过：这道判断要拦在读之前，否则一个注定被拒的请求
	// 仍然能让面板收下整个包（上限 32MB）。直接量"还剩多少没读"，比看文案实在。
	rest, err := io.ReadAll(ctx.Request.Body)
	if err != nil {
		t.Fatal(err)
	}
	if int64(len(rest)) != bodyLen {
		t.Fatalf("请求体已被读掉 %d 字节，这道判断应该拦在读之前", bodyLen-int64(len(rest)))
	}
}

// TestSelfUpdateRefusedAfterWindowExpired 窗口过期即自动失效，且同样拦在读请求体之前。
//
// 这是把「一个开关」改成「一段窗口」的全部意义：开关一开就再也不会自己关上，
// 而那扇门后面是"面板执行任意二进制"。到期不用任何后台任务，纯算出来的。
func TestSelfUpdateRefusedAfterWindowExpired(t *testing.T) {
	skipOnWindows(t)
	s := newUpdateGateServer(t, func(u *config.UpdateConfig) {
		u.AllowUnsignedUpdate = true
		u.AllowUnsignedSince = expiredWindowStart()
	})

	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	ctx.Request = newUpdateUploadRequest(t, "不是真的更新包", adminUploadFields()...)
	bodyLen := ctx.Request.ContentLength

	s.handleSelfUpdate(ctx)

	if w.Code != http.StatusForbidden {
		t.Fatalf("过期的窗口应当拒收，实际 %d：%s", w.Code, w.Body.String())
	}
	// 密码给对了也没用：这一条要能与"密码错"区分开，否则用户会反复去改密码。
	if body := w.Body.String(); !strings.Contains(body, "有效期") {
		t.Fatalf("拒绝原因应指向有效期，实际：%s", body)
	}
	rest, err := io.ReadAll(ctx.Request.Body)
	if err != nil {
		t.Fatal(err)
	}
	if int64(len(rest)) != bodyLen {
		t.Fatalf("请求体已被读掉 %d 字节，过期这一支也该拦在读之前", bodyLen-int64(len(rest)))
	}
}

// TestSelfUpdateUnsignedRequiresPassword 窗口开着也不够：每次上传未验签的包都要当场再验一次密码。
//
// 少了这一道，窗口期内一条被盗的会话照样能把面板二进制换掉——那次打开开关时验的密码
// 只证明了"打开它的人是本人"，证明不了此刻上传这个包的人是谁。
func TestSelfUpdateUnsignedRequiresPassword(t *testing.T) {
	skipOnWindows(t)
	window := func(u *config.UpdateConfig) {
		u.AllowUnsignedUpdate = true
		u.AllowUnsignedSince = freshWindowStart()
	}

	t.Run("不带凭据", func(t *testing.T) {
		s := newUpdateGateServer(t, window)
		code, body := postSelfUpdate(t, s, "不是真的更新包")
		if code != http.StatusForbidden {
			t.Fatalf("没给凭据就该拒收，实际 %d：%s", code, body)
		}
		if !strings.Contains(body, "账户或密码错误") {
			t.Fatalf("拒绝原因应指向凭据，实际：%s", body)
		}
		// 401 会让前端拦截器强制登出跳登录页，而这里只是这一次操作的凭据没对上。
		if code == http.StatusUnauthorized {
			t.Fatal("不能回 401：那会把用户踢回登录页")
		}
		// 拒绝也要留痕：这是"有人在拿着一条会话试着换掉二进制"的唯一线索。
		e := mustLogEntry(t, s.deps.Log, "身份复核失败", "WARN")
		if v, _ := logFieldStr(e, "exe"); v == "" {
			t.Fatalf("这条日志少了 exe 字段：%v", e.Fields)
		}
	})

	t.Run("密码不对", func(t *testing.T) {
		s := newUpdateGateServer(t, window)
		code, body := postSelfUpdate(t, s, "不是真的更新包",
			updateUploadField{"account", updateTestUser}, updateUploadField{"password", "wrong-pass"})
		if code != http.StatusForbidden {
			t.Fatalf("密码不对就该拒收，实际 %d：%s", code, body)
		}
	})

	t.Run("账户不对", func(t *testing.T) {
		s := newUpdateGateServer(t, window)
		code, body := postSelfUpdate(t, s, "不是真的更新包",
			updateUploadField{"account", "root"}, updateUploadField{"password", updateTestPass})
		if code != http.StatusForbidden {
			t.Fatalf("账户不对就该拒收，实际 %d：%s", code, body)
		}
	})

	// 凭据对了就放行到解包那一步。只验"不再是 403"：放行之后走的是解包、架构校验、
	// 冒烟测试那条长链路，拿一段假内容进去必然失败，那些是别的测试的事。
	t.Run("凭据正确", func(t *testing.T) {
		s := newUpdateGateServer(t, window)
		code, body := postSelfUpdate(t, s, "不是真的更新包", adminUploadFields()...)
		if code == http.StatusForbidden {
			t.Fatalf("凭据正确不该被拦，实际：%s", body)
		}
		if !strings.Contains(body, "更新包解析失败") {
			t.Fatalf("应当已经走到解包那一步，实际：%s", body)
		}
	})
}

// TestSelfUpdateSignedSkipsPassword 配了公钥就不再问密码：签名本身即授权。
//
// 拿不到私钥的人做不出能通过验签的包，再问一次密码只是给用户添一道手续。
// 这一条同时护住反方向的改动——把第二因素改成"一律要求"会让所有已配公钥的
// 自动化更新流程（CI 推包）在没有人输密码的地方全部失败。
func TestSelfUpdateSignedSkipsPassword(t *testing.T) {
	skipOnWindows(t)
	s := newUpdateGateServer(t, func(u *config.UpdateConfig) {
		u.SignKey = "dGVzdA=="
	})

	code, body := postSelfUpdate(t, s, "不是真的更新包")
	if code == http.StatusForbidden {
		t.Fatalf("配了公钥的这条路不该问密码，实际：%s", body)
	}
	if !strings.Contains(body, "更新包解析失败") {
		t.Fatalf("应当已经走到解包那一步，实际：%s", body)
	}
}

// 下面这几支走的是设置接口，没有平台限制（handleUpdateSettings 不分 GOOS），
// 因此在 Windows 上也会真的跑。

// TestUpdateSettingsEnableRequiresPassword 打开这个开关要当场验一次密码，验不过则一个字段都不落盘。
func TestUpdateSettingsEnableRequiresPassword(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
	}{
		{"不带凭据", `{"update":{"allowUnsignedUpdate":true}}`},
		{"密码不对", `{"update":{"allowUnsignedUpdate":true,"account":"admin","password":"wrong-pass"}}`},
		{"账户不对", `{"update":{"allowUnsignedUpdate":true,"account":"root","password":"` + updateTestPass + `"}}`},
		// 备份口令与管理员密码是两套不同的凭据，这里只认后者。
		{"只给了账户", `{"update":{"allowUnsignedUpdate":true,"account":"admin"}}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newUpdateGateServer(t, nil)
			w := putSettings(t, s, tc.body)
			if w.Code != http.StatusForbidden {
				t.Fatalf("凭据不对就该拒绝，实际 %d：%s", w.Code, w.Body.String())
			}
			if !strings.Contains(w.Body.String(), "账户或密码错误") {
				t.Fatalf("拒绝原因应指向凭据，实际：%s", w.Body.String())
			}
			// 拒绝这一次不能留下半个状态：开关没开、起点也没记。
			snap := s.deps.Config.Snapshot()
			if snap.Update.AllowUnsignedUpdate || snap.Update.AllowUnsignedSince != 0 {
				t.Fatalf("被拒的提交仍写进了配置：allow=%v since=%d",
					snap.Update.AllowUnsignedUpdate, snap.Update.AllowUnsignedSince)
			}
			mustLogEntry(t, s.deps.Log, "身份复核失败", "WARN")
		})
	}
}

// TestUpdateSettingsEnablePersistsWindow 凭据正确时开关与起点一起落盘，
// 响应里带回算好的窗口，并留下一条带到期时刻的审计记录。
func TestUpdateSettingsEnablePersistsWindow(t *testing.T) {
	s := newUpdateGateServer(t, nil)
	before := time.Now().Unix()
	w := putSettings(t, s, `{"update":{"allowUnsignedUpdate":true,"account":"`+updateTestUser+
		`","password":"`+updateTestPass+`"}}`)
	if w.Code != http.StatusOK {
		t.Fatalf("凭据正确应当保存成功，实际 %d：%s", w.Code, w.Body.String())
	}
	after := time.Now().Unix()

	snap := s.deps.Config.Snapshot()
	if !snap.Update.AllowUnsignedUpdate {
		t.Fatal("开关没存下来")
	}
	// 起点必须是"现在"：它是窗口的计时基准，取错了窗口的长度就不是 TTL。
	if snap.Update.AllowUnsignedSince < before || snap.Update.AllowUnsignedSince > after {
		t.Fatalf("起点 %d 不在 [%d,%d] 之内", snap.Update.AllowUnsignedSince, before, after)
	}

	// 响应里直接带回窗口状态，前端不必为这一项重载整份设置——那会把用户在这一页
	// 别处未保存的改动一起冲掉。
	sec := jsonSection(t, w.Body.Bytes(), "update")
	if !jsonBool(t, sec, "allowUnsignedUpdate") {
		t.Fatalf("响应里的开关应为真：%v", sec)
	}
	wantExpiry := snap.Update.AllowUnsignedSince + int64(config.AllowUnsignedUpdateTTL/time.Second)
	if got := jsonNum(t, sec, "allowUnsignedExpiresAt"); got != wantExpiry {
		t.Fatalf("到期时刻是 %d，期望起点 + TTL = %d", got, wantExpiry)
	}
	// 界面上那句说明里的小时数取自这个值，两边不该各写一遍。
	if got := jsonNum(t, sec, "allowUnsignedTtlHours"); got != int64(config.AllowUnsignedUpdateTTL/time.Hour) {
		t.Fatalf("TTL 小时数是 %d，与后端常量不一致", got)
	}

	// 审计记录：这一项一开，任何一条有效会话都能上传包换掉二进制，所以记 Warn，
	// 且必须带上到期时刻——否则事后翻日志的人不知道那扇门开到什么时候。
	e := mustLogEntry(t, s.deps.Log, "已打开「允许未验签的更新包」", "WARN")
	exp, ok := logFieldStr(e, "expiresAt")
	if !ok {
		t.Fatalf("这条日志少了 expiresAt 字段：%v", e.Fields)
	}
	if _, err := time.Parse(time.RFC3339, exp); err != nil {
		t.Fatalf("expiresAt 不是 RFC3339：%q", exp)
	}
}

// TestUpdateSettingsKeepsWindowOnUnrelatedSave 开关不会被别处的设置提交顺手关掉，
// 显式关闭则连起点一起清干净。
//
// 前半段是这一项用 *bool 接收的原因：按值接收的话，任何一次没带 allowUnsignedUpdate
// 的 update 提交都会把它重置成关闭——用户在关于页发现上传按钮又灰了，
// 而他刚才只是改了个更新清单地址。
func TestUpdateSettingsKeepsWindowOnUnrelatedSave(t *testing.T) {
	s := newUpdateGateServer(t, func(u *config.UpdateConfig) {
		u.AllowUnsignedUpdate = true
		u.AllowUnsignedSince = freshWindowStart()
	})
	since := s.deps.Config.Snapshot().Update.AllowUnsignedSince

	// 只改更新清单地址，不带这一项、也不带凭据：开关与起点都必须保持原样。
	if w := putSettings(t, s, `{"update":{"manifestUrl":"https://example.com/m.json"}}`); w.Code != http.StatusOK {
		t.Fatalf("保存设置失败（%d）：%s", w.Code, w.Body.String())
	}
	snap := s.deps.Config.Snapshot()
	if !snap.Update.AllowUnsignedUpdate {
		t.Fatal("一次不相关的设置提交把开关关掉了")
	}
	if snap.Update.AllowUnsignedSince != since {
		t.Fatalf("一次不相关的设置提交改了起点：%d → %d", since, snap.Update.AllowUnsignedSince)
	}

	// 关闭不需要凭据：那是在收紧，拦它只会让用户没法及时关掉这扇门。
	if w := putSettings(t, s, `{"update":{"allowUnsignedUpdate":false}}`); w.Code != http.StatusOK {
		t.Fatalf("关闭不该被拦（%d）：%s", w.Code, w.Body.String())
	}
	snap = s.deps.Config.Snapshot()
	if snap.Update.AllowUnsignedUpdate {
		t.Fatal("显式关闭没生效")
	}
	// 起点必须一起清零：留着它，下次打开时若少写了记时那一步，窗口会从很久以前起算。
	if snap.Update.AllowUnsignedSince != 0 {
		t.Fatalf("关闭后起点没清零，仍是 %d", snap.Update.AllowUnsignedSince)
	}
	mustLogEntry(t, s.deps.Log, "已关闭「允许未验签的更新包」", "INFO")
}

// TestUpdateSettingsDoesNotExtendActiveWindow 窗口开着的时候重复保存不续期。
//
// 若每次保存都重记起点，用户只要停留在这一页上定期点保存，就能把这段窗口无限续下去——
// 那就又变回了"一扇一旦打开就再也不会关的门"。真要续期得先关一次再开一次（那要输密码）。
func TestUpdateSettingsDoesNotExtendActiveWindow(t *testing.T) {
	s := newUpdateGateServer(t, func(u *config.UpdateConfig) {
		u.AllowUnsignedUpdate = true
		// 起点放在一小时前：窗口仍有效，而"有没有被重记"一眼看得出来。
		u.AllowUnsignedSince = time.Now().Add(-time.Hour).Unix()
	})
	since := s.deps.Config.Snapshot().Update.AllowUnsignedSince

	// 带着 allowUnsignedUpdate:true 再保存一次。窗口已经开着，所以这次不算"打开"，
	// 既不要求凭据、也不该重新计时。
	if w := putSettings(t, s, `{"update":{"allowUnsignedUpdate":true}}`); w.Code != http.StatusOK {
		t.Fatalf("窗口开着时不该再问凭据（%d）：%s", w.Code, w.Body.String())
	}
	snap := s.deps.Config.Snapshot()
	if snap.Update.AllowUnsignedSince != since {
		t.Fatalf("一次普通保存把窗口续期了：%d → %d", since, snap.Update.AllowUnsignedSince)
	}
	if !snap.Update.AllowUnsignedUpdate {
		t.Fatal("开关不该被这次保存关掉")
	}
}

// TestUpdateSettingsReEnableAfterExpiryNeedsPassword 窗口过期后重新打开要再验一次密码。
//
// 这一支单独钉住是因为它的判据与"从关到开"不同：过期时布尔值本来就是真，
// 只看布尔值有没有变化会把这次当成"什么都没改"，于是既不问密码也不重记起点，
// 那扇门就永远开不回来了（或者更糟：无声地又开着了）。
func TestUpdateSettingsReEnableAfterExpiryNeedsPassword(t *testing.T) {
	s := newUpdateGateServer(t, func(u *config.UpdateConfig) {
		u.AllowUnsignedUpdate = true
		u.AllowUnsignedSince = expiredWindowStart()
	})
	stale := s.deps.Config.Snapshot().Update.AllowUnsignedSince

	// 不带凭据：拒绝，且起点保持原样（仍是过期的那个）。
	w := putSettings(t, s, `{"update":{"allowUnsignedUpdate":true}}`)
	if w.Code != http.StatusForbidden {
		t.Fatalf("过期后重新打开也要验密码，实际 %d：%s", w.Code, w.Body.String())
	}
	if got := s.deps.Config.Snapshot().Update.AllowUnsignedSince; got != stale {
		t.Fatalf("被拒的提交改了起点：%d → %d", stale, got)
	}

	// 带上凭据：起点刷新，窗口重新开始计时。
	w = putSettings(t, s, `{"update":{"allowUnsignedUpdate":true,"account":"`+updateTestUser+
		`","password":"`+updateTestPass+`"}}`)
	if w.Code != http.StatusOK {
		t.Fatalf("凭据正确应当重新打开（%d）：%s", w.Code, w.Body.String())
	}
	snap := s.deps.Config.Snapshot()
	if snap.Update.AllowUnsignedSince <= stale {
		t.Fatalf("起点没有刷新，仍是 %d", snap.Update.AllowUnsignedSince)
	}
	if !snap.Update.UnsignedUpdateAllowed(time.Now()) {
		t.Fatal("重新打开之后窗口应当有效")
	}
	// 重开的判据是"起点变了"，布尔值这次没有变化——审计记录不能因此漏掉这一次。
	mustLogEntry(t, s.deps.Log, "已打开「允许未验签的更新包」", "WARN")
}

// TestGetSettingsReportsEffectiveWindow 读设置时报的是**当前实际有效**的状态，
// 不是配置文件里存的那个布尔值。
//
// 到期是算出来的、没有后台任务去改配置（见 config.UpdateConfig.UnsignedUpdateAllowed），
// 所以过期之后磁盘上那个 allowUnsignedUpdate 仍然是 true。要是接口照原样报出去，
// 关于页就会显示"可以上传"、设置页的开关也还是打开的，用户传完几十 MB 才收一个 403。
func TestGetSettingsReportsEffectiveWindow(t *testing.T) {
	// 到期时刻由前端拿去显示，得让它算得出：TTL 也一并报，省得前端自己写死一个数。
	ttlHours := int64(config.AllowUnsignedUpdateTTL / time.Hour)

	t.Run("窗口有效", func(t *testing.T) {
		since := freshWindowStart()
		s := newUpdateGateServer(t, func(u *config.UpdateConfig) {
			u.AllowUnsignedUpdate = true
			u.AllowUnsignedSince = since
		})
		sec := settingsUpdateSection(t, s)
		if !jsonBool(t, sec, "allowUnsignedUpdate") {
			t.Fatal("窗口有效时应当报 true")
		}
		if got := jsonNum(t, sec, "allowUnsignedExpiresAt"); got != since+ttlHours*3600 {
			t.Fatalf("到期时刻应为起点 + %d 小时（%d），实际 %d", ttlHours, since+ttlHours*3600, got)
		}
		if got := jsonNum(t, sec, "allowUnsignedTtlHours"); got != ttlHours {
			t.Fatalf("allowUnsignedTtlHours 应为 %d，实际 %d", ttlHours, got)
		}
	})

	t.Run("窗口已过期", func(t *testing.T) {
		s := newUpdateGateServer(t, func(u *config.UpdateConfig) {
			u.AllowUnsignedUpdate = true
			u.AllowUnsignedSince = expiredWindowStart()
		})
		sec := settingsUpdateSection(t, s)
		if jsonBool(t, sec, "allowUnsignedUpdate") {
			t.Fatal("窗口过期后应当报 false，否则界面上那个开关还是打开的")
		}
		if got := jsonNum(t, sec, "allowUnsignedExpiresAt"); got != 0 {
			t.Fatalf("过期时不该报到期时刻，实际 %d", got)
		}
		// 磁盘上的值不该被这次读取改写：改配置是写接口的事，读接口只负责算。
		if !s.deps.Config.Snapshot().Update.AllowUnsignedUpdate {
			t.Fatal("读一次设置把配置里的开关改了")
		}
	})

	t.Run("从未打开", func(t *testing.T) {
		s := newUpdateGateServer(t, nil)
		sec := settingsUpdateSection(t, s)
		if jsonBool(t, sec, "allowUnsignedUpdate") {
			t.Fatal("默认应当是关闭的")
		}
		if got := jsonNum(t, sec, "allowUnsignedExpiresAt"); got != 0 {
			t.Fatalf("默认不该有到期时刻，实际 %d", got)
		}
	})
}
