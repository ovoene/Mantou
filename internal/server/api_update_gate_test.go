package server

import (
	"bytes"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"mantou/internal/config"
	"mantou/internal/logx"
)

// 上传更新包的结果是面板拿一个新二进制把自己换掉。没有验签就没有任何环节能分辨
// 那个包是不是用户自己的，所以公钥留空时默认不收——想跳过验签得先自己在设置里
// 打开「允许未验签的更新包」。下面这组测试钉住这个默认值与那个开关（见 5-H）。

// TestUnsignedUpdateBlockedStates 四种组合各该是什么结论。
func TestUnsignedUpdateBlockedStates(t *testing.T) {
	cases := []struct {
		name        string
		signKey     string
		allow       bool
		wantBlocked bool
	}{
		// 这一条是默认状态：全新装起来的面板收不了更新包。
		{"公钥留空、开关关闭", "", false, true},
		{"公钥留空、开关打开", "", true, false},
		{"配了公钥、开关关闭", "dGVzdA==", false, false},
		// 配了公钥时开关不起作用：有公钥就一律验签，这个开关只管"没有公钥怎么办"。
		{"配了公钥、开关打开", "dGVzdA==", true, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := unsignedUpdateBlocked(config.UpdateConfig{
				SignKey:             tc.signKey,
				AllowUnsignedUpdate: tc.allow,
			})
			if got != tc.wantBlocked {
				t.Fatalf("期望 blocked=%v，实际 %v", tc.wantBlocked, got)
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
	if !unsignedUpdateBlocked(config.UpdateConfig{SignKey: "   \t\n"}) {
		t.Fatal("只有空白字符的公钥应视为没填，默认不接收更新包")
	}
}

// TestSelfUpdateRefusedWithoutSignKey 默认配置下上传更新包被拒，且拒在读请求体之前。
func TestSelfUpdateRefusedWithoutSignKey(t *testing.T) {
	if runtime.GOOS == "windows" {
		// Windows 上 handleSelfUpdate 第一行就返回 501，走不到这道判断。
		// 判断本身由 TestUnsignedUpdateBlockedStates 逐个状态覆盖，这里只在别的平台上跑。
		t.Skip("Windows 不支持在线覆盖更新")
	}
	gin.SetMode(gin.TestMode)
	cfg := config.NewManager(filepath.Join(t.TempDir(), "config.json"))
	if err := cfg.Load(); err != nil {
		t.Fatal(err)
	}
	// 前提：默认配置就是"公钥留空、开关关闭"。
	if snap := cfg.Snapshot(); snap.Update.SignKey != "" || snap.Update.AllowUnsignedUpdate {
		t.Fatalf("测试前提不成立：默认配置已经允许未验签更新（signKey=%q allow=%v）",
			snap.Update.SignKey, snap.Update.AllowUnsignedUpdate)
	}

	s := &Server{deps: Deps{Config: cfg, Log: logx.New(logx.Options{})}}
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

// TestSelfUpdateAcceptedAfterAllowingUnsigned 打开开关之后这道判断放行。
//
// 只验"不再是 403"：放行之后走的是解包、架构校验、冒烟测试那条长链路，
// 拿一段假内容进去必然失败，那些是别的测试的事。
func TestSelfUpdateAcceptedAfterAllowingUnsigned(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows 不支持在线覆盖更新")
	}
	gin.SetMode(gin.TestMode)
	cfg := config.NewManager(filepath.Join(t.TempDir(), "config.json"))
	if err := cfg.Load(); err != nil {
		t.Fatal(err)
	}
	if err := cfg.Update(func(c *config.Config) { c.Update.AllowUnsignedUpdate = true }); err != nil {
		t.Fatal(err)
	}

	s := &Server{deps: Deps{Config: cfg, Log: logx.New(logx.Options{})}}
	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	ctx.Request = newUpdateUploadRequest(t, "不是真的更新包")

	s.handleSelfUpdate(ctx)

	if w.Code == http.StatusForbidden {
		t.Fatalf("开关已打开，不该再被这道判断拦下：%s", w.Body.String())
	}
}

// TestUpdateSettingsPersistsAllowUnsigned 开关能存下来，且不会被别处的设置提交顺手关掉。
//
// 后半段是这一项用 *bool 接收的原因：按值接收的话，任何一次没带
// allowUnsignedUpdate 的 update 提交都会把它重置成关闭——用户在关于页发现
// 上传按钮又灰了，而他刚才只是改了个更新清单地址。
func TestUpdateSettingsPersistsAllowUnsigned(t *testing.T) {
	gin.SetMode(gin.TestMode)
	cfg := config.NewManager(filepath.Join(t.TempDir(), "config.json"))
	if err := cfg.Load(); err != nil {
		t.Fatal(err)
	}
	s := &Server{deps: Deps{Config: cfg, Log: logx.New(logx.Options{})}}

	putSettings := func(body string) {
		t.Helper()
		w := httptest.NewRecorder()
		ctx, _ := gin.CreateTestContext(w)
		ctx.Request = httptest.NewRequest(http.MethodPut, "/settings", strings.NewReader(body))
		ctx.Request.Header.Set("Content-Type", "application/json")
		s.handleUpdateSettings(ctx)
		if w.Code != http.StatusOK {
			t.Fatalf("保存设置失败（%d）：%s", w.Code, w.Body.String())
		}
	}

	putSettings(`{"update":{"allowUnsignedUpdate":true}}`)
	if !cfg.Snapshot().Update.AllowUnsignedUpdate {
		t.Fatal("开关没存下来")
	}

	// 只改更新清单地址，不带这一项：开关必须保持原样。
	putSettings(`{"update":{"manifestUrl":"https://example.com/m.json"}}`)
	if !cfg.Snapshot().Update.AllowUnsignedUpdate {
		t.Fatal("一次不相关的设置提交把开关关掉了")
	}

	putSettings(`{"update":{"allowUnsignedUpdate":false}}`)
	if cfg.Snapshot().Update.AllowUnsignedUpdate {
		t.Fatal("显式关闭没生效")
	}
}

// newUpdateUploadRequest 造一个与前端一致的 multipart 上传请求（字段名 file）。
func newUpdateUploadRequest(t *testing.T, content string) *http.Request {
	t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
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
