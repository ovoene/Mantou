package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"mantou/internal/config"
)

// 定时重启这份设置有两个"存下来就完了"的失败模式，都不会立刻报错：
//   - 存下来但永远不会触发（开着、但一天都没选 / 缺起算日）——界面显示已启用，实际一次也不重启；
//   - 客户端能改 LastRunAt——那是防重启循环的凭据，改到未来就等于永久关闭定时重启。
// 因此下面走真实接口把这两条钉住。

func putSettings(t *testing.T, server *Server, body string) *httptest.ResponseRecorder {
	t.Helper()
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodPut, "/api/settings", strings.NewReader(body))
	ctx.Request.Header.Set("Content-Type", "application/json")
	server.handleUpdateSettings(ctx)
	return recorder
}

func getSettings(t *testing.T, server *Server) map[string]any {
	t.Helper()
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodGet, "/api/settings", nil)
	server.handleGetSettings(ctx)
	if recorder.Code != http.StatusOK {
		t.Fatalf("GET /settings = %d，期望 200：%s", recorder.Code, recorder.Body.String())
	}
	var resp struct {
		Data map[string]any `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &resp); err != nil {
		t.Fatalf("解析设置响应失败: %v", err)
	}
	restart, ok := resp.Data["restart"].(map[string]any)
	if !ok {
		t.Fatalf("设置响应里没有 restart 段：%s", recorder.Body.String())
	}
	return restart
}

func TestUpdateSettingsSavesRestartPolicy(t *testing.T) {
	server, manager, _ := newE2EEnv(t)
	rec := putSettings(t, server, `{"restart":{"enabled":true,"mode":"weekly","weekdays":[3,1],"hour":3,"minute":20}}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("保存定时重启 = %d，期望 200：%s", rec.Code, rec.Body.String())
	}
	got := manager.Snapshot().Settings.Restart
	if !got.Enabled || got.Mode != config.RestartModeWeekly || got.Hour != 3 || got.Minute != 20 {
		t.Fatalf("落盘的设置不对：%+v", got)
	}
	// 星期要按规范化后的顺序存（界面与日志的顺序才稳定）。
	if len(got.Weekdays) != 2 || got.Weekdays[0] != 1 || got.Weekdays[1] != 3 {
		t.Fatalf("星期 = %v，期望 [1 3]", got.Weekdays)
	}
	// 下次执行由后端算并下发：前端不重复实现这套判断。
	restart := getSettings(t, server)
	next, _ := restart["nextRunAt"].(float64)
	if int64(next) <= time.Now().Unix() {
		t.Fatalf("下次执行 = %v，应当是一个未来时刻", next)
	}
}

func TestUpdateSettingsNormalizesRestartPolicy(t *testing.T) {
	server, manager, _ := newE2EEnv(t)
	// 越界与重复值不是"报错"而是"夹住"：这一段是整段提交的，
	// 因为一个 99 就整份设置存不进去，对用户没有帮助。
	rec := putSettings(t, server, `{"restart":{"enabled":true,"mode":"weekly","weekdays":[3,3,1,9,-1],"hour":99,"minute":-5}}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("保存 = %d，期望 200：%s", rec.Code, rec.Body.String())
	}
	got := manager.Snapshot().Settings.Restart
	if got.Hour != 23 || got.Minute != 0 {
		t.Fatalf("时刻 = %d:%d，期望 23:0", got.Hour, got.Minute)
	}
	if len(got.Weekdays) != 2 || got.Weekdays[0] != 1 || got.Weekdays[1] != 3 {
		t.Fatalf("星期 = %v，期望 [1 3]（去重、排序、丢掉越界值）", got.Weekdays)
	}
}

func TestUpdateSettingsRejectsUnrunnableRestartPolicy(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{"按星期但一天都没选", `{"restart":{"enabled":true,"mode":"weekly","weekdays":[],"hour":4}}`},
		{"按日历但一个日期都没选", `{"restart":{"enabled":true,"mode":"dates","dates":[],"hour":4}}`},
		{"每隔 N 天但没填起算日", `{"restart":{"enabled":true,"mode":"interval","everyDays":3,"hour":4}}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server, manager, _ := newE2EEnv(t)
			rec := putSettings(t, server, tc.body)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("保存 = %d，期望 400：%s", rec.Code, rec.Body.String())
			}
			// 拒绝必须是"什么都没改"，不能留下半截设置。
			if manager.Snapshot().Settings.Restart.Enabled {
				t.Fatal("请求被拒绝后设置仍被改成了已启用")
			}
		})
	}
}

func TestUpdateSettingsKeepsRestartPolicyDisabledEvenIfIncomplete(t *testing.T) {
	// 关闭状态下填成什么样都放过：否则用户想"先关掉再慢慢改"都做不到。
	server, manager, _ := newE2EEnv(t)
	rec := putSettings(t, server, `{"restart":{"enabled":false,"mode":"weekly","weekdays":[],"hour":4}}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("保存 = %d，期望 200：%s", rec.Code, rec.Body.String())
	}
	if got := manager.Snapshot().Settings.Restart; got.Enabled || len(got.Weekdays) != 0 {
		t.Fatalf("落盘的设置不对：%+v", got)
	}
}

func TestUpdateSettingsIgnoresClientSuppliedLastRunAt(t *testing.T) {
	server, manager, _ := newE2EEnv(t)
	if err := manager.Update(func(cfg *config.Config) {
		cfg.Settings.Restart.LastRunAt = 1700000000
	}); err != nil {
		t.Fatal(err)
	}
	// 请求里带上 lastRunAt：它不在请求结构里，必须被忽略。
	// 能改它就等于能把定时重启永久关掉（改到未来）或造成重启循环（改到过去）。
	rec := putSettings(t, server,
		`{"restart":{"enabled":true,"mode":"weekly","weekdays":[1],"hour":4,"lastRunAt":4102444800}}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("保存 = %d，期望 200：%s", rec.Code, rec.Body.String())
	}
	if got := manager.Snapshot().Settings.Restart.LastRunAt; got != 1700000000 {
		t.Fatalf("上次执行时间 = %d，期望保持 1700000000（不接受客户端设置）", got)
	}
}

func TestRestartNowWithoutHookReportsUnsupported(t *testing.T) {
	server, _, _ := newE2EEnv(t)
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodPost, "/api/settings/restart-now", nil)
	server.handleRestartNow(ctx)
	// 没有注入重启能力时必须明确报"不支持"，而不是回 ok 让用户以为重启了。
	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("立即重启 = %d，期望 503：%s", recorder.Code, recorder.Body.String())
	}
}

func TestRestartNowTriggersExecOnceAndRejectsSecondCall(t *testing.T) {
	server, _, _ := newE2EEnv(t)
	paths := make(chan string, 4)
	server.deps.RestartExec = func(path string) error {
		paths <- path
		return nil
	}

	restartNow := func() *httptest.ResponseRecorder {
		recorder := httptest.NewRecorder()
		ctx, _ := gin.CreateTestContext(recorder)
		ctx.Request = httptest.NewRequest(http.MethodPost, "/api/settings/restart-now", nil)
		server.handleRestartNow(ctx)
		return recorder
	}

	if rec := restartNow(); rec.Code != http.StatusOK {
		t.Fatalf("立即重启 = %d，期望 200：%s", rec.Code, rec.Body.String())
	}
	// 连点第二下应当得到明确回复，而不是撞到底层"已有待执行的重启请求"那句内部错误上。
	if rec := restartNow(); rec.Code != http.StatusConflict {
		t.Fatalf("重复请求 = %d，期望 409：%s", rec.Code, rec.Body.String())
	}

	want, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-paths:
		if got != want {
			t.Fatalf("重启用的路径 = %q，期望当前可执行文件 %q", got, want)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("响应之后没有真正触发重启")
	}
	select {
	case extra := <-paths:
		t.Fatalf("重启被触发了两次（第二次路径 %q）", extra)
	case <-time.After(300 * time.Millisecond):
	}
}

// 超限的日期列表要**报错**而不是被静默夹住：规范化在加载期必须能夹（配置有三条写入路径），
// 但接口这一侧夹掉用户刚点的 20 个日期而不说话，比直接告诉他"最多 60 个"糟得多。
func TestUpdateSettingsRejectsTooManyRestartDates(t *testing.T) {
	server, manager, _ := newE2EEnv(t)
	dates := make([]string, 0, config.MaxRestartDates+1)
	for i := 0; i <= config.MaxRestartDates; i++ {
		dates = append(dates, time.Now().AddDate(0, 0, i+1).Format("2006-01-02"))
	}
	body, err := json.Marshal(map[string]any{
		"restart": map[string]any{"enabled": true, "mode": "dates", "dates": dates, "hour": 4},
	})
	if err != nil {
		t.Fatal(err)
	}
	rec := putSettings(t, server, string(body))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("保存 %d 个日期 = %d，期望 400：%s", len(dates), rec.Code, rec.Body.String())
	}
	if manager.Snapshot().Settings.Restart.Enabled {
		t.Fatal("请求被拒绝后设置仍被改成了已启用")
	}
	// 正好等于上限则放过（边界不能连自己都存不下）。
	body, err = json.Marshal(map[string]any{
		"restart": map[string]any{"enabled": true, "mode": "dates", "dates": dates[:config.MaxRestartDates], "hour": 4},
	})
	if err != nil {
		t.Fatal(err)
	}
	if rec := putSettings(t, server, string(body)); rec.Code != http.StatusOK {
		t.Fatalf("保存 %d 个日期 = %d，期望 200：%s", config.MaxRestartDates, rec.Code, rec.Body.String())
	}
	if got := len(manager.Snapshot().Settings.Restart.Dates); got != config.MaxRestartDates {
		t.Fatalf("落盘的日期数量 = %d，期望 %d", got, config.MaxRestartDates)
	}
}
