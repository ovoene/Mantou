package server

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"mantou/internal/config"
)

// 面板端口保存是全项目唯一一个"改错了就没法在界面上改回来"的操作：
// 保存成功 → 面板重启 → 新端口绑不上 → 整个进程退出，八个模块一起下线。
// 下面这组测试钉住"落盘之前先试一次"这件事（见 5-J / 2.13-A）。

// panelPortEnv 造一台能保存设置的面板。重启回调换成空实现：真回调会重建监听。
func panelPortEnv(t *testing.T) (*Server, *config.Manager) {
	t.Helper()
	server, manager, _ := newE2EEnv(t)
	server.deps.RestartPanel = func() {}
	return server, manager
}

// freePort 返回一个此刻空着的端口。拿完就放，中间被别人抢走的概率可以忽略。
func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	if err := ln.Close(); err != nil {
		t.Fatal(err)
	}
	return port
}

// requireExclusiveBind 确认本平台不允许两次绑定同一地址——这一组测试全部以此为前提。
// 允许的话，试绑既检测不出占用、测试也无从验证，那就跳过并说明原因，别给一个假通过。
func requireExclusiveBind(t *testing.T) {
	t.Helper()
	ln, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port
	if again, aerr := net.Listen("tcp", addr("0.0.0.0", port)); aerr == nil {
		_ = again.Close()
		t.Skipf("本平台允许重复绑定 0.0.0.0:%d，无法在此环境下验证预试绑定", port)
	}
}

// busyPort 占住一个端口并在测试结束时释放。
// 故意绑 0.0.0.0 而不是 127.0.0.1：面板默认也绑 0.0.0.0，两边地址一致才谈得上冲突。
func busyPort(t *testing.T) int {
	t.Helper()
	requireExclusiveBind(t)
	ln, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	return ln.Addr().(*net.TCPAddr).Port
}

// savedPanelPort 读回落盘后的面板端口。
func savedPanelPort(t *testing.T, manager *config.Manager) int {
	t.Helper()
	return manager.Snapshot().Panel.Port
}

// restartRequiredOf 取响应里的 restartRequired。
func restartRequiredOf(t *testing.T, rec *httptest.ResponseRecorder) bool {
	t.Helper()
	var resp struct {
		Data struct {
			RestartRequired bool `json:"restartRequired"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("解析保存响应失败: %v（%s）", err, rec.Body.String())
	}
	return resp.Data.RestartRequired
}

// TestSavePanelPortRejectsBusyPort 是这一组里唯一覆盖"本机其他程序占用"的测试：
// 配置校验看不出来，同进程的监听表里也没有，只有真绑一次才知道。
func TestSavePanelPortRejectsBusyPort(t *testing.T) {
	port := busyPort(t)
	server, manager := panelPortEnv(t)
	before := savedPanelPort(t, manager)
	if before == port {
		t.Fatalf("测试前提不成立：占用的端口正好等于当前面板端口 %d", port)
	}

	rec := putSettings(t, server, `{"panel":{"port":`+strconv.Itoa(port)+`}}`)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("保存被占用的端口 %d = %d，期望 400：%s", port, rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	// 报文里必须有端口号，否则用户不知道是哪个值出了问题；
	// 也必须说清"没存下来"，否则用户会以为已经改了、等着重启生效。
	if !strings.Contains(body, strconv.Itoa(port)) {
		t.Errorf("错误信息里没有端口号 %d：%s", port, body)
	}
	if !strings.Contains(body, "配置未保存") {
		t.Errorf("错误信息没说明配置未保存：%s", body)
	}
	if got := savedPanelPort(t, manager); got != before {
		t.Fatalf("保存被拒后端口仍被改成了 %d，期望保持 %d", got, before)
	}
}

// TestSavePanelPortAcceptsFreePort 反向钉住：新增的检查不能变成"一律拒绝"。
func TestSavePanelPortAcceptsFreePort(t *testing.T) {
	port := freePort(t)
	server, manager := panelPortEnv(t)
	if savedPanelPort(t, manager) == port {
		t.Fatalf("测试前提不成立：空闲端口正好等于当前面板端口 %d", port)
	}

	rec := putSettings(t, server, `{"panel":{"port":`+strconv.Itoa(port)+`}}`)

	if rec.Code != http.StatusOK {
		t.Fatalf("保存空闲端口 %d = %d，期望 200：%s", port, rec.Code, rec.Body.String())
	}
	if got := savedPanelPort(t, manager); got != port {
		t.Fatalf("端口没落盘：得到 %d，期望 %d", got, port)
	}
	if !restartRequiredOf(t, rec) {
		t.Error("改了端口却没要求重启，前端不会提示用户")
	}
}

// TestSavePanelPortAllowsUnchangedPort 端口没变时不能试绑：进程此刻正占着它，
// 试绑必然失败——那会让"只改了别的设置"这一类保存全部报错。
func TestSavePanelPortAllowsUnchangedPort(t *testing.T) {
	port := busyPort(t)
	server, manager := panelPortEnv(t)
	if err := manager.Update(func(cfg *config.Config) { cfg.Panel.Port = port }); err != nil {
		t.Fatal(err)
	}

	rec := putSettings(t, server, `{"panel":{"port":`+strconv.Itoa(port)+`}}`)

	if rec.Code != http.StatusOK {
		t.Fatalf("原值保存 = %d，期望 200：%s", rec.Code, rec.Body.String())
	}
	if restartRequiredOf(t, rec) {
		t.Error("端口没变却要求重启面板")
	}
	if got := savedPanelPort(t, manager); got != port {
		t.Fatalf("端口被改成了 %d，期望保持 %d", got, port)
	}
}

// TestSavePanelPortProbeReleasesPort 试绑之后必须把端口放回去。
//
// 若它把监听留在自己手里：保存成功 → 面板重启 → 绑不上 → 进程退出。
// 绑不上的原因还正是刚才那次试绑——这套检查要防的后果，会由检查本身制造出来。
// 上一版没有这条，去掉 ln.Close() 六个测试全绿。
func TestSavePanelPortProbeReleasesPort(t *testing.T) {
	requireExclusiveBind(t)
	port := freePort(t)
	server, manager := panelPortEnv(t)

	rec := putSettings(t, server, `{"panel":{"port":`+strconv.Itoa(port)+`}}`)

	if rec.Code != http.StatusOK {
		t.Fatalf("保存空闲端口 %d = %d，期望 200：%s", port, rec.Code, rec.Body.String())
	}
	if got := savedPanelPort(t, manager); got != port {
		t.Fatalf("测试前提不成立：端口没落盘，得到 %d，期望 %d", got, port)
	}
	ln, err := net.Listen("tcp", addr("0.0.0.0", port))
	if err != nil {
		t.Fatalf("保存后端口 %d 还占着，试绑没有释放它：%v", port, err)
	}
	_ = ln.Close()
}

// TestSavePanelPortRejectsWebServicePort 同进程内的冲突：Web 服务此刻可能还没起监听
// （比如刚配好没重载），试绑会成功，所以这一支只能查配置。
// 报文要说得出是谁占着，用户才知道该改哪一边。
func TestSavePanelPortRejectsWebServicePort(t *testing.T) {
	port := freePort(t)
	server, manager := panelPortEnv(t)
	if err := manager.Update(func(cfg *config.Config) {
		cfg.WebServices = []config.WebService{{
			ID: "ws-1", Name: "官网", Enabled: true, Port: port,
			Children: []config.WebChild{{ID: "ch-1", Enabled: true, Domains: []string{"www.example.com"}}},
		}}
	}); err != nil {
		t.Fatal(err)
	}
	before := savedPanelPort(t, manager)

	rec := putSettings(t, server, `{"panel":{"port":`+strconv.Itoa(port)+`}}`)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("保存 Web 服务占着的端口 = %d，期望 400：%s", rec.Code, rec.Body.String())
	}
	if body := rec.Body.String(); !strings.Contains(body, "官网") {
		t.Errorf("错误信息没说是哪个 Web 服务占着：%s", body)
	}
	if got := savedPanelPort(t, manager); got != before {
		t.Fatalf("保存被拒后端口仍被改成了 %d，期望保持 %d", got, before)
	}
}

// TestSavePanelPortRejectsWebhookPort 同上，消息路由那一支。
func TestSavePanelPortRejectsWebhookPort(t *testing.T) {
	port := freePort(t)
	server, manager := panelPortEnv(t)
	if err := manager.Update(func(cfg *config.Config) {
		cfg.Webhook.Enabled = true
		cfg.Webhook.Port = port
	}); err != nil {
		t.Fatal(err)
	}
	before := savedPanelPort(t, manager)

	rec := putSettings(t, server, `{"panel":{"port":`+strconv.Itoa(port)+`}}`)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("保存消息路由占着的端口 = %d，期望 400：%s", rec.Code, rec.Body.String())
	}
	if body := rec.Body.String(); !strings.Contains(body, "消息路由") {
		t.Errorf("错误信息没提到消息路由：%s", body)
	}
	if got := savedPanelPort(t, manager); got != before {
		t.Fatalf("保存被拒后端口仍被改成了 %d，期望保持 %d", got, before)
	}
}

// TestSavePanelPortIgnoresOutOfRange 越界值仍走既有行为：保存逻辑跳过它，
// 端口保持不变。这一步不做拦截，也不该因为新增检查而报错。
func TestSavePanelPortIgnoresOutOfRange(t *testing.T) {
	server, manager := panelPortEnv(t)
	before := savedPanelPort(t, manager)

	for _, body := range []string{`{"panel":{"port":0}}`, `{"panel":{"port":70000}}`, `{"panel":{"port":-1}}`} {
		rec := putSettings(t, server, body)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s = %d，期望 200：%s", body, rec.Code, rec.Body.String())
		}
		if got := savedPanelPort(t, manager); got != before {
			t.Fatalf("%s 把端口改成了 %d，期望保持 %d", body, got, before)
		}
	}
}
