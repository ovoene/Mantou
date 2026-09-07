package server

import (
	"net/http"
	"strings"
	"testing"

	"mantou/internal/config"
)

// 本文件盯住计划任务保存时的表达式校验（审计 L-05）。
//
// 从前这里什么都不校验：写错的表达式 200 存下来，列表里显示「启用」，模块状态显示健康，
// 而它永远不会执行——唯一的痕迹是重载时一行 ERROR 日志。表达式是用户手写的
//（调度类型选「自定义」那一档），写错是常态。

// cronTask 造一条只填了启用开关与表达式的任务。
func cronTask(enabled bool, spec string) config.CronTask {
	return config.CronTask{
		ID: "ct1", Name: "任务", Enabled: enabled, Cron: spec,
		Action: config.CronAction{Type: "ddns.refresh"},
	}
}

func TestValidateCronTaskRejectsUnschedulableSpec(t *testing.T) {
	// 报告里实测过的那四种输入，全部曾经 200 存盘。
	for _, spec := range []string{"", "   ", "not a cron", "*/5 * * *", "99 99 * * *"} {
		t.Run("拒："+spec, func(t *testing.T) {
			err := validateCronTask(nil, cronTask(true, spec))
			if err == nil {
				t.Fatalf("表达式 %q 排不进调度器，保存时就该拒", spec)
			}
			// 报错要能自己看懂：带上标准格式与一个例子，而不只是 robfig 的英文原话。
			if !strings.Contains(err.Error(), "分 时 日 月 周") {
				t.Errorf("错误文案里应说明正确格式，实际 %q", err.Error())
			}
		})
	}

	for _, spec := range []string{"0 3 * * *", "* * * * *", "*/5 * * * *", "0 3 * * 1,5", "@every 1h"} {
		t.Run("收："+spec, func(t *testing.T) {
			if err := validateCronTask(nil, cronTask(true, spec)); err != nil {
				t.Fatalf("表达式 %q 是合法的，不该被拦：%v", spec, err)
			}
		})
	}
}

// TestValidateCronTaskAllowsDisabledBadSpec 关掉一条坏任务这件事必须永远做得到。
//
// 计划任务没有轻量 toggle 端点，列表里那个开关走的是整行 PUT（把存着的坏表达式原样送回来）。
// 若无条件校验，一份从备份导入或手改进来的坏任务就成了死角：改不动，也关不掉。
// 而禁用中的坏表达式本身无害——它排不进调度器，也不该排。
func TestValidateCronTaskAllowsDisabledBadSpec(t *testing.T) {
	for _, spec := range []string{"", "not a cron", "99 99 * * *"} {
		if err := validateCronTask(nil, cronTask(false, spec)); err != nil {
			t.Errorf("禁用中的任务不该因表达式被拦（%q）：%v", spec, err)
		}
	}
}

// TestCronTaskRouteRejectsBadSpec 走**线上那份** registerResourceRoutes，确认校验真的接在
// crontasks 上。上面几条只证明 validateCronTask 本身对，证明不了它被挂上去了——
// 而"忘了挂"与"没写校验"在用户那边是同一个症状。
func TestCronTaskRouteRejectsBadSpec(t *testing.T) {
	manager, router := newAllResourcesTest(t)

	bad := `{"name":"坏任务","enabled":true,"cron":"not a cron","action":{"type":"ddns.refresh","params":{}}}`
	w := performJSONRequest(router, http.MethodPost, "/crontasks", bad)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("POST 坏表达式应 400，实际 %d：%s", w.Code, w.Body.String())
	}
	if n := len(manager.Snapshot().CronTasks); n != 0 {
		t.Fatalf("被拒的请求不该留下条目，实际存了 %d 条", n)
	}

	good := `{"name":"好任务","enabled":true,"cron":"0 4 * * *","action":{"type":"ddns.refresh","params":{}}}`
	if w := performJSONRequest(router, http.MethodPost, "/crontasks", good); w.Code != http.StatusOK {
		t.Fatalf("POST 合法表达式应 200，实际 %d：%s", w.Code, w.Body.String())
	}
	tasks := manager.Snapshot().CronTasks
	if len(tasks) != 1 {
		t.Fatalf("合法任务应存下来，实际 %d 条", len(tasks))
	}

	// 存量坏任务的出路：把它关掉。这一条走真实 PUT，载荷就是列表里那个开关会送的形状。
	if err := manager.Update(func(cfg *config.Config) {
		cfg.CronTasks = append(cfg.CronTasks, cronTask(true, "*/5 * * *"))
	}); err != nil {
		t.Fatal(err)
	}
	off := `{"name":"任务","enabled":false,"cron":"*/5 * * *","action":{"type":"ddns.refresh","params":{}}}`
	if w := performJSONRequest(router, http.MethodPut, "/crontasks/ct1", off); w.Code != http.StatusOK {
		t.Fatalf("关掉一条存量坏任务应 200，实际 %d：%s", w.Code, w.Body.String())
	}
	for _, task := range manager.Snapshot().CronTasks {
		if task.ID == "ct1" && task.Enabled {
			t.Fatal("那条坏任务应已被关掉")
		}
	}
}
