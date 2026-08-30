package cron

import (
	"errors"
	"sync"
	"testing"
	"time"

	robfig "github.com/robfig/cron/v3"

	"mantou/internal/config"
	"mantou/internal/logx"
	"mantou/internal/module"
)

func newTestModule(t *testing.T) *Module {
	t.Helper()
	m := New(logx.New(logx.Options{}), nil)
	t.Cleanup(func() { _ = m.Close() })
	return m
}

func testTask(id string) config.CronTask {
	return config.CronTask{ID: id, Name: id, Enabled: true, Cron: "0 3 * * *", Action: config.CronAction{Type: "test"}}
}

// 同一任务不得并发执行：间隔短于耗时（每分钟一次、但签发要跑几分钟）时实例会不断叠加，
// 并发向 CA 下单会耗尽重复签发配额，并发改 DNS 会写入互相冲突的记录。
func TestExecuteSkipsTaskAlreadyRunning(t *testing.T) {
	m := newTestModule(t)
	var once sync.Once
	started := make(chan struct{})
	release := make(chan struct{})
	m.RegisterHandler("test", func(config.CronAction, int) (string, error) {
		once.Do(func() { close(started) })
		<-release
		return "成功", nil
	})

	task := testTask("t1")
	firstDone := make(chan struct{})
	go func() {
		defer close(firstDone)
		if _, err := m.execute(task); err != nil {
			t.Error(err)
		}
	}()
	<-started

	if _, err := m.execute(task); !errors.Is(err, errStillRunning) {
		t.Fatalf("上一轮未结束时应跳过，实际 err=%v", err)
	}
	close(release)
	<-firstDone

	// 上一轮结束后不再跳过。
	if _, err := m.execute(task); err != nil {
		t.Fatalf("上一轮已结束，本轮应正常执行: %v", err)
	}
}

// Reload 等待「在执行的任务收尾」时不得持有 Status 用的锁：
// cert.renew 的兜底超时是 10 分钟，持锁等待会让总览页每 3 秒一次的轮询全部挂住。
func TestReloadDoesNotBlockStatusWhileWaitingForRunningJob(t *testing.T) {
	m := newTestModule(t)

	// 用带秒字段的解析器让任务立即开始执行，避免测试等待整分钟。
	parser := robfig.NewParser(robfig.Second | robfig.Minute | robfig.Hour | robfig.Dom | robfig.Month | robfig.Dow)
	c := robfig.New(robfig.WithParser(parser))
	var once sync.Once
	started := make(chan struct{})
	release := make(chan struct{})
	if _, err := c.AddFunc("* * * * * *", func() {
		once.Do(func() { close(started) })
		<-release
	}); err != nil {
		t.Fatal(err)
	}
	c.Start()
	m.mu.Lock()
	m.cron = c
	m.mu.Unlock()
	<-started

	reloaded := make(chan struct{})
	go func() {
		defer close(reloaded)
		if err := m.Reload(&config.Config{}); err != nil {
			t.Error(err)
		}
	}()

	// 任务仍阻塞着，Reload 必然停在「等待收尾」这一步——此时 Status 必须照常返回。
	time.Sleep(200 * time.Millisecond)
	select {
	case <-reloaded:
		t.Fatal("在执行的任务尚未结束，Reload 不应已完成（测试前提不成立）")
	default:
	}
	status := make(chan module.Status, 1)
	go func() { status <- m.Status() }()
	select {
	case <-status:
	case <-time.After(3 * time.Second):
		t.Fatal("Reload 等待任务收尾期间 Status 被阻塞")
	}

	close(release)
	select {
	case <-reloaded:
	case <-time.After(10 * time.Second):
		t.Fatal("任务结束后 Reload 未完成")
	}
}

// Healthy 必须反映真实状况：失败后为 false，下次成功自动恢复，任务被删除后不残留。
func TestStatusHealthyReflectsLastRunOutcome(t *testing.T) {
	m := newTestModule(t)
	var failing bool
	m.RegisterHandler("test", func(config.CronAction, int) (string, error) {
		if failing {
			return "", errors.New("boom")
		}
		return "成功", nil
	})

	task := testTask("t1")
	cfg := &config.Config{CronTasks: []config.CronTask{task}}
	if err := m.Reload(cfg); err != nil {
		t.Fatal(err)
	}
	if !m.Status().Healthy {
		t.Fatal("尚未执行过任何任务时应为健康")
	}

	failing = true
	if _, err := m.execute(task); err == nil {
		t.Fatal("预期执行失败")
	}
	if m.Status().Healthy {
		t.Fatal("最近一次执行失败时不应报告健康")
	}

	failing = false
	if _, err := m.execute(task); err != nil {
		t.Fatal(err)
	}
	if !m.Status().Healthy {
		t.Fatal("重新执行成功后应恢复健康")
	}

	// 失败的任务被删除后，其失败标记不应让模块永远显示不健康。
	failing = true
	if _, err := m.execute(task); err == nil {
		t.Fatal("预期执行失败")
	}
	if err := m.Reload(&config.Config{}); err != nil {
		t.Fatal(err)
	}
	if !m.Status().Healthy {
		t.Fatal("任务已删除，失败标记应随重载清理")
	}
}

// Close 之后调度器为空：此时报告健康会掩盖「调度器没在跑」这一事实。
func TestStatusUnhealthyWithoutScheduler(t *testing.T) {
	m := newTestModule(t)
	if err := m.Reload(&config.Config{}); err != nil {
		t.Fatal(err)
	}
	if !m.Status().Healthy {
		t.Fatal("调度器已启动且无失败任务，应为健康")
	}
	if err := m.Close(); err != nil {
		t.Fatal(err)
	}
	if m.Status().Healthy {
		t.Fatal("调度器已停止时不应报告健康")
	}
}
