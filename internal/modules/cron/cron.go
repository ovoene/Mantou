package cron

import (
	"errors"
	"fmt"
	"sync"
	"time"

	robfig "github.com/robfig/cron/v3"

	"mantou/internal/config"
	"mantou/internal/logx"
	"mantou/internal/module"
)

// ActionFunc 执行一个计划任务动作，返回执行结果的简短描述与错误。
// timeoutSec 为任务配置的超时秒数（<=0 表示不限制），命令/HTTP 等长耗时动作应据此终止。
type ActionFunc func(action config.CronAction, timeoutSec int) (string, error)

// Module 管理 cron 计划任务的注册与执行。
// 动作的具体实现由外部通过 RegisterHandler 注入，实现模块解耦（DDNS/WOL/证书等各自注册处理器）。
type Module struct {
	// reloadMu 串行化 Reload/Close 的整体流程（含锁外的"等待旧调度器收尾"），
	// 使这段长耗时等待不必持有 mu——否则 Status() 会被一起挂住（见 Reload）。
	reloadMu sync.Mutex

	mu       sync.Mutex
	log      *logx.Logger
	cfgMgr   *config.Manager
	cron     *robfig.Cron
	handlers map[string]ActionFunc // key = action.Type
	running  map[string]bool       // 正在执行的任务 ID，防止同一任务并发执行（见 beginRun）
	failed   map[string]bool       // 最近一次执行失败的任务 ID，供 Status 反映健康状况
	tasks    int
	active   int
}

// New 创建计划任务模块。robfig/cron 使用标准 5 段解析器（分 时 日 月 周）。
func New(log *logx.Logger, cfgMgr *config.Manager) *Module {
	return &Module{
		log:      log,
		cfgMgr:   cfgMgr,
		handlers: make(map[string]ActionFunc),
		running:  make(map[string]bool),
		failed:   make(map[string]bool),
	}
}

// Name 实现 module.Module。
func (m *Module) Name() string { return "cron" }

// RegisterHandler 注册某类动作的执行器。应在首次 Reload 前完成注册。
func (m *Module) RegisterHandler(actionType string, fn ActionFunc) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.handlers[actionType] = fn
}

// Reload 重建 cron 调度器并挂载所有启用的任务。
func (m *Module) Reload(cfg *config.Config) error {
	m.reloadMu.Lock()
	defer m.reloadMu.Unlock()

	// 先在锁内摘走旧调度器、立刻释放锁，把「等待在执行的任务收尾」放到锁外：
	// cron.Stop() 返回的 ctx 要等所有在执行的任务返回才 Done，而 cert.renew 的兜底超时是
	// 10 分钟。持 mu 等待会连带挂住 Status()，而总览页每 3 秒轮询一次 /api/overview——
	// 管理员只是点了一下「保存」，看到的却是整个面板无响应。
	m.mu.Lock()
	old := m.cron
	m.cron = nil
	m.mu.Unlock()
	m.stopScheduler(old)

	c := robfig.New()
	total, active := 0, 0
	now := time.Now()
	// nextByID 记录本次重载后各启用任务的「下次执行时间」，稍后统一回写。
	nextByID := make(map[string]int64)
	for _, t := range cfg.CronTasks {
		total++
		if !t.Enabled {
			continue
		}
		task := t // 捕获副本
		_, err := c.AddFunc(task.Cron, func() { m.runTask(task) })
		if err != nil {
			m.log.Error("计划任务表达式无效", "task", task.Name, "cron", task.Cron, "err", err.Error())
			continue
		}
		if sched, perr := robfig.ParseStandard(task.Cron); perr == nil {
			nextByID[task.ID] = sched.Next(now).Unix()
		}
		active++
	}
	c.Start()

	valid := make(map[string]bool, len(cfg.CronTasks))
	for _, t := range cfg.CronTasks {
		valid[t.ID] = true
	}
	m.mu.Lock()
	m.cron = c
	m.tasks = total
	m.active = active
	// 清理已删除任务的失败标记，否则删掉一个失败任务后模块会永远显示「不健康」。
	for id := range m.failed {
		if !valid[id] {
			delete(m.failed, id)
		}
	}
	m.mu.Unlock()

	m.persistNextRuns(cfg.CronTasks, nextByID)
	return nil
}

// stopSchedulerWait 等待旧调度器收尾的上限。超时后放弃等待并继续重载：
// 让新旧调度器短暂并存优于把重载无限期挂住——旧调度器已不会再触发新任务，
// 只是仍有任务在执行；而同一任务的并发由 beginRun 兜住。
const stopSchedulerWait = 30 * time.Second

// stopScheduler 停止调度器并等待其在执行的任务结束（有上限）。必须在锁外调用。
func (m *Module) stopScheduler(c *robfig.Cron) {
	if c == nil {
		return
	}
	select {
	case <-c.Stop().Done():
	case <-time.After(stopSchedulerWait):
		m.log.Warn("计划任务：等待在执行的任务结束超时，继续重载", "wait", stopSchedulerWait.String())
	}
}

// persistNextRuns 将计算好的下次执行时间回写到配置（仅在有变化时落盘，避免无谓写入）。
// 禁用或表达式非法的任务其 NextRunAt 归零。
func (m *Module) persistNextRuns(current []config.CronTask, nextByID map[string]int64) {
	if m.cfgMgr == nil {
		return
	}
	changed := false
	for i := range current {
		want := nextByID[current[i].ID] // 不在 map 中则为 0
		if current[i].NextRunAt != want {
			changed = true
			break
		}
	}
	if !changed {
		return
	}
	_ = m.cfgMgr.UpdateState(func(c *config.Config) {
		for i := range c.CronTasks {
			c.CronTasks[i].NextRunAt = nextByID[c.CronTasks[i].ID]
		}
	})
}

// Close 停止调度器。与 Reload 同样把等待收尾放到锁外（理由见 Reload）。
func (m *Module) Close() error {
	m.reloadMu.Lock()
	defer m.reloadMu.Unlock()

	m.mu.Lock()
	old := m.cron
	m.cron = nil
	m.mu.Unlock()
	m.stopScheduler(old)
	return nil
}

// Status 实现 module.StatusReporter。
func (m *Module) Status() module.Status {
	m.mu.Lock()
	defer m.mu.Unlock()
	// 健康 = 调度器在运行，且没有任务的最近一次执行是失败的。
	// 任一任务下次执行成功即自动恢复健康（见 markResult），不需要人工清除。
	return module.Status{
		Name:    "cron",
		Total:   m.tasks,
		Active:  m.active,
		Healthy: m.cron != nil && len(m.failed) == 0,
	}
}

// RunTaskByID 立即执行一次指定任务（供「立即执行」按钮调用）。
// 无论任务是否启用都可手动触发；执行结果同样回写 LastRunAt/LastStatus。
func (m *Module) RunTaskByID(id string) (string, error) {
	if m.cfgMgr == nil {
		return "", fmt.Errorf("配置未就绪")
	}
	cfg := m.cfgMgr.Snapshot()
	var task *config.CronTask
	for i := range cfg.CronTasks {
		if cfg.CronTasks[i].ID == id {
			task = &cfg.CronTasks[i]
			break
		}
	}
	if task == nil {
		return "", fmt.Errorf("计划任务不存在")
	}
	return m.execute(*task)
}

// runTask 查找并执行任务动作（调度器回调，忽略返回值，仅记录日志）。
func (m *Module) runTask(task config.CronTask) {
	if _, err := m.execute(task); err != nil && !errors.Is(err, errStillRunning) {
		m.log.Error("计划任务执行失败", "task", task.Name, "err", err.Error())
	}
}

// errStillRunning 表示同一任务的上一轮尚未结束，本次执行被跳过（不是执行失败）。
var errStillRunning = errors.New("上一轮仍在执行中，已跳过本次执行")

// beginRun 声明某任务开始执行；该任务已在执行时返回 false。
//
// 不用 robfig 的 cron.WithChain(cron.SkipIfStillRunning(...))：它的"是否在执行"状态挂在
// 调度器条目上，而保存任意配置都会触发 Reload 重建调度器，状态随之重置；它也完全覆盖不到
// 面板「立即执行」按钮走的 RunTaskByID 路径。模块级集合两条路径都能挡住，且跨重载有效。
//
// 并发执行同一任务的代价是实打实的：cron 表达式的间隔短于任务耗时时（例如每分钟一次、
// 但 cert.renew 的 DNS-01 要跑几分钟），实例会不断叠加——同时向 CA 下多个 order 会迅速
// 耗尽 Let's Encrypt 每周 5 次的重复签发配额，并写入互相冲突的 DNS TXT 记录；
// ddns.refresh 则会并发改写同一条 DNS 记录。
func (m *Module) beginRun(id string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.running[id] {
		return false
	}
	m.running[id] = true
	return true
}

// endRun 清除任务的"在执行"标记。
func (m *Module) endRun(id string) {
	m.mu.Lock()
	delete(m.running, id)
	m.mu.Unlock()
}

// markResult 记录任务最近一次执行是否失败，供 Status 判定健康状况。
func (m *Module) markResult(id string, failed bool) {
	m.mu.Lock()
	if failed {
		m.failed[id] = true
	} else {
		delete(m.failed, id)
	}
	m.mu.Unlock()
}

// execute 执行任务动作并回写执行状态，返回结果描述与错误。
func (m *Module) execute(task config.CronTask) (string, error) {
	// 同一任务不并发执行；跳过时不改写 LastStatus——上一轮的真实结果比"已跳过"更有用。
	if !m.beginRun(task.ID) {
		m.log.Warn("计划任务上一轮仍在执行，跳过本轮", "task", task.Name)
		return "", errStillRunning
	}
	defer m.endRun(task.ID)

	m.mu.Lock()
	fn := m.handlers[task.Action.Type]
	m.mu.Unlock()

	start := time.Now()
	if fn == nil {
		m.log.Warn("计划任务无对应处理器", "task", task.Name, "type", task.Action.Type)
		m.markResult(task.ID, true)
		m.writeResult(task, "无对应处理器: "+task.Action.Type)
		return "", fmt.Errorf("无对应处理器: %s", task.Action.Type)
	}

	msg, err := fn(task.Action, task.TimeoutSec)
	elapsed := time.Since(start).Milliseconds()
	if err != nil {
		m.markResult(task.ID, true)
		m.writeResult(task, "失败: "+err.Error())
		return "", err
	}
	m.markResult(task.ID, false)
	if msg == "" {
		msg = "成功"
	}
	m.log.Info("计划任务执行完成", "task", task.Name, "result", msg, "ms", elapsed)
	m.writeResult(task, msg)
	return msg, nil
}

// writeResult 回写任务的最近执行时间、状态，并刷新下次执行时间。
func (m *Module) writeResult(task config.CronTask, status string) {
	if m.cfgMgr == nil {
		return
	}
	now := time.Now()
	var next int64
	if task.Enabled {
		if sched, perr := robfig.ParseStandard(task.Cron); perr == nil {
			next = sched.Next(now).Unix()
		}
	}
	_ = m.cfgMgr.UpdateState(func(c *config.Config) {
		for i := range c.CronTasks {
			if c.CronTasks[i].ID == task.ID {
				c.CronTasks[i].LastRunAt = now.Unix()
				// 任务结果可能是被请求 URL 的整段响应体，长度不可控，需裁剪后再持久化。
				c.CronTasks[i].LastStatus = config.TruncateStatus(status)
				c.CronTasks[i].NextRunAt = next
				return
			}
		}
	})
}
