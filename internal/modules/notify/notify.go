// Package notify 是消息路由的**出站**一半：把已经渲染好的消息投递到钉钉、企业微信
// 或任意自定义 HTTP 接收端，并负责超时、重试与结果回报。
//
// 它刻意不知道消息是怎么来的：入站接收器、规则匹配、模板渲染全在 webhook 模块里，
// 送到这里的已经是"发什么 + 发给谁"。这条边界让两件事各自可测，也让"手动测试发送"
// 与"真实推送"走完全相同的投递代码——面板上点一下能发出去，线上就一定能发出去。
//
// # 为什么 worker 在 New 里启动而不是 Reload 里
//
// Reload 会在每次保存配置时被调用。若 worker 随 Reload 重建，那么"用户在消息高峰时
// 改了个备注"就会连带把队列里在飞的任务连根拔掉。所以 worker 的生命周期绑在进程上，
// Reload 只做一件事：把目标表换掉。正在重试的任务下一次投递就会用上新配置
// （例如用户刚把打错的机器人地址改对），这正是想要的行为。
//
// # 存储决策（来自项目的既定约束）
//
// 不引入数据库：重试队列在内存里且有界，进程重启即丢；重试仍失败的结果记进执行日志。
// 这套取舍的前提是"通知是尽力而为的旁路"——为了不丢一条群消息而引入 8 MB 的
// SQLite 驱动（CGO_ENABLED=0 下只能用纯 Go 实现）并不划算。
package notify

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"text/template"
	"time"

	"mantou/internal/config"
	"mantou/internal/logx"
	"mantou/internal/module"
	"mantou/internal/strutil"
	"mantou/internal/tmplx"
)

// StatsWriter 供模块记下投递结果：最近投递时刻与状态、成功/失败计数。
// 这几个数只在内存里，重启归零，不落盘（见 internal/runstats 的说明）。
//
// 刻意只要这一个方法，不留泛型的 UpdateState：本模块从不主动读配置——它要用的一切
// 都在 Reload 传进来的 cfg 里预处理成了 targets，投递热路径上不该再去碰配置管理器
// （Get 每次深拷贝整份配置）。而这条路每个投递结果走一次，一条入站消息扇出到 N 个目标
// 就是 N 次。接口里没有那种方法，也就没人能顺手把它写回来。
type StatsWriter interface {
	Sent(id string, at int64, status string, ok bool)
}

var (
	// ErrQueueFull 队列已满，本次投递被拒绝。
	// 刻意返回错误而不是静默丢弃：调用方（入站接收器）据此写一条执行日志，
	// 用户才能看到"消息是被自己的队列挡下的"，而不是对着空日志猜。
	ErrQueueFull = errors.New("出站队列已满，消息被丢弃")
	// ErrQueueMemFull 队列的内存预算用完了（见 queueMemBudget）。
	// 与"条数满"分成两个错误：一个的解法是等下游恢复，另一个的解法是把消息模板写短些。
	ErrQueueMemFull = errors.New("出站队列内存已满，消息被丢弃")
	// ErrClosed 模块已关闭（进程正在退出）。
	ErrClosed = errors.New("出站模块已关闭")
	// ErrNoTarget 请求里没有任何可用目标。
	ErrNoTarget = errors.New("没有可用的通知目标")
)

// Request 一次投递请求：内容已渲染完毕，只剩"发给谁"。
type Request struct {
	// TargetIDs 目标 ID 列表。逐个投递，互不影响：一个群发失败不该拖累另一个。
	TargetIDs []string
	// Title markdown 消息的标题（钉钉必需）。
	Title string
	// Message 渲染好的正文。
	Message string
	// Format text / markdown。
	Format string
	// Data 内部事件全量数据，只给自定义 HTTP 的请求体模板用。
	Data any

	// ---- 溯源信息，只进执行日志，不影响投递 ----
	Source   string // 接收器名称
	RuleName string // 命中的规则名
	EventID  string // 入站事件 ID
}

// Result 一次投递的结果。
type Result struct {
	TargetID   string `json:"targetId"`
	TargetName string `json:"targetName"`
	TargetType string `json:"targetType"`
	OK         bool   `json:"ok"`
	// Attempt 这是第几次投递（1 起）。
	Attempt int `json:"attempt"`
	// Retrying 为真表示本次失败之后还会重试，因此不是最终结果。
	// 执行日志据此区分"失败了但还在救"与"彻底失败"。
	Retrying bool `json:"retrying"`
	// Status 人类可读的结果，成功时形如 "HTTP 200"，失败时是错误原因。
	Status string `json:"status"`
	CostMS int64  `json:"costMs"`
	At     int64  `json:"at"`

	// 溯源信息，从 Request 带过来，便于日志侧不必再关联。
	Source   string `json:"source,omitempty"`
	RuleName string `json:"ruleName,omitempty"`
	EventID  string `json:"eventId,omitempty"`
}

// targetRT 一个目标的运行期形态：配置 + 预编译好的请求体模板。
//
// 请求体模板在 Reload 时就编译好，而不是每次投递现编：一是省掉热路径上的解析，
// 二是模板写错能在"保存配置"这一刻就落到日志里，而不是等到第一条真实消息进来才暴露。
type targetRT struct {
	cfg  config.NotifyTarget
	body *template.Template
	// bodyErr 请求体模板编译失败的原因。保留目标而不是丢掉它，
	// 是为了让投递时能给出"模板有错"这个准确原因，而不是"找不到目标"。
	bodyErr error
}

// Module 出站通知模块。
type Module struct {
	mu           sync.RWMutex
	log          *logx.Logger
	stats        StatsWriter
	targets      map[string]*targetRT
	blockPrivate bool
	sink         func(Result)
	closed       bool

	// queue 有界任务队列。满了就拒绝（见 ErrQueueFull）——无界队列在对方持续故障时
	// 会把内存吃光，而这是个"通知"模块，宁可明确丢弃并记账。
	queue chan *task
	stop  chan struct{}
	wg    sync.WaitGroup

	// retryTimers 记录在等待重试的定时器，Close 时统一停掉。
	// 用 map 而不是计数：Close 需要真正 Stop 每一个，否则进程退出后
	// time.AfterFunc 的回调仍可能触发一次投递。
	retryTimers map[*time.Timer]struct{}

	depth   atomic.Int64 // 队列中 + 正在投递的任务数
	bytes   atomic.Int64 // 队列中 + 正在投递 + 等待重试的任务占的字节数（上限 queueMemBudget）
	dropped atomic.Int64 // 累计因队列满被丢弃的任务数
	failed  atomic.Int64 // 累计最终失败（含重试用尽）的投递数
	sent    atomic.Int64 // 累计成功投递数
}

// queueCap 队列容量（条数闸）。
//
// 1024 是按"对方挂掉时能缓冲多久"定的：一条推送最多扇出几个群，正常速率是分钟级，
// 1024 条足以覆盖一次十几分钟的对端故障。
//
// 条数之外还有一道字节闸 queueMemBudget：条数管不住内存，一条渲染出 64 KB 的消息
// 乘 1024 就是 64 MB。两道闸谁先到都会拒绝新任务（明确记账，不静默丢弃）。
const queueCap = 1024

// queueMemBudget 队列（含正在投递、以及在等重试）持有的字节上限，1 MiB。
//
// 这是全程序三处内存预算之一，合起来最多 5 MiB 硬上限（出厂默认 4 MiB）：
// 执行历史 1 MiB（webhook.historyMemBudget）、入站原文留存 0 ~ 3 MiB
// （webhook.defaultSourceBudget，界面上可调，默认 2 MiB）、本队列 1 MiB。
// 三处各自独立淘汰/拒绝，互不牵连。
//
// 满了就拒绝而不是排更多：这是个"通知"模块，宁可明确丢弃并记一条执行历史，
// 也不能因为下游一直不通就把内存吃到把面板自己拖死。
const queueMemBudget = 1 << 20

// taskBase 一个任务除字符串之外的固定开销（结构体 + 各种头）的估值。
const taskBase = 256

// taskBytes 一个排队任务占住的字节数。
//
// 前提是排队任务只持有字符串——事件数据已在 prepareQueued 里摘掉了，
// 否则这个数就是假的（Data 的大小由第三方推来的载荷决定，本程序说不准）。
//
// 同一条请求扇出到多个目标时，正文其实是几个任务共用的一份，这里按每个任务各算一份：
// 宁可把账算大，也不要让实际占用超出预算。
func taskBytes(t *task) int {
	n := taskBase + len(t.body) +
		len(t.req.Title) + len(t.req.Message) + len(t.req.Format) +
		len(t.req.Source) + len(t.req.RuleName) + len(t.req.EventID)
	for _, id := range t.req.TargetIDs {
		n += len(id) + 16
	}
	return n
}

// reserve 抢一块字节预算，抢不到返回 false。
// 用 CAS 而不是加锁：push 会被多个入站请求协程同时调用，而这里只需要
// "累计值不越过上限"这一个保证。
func (m *Module) reserve(n int) bool {
	for {
		cur := m.bytes.Load()
		if cur+int64(n) > queueMemBudget {
			return false
		}
		if m.bytes.CompareAndSwap(cur, cur+int64(n)) {
			return true
		}
	}
}

// release 归还任务占的预算。一条投递链的终点只有四处：投完不再重试、进不了队列、
// 排重试时模块已关闭、重试定时器醒来时模块已关闭——四处都必须调它，
// 漏一处预算就会只减不增，最后表现成"明明没积压却一直说内存满"。
func (m *Module) release(t *task) {
	if !t.counted {
		return
	}
	t.counted = false
	m.bytes.Add(-int64(t.size))
}

// workerCount 并发投递数。
//
// 4 条足够：投递是纯 IO 等待，而各家群机器人本身有频率限制（钉钉 20 条/分钟），
// 并发再高也只是更快地撞上对方的限流。少而稳比多而挤好。
const workerCount = 4

// New 创建出站通知模块并启动 worker。
//
// worker 在这里启动而不是在 Reload 里，理由见包注释：配置保存不该打断在飞的投递。
func New(log *logx.Logger, stats StatsWriter) *Module {
	m := &Module{
		log:         log,
		stats:       stats,
		targets:     make(map[string]*targetRT),
		retryTimers: make(map[*time.Timer]struct{}),
		queue:       make(chan *task, queueCap),
		stop:        make(chan struct{}),
	}
	m.wg.Add(workerCount)
	for i := 0; i < workerCount; i++ {
		go m.worker()
	}
	return m
}

// Name 实现 module.Module。
func (m *Module) Name() string { return "notify" }

// Reload 换掉目标表。不重启 worker，不动队列。
func (m *Module) Reload(cfg *config.Config) error {
	next := make(map[string]*targetRT, len(cfg.NotifyTargets))
	for _, t := range cfg.NotifyTargets {
		rt := &targetRT{cfg: t}
		if t.Type == "http" && t.BodyTemplate != "" {
			tmpl, err := tmplx.Compile("notify:"+t.ID, t.BodyTemplate)
			if err != nil {
				rt.bodyErr = err
				m.log.Warn("通知目标的请求体模板有错，向它投递会直接失败",
					"target", t.Name, "err", err.Error())
			} else {
				rt.body = tmpl
			}
		}
		next[t.ID] = rt
	}

	m.mu.Lock()
	m.targets = next
	m.blockPrivate = cfg.Settings.Security.BlockPrivateNetwork
	m.mu.Unlock()
	return nil
}

// Close 停止接收新任务，给在飞的任务一个有界的收尾窗口，然后停掉 worker。
// 可重复调用（自更新路径会调用两次 CloseAll，见 module.Manager 的说明）。
func (m *Module) Close() error {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return nil
	}
	m.closed = true
	// 等待重试的任务不再有机会投递了：进程要退出，与其让 AfterFunc 在关闭中的
	// 队列上再折腾一轮，不如现在就停掉并把它们计入丢弃数（下面会记一条日志）。
	// 它们占的字节预算不必退：模块已关闭，push 会先在 closed 上被挡掉，不会再有人来申请。
	pendingRetry := len(m.retryTimers)
	for t := range m.retryTimers {
		t.Stop()
		delete(m.retryTimers, t)
	}
	m.mu.Unlock()

	// 有界排空：队列里剩的多半是几条群消息，正常几百毫秒就走完。
	// 上限 drainTimeout 是硬约束——退出流程不能被一个吊住不返回的对端无限拖住。
	deadline := time.Now().Add(drainTimeout)
	for m.depth.Load() > 0 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if left := m.depth.Load(); left > 0 {
		m.log.Warn("退出时仍有未投递的通知，已放弃", "pending", left, "waited", drainTimeout.String())
	}
	if pendingRetry > 0 {
		m.log.Warn("退出时有等待重试的通知，已放弃", "pending", pendingRetry)
	}

	close(m.stop)
	m.wg.Wait()
	return nil
}

// drainTimeout 退出时等待在飞任务的上限。
// 30 秒是按"最慢的一次投递"定的：单次超时上限是 MaxNotifyTimeoutSec（120 秒）没错，
// 但那是用户为慢接收端留的余量，不该让整个进程的退出跟着它走。
const drainTimeout = 30 * time.Second

// Status 实现 module.StatusReporter。
func (m *Module) Status() module.Status {
	m.mu.RLock()
	total := len(m.targets)
	enabled := 0
	broken := 0
	for _, rt := range m.targets {
		if rt.cfg.Enabled {
			enabled++
		}
		if rt.bodyErr != nil {
			broken++
		}
	}
	m.mu.RUnlock()

	st := module.Status{Name: "notify", Total: total, Active: enabled, Healthy: true}
	switch {
	case broken > 0:
		st.Healthy = false
		st.Message = fmt.Sprintf("%d 个目标的请求体模板有错", broken)
	case m.dropped.Load() > 0:
		st.Healthy = false
		st.Message = fmt.Sprintf("已丢弃 %d 条（队列满）", m.dropped.Load())
	case m.depth.Load() > 0:
		st.Message = fmt.Sprintf("队列中 %d 条", m.depth.Load())
	}
	return st
}

// SetResultSink 注册结果回调，供 webhook 模块把投递结果写进执行日志。
// 回调在 worker 协程里同步调用，实现方必须自己保证快速返回且并发安全。
func (m *Module) SetResultSink(fn func(Result)) {
	m.mu.Lock()
	m.sink = fn
	m.mu.Unlock()
}

// Metrics 返回累计计数，供总览与执行日志页展示。
func (m *Module) Metrics() (sent, failed, dropped, pending int64) {
	return m.sent.Load(), m.failed.Load(), m.dropped.Load(), m.depth.Load()
}

// Targets 返回当前启用的目标（ID → 名称），供面板下拉与试运行使用。
func (m *Module) Targets() map[string]string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make(map[string]string, len(m.targets))
	for id, rt := range m.targets {
		if rt.cfg.Enabled {
			out[id] = rt.cfg.Name
		}
	}
	return out
}

// Enqueue 异步投递：入队即返回，失败按目标各自的 Retry 重试。
// 入站接收器走这条路径——第三方系统等的是一个"收到了"，不该被下游群机器人的
// 响应时间拖住（HTTP 客户端超时通常只有几秒，而钉钉偶发抖动可能就要几秒）。
func (m *Module) Enqueue(req Request) error {
	tasks, err := m.buildTasks(req)
	if err != nil {
		return err
	}
	var firstErr error
	for _, t := range tasks {
		if err := m.prepareQueued(t); err != nil {
			// 请求体模板渲染不出来是确定性错误，重试一百次也是同样的结果，
			// 所以直接记一条失败、不入队。
			m.report(failedResult(t.req, t.target.cfg.ID, t.target.cfg.Name, t.target.cfg.Type, err.Error()))
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		if err := m.push(t); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// prepareQueued 把一个即将排队的任务压成"只持有字符串"。
//
// 自定义 HTTP 的请求体在这一刻就渲染掉（而不是每次投递现渲染），然后把 Data 摘掉。
// 因为 Data 是第三方推来的整份载荷解码后的样子，大小不受本程序控制——一条带上千条
// 记录的消息就能让队列里的一个任务占掉几兆，那么 queueMemBudget 这道闸就形同虚设。
// 顺带的好处：重试不再重复渲染同一份请求体。
//
// 同步的 Send 不走这里。它投完就返回，没有"长期持有"的问题，请求体仍在投递时渲染。
func (m *Module) prepareQueued(t *task) error {
	if t.target.cfg.Type == "http" && t.target.body != nil {
		rendered, missing, err := tmplx.Render(t.target.body, m.bodyData(t.req))
		if err != nil {
			return fmt.Errorf("渲染请求体失败: %w", err)
		}
		if missing > 0 {
			// 不是错误：多来源共用一个目标时，模板引用了本次事件没带的字段很常见。
			m.log.Debug("请求体模板有取不到值的字段", "target", t.target.cfg.Name, "count", missing)
		}
		t.body = []byte(rendered)
	}
	t.req.Data = nil
	return nil
}

// Send 同步投递：每个目标只投一次，不重试，等全部结果返回。
// 面板的"测试发送"与"试运行"走这条路径——用户点了按钮就是要当场看到结果，
// 而"排到队列里等重试"对调试毫无帮助。
//
// 刻意不走 report：那一步做三件事（累计计数、列表页统计、执行历史回调），
// 而这条路径上的每一次投递都是用户自己在面板上点出来的，三件事都不该沾。
// 调十次模板就让「已发送」涨十条、执行历史里混进十条自己点的记录，
// 那两处数字与那份历史就不再是"外面发生了什么"的记录了。
// 结果直接返回给调用方，用户在弹窗里当场看到——这条路径的可观测性由那里承担。
func (m *Module) Send(ctx context.Context, req Request) ([]Result, error) {
	tasks, err := m.buildTasks(req)
	if err != nil {
		return nil, err
	}
	out := make([]Result, 0, len(tasks))
	for _, t := range tasks {
		t.attempt = 1
		t.retryLeft = 0
		out = append(out, m.deliver(ctx, t))
	}
	return out, nil
}

// buildTasks 把一次请求展开成"每个目标一个任务"，并在这一步就滤掉不可用的目标。
//
// 找不到与被禁用的目标在这里就地生成一条失败结果（而不是静默跳过）：
// 用户删掉一个目标却忘了从规则里摘掉它时，执行日志里必须留下痕迹，
// 否则表现就是"规则命中了，但什么都没发生"——这是最难排查的一类故障。
func (m *Module) buildTasks(req Request) ([]*task, error) {
	if len(req.TargetIDs) == 0 {
		return nil, ErrNoTarget
	}
	m.mu.RLock()
	closed := m.closed
	blockPrivate := m.blockPrivate
	rts := make([]*targetRT, 0, len(req.TargetIDs))
	var missing []Result
	seen := make(map[string]bool, len(req.TargetIDs))
	for _, id := range req.TargetIDs {
		if id == "" || seen[id] {
			continue
		}
		seen[id] = true
		rt, ok := m.targets[id]
		switch {
		case !ok:
			missing = append(missing, failedResult(req, id, "", "", "目标不存在（可能已被删除）"))
		case !rt.cfg.Enabled:
			missing = append(missing, failedResult(req, id, rt.cfg.Name, rt.cfg.Type, "目标已禁用"))
		default:
			rts = append(rts, rt)
		}
	}
	m.mu.RUnlock()

	if closed {
		return nil, ErrClosed
	}
	// 不可用目标的结果直接进日志与计数，不进队列。
	for _, r := range missing {
		m.report(r)
	}
	if len(rts) == 0 {
		return nil, ErrNoTarget
	}

	tasks := make([]*task, 0, len(rts))
	for _, rt := range rts {
		tasks = append(tasks, &task{
			req:          req,
			target:       rt,
			blockPrivate: blockPrivate,
			attempt:      1,
			retryLeft:    rt.cfg.Retry,
		})
	}
	return tasks, nil
}

// push 把任务放进队列。非阻塞：满了立刻拒绝，绝不在调用方（可能是 HTTP 请求处理协程）
// 上等待——那会让入站接口跟着下游一起卡住。
func (m *Module) push(t *task) error {
	m.mu.RLock()
	closed := m.closed
	m.mu.RUnlock()
	if closed {
		return ErrClosed
	}
	// 首投时抢字节预算；重试任务已经带着预算过来了（见 scheduleRetry），不再重复记账。
	if !t.counted {
		t.size = taskBytes(t)
		if !m.reserve(t.size) {
			m.dropped.Add(1)
			r := failedResult(t.req, t.target.cfg.ID, t.target.cfg.Name, t.target.cfg.Type, ErrQueueMemFull.Error())
			m.report(r)
			m.log.Warn("出站队列内存已满，通知被丢弃",
				"target", t.target.cfg.Name, "sizeKB", t.size>>10,
				"usedKB", m.bytes.Load()>>10, "budgetKB", queueMemBudget>>10, "source", t.req.Source)
			return ErrQueueMemFull
		}
		t.counted = true
	}
	// queue 从不被 close，因此这里的发送不会 panic；Close 只关 stop 让 worker 退出。
	select {
	case m.queue <- t:
		m.depth.Add(1)
		return nil
	default:
		m.release(t)
		m.dropped.Add(1)
		r := failedResult(t.req, t.target.cfg.ID, t.target.cfg.Name, t.target.cfg.Type, ErrQueueFull.Error())
		m.report(r)
		m.log.Warn("出站队列已满，通知被丢弃",
			"target", t.target.cfg.Name, "cap", queueCap, "source", t.req.Source)
		return ErrQueueFull
	}
}

// failedResult 造一条"还没真正发出去就已经失败"的结果。
func failedResult(req Request, id, name, typ, status string) Result {
	return Result{
		TargetID: id, TargetName: name, TargetType: typ,
		OK: false, Attempt: 1, Status: status,
		At:     time.Now().Unix(),
		Source: req.Source, RuleName: req.RuleName, EventID: req.EventID,
	}
}

// report 把一条结果分发出去：计数 → 运行态回写 → 执行日志回调。
func (m *Module) report(r Result) {
	switch {
	case r.OK:
		m.sent.Add(1)
	case !r.Retrying:
		// 只有最终失败才计入失败数，否则一次"重试后成功"会同时被计成 1 失败 1 成功。
		m.failed.Add(1)
	}

	if r.TargetID != "" {
		m.writeState(r)
	}

	m.mu.RLock()
	sink := m.sink
	m.mu.RUnlock()
	if sink != nil {
		sink(r)
	}
}

// writeState 把最近投递结果记进统计。
//
// 只拼状态文本，裁剪由 runstats 那边负责（它是唯一的入库口，裁一次就够）。
func (m *Module) writeState(r Result) {
	// 重试中的失败不记：用户看面板时该看到的是"这个目标现在行不行"，
	// 而一次正在被重试的失败还不构成结论，写进去只会让状态在几秒内来回跳。
	if r.Retrying {
		return
	}
	status := r.Status
	if !r.OK && r.Attempt > 1 {
		status = fmt.Sprintf("%s（第 %d 次尝试后放弃）", status, r.Attempt)
	}
	m.stats.Sent(r.TargetID, r.At, status, r.OK)
}

// statusText 把投递结果整理成一句人话（同时兜住超长的对端响应）。
func statusText(err error, detail string) string {
	if err != nil {
		return strutil.Truncate(err.Error(), 300, "…")
	}
	return strutil.Truncate(detail, 300, "…")
}
