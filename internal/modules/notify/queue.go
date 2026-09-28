package notify

import (
	"context"
	"time"

	"mantou/internal/config"
)

// task 一次针对**单个目标**的投递尝试。
// 一个 Request 扇出成多个 task，彼此完全独立：一个群发失败既不阻塞、也不影响另一个。
type task struct {
	req          Request
	target       *targetRT
	blockPrivate bool
	attempt      int // 第几次投递，1 起
	retryLeft    int // 还剩几次重试机会

	// body 预渲染好的自定义 HTTP 请求体，只有异步排队的任务才有（见 prepareQueued）。
	body []byte
	// size / counted 这个任务占的字节预算，以及是否已经记在账上。
	// 一次"首投 + N 次重试"的整条链只占一份预算：所有权随重试任务往下传，
	// 到链终结（成功 / 重试用尽 / 进不了队列）时归还。
	size    int
	counted bool
}

// retryBase / retryMax 重试的退避基数与上限。
//
// 首次重试等 5 秒而不是立刻重来：能救回来的失败几乎都是瞬时的（连接重置、对端限流、
// 一次 DNS 抖动），立刻重试撞上的往往是同一个故障窗口。之后每次乘 3
// （5s → 15s → 45s → 60s → …），封顶 60 秒：重试次数上限是 10，
// 不封顶的话最后几次会等到几十分钟以后，那时消息早已没有意义。
const (
	retryBase = 5 * time.Second
	retryMax  = 60 * time.Second
)

// backoff 返回第 attempt 次投递失败后应等待的时长。
func backoff(attempt int) time.Duration {
	d := retryBase
	for i := 1; i < attempt && d < retryMax; i++ {
		d *= 3
	}
	if d > retryMax {
		d = retryMax
	}
	return d
}

// retryDelay 是 scheduleRetry 实际取用的等待时长。
//
// 之所以是变量而不是直接调用 backoff：真实退避 5 秒起步，一个"失败→重试→成功"的
// 用例就要跑十几秒，那样的测试没人会去跑，最后等于没有测试。只有测试会改写它。
var retryDelay = backoff

// worker 从队列取任务并投递，直到 Close 关闭 stop。
//
// 收尾语义是"先把队列里的取完，再看 stop"：select 对多个就绪 case 是随机选的，
// 所以单靠一个 select 会在退出时随机丢下队列里已有的任务。这里先做一次非阻塞取，
// 取到就干活，取不到才去看是否该退出——于是 Close 的有界排空窗口是真的有用。
func (m *Module) worker() {
	defer m.wg.Done()
	for {
		select {
		case t := <-m.queue:
			m.run(t)
			continue
		default:
		}
		select {
		case t := <-m.queue:
			m.run(t)
		case <-m.stop:
			return
		}
	}
}

// run 执行一次投递，并决定要不要安排重试。
// depth 在这里递减：它统计的是"队列里 + 正在投递"的总数，Close 的排空窗口靠它判断是否已清空。
func (m *Module) run(t *task) {
	defer m.depth.Add(-1)

	if reason := m.refresh(t); reason != "" {
		// 目标已经投不了了：这条链到此为止，记一条最终失败，不再重试。
		m.release(t)
		r := failedResult(t.req, t.target.cfg.ID, t.target.cfg.Name, t.target.cfg.Type, reason)
		r.Attempt = t.attempt
		m.report(r)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeoutOf(t.target.cfg))
	res := m.deliver(ctx, t)
	cancel()

	if res.OK || t.retryLeft <= 0 {
		// 这条链到此为止，占的字节预算还回去。
		m.release(t)
		m.report(res)
		return
	}
	// 还有重试机会：先如实报一条"失败但还在救"，再排定下一次。
	res.Retrying = true
	m.report(res)
	m.scheduleRetry(t)
}

// refresh 投递前把任务换成当前的目标配置；目标已经投不了时返回放弃的原因。
//
// 任务里那份目标是入队时的快照，而从入队到真正投出去之间隔着排队，重试更是隔着最长
// 一分钟的退避——这期间用户可能改了地址、禁用或删掉了这个目标，或者打开了「禁止访问
// 内网」。照着快照投，就是删掉的目标还在收消息、刚改对的地址用不上、刚打开的内网防护
// 管不到这几条。所以每一次投递前都按 ID 重新取一次。
//
// 自定义 HTTP 的请求体是唯一换不过来的：它在入队时就按当时的模板渲染好了，事件数据
// 随即释放（见 prepareQueued），没法按新模板重渲。模板被改过的，这条按旧模板准备的
// 消息只能放弃——把旧模板的产物发给按新模板等着的接收端，比明确放弃更糟。
func (m *Module) refresh(t *task) string {
	m.mu.RLock()
	cur, ok := m.targets[t.target.cfg.ID]
	blockPrivate := m.blockPrivate
	m.mu.RUnlock()
	switch {
	case !ok:
		return "目标不存在（可能已被删除）"
	case !cur.cfg.Enabled:
		return "目标已禁用"
	}
	t.blockPrivate = blockPrivate
	if cur == t.target {
		return ""
	}
	old := t.target.cfg
	if cur.cfg.Type == "http" && cur.cfg.BodyTemplate != "" &&
		(old.Type != "http" || old.BodyTemplate != cur.cfg.BodyTemplate) {
		return "目标的请求体模板在排队期间被修改，这条按旧模板准备的消息已放弃"
	}
	if cur.cfg.Type != "http" || cur.cfg.BodyTemplate == "" {
		// 新配置用不上预渲染的请求体（改成了默认请求体，或者压根不是自定义 HTTP 了）。
		t.body = nil
	}
	t.target = cur
	return ""
}

// timeoutOf 单次投递的超时。配置里的 0 已由 normalizeNotifyTarget 兜成默认值，
// 这里再兜一次是因为 Send 也可能被单元测试用未规范化的配置直接调用。
func timeoutOf(t config.NotifyTarget) time.Duration {
	sec := t.TimeoutSec
	if sec <= 0 {
		sec = config.DefaultNotifyTimeoutSec
	}
	if sec > config.MaxNotifyTimeoutSec {
		sec = config.MaxNotifyTimeoutSec
	}
	return time.Duration(sec) * time.Second
}

// scheduleRetry 用 time.AfterFunc 排一次重投。
//
// 为什么不是"worker 里 sleep 一下再重试"：那会让一个 worker 在等待期间完全空转，
// 4 个 worker 只要各卡一条失败任务，整个模块就停摆了。定时器把等待期还给 worker，
// 代价是需要在 Close 时把它们逐个停掉（见 retryTimers）。
func (m *Module) scheduleRetry(t *task) {
	wait := retryDelay(t.attempt)
	next := &task{
		req:          t.req,
		target:       t.target,
		blockPrivate: t.blockPrivate,
		attempt:      t.attempt + 1,
		retryLeft:    t.retryLeft - 1,
		body:         t.body,
		size:         t.size,
		counted:      t.counted,
	}
	// 预算的所有权交给 next：t 之后不该再被 release，否则同一份预算会退两次。
	t.counted = false

	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		m.release(next)
		return
	}
	// 先占位再赋值：AfterFunc 的回调需要用 timer 自身做 key 把自己摘掉，
	// 而回调最快可能在 AfterFunc 返回前就跑起来（wait 极小的测试场景），
	// 因此回调里必须容忍"key 还没登记"——用 holder 间接持有可以避开这个竞态。
	holder := &struct{ t *time.Timer }{}
	timer := time.AfterFunc(wait, func() {
		m.mu.Lock()
		if holder.t != nil {
			delete(m.retryTimers, holder.t)
		}
		closed := m.closed
		m.mu.Unlock()
		if closed {
			m.release(next)
			return
		}
		// 重投同样走 push：队列此刻若已满，这条消息就按"队列满"记账并丢弃，
		// 与首投的处理完全一致。
		if err := m.push(next); err != nil {
			m.log.Warn("通知重试入队失败", "target", t.target.cfg.Name, "err", err.Error())
		}
	})
	holder.t = timer
	m.retryTimers[timer] = struct{}{}
	m.mu.Unlock()

	m.log.Info("通知投递失败，已排定重试",
		"target", t.target.cfg.Name, "attempt", t.attempt, "retryIn", wait.String(), "left", t.retryLeft)
}
