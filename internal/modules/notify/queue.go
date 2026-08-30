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
