package webhook

import (
	"strconv"
	"sync"
	"time"
)

// 拒收也要留痕：每条被拒的请求都会记一条执行历史、写一行程序日志（见 handler.go 的 reject）。
// 历史进的是内存环（2000 条，满了顶掉最旧的），而程序日志那一行是**同步落盘**——
// logx 的写入在调用方的 goroutine 上完成，且全进程共用一把锁（见 logx/rotate.go）。
//
// 于是"每个请求都被拒"本身就成了放大器：对端不需要任何凭证，只要持续发，就能
//   - 把内存环整个顶掉，用户真正要看的记录一条不剩；
//   - 让每个请求都换来一次持锁写盘，把整个进程的日志写入排到一条队上。
//
// 所以"记录"这件事必须有配额，两道，按"能不能归属到接收器"分：
//
//   - anonRecorder：全局一份。路径不存在、以及启用 HTTPS / 共享端口后域名不匹配——
//     这两条路走到时还没有接收器可归属，路径本身是唯一的凭证，只能按全局算。
//   - rejectQuota：每接收器一份。路由到接收器之后的拒收（鉴权失败、超限、超体积、
//     关键词不匹配）。分开算，一个接收器被刷不影响别的接收器留痕。
//
// 两道配额都只管"记不记"，不管"回不回"：响应照旧要给，对面可能是配错了地址的第三方系统。

const (
	// anonRecordBurst 攒得下的记录配额上限，也是冷启动时一次能记多少条。
	// 给到 5：连着配错几个地址是常事，头几次必须条条都看得见。
	anonRecordBurst = 5

	// anonRecordPer 配额用完之后每隔多久补一个。
	//
	// 合到 6 条/分钟：一个持续扫描要跑五个多小时才填满 2000 条的内存环，
	// 而真在调地址的用户等一次重试就能看到下一条。
	anonRecordPer = 10 * time.Second

	// rejectRecordBurst / rejectRecordPer 带接收器的拒收的记录配额，每接收器一份。
	//
	// 比匿名那侧宽（20 条起、20 条/分钟）：能路由到接收器说明地址是对的，这类拒收
	// 十有八九正是用户在排查的东西——令牌填错、体积超限、关键词没匹配上，头几十条
	// 一条都不该省。同时仍然封着顶：按接收器算，刷一个接收器最多换来 20 条/分钟，
	// 顶不空内存环，也排不满日志写入。
	rejectRecordBurst = 20
	rejectRecordPer   = 3 * time.Second

	// maxRejectQuotaEntries 配额表的条目上限。表按接收器 ID 长键，删掉接收器后旧键
	// 会留下来，所以要有个顶。超了整表重置（等于所有接收器的配额重新加满）：
	// 要攒到这个数得先建过、删过几百个接收器，且每个都吃过一次拒收。
	maxRejectQuotaEntries = 512
)

// anonRecorder 发放"记一条拒收记录"的配额。
//
// 被挡下的次数攒着，由下一条记下来的记录带出去——否则一次扫描会安静地什么都不留，
// 而"历史里突然只剩几条"本身就是用户需要知道的事。
type anonRecorder struct {
	burst float64
	per   time.Duration

	mu      sync.Mutex
	tokens  float64
	last    time.Time
	dropped int64
}

// newRecorder 按给定的攒量与补充间隔建一个配额器。
func newRecorder(burst float64, per time.Duration) *anonRecorder {
	return &anonRecorder{burst: burst, per: per, tokens: burst}
}

// newAnonRecorder 建"没有接收器可归属的拒收"用的那一份（全局一个）。
func newAnonRecorder() *anonRecorder { return newRecorder(anonRecordBurst, anonRecordPer) }

// take 取一个记录配额。
//
// 取到时返回 merged：上一条记录之后被挡下的次数，随即归零。取不到时把这一次攒进去。
// now 用调用方手上那个时刻（请求进来的时间），不自己取时钟——测试要能推时间。
func (a *anonRecorder) take(now time.Time) (ok bool, merged int64) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.last.IsZero() {
		a.last = now
	}
	// 只在时间往前走时补配额。
	switch elapsed := now.Sub(a.last); {
	case elapsed < 0:
		// 系统时钟被往回调了（NTP 校正、手工改时间）。既不补也不倒扣，
		// 但要把窗口挪到当下：把 last 留在"未来"等于要等时钟重新走到那儿才恢复，
		// 时钟往回跳一小时就是一小时之内一条记录都不会有。
		a.last = now
	case elapsed > 0:
		a.tokens += elapsed.Seconds() / a.per.Seconds()
		// 封顶。不封的话，闲置一小时就能换来一次三百多条的连续记录，
		// 内存环照样被顶空——那正是这道配额要防的事。
		if a.tokens > a.burst {
			a.tokens = a.burst
		}
		a.last = now
	}
	if a.tokens < 1 {
		a.dropped++
		return false, 0
	}
	a.tokens--
	merged, a.dropped = a.dropped, 0
	return true, merged
}

// rejectQuota 按接收器 ID 各发一份记录配额。
//
// 挂在 Module 上而不是放进 receiverRT：路由表每次保存配置都整份重编译（见 compileAll），
// 配额跟着新表归零，等于用户保存一次配置就把闸重新打开——正在被刷的那一侧只要等一次
// 保存就能重新把内存环顶空。挂在模块上才跨重载存活，与 limiter 同一个理由。
type rejectQuota struct {
	mu   sync.Mutex
	byID map[string]*anonRecorder
}

func newRejectQuota() *rejectQuota {
	return &rejectQuota{byID: make(map[string]*anonRecorder)}
}

// take 取该接收器的一个记录配额，语义同 anonRecorder.take。
func (q *rejectQuota) take(id string, now time.Time) (ok bool, merged int64) {
	q.mu.Lock()
	if len(q.byID) > maxRejectQuotaEntries {
		q.byID = make(map[string]*anonRecorder, 1)
	}
	r := q.byID[id]
	if r == nil {
		r = newRecorder(rejectRecordBurst, rejectRecordPer)
		q.byID[id] = r
	}
	q.mu.Unlock()
	return r.take(now)
}

// mergedNote 把被合并掉的次数缀到原因后面。0 次返回空串。
func mergedNote(merged int64) string {
	if merged <= 0 {
		return ""
	}
	return "；期间另有 " + strconv.FormatInt(merged, 10) + " 次未记入"
}
