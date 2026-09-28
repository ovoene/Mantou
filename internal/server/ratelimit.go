package server

import (
	"sync"
	"time"

	"mantou/internal/mapx"
)

const (
	// loginLimiterMaxEntries 失败记录表上限，防止长期运行后因大量独立来源（IP）的未清零记录无限增长。
	loginLimiterMaxEntries = 4096
	// loginLimiterShrinkFloor 触发 map 重建的最小峰值。一次分布式爆破会把表撑到几千条，
	// 而 sweep 删除条目并不会让 map 归还桶内存（见 mapx.ShrinkSparse），
	// 于是攻击停止后那块内存会一直挂着。峰值低于该阈值时不值得为此付一次全表拷贝。
	loginLimiterShrinkFloor = 512
)

// loginLimiter 对登录失败进行限流，按客户端 IP 记录失败次数与锁定截止时间。
// 达到 maxFails 后锁定 lockFor 时长；成功登录后清零。
type loginLimiter struct {
	mu       sync.Mutex
	entries  map[string]*limiterEntry
	maxFails int
	window   time.Duration
	lockFor  time.Duration
	// disabled 为 true 时（maxFails ≤ 0）不做任何限制，便于用户在设置中关闭锁定。
	disabled bool
	// pendingTTL 进行中名额的存活上限，见 defaultPendingTTL。
	pendingTTL time.Duration
	// peak 记录 entries 见过的最大条目数，供 sweep 判断是否该重建 map 以真正释放内存。
	peak int
}

type limiterEntry struct {
	fails int
	// pending 已经放行、还没出结果的尝试数（见 Acquire）。
	//
	// 只数 fails 的话，放行判断与失败记账之间隔着一次 bcrypt（约百毫秒）：
	// 同一时刻涌进来的几百个请求全都在第一条 Fail 落账之前通过了检查，
	// 「5 次失败即锁定」于是变成了「每一轮能并发多少就试多少次」。
	pending int
	// pendingAt 最近一次 Acquire 的时刻，供 pendingTTL 判断进行中的名额是不是漏还了。
	pendingAt   time.Time
	firstFailAt time.Time
	lockedUntil time.Time
}

// defaultPendingTTL 进行中名额的默认存活上限。
//
// 这是一张安全网，不是计时器：正常路径上每个名额都会被 Fail / Reset / Release 还回来。
// 它兜的是"某条路径占了名额却忘了还"（将来的改动漏写一支、或处理中途 panic）——
// 没有它，漏掉的名额会一直计入阈值，攒够 maxFails 个就把这个键永久锁死，而且没有任何
// 失败记录能解释为什么。登录那一次 bcrypt 至多几秒，两分钟已是极宽的余量；
// 需要长时间持有名额的调用方（边传边验的导入）自己把它调大（见 Server.reauth）。
const defaultPendingTTL = 2 * time.Minute

func newLoginLimiter(maxFails int, window, lockFor time.Duration) *loginLimiter {
	// 是否关闭锁定由「原始入参」判定：maxFails ≤ 0 视为不限制。
	// 必须在下方补默认值之前记录，否则关闭意图会被默认值 5 覆盖，导致设置里关不掉锁定。
	disabled := maxFails <= 0
	if maxFails <= 0 {
		maxFails = 5
	}
	if window <= 0 {
		window = 5 * time.Minute
	}
	if lockFor <= 0 {
		lockFor = 10 * time.Minute
	}
	return &loginLimiter{
		entries:    make(map[string]*limiterEntry),
		maxFails:   maxFails,
		window:     window,
		lockFor:    lockFor,
		disabled:   disabled,
		pendingTTL: defaultPendingTTL,
	}
}

// Allowed 返回该 key 当前是否允许尝试登录；若被锁定，返回剩余锁定秒数。
func (l *loginLimiter) Allowed(key string) (bool, int) {
	if l.disabled {
		return true, 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	l.sweep(now) // 顺手回收已失效记录，避免无限增长
	e := l.entries[key]
	if e == nil {
		return true, 0
	}
	if now.Before(e.lockedUntil) {
		return false, int(time.Until(e.lockedUntil).Seconds()) + 1
	}
	return true, 0
}

// Acquire 原子地完成「能不能试」与「占一个名额」两件事：放行时返回 (true, 0)，
// 并把这次尝试记为进行中；被拒时返回 false 与建议的重试秒数。
//
// 这是给「放行之后还要跑 bcrypt」的调用方用的（登录、敏感操作前的密码复核）。
// 与 Allowed + Fail 的区别在于并发：Allowed 只看已经落账的失败，而那一次 bcrypt 的
// 耗时里，任意多个并发请求都能通过检查——锁定阈值因此约束不了一次并发突发。
// Acquire 把进行中的尝试也算进阈值：同一个键上"已失败 + 正在验"的总数到了上限，
// 新来的就先等（Retry-After 1 秒，进行中的那几次很快就会出结果）。
//
// 放行之后调用方必须以下面三者之一收尾，名额才会还回来：
//   - Fail：这次尝试失败了（记一次失败，可能触发锁定）；
//   - Reset：这次尝试成功了（清掉整条记录）；
//   - Release：这次尝试没有结论（请求本身不合法、服务端状态不对等），不算失败也不算成功。
func (l *loginLimiter) Acquire(key string) (bool, int) {
	if l.disabled {
		return true, 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	l.sweep(now)
	e := l.entries[key]
	if e != nil && now.Before(e.lockedUntil) {
		return false, int(time.Until(e.lockedUntil).Seconds()) + 1
	}
	if e == nil {
		e = &limiterEntry{firstFailAt: now}
		l.entries[key] = e
	} else if now.Sub(e.firstFailAt) > l.window {
		// 窗口已过：旧的失败不再作数（与 Fail 的口径一致），进行中的照旧算。
		e.fails = 0
		e.firstFailAt = now
	}
	if e.pending > 0 && now.Sub(e.pendingAt) > l.pendingTTL {
		e.pending = 0 // 见 defaultPendingTTL：漏还的名额到点作废
	}
	if e.fails+e.pending >= l.maxFails {
		return false, 1
	}
	e.pending++
	e.pendingAt = now
	l.trimToCap(now)
	return true, 0
}

// Release 归还一个 Acquire 占下的名额，不记失败也不清失败史（见 Acquire 的说明）。
//
// 不看 disabled：名额可能是在锁定还开着时占下的，中途用户在设置里关掉了锁定。
// 这时照样得还——否则再打开锁定时，这些早就结束的尝试还挂在账上。
func (l *loginLimiter) Release(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	e := l.entries[key]
	if e == nil {
		return
	}
	if e.pending > 0 {
		e.pending--
	}
	// 只为占名额而建的空记录就地删掉，不必等清扫：成功登录走的是 Reset，
	// 走到这里的多半是参数不对的请求，没有理由让它们在表里各占一格。
	if e.fails == 0 && e.pending == 0 && e.lockedUntil.IsZero() {
		delete(l.entries, key)
	}
}

// Fail 记录一次失败；必要时进入锁定状态。
// 若这次失败对应一个 Acquire 占下的名额，名额同时归还。
func (l *loginLimiter) Fail(key string) {
	if l.disabled {
		// 锁定关着时不记失败，但占下的名额照样要还（理由同 Release）。
		l.Release(key)
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	l.sweep(now) // 回收已失效记录
	e := l.entries[key]
	if e == nil {
		e = &limiterEntry{firstFailAt: now}
		l.entries[key] = e
	} else if now.Sub(e.firstFailAt) > l.window {
		// 只重置失败计数，不换掉整条记录：进行中的名额（pending）还挂在这条上面。
		e.fails = 0
		e.firstFailAt = now
	}
	if e.pending > 0 {
		e.pending--
	}
	e.fails++
	if e.fails >= l.maxFails {
		e.lockedUntil = now.Add(l.lockFor)
		e.fails = 0
		e.firstFailAt = now
	}
	l.trimToCap(now) // 超出上限时淘汰最旧/已失效记录
}

// Reset 清除该 key 的失败记录（登录成功后调用）。
func (l *loginLimiter) Reset(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.entries, key)
}

// sweep 移除已彻底失效的记录：锁定已过期且失败窗口也已过去——这类记录不再有意义。
// 删除只清条目、不缩容，因此清扫后顺带判断一次是否该整表重建（爆破退潮后归还内存）。
func (l *loginLimiter) sweep(now time.Time) {
	for k, e := range l.entries {
		if l.expired(e, now) {
			delete(l.entries, k)
		}
	}
	l.entries = mapx.ShrinkSparse(l.entries, &l.peak, loginLimiterShrinkFloor)
}

// expired 这条记录是否已经没有任何作用：没有进行中的尝试、锁定已过、失败窗口也已过去。
// 进行中的那条必须留着——删掉它，Acquire 记下的名额就凭空消失了；
// 名额超过 pendingTTL 还没还的按漏还处理（见 defaultPendingTTL），不再拦着清扫。
func (l *loginLimiter) expired(e *limiterEntry, now time.Time) bool {
	idle := e.pending == 0 || now.Sub(e.pendingAt) > l.pendingTTL
	return idle && now.After(e.lockedUntil) && now.Sub(e.firstFailAt) >= l.window
}

// trimToCap 在记录数超过上限时淘汰，直到回到上限以内：先清已失效记录，再逐条淘汰最不值得留的那条。
//
// 原来这里只淘汰一条就返回，而且锁定中的记录一概跳过。于是"表已满、且记录都还有效"时
// 记录数会继续增长——IPv6 下来源地址可以任意多，这就是一条无界的内存放大。
// 现在的取舍与 ipx.IPLimiter 一致：内存有界优先，限流效果按"淘汰哪一条"来保。
func (l *loginLimiter) trimToCap(now time.Time) {
	if len(l.entries) <= loginLimiterMaxEntries {
		return
	}
	for k, e := range l.entries {
		if l.expired(e, now) {
			delete(l.entries, k)
		}
	}
	for len(l.entries) > loginLimiterMaxEntries {
		if !l.evictOne(now) {
			return
		}
	}
}

// evictOne 淘汰一条最不值得留的记录，返回是否真的删掉了一条；调用方须持有 l.mu。
//
// 优先淘汰未锁定的、失败最早的那条：它离锁定还差几次，删掉它的代价最小。
// 只有整张表都在锁定中时才动锁定记录，且挑锁定最快到期的那条——
// 保住内存上限的同时，留下的是还能挡更久的那些锁。
//
// 有进行中尝试的记录（pending > 0）与锁定记录同等对待：删掉它等于把正在计入阈值的
// 那几次尝试一笔勾销，而"并发突发"恰恰是这张表满的时候最可能出现的形态。
func (l *loginLimiter) evictOne(now time.Time) bool {
	var (
		victim        string
		found         bool
		haveUnlocked  bool
		oldestFail    time.Time
		soonestUnlock time.Time
	)
	for k, e := range l.entries {
		if now.Before(e.lockedUntil) || e.pending > 0 {
			if haveUnlocked {
				continue // 有未锁定的候选可淘汰时，锁定中的记录一律保留
			}
			if !found || e.lockedUntil.Before(soonestUnlock) {
				victim, found, soonestUnlock = k, true, e.lockedUntil
			}
			continue
		}
		if !haveUnlocked || e.firstFailAt.Before(oldestFail) {
			victim, found, haveUnlocked, oldestFail = k, true, true, e.firstFailAt
		}
	}
	if !found {
		return false
	}
	delete(l.entries, victim)
	return true
}

// update 在运行时按设置刷新限流参数（次数上限 / 锁定窗口 / 锁定时长），保留既有失败记录。
func (l *loginLimiter) update(maxFails int, window, lockFor time.Duration) {
	if window <= 0 {
		window = 5 * time.Minute
	}
	if lockFor <= 0 {
		lockFor = 10 * time.Minute
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.maxFails = maxFails
	l.window = window
	l.lockFor = lockFor
	l.disabled = maxFails <= 0
}
