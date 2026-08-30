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
	// peak 记录 entries 见过的最大条目数，供 sweep 判断是否该重建 map 以真正释放内存。
	peak int
}

type limiterEntry struct {
	fails       int
	firstFailAt time.Time
	lockedUntil time.Time
}

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
		entries:  make(map[string]*limiterEntry),
		maxFails: maxFails,
		window:   window,
		lockFor:  lockFor,
		disabled: disabled,
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

// Fail 记录一次失败；必要时进入锁定状态。
func (l *loginLimiter) Fail(key string) {
	if l.disabled {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	l.sweep(now) // 回收已失效记录
	e := l.entries[key]
	if e == nil || now.Sub(e.firstFailAt) > l.window {
		e = &limiterEntry{firstFailAt: now}
		l.entries[key] = e
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
		if now.After(e.lockedUntil) && now.Sub(e.firstFailAt) >= l.window {
			delete(l.entries, k)
		}
	}
	l.entries = mapx.ShrinkSparse(l.entries, &l.peak, loginLimiterShrinkFloor)
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
		if now.After(e.lockedUntil) && now.Sub(e.firstFailAt) >= l.window {
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
func (l *loginLimiter) evictOne(now time.Time) bool {
	var (
		victim        string
		found         bool
		haveUnlocked  bool
		oldestFail    time.Time
		soonestUnlock time.Time
	)
	for k, e := range l.entries {
		if now.Before(e.lockedUntil) {
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
