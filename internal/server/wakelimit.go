package server

import (
	"sync"
	"time"

	"mantou/internal/mapx"
)

const (
	// wakeBurst 单台设备手动唤醒的令牌桶容量。
	// 取 3 是因为「连点两三下」是正常的人类操作——魔术包是不可靠的 UDP 广播，
	// 用户没看到设备亮起来就再点一次，这不该被当成滥用。
	wakeBurst = 3

	// wakeRefillInterval 令牌补充间隔：每这么久补 1 个。
	// 取 3 秒的依据是这个动作本身的性质：魔术包要么被目标网卡收到并触发开机，
	// 要么目标压根没开 WOL / 不在同一二层网段——无论哪种，1 秒内重试第二次
	// 都不会改变结果，只是多打一份广播。
	wakeRefillInterval = 3 * time.Second

	// wakeIdleTTL 某台设备的桶在令牌补满且这段时间没被碰过之后清掉。
	// 满桶且闲置的桶与「不存在」完全等价，删掉不改变任何可见行为。
	wakeIdleTTL = 10 * time.Minute

	// wakeGCInterval 清扫间隔：清扫要遍历全表，不值得每次请求都做。
	wakeGCInterval = time.Minute

	// wakeShrinkFloor 触发 map 缩容的最小峰值，见 mapx.ShrinkSparse。
	wakeShrinkFloor = 256
)

// wakeBucket 一台设备的令牌桶。按值存放在 map 里，省掉每台设备一次堆分配。
type wakeBucket struct {
	tokens float64
	last   time.Time
}

// wakeLimiter 手动唤醒接口的按设备令牌桶。
//
// 为什么需要它：手动唤醒接口每次调用在自动模式下会向每张可广播网卡各发一个魔术包，
// 而接口本身没有任何速率约束——一个持有面板会话的调用方（正常用户误操作的脚本、
// 被盗用的令牌、装了恶意扩展的浏览器）可以用它当成任意速率的 UDP 广播发生器，
// 把整个二层网段灌满。限流按**设备**而不是按 IP 或全局：
// 拥有 20 台设备的用户应当能连续唤醒这 20 台，但不该能对同一台每秒打上千个包。
//
// 按设备计量还有一个附带好处：键的取值范围由本机配置（见 config.MaxWOLDevices）
// 而不是由请求方决定，表的规模天然有界——前提是调用方必须在**设备存在性检查通过之后**
// 才调用 allow，否则伪造的设备 ID 会把这张表撑大（见 handleWakeDevice）。
type wakeLimiter struct {
	mu      sync.Mutex
	buckets map[string]wakeBucket
	peak    int // buckets 见过的最大条目数，供 mapx.ShrinkSparse 判断是否该重建
	lastGC  time.Time
}

func newWakeLimiter() *wakeLimiter {
	return &wakeLimiter{buckets: make(map[string]wakeBucket, 16), lastGC: time.Now()}
}

// allow 尝试为某台设备消费一个令牌。
// 返回是否放行；被拒时第二个返回值是建议的重试等待时长（供 Retry-After 与提示文案使用）。
func (l *wakeLimiter) allow(deviceID string, now time.Time) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()

	b, ok := l.buckets[deviceID]
	if !ok {
		b = wakeBucket{tokens: wakeBurst, last: now}
	} else if elapsed := now.Sub(b.last); elapsed > 0 {
		// elapsed > 0 的判断同时挡住了系统时钟被向后调整的情况：
		// 那会让 elapsed 为负、凭空扣掉令牌。
		b.tokens += elapsed.Seconds() / wakeRefillInterval.Seconds()
		if b.tokens > wakeBurst {
			b.tokens = wakeBurst
		}
		b.last = now
	}

	allowed := b.tokens >= 1
	var retry time.Duration
	if allowed {
		b.tokens--
	} else {
		retry = time.Duration((1 - b.tokens) * float64(wakeRefillInterval))
		if retry < time.Second {
			retry = time.Second
		}
	}
	l.buckets[deviceID] = b
	if n := len(l.buckets); n > l.peak {
		l.peak = n
	}
	l.gcLocked(now)
	return allowed, retry
}

// gcLocked 清掉满桶且久未使用的条目，并在表远低于历史峰值时真正归还桶内存。
// 调用方需已持锁。
func (l *wakeLimiter) gcLocked(now time.Time) {
	if now.Sub(l.lastGC) < wakeGCInterval {
		return
	}
	l.lastGC = now
	for id, b := range l.buckets {
		idle := now.Sub(b.last)
		if idle <= wakeIdleTTL {
			continue
		}
		// 令牌是**懒补充**的：只在 allow 里按经过时间补，闲置条目里存的 tokens
		// 永远停在上次被扣减后的值（远低于容量）。因此这里必须先把闲置期间该补的补上，
		// 再判断桶是否已满——直接读 b.tokens 会导致任何被消费过的桶永远清不掉。
		if b.tokens+idle.Seconds()/wakeRefillInterval.Seconds() >= wakeBurst {
			// 满桶且闲置：与「不存在」完全等价（新建的桶也是满的），删掉不改变任何行为。
			delete(l.buckets, id)
		}
	}
	// Go 的 map 删除元素不会归还底层桶内存，必须显式重建，见 mapx.ShrinkSparse。
	l.buckets = mapx.ShrinkSparse(l.buckets, &l.peak, wakeShrinkFloor)
}
