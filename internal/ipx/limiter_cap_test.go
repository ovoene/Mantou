package ipx

import (
	"fmt"
	"testing"
	"time"
)

// 桶数撞上上限时原来是"本次直接放行"，于是限流可以被来源轮换整体关掉：
// IPv6 下一个 /64 能提供任意多的来源地址，撑满 8192 个桶之后每个新来源都免检。
// 现在改成淘汰一批最闲的桶给新来源让位。下面这组测试钉住两件事：
// 表满之后新来源仍然受限，以及正在被限流的来源不会被轮换顶出去（见 5-G）。
//
// 另一半是 3-E：这张表被所有作用域共用，所以"8192 个桶"是全局上限，
// 而不是每个接收器 / 每个站点子项各 8192 个。

// scope 测试用的作用域名。多数用例只关心一张表内的行为，用同一个即可。
const scope = "r1"

// fillLimiter 把桶表填到上限，每个来源各取掉一个令牌。
func fillLimiter(t *testing.T, l *IPLimiter) {
	t.Helper()
	for i := 0; i < limiterMaxEntries; i++ {
		if !l.Allow(scope, fmt.Sprintf("10.0.%d.%d", i/256, i%256), 1) {
			t.Fatalf("填表阶段第 %d 个来源就被拒了，测试前提不成立", i)
		}
	}
	if got := len(l.buckets); got != limiterMaxEntries {
		t.Fatalf("填表后桶数是 %d，期望 %d", got, limiterMaxEntries)
	}
}

// TestIPLimiterStillLimitsNewSourceWhenFull 表满之后，新来源照样只有一个令牌。
//
// 量的是"第二次请求"：老实现连桶都不建，所以同一个新来源可以无限次免检——
// 这正是限流被整体关掉的那条路。
func TestIPLimiterStillLimitsNewSourceWhenFull(t *testing.T) {
	l := NewIPLimiter()
	fillLimiter(t, l)

	const fresh = "203.0.113.7"
	if !l.Allow(scope, fresh, 1) {
		t.Fatal("表满时新来源的第一次请求应放行")
	}
	if l.Allow(scope, fresh, 1) {
		t.Fatal("表满时新来源的第二次请求仍被放行：这个来源没有被计入限流")
	}
}

// TestIPLimiterBucketCountStaysBounded 来源数远超上限时桶数仍不越界。
func TestIPLimiterBucketCountStaysBounded(t *testing.T) {
	l := NewIPLimiter()
	for i := 0; i < limiterMaxEntries*3; i++ {
		l.Allow(scope, fmt.Sprintf("172.16.%d.%d", (i/256)%256, i%256), 1)
	}
	if got := len(l.buckets); got > limiterMaxEntries {
		t.Fatalf("桶数 %d 超过上限 %d", got, limiterMaxEntries)
	}
}

// TestIPLimiterEvictionKeepsThrottledSource 正在被限流的来源不会被来源轮换顶出去。
//
// 这条是"按空闲时长淘汰"这个方向的意义所在：攻击者若能靠制造新来源把自己的桶顶掉，
// 就等于拿到一个随时可用的重置开关，淘汰策略再有界也没用。
func TestIPLimiterEvictionKeepsThrottledSource(t *testing.T) {
	l := NewIPLimiter()
	fillLimiter(t, l)

	const busy = "10.0.0.0" // 填表时的第一个来源
	if l.Allow(scope, busy, 1) {
		t.Fatal("测试前提不成立：令牌已取完，这次应被拒")
	}

	// 让这个来源成为表里"最不闲"的那一个，其余都是闲着的。
	// 直接改 last 是为了不等真实时间；GC 每 10 分钟才跑一次，这里不会被它顺手清掉。
	now := time.Now()
	for k, b := range l.buckets {
		if k == scope+"\x00"+busy {
			b.last = now
			continue
		}
		b.last = now.Add(-5 * time.Minute)
	}

	if !l.Allow(scope, "198.51.100.1", 1) { // 触发一次淘汰
		t.Fatal("新来源的第一次请求应放行")
	}
	if n := len(l.buckets); n >= limiterMaxEntries {
		t.Fatalf("测试前提不成立：桶数仍是 %d，没有发生淘汰", n)
	}
	if l.Allow(scope, busy, 1) {
		t.Fatal("被限流的来源在一次淘汰后又拿到了满额令牌")
	}
}

// TestIPLimiterEvictLocked 淘汰一定有进展，且一次不超过一批。
//
// "有进展"这一点值得单独钉：阈值若取成最大空闲时长，全表空闲时长相同时会一个都删不掉，
// 表满之后就再也插不进新来源——那是另一种形式的失效。
func TestIPLimiterEvictLocked(t *testing.T) {
	l := NewIPLimiter()
	fillLimiter(t, l)

	now := time.Now()
	for _, b := range l.buckets {
		b.last = now // 全表空闲时长完全相同
	}
	l.evictLocked(now)
	removed := limiterMaxEntries - len(l.buckets)
	if removed == 0 {
		t.Fatal("一次淘汰什么都没删掉")
	}
	if removed > limiterEvictBatch {
		t.Fatalf("一次淘汰了 %d 个，超过单批上限 %d", removed, limiterEvictBatch)
	}

	// 空表上调用不应 panic，也不该做什么。
	empty := NewIPLimiter()
	empty.evictLocked(time.Now())
	if len(empty.buckets) != 0 {
		t.Fatal("空表淘汰后桶数不为 0")
	}
}

// ---------- 3-E：一张表被所有作用域共用 ----------

// TestIPLimiterCapIsGlobalAcrossScopes 桶数上限是**整张表**的，不随作用域个数翻倍。
//
// 这是 3-E 要解决的问题本身：原来每个接收器各建一张表，50 个接收器各被扫一遍
// 就是 50 × 8192 个桶（45 MB 量级）。共用之后，来源再多、作用域再多，桶数仍不越界。
func TestIPLimiterCapIsGlobalAcrossScopes(t *testing.T) {
	l := NewIPLimiter()
	for s := 0; s < 20; s++ {
		id := fmt.Sprintf("recv-%d", s)
		for i := 0; i < 1000; i++ {
			l.Allow(id, fmt.Sprintf("10.%d.%d.%d", s, i/256, i%256), 1)
		}
	}
	if got := l.Len(); got > limiterMaxEntries {
		t.Fatalf("20 个作用域各扫 1000 个来源后桶数 %d，超过全局上限 %d", got, limiterMaxEntries)
	}
}

// TestIPLimiterScopesCountSeparately 共用的是表的容量，不是令牌。
//
// 同一个 IP 打两个接收器，各自的每秒配额必须各算各的——否则合并一张表就成了
// "访问 A 会消耗 B 的额度"，用户在界面上按接收器配的那个数字就不成立了。
func TestIPLimiterScopesCountSeparately(t *testing.T) {
	l := NewIPLimiter()
	const ip = "203.0.113.9"
	if !l.Allow("a", ip, 1) {
		t.Fatal("作用域 a 的第一次应放行")
	}
	if l.Allow("a", ip, 1) {
		t.Fatal("测试前提不成立：作用域 a 的令牌应已取完")
	}
	if !l.Allow("b", ip, 1) {
		t.Fatal("同一个 IP 在作用域 b 下应有自己的令牌")
	}
}

// TestIPLimiterScopeKeyNoCollision 拼键不能把两个不同的（作用域, 来源）拼成同一个桶。
//
// 直接首尾相接的话 ("ab","c") 与 ("a","bc") 就是同一个键，表现为两个接收器
// 莫名其妙地互相消耗额度——这种事一旦发生，从界面上完全看不出原因。
func TestIPLimiterScopeKeyNoCollision(t *testing.T) {
	l := NewIPLimiter()
	if !l.Allow("ab", "c", 1) {
		t.Fatal("第一次应放行")
	}
	if !l.Allow("a", "bc", 1) {
		t.Fatal("(a, bc) 与 (ab, c) 被拼成了同一个桶")
	}
	if got := l.Len(); got != 2 {
		t.Fatalf("应是两个独立的桶，实际 %d 个", got)
	}
}

// TestIPLimiterRateChangeTakesEffect 表跨配置保存存活，所以用户改了每秒上限要立刻生效。
//
// 老实现靠"整张表跟着路由表重建"来换新速率，共用一张长命的表之后这条路没了：
// 不在每次调用时把速率带进去，改动就得等那个桶空闲十分钟被回收才生效。
func TestIPLimiterRateChangeTakesEffect(t *testing.T) {
	l := NewIPLimiter()
	const ip = "198.51.100.20"
	key := scope + "\x00" + ip
	if !l.Allow(scope, ip, 1) {
		t.Fatal("第一次应放行")
	}
	if l.Allow(scope, ip, 1) {
		t.Fatal("测试前提不成立：1 次/秒的令牌应已取完")
	}

	// 调高。把"上次取令牌"挪到一秒前，于是这一秒按新速率该补出 100 个令牌——
	// 不这么做就只能等真实时间，而 1 次/秒与 100 次/秒的差别只有 10 毫秒。
	b := l.buckets[key]
	b.mu.Lock()
	b.last = time.Now().Add(-time.Second)
	b.mu.Unlock()
	passed := 0
	for i := 0; i < 50; i++ {
		if l.Allow(scope, ip, 100) {
			passed++
		}
	}
	if passed != 50 {
		t.Fatalf("上限调高到 100 次/秒后，一秒的额度只放行了 %d 次（老速率只够 1 次）", passed)
	}

	// 调低。存量令牌不许按老额度漏过去：调低之后能过的次数就是新上限。
	b.mu.Lock()
	b.tokens = 100
	b.mu.Unlock()
	if !l.Allow(scope, ip, 2) {
		t.Fatal("调低后第一次仍应放行")
	}
	if !l.Allow(scope, ip, 2) {
		t.Fatal("2 次/秒，第二次应放行")
	}
	if l.Allow(scope, ip, 2) {
		t.Fatal("上限调低后，存量令牌仍按老额度放过去了")
	}
}

// TestIPLimiterLen 与内部桶数一致：状态展示与测试都读它。
func TestIPLimiterLen(t *testing.T) {
	l := NewIPLimiter()
	if l.Len() != 0 {
		t.Fatalf("空表应是 0，实际 %d", l.Len())
	}
	l.Allow(scope, "192.0.2.1", 1)
	l.Allow(scope, "192.0.2.2", 1)
	if l.Len() != 2 {
		t.Fatalf("两个来源应是 2 个桶，实际 %d", l.Len())
	}
}

// TestIPLimiterMemoryBudget 桶数上限本身的值，绝对值写死。
//
// 上面那几条都是拿 limiterMaxEntries 算出输入再拿它做断言的，所以谁把这个常量调大
// 它们照样全绿——"内存有界"这句话真正依赖的是这个数字本身，那就得直接钉住它。
// （3-F 的 FG8 就是这么漏过去一轮的。）
//
// 一个桶的实际占用：Bucket 本体 48 字节（锁 8 + limit 8 + tokens 8 + last 24）+ 指针 8
// + 键（作用域 + \x00 + IP，字符串头 16 加数据几十字节）+ map 自身的槽位开销，
// 合计按 128 字节估。8192 × 128 = 1 MiB 出头，这是**整个模块**的上限，
// 不再乘以接收器 / 站点子项的个数。
func TestIPLimiterMemoryBudget(t *testing.T) {
	const perBucketBytes = 128
	if limiterMaxEntries != 8192 {
		t.Fatalf("桶数上限被改成了 %d：内存那笔账要跟着重算，改完把这里的数字一起改", limiterMaxEntries)
	}
	if got := limiterMaxEntries * perBucketBytes; got > 2<<20 {
		t.Fatalf("单个限流器最坏占用约 %d 字节，超过 2 MiB", got)
	}
	if limiterEvictBatch != limiterMaxEntries/8 {
		t.Fatalf("单批淘汰数应是上限的八分之一，实际 %d", limiterEvictBatch)
	}
}
