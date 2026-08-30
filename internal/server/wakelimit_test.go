package server

import (
	"testing"
	"time"
)

// TestWakeLimiterBurstThenThrottle 锁定 W-9b：手动唤醒接口必须有速率上限。
// 桶容量内的连点放行，之后按补充间隔放行。
func TestWakeLimiterBurstThenThrottle(t *testing.T) {
	l := newWakeLimiter()
	now := time.Now()

	// 连点 wakeBurst 次都应放行：这是正常的人类操作。
	for i := 0; i < wakeBurst; i++ {
		if ok, _ := l.allow("d1", now); !ok {
			t.Fatalf("第 %d 次（桶容量 %d 之内）被误拦", i+1, wakeBurst)
		}
	}
	// 第 wakeBurst+1 次必须被拦，且给出可用的重试提示。
	ok, retry := l.allow("d1", now)
	if ok {
		t.Fatalf("超出桶容量 %d 仍被放行：接口可被当成任意速率的 UDP 广播发生器", wakeBurst)
	}
	if retry <= 0 || retry > wakeRefillInterval {
		t.Fatalf("重试提示不合理：%v（应在 0 与补充间隔 %v 之间）", retry, wakeRefillInterval)
	}

	// 等一个补充间隔后应恰好放行一次，紧接着的第二次仍被拦。
	now = now.Add(wakeRefillInterval)
	if ok, _ := l.allow("d1", now); !ok {
		t.Fatalf("等满一个补充间隔 %v 后仍被拦", wakeRefillInterval)
	}
	if ok, _ := l.allow("d1", now); ok {
		t.Fatal("一个补充间隔只应补 1 个令牌，却放行了两次")
	}
}

// TestWakeLimiterPerDevice 限流按设备计量：一台被限速不该牵连另一台。
// 否则「20 台设备逐个唤醒」这种完全正常的操作会被自己拦下来。
func TestWakeLimiterPerDevice(t *testing.T) {
	l := newWakeLimiter()
	now := time.Now()

	for i := 0; i <= wakeBurst; i++ {
		l.allow("d1", now)
	}
	if ok, _ := l.allow("d1", now); ok {
		t.Fatal("d1 应已被限速")
	}
	for i := 0; i < wakeBurst; i++ {
		if ok, _ := l.allow("d2", now); !ok {
			t.Fatalf("d2 的第 %d 次被 d1 的限速牵连", i+1)
		}
	}
}

// TestWakeLimiterRejectsClockJumpBackwards 系统时钟被向后调整时不得凭空扣令牌。
func TestWakeLimiterRejectsClockJumpBackwards(t *testing.T) {
	l := newWakeLimiter()
	now := time.Now()
	l.allow("d1", now)

	// 时钟倒退 1 小时：剩余令牌应保持不变，而不是被负的 elapsed 扣成 0。
	back := now.Add(-time.Hour)
	before := l.buckets["d1"].tokens
	l.allow("d1", back)
	after := l.buckets["d1"].tokens
	if after != before-1 {
		t.Fatalf("时钟倒退后令牌数异常：%v → %v（应恰好少 1）", before, after)
	}
}

// TestWakeLimiterGCReleasesBuckets 满桶且闲置的条目应被清掉，
// 且表远低于历史峰值时归还桶内存——否则一次大批量唤醒会永久占住这块内存。
func TestWakeLimiterGCReleasesBuckets(t *testing.T) {
	l := newWakeLimiter()
	now := time.Now()

	// 撑到足以触发 mapx.ShrinkSparse 的规模。
	for i := 0; i < wakeShrinkFloor*2; i++ {
		l.allow(string(rune('a'+i%26))+string(rune('A'+i/26)), now)
	}
	grown := len(l.buckets)
	if grown < wakeShrinkFloor {
		t.Skipf("键构造重复过多，只涨到 %d 条，不足以验证缩容", grown)
	}

	// 时间推进到令牌补满且超过闲置期之后，再触发一次清扫。
	later := now.Add(wakeIdleTTL + wakeBurst*wakeRefillInterval + time.Minute)
	l.allow("survivor", later)
	if n := len(l.buckets); n > 1 {
		t.Fatalf("满桶且闲置 %v 的条目未被清掉：仍有 %d 条", wakeIdleTTL, n)
	}
	if l.peak > 1 {
		t.Fatalf("缩容后峰值未同步下调：peak = %d", l.peak)
	}
}
