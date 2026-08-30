package server

import (
	"fmt"
	"testing"
	"time"
)

// 记录数撞上上限时，原来的 trimToCap 一次最多淘汰一条，而且锁定中的记录一概跳过。
// 于是"表已满、记录都还有效"时记录数会继续增长——来源地址可以任意多（IPv6 一个 /64 就够），
// 这就是一条无界的内存放大。下面这组测试钉住"内存有界 + 该保的锁还在"（见 5-G）。

// failN 对 key 连续记 n 次失败。
func failN(l *loginLimiter, key string, n int) {
	for i := 0; i < n; i++ {
		l.Fail(key)
	}
}

// TestLoginLimiterCapHoldsWhenEverythingLocked 全表都在锁定中时，记录数仍不越界。
//
// maxFails=1 使每个来源一次失败即锁定，这是老实现下淘汰完全失效的那个状态。
func TestLoginLimiterCapHoldsWhenEverythingLocked(t *testing.T) {
	l := newLoginLimiter(1, 5*time.Minute, 10*time.Minute)
	for i := 0; i < loginLimiterMaxEntries+500; i++ {
		l.Fail(fmt.Sprintf("10.1.%d.%d", (i/256)%256, i%256))
	}
	if got := len(l.entries); got > loginLimiterMaxEntries {
		t.Fatalf("记录数 %d 超过上限 %d", got, loginLimiterMaxEntries)
	}
}

// TestLoginLimiterKeepsLockedWhileUnlockedExist 有未锁定记录可淘汰时，锁定中的记录必须留着。
//
// 这条是淘汰顺序的意义所在：锁定是这个限流器唯一实际起作用的状态，
// 若来源轮换能把锁定记录顶掉，攻击者就拿到了一个重置锁定的开关。
func TestLoginLimiterKeepsLockedWhileUnlockedExist(t *testing.T) {
	l := newLoginLimiter(5, 5*time.Minute, 10*time.Minute)

	const locked = "203.0.113.9"
	failN(l, locked, 5) // 达到上限，进入锁定
	if ok, _ := l.Allowed(locked); ok {
		t.Fatal("测试前提不成立：连续 5 次失败之后应处于锁定状态")
	}

	// 把表填到上限（含上面那条锁定记录），填进去的都是"只失败过一次"的未锁定记录。
	for i := 0; i < loginLimiterMaxEntries-1; i++ {
		l.Fail(fmt.Sprintf("10.2.%d.%d", (i/256)%256, i%256))
	}

	// 让锁定记录明确成为"失败最早"的那一条。这一步不能省：Windows 上这几千次
	// time.Now() 会大量落到同一个时钟刻度，firstFailAt 一片相同，"最早"取决于
	// map 遍历顺序。钉死它，量到的才是"锁定记录被保留"这条淘汰顺序的功劳，
	// 而不是撞上了有利的遍历顺序。
	l.entries[locked].firstFailAt = time.Now().Add(-4 * time.Minute)

	l.Fail("198.51.100.3") // 超出上限一条，触发一次淘汰

	if got := len(l.entries); got > loginLimiterMaxEntries {
		t.Fatalf("记录数 %d 超过上限 %d", got, loginLimiterMaxEntries)
	}
	if ok, _ := l.Allowed(locked); ok {
		t.Fatal("锁定记录被来源轮换顶掉了")
	}
}

// TestLoginLimiterEvictsSoonestUnlockWhenAllLocked 全表锁定时，淘汰最快到期的那条。
//
// 只有这个状态下才会动锁定记录，挑谁很重要：删掉快到期的那条损失最小，
// 删掉最晚到期的那条等于把最该挡的来源放了。
func TestLoginLimiterEvictsSoonestUnlockWhenAllLocked(t *testing.T) {
	l := newLoginLimiter(1, 5*time.Minute, 10*time.Minute)
	for i := 0; i < loginLimiterMaxEntries; i++ {
		l.Fail(fmt.Sprintf("10.3.%d.%d", (i/256)%256, i%256))
	}
	if got := len(l.entries); got != loginLimiterMaxEntries {
		t.Fatalf("填表后记录数是 %d，期望 %d", got, loginLimiterMaxEntries)
	}

	now := time.Now()
	const soonest, longest = "10.3.0.0", "10.3.0.1"
	l.entries[soonest].lockedUntil = now.Add(time.Minute)
	l.entries[longest].lockedUntil = now.Add(time.Hour)

	l.Fail("198.51.100.2") // 超出上限一条，触发一次淘汰

	if _, ok := l.entries[soonest]; ok {
		t.Fatal("最快到期的锁定记录没有被淘汰")
	}
	if _, ok := l.entries[longest]; !ok {
		t.Fatal("最晚到期的锁定记录被淘汰了")
	}
	if got := len(l.entries); got > loginLimiterMaxEntries {
		t.Fatalf("记录数 %d 超过上限 %d", got, loginLimiterMaxEntries)
	}
}

// TestLoginLimiterNoEvictionBelowCap 没到上限就一条都不淘汰。
//
// 反向钉住：淘汰只该在撞上上限时发生。少了这条，把 trimToCap 写成无条件淘汰也能让上面三条通过，
// 而那会让正常使用中的锁定随时消失。
func TestLoginLimiterNoEvictionBelowCap(t *testing.T) {
	l := newLoginLimiter(5, 5*time.Minute, 10*time.Minute)
	for i := 0; i < 50; i++ {
		l.Fail(fmt.Sprintf("192.0.2.%d", i))
	}
	if got := len(l.entries); got != 50 {
		t.Fatalf("记录数是 %d，期望 50——未到上限不该淘汰任何记录", got)
	}
}
