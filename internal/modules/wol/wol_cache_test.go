package wol

import (
	"sync"
	"testing"
	"time"
)

// TestCachedBroadcastTargetsReuses 锁定 W-4：同一 TTL 窗口内不得重复枚举网卡。
func TestCachedBroadcastTargetsReuses(t *testing.T) {
	invalidateTargetCache()

	first := cachedBroadcastTargets()
	if len(first) == 0 {
		t.Skip("本机没有可广播的网卡，无法验证缓存复用")
	}
	// 第二次必须命中缓存：切片头（指针/长度/容量）应与第一次完全一致。
	second := cachedBroadcastTargets()
	if len(second) != len(first) || &second[0] != &first[0] {
		t.Fatal("同一 TTL 窗口内重新枚举了网卡：缓存未命中")
	}

	// 作废后必须重新枚举，拿到的是新分配的切片。
	invalidateTargetCache()
	third := cachedBroadcastTargets()
	if len(third) > 0 && &third[0] == &first[0] {
		t.Fatal("缓存作废后仍返回旧结果")
	}
}

// TestCachedBroadcastTargetsSingleFlight 并发唤醒时枚举应被收敛成一次，
// 而不是每条协程各向内核索取一份完整适配器表。
func TestCachedBroadcastTargetsSingleFlight(t *testing.T) {
	invalidateTargetCache()

	const n = 32
	var wg sync.WaitGroup
	got := make([][]wakeTarget, n)
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func(i int) {
			defer wg.Done()
			got[i] = cachedBroadcastTargets()
		}(i)
	}
	wg.Wait()

	if len(got[0]) == 0 {
		t.Skip("本机没有可广播的网卡，无法验证单飞")
	}
	for i := 1; i < n; i++ {
		if len(got[i]) != len(got[0]) || &got[i][0] != &got[0][0] {
			t.Fatalf("第 %d 条协程拿到的不是同一份枚举结果：并发唤醒会重复枚举", i)
		}
	}
}

// BenchmarkBroadcastTargets 未缓存的裸枚举代价，作为缓存收益的对照基准。
func BenchmarkBroadcastTargets(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = broadcastTargets()
	}
}

// BenchmarkCachedBroadcastTargets 缓存命中时的代价。
func BenchmarkCachedBroadcastTargets(b *testing.B) {
	invalidateTargetCache()
	cachedBroadcastTargets() // 预热，把枚举本身排除在计时之外
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = cachedBroadcastTargets()
	}
}

// BenchmarkWakeAuto 自动模式下单个魔术包的端到端代价（含缓存）。
// 对照点：缓存前实测 142 ms/op、295 KB/op。
func BenchmarkWakeAuto(b *testing.B) {
	invalidateTargetCache()
	if len(cachedBroadcastTargets()) == 0 {
		b.Skip("本机没有可广播的网卡")
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = Wake("AA:BB:CC:DD:EE:FF", "", 9, "")
	}
}

// BenchmarkWakeBurst100 固定时间模式的上限：一秒内连发 100 个包。
// 缓存前这一轮的枚举开销就要十几秒，远超「一秒内」的语义。
// 这里只量发包本身（不含 fireScheduled 铺开的间隔）。
func BenchmarkWakeBurst100(b *testing.B) {
	invalidateTargetCache()
	if len(cachedBroadcastTargets()) == 0 {
		b.Skip("本机没有可广播的网卡")
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for j := 0; j < 100; j++ {
			_ = Wake("AA:BB:CC:DD:EE:FF", "", 9, "")
		}
	}
	_ = time.Second
}
