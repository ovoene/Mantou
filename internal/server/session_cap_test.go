package server

import (
	"fmt"
	"testing"
	"time"
)

// 本文件盯住会话表的条目上限（审计 R-02）。
//
// 从前这张表没有任何上限：每次登录成功新增一条，条目要活到绝对过期时间才被清掉，
// 而"成功登录"不经过任何限流（登录限流只在失败时记账）。反复登录就是一条无界内存增长。
//
// 要钉住的是三件事：上限真的封得住、封的代价没落在"管理员登不进来"上、
// 淘汰挑的是最不值得留的那条。

// capToken 造一个可预测的令牌。
func capToken(i int) string { return fmt.Sprintf("tok-%05d", i) }

// addN 连续注册 n 个会话。
func addN(r *sessionRegistry, n int, ttl time.Duration) {
	for i := 0; i < n; i++ {
		r.add(capToken(i), testSessionUser, ttl)
	}
}

// sessionCount 取当前条目数。
func sessionCount(r *sessionRegistry) int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.entries)
}

// TestSessionRegistryHonoursCap 反复登录不能把表撑破上限。
func TestSessionRegistryHonoursCap(t *testing.T) {
	r := newTestRegistry(t)
	// 全部给足够长的有效期：这里要测的是"活着的条目也有上限"，
	// 靠过期兜住的那部分不算数。
	const extra = 200
	for i := 0; i < sessionMaxEntries+extra; i++ {
		r.add(capToken(i), testSessionUser, time.Hour)
		if got := sessionCount(r); got > sessionMaxEntries {
			t.Fatalf("插到第 %d 条时表已有 %d 条，超过上限 %d", i+1, got, sessionMaxEntries)
		}
	}
	if got := sessionCount(r); got != sessionMaxEntries {
		t.Fatalf("插了 %d 条之后表应停在上限 %d，实际 %d",
			sessionMaxEntries+extra, sessionMaxEntries, got)
	}
}

// TestSessionRegistryNeverEvictsTheNewSession 表满时新登录必须仍然能用。
//
// 这是"淘汰而不是拒绝"的另一半：拒绝会让管理员登不进来，而"插进去随即被自己触发的
// 淘汰挑走"是同一个后果的隐蔽版本——登录接口返回 200 并下发 Cookie，那个 Cookie 却
// 从第一次请求起就是无效的。
func TestSessionRegistryNeverEvictsTheNewSession(t *testing.T) {
	r := newTestRegistry(t)
	addN(r, sessionMaxEntries+50, time.Hour)

	const latest = "tok-latest"
	r.add(latest, testSessionUser, time.Hour)
	if !sessionExists(r, latest) {
		t.Fatal("表满时新登录的那条被自己触发的淘汰挑走了")
	}
	if name, ok := r.valid(latest, testSessionUser, true, 0); !ok || name != testSessionUser {
		t.Fatalf("新会话应当立刻可用，实际 name=%q ok=%v", name, ok)
	}
}

// TestSessionRegistryEvictsDeadEntriesFirst 表满时先清已经没救的，不动还活着的。
func TestSessionRegistryEvictsDeadEntriesFirst(t *testing.T) {
	r := newTestRegistry(t)

	// 一条活的，且刚刚露过面。
	const alive = "tok-alive"
	r.add(alive, testSessionUser, time.Hour)

	// 把表填满，其中绝大多数是已经绝对过期的死条目。
	// 死条目排在活的前面被清掉，活的这条就不该被碰。
	for i := 0; i < sessionMaxEntries+10; i++ {
		r.add(capToken(i), testSessionUser, time.Millisecond)
	}
	time.Sleep(20 * time.Millisecond)
	r.add("tok-trigger", testSessionUser, time.Hour)

	if !sessionExists(r, alive) {
		t.Fatal("表里满是过期条目时，不该动那条还活着的会话")
	}
	if got := sessionCount(r); got > sessionMaxEntries {
		t.Fatalf("清完之后仍超上限：%d > %d", got, sessionMaxEntries)
	}
}

// TestSessionRegistryEvictsLeastRecentlySeen 全是活条目时，淘汰最久没露面的那条。
//
// lastSeenAt 每次鉴权请求都会刷新，所以"最久没露面"就是"这个浏览器最可能已经不在了"。
// 反过来，一个正在用面板的管理员每几秒就有一次轮询，绝不该被挤下去——
// 这条断言就是在钉这一点。
func TestSessionRegistryEvictsLeastRecentlySeen(t *testing.T) {
	r := newTestRegistry(t)

	const active = "tok-active"
	r.add(active, testSessionUser, time.Hour)
	// 把它连同后面填进来的一起做旧，再单独把 active 刷新回"刚刚"——
	// 于是它是全表最近露面的一条，而其余全部很旧。
	addN(r, sessionMaxEntries-2, time.Hour)
	r.mu.Lock()
	for _, e := range r.entries {
		e.lastSeenAt = e.lastSeenAt.Add(-time.Hour)
	}
	r.mu.Unlock()
	if _, ok := r.valid(active, testSessionUser, true, 0); !ok {
		t.Fatal("active 会话应当还有效")
	}

	// 再灌一批新的，逼着它淘汰。新灌进来的 lastSeenAt 都是"刚刚"，
	// 所以被挑走的只能是那批做旧过的。
	for i := 0; i < 100; i++ {
		r.add(fmt.Sprintf("tok-new-%03d", i), testSessionUser, time.Hour)
	}

	if !sessionExists(r, active) {
		t.Fatal("最近还在活动的会话被挤下去了——正在用面板的管理员会被无故踢出")
	}
	if got := sessionCount(r); got > sessionMaxEntries {
		t.Fatalf("超上限：%d > %d", got, sessionMaxEntries)
	}
}

// TestSessionSweepShrinksMap 清扫把表放空之后要真正归还桶内存。
//
// 删条目不会让 map 归还桶数组（见 mapx.ShrinkSparse），所以"堆满一次就永久损失一块内存"
// 是个只靠上限挡不住的后果。缩容与否在外部不可见，这里断言的是它的判据：峰值被下调。
func TestSessionSweepShrinksMap(t *testing.T) {
	r := newTestRegistry(t)
	addN(r, sessionMaxEntries, time.Millisecond)
	r.mu.RLock()
	peakAfterFill := r.peak
	r.mu.RUnlock()
	if peakAfterFill < sessionShrinkFloor {
		t.Fatalf("峰值 %d 低于缩容阈值 %d，本用例失去意义", peakAfterFill, sessionShrinkFloor)
	}

	r.sweep(time.Now().Add(time.Minute))

	r.mu.RLock()
	n, peak := len(r.entries), r.peak
	r.mu.RUnlock()
	if n != 0 {
		t.Fatalf("清扫后应一条不剩，实际 %d 条", n)
	}
	if peak != 0 {
		t.Fatalf("清扫后峰值应随之下调（表已重建），实际仍是 %d", peak)
	}
}
