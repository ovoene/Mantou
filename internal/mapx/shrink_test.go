package mapx

import "testing"

// TestShrinkSparseTracksPeak 峰值上升期不应发生任何重建。
func TestShrinkSparseTracksPeak(t *testing.T) {
	m := map[string]int{}
	peak := 0
	for i := range 100 {
		m[string(rune('a'+i%26))+string(rune('a'+i/26))] = i
		before := m
		m = ShrinkSparse(m, &peak, 8)
		if len(m) != len(before) {
			t.Fatalf("条目数被改变: %d -> %d", len(before), len(m))
		}
	}
	if peak != len(m) {
		t.Fatalf("峰值未跟上: peak=%d len=%d", peak, len(m))
	}
}

// TestShrinkSparseRebuildsAndPreserves 跌到峰值 1/4 以下时应重建，且内容完整保留。
func TestShrinkSparseRebuildsAndPreserves(t *testing.T) {
	m := make(map[int]string, 0)
	peak := 0
	for i := range 1000 {
		m[i] = "v"
	}
	m = ShrinkSparse(m, &peak, 512)
	if peak != 1000 {
		t.Fatalf("峰值应为 1000，实际 %d", peak)
	}

	// 删到 200 条（≤ 1000/4），应触发重建。
	for i := 200; i < 1000; i++ {
		delete(m, i)
	}
	m[7] = "kept"
	got := ShrinkSparse(m, &peak, 512)
	if peak != 200 {
		t.Fatalf("重建后峰值应下调为 200，实际 %d", peak)
	}
	if len(got) != 200 {
		t.Fatalf("重建后条目数应为 200，实际 %d", len(got))
	}
	if got[7] != "kept" {
		t.Fatalf("重建丢失了条目值: %q", got[7])
	}
	for i := range 200 {
		if _, ok := got[i]; !ok {
			t.Fatalf("重建丢失了 key %d", i)
		}
	}

	// 峰值已下调，紧接着再调用不应再次重建（否则每次删除都会付一次全表拷贝）。
	for i := 100; i < 200; i++ {
		delete(m, i)
	}
	// 100 条 vs 峰值 200：未到 1/4，不该重建。
	before := peak
	_ = ShrinkSparse(got, &peak, 512)
	if peak != before {
		t.Fatalf("未达阈值却重建了: peak %d -> %d", before, peak)
	}
}

// TestShrinkSparseRespectsFloor 峰值低于 floor 时不做重建（小表收缩是净亏损）。
func TestShrinkSparseRespectsFloor(t *testing.T) {
	m := map[int]int{}
	peak := 0
	for i := range 40 {
		m[i] = i
	}
	m = ShrinkSparse(m, &peak, 512)
	for i := 10; i < 40; i++ {
		delete(m, i)
	}
	if got := ShrinkSparse(m, &peak, 512); peak != 40 {
		t.Fatalf("floor 之下不应改动峰值: peak=%d len=%d", peak, len(got))
	}
}
