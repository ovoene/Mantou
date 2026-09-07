package webhook

import (
	"runtime"
	"strings"
	"testing"
)

// 键值文本原来每试一组分隔符就 strings.Split 一次整段请求体。请求体最大 4 MB，
// 一段塞满 "a=1&" 的载荷能拆出上百万段，光那个 []string 就有几十 MB——
// 而 sniffKV 会对 12 组候选分隔符各拆一次，maxKVPairs / maxKVFields 两道闸
// 都在拿到切片之后才起作用，一个字节也挡不住。
//
// 本文件钉住两件事：逐段遍历的划分与 strings.Split 一模一样（拆法不能因此改变），
// 且这条路上不再有按载荷大小增长的分配。

// TestForEachChunkMatchesSplit 划分必须与 strings.Split 逐段相同——
// 包括空段、首尾的空段、连续分隔符、多字符分隔符这些边角。
func TestForEachChunkMatchesSplit(t *testing.T) {
	cases := []struct{ text, sep string }{
		{"a=1&b=2&c=3", "&"},
		{"", "&"},
		{"a=1", "&"},
		{"&a=1", "&"},
		{"a=1&", "&"},
		{"a=1&&b=2", "&"},
		{"&&", "&"},
		{"a=1\r\nb=2", "\r\n"},   // 多字符分隔符
		{"a=1<SEP>b=2", "<SEP>"}, // 用户可以在界面上填任意分隔符
		{"没有分隔符的一整段中文", "&"},
	}
	for _, tc := range cases {
		want := strings.Split(tc.text, tc.sep)
		var got []string
		forEachChunk(tc.text, tc.sep, func(chunk string) bool {
			got = append(got, chunk)
			return true
		})
		if len(got) != len(want) {
			t.Errorf("%q 按 %q 拆：段数 %d，strings.Split 是 %d（%q vs %q）",
				tc.text, tc.sep, len(got), len(want), got, want)
			continue
		}
		for i := range want {
			if got[i] != want[i] {
				t.Errorf("%q 按 %q 拆：第 %d 段是 %q，strings.Split 给的是 %q",
					tc.text, tc.sep, i, got[i], want[i])
			}
		}
	}

	// 说"够了"就不再往下切，剩下的段一个都不碰。
	n := 0
	forEachChunk("a=1&b=2&c=3", "&", func(string) bool { n++; return n < 2 })
	if n != 2 {
		t.Errorf("第二段就叫停，却走了 %d 段", n)
	}
}

// TestCountKVPairsDoesNotAllocate 嗅探分隔符是 12 组候选各走一遍的热路径，
// 它必须一个字节都不分配——否则请求体有多大，这一步的临时内存就有多大。
func TestCountKVPairsDoesNotAllocate(t *testing.T) {
	text := strings.Repeat("k=v&", 20000) // 80 KB，拆出两万段
	if n := countKVPairs(text, "&", "="); n != 20000 {
		t.Fatalf("测试前提不成立：应数出 20000 对，实际 %d", n)
	}
	if allocs := testing.AllocsPerRun(3, func() { countKVPairs(text, "&", "=") }); allocs != 0 {
		t.Errorf("数对数分配了 %.0f 次（切片又落地了）", allocs)
	}
}

// TestSplitKVAllocationBoundedByCaps 拆字段的临时内存只跟两道上限有关，
// 与请求体本身有多大无关。切片一落地，这句话就不成立了。
func TestSplitKVAllocationBoundedByCaps(t *testing.T) {
	// 一百万段：strings.Split 光切片就要 16 MB，还要再加每段字符串头。
	text := strings.Repeat("a=1&", 1000000)

	const rounds = 5
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	for i := 0; i < rounds; i++ {
		if len(splitKV(text, "&", "=")) != 1 {
			t.Fatal("同名字段应合并成一个")
		}
	}
	runtime.ReadMemStats(&after)

	// 两道闸相乘的真实上界是 500 对 × 8 KiB，一次调用的合理分配在几十 KB 量级；
	// 留到 1 MB 是为了只抓"又按载荷大小分配了"，不去抠合并字符串的那点开销。
	per := (after.TotalAlloc - before.TotalAlloc) / rounds
	if per > 1<<20 {
		t.Errorf("一次拆分配了 %d 字节，与载荷大小同阶——切片又落地了", per)
	}
}
