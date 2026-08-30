package webhook

import (
	"runtime"
	"strconv"
	"testing"

	"mantou/internal/config"
)

// 条件求值原来先把 [*] 展开的全部值平铺成一个切片再开始比。请求体虽有体积上限
//（MaxBodyKB，最大 4 MB），但那管不住展开的规模：嵌套 [*] 是乘法关系，
// 而成本是"每请求 × 每条件"（上限 50 条规则）。下面这组测试钉住那道上限，
// 以及"封顶之后每个算子怎么答"（见 5-D / 2.8-E）。

// starRoot 造一份 {"body":{"items":[...]}}，n 个元素由 fill 决定长什么样。
func starRoot(n int, fill func(i int) any) map[string]any {
	items := make([]any, 0, n)
	for i := 0; i < n; i++ {
		items = append(items, fill(i))
	}
	return map[string]any{"body": map[string]any{"items": items}}
}

// nestedStarRoot 造两层数组：outer 组、每组 inner 个元素。
// 嵌套 [*] 是乘法关系——一份不大的载荷正是这样展开出远大于自身的东西。
func nestedStarRoot(outer, inner int) map[string]any {
	groups := make([]any, 0, outer)
	for i := 0; i < outer; i++ {
		items := make([]any, 0, inner)
		for j := 0; j < inner; j++ {
			items = append(items, map[string]any{"名称": "馒头"})
		}
		groups = append(groups, map[string]any{"items": items})
	}
	return map[string]any{"body": map[string]any{"groups": groups}}
}

func plainItem(int) any { return map[string]any{"名称": "馒头"} }

// ---------- 上限本身 ----------

// TestLookupVisitCapsFlatExpansion 单层 [*] 撞上上限时停下来，并如实报告还有值没看。
func TestLookupVisitCapsFlatExpansion(t *testing.T) {
	root := starRoot(maxLookupVisits+500, plainItem)
	n, capped := lookupVisit(root, parsePath("body.items[*].名称"), func(any) bool { return true })
	if n != maxLookupVisits {
		t.Fatalf("访问了 %d 个值，上限应为 %d", n, maxLookupVisits)
	}
	if !capped {
		t.Fatal("撞上上限却没报告 capped——调用方就没法知道自己看的是不全的")
	}
}

// TestLookupVisitCapsNestedExpansion 嵌套 [*] 是乘法关系，上限一样管得到。
func TestLookupVisitCapsNestedExpansion(t *testing.T) {
	const outer, inner = 200, 200
	if outer*inner <= maxLookupVisits {
		t.Fatalf("测试前提不成立：%d×%d 没超过上限 %d", outer, inner, maxLookupVisits)
	}
	root := nestedStarRoot(outer, inner)
	n, capped := lookupVisit(root, parsePath("body.groups[*].items[*].名称"), func(any) bool { return true })
	if n != maxLookupVisits || !capped {
		t.Fatalf("%d×%d 的展开应停在 %d 并报告封顶，实际 n=%d capped=%v",
			outer, inner, maxLookupVisits, n, capped)
	}
}

// TestLookupVisitStopsOnFirstWhenAsked 调用方说"够了"就立刻收工。
// 这是绝大多数算子的常态：一个命中值就能定论，不必把数组走完。
func TestLookupVisitStopsOnFirstWhenAsked(t *testing.T) {
	root := starRoot(maxLookupVisits+500, plainItem)
	n, capped := lookupVisit(root, parsePath("body.items[*].名称"), func(any) bool { return false })
	if n != 1 {
		t.Fatalf("说了第一个就够，却访问了 %d 个值", n)
	}
	if capped {
		t.Fatal("提前收工不该报告封顶：那是两回事，会让调用方以为答案不全")
	}
}

// TestLookupVisitSmallPayloadUntouched 反向钉住：正常大小的载荷一切照旧，
// 取值个数、顺序、以及"取不到就是取不到"都不因为多了这道上限而改变。
func TestLookupVisitSmallPayloadUntouched(t *testing.T) {
	root := sampleRoot(t)
	got := collectPath(root, parsePath("body.items[*].名称"))
	if len(got) != 2 || got[0] != "馒头" || got[1] != "花卷" {
		t.Fatalf("[*] 的取值变了：%v", got)
	}
	n, capped := lookupVisit(root, parsePath("body.items[*].名称"), func(any) bool { return true })
	if n != 2 || capped {
		t.Fatalf("两个元素的数组不该封顶，实际 n=%d capped=%v", n, capped)
	}
}

// TestLookupVisitDoesNotMaterialize 取值过程不再把中间层落地成切片。
//
// 这是这次修的正题：原来每个条件都要为 [*] 展开出的值拼一个平铺切片，
// 每个 any 占 16 字节，而这份成本按"每请求 × 每条件"计。
func TestLookupVisitDoesNotMaterialize(t *testing.T) {
	const n = maxLookupVisits
	root := starRoot(n, plainItem)
	segs := parsePath("body.items[*].名称")

	if got, capped := lookupVisit(root, segs, func(any) bool { return true }); got != n || capped {
		t.Fatalf("测试前提不成立：应访问 %d 个值且未封顶，实际 %d capped=%v", n, got, capped)
	}

	const rounds = 10
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	for i := 0; i < rounds; i++ {
		seen := 0
		lookupVisit(root, segs, func(any) bool { seen++; return true })
		if seen != n {
			t.Fatalf("第 %d 轮只访问了 %d 个值", i+1, seen)
		}
	}
	runtime.ReadMemStats(&after)

	per := (after.TotalAlloc - before.TotalAlloc) / rounds
	// 平铺一份的话，光这 n 个 any 就要 16n 字节。留 16 倍余量：
	// 这里要抓的是"又落地了"，不是抠几十字节的闭包开销。
	const flat = 16 * n
	if per > flat/16 {
		t.Fatalf("每次取值分配了 %d 字节，平铺一份要 %d 字节——中间层又落地了", per, flat)
	}
}

// ---------- 封顶之后每个算子怎么答 ----------

// TestCountAboveCapAnswersLowerBound 数量类算子在封顶时按"不少于上限"作答。
//
// 这个下界对任何小于上限的阈值都仍然是准的：真实数量既然不少于上限，
// "多于 500"必然成立、"少于 500"必然不成立。只有阈值本身写到上限以上才会有出入，
// 最后两条就是钉这个边界——它是这道上限唯一改变了含义的地方。
func TestCountAboveCapAnswersLowerBound(t *testing.T) {
	root := starRoot(maxLookupVisits+500, plainItem)
	capStr := strconv.Itoa(maxLookupVisits)
	// 高于上限、但低于真实数量（maxLookupVisits+500）——正好夹在两个答案之间。
	between := strconv.Itoa(maxLookupVisits + 200)
	cases := []struct {
		name string
		c    config.Condition
		want bool
	}{
		{"远小于上限的阈值：多于", cond("body.items[*].名称", "countGt", "500"), true},
		{"远小于上限的阈值：不少于", cond("body.items[*].名称", "countGte", "500"), true},
		{"远小于上限的阈值：少于", cond("body.items[*].名称", "countLt", "500"), false},
		{"远小于上限的阈值：不多于", cond("body.items[*].名称", "countLte", "500"), false},
		{"远小于上限的阈值：等于", cond("body.items[*].名称", "countEq", "500"), false},
		{"刚好等于上限：不少于", cond("body.items[*].名称", "countGte", capStr), true},
		// 以下两条是被这道上限改了含义的：真实数量是 maxLookupVisits+500，
		// 数完的话这两条答案正好相反。阈值写到上限以上的数量条件本身已经不是这个模块的用法。
		{"阈值高于上限：少于（按下界作答）", cond("body.items[*].名称", "countLt", between), true},
		{"阈值高于上限：多于（按下界作答）", cond("body.items[*].名称", "countGt", between), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := evalOne(t, root, tc.c); got != tc.want {
				t.Fatalf("期望 %v，实际 %v", tc.want, got)
			}
		})
	}
}

// TestCountArrayFieldExactAboveCap 直接写字段名问数量，多大的数组都是准的。
//
// 这条路根本不展开：取到一个值、那个值是数组、答数组长度（见 countPath）。
// 用户想问"这批条目有几行"时写的就是这个，所以这道上限碰不到它。
func TestCountArrayFieldExactAboveCap(t *testing.T) {
	const n = maxLookupVisits + 500
	root := starRoot(n, plainItem)
	if !evalOne(t, root, cond("body.items", "countEq", strconv.Itoa(n))) {
		t.Fatalf("不带 [*] 的数量条件应准确答出 %d", n)
	}
	if !evalOne(t, root, cond("body.items", "countGt", strconv.Itoa(maxLookupVisits))) {
		t.Fatalf("%d 行条目应判为多于上限 %d", n, maxLookupVisits)
	}
}

// TestValueMatchStopsAtHitAboveCap 值比较：上限之内命中就算命中。
func TestValueMatchStopsAtHitAboveCap(t *testing.T) {
	root := starRoot(maxLookupVisits+500, func(i int) any {
		if i == 3 {
			return map[string]any{"名称": "花卷"}
		}
		return map[string]any{"名称": "馒头"}
	})
	if !evalOne(t, root, cond("body.items[*].名称", "eq", "花卷")) {
		t.Fatal("第 4 个元素就命中了，却判为不命中")
	}
}

// TestValueMatchBeyondCapNotFound 只出现在上限之外的值取不到，条件按不命中作答。
//
// 方向上是收紧的：条件不成立 → 消息不发到这个目标。反过来（把封顶当命中）
// 会让一份足够大的载荷把消息推到任何一个配了条件的群里。
func TestValueMatchBeyondCapNotFound(t *testing.T) {
	last := maxLookupVisits + 499
	root := starRoot(maxLookupVisits+500, func(i int) any {
		if i == last {
			return map[string]any{"名称": "花卷"}
		}
		return map[string]any{"名称": "馒头"}
	})
	// 前提：那个值真的在载荷里，只是排在上限之外。
	if got := collectPath(root, parsePath("body.items["+strconv.Itoa(last)+"].名称")); len(got) != 1 || got[0] != "花卷" {
		t.Fatalf("测试前提不成立：第 %d 个元素不是花卷，实际 %v", last, got)
	}
	if evalOne(t, root, cond("body.items[*].名称", "eq", "花卷")) {
		t.Fatal("只在上限之外出现的值不该判为命中")
	}
}

// TestValueMatchStopsAtFirstHit 值比较命中之后立刻收工，不把数组走完。
//
// 条件求值是"每请求 × 每条件"的成本（上限 50 条规则），一条已经命中的条件
// 不该再为后面一万个元素买单。原来的写法非要先把全部值平铺出来才开始比。
//
// 用分配量来钉：这里每个元素都是对象，比较时要先转成文本（tmplx.Str 走 json.Marshal），
// 于是"只比一个"与"比一万个"的分配量差着三个数量级，量出来不会含糊。
func TestValueMatchStopsAtFirstHit(t *testing.T) {
	root := starRoot(maxLookupVisits, plainItem) // 每个元素都是 {"名称":"馒头"}，条条都命中
	g, errs := compileConds("all", []config.Condition{cond("body.items[*]", "contains", "馒头")})
	if len(errs) > 0 {
		t.Fatalf("条件编译出错: %v", errs)
	}
	if !g.match(root) {
		t.Fatal("测试前提不成立：第一个元素就该命中")
	}

	const rounds = 10
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	for i := 0; i < rounds; i++ {
		if !g.match(root) {
			t.Fatalf("第 %d 轮不命中了", i+1)
		}
	}
	runtime.ReadMemStats(&after)

	per := (after.TotalAlloc - before.TotalAlloc) / rounds
	// 走完一万个元素的话，单是每个元素转一次文本就要几十万字节。
	const budget = 4096
	if per > budget {
		t.Fatalf("一次求值分配了 %d 字节（上限 %d）——命中之后还在往下走", per, budget)
	}
}

// TestExistsAndEmptyAboveCap exists 只要一个值，empty 按上限之内的值作答。
func TestExistsAndEmptyAboveCap(t *testing.T) {
	blank := starRoot(maxLookupVisits+500, func(int) any { return map[string]any{"名称": "  "} })
	if !evalOne(t, blank, cond("body.items[*].名称", "exists", "")) {
		t.Fatal("有值却判为不存在")
	}
	if !evalOne(t, blank, cond("body.items[*].名称", "empty", "")) {
		t.Fatal("上限之内全是空白，应判为空")
	}

	// 第一个就非空：立刻定论，不必把数组走完。
	filled := starRoot(maxLookupVisits+500, func(i int) any {
		if i == 0 {
			return map[string]any{"名称": "馒头"}
		}
		return map[string]any{"名称": "  "}
	})
	if evalOne(t, filled, cond("body.items[*].名称", "empty", "")) {
		t.Fatal("第一个元素非空，不该判为空")
	}
}
