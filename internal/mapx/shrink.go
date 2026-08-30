// Package mapx 存放对内置 map 的通用辅助，目前只有一件事：把删空后的 map 真正缩容。
package mapx

// ShrinkSparse 在 m 的条目数已远低于历史峰值时，用一个按当前规模重新分配的 map 替换它。
// 返回值即后续应使用的 map（未触发收缩时原样返回 m，不发生任何拷贝）。
//
// 为什么需要它：Go 的 map **删除元素不会归还底层桶内存**。限流器、日志抑制器这类
// 「key 由外部来源决定」的表，在一次扫描/爆破/CC 中会涨到数千条，随后被过期清扫删空——
// 但那几 MB 桶数组会一直挂在进程上直到重启。对 128MB 内存上限的部署来说，
// 这等于每遭一次攻击就永久损失一块内存。
//
// 参数：
//   - peak 由调用方持有（通常是限流器结构体的一个字段），记录见过的最大条目数；
//     函数负责更新它，调用方只需在同一把锁下调用。
//   - floor 是触发收缩的最小峰值。峰值低于它就不值得收缩：几十条记录的桶数组本就只有
//     几 KB，为此付一次全表拷贝是净亏损。
//
// 触发条件是「当前条目数 ≤ 峰值的 1/4」。收缩后峰值同步下调为当前条目数，
// 因此不会在同一水位反复重建：要再次触发，必须先重新涨上去 4 倍。
//
// 刻意不用 maps.Clone：它是否按元素数重新分配属于实现细节（Go 1.24 起 map 底层
// 换成了 Swiss Table，克隆路径也随之改写）。这里要的恰恰是「按当前规模重新分配」这一
// 唯一效果，显式 make + 拷贝才是与实现无关的写法。
func ShrinkSparse[K comparable, V any](m map[K]V, peak *int, floor int) map[K]V {
	n := len(m)
	if n > *peak {
		*peak = n
		return m
	}
	if *peak < floor || n*4 > *peak {
		return m
	}
	next := make(map[K]V, n)
	for k, v := range m {
		next[k] = v
	}
	*peak = n
	return next
}
