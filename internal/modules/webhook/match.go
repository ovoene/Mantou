package webhook

import (
	"regexp"
	"strconv"
	"strings"

	"mantou/internal/config"
	"mantou/internal/tmplx"
)

// Operators 全部可用算子，供 API 校验与前端下拉共用一份清单。
// 新增算子要同时改这里和 matchValue（或 test，若它不逐值求值）。
//
// count* 这一组与其余算子有本质区别：它们比的是**取到几个值**，而不是值本身，
// 因此在 test 里就地判掉，不进逐值循环。"创建人多于 1 个"这类分流只能这么表达——
// 路径带 [*] 时一条载荷会取出一串值，逐值比较永远回答不了"一共几个"。
var Operators = []string{
	"eq", "ne", "contains", "notContains", "prefix", "suffix",
	"in", "regex", "gt", "gte", "lt", "lte", "exists", "empty",
	"countGt", "countGte", "countLt", "countLte", "countEq",
}

// opByLower 算子的大小写容错表：小写形式 → 清单里的规范形式。
var opByLower = func() map[string]string {
	m := make(map[string]string, len(Operators))
	for _, op := range Operators {
		m[strings.ToLower(op)] = op
	}
	return m
}()

// CanonicalOperator 把算子归一成清单里的写法，认不出则原样返回。
//
// 大小写容错只在这里做：清单里有 notContains、countGt 这类驼峰名，
// 而配置有三条写入路径（面板、整份导入、手改 config.json），后两条很容易写成全小写。
// 归一放在加载/编译侧而不是保存侧，是因为保存侧的校验必须拿规范形式去比，
// 若在那之前统一转小写，这些驼峰算子将永远通不过校验。
func CanonicalOperator(op string) string {
	if c, ok := opByLower[strings.ToLower(strings.TrimSpace(op))]; ok {
		return c
	}
	return op
}

// ValidOperator 判断算子是否受支持（大小写不敏感）。
func ValidOperator(op string) bool {
	_, ok := opByLower[strings.ToLower(strings.TrimSpace(op))]
	return ok
}

// IsCountOperator 判断算子比的是"取到几个值"。供 API 校验与前端提示复用：
// 这组算子的 Value 必须是个数字，而其余算子的 Value 是任意文本。
func IsCountOperator(op string) bool {
	switch CanonicalOperator(op) {
	case "countGt", "countGte", "countLt", "countLte", "countEq":
		return true
	}
	return false
}

// CheckRegex 校验正则表达式能否编译，供 API 在保存时拦下写错的表达式。
//
// 运行期编译失败只能让这条条件永不命中（见 condRT.test），从用户角度就是
// "规则配了却不生效"，无从查起；保存时报错才能把问题还原成一句可以照着改的话。
func CheckRegex(expr string) error {
	_, err := regexp.Compile(expr)
	return err
}

// segment 路径里的一段。
//
// 支持三种写法：
//
//	body.消息编号     普通字段
//	body.items[0]     取第 0 个元素
//	body.items[*].名称 展开数组，后续段对**每个元素**求值
//
// [*] 的语义是「任一元素满足即算满足」：判断"这一组数据里有没有某个名称"时，
// 只能这么表达——写死下标就变成了只看第一条。
type segment struct {
	name string
	idx  int  // -1 表示不按下标取
	star bool // [*] 展开
}

// parsePath 把点分路径预解析成段。
// 在 Reload 时做一次，而不是每个请求都 strings.Split ——
// 条件是每请求成本，一个接收器 50 条规则 × 20 个条件就是每请求 1000 次解析。
func parsePath(path string) []segment {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil
	}
	parts := strings.Split(path, ".")
	segs := make([]segment, 0, len(parts))
	for _, p := range parts {
		segs = append(segs, parseSeg(p))
	}
	return segs
}

func parseSeg(seg string) segment {
	i := strings.IndexByte(seg, '[')
	if i < 0 || !strings.HasSuffix(seg, "]") {
		return segment{name: seg, idx: -1}
	}
	name := seg[:i]
	inner := seg[i+1 : len(seg)-1]
	switch {
	case inner == "*":
		return segment{name: name, idx: -1, star: true}
	default:
		if n, err := strconv.Atoi(inner); err == nil && n >= 0 {
			return segment{name: name, idx: n}
		}
		// 方括号里既不是 * 也不是下标：整段当普通字段名。
		// 载荷里真有 "a[b]" 这种字段名时，不该被当成路径语法。
		return segment{name: seg, idx: -1}
	}
}

// maxLookupVisits 一次取值最多访问多少个值。
//
// 请求体本身有体积上限（MaxBodyKB，最大 4 MB），但那管不住展开的规模：
// [*] 的每一层都按数组长度乘一次，而 4 MB 的 JSON 里能塞进两百万个数组元素。
// 与键值文本那侧的 maxKVFields 同一个用意——上限之内也要有个可预算的数。
//
// 给到 10000：一条带两万行数据的消息已经超出"配个模板转发一下"的范围，
// 而真实场景里几十到几百行是常态。封顶之后仍然如实作答（见 lookupVisit 的说明）。
const maxLookupVisits = 10000

// lookupVisit 按段深度优先取值，对每个命中的值调用 fn，返回访问到的值个数。
//
// 刻意不返回切片：[*] 展开出来的值全部已经在 root 里躺着，再拼一个平铺切片
// 等于把它们按 16 字节一个重新数一遍，且成本是"每请求 × 每条件"（上限 50 条规则）。
// 走访问者之后，中间层一个都不落地，内存只用掉递归栈的那几层。
//
// fn 返回 false 表示"够了"，整趟立刻结束——绝大多数算子只要第一个命中就能定论，
// 原来的写法非要先把全部值算出来才开始比。
//
// capped 为真表示访问数撞上了 maxLookupVisits，后面还有值没看。
// 调用方必须自己决定这时候怎么答（见 condRT.test 里逐个算子的处理）：
// 一律当成"看完了"会让条件的含义随载荷大小悄悄改变。
func lookupVisit(root any, segs []segment, fn func(any) bool) (n int, capped bool) {
	// 空路径不取任何值。原来的写法在这里返回 nil，别改成"返回 root"——
	// 那会让一条路径没填的条件突然变成"命中根对象"。
	if len(segs) == 0 {
		return 0, false
	}
	p := pathVisitor{fn: fn}
	p.descend(root, segs)
	return p.n, p.capped
}

// pathVisitor lookupVisit 的一次遍历状态。
type pathVisitor struct {
	fn     func(any) bool
	n      int
	capped bool
}

// emit 交出一个值。返回 false 表示整趟结束（fn 叫停，或撞上上限）。
func (p *pathVisitor) emit(v any) bool {
	if p.n >= maxLookupVisits {
		p.capped = true
		return false
	}
	p.n++
	return p.fn(v)
}

// descend 沿剩下的段往下走。返回 false 表示整趟结束。
//
// 递归深度是段数，也就是用户填的那条路径里点号的个数——由配置决定，与载荷无关，
// 所以这里不会被一份深层嵌套的 JSON 递归爆栈。
func (p *pathVisitor) descend(v any, segs []segment) bool {
	if len(segs) == 0 {
		return p.emit(v)
	}
	s := segs[0]
	if s.name != "" {
		m, ok := v.(map[string]any)
		if !ok {
			return true
		}
		child, ok := m[s.name]
		if !ok {
			return true
		}
		v = child
	}
	switch {
	case s.star:
		items, ok := v.([]any)
		if !ok {
			return true
		}
		// 顺序与原来那版逐层平铺的结果一致（按下标从左到右），
		// lookupOne 取的"第一个"因此没有变。
		for _, it := range items {
			if !p.descend(it, segs[1:]) {
				return false
			}
		}
		return true
	case s.idx >= 0:
		items, ok := v.([]any)
		if !ok || s.idx >= len(items) {
			return true
		}
		return p.descend(items[s.idx], segs[1:])
	default:
		return p.descend(v, segs[1:])
	}
}

// lookupOne 取单个值（段已预解析），供字段映射与必填校验使用——
// 它们不需要 [*] 的多值语义，命中多个时取第一个。
func lookupOne(root any, segs []segment) (any, bool) {
	var first any
	got := false
	lookupVisit(root, segs, func(v any) bool {
		first, got = v, true
		return false // 第一个就够
	})
	return first, got
}

// condRT 一条条件的运行态：路径与正则都在 Reload 时预处理好。
type condRT struct {
	cfg  config.Condition
	segs []segment
	re   *regexp.Regexp
	// reErr 正则编译失败的原因。保留条件而不是丢掉：一条编译不了的正则
	// 必须表现为"这条条件永不命中"并在保存时给出提示，不能表现为"这条条件不存在"
	//（后者会让规则意外命中，把消息发到错误的群里）。
	reErr error
	// dead 这条条件**无法求值**：正则编译不了，或者算子不认识。
	//
	// 与"求值为假"必须分开，否则勾了取反就把它变成一条恒真条件（见 eval）。
	// 在 compileConds 里一次算好，不在每条请求上重算——条件求值是每请求 × 每条件的成本。
	dead bool
}

// condGroup 一组条件及其组合方式。
type condGroup struct {
	anyOf bool
	conds []condRT
}

// compileConds 预编译一组条件。第二个返回值是正则编译失败的原因，供状态展示。
//
// 未知算子只置 dead、不进 errs：调用方把 errs 里的每一项都当成"正则无法编译"来措辞
// （见 compileCondsWarn），混进去会给出一句对不上的提示。未知算子的警告由那里单独生成。
func compileConds(match string, list []config.Condition) (condGroup, []error) {
	g := condGroup{anyOf: match == "any", conds: make([]condRT, 0, len(list))}
	var errs []error
	for _, c := range list {
		c.Op = CanonicalOperator(c.Op)
		rt := condRT{cfg: c, segs: parsePath(c.Path)}
		if !ValidOperator(c.Op) {
			rt.dead = true
		}
		if c.Op == "regex" {
			re, err := regexp.Compile(c.Value)
			if err != nil {
				rt.reErr = err
				rt.dead = true
				errs = append(errs, err)
			} else {
				rt.re = re
			}
		}
		g.conds = append(g.conds, rt)
	}
	return g, errs
}

// match 判断这组条件是否成立。
//
// 条件为空表示无条件成立——用来做兜底规则（放在优先级最后那条），
// 这是"消息来源不止一家"时避免消息被静默丢弃的常规手法。
func (g condGroup) match(root any) bool {
	if len(g.conds) == 0 {
		return true
	}
	for _, c := range g.conds {
		ok := c.eval(root)
		if g.anyOf && ok {
			return true
		}
		if !g.anyOf && !ok {
			return false
		}
	}
	return !g.anyOf
}

// eval 求值单条条件（含取反）。
//
// dead 的条件（算子不认识 / 正则编译不了）在取反之前就短路掉。少了这一步，
// "写错 + 勾了取反"会得到一条**恒真**条件：test 只能答 false，取反就成了 true，
// 于是这条规则对任何载荷都命中，而面板上的提示写的是"该条件永不命中"——
// 提示与实际行为相反，等于把人往错的方向指。
func (c condRT) eval(root any) bool {
	if c.dead {
		return false
	}
	res := c.test(root)
	if c.cfg.Not {
		return !res
	}
	return res
}

// test 求值单条条件（不含取反）。
//
// 每个算子都走 lookupVisit，一命中就叫停。撞上 maxLookupVisits 时的答案在下面逐个交代：
// 取值只在这一层封顶，不按请求累计——按请求累计的话，改了第 1 条规则会悄悄改变
// 第 8 条规则的结果，用户没有任何办法看出来。
func (c condRT) test(root any) bool {
	// exists / empty / count* 判断的是"有没有值"和"有几个值"，必须在取不到值时
	// 也能给出答案，因此不能走下面那个"遍历取到的值"的循环。
	switch c.cfg.Op {
	case "exists":
		// 一个就够，不必数完。
		n, _ := lookupVisit(root, c.segs, func(any) bool { return false })
		return n > 0
	case "empty":
		// 见到第一个非空值就收工。封顶时按"前 maxLookupVisits 个都是空的"作答：
		// 要翻到第一万个之后才出现的那个非空值，已经不是"这个字段填了没有"的语义了。
		blank := true
		lookupVisit(root, c.segs, func(v any) bool {
			if !isBlank(v) {
				blank = false
				return false
			}
			return true
		})
		return blank
	case "countGt", "countGte", "countLt", "countLte", "countEq":
		return matchCount(c.cfg.Op, countPath(root, c.segs), c.cfg.Value)
	}

	if c.cfg.Op == "regex" && c.re == nil {
		return false // 兜底：正常路径上 eval 已按 dead 短路，走不到这里
	}
	// 任一取到的值满足即算满足，这就是 [*] 的"任一元素命中"语义。
	// 封顶时按"没命中"作答：条件不成立 → 消息不发到这个目标，方向上是收紧的。
	hit := false
	lookupVisit(root, c.segs, func(v any) bool {
		if c.matchValue(v) {
			hit = true
			return false
		}
		return true
	})
	return hit
}

// matchValue 拿单个值与条件里的字面量比较。
//
// 比较刻意是松类型的：JSON 里的 200 可能是数字也可能是字符串，
// 而配规则的人不该需要先搞清楚对方发的是哪种。
// eq/ne/contains 一律转字符串比；gt/lt 先按数字比，两边有一个不是数字才退回字符串比
// （"2026-08-22" > "2026-01-01" 这种日期字符串比较因此也能用）。
func (c condRT) matchValue(v any) bool {
	want := c.cfg.Value
	s := tmplx.Str(v)
	switch c.cfg.Op {
	case "eq":
		return s == want
	case "ne":
		return s != want
	case "contains":
		return strings.Contains(s, want)
	case "notContains":
		return !strings.Contains(s, want)
	case "prefix":
		return strings.HasPrefix(s, want)
	case "suffix":
		return strings.HasSuffix(s, want)
	case "in":
		for _, part := range splitList(want) {
			if part == s {
				return true
			}
		}
		return false
	case "regex":
		return c.re.MatchString(s)
	case "gt", "gte", "lt", "lte":
		return order(c.cfg.Op, v, s, want)
	}
	// 兜底：认不出的算子。正常路径上 eval 已按 dead 短路，走不到这里
	// （所以不必在这里操心"取反会不会把它翻成真"——那正是 dead 要解决的事）。
	return false
}

// order 处理大小比较。
func order(op string, v any, s, want string) bool {
	if a, ok1 := tmplx.Num(v); ok1 {
		if b, ok2 := tmplx.Num(want); ok2 {
			switch op {
			case "gt":
				return a > b
			case "gte":
				return a >= b
			case "lt":
				return a < b
			case "lte":
				return a <= b
			}
		}
	}
	switch op {
	case "gt":
		return s > want
	case "gte":
		return s >= want
	case "lt":
		return s < want
	case "lte":
		return s <= want
	}
	return false
}

// countPath 这条路径"取到了几个值"。
//
// 两种写法都要算得出用户心里那个数：
//
//	body.列表[*].名称   路径展开成 N 个值 → N
//	body.创建人        路径取到一个值，但那个值本身是数组 → 数组长度
//
// 后者是必须的：用户想问"创建人是不是多于一个"时会直接写字段名，
// 不会想到要补 [*]。少了这一条，那种条件永远返回"1 个"。
// 它同时是条便宜路：不带 [*] 的数量条件只访问一个值，数组多长都不用走进去。
//
// 撞上 maxLookupVisits 时返回的是上限本身，也就是真实数量的一个下界。
// 由此得出的结论对**任何小于上限的阈值**都仍然是准的：
// 真实数量既然不小于 10000，那么"多于 500"必然成立、"少于 500"必然不成立。
// 只有阈值本身写到 10000 以上时，这个答案才可能与数完之后不同。
func countPath(root any, segs []segment) float64 {
	var first any
	got := false
	n, _ := lookupVisit(root, segs, func(v any) bool {
		if !got {
			first, got = v, true
		}
		return true
	})
	if n == 1 {
		if arr, ok := first.([]any); ok {
			return float64(len(arr))
		}
	}
	return float64(n)
}

// matchCount 比较数量。want 不是数字时返回 false：
// 让条件不命中，而不是拿 0 去比——后者会让"数量大于 abc"莫名成立。
func matchCount(op string, got float64, want string) bool {
	n, ok := tmplx.Num(want)
	if !ok {
		return false
	}
	switch op {
	case "countGt":
		return got > n
	case "countGte":
		return got >= n
	case "countLt":
		return got < n
	case "countLte":
		return got <= n
	case "countEq":
		return got == n
	}
	return false
}

// splitList 拆分 in 算子的候选值：逗号、中文逗号与换行都当分隔符
// （用户会直接从别处粘一列值过来），每项去空白，丢掉空项。
func splitList(s string) []string {
	raw := strings.FieldsFunc(s, func(r rune) bool {
		return r == ',' || r == '，' || r == '\n' || r == '\r'
	})
	out := make([]string, 0, len(raw))
	for _, p := range raw {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// isBlank 判断"这个值算不算空"，供 empty 算子使用。
//
// 与 tmplx 内部的判空刻意不同：这里**不**把数字 0 视为空。
// 模板里 {{default "无" .数量}} 在数量为 0 时给个"无"是合理的展示选择，
// 但条件里 "数量 为空" 对 0 成立会让人完全无法理解规则为什么命中了。
func isBlank(v any) bool {
	switch t := v.(type) {
	case nil:
		return true
	case string:
		return strings.TrimSpace(t) == ""
	case []any:
		return len(t) == 0
	case map[string]any:
		return len(t) == 0
	}
	return strings.TrimSpace(tmplx.Str(v)) == ""
}
