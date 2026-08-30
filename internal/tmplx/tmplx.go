// Package tmplx 是消息模板的渲染引擎：标准库 text/template 加上一小组**手工挑选**的纯函数。
//
// 为什么用 text/template 而不是自造一套 ${字段} 占位符替换：
// 真实场景里最常见的一类消息是"一条消息带 N 条记录，每条渲染一行"——
// 纯占位符替换表达不出循环，用户就只能回去写代码（这正是要摆脱的东西）。
// {{range}} / {{if}} 一次性解决了聚合与分支，且是零依赖、零学习成本转移
// （用户搜到的任何 Go 模板资料都直接适用）。
//
// # 安全红线：不引入 sprig
//
// 模板正文是**可以在面板里编辑**的内容。sprig 这类"模板函数大全"带 env / expandenv /
// getHostByName / getHostByName，等于给模板编辑者一条读取 MANTOU_MASTER_KEY
// （配置里全部凭证的唯一钥匙）与探测内网的通路。本包的函数表是手工挑的，
// 每一个都只做取值与格式化：不碰环境变量、不碰文件系统、不碰网络、不碰时区数据库之外的任何外部状态。
// 往这张表里加函数之前，请先回答"面板上任何一个能编辑模板的人拿到它能做什么"。
package tmplx

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"text/template"
	"time"

	"mantou/internal/strutil"
)

// MaxRenderBytes 单次渲染输出的上限。
//
// 必须有上限：{{range}} 遍历的是外部推来的数组，长度不受本程序控制——
// 一次推送里带上一万条记录，渲染结果就是几兆字符串，而它随后还要进内存队列、
// 进执行日志、进 HTTP 请求体。8 KB 也远超各家群机器人自己的上限
// （钉钉 markdown 约 20000 字节，企业微信 text 2048 字节），故上限主要是防"失控"，
// 不是防"稍微有点长"。
const MaxRenderBytes = 64 * 1024

// noValue 是 text/template 对"取不到的字段"的内置渲染结果。
//
// 本包刻意选择 missingkey=default（而不是 zero 或 error）：只有这一档能让
// {{.a.b.c}} 在中间某一层缺失时**不中断整次渲染**——zero 会报
// "nil pointer evaluating interface {}.c"，一个可选的嵌套字段就能让整条告警发不出去。
// 代价是缺字段会渲染成 <no value>，那在钉钉群里看着像程序出错，所以渲染完统一抹掉，
// 并把出现次数回报给调用方（试运行页据此提示"有 N 处字段取不到值"）。
//
// 理论上载荷里真的含有 "<no value>" 这段字面文本时也会被抹掉；
// 这个取舍是明知的——它的后果只是消息里少了一段无意义的文本。
const noValue = "<no value>"

// ErrTooLarge 渲染结果超出 MaxRenderBytes。
// 调用方拿到它时 text 仍是**已截断的可用内容**：宁可发一条被截断的告警，也不要什么都不发。
var ErrTooLarge = errors.New("渲染结果超出长度上限")

// Compile 解析一个模板。name 只用于错误信息定位。
func Compile(name, text string) (*template.Template, error) {
	return template.New(name).Funcs(funcMap).Option("missingkey=default").Parse(text)
}

// DecodeJSON 是把入站载荷变成模板数据的**唯一**正确入口。
//
// 关键点是 UseNumber()：encoding/json 默认把所有数字解成 float64，而
// text/template 输出裸字段（{{.数值}}）走的是 fmt.Fprint，float64 到了
// 1e6 量级就会打成 1.2345675e+06——而数值、数量、编号恰恰全是数字，
// 通知里出现科学计数法是不可接受的。本包的 toStr 只在显式调用函数时才生效，
// 救不了裸字段，所以必须在解码这一层就解决。
//
// UseNumber 还顺带修掉一个更隐蔽的损坏：float64 只有 53 位有效整数位，
// 19 位的雪花 ID / 长编号经过一次 float64 会被改写成另一个数字，
// 而 json.Number 保留源系统发来的**原始文本**，一个字节都不动。
//
// 代价：数值字段在模板里是 json.Number（底层是 string）。本包的 num/add/fixed
// 都认它；要做数值比较请用这些函数，别用内置的 gt/lt（那会按字符串比大小）。
func DecodeJSON(data []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	return v, nil
}

// Normalize 把 Go 侧手工构造的数据整成与 DecodeJSON 一致的形态
// （递归把 float64 / 整数换成 json.Number），供试运行、测试发送这类
// 不经过 JSON 解码的路径使用，免得同一个模板在"真实推送"与"面板试运行"里
// 渲染出不同的数字格式。
func Normalize(v any) any {
	switch t := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, item := range t {
			out[k] = Normalize(item)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, item := range t {
			out[i] = Normalize(item)
		}
		return out
	case float64:
		return json.Number(strconv.FormatFloat(t, 'f', -1, 64))
	case float32:
		return json.Number(strconv.FormatFloat(float64(t), 'f', -1, 32))
	case int:
		return json.Number(strconv.Itoa(t))
	case int64:
		return json.Number(strconv.FormatInt(t, 10))
	}
	return v
}

// Render 执行模板。
//
// 三个返回值：渲染文本、取不到值的字段数、错误。
// 超长时返回 ErrTooLarge 但 text 仍然可用（已截断并带标记）。
func Render(t *template.Template, data any) (text string, missing int, err error) {
	if t == nil {
		return "", 0, errors.New("模板未编译")
	}
	var sb strings.Builder
	w := &capWriter{sb: &sb, limit: MaxRenderBytes}
	execErr := t.Execute(w, data)
	out := sb.String()
	// 先数再抹：计数要在截断之后的实际输出上做也无妨——它只是给用户的提示强度，
	// 而截断本身已经是一条更醒目的提示。
	missing = strings.Count(out, noValue)
	if missing > 0 {
		out = strings.ReplaceAll(out, noValue, "")
	}
	switch {
	case w.truncated:
		return out + "\n…（内容过长已截断）", missing, ErrTooLarge
	case execErr != nil:
		return out, missing, execErr
	}
	return out, missing, nil
}

// RenderText 是 Compile + Render 的便捷组合，用于"只渲染一次"的场合（试运行、测试发送）。
func RenderText(name, tmpl string, data any) (string, int, error) {
	t, err := Compile(name, tmpl)
	if err != nil {
		return "", 0, err
	}
	return Render(t, data)
}

// capWriter 是带上限的写入器：写满 limit 之后丢弃其余内容并置 truncated。
// 刻意**不**返回错误来中断 Execute——range 到一半被打断会留下半句话，
// 让它继续跑完再统一加截断标记，输出更像"一条被截短的消息"而不是"坏了的消息"。
type capWriter struct {
	sb        *strings.Builder
	limit     int
	truncated bool
}

func (w *capWriter) Write(p []byte) (int, error) {
	if w.truncated {
		return len(p), nil
	}
	room := w.limit - w.sb.Len()
	if room <= 0 {
		w.truncated = true
		return len(p), nil
	}
	if len(p) > room {
		w.sb.Write(p[:room])
		w.truncated = true
		return len(p), nil
	}
	w.sb.Write(p)
	return len(p), nil
}

// funcMap 是模板里可用的全部函数。
//
// 每一个都是纯函数：输入只有参数，输出只有返回值，不读环境、不读文件、不发请求。
// 新增函数前请重读本文件顶部的安全红线。
var funcMap = template.FuncMap{
	// ---- 取值兜底 ----
	"default":  tplDefault,  // {{default "无" .备注}}
	"coalesce": tplCoalesce, // {{coalesce .优先 .次选 "兜底"}}

	// ---- 字符串 ----
	// 全部经 toStr 收口，而不是直接绑 strings.ToUpper 之类：绑原型的话
	// {{upper .数量}} 会因为参数不是 string 而让整次渲染报错，而"这个字段这次是数字"
	// 完全取决于源系统，不该由模板作者承担。
	"upper":     func(v any) string { return strings.ToUpper(toStr(v)) },
	"lower":     func(v any) string { return strings.ToLower(toStr(v)) },
	"trim":      func(v any) string { return strings.TrimSpace(toStr(v)) },
	"contains":  func(sub, v any) bool { return strings.Contains(toStr(v), toStr(sub)) },
	"hasPrefix": func(p, v any) bool { return strings.HasPrefix(toStr(v), toStr(p)) },
	"hasSuffix": func(s, v any) bool { return strings.HasSuffix(toStr(v), toStr(s)) },
	"replace":   func(old, new, v any) string { return strings.ReplaceAll(toStr(v), toStr(old), toStr(new)) },
	"truncate":  tplTruncate, // {{truncate 100 .描述}}
	"str":       toStr,       // 显式转字符串（比较数字与字符串时有用）
	"pad":       tplPad,      // {{pad 8 .编号}} 右侧补空格，用于对齐

	// ---- 集合 ----
	"join":  tplJoin, // {{join "、" .收件人}}
	"first": tplFirst,
	"last":  tplLast,
	"count": tplCount, // len 对 nil / 非集合会报错，count 一律给 0
	"list":  tplList,  // {{range list .body.items}}：一条也好、一批也好，循环写法只有一种

	// ---- 数值 ----
	"add": func(a, b any) float64 { return toNum(a) + toNum(b) },
	"sub": func(a, b any) float64 { return toNum(a) - toNum(b) },
	"num": toNum,
	// fixed 保留小数位：数值直接用 {{.数值}} 会渲染成 1.234e+06 这种科学计数法
	//（JSON 数字进 Go 是 float64），在通知里是不可接受的。
	"fixed": tplFixed, // {{fixed 2 .数值}}

	// ---- 时间 ----
	// now 是本表里唯一读外部状态的函数，读的只是墙上时钟：它既无法用于探测环境，
	// 也不携带任何机密，而"消息里带一个生成时间"是极常见的需求。
	"now":        func() time.Time { return time.Now() },
	"formatTime": tplFormatTime, // {{formatTime "2006-01-02 15:04:05" .时间}}

	// ---- JSON ----
	// toJSON 双用：调试时把整个对象打出来看结构，以及在自定义 HTTP 请求体里
	// 安全地插入一段可能含引号 / 换行的文本（{{toJSON .message}} 会带上引号并转义）。
	"toJSON":       tplToJSON,
	"toJSONIndent": tplToJSONIndent,
}

// tplDefault 取不到值（nil / 空串 / 空集合）时返回 d。
func tplDefault(d, v any) any {
	if isEmpty(v) {
		return d
	}
	return v
}

// tplCoalesce 返回第一个非空参数；全空则返回空串。
func tplCoalesce(vs ...any) any {
	for _, v := range vs {
		if !isEmpty(v) {
			return v
		}
	}
	return ""
}

// isEmpty 判断模板里"取不到值"的各种形态。
func isEmpty(v any) bool {
	switch t := v.(type) {
	case nil:
		return true
	case string:
		return t == ""
	case json.Number:
		// json.Number 底层是 string，不会落到上面那条 case。
		// 与 float64 一致地把 0 视为空，否则 {{default "—" .数量}} 在数量为 0 时
		// 表现会随"这份载荷是解码来的还是手工构造的"而变。
		f, err := t.Float64()
		return t == "" || (err == nil && f == 0)
	case bool:
		return !t
	case []any:
		return len(t) == 0
	case map[string]any:
		return len(t) == 0
	case float64:
		return t == 0
	case int:
		return t == 0
	case int64:
		return t == 0
	}
	return false
}

// toStr 把任意 JSON 值渲染成字符串。
//
// 数字单独处理：JSON 数字在 Go 里是 float64，fmt 的 %v 会把 1234567 打成 1.234567e+06，
// 而消息编号、数值、数量恰恰都是数字——这个默认行为会让消息里出现科学计数法。
func toStr(v any) string {
	switch t := v.(type) {
	case nil:
		return ""
	case string:
		return t
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64)
	case float32:
		return strconv.FormatFloat(float64(t), 'f', -1, 32)
	case bool:
		return strconv.FormatBool(t)
	case json.Number:
		return t.String()
	case []any, map[string]any:
		b, err := json.Marshal(t)
		if err != nil {
			return fmt.Sprint(t)
		}
		return string(b)
	}
	return fmt.Sprint(v)
}

// toNum 尽力把值转成数字；转不动返回 0（模板里报错没有意义，用户看到 0 就知道路径写错了）。
func toNum(v any) float64 {
	switch t := v.(type) {
	case float64:
		return t
	case float32:
		return float64(t)
	case int:
		return float64(t)
	case int64:
		return float64(t)
	case json.Number:
		f, _ := t.Float64()
		return f
	case string:
		f, _ := strconv.ParseFloat(strings.TrimSpace(t), 64)
		return f
	case bool:
		if t {
			return 1
		}
	}
	return 0
}

// Str 把任意 JSON 值转成字符串，供包外（webhook 的条件匹配）使用。
// 导出它而不是让调用方自己写一份：数字不能出现科学计数法这条要求，两边必须一致。
func Str(v any) string { return toStr(v) }

// Num 尽力把值转成数字，第二个返回值为假表示它不是数字。
// 与内部的 toNum 分开：toNum 转不动就返回 0，而条件匹配必须能区分
// "值是 0" 和 "值不是数字"——否则 gt 0 会对一切非数字字段成立。
func Num(v any) (float64, bool) {
	switch t := v.(type) {
	case float64:
		return t, true
	case float32:
		return float64(t), true
	case int:
		return float64(t), true
	case int64:
		return float64(t), true
	case json.Number:
		f, err := t.Float64()
		return f, err == nil
	case string:
		f, err := strconv.ParseFloat(strings.TrimSpace(t), 64)
		return f, err == nil
	}
	return 0, false
}

// tplFixed 保留 n 位小数。
func tplFixed(n int, v any) string {
	if n < 0 {
		n = 0
	} else if n > 10 {
		n = 10
	}
	return strconv.FormatFloat(toNum(v), 'f', n, 64)
}

// tplTruncate 按 rune 边界截断到 n 字节（复用与配置状态文本同一套实现）。
func tplTruncate(n int, v any) string {
	if n <= 0 {
		return ""
	}
	return strutil.Truncate(toStr(v), n, "…")
}

// tplPad 右侧补空格到 n 个显示宽度（粗略：汉字算 2）。用于在等宽字体里对齐成列的数据。
func tplPad(n int, v any) string {
	s := toStr(v)
	w := 0
	for _, r := range s {
		if r > 0x7F {
			w += 2
		} else {
			w++
		}
	}
	if w >= n {
		return s
	}
	return s + strings.Repeat(" ", n-w)
}

// tplJoin 用 sep 连接集合的各元素（元素各自走 toStr）。
func tplJoin(sep string, v any) string {
	items, ok := toSlice(v)
	if !ok {
		return toStr(v)
	}
	parts := make([]string, 0, len(items))
	for _, it := range items {
		parts = append(parts, toStr(it))
	}
	return strings.Join(parts, sep)
}

func tplFirst(v any) any {
	if items, ok := toSlice(v); ok && len(items) > 0 {
		return items[0]
	}
	return ""
}

func tplLast(v any) any {
	if items, ok := toSlice(v); ok && len(items) > 0 {
		return items[len(items)-1]
	}
	return ""
}

// tplList 把"可能是一批、也可能只有一条"的值统一成可以 range 的切片。
//
// 存在的理由是真实来源的这个习惯：只有一条时不发数组，直接发那个对象
// （{"items":{...}}），有多条才发数组。裸 {{range .body.items}} 遇到对象会去遍历它的
// **值**，于是 {{.creator}} 报错、整条消息发不出去；而模板作者无法预知对方这次发的是哪种。
//
//	数组     原样返回
//	nil/缺失 空切片（range 直接走 {{else}}）
//	其它     包成一个元素的切片（一条也当一批处理）
//
// 不把字符串按字符摊开：那对"一组记录"这个语义毫无意义，而 {{range}} 一个字符串
// 在 text/template 里本来就是报错，包成一条反而让 {{.}} 拿到整段文本。
func tplList(v any) []any {
	if v == nil {
		return nil
	}
	if items, ok := toSlice(v); ok {
		return items
	}
	return []any{v}
}

// tplCount 集合元素个数；非集合返回 0。
// 存在的意义是替代内置 len——len 对 nil 与非集合会直接让整次渲染报错，
// 而"这个字段这次没带数组"是完全正常的输入。
func tplCount(v any) int {
	if items, ok := toSlice(v); ok {
		return len(items)
	}
	if m, ok := v.(map[string]any); ok {
		return len(m)
	}
	if s, ok := v.(string); ok {
		return len([]rune(s))
	}
	return 0
}

func toSlice(v any) ([]any, bool) {
	items, ok := v.([]any)
	return items, ok
}

// tplFormatTime 按 layout 格式化时间值。
//
// 入参的形态在真实载荷里五花八门：Unix 秒、Unix 毫秒、RFC3339 字符串、
// 以及 "2006-01-02 15:04:05" 这种没有时区的本地时间串。逐个试，试不出来就原样返回——
// 原样返回比返回一个 1970 年的时间有用得多。
func tplFormatTime(layout string, v any) string {
	if layout == "" {
		layout = "2006-01-02 15:04:05"
	}
	switch t := v.(type) {
	case time.Time:
		return t.Format(layout)
	}
	if n := toNum(v); n > 0 {
		sec := int64(n)
		// 大于 1e12 视为毫秒（1e12 秒是公元 33658 年，不可能是秒）。
		if sec > 1e12 {
			return time.UnixMilli(sec).Format(layout)
		}
		return time.Unix(sec, 0).Format(layout)
	}
	s := strings.TrimSpace(toStr(v))
	if s == "" {
		return ""
	}
	for _, in := range []string{
		time.RFC3339Nano, time.RFC3339,
		"2006-01-02T15:04:05", "2006-01-02 15:04:05", "2006-01-02 15:04", "2006-01-02",
	} {
		if parsed, err := time.ParseInLocation(in, s, time.Local); err == nil {
			return parsed.Format(layout)
		}
	}
	return s
}

func tplToJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	return string(b)
}

func tplToJSONIndent(v any) string {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return ""
	}
	return string(b)
}

// FuncNames 返回可用函数名列表（已按名称排序），供面板的模板编辑器做提示。
// 排序在这里做而不是交给调用方：map 遍历顺序每次都不同，
// 界面上那排函数名会每刷新一次就重排一遍。
func FuncNames() []string {
	out := make([]string, 0, len(funcMap))
	for name := range funcMap {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}
