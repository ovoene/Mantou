package tmplx

import (
	"encoding/json"
	"errors"
	"math/rand"
	"runtime"
	"strings"
	"testing"
)

// 本文件盯的是"输出有上限，但算出输出的过程没有"那一类问题。
//
// capWriter 截的是**写出去**的字节。在那之前整段排好的中间结果不受它管：
// pad 按模板里写的宽度先分配、toJSONIndent 的缩进随嵌套深度平方增长。
// 前者模板作者边打字边预览就会撞上，后者外部推来一份 20 KB 的载荷就够了。

// allocDuring 返回 fn 执行期间累计分配的字节数。
// 本包的测试都不并行，其它协程的分配不会混进这个数里。
func allocDuring(fn func()) uint64 {
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	fn()
	runtime.ReadMemStats(&after)
	return after.TotalAlloc - before.TotalAlloc
}

// 超大的补齐宽度：不能先分配整段，可见结果仍是"内容过长已截断"。
func TestPadWidthDoesNotAllocateBeyondRenderCap(t *testing.T) {
	var out string
	var err error
	n := allocDuring(func() {
		out, _, err = RenderText("pad", `{{pad 2000000000 .x}}`, map[string]any{"x": "a"})
	})
	if !errors.Is(err, ErrTooLarge) || !strings.HasSuffix(out, "（内容过长已截断）") {
		t.Fatalf("超出渲染上限应照旧判为截断：err=%v", err)
	}
	if n > 16<<20 {
		t.Fatalf("补齐 20 亿个空格的模板分配了 %d MB，宽度没有被封顶", n>>20)
	}
	// 正常宽度一个字节都不变。
	if got, _, err := RenderText("pad", `[{{pad 6 .x}}]`, map[string]any{"x": "ab"}); err != nil || got != "[ab    ]" {
		t.Fatalf("正常补齐被改动了：%q %v", got, err)
	}
}

// 一万层嵌套的数组只有 20 KB，标准库缩进之后是 200 MB（累计分配超过 1 GB）。
func TestToJSONIndentBoundedOnDeepNesting(t *testing.T) {
	const depth = 9999 // JSON 解码器允许的最深层数
	data, err := DecodeJSON([]byte(strings.Repeat("[", depth) + strings.Repeat("]", depth)))
	if err != nil {
		t.Fatalf("样本解不出来：%v", err)
	}
	var out string
	var rerr error
	n := allocDuring(func() {
		out, _, rerr = RenderText("dump", `{{toJSONIndent .}}`, data)
	})
	if n > 64<<20 {
		t.Fatalf("缩进一份 20 KB 的载荷分配了 %d MB", n>>20)
	}
	if !errors.Is(rerr, ErrTooLarge) {
		t.Fatalf("超出渲染上限应判为截断：%v", rerr)
	}
	if !strings.HasPrefix(out, "[\n  [\n    [") {
		t.Fatalf("截断前的那一段应是正常缩进：%q", out[:min(len(out), 32)])
	}
}

// indentJSON 与标准库 MarshalIndent 逐字节一致：固定的边角样本 + 一批随机生成的值。
func TestIndentJSONMatchesStdlib(t *testing.T) {
	cases := []any{
		nil, true, false, json.Number("1.5"), json.Number("-0"), "", "文本",
		`引号"反斜杠\与换行` + "\n" + `括号[{}]逗号,冒号:`,
		"<script>&amp;</script>", // Marshal 会把这几个转成 < 之类，两边都得一样
		`\`, `\\`, `"\"`,
		map[string]any{}, []any{}, []any{[]any{}, map[string]any{}},
		map[string]any{"a:b": "[1,2]", `x"y`: "}", "嵌套": map[string]any{"数组": []any{json.Number("1"), nil, "s"}}},
		[]any{map[string]any{"k": []any{}}, []any{[]any{[]any{}}}, map[string]any{"": ""}},
	}
	rng := rand.New(rand.NewSource(20260928))
	for i := 0; i < 300; i++ {
		cases = append(cases, randomJSONValue(rng, 5))
	}
	for i, v := range cases {
		want, err := json.MarshalIndent(v, "", "  ")
		if err != nil {
			t.Fatalf("样本 %d：标准库出错 %v", i, err)
		}
		compact, _ := json.Marshal(v)
		if got := indentJSON(compact, 1<<30); string(got) != string(want) {
			t.Fatalf("样本 %d 与标准库不一致：\n想要 %q\n实际 %q", i, want, got)
		}
		if got := tplToJSONIndent(v); got != string(want) {
			t.Fatalf("样本 %d：toJSONIndent 与标准库不一致", i)
		}
	}
}

// indentJSON 写过上限就停，停下时比上限多出的只是最后一小段。
func TestIndentJSONStopsPastLimit(t *testing.T) {
	v := make([]any, 5000)
	for i := range v {
		v[i] = "一段填充文本"
	}
	compact, _ := json.Marshal(v)
	full, _ := json.MarshalIndent(v, "", "  ")
	got := indentJSON(compact, 1000)
	if len(got) <= 1000 || len(got) > 1100 {
		t.Fatalf("应在刚过 1000 字节处停下，实际 %d 字节", len(got))
	}
	if !strings.HasPrefix(string(full), string(got)) {
		t.Fatal("停下之前的那一段必须与完整结果的开头一致")
	}
}

// randomJSONValue 生成一个 JSON 形态的值（与 DecodeJSON 的产物同构：json.Number、map、切片）。
func randomJSONValue(rng *rand.Rand, depth int) any {
	pieces := []string{"a", "中", `"`, `\`, "\n", "\t", "<", ">", "&", "[", "]", "{", "}", ",", ":", " ", " ", "é"}
	str := func() string {
		var b strings.Builder
		for n := rng.Intn(6); n > 0; n-- {
			b.WriteString(pieces[rng.Intn(len(pieces))])
		}
		return b.String()
	}
	kind := rng.Intn(7)
	if depth <= 0 && kind >= 5 {
		kind = rng.Intn(5)
	}
	switch kind {
	case 0:
		return nil
	case 1:
		return rng.Intn(2) == 0
	case 2:
		return json.Number([]string{"0", "12", "-3.5", "1e9", "123456789012345678901"}[rng.Intn(5)])
	case 3, 4:
		return str()
	case 5:
		m := map[string]any{}
		for n := rng.Intn(4); n > 0; n-- {
			m[str()] = randomJSONValue(rng, depth-1)
		}
		return m
	default:
		s := make([]any, rng.Intn(4))
		for i := range s {
			s[i] = randomJSONValue(rng, depth-1)
		}
		return s
	}
}
