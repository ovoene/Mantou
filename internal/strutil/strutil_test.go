package strutil

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestTruncateKeepsShortInputVerbatim(t *testing.T) {
	for _, s := range []string{"", "abc", "短状态", strings.Repeat("a", 300)} {
		if got := Truncate(s, 300, "…"); got != s {
			t.Errorf("未超长时应原样返回：Truncate(%q) = %q", s, got)
		}
	}
}

// TestTruncateCutsOnRuneBoundary 这是本包存在的唯一理由：按字节切中文有 2/3 概率
// 切出残缺 UTF-8，encoding/json 会替换成 U+FFFD，在面板上就是乱码方块。
func TestTruncateCutsOnRuneBoundary(t *testing.T) {
	// "返回内容不是合法的公网地址" 每字 3 字节。上限取 5 字节 → 只能容纳 1 个整字。
	got := Truncate("返回内容不是合法的公网地址", 5, "…")
	if !utf8.ValidString(got) {
		t.Fatalf("结果不是合法 UTF-8：%q", got)
	}
	if want := "返…"; got != want {
		t.Fatalf("Truncate = %q，期望 %q", got, want)
	}

	// 逐一验证所有可能的切点都落在字符边界上（回退最多 3 字节）。
	src := strings.Repeat("🚀汉a", 40) // 4 字节 + 3 字节 + 1 字节循环，覆盖各种偏移
	for n := 1; n <= len(src); n++ {
		out := Truncate(src, n, "")
		if !utf8.ValidString(out) {
			t.Fatalf("maxBytes=%d 时结果非法：%q", n, out)
		}
		if len(out) > n {
			t.Fatalf("maxBytes=%d 时结果反而更长：%d 字节", n, len(out))
		}
		if n < len(src) && len(out) < n-3 {
			t.Fatalf("maxBytes=%d 时回退过多：%d 字节", n, len(out))
		}
	}
}

func TestTruncateAppendsSuffixOnlyWhenCut(t *testing.T) {
	if got := Truncate("abcdef", 3, "…（已截断）"); got != "abc…（已截断）" {
		t.Errorf("超长时应追加后缀，实际 %q", got)
	}
	if got := Truncate("abc", 3, "…（已截断）"); got != "abc" {
		t.Errorf("刚好等于上限时不应追加后缀，实际 %q", got)
	}
}

func TestTruncateRejectsNonPositiveLimit(t *testing.T) {
	if got := Truncate("abc", 0, "…"); got != "" {
		t.Errorf("maxBytes=0 应返回空串（且不带后缀），实际 %q", got)
	}
	if got := Truncate("abc", -1, "…"); got != "" {
		t.Errorf("maxBytes<0 应返回空串，实际 %q", got)
	}
}

// ---------- StripInvisible ----------

// 不可见字符全部由码点算出来，不写成字面量。两个理由：
// 一是源码里出现裸 BOM 会让 Go 直接拒绝编译（illegal byte order mark）；
// 二是写成字面量的话，这份测试自己就成了"肉眼看不出差别"的受害者——
// 谁来改都看不出那几个空位里藏着什么，一次误删就把断言悄悄弱化了。
var (
	zwsp = string(rune(0x200B)) // ZERO WIDTH SPACE
	bom  = string(rune(0xFEFF)) // BOM / ZERO WIDTH NO-BREAK SPACE
	lrm  = string(rune(0x200E)) // LEFT-TO-RIGHT MARK
	wj   = string(rune(0x2060)) // WORD JOINER
	shy  = string(rune(0x00AD)) // SOFT HYPHEN
	nbsp = string(rune(0x00A0)) // NO-BREAK SPACE
	ideo = string(rune(0x3000)) // IDEOGRAPHIC SPACE（全角空格）
)

// TestStripInvisibleKillsZeroWidth 钉住本函数存在的理由：这几个字符不属于 Unicode
// 空白，strings.TrimSpace 一个都不会碰，于是能跟着粘贴来的手机号一路进到钉钉正文里，
// 变成 "@13912521835<U+200B>"——钉钉匹配不到人，@ 静默失效。
func TestStripInvisibleKillsZeroWidth(t *testing.T) {
	const want = "13912521835"
	cases := map[string]string{
		"尾随零宽空格":  want + zwsp,
		"开头 BOM":  bom + want,
		"尾随双向标记":  want + lrm,
		"尾随单词连接符": want + wj,
		"中间软连字符":  "139" + shy + "12521835",
		"中间零宽空格":  "139" + zwsp + "12521835",
		"两头都有":    bom + want + zwsp,
		"混合多个":    zwsp + "139" + wj + "1252" + lrm + "1835" + bom,
	}
	for name, in := range cases {
		if got := StripInvisible(in); got != want {
			// 出错时把码点打出来，否则错误消息里两个串看起来一模一样。
			t.Errorf("%s：StripInvisible 未清净，得到 %q（码点 %U）", name, got, []rune(got))
		}
		// TrimSpace 拦不住这些——这条断言在说明为什么不能只靠它。
		if strings.TrimSpace(in) == want {
			t.Errorf("%s：TrimSpace 竟然清掉了零宽字符，本函数的前提已变，请重看注释", name)
		}
	}
}

// TestStripInvisibleKillsWhitespaceAnywhere 空白也要清，且不限首尾——
// 号码中间的空格（"139 1252 1835"）同样会让 @ 匹配不上，而 TrimSpace 只管首尾。
func TestStripInvisibleKillsWhitespaceAnywhere(t *testing.T) {
	const want = "13912521835"
	cases := map[string]string{
		"首尾半角空格":  "  " + want + "  ",
		"中间半角空格":  "139 1252 1835",
		"尾随制表符":   want + "\t",
		"中间换行":    "139\n1252\r1835",
		"尾随不换行空格": want + nbsp,
		"尾随全角空格":  want + ideo,
	}
	for name, in := range cases {
		if got := StripInvisible(in); got != want {
			t.Errorf("%s：StripInvisible(%q) = %q，期望 %q", name, in, got, want)
		}
	}
}

// TestStripInvisibleKeepsVisibleVerbatim 可见字符一个都不能动。
//
// 这条比看起来重要：判据是 unicode.Is(unicode.Cf, r)，Cf 是个不小的类，
// 若哪天误换成更宽的判据（比如把 Mn 组合记号也算进来），带声调的文本就会被悄悄改写。
func TestStripInvisibleKeepsVisibleVerbatim(t *testing.T) {
	for _, s := range []string{
		"",
		"13912521835",
		"+8613912521835",
		"１３９１２５２１８３５", // 全角数字：肉眼是数字，但它可见，本函数不负责它
		"139-1252-1835",
		"顾凤萍",
		"a1!@#$%^&*()_+",
		"cafe" + string(rune(0x0301)), // 组合重音，属 Mn 而非 Cf，必须留下
	} {
		if got := StripInvisible(s); got != s {
			t.Errorf("可见字符被改写：StripInvisible(%q) = %q（码点 %U）", s, got, []rune(got))
		}
	}
}

// TestStripInvisibleIsIdempotent 清理会在每次 Load 的 migrate 与每次保存时反复跑，
// 必须幂等（见 config/webhook.go 顶部的规范化约定）。
func TestStripInvisibleIsIdempotent(t *testing.T) {
	for _, s := range []string{bom + "139" + zwsp + "12521835" + wj, "  1 3 9  ", "13912521835", ""} {
		once := StripInvisible(s)
		if twice := StripInvisible(once); twice != once {
			t.Errorf("不幂等：%q → %q → %q", s, once, twice)
		}
	}
}
