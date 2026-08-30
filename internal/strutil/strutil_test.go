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
