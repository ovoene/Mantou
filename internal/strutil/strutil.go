// Package strutil 收拢仓库里重复出现的字符串处理小工具。
//
// 建立这个包的直接动因是「截断」这一件事在仓库里长过三份实现，且其中两份是按字节切的：
// config.TruncateStatus（300 字节，写进 config.json 的状态文本）、
// ddns.truncate（按 rune，拼进错误信息）、server/api_update.go 里内联的 detail[:200]。
// 三份各自演化的结果是同一个 UTF-8 截断陷阱要修三次——按字节切中文有 2/3 概率切在字符
// 中间，encoding/json 会把残缺序列换成 U+FFFD，在面板上显示为乱码方块。
package strutil

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

// Truncate 把 s 裁剪到最多 maxBytes 字节；只有确实发生裁剪时才追加 suffix。
//
// 用字节而不是字符数作上限，是因为调用方真正要限制的是「这段文本会占多少内存 / 落多大盘」：
// 状态文本会被持久化进 config.json 并常驻内存（config.Manager 每次 Get() 都深拷贝一遍），
// 而上游返回的内容长度完全不受本程序控制。按字符数限制无法给出内存上界（一个字符最多 4 字节），
// 且 []rune(s) 转换会为超长输入额外分配约 4 倍大小的切片——正好是最需要截断的场景。
//
// 裁剪点会向前回退到 UTF-8 字符起始位置，因此返回值必然是合法 UTF-8（前提是 s 本身合法）。
// 回退最多消耗 3 字节，所以结果长度落在 [maxBytes-3, maxBytes] 加上 suffix。
// maxBytes <= 0 时返回空串（不追加 suffix：调用方要的是「什么都不要」）。
func Truncate(s string, maxBytes int, suffix string) string {
	if maxBytes <= 0 {
		return ""
	}
	if len(s) <= maxBytes {
		return s
	}
	cut := maxBytes
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + suffix
}

// StripInvisible 删掉 s 里的全部不可见字符：Unicode 空白，以及「格式字符」
// （Cf 类，含零宽空格 U+200B、BOM U+FEFF、双向标记 U+200E/200F、单词连接符 U+2060、
// 软连字符 U+00AD 等）。可见字符一律原样保留。
//
// 为什么需要它。粘贴是最主要的输入方式，而网页、IM、Excel 里复制出来的一段文本
// 常常尾随或内嵌这类字符。它们在**任何**界面上都渲染成零宽度或空白，因此
// 「肉眼一模一样但两个字符串不相等」是它们唯一的表现——那正是最难排查的一类故障。
//
// 与 strings.TrimSpace 的区别有两处，都关键：
//   - TrimSpace 只认空白，Cf 类不属于空白，一个都不会被它碰到；
//   - TrimSpace 只裁首尾，而粘贴带进来的字符也可能落在中间（"139<ZWSP>12521835"）。
//
// 只在「值本身不允许包含不可见字符」的字段上用它——手机号、标识符、路径这类。
// 不要用在自由文本上：那里的空格是内容，删掉就改变了原意。
func StripInvisible(s string) string {
	// 绝大多数输入是干净的，先扫一遍避免无谓的分配。
	if strings.IndexFunc(s, invisible) < 0 {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if !invisible(r) {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// invisible 判断一个字符是否零宽或空白。
func invisible(r rune) bool {
	return unicode.IsSpace(r) || unicode.Is(unicode.Cf, r)
}
