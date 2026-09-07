package webservice

import (
	"crypto/tls"
	"testing"
)

// tlsMinVersion 的映射：只有 1.3 抬到 TLS 1.3，其余一律 1.2（审计 L-06）。
//
// 值得单独钉一条的原因是这个函数从前有四个分支，1.0 / 1.1 各自映到
// tls.VersionTLS10 / TLS11。那两个值到不了这里（保存接口只收 1.2/1.3，加载期又把
// 非 1.3 抬到 1.2），所以那两个分支只是躺在那儿——一旦上游哪道收紧被拆掉，
// 它们就会安静地把弱加密放出去。合成"非 1.3 即 1.2"之后，失效方向只剩一个。
//
// 空值也在表里：它是界面上的"自动"，落到这里必须是 1.2 而不是别的什么。
func TestTLSMinVersionMapping(t *testing.T) {
	cases := map[string]uint16{
		"1.3":     tls.VersionTLS13,
		" 1.3 ":   tls.VersionTLS13, // 前后空格是手改配置里常见的写法
		"1.2":     tls.VersionTLS12,
		"":        tls.VersionTLS12, // 界面上的"自动"
		"1.1":     tls.VersionTLS12, // 上游收紧若被拆掉，这里必须往严的方向倒
		"1.0":     tls.VersionTLS12,
		"tls1.3":  tls.VersionTLS12, // 无法识别的写法不能当成 1.3
		"unknown": tls.VersionTLS12,
	}
	for in, want := range cases {
		if got := tlsMinVersion(in); got != want {
			t.Errorf("tlsMinVersion(%q) = 0x%04x，期望 0x%04x", in, got, want)
		}
	}
}
