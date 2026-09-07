package server

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// detectBinaryArch 原先固定按小端读 e_machine，于是它在大端机器上是错的：
//   - 一个真正的 GOARCH=mips 包（大端 ELF，e_machine 存成 00 08）被读成 0x0800，
//     用户在 MIPS 面板上传正确的包，收到的是「无法识别的 CPU 架构」；
//   - 反过来，小端的 mipsle 包在大端 MIPS 面板上会被算成 "mips" 从而通过这道闸，
//     要等后面 exec 冒烟测试以 ENOEXEC 失败才拦下——而这道闸的意义正是提前给一句人话。
//
// 本文件用合成的 20 字节 ELF 头把 (e_machine, EI_CLASS, EI_DATA) → GOARCH 的映射钉住，
// 并反向钉住"Go 没有这个端序的移植"必须报错而不是猜一个名字。

// elfHeader 合成一个 20 字节 ELF 头：只有架构判断用得到的那几个字节是真的。
func elfHeader(class, data byte, machine uint16) []byte {
	h := make([]byte, 20)
	copy(h, []byte{0x7f, 'E', 'L', 'F'})
	h[4] = class // EI_CLASS：1=32 位，2=64 位
	h[5] = data  // EI_DATA：1=小端，2=大端
	h[6] = 1     // EI_VERSION
	h[16] = 2    // e_type=ET_EXEC（低字节；本函数不看它，填上只为像个真头）
	if data == 2 {
		binary.BigEndian.PutUint16(h[18:20], machine)
	} else {
		binary.LittleEndian.PutUint16(h[18:20], machine)
	}
	return h
}

func writeTempFile(t *testing.T, b []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "candidate")
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestDetectBinaryArch(t *testing.T) {
	const (
		c32, c64 = 1, 2
		lsb, msb = 1, 2
	)
	for _, tc := range []struct {
		name    string
		hdr     []byte
		want    string // 期望的 GOARCH；空串=期望被拒
		wantErr string // 期望错误里出现的字样（want 为空时才检查）
	}{
		{name: "amd64", hdr: elfHeader(c64, lsb, 0x3e), want: "amd64"},
		{name: "arm64", hdr: elfHeader(c64, lsb, 0xb7), want: "arm64"},
		{name: "386", hdr: elfHeader(c32, lsb, 0x03), want: "386"},
		{name: "arm", hdr: elfHeader(c32, lsb, 0x28), want: "arm"},
		{name: "riscv64", hdr: elfHeader(c64, lsb, 0xf3), want: "riscv64"},
		{name: "loong64", hdr: elfHeader(c64, lsb, 0x102), want: "loong64"},
		// s390x 只有大端一个移植，它是"必须是大端"的那一侧。
		{name: "s390x", hdr: elfHeader(c64, msb, 0x16), want: "s390x"},

		// 同一个 e_machine，端序决定名字。
		{name: "ppc64 大端", hdr: elfHeader(c64, msb, 0x15), want: "ppc64"},
		{name: "ppc64le 小端", hdr: elfHeader(c64, lsb, 0x15), want: "ppc64le"},
		// MIPS 是大小端 × 32/64 位四个 GOARCH 共用一个 e_machine。
		{name: "mips 大端 32 位", hdr: elfHeader(c32, msb, 0x08), want: "mips"},
		{name: "mipsle 小端 32 位", hdr: elfHeader(c32, lsb, 0x08), want: "mipsle"},
		{name: "mips64 大端 64 位", hdr: elfHeader(c64, msb, 0x08), want: "mips64"},
		{name: "mips64le 小端 64 位", hdr: elfHeader(c64, lsb, 0x08), want: "mips64le"},

		// 下面这些端序压根没有对应的 Go 移植，报「无法识别」比猜一个名字好：
		// 猜出来的名字要么误放一个跑不起来的包，要么给出一句更让人困惑的不匹配提示。
		{name: "大端 x86_64 没有对应移植", hdr: elfHeader(c64, msb, 0x3e), wantErr: "无法识别"},
		{name: "大端 arm64 没有对应移植", hdr: elfHeader(c64, msb, 0xb7), wantErr: "无法识别"},
		{name: "小端 s390 没有对应移植", hdr: elfHeader(c64, lsb, 0x16), wantErr: "无法识别"},
		// 报错要带上端序：同一个数字配错端序也走这里，光看 e_machine 会以为是别的毛病。
		{name: "报错带端序", hdr: elfHeader(c64, msb, 0x3e), wantErr: "大端"},
		{name: "未知架构", hdr: elfHeader(c64, lsb, 0x5678), wantErr: "e_machine=0x5678"},
		{name: "字节序标记无效", hdr: elfHeader(c64, 0, 0x3e), wantErr: "EI_DATA"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := detectBinaryArch(writeTempFile(t, tc.hdr))
			if tc.want != "" {
				if err != nil {
					t.Fatalf("应当识别为 %s，实际报错：%v", tc.want, err)
				}
				if got != tc.want {
					t.Fatalf("期望 %s，实际 %s", tc.want, got)
				}
				return
			}
			if err == nil {
				t.Fatalf("应当被拒，实际识别成了 %q", got)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("错误里应含 %q，实际：%v", tc.wantErr, err)
			}
		})
	}

	// 非 ELF 与截断的头都不能被当成"某个架构"。
	if _, err := detectBinaryArch(writeTempFile(t, []byte("MZ\x90\x00 这是个 Windows PE 头"))); err == nil ||
		!strings.Contains(err.Error(), "ELF") {
		t.Errorf("非 ELF 文件应当被拒且提到 ELF，实际：%v", err)
	}
	if _, err := detectBinaryArch(writeTempFile(t, []byte{0x7f, 'E', 'L', 'F', 2, 1})); err == nil ||
		!strings.Contains(err.Error(), "读取文件头失败") {
		t.Errorf("头部不足 20 字节应当被拒，实际：%v", err)
	}
}

// 合成头能自证一致，却证不了 EM_* 常量本身没写错。测试自己的二进制就是一份真 ELF，
// 它的架构必然等于 runtime.GOARCH——这条把整张映射表锚在现实上。
func TestDetectBinaryArchOnRealBinary(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("只有 Linux 上的测试二进制是 ELF")
	}
	exe, err := os.Executable()
	if err != nil {
		t.Skipf("拿不到测试二进制路径: %v", err)
	}
	got, err := detectBinaryArch(exe)
	if err != nil {
		t.Fatalf("识别本进程二进制失败：%v", err)
	}
	if got != runtime.GOARCH {
		t.Errorf("本进程二进制应被识别为 %s，实际 %s", runtime.GOARCH, got)
	}
}
