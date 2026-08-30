package server

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// buildUpdateTarGz 打包若干条目为 gzip+tar 流（同名条目按给定顺序写入）。
func buildUpdateTarGz(t *testing.T, entries [][2]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, e := range entries {
		name, content := e[0], e[1]
		if err := tw.WriteHeader(&tar.Header{
			Name:     name,
			Mode:     0o755,
			Size:     int64(len(content)),
			Typeflag: tar.TypeReg,
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// 同名条目重复出现时必须拒绝整个包：若沿用"后者覆盖前者"，
// 实际落盘的二进制就与人工检查包时看到的第一个条目不是同一个。
func TestExtractExecutableRejectsDuplicateEntries(t *testing.T) {
	dir := t.TempDir()
	binDst := filepath.Join(dir, "mantou")
	sigDst := filepath.Join(dir, "mantou.sig")

	pkg := buildUpdateTarGz(t, [][2]string{
		{"mantou", "第一个二进制"},
		{"mantou", "冒名顶替的二进制"},
		{"mantou.sig", "签名"},
	})
	err := extractExecutable(bytes.NewReader(pkg), "mantou", binDst, sigDst)
	if err == nil || !strings.Contains(err.Error(), "多个名为") {
		t.Fatalf("重复的可执行条目应被拒绝，实际 err=%v", err)
	}

	pkg = buildUpdateTarGz(t, [][2]string{
		{"mantou.sig", "签名 A"},
		{"mantou.sig", "签名 B"},
		{"mantou", "二进制"},
	})
	if err := extractExecutable(bytes.NewReader(pkg), "mantou", binDst, sigDst); err == nil ||
		!strings.Contains(err.Error(), "多个签名条目") {
		t.Fatalf("重复的签名条目应被拒绝，实际 err=%v", err)
	}
}

// 正常包：取到需要的两个条目即停止读取，其后堆放的填充数据不影响结果。
func TestExtractExecutableStopsAfterRequiredEntries(t *testing.T) {
	dir := t.TempDir()
	binDst := filepath.Join(dir, "mantou")
	sigDst := filepath.Join(dir, "mantou.sig")

	pkg := buildUpdateTarGz(t, [][2]string{
		{"dist/mantou", "二进制内容"},
		{"dist/mantou.sig", "签名内容"},
		{"padding.bin", strings.Repeat("x", 4096)},
	})
	if err := extractExecutable(bytes.NewReader(pkg), "mantou", binDst, sigDst); err != nil {
		t.Fatal(err)
	}
	bin, err := os.ReadFile(binDst)
	if err != nil {
		t.Fatal(err)
	}
	if string(bin) != "二进制内容" {
		t.Fatalf("提取到的二进制内容不符: %q", bin)
	}
	sig, err := os.ReadFile(sigDst)
	if err != nil {
		t.Fatal(err)
	}
	if string(sig) != "签名内容" {
		t.Fatalf("提取到的签名内容不符: %q", sig)
	}
}

// 需要的条目全部取到后即停止读取，因此排在它们之后的同名条目根本不会被读到——
// 落盘的始终是首个条目（也正是签名校验的那份）。这里把这一交互固定下来。
func TestExtractExecutableIgnoresTrailingDuplicateAfterEarlyStop(t *testing.T) {
	dir := t.TempDir()
	binDst := filepath.Join(dir, "mantou")
	sigDst := filepath.Join(dir, "mantou.sig")

	pkg := buildUpdateTarGz(t, [][2]string{
		{"mantou", "第一个二进制"},
		{"mantou.sig", "签名"},
		{"mantou", "冒名顶替的二进制"},
	})
	if err := extractExecutable(bytes.NewReader(pkg), "mantou", binDst, sigDst); err != nil {
		t.Fatal(err)
	}
	bin, err := os.ReadFile(binDst)
	if err != nil {
		t.Fatal(err)
	}
	if string(bin) != "第一个二进制" {
		t.Fatalf("落盘内容应为首个同名条目，实际 %q", bin)
	}
}

// 包内没有与当前二进制严格同名的条目时必须拒绝，而不是随便挑一个可执行文件。
func TestExtractExecutableRequiresMatchingName(t *testing.T) {
	dir := t.TempDir()
	pkg := buildUpdateTarGz(t, [][2]string{{"mantou-linux-amd64", "别的名字"}})
	err := extractExecutable(bytes.NewReader(pkg), "mantou", filepath.Join(dir, "mantou"), "")
	if err == nil || !strings.Contains(err.Error(), "未找到") {
		t.Fatalf("同名条目缺失应被拒绝，实际 err=%v", err)
	}
}
