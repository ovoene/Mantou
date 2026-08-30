package restart

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestCheckExecutable(t *testing.T) {
	dir := t.TempDir()

	good := filepath.Join(dir, "mantou")
	if err := os.WriteFile(good, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatalf("准备可执行文件: %v", err)
	}
	if err := CheckExecutable(good); err != nil {
		t.Fatalf("正常的可执行文件应当通过，实际: %v", err)
	}

	if err := CheckExecutable(""); err == nil {
		t.Fatal("空路径应当被拒绝")
	}
	if err := CheckExecutable(filepath.Join(dir, "no-such-file")); err == nil {
		t.Fatal("不存在的文件应当被拒绝（二进制被删掉或改名就是这一种）")
	}
	if err := CheckExecutable(dir); err == nil {
		t.Fatal("目录应当被拒绝")
	}

	// 可执行位只在类 Unix 上有意义。
	if runtime.GOOS == "windows" {
		return
	}
	noX := filepath.Join(dir, "no-exec-bit")
	if err := os.WriteFile(noX, []byte("x"), 0o644); err != nil {
		t.Fatalf("准备无执行位的文件: %v", err)
	}
	if err := CheckExecutable(noX); err == nil {
		t.Fatal("没有可执行权限的文件应当被拒绝")
	}
}
