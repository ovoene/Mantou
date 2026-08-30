//go:build !windows

package main

import (
	"os"
	"syscall"
)

// execSelf 用磁盘上已替换的新二进制替换当前进程映像（PID 不变，argv 与环境保留）。
// 仅非 Windows 可用；这是自更新后"无需外部守护进程也能自动重启到新版本"的关键。
// 调用必须在主 goroutine（主线程）执行，否则 syscall.Exec 会 panic。
func execSelf(path string) error {
	return syscall.Exec(path, os.Args, os.Environ())
}
