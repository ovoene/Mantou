//go:build windows

package main

import (
	"os"
	"os/exec"
	"syscall"
)

// execSelf Windows 平台的进程替换。
//
// Windows 没有 exec 语义（无法在运行中替换自己的进程映像），因此改为**先拉起一个新进程，
// 再退出当前进程**：argv、环境变量、工作目录、标准输入输出全部沿用，从外部看与重启一次无异，
// 只是 PID 会变。
//
// 这样做的目的是让「立即重启 / 定时重启」在没有外部守护进程的机器上也能生效——
// 直接双击运行、或从命令行启动的场景下，单纯退出就是关掉程序，再也起不来。
//
// 调用前提（由 servePanels 保证）：面板监听已优雅关闭、各模块监听已关闭、运行态已落盘。
// 否则新进程会撞上"端口已被占用"，而旧进程已经在退出路上，两边都起不来。
func execSelf(path string) error {
	cmd := exec.Command(path, os.Args[1:]...)
	cmd.Env = os.Environ()
	// 继承控制台的三个句柄：从命令行启动时用户还看得到新进程的输出，
	// 而不是重启之后界面一切正常、控制台却突然安静了。
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	// 新建进程组：旧进程即将退出，若新进程仍留在同一组里，
	// 发给旧进程的 Ctrl+C / 关闭控制台事件会连带打到新进程上。
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: syscall.CREATE_NEW_PROCESS_GROUP}
	if err := cmd.Start(); err != nil {
		return err
	}
	// 不 Wait：新进程要独立活下去。Release 交还句柄，避免留下无人回收的进程句柄。
	_ = cmd.Process.Release()
	os.Exit(0)
	return nil
}
