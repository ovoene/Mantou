//go:build windows

package lockfile

import (
	"errors"
	"os"
	"syscall"
)

// Windows 独占打开失败时的两个错误码。标准库的 syscall 没有导出它们
// （x/sys/windows 里有，但那个包在本仓只是间接依赖，为一把锁把它提成直接依赖不值得），
// 按 winerror.h 的定义写在这里。
const (
	errorSharingViolation syscall.Errno = 32 // ERROR_SHARING_VIOLATION
	errorLockViolation    syscall.Errno = 33 // ERROR_LOCK_VIOLATION
)

// tryLock 用「不共享写」的方式打开锁文件。
//
// Windows 没有 flock。这里用的是 CreateFile 自带的共享语义：本进程要读写权限、
// 只放行别人**读**，于是第二个实例（同样要写权限）会拿到 ERROR_SHARING_VIOLATION。
// 句柄在进程终止时由系统关闭，锁随之释放——与 unix 的 flock 一样没有陈旧锁的问题。
//
// 留着 FILE_SHARE_READ 是为了让人能 type 一下这个文件、看见持有者进程号；
// 不留写共享，锁才成立。
//
// OPEN_ALWAYS：文件不存在就建，存在就打开（不截断——截断要等拿到锁之后，
// 见 writeHolder，否则会抹掉正在运行的那个实例写下的进程号）。
func tryLock(path string) (*os.File, error) {
	p, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	h, err := syscall.CreateFile(p,
		syscall.GENERIC_READ|syscall.GENERIC_WRITE,
		syscall.FILE_SHARE_READ,
		nil,
		syscall.OPEN_ALWAYS,
		syscall.FILE_ATTRIBUTE_NORMAL,
		0)
	if err != nil {
		if errors.Is(err, errorSharingViolation) || errors.Is(err, errorLockViolation) {
			return nil, ErrHeld
		}
		// 其余错误（路径不存在、权限不足、目录不可写）原样交上去，
		// 由调用方按"拿不到锁"而不是"有人占着"处理。
		return nil, err
	}
	return os.NewFile(uintptr(h), path), nil
}

// unlock 关句柄即放锁。
func unlock(f *os.File) error { return f.Close() }
