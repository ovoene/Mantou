//go:build unix

package lockfile

import (
	"errors"
	"os"
	"syscall"
)

// tryLock 打开锁文件并抢一次 flock。
//
// LOCK_NB：抢不到立刻返回 EWOULDBLOCK，不挂在这里等——要不要等由 Acquire 决定。
// 锁挂在这个 fd 对应的**打开文件描述**上，因此同一个进程用两个 fd 也会互斥
// （测试就是靠这一点在单进程里验证互斥），而进程一死内核就放锁。
//
// 刻意不用 O_TRUNC：截断发生在 open 阶段，那时锁还没拿到，会把正在运行的那个实例
// 写下的进程号抹掉。真正的截断在 writeHolder 里、拿到锁之后做。
func tryLock(path string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, lockFileMode)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		// EWOULDBLOCK 与 EAGAIN 在 Linux/darwin 上是同一个值，两个都列上是为了不依赖这一点。
		if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
			return nil, ErrHeld
		}
		// 其余错误（ENOLCK / EOPNOTSUPP：这个挂载点没有文件锁）原样交上去，
		// 由调用方按"拿不到锁"而不是"有人占着"处理。
		return nil, err
	}
	return f, nil
}

// unlock 放锁。关掉 fd 本身就已经放了，显式 LOCK_UN 只为让意图写在代码里。
func unlock(f *os.File) error {
	_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
	return f.Close()
}
