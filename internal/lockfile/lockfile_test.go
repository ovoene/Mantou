package lockfile

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// 这一组盯的是 F-05 的后半段：同一个数据目录不许被两个进程同时写。
//
// 为什么单进程里的测试就够：两个平台的互斥都不是"按进程"判的——
// unix 的 flock 挂在**打开的文件描述**上（同进程开两次也互斥），
// Windows 的共享模式是**按句柄**判的。所以同进程开两把就能验到真实的互斥语义，
// 不必为此编一个辅助二进制、再去处理"子进程什么时候真的起来了"这类噪声。
//
// 反过来说，本文件里每条断言都必须在两个平台上都成立：这是唯一一处不能靠"CI 是 Linux"
// 蒙混过去的地方，Windows 用的是完全另一套实现（CreateFile 共享模式）。

// lockPath 造一个临时数据目录，返回其中的锁文件路径。
func lockPath(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), ".lock")
}

// TestAcquireRejectsSecondHolder 第二把锁必须被拒，放掉之后又能拿到。
func TestAcquireRejectsSecondHolder(t *testing.T) {
	path := lockPath(t)
	first, err := Acquire(path, 0)
	if err != nil {
		t.Fatalf("第一把锁没拿到: %v", err)
	}

	second, err := Acquire(path, 0)
	if err == nil {
		_ = second.Release()
		t.Fatal("同一个数据目录被拿到了第二把锁：两个进程会各持一份内存配置互相覆盖")
	}
	if !errors.Is(err, ErrHeld) {
		t.Fatalf("错误应当满足 errors.Is(err, ErrHeld)，实际 %v——"+
			"调用方靠它区分「有人占着」（拒绝启动）与「这个挂载点没有文件锁」（照常启动）", err)
	}
	// 报错要能指认是谁占着，否则用户面对的只是一句"目录被占用"。
	if want := strconv.Itoa(os.Getpid()); !strings.Contains(err.Error(), want) {
		t.Fatalf("错误信息里没有持有者进程号 %s：%v", want, err)
	}

	if err := first.Release(); err != nil {
		t.Fatalf("放锁失败: %v", err)
	}
	again, err := Acquire(path, 0)
	if err != nil {
		t.Fatalf("放锁之后仍拿不到锁: %v", err)
	}
	if err := again.Release(); err != nil {
		t.Fatal(err)
	}
}

// TestAcquireWaitsForRelease 持有者在等待期内放手，Acquire 就该拿到锁。
//
// 这条守的是重启：Windows 上没有 exec 语义，新进程是旧进程拉起来的，两边有一瞬间
// 同时活着。等不了的话，一次自更新或定时重启就会把面板永久关掉。
func TestAcquireWaitsForRelease(t *testing.T) {
	path := lockPath(t)
	held, err := Acquire(path, 0)
	if err != nil {
		t.Fatal(err)
	}
	release := time.AfterFunc(150*time.Millisecond, func() { _ = held.Release() })
	defer release.Stop()

	start := time.Now()
	lock, err := Acquire(path, 3*time.Second)
	if err != nil {
		t.Fatalf("持有者已放手，等待期内仍没拿到锁: %v", err)
	}
	defer func() { _ = lock.Release() }()
	// 确认真的是"等到"的，而不是第一把锁压根没生效。
	if elapsed := time.Since(start); elapsed < 100*time.Millisecond {
		t.Fatalf("只用了 %v 就拿到锁，第一把锁恐怕没有真正生效", elapsed)
	}
}

// TestAcquireGivesUpAfterWait 一直不放手就必须在等待期结束后失败，不能无限期挂着。
func TestAcquireGivesUpAfterWait(t *testing.T) {
	path := lockPath(t)
	held, err := Acquire(path, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = held.Release() }()

	start := time.Now()
	if _, err := Acquire(path, 300*time.Millisecond); !errors.Is(err, ErrHeld) {
		t.Fatalf("等待超时后应当返回 ErrHeld，实际 %v", err)
	}
	// 至少等过一个重试间隔：wait 被忽略（每次都只试一次）时这里会瞬间返回。
	if elapsed := time.Since(start); elapsed < retryInterval {
		t.Fatalf("只用了 %v 就放弃，wait 参数没起作用", elapsed)
	}
}

// TestContentionKeepsHolderPID 抢锁失败不能把持有者写下的进程号抹掉。
//
// 这条钉的是"打开锁文件时不许带 O_TRUNC"：截断发生在拿到锁之前，
// 一个刚启动就被拒的第二实例会顺手清空正在运行的那个实例留下的进程号，
// 于是报错里再也指不出是谁占着——而那句话往往是用户唯一的线索。
func TestContentionKeepsHolderPID(t *testing.T) {
	path := lockPath(t)
	held, err := Acquire(path, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = held.Release() }()

	if _, err := Acquire(path, 0); !errors.Is(err, ErrHeld) {
		t.Fatalf("第二把锁应当被拒，实际 %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		// Windows 上持有者留了 FILE_SHARE_READ，读得到；unix 上更没有理由读不到。
		t.Fatalf("锁文件读不出来（持有者应当允许别人读）: %v", err)
	}
	if got := strings.TrimSpace(string(data)); got != strconv.Itoa(os.Getpid()) {
		t.Fatalf("锁文件内容是 %q，期望持有者进程号 %d", got, os.Getpid())
	}
}

// TestReleaseIsIdempotent 重复放锁、在 nil 上放锁都必须安全。
//
// cmd/mantou 两处都会放：defer 里一次，换进程之前显式一次；而拿锁失败时
// （挂载点给不了锁）那个 defer 拿到的是 nil。
func TestReleaseIsIdempotent(t *testing.T) {
	lock, err := Acquire(lockPath(t), 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := lock.Release(); err != nil {
		t.Fatalf("第一次放锁失败: %v", err)
	}
	if err := lock.Release(); err != nil {
		t.Fatalf("第二次放锁应当什么都不做，实际报错: %v", err)
	}
	var nilLock *Lock
	if err := nilLock.Release(); err != nil {
		t.Fatalf("在 nil 上放锁应当什么都不做，实际报错: %v", err)
	}
}

// TestAcquireMissingDirIsNotHeld 目录不存在时报的必须**不是** ErrHeld。
//
// 这两类错误在 cmd/mantou 里走完全不同的两条路：ErrHeld 拒绝启动，
// 其余（挂载点没有文件锁、路径不可写）只记一条告警照常启动。
// 把后者误判成前者，面板会在 NFS/CIFS 上彻底起不来。
func TestAcquireMissingDirIsNotHeld(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nope", ".lock")
	_, err := Acquire(path, 0)
	if err == nil {
		t.Fatal("目录不存在时应当报错")
	}
	if errors.Is(err, ErrHeld) {
		t.Fatalf("目录不存在被误判成「已被占用」：%v", err)
	}
}
