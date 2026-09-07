// Package lockfile 把「同一个数据目录只允许一个 Mantou 进程」这件事钉在操作系统上。
//
// 为什么需要：面板所有的写入路径（config.json、master.key、state.json、证书、上传文件）
// 都靠进程内的一把 sync.RWMutex 串行化，而那把锁跨不出进程。两个进程指着同一个数据目录
// 跑起来时（忘了旧实例还开着、systemd 单元与手工启动的各一份、两个容器挂同一个卷），
// 双方各持一份内存配置，谁后保存谁的算数，另一份的改动无声消失；各模块还会同时去抢
// 同一批端口。症状是"面板时好时坏、设置改了又变回去"，极难联想到根因。
//
// 锁的语义由内核给，不由文件内容给：
//   - unix：flock(LOCK_EX|LOCK_NB)，锁挂在打开的文件描述上，进程一死内核就放；
//   - windows：不共享写的 CreateFile，句柄随进程终止关闭，同样自动放。
//
// 两者都没有"陈旧锁"这回事：进程被 kill -9、被 OOM 杀掉、断电，下次启动照样拿得到锁，
// 不需要"这把锁是不是已经过期了"这类猜测。文件里那个进程号纯粹给人看（报错时指认谁占着），
// 代码里任何判断都不读它。
package lockfile

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"
)

// ErrHeld 锁被另一个进程占着。调用方用 errors.Is 判定，据此给出"另一个实例正在运行"。
//
// 只有这一种错误代表"确实有人占着"。其余错误（多见于 NFS / CIFS / 某些 FUSE 挂载上
// 根本没有文件锁）语义完全不同：那种环境里谁也拿不到锁，把它一并当成"有人占着"，
// 会让面板在这类挂载上再也起不来。调用方必须分开处理，见 cmd/mantou/main.go。
var ErrHeld = errors.New("数据目录已被另一个实例占用")

// lockFileMode 锁文件权限，与数据目录里其它东西同口径。
const lockFileMode os.FileMode = 0o600

// retryInterval 等待期间的重试间隔。
const retryInterval = 100 * time.Millisecond

// Lock 是一把已经拿到手的锁。
type Lock struct{ f *os.File }

// Acquire 取 path 上的独占锁。wait > 0 时在这段时间里反复重试，wait <= 0 只试一次。
//
// 需要等的场合只有一类：新旧两个进程有一瞬间同时活着。Windows 的重启就是这样——
// 没有 exec 语义，只能"先拉起新进程、再退掉自己"（见 cmd/mantou/exec_self_windows.go）；
// 外部守护把新实例拉起得比旧实例退出更早时同理。等不到就返回包着 ErrHeld 的错误，
// 不会无限期挂在这里。
func Acquire(path string, wait time.Duration) (*Lock, error) {
	deadline := time.Now().Add(wait)
	for {
		f, err := tryLock(path)
		if err == nil {
			writeHolder(f)
			return &Lock{f: f}, nil
		}
		if !errors.Is(err, ErrHeld) {
			return nil, err
		}
		// 只在"睡完还来得及再试一次"时才睡，免得白等一整个间隔之后才发现已经超时。
		if !time.Now().Add(retryInterval).Before(deadline) {
			return nil, fmt.Errorf("%w：%s%s", ErrHeld, path, holderSuffix(path))
		}
		time.Sleep(retryInterval)
	}
}

// Release 放锁。可重复调用，也允许在 nil 上调用：cmd/mantou 既在 defer 里放一次，
// 也在换进程之前显式放一次，而拿锁失败时（不支持文件锁的挂载）那个 defer 拿到的是 nil。
func (l *Lock) Release() error {
	if l == nil || l.f == nil {
		return nil
	}
	f := l.f
	l.f = nil
	return unlock(f)
}

// writeHolder 把当前进程号写进锁文件。
//
// 失败一概忽略：锁已经拿到手了，这一步只是给排查的人留个线索，
// 不该因为它失败而让程序起不来。也不 fsync——读者与写者都在同一台机器上，
// 页缓存本来就一致，而这个数掉了不影响任何判断。
func writeHolder(f *os.File) {
	if err := f.Truncate(0); err != nil {
		return
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return
	}
	_, _ = fmt.Fprintf(f, "%d\n", os.Getpid())
}

// holderSuffix 读锁文件里的进程号，拼成一小段附在错误信息后面。
// 读不到（还没写进去、被清空过、平台不让读）就返回空串：它只是提示，不是判据。
func holderSuffix(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil || pid <= 0 {
		return ""
	}
	return fmt.Sprintf("（持有者进程号 %d）", pid)
}
