package logx

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// LogMaxSizeMB 磁盘日志单文件体积上限（MB），固定值、不可配置。
// LogMaxBackups 历史备份份数，固定为 0（不保留历史）。
//
// 体积上限刻意做成常量而非配置项：它是「磁盘占用绝对上界」这一硬约束的唯一来源，
// 交给用户配置只会带来「界面写了 100MB、实际被夹到别的值」这类表里不一。
//
// 它与用户可调的「日志最大条数」是**两道并行的界限，先到先轮转**：
//   - 条数（MaxLogEntries 区间内，用户可调）：语义直观，用户想控制的就是"留多少条"；
//   - 体积（固定 5 MB）：条数管不住体积。单条日志长度差异极大——普通访问事件 JSON 约 250 B，
//     但 TLS 握手错误的 detail 字段能到 1 KB 以上。若只按条数，5000 条最坏可落盘 15~20 MB，
//     "日志目录占用有确定上界"这个承诺就没了（README「资源占用」对外写明了 5MB）。
//
// 两道界限同时生效的代价：极端长行场景下，磁盘上的条数会不足用户设定的条数。
// 这是刻意的取舍——宁可少留几条日志，也不让日志目录不受控地膨胀。
const (
	LogMaxSizeMB  = 5
	LogMaxBackups = 0
)

// RotatingFile 是一个按「行数 + 体积」双界限轮转的日志文件写入器，实现 io.Writer。
// 写入前预判任一界限将被突破即先轮转（当前文件重命名为带时间戳的历史文件），
// 随后按 maxBackups 保留历史（固定为 0，即轮转时清除全部历史）。
//
// ⚠️ 语义提示：maxBackups=0 意味着「轮转即删除全部历史」，因此磁盘文件里的条数是
// **0 到 maxEntries 之间的锯齿**（写满即归零重新累积），而不是内存环那样恒定保留最新 N 条。
// 「不超过 N 条」这个上限承诺成立，但不要指望"文件里永远能翻到最近 N 条"。
type RotatingFile struct {
	mu         sync.Mutex
	path       string
	maxSize    int64
	maxBackups int
	size       int64
	// maxEntries 是当前生效的行数上限。用 atomic 而非 mu 保护，是为了让 SetMaxEntries
	// 不必和正在进行的 Write 抢同一把锁——日志写入在热路径上，设置保存却极罕见。
	maxEntries atomic.Int64
	// count 是当前文件已写入的行数。仅在持有 mu 时读写。
	count int64
	file  *os.File
}

// NewRotatingFile 打开（或创建）日志文件。
// maxEntries 为全局「日志最大条数」，会先经 NormalizeLogEntries 夹入合法区间；
// 体积与份数则由包级常量固定（LogMaxSizeMB / LogMaxBackups），不接受调用方参数，
// 以保证「磁盘日志占用 ≤ 5MB」这一上界在任何配置下都成立。
func NewRotatingFile(path string, maxEntries int) (*RotatingFile, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	r := &RotatingFile{
		path:       path,
		maxSize:    int64(LogMaxSizeMB) * 1024 * 1024,
		maxBackups: LogMaxBackups,
	}
	r.maxEntries.Store(int64(NormalizeLogEntries(maxEntries)))
	if err := r.openExisting(); err != nil {
		return nil, err
	}
	return r, nil
}

// SetMaxEntries 热更新行数上限，由「设置 → 日志 → 日志最大条数」保存时调用，无需重启。
//
// 只改阈值，不动已落盘内容：追加写的文件无法"就地保留最新 N 条"（那要整文件重写，
// 在路由器 / NAS 这类目标设备上代价过高，且断电时有损坏风险）。
// 因此调小到低于当前行数时，下一条写入就会触发一次轮转、当前文件被丢弃。
func (r *RotatingFile) SetMaxEntries(maxEntries int) {
	r.maxEntries.Store(int64(NormalizeLogEntries(maxEntries)))
}

// MaxEntries 返回当前生效的行数上限（供接口回显 / 测试断言）。
func (r *RotatingFile) MaxEntries() int {
	return int(r.maxEntries.Load())
}

// openExisting 打开当前日志文件，并同步 size / count 两个计数器。
//
// count 必须真的去数一遍现有文件的行数，不能从 0 起算：进程重启后若把已有内容当成 0 行，
// 文件就会一路涨到「重启前行数 + maxEntries」才轮转，行数上限对重启后的第一个周期形同失效。
// 代价是启动时扫一遍文件，但文件受 5MB 上限约束，一次顺序读在毫秒级。
func (r *RotatingFile) openExisting() error {
	f, err := os.OpenFile(r.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return err
	}
	lines, err := countLines(r.path)
	if err != nil {
		_ = f.Close()
		return err
	}
	r.file = f
	r.size = info.Size()
	r.count = lines
	return nil
}

// countLines 统计文件中的换行符个数。文件不存在视为 0 行（首次启动）。
func countLines(path string) (int64, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, err
	}
	defer f.Close()

	var total int64
	buf := make([]byte, 64<<10)
	for {
		n, err := f.Read(buf)
		if n > 0 {
			total += int64(bytes.Count(buf[:n], []byte{'\n'}))
		}
		if err == io.EOF {
			return total, nil
		}
		if err != nil {
			return 0, err
		}
	}
}

// Write 实现 io.Writer。行数或体积任一将越界即先轮转。
//
// slog 的 JSONHandler 每条记录一次 Write 且以 '\n' 结尾，所以这里按换行符计数即等于按记录计数；
// 按换行符而不是「一次 Write 记一条」，是为了对多行写入也保持正确。
func (r *RotatingFile) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	lines := int64(bytes.Count(p, []byte{'\n'}))
	limit := r.maxEntries.Load()
	// 单次写入本身就超过整个行数上限时（正常日志不会发生，slog 每次只写一条），
	// 轮转也救不了——那就照写，让体积界限去兜底，避免陷入"每次写都轮转"的空转。
	overEntries := lines <= limit && r.count+lines > limit
	overSize := r.size+int64(len(p)) > r.maxSize
	if overEntries || overSize {
		if err := r.rotate(); err != nil {
			return 0, err
		}
	}
	n, err := r.file.Write(p)
	r.size += int64(n)
	r.count += int64(bytes.Count(p[:n], []byte{'\n'}))
	return n, err
}

// Close 关闭底层文件。
func (r *RotatingFile) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.file != nil {
		return r.file.Close()
	}
	return nil
}

// Path 返回当前日志文件路径。
func (r *RotatingFile) Path() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.path
}

// Reset 清空全部日志文件（当前文件 + 历史备份），并重新创建一个空的当前日志文件。
// 用于「手动清空所有日志」：删除磁盘上的日志文件后，复用同一 *RotatingFile 实例重新打开，
// 后续写入继续落盘到新的空文件，无需重启进程。
// size / count 由 openExisting 依据新建的空文件重新同步（均归零）。
func (r *RotatingFile) Reset() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.file != nil {
		_ = r.file.Close()
		r.file = nil
	}
	// 删除当前文件及其全部历史备份（时间戳后缀，形如 mantou.log.20060102-...）。
	pattern := r.path + ".*"
	if matches, err := filepath.Glob(pattern); err == nil {
		for _, m := range matches {
			_ = os.Remove(m)
		}
	}
	_ = os.Remove(r.path)
	return r.openExisting()
}

// rotate 将当前文件归档并重开一个新文件。调用方必须持有 mu。
func (r *RotatingFile) rotate() error {
	if r.file != nil {
		_ = r.file.Close()
	}
	ts := fmt.Sprintf("%s.%s", r.path, time.Now().Format("20060102-150405.000000000"))
	if err := os.Rename(r.path, ts); err != nil {
		// 归档失败时尽量继续写入原文件（openExisting 会重新同步 size / count）。
		return r.openExisting()
	}
	r.pruneBackups()
	f, err := os.OpenFile(r.path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	r.file = f
	r.size = 0
	r.count = 0
	return nil
}

// pruneBackups 删除超出保留数量的最旧历史文件；maxBackups=0 时清除全部历史（体积优先）。
func (r *RotatingFile) pruneBackups() {
	pattern := r.path + ".*"
	matches, err := filepath.Glob(pattern)
	if err != nil {
		return
	}
	if len(matches) <= r.maxBackups {
		return
	}
	sort.Strings(matches) // 时间戳后缀，字典序≈时间序
	for _, old := range matches[:len(matches)-r.maxBackups] {
		_ = os.Remove(old)
	}
}
