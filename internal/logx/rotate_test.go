package logx

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// newTestRotatingFile 造一个位于临时目录的轮转文件；行数上限按需指定。
func newTestRotatingFile(t *testing.T, maxEntries int) *RotatingFile {
	t.Helper()
	r, err := NewRotatingFile(filepath.Join(t.TempDir(), "logs", "mantou.log"), maxEntries)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close() })
	return r
}

// writeLines 写入 n 条以 '\n' 结尾的记录（与 slog.JSONHandler 的写法一致：一次 Write 一条）。
func writeLines(t *testing.T, r *RotatingFile, from, n int) {
	t.Helper()
	for i := from; i < from+n; i++ {
		if _, err := fmt.Fprintf(r, "line-%d\n", i); err != nil {
			t.Fatal(err)
		}
	}
}

// fileLines 读回当前日志文件的所有非空行。
func fileLines(t *testing.T, r *RotatingFile) []string {
	t.Helper()
	b, err := os.ReadFile(r.Path())
	if err != nil {
		t.Fatal(err)
	}
	text := strings.TrimSuffix(string(b), "\n")
	if text == "" {
		return nil
	}
	return strings.Split(text, "\n")
}

// TestRotatingFileNeverExceedsMaxEntries 是「日志最大条数」对磁盘生效的核心断言：
// 用户设定 N 条，磁盘文件的行数在任何时刻都不得超过 N。
//
// 这是本次改动的原因所在：此前磁盘只按 5MB 体积轮转，条数设置对落盘量完全没有约束，
// 于是「把条数调小」在磁盘上看不到任何效果。
func TestRotatingFileNeverExceedsMaxEntries(t *testing.T) {
	const n = MinLogEntries
	r := newTestRotatingFile(t, n)

	// 连续写 5 倍于上限的量，每写一条都检查一次，抓的是"某一瞬间越界"而不只是最终态。
	for i := 0; i < 5*n; i++ {
		writeLines(t, r, i, 1)
		if got := len(fileLines(t, r)); got > n {
			t.Fatalf("写入第 %d 条后磁盘行数为 %d，超过上限 %d", i, got, n)
		}
	}
}

// TestRotatingFileRotatesExactlyAtLimit 精确定位轮转时机：写满第 N 条不轮转，第 N+1 条才轮转。
// 提前轮转会让磁盘长期只留很少几条，晚一条则突破用户设定的上限。
func TestRotatingFileRotatesExactlyAtLimit(t *testing.T) {
	const n = MinLogEntries
	r := newTestRotatingFile(t, n)

	writeLines(t, r, 0, n)
	lines := fileLines(t, r)
	if len(lines) != n {
		t.Fatalf("刚好写满时应有 %d 行（不该提前轮转），实际 %d", n, len(lines))
	}
	if lines[0] != "line-0" || lines[n-1] != fmt.Sprintf("line-%d", n-1) {
		t.Fatalf("写满时内容不对：首 %q 末 %q", lines[0], lines[n-1])
	}

	// 第 N+1 条触发轮转：maxBackups=0 意味着历史被清除，当前文件重新从 1 行开始。
	writeLines(t, r, n, 1)
	lines = fileLines(t, r)
	if len(lines) != 1 || lines[0] != fmt.Sprintf("line-%d", n) {
		t.Fatalf("越界那条应触发轮转、新文件只含它自己，实际 %#v", lines)
	}
	// 历史备份不应堆积（maxBackups=0）。
	backups, err := filepath.Glob(r.Path() + ".*")
	if err != nil {
		t.Fatal(err)
	}
	if len(backups) != 0 {
		t.Fatalf("maxBackups=0 时不应留下历史备份，实际 %#v", backups)
	}
}

// TestRotatingFileRecoversCountAfterReopen 锁住重启后的行数恢复。
//
// 若 openExisting 把已有内容当成 0 行，重启后的第一个周期能涨到「重启前行数 + N」才轮转，
// 行数上限对那一段形同失效。这个 bug 只在重启后出现，是最容易被漏掉的一类。
func TestRotatingFileRecoversCountAfterReopen(t *testing.T) {
	const n = MinLogEntries
	dir := t.TempDir()
	path := filepath.Join(dir, "logs", "mantou.log")

	first, err := NewRotatingFile(path, n)
	if err != nil {
		t.Fatal(err)
	}
	writeLines(t, first, 0, n-1) // 写到只差一条就满
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}

	// 模拟进程重启：同一路径重新打开。
	second, err := NewRotatingFile(path, n)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()

	writeLines(t, second, n, 1) // 第 N 条：正好写满，仍不该轮转
	if got := len(fileLines(t, second)); got != n {
		t.Fatalf("重启后应接着已有 %d 行继续计数，写满时期望 %d 行，实际 %d", n-1, n, got)
	}
	writeLines(t, second, n+1, 1) // 第 N+1 条：必须轮转
	if got := len(fileLines(t, second)); got != 1 {
		t.Fatalf("重启后越界仍应轮转，期望新文件 1 行，实际 %d 行", got)
	}
}

// TestRotatingFileSetMaxEntriesAppliesImmediately 条数改动无需重启即生效。
func TestRotatingFileSetMaxEntriesAppliesImmediately(t *testing.T) {
	r := newTestRotatingFile(t, 4*MinLogEntries)
	writeLines(t, r, 0, 2*MinLogEntries)
	if got := len(fileLines(t, r)); got != 2*MinLogEntries {
		t.Fatalf("前置写入应全部保留，期望 %d 行，实际 %d", 2*MinLogEntries, got)
	}

	// 调小到低于当前行数：下一条写入即触发轮转、当前文件被丢弃（追加写的文件无法就地保留最新 N 条）。
	r.SetMaxEntries(MinLogEntries)
	if got := r.MaxEntries(); got != MinLogEntries {
		t.Fatalf("SetMaxEntries 未生效，实际 %d", got)
	}
	writeLines(t, r, 9000, 1)
	if got := len(fileLines(t, r)); got != 1 {
		t.Fatalf("调小后下一条写入应触发轮转，期望 1 行，实际 %d", got)
	}
	// 之后按新上限轮转，不能再涨回旧上限。
	writeLines(t, r, 9001, 2*MinLogEntries)
	if got := len(fileLines(t, r)); got > MinLogEntries {
		t.Fatalf("轮转后仍应遵守新上限 %d，实际 %d 行", MinLogEntries, got)
	}
}

// TestRotatingFileMaxEntriesClamped 越界的条数被夹进合法区间，与内存环共用同一套规则。
func TestRotatingFileMaxEntriesClamped(t *testing.T) {
	for _, c := range []struct{ in, want int }{
		{0, DefaultLogEntries},
		{-1, DefaultLogEntries},
		{1, MinLogEntries},
		{777, 777},
		{1_000_000_000, MaxLogEntries},
	} {
		r := newTestRotatingFile(t, c.in)
		if got := r.MaxEntries(); got != c.want {
			t.Errorf("NewRotatingFile(maxEntries=%d) → %d，期望 %d", c.in, got, c.want)
		}
		r.SetMaxEntries(c.in)
		if got := r.MaxEntries(); got != c.want {
			t.Errorf("SetMaxEntries(%d) → %d，期望 %d", c.in, got, c.want)
		}
	}
}

// TestRotatingFileResetZeroesCount 手动清空后行数计数必须归零，否则新文件会提前轮转。
func TestRotatingFileResetZeroesCount(t *testing.T) {
	const n = MinLogEntries
	r := newTestRotatingFile(t, n)
	writeLines(t, r, 0, n-1)

	if err := r.Reset(); err != nil {
		t.Fatal(err)
	}
	if got := len(fileLines(t, r)); got != 0 {
		t.Fatalf("清空后文件应为空，实际 %d 行", got)
	}
	// 清空后应能重新写满 N 条；若 count 没归零，写到第 2 条就轮转了。
	writeLines(t, r, 0, n)
	if got := len(fileLines(t, r)); got != n {
		t.Fatalf("清空后应能重新容纳 %d 行，实际 %d", n, got)
	}
}

// TestRotatingFileSizeBoundStillApplies 体积界限与条数界限并行、先到先轮转。
// 条数给到上限、但每行很长，此时应由 5MB 体积界限先触发轮转，磁盘占用不会失控。
func TestRotatingFileSizeBoundStillApplies(t *testing.T) {
	r := newTestRotatingFile(t, MaxLogEntries)
	// 每行 4 KB：5000 行 ≈ 20 MB，远超 5MB 上限，必须在中途按体积轮转。
	line := strings.Repeat("x", 4<<10) + "\n"
	for i := 0; i < MaxLogEntries; i++ {
		if _, err := r.Write([]byte(line)); err != nil {
			t.Fatal(err)
		}
		info, err := os.Stat(r.Path())
		if err != nil {
			t.Fatal(err)
		}
		if info.Size() > int64(LogMaxSizeMB)*1024*1024 {
			t.Fatalf("写入第 %d 行后文件 %d 字节，超过 %d MB 上限", i, info.Size(), LogMaxSizeMB)
		}
	}
}
