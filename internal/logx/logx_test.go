package logx

import (
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestRecentKeepsStructuredFields(t *testing.T) {
	log := New(Options{})
	log.Info("面板访问", "host", "panel.example.com", "status", 200, "ip", "127.0.0.1")

	items := log.Recent(10)
	if len(items) != 1 {
		t.Fatalf("expected 1 log entry, got %d", len(items))
	}
	if items[0].Message != "面板访问" {
		t.Fatalf("unexpected message: %q", items[0].Message)
	}
	if got := items[0].Fields.Get("host"); got != "panel.example.com" {
		t.Fatalf("unexpected host field: %#v", got)
	}
	switch got := items[0].Fields.Get("status").(type) {
	case int:
		if got != 200 {
			t.Fatalf("unexpected status field: %#v", got)
		}
	case int64:
		if got != 200 {
			t.Fatalf("unexpected status field: %#v", got)
		}
	default:
		t.Fatalf("unexpected status field type: %T (%#v)", got, got)
	}
	if got := items[0].Fields.Get("ip"); got != "127.0.0.1" {
		t.Fatalf("unexpected ip field: %#v", got)
	}
}

func TestStandardBridgesIntoStructuredLog(t *testing.T) {
	log := New(Options{})
	std := log.Standard(slog.LevelWarn, "TLS 或连接异常")

	std.Println("http: TLS handshake error from 127.0.0.1:12345: EOF")

	items := log.Recent(10)
	if len(items) != 1 {
		t.Fatalf("expected 1 log entry, got %d", len(items))
	}
	if items[0].Level != "WARN" {
		t.Fatalf("unexpected level: %q", items[0].Level)
	}
	if items[0].Message != "TLS 或连接异常" {
		t.Fatalf("unexpected message: %q", items[0].Message)
	}
	if got := items[0].Fields.Get("detail"); got != "http: TLS handshake error from 127.0.0.1:12345: EOF" {
		t.Fatalf("unexpected detail field: %#v", got)
	}
}

func TestNormalizeLogEntriesClampsToRange(t *testing.T) {
	cases := []struct {
		in   int
		want int
	}{
		{0, DefaultLogEntries},         // 未配置 → 默认
		{-1, DefaultLogEntries},        // 负数同样视为未配置
		{1, MinLogEntries},             // 过小：小到看不完一次启动日志
		{MinLogEntries, MinLogEntries}, // 边界原样保留
		{777, 777},
		{MaxLogEntries, MaxLogEntries},
		{1_000_000_000, MaxLogEntries}, // 绕过面板直接调接口传天文数字
	}
	for _, c := range cases {
		if got := NormalizeLogEntries(c.in); got != c.want {
			t.Errorf("NormalizeLogEntries(%d) = %d，期望 %d", c.in, got, c.want)
		}
	}
}

// fillRing 依次写入 n 条可识别消息（seq-0、seq-1……），便于断言环形缓冲的轮转顺序。
func fillRing(l *Logger, n int) {
	for i := 0; i < n; i++ {
		l.Info(fmt.Sprintf("seq-%d", i))
	}
}

func messages(entries []Entry) []string {
	out := make([]string, len(entries))
	for i, e := range entries {
		out[i] = e.Message
	}
	return out
}

func TestSetMaxEntriesGrowKeepsExistingEntries(t *testing.T) {
	l := New(Options{MaxEntries: MinLogEntries})
	fillRing(l, 150) // 超出容量：环里应只剩 seq-50 .. seq-149

	l.SetMaxEntries(2 * MinLogEntries)

	got := messages(l.Recent(0))
	if len(got) != MinLogEntries {
		t.Fatalf("扩容不应丢日志，期望 %d 条，实际 %d 条", MinLogEntries, len(got))
	}
	if got[0] != "seq-50" || got[len(got)-1] != "seq-149" {
		t.Fatalf("扩容后顺序/内容不对：首 %q 末 %q", got[0], got[len(got)-1])
	}

	// 扩容后的新容量必须真的能用满：再写 100 条应累积到 200 条。
	fillRing(l, MinLogEntries)
	if n := len(l.Recent(0)); n != 2*MinLogEntries {
		t.Fatalf("扩容后应能容纳 %d 条，实际 %d 条", 2*MinLogEntries, n)
	}
}

func TestSetMaxEntriesShrinkKeepsNewest(t *testing.T) {
	l := New(Options{MaxEntries: 2 * MinLogEntries})
	fillRing(l, 2*MinLogEntries) // 刚好写满：seq-0 .. seq-199

	l.SetMaxEntries(MinLogEntries)

	got := messages(l.Recent(0))
	if len(got) != MinLogEntries {
		t.Fatalf("缩容后期望 %d 条，实际 %d 条", MinLogEntries, len(got))
	}
	// 缩容丢最旧的：用户调小是为了省内存，最新的才有排障价值。
	if got[0] != "seq-100" || got[len(got)-1] != "seq-199" {
		t.Fatalf("缩容应保留最新的一段：首 %q 末 %q", got[0], got[len(got)-1])
	}

	// 缩容后继续写入不能越界，且仍按新容量轮转。
	fillRing(l, 10)
	got = messages(l.Recent(0))
	if len(got) != MinLogEntries {
		t.Fatalf("缩容后继续写入，条数应稳定在 %d，实际 %d", MinLogEntries, len(got))
	}
	if got[len(got)-1] != "seq-9" {
		t.Fatalf("缩容后最新一条应是新写入的 seq-9，实际 %q", got[len(got)-1])
	}
}

// TestSetMaxEntriesKeepsDerivedHandlersWriting 锁住 SetMaxEntries 的实现约束：
// 必须就地改写 ringState 而不能替换 l.ring.state 指针。
// WithAttrs/WithGroup 的克隆各自持有一份 state 指针副本，替换指针后它们仍写向旧缓冲——
// 表现为「调过一次条数之后，由 With(...) 派生的日志（模块日志基本都是）再也不出现在面板上」。
func TestSetMaxEntriesKeepsDerivedHandlersWriting(t *testing.T) {
	l := New(Options{})
	derived := l.With("module", "webservice")
	grouped := l.WithGroup("cert").With("id", "c1")

	l.SetMaxEntries(MinLogEntries)

	derived.Info("派生日志")
	grouped.Warn("分组日志")

	items := l.Recent(0)
	if len(items) != 2 {
		t.Fatalf("派生 logger 的日志应仍写入同一个环，期望 2 条，实际 %d 条：%v", len(items), messages(items))
	}
	if got := items[0].Fields.Get("module"); got != "webservice" {
		t.Errorf("派生 logger 的属性丢失：%#v", got)
	}
	if got := items[1].Fields.Get("cert.id"); got != "c1" {
		t.Errorf("分组 logger 的属性丢失：%#v", got)
	}
}

func TestSetMaxEntriesSameCapacityIsNoop(t *testing.T) {
	l := New(Options{MaxEntries: MinLogEntries})
	fillRing(l, 3)

	l.SetMaxEntries(MinLogEntries) // 完全相同
	l.SetMaxEntries(1)             // 会被夹到 MinLogEntries，同样等价于不变
	l.SetMaxEntries(0)             // ≤0 → DefaultLogEntries，这次是真的要变
	if got := messages(l.Recent(0)); len(got) != 3 || got[0] != "seq-0" || got[2] != "seq-2" {
		t.Fatalf("反复调整容量不应丢日志，实际 %v", got)
	}
}

// 单条日志的长度必须有闸：真正会踩到的路径是「把上游 256 KB 的响应体拼进 error
// 再写进日志」，一条就能顶到实测最坏值的几百倍，而条数上限对此毫无作用。
func TestHandleClipsLongValues(t *testing.T) {
	log := New(Options{})
	huge := strings.Repeat("上", 100*1024) // 300 KB，且每字 3 字节：按字节切必然切坏
	log.Error("同步失败", "error", huge)

	items := log.Recent(10)
	if len(items) != 1 {
		t.Fatalf("期望 1 条日志，得到 %d", len(items))
	}
	got, ok := items[0].Fields.Get("error").(string)
	if !ok {
		t.Fatalf("error 字段不是字符串：%T", items[0].Fields.Get("error"))
	}
	if len(got) > maxLogValueBytes+len(logClipSuffix) {
		t.Fatalf("字段值 %d 字节，超过单值上限 %d", len(got), maxLogValueBytes)
	}
	if !strings.HasSuffix(got, logClipSuffix) {
		t.Fatalf("被裁剪的值应当带上标记，实际结尾是 %q", got[max(0, len(got)-30):])
	}
	if !utf8.ValidString(got) {
		t.Fatal("裁剪结果不是合法 UTF-8（按字节切中文会切在字符中间，面板上显示为乱码方块）")
	}
}

// Message 与字段值走同一套预算。
func TestHandleClipsLongMessage(t *testing.T) {
	log := New(Options{})
	log.Info(strings.Repeat("a", 64*1024))
	items := log.Recent(10)
	if len(items) != 1 {
		t.Fatalf("期望 1 条日志，得到 %d", len(items))
	}
	if len(items[0].Message) > maxLogValueBytes+len(logClipSuffix) {
		t.Fatalf("Message %d 字节，超过单值上限 %d", len(items[0].Message), maxLogValueBytes)
	}
}

// 每值上限之外还要有每条上限：字段个数虽然由代码决定，但 6 个 2 KiB 的值
// 已经是实测最坏值的 20 倍，占用注释里那套数字仍然不成立。
func TestHandleClipsWholeEntryBudget(t *testing.T) {
	log := New(Options{})
	long := strings.Repeat("b", maxLogValueBytes*2)
	log.Info(long, "a", long, "b", long, "c", long, "d", long, "e", long, "f", long)

	items := log.Recent(10)
	if len(items) != 1 {
		t.Fatalf("期望 1 条日志，得到 %d", len(items))
	}
	total := len(items[0].Message)
	for _, kv := range items[0].Fields {
		s, ok := kv.Val.(string)
		if !ok {
			continue
		}
		total += len(s)
	}
	// 预算之外还要容下每段的裁剪标记与用尽后的占位串，它们都是固定长度。
	slack := (1 + len(items[0].Fields)) * (len(logClipSuffix) + len(logValueClipped))
	if total > maxLogEntryBytes+slack {
		t.Fatalf("整条日志文本合计 %d 字节，超过单条上限 %d（+标记 %d）",
			total, maxLogEntryBytes, slack)
	}
	// 预算用尽之后的字段要能与"值本来就是空"区分开。
	var placeholders int
	for _, kv := range items[0].Fields {
		if kv.Val == logValueClipped {
			placeholders++
		}
	}
	if placeholders == 0 {
		t.Fatal("6 个超长字段却没有任何一个落到占位串上，预算没有真的被消耗")
	}
}

// 常规日志不能被这套闸门碰到——短串必须原样保留，否则排障时会怀疑日志本身。
func TestHandleKeepsNormalValuesVerbatim(t *testing.T) {
	log := New(Options{})
	msg := "证书续期完成"
	detail := strings.Repeat("详情", 100) // 600 字节，远在单值上限之内
	log.Info(msg, "cert", "panel.example.com", "detail", detail, "days", 89)

	items := log.Recent(10)
	if len(items) != 1 {
		t.Fatalf("期望 1 条日志，得到 %d", len(items))
	}
	if items[0].Message != msg {
		t.Fatalf("Message 被改动了：%q", items[0].Message)
	}
	if items[0].Fields.Get("detail") != detail {
		t.Fatal("正常长度的字段值被裁剪了")
	}
	if items[0].Fields.Get("days") != int64(89) {
		t.Fatalf("非字符串字段被动过了：%#v", items[0].Fields.Get("days"))
	}
}
