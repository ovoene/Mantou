package webservice

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"mantou/internal/config"
	"mantou/internal/logx"
)

// 本文件验证响应体写入停滞超时（见 conntrack.go 的 writeGuard）。
//
// 关于"没有测什么"：这里不去等一次真实的写超时触发——那要占满一个 writeStallTimeout
// （60 秒）的挂钟时间，而它触发之后的行为是 net.Conn 的既定契约（超过写超时仍未完成的
// 写返回 os.ErrDeadlineExceeded），不是本项目的代码。这里钉住的是那条因果链上属于我们
// 的那一段：超时值确实落到了连接上、每一段都会重新落一次、写完立刻撤掉。

// deadlineRec 是一个"支持写超时"的 ResponseWriter，并记下每一次设置的值。
//
// 不能直接用 httptest.ResponseRecorder：它没有 SetWriteDeadline，
// 而那正好是这道闸要用的那个方法——用它做底座就什么都测不到了。
type deadlineRec struct {
	*httptest.ResponseRecorder
	mu        sync.Mutex
	deadlines []time.Time
}

func newDeadlineRec() *deadlineRec {
	return &deadlineRec{ResponseRecorder: httptest.NewRecorder()}
}

func (d *deadlineRec) SetWriteDeadline(t time.Time) error {
	d.mu.Lock()
	d.deadlines = append(d.deadlines, t)
	d.mu.Unlock()
	return nil
}

func (d *deadlineRec) snapshot() []time.Time {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]time.Time(nil), d.deadlines...)
}

// sendfileRec 在 deadlineRec 之上再实现 io.ReaderFrom，模拟 net/http 的 *response：
// 记下每一次 ReadFrom 收到的源与写出的字节数，用来验证零拷贝的形态与分段的粒度。
type sendfileRec struct {
	*deadlineRec
	mu     sync.Mutex
	srcs   []io.Reader // 原样存下来供类型断言：形态被破坏是静默的，只能这样看出来
	counts []int64
}

func newSendfileRec() *sendfileRec {
	return &sendfileRec{deadlineRec: newDeadlineRec()}
}

func (s *sendfileRec) ReadFrom(src io.Reader) (int64, error) {
	s.mu.Lock()
	s.srcs = append(s.srcs, src)
	s.mu.Unlock()
	// 用只有 Write 的壳收下内容：直接传 s 会被 io.Copy 挑中 ReadFrom，自己调自己。
	n, err := io.Copy(writeOnly{w: s.ResponseRecorder}, src)
	s.mu.Lock()
	s.counts = append(s.counts, n)
	s.mu.Unlock()
	return n, err
}

func (s *sendfileRec) reads() ([]io.Reader, []int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]io.Reader(nil), s.srcs...), append([]int64(nil), s.counts...)
}

// bigTempFile 造一个 size 字节的临时文件，内容是可校验的确定序列。
func bigTempFile(t *testing.T, size int) (*os.File, []byte) {
	t.Helper()
	want := make([]byte, size)
	for i := range want {
		want[i] = byte(i%251 + 1)
	}
	p := filepath.Join(t.TempDir(), "big.bin")
	if err := os.WriteFile(p, want, 0o600); err != nil {
		t.Fatalf("写临时文件失败: %v", err)
	}
	f, err := os.Open(p)
	if err != nil {
		t.Fatalf("打开临时文件失败: %v", err)
	}
	t.Cleanup(func() { _ = f.Close() })
	return f, want
}

// assertArmDisarmPairs 断言这批超时记录是「上闸—撤闸」严格成对的，
// 且每次上闸都落在 now + writeStallTimeout 附近。
func assertArmDisarmPairs(t *testing.T, ds []time.Time, wantPairs int) {
	t.Helper()
	if len(ds) != wantPairs*2 {
		t.Fatalf("应有 %d 对上闸/撤闸共 %d 次设置，实际 %d 次", wantPairs, wantPairs*2, len(ds))
	}
	for i := 0; i < len(ds); i += 2 {
		if ds[i].IsZero() {
			t.Fatalf("第 %d 次应是上闸（非零超时），实际是零值", i)
		}
		if d := time.Until(ds[i]); d <= 0 || d > writeStallTimeout+time.Second {
			t.Fatalf("第 %d 次上闸的剩余时长 %v 不在 (0, %v] 内", i, d, writeStallTimeout)
		}
		if !ds[i+1].IsZero() {
			t.Fatalf("第 %d 次应是撤闸（零值），实际 %v", i+1, ds[i+1])
		}
	}
}

// TestWriteGuardPreservesSendfileShape 分段之后零拷贝的形态必须原样保留。
//
// 这是整段改动里最容易悄悄坏掉的一处：net.sendFile 只认得剥掉**一层**
// *io.LimitedReader 之后是不是 *os.File，多包一层它就认不出来，于是大文件下载静默退化
// 成用户态复制循环——功能全对、吞吐掉一截，没有任何测试会失败。所以这里直接断言
// 交到底层手里的那个源仍然是 *io.LimitedReader{R: *os.File}。
func TestWriteGuardPreservesSendfileShape(t *testing.T) {
	size := 3*writeChunkBytes + 123
	f, want := bigTempFile(t, size)
	st, err := f.Stat()
	if err != nil {
		t.Fatalf("Stat 失败: %v", err)
	}

	rec := newSendfileRec()
	req := httptest.NewRequest(http.MethodGet, "/big.bin", nil)
	sw := &statusWriter{ResponseWriter: rec, status: http.StatusOK, wg: newWriteGuard(rec, req)}
	http.ServeContent(sw, req, st.Name(), st.ModTime(), f)

	srcs, counts := rec.reads()
	// 3 个整段 + 1 个零头。
	if len(srcs) != 4 {
		t.Fatalf("应分 4 段交给底层，实际 %d 段（长度分别为 %v）", len(srcs), counts)
	}
	for i, src := range srcs {
		lr, ok := src.(*io.LimitedReader)
		if !ok {
			t.Fatalf("第 %d 段交下去的源是 %T，不是 *io.LimitedReader —— 零拷贝已失效", i, src)
		}
		if _, ok := lr.R.(*os.File); !ok {
			t.Fatalf("第 %d 段的 LimitedReader 里包的是 %T，不是 *os.File —— 多包了一层", i, lr.R)
		}
	}
	for i, n := range counts[:3] {
		if n != writeChunkBytes {
			t.Errorf("第 %d 段应写 %d 字节，实际 %d", i, writeChunkBytes, n)
		}
	}
	if counts[3] != 123 {
		t.Errorf("最后一段应写 123 字节，实际 %d", counts[3])
	}
	if got := rec.Body.Bytes(); !bytes.Equal(got, want) {
		t.Fatalf("响应体与源文件不一致：%d 字节 vs %d 字节", len(got), len(want))
	}
	// 每一段之前都要重新上闸——否则 60 秒就成了整次下载的总时限，
	// 一个大文件必然被掐断，而这恰恰是"不设 WriteTimeout"想避免的事。
	assertArmDisarmPairs(t, rec.snapshot(), 4)
}

// TestWriteGuardChunkedSendfileSpansManyRounds 段数确实随文件大小增长：
// 这条钉的是"分段"不是摆设，而是真的把一次大传输切成了若干个可续期的窗口。
func TestWriteGuardChunkedSendfileSpansManyRounds(t *testing.T) {
	const rounds = 9
	f, want := bigTempFile(t, rounds*writeChunkBytes)
	st, _ := f.Stat()
	rec := newSendfileRec()
	req := httptest.NewRequest(http.MethodGet, "/big.bin", nil)
	sw := &statusWriter{ResponseWriter: rec, status: http.StatusOK, wg: newWriteGuard(rec, req)}
	http.ServeContent(sw, req, st.Name(), st.ModTime(), f)

	_, counts := rec.reads()
	if len(counts) != rounds {
		t.Fatalf("应分 %d 段，实际 %d 段", rounds, len(counts))
	}
	if got := rec.Body.Len(); got != len(want) {
		t.Fatalf("响应体应为 %d 字节，实际 %d", len(want), got)
	}
	assertArmDisarmPairs(t, rec.snapshot(), rounds)
}

// TestWriteGuardAbsentDelegatesWholeBody 没有这道闸时（协议升级请求，或测试里直接
// 组装的 statusWriter）ReadFrom 应原样一次委托下去，行为与改动之前完全一致。
func TestWriteGuardAbsentDelegatesWholeBody(t *testing.T) {
	f, want := bigTempFile(t, 3*writeChunkBytes)
	st, _ := f.Stat()
	rec := newSendfileRec()
	req := httptest.NewRequest(http.MethodGet, "/big.bin", nil)
	sw := &statusWriter{ResponseWriter: rec, status: http.StatusOK} // wg 为 nil
	http.ServeContent(sw, req, st.Name(), st.ModTime(), f)

	_, counts := rec.reads()
	if len(counts) != 1 {
		t.Fatalf("无闸时应一次推完，实际分了 %d 段", len(counts))
	}
	if counts[0] != int64(len(want)) {
		t.Fatalf("应一次写 %d 字节，实际 %d", len(want), counts[0])
	}
	if ds := rec.snapshot(); len(ds) != 0 {
		t.Fatalf("无闸时不该设置任何写超时，实际 %d 次", len(ds))
	}
}

// TestWriteGuardFallbackCopyIsGuarded 底层没有 ReaderFrom 时退回逐块写，
// 而那些写同样要经过闸门。
//
// 顺带钉住一个会当场炸掉的坑：这条回退路径若把 statusWriter 自己交给 io.Copy，
// io.Copy 会挑中它的 ReadFrom，于是自己调自己——本测试会直接栈溢出，而不是失败。
func TestWriteGuardFallbackCopyIsGuarded(t *testing.T) {
	rec := newDeadlineRec() // 只有 Write，没有 ReadFrom
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	sw := &statusWriter{ResponseWriter: rec, status: http.StatusOK, wg: newWriteGuard(rec, req)}

	body := strings.Repeat("mantou", 20000) // 大于一个复制缓冲，保证走多次 Write
	n, err := sw.ReadFrom(strings.NewReader(body))
	if err != nil {
		t.Fatalf("ReadFrom 出错: %v", err)
	}
	if n != int64(len(body)) {
		t.Fatalf("应复制 %d 字节，实际 %d", len(body), n)
	}
	if got := rec.Body.String(); got != body {
		t.Fatalf("响应体不一致：%d 字节 vs %d 字节", len(got), len(body))
	}
	ds := rec.snapshot()
	if len(ds) == 0 || len(ds)%2 != 0 {
		t.Fatalf("回退路径上的写没有经过闸门（%d 次设置）", len(ds))
	}
	assertArmDisarmPairs(t, ds, len(ds)/2)
}

// TestWriteGuardWrapsEveryWrite 普通的 Write（反代与压缩后的静态响应都走这条）
// 也要上闸，且写完立刻撤——两次写之间的空闲不该被管，否则 SSE 与长轮询会被切掉。
func TestWriteGuardWrapsEveryWrite(t *testing.T) {
	rec := newDeadlineRec()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	sw := &statusWriter{ResponseWriter: rec, status: http.StatusOK, wg: newWriteGuard(rec, req)}
	for i := 0; i < 3; i++ {
		if _, err := sw.Write([]byte("event\n")); err != nil {
			t.Fatalf("第 %d 次写出错: %v", i, err)
		}
	}
	assertArmDisarmPairs(t, rec.snapshot(), 3)
}

// TestWriteGuardWrapsFlush Flush 也要上闸。
//
// 这不是求对称：net/http 的 *response 把小块写先攒进一个 2 KB 的 bufio，真正下到 socket
// 的那一次发生在 Flush 里。也就是说「小块 + Flush」这种形态（SSE，以及 ReverseProxy 给
// 流式响应装的 maxLatencyWriter）里那次会阻塞的写只被 Flush 覆盖——只管 Write 的话，
// 一个订完 SSE 就不再 recv 的客户端照样能无限期占住一条连接与一个 goroutine。
func TestWriteGuardWrapsFlush(t *testing.T) {
	rec := newDeadlineRec() // 内嵌的 ResponseRecorder 自带 Flush
	req := httptest.NewRequest(http.MethodGet, "/events", nil)
	sw := &statusWriter{ResponseWriter: rec, status: http.StatusOK, wg: newWriteGuard(rec, req)}
	// 一个典型的 SSE 循环：写一小段、立刻 flush。
	for i := 0; i < 3; i++ {
		if _, err := sw.Write([]byte("data: tick\n\n")); err != nil {
			t.Fatalf("第 %d 次写出错: %v", i, err)
		}
		sw.Flush()
	}
	// 3 次 Write + 3 次 Flush，各自一对上闸/撤闸。
	assertArmDisarmPairs(t, rec.snapshot(), 6)
	if !rec.Flushed {
		t.Fatal("Flush 没有传导到底层 ResponseWriter")
	}
}

// TestWriteGuardSkipsUpgradeRequest 协议升级（WebSocket）不设这道闸：
// 握手成功后连接被 Hijack 走，留在连接上的超时会把之后每一次安静超过一分钟的
// 长连接切掉，而那时候的收发早已不经过 ResponseWriter。
func TestWriteGuardSkipsUpgradeRequest(t *testing.T) {
	rec := newDeadlineRec()
	req := httptest.NewRequest(http.MethodGet, "/ws", nil)
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Connection", "keep-alive, Upgrade")
	if g := newWriteGuard(rec, req); g != nil {
		t.Fatal("协议升级请求不该有写停滞超时")
	}
	// 普通请求要有，否则上面那条等于把闸整个关掉了也测不出来。
	if g := newWriteGuard(rec, httptest.NewRequest(http.MethodGet, "/", nil)); g == nil {
		t.Fatal("普通请求应有写停滞超时")
	}
}

// refuseRec 一律回绝写超时的 ResponseWriter，用来验证"不支持就彻底放弃"。
type refuseRec struct {
	*httptest.ResponseRecorder
	attempts int
}

func (r *refuseRec) SetWriteDeadline(time.Time) error {
	r.attempts++
	return http.ErrNotSupported
}

// TestWriteGuardGivesUpWhenUnsupported 底层不支持写超时时只试一次就作罢。
// 不记住这件事的话，每个响应分片都要白跑一遍穿透 Unwrap 链的查找。
func TestWriteGuardGivesUpWhenUnsupported(t *testing.T) {
	rec := &refuseRec{ResponseRecorder: httptest.NewRecorder()}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	sw := &statusWriter{ResponseWriter: rec, status: http.StatusOK, wg: newWriteGuard(rec, req)}
	for i := 0; i < 5; i++ {
		if _, err := sw.Write([]byte("x")); err != nil {
			t.Fatalf("第 %d 次写出错: %v", i, err)
		}
	}
	if rec.attempts != 1 {
		t.Fatalf("应只尝试 1 次就放弃，实际 %d 次", rec.attempts)
	}
	if rec.Body.String() != "xxxxx" {
		t.Fatalf("响应体应为 xxxxx，实际 %q", rec.Body.String())
	}
}

// TestWriteGuardNilSafe nil 闸（无闸的响应）上的全部方法都必须安全。
func TestWriteGuardNilSafe(t *testing.T) {
	var g *writeGuard
	g.arm()
	g.disarm()
	sw := &statusWriter{ResponseWriter: httptest.NewRecorder(), status: http.StatusOK}
	if _, err := sw.Write([]byte("ok")); err != nil {
		t.Fatalf("无闸时写出错: %v", err)
	}
}

// panicWriter 在 Write 里 panic，用来验证 instrument 里那条兜底撤闸。
type panicWriter struct {
	*deadlineRec
}

func (p *panicWriter) Write([]byte) (int, error) { panic("boom") }

// TestWriteGuardDisarmedOnPanic 写到一半 panic 时闸也必须撤掉。
//
// 撤不掉的后果不是这次请求出错（它本来就废了），而是超时留在**连接**上：
// 这条 keep-alive 连接上的下一个请求一开始就撞到一个已经过期的写超时。
func TestWriteGuardDisarmedOnPanic(t *testing.T) {
	m := New(logx.New(logx.Options{}))
	t.Cleanup(func() { _ = m.Close() })
	var ch config.WebChild
	ch.ID = "ch1"
	rec := &panicWriter{deadlineRec: newDeadlineRec()}
	h := m.instrument("官网", ch, m.connCounter(ch.ID), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("half"))
	}))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "203.0.113.90:40000"

	func() {
		defer func() {
			if recover() == nil {
				t.Error("panic 应继续向上传播，不该被吞掉")
			}
		}()
		h.ServeHTTP(rec, req)
	}()

	ds := rec.snapshot()
	if len(ds) != 2 {
		t.Fatalf("应有 1 次上闸 + 1 次兜底撤闸，实际 %d 次设置：%v", len(ds), ds)
	}
	if ds[0].IsZero() {
		t.Fatal("第 1 次应是上闸")
	}
	if !ds[1].IsZero() {
		t.Fatalf("panic 之后闸没有撤掉，仍留着 %v", ds[1])
	}
}
