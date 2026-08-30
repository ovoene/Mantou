package webhook

import (
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// 本文件盯的是入站并发闸（3-G）。
//
// 单条入站请求的体积有闸（MaxBytesReader），同时在处理的条数没有：
// http.Server 默认不限并发，每 IP 限流又默认不启用，于是"并发数"是一个由对端
// 说了算的乘数——单请求峰值几十 MB 乘上去就没有上界了。
//
// 这里要钉住四件事，其中第二件最要紧：
//   1. 满了要回 503，且那条消息一条都不投递；
//   2. 名额必须还得回来——漏一次 defer 就是整条监听永久卡死，而且没有任何报错；
//   3. 闸装在鉴权之后：猜错令牌的请求不许占名额；
//   4. 计数本身要精确到不超额（CAS，不是"先加再判"）。

// fillGate 把并发闸占满，返回一个还原函数。
func fillGate(t *testing.T, m *Module) func() {
	t.Helper()
	for i := 0; i < maxInflight; i++ {
		if !m.gate.enter() {
			t.Fatalf("占第 %d 个名额就失败了，上限是 %d", i+1, maxInflight)
		}
	}
	return func() {
		for i := 0; i < maxInflight; i++ {
			m.gate.leave()
		}
	}
}

// 名额占满时回 503，且这条消息不投递、不计入接收数；原因要进执行历史。
func TestServeRejectsWhenInflightFull(t *testing.T) {
	h := newHarness(t, hitCfg(nil))
	restore := fillGate(t, h.m)

	code, body := h.post(t, "/hook", `{"消息编号":"MSG-1"}`)
	if code != http.StatusServiceUnavailable {
		t.Fatalf("并发满时应回 503，实际 %d：%s", code, body)
	}
	// 与 429 同口径：纯文本响应体只回一句通用文本，稍后再来这层意思由状态码承担。
	if strings.TrimSpace(body) != "rejected" {
		t.Fatalf("响应体应是那句通用文本：%q", body)
	}
	if reqs := h.n.all(); len(reqs) != 0 {
		t.Fatalf("被闸住的请求不该投递任何消息：%+v", reqs)
	}
	// 管理员要能看出"是并发满了"，否则现象只是"消息偶尔丢"。
	if e := h.last(t); e.Event != EventRejected || !strings.Contains(e.Reason, "上限") {
		t.Fatalf("原因应进历史：%+v", e)
	}

	// 名额还回去之后照常接收：这道闸是暂时的背压，不是熔断。
	restore()
	if code, body := h.post(t, "/hook", `{"消息编号":"MSG-2"}`); code != http.StatusOK {
		t.Fatalf("名额释放后应恢复接收，实际 %d：%s", code, body)
	}
	if reqs := h.n.all(); len(reqs) != 1 {
		t.Fatalf("恢复后应投递 1 条，实际 %d", len(reqs))
	}
}

// 名额要还得回来。
//
// 这是这道闸最危险的一半：漏掉 defer 的话，前 maxInflight 条请求全部正常，
// 之后整条入站监听永久回 503——没有报错、没有日志、重启才好。
// 连着发 maxInflight+5 条（每条都已收完）来钉住它。
func TestServeReleasesInflightSlot(t *testing.T) {
	h := newHarness(t, hitCfg(nil))
	for i := 0; i < maxInflight+5; i++ {
		if code, body := h.post(t, "/hook", `{"消息编号":"MSG-1"}`); code != http.StatusOK {
			t.Fatalf("第 %d 条就被闸住了（名额没还回来）：%d %s", i+1, code, body)
		}
	}
	if cur := h.m.gate.cur.Load(); cur != 0 {
		t.Fatalf("请求都处理完了，占用数应归零，实际 %d", cur)
	}
}

// 闸装在鉴权之后：猜错令牌的请求不许占名额，也不该拿到 503。
//
// 反过来的话，一串错令牌的请求就能把名额占满，真消息被挡在外面——
// 这与"先限流再鉴权"是同一条推理（见 handler.go 顶部的检查顺序）。
func TestInflightGateSitsAfterAuth(t *testing.T) {
	full := hitCfg(nil)
	full.WebhookReceivers[0].AuthType = "token"
	full.WebhookReceivers[0].Token = "正确令牌"
	h := newHarness(t, full)

	// 闸满着，令牌是错的：应该报 401（鉴权先拦），而不是 503。
	restore := fillGate(t, h.m)
	if code, body := h.post(t, "/hook?token=错令牌", `{"消息编号":"MSG-1"}`); code != http.StatusUnauthorized {
		t.Fatalf("鉴权应先拦，实际 %d：%s", code, body)
	}
	restore()

	// 闸空着，令牌还是错的：连着发几条之后占用数仍是 0——它们一个名额都没占。
	for i := 0; i < 5; i++ {
		if code, _ := h.post(t, "/hook?token=错令牌", `{}`); code != http.StatusUnauthorized {
			t.Fatalf("第 %d 条应是 401，实际 %d", i+1, code)
		}
	}
	if cur := h.m.gate.cur.Load(); cur != 0 {
		t.Fatalf("被鉴权拦下的请求不该占名额，实际占用 %d", cur)
	}
}

// 路径都没命中的请求同样不占名额：那条路上连接收器都还没找到。
func TestInflightGateNotTakenByUnknownPath(t *testing.T) {
	h := newHarness(t, hitCfg(nil))
	for i := 0; i < 5; i++ {
		if code, _ := h.post(t, "/不存在的路径", `{}`); code != http.StatusNotFound {
			t.Fatalf("第 %d 条应是 404，实际 %d", i+1, code)
		}
	}
	if cur := h.m.gate.cur.Load(); cur != 0 {
		t.Fatalf("路径未命中的请求不该占名额，实际占用 %d", cur)
	}
}

// 闸自己的计数：正好 maxInflight 个能进，第 maxInflight+1 个进不去，还回一个就又能进一个。
func TestInflightGateCapAndRelease(t *testing.T) {
	var g inflightGate
	for i := 0; i < maxInflight; i++ {
		if !g.enter() {
			t.Fatalf("第 %d 个应能进（上限 %d）", i+1, maxInflight)
		}
	}
	if g.enter() {
		t.Fatalf("第 %d 个应被挡住", maxInflight+1)
	}
	g.leave()
	if !g.enter() {
		t.Fatal("还回一个之后应能再进一个")
	}
	if got := g.cur.Load(); got != int64(maxInflight) {
		t.Fatalf("占用数应回到 %d，实际 %d", maxInflight, got)
	}
}

// 正常并发不该被这道闸挡住。
//
// 上限定多少是个判断题，而定得太低会让这道闸从"内存护栏"变成"吞吐瓶颈"——
// 那种退化在逐条发请求的测试里完全看不出来（每条都已经把名额还回去了）。
// 这一条把 16 条请求同时按在"处理到一半"的位置，它们真的同时占着名额，
// 要求全部收下。用假出站的 hold 通道卡住入队，卡住的位置就在名额里面。
func TestInflightGateAllowsNormalConcurrency(t *testing.T) {
	const concurrent = 16
	if concurrent > maxInflight {
		t.Fatalf("并发上限 %d 低于正常并发量 %d，这道闸会挡住正常推送", maxInflight, concurrent)
	}
	h := newHarness(t, hitCfg(nil))
	hold := make(chan struct{})
	h.n.setHold(hold)

	type result struct {
		code int
		err  error
	}
	// 请求在子 goroutine 里发，所以不能用 h.post（它出错时会调 t.Fatalf，
	// 那在非测试 goroutine 里不算失败，只会把现场搅乱）。结果带回主 goroutine 再判。
	out := make(chan result, concurrent)
	var wg sync.WaitGroup
	for i := 0; i < concurrent; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req, err := http.NewRequest(http.MethodPost, h.srv.URL+"/hook", strings.NewReader(`{"消息编号":"MSG-1"}`))
			if err != nil {
				out <- result{err: err}
				return
			}
			req.Header.Set("Content-Type", "application/json")
			resp, err := h.srv.Client().Do(req)
			if err != nil {
				out <- result{err: err}
				return
			}
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			out <- result{code: resp.StatusCode}
		}()
	}

	// 等到全部请求都进了入队（也就都占着名额）再放行。轮询而不是 sleep 一个固定时长：
	// 固定时长在慢机器上就是随机失败，在快机器上又白等。
	deadline := time.Now().Add(10 * time.Second)
	for h.m.gate.cur.Load() < concurrent {
		if time.Now().After(deadline) {
			t.Fatalf("等了 10 秒只有 %d 条请求同时在处理，期望 %d 条", h.m.gate.cur.Load(), concurrent)
		}
		time.Sleep(time.Millisecond)
	}
	close(hold)
	wg.Wait()

	for i := 0; i < concurrent; i++ {
		r := <-out
		if r.err != nil {
			t.Fatalf("第 %d 条请求发不出去：%v", i+1, r.err)
		}
		if r.code != http.StatusOK {
			t.Fatalf("第 %d 条请求应被收下，实际 %d——正常并发被闸住了", i+1, r.code)
		}
	}
	if got := len(h.n.all()); got != concurrent {
		t.Fatalf("应投递 %d 条，实际 %d", concurrent, got)
	}
	if cur := h.m.gate.cur.Load(); cur != 0 {
		t.Fatalf("请求都处理完了，占用数应归零，实际 %d", cur)
	}
}

// 并发进入时放进去的条数不许超过上限。
//
// 少了 CAS（读一次 cur、判一下、再 Add(1)）在单线程下看着完全一样：两个 goroutine
// 读到同一个 cur 才会双双放行，而那个窗口只有几纳秒。所以这一条不是发一轮就完事，
// 而是**反复发很多轮**——实测在 4 核机器上 300 轮 × 512 个 goroutine 每次都能把
// 那个窗口撞开（把 CompareAndSwap 换成 Add 之后连着 5 次运行都转红）。
// 轮数少了它会时红时绿，那种测试比没有更糟。
func TestInflightGateNeverExceedsCapUnderConcurrency(t *testing.T) {
	const (
		rounds  = 300
		workers = 512
	)
	for round := 0; round < rounds; round++ {
		var g inflightGate
		var ok atomic.Int64

		// 全部 goroutine 卡在同一个 channel 上，close 之后一起放出来：
		// 不这么做的话它们会边建边跑，压根撞不到一起。
		start := make(chan struct{})
		var wg sync.WaitGroup
		for i := 0; i < workers; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				if g.enter() {
					ok.Add(1)
				}
			}()
		}
		close(start)
		wg.Wait()

		// 计数器刻意用 atomic 而不是加锁：锁会把 goroutine 串起来，
		// 反而把要撞的那个窗口关上了。
		if got := ok.Load(); got != int64(maxInflight) {
			t.Fatalf("第 %d 轮：%d 个 goroutine 抢 %d 个名额，放进去了 %d 个",
				round+1, workers, maxInflight, got)
		}
		if got := g.cur.Load(); got != int64(maxInflight) {
			t.Fatalf("第 %d 轮：占用数应是 %d，实际 %d", round+1, maxInflight, got)
		}
	}
}
