package app

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"mantou/internal/config"
)

// countingReader 吐出固定数量的字节，并记下实际被读走了多少。
type countingReader struct {
	remaining int64
	read      int64
}

func (r *countingReader) Read(p []byte) (int, error) {
	if r.remaining <= 0 {
		return 0, io.EOF
	}
	n := int64(len(p))
	if n > r.remaining {
		n = r.remaining
	}
	r.remaining -= n
	r.read += n
	return int(n), nil
}

// 排空必须有上限：读满上限就停手，一个字节都不多读。
func TestDrainForReuseStopsAtLimit(t *testing.T) {
	const limit = 32 << 10

	huge := &countingReader{remaining: 8 << 20}
	if drainForReuse(huge, limit) {
		t.Error("后面还有大量数据，不该报告已读完")
	}
	if huge.read != limit {
		t.Errorf("最多只该读 %d 字节，实际读了 %d", limit, huge.read)
	}

	small := &countingReader{remaining: 100}
	if !drainForReuse(small, limit) {
		t.Error("100 字节的响应体应当被完整读完")
	}
	if small.read != 100 {
		t.Errorf("应当读完 100 字节，实际 %d", small.read)
	}

	// 刚好等于上限：报"未读完"。这与 Transport 的实际行为一致——它也要看到 EOF
	// 才会复用连接，而这一读并没有触到 EOF。
	exact := &countingReader{remaining: limit}
	if drainForReuse(exact, limit) {
		t.Error("读满上限但没触到 EOF，应当报未读完")
	}
}

// 上限必须真的接在动作上：对端吐多少就下多少的话，一个填错成大文件直链的 URL
// 会让这条任务每次触发都吃掉几十上百 MB 下行（审计四 4-D）。
func TestRunHTTPActionDoesNotDownloadWholeBody(t *testing.T) {
	// 服务端愿意吐出的总量，远大于「读一小段 + 有上限地排空」之和（4 KiB + 32 KiB）。
	const offered = 32 << 20
	// 判定线取 offered 的四分之一：本机回环的收发缓冲能吞下几百 KB 到一两 MB，
	// 留这么多余量才不会因为缓冲大小而误判。没有上限时这里会跑满 offered。
	const ceiling = offered / 4

	var written int64
	chunk := strings.Repeat("x", 32<<10)
	handlerDone := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		defer close(handlerDone)
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		for atomic.LoadInt64(&written) < offered {
			n, err := io.WriteString(w, chunk)
			atomic.AddInt64(&written, int64(n))
			if err != nil {
				return // 客户端已经撒手，正是期望的结果
			}
		}
	}))
	defer srv.Close()

	action := config.CronAction{Params: map[string]string{"url": srv.URL}}
	out, err := runHTTPAction(action, 30, false)
	if err != nil {
		t.Fatalf("请求本身应当成功：%v", err)
	}
	if out != "HTTP 200" {
		t.Errorf("结果应当是 HTTP 200，实际 %q", out)
	}

	select {
	case <-handlerDone:
	case <-time.After(30 * time.Second):
		t.Fatal("服务端一直在写，说明客户端还在收")
	}
	if got := atomic.LoadInt64(&written); got > ceiling {
		t.Errorf("下行 %d 字节，超过判定线 %d——排空没有上限", got, ceiling)
	}
}

// 排空是为了复用连接，这条测试盯的就是那个目的：响应体比"读一小段"的上限长，
// 但短于排空上限时，第二次请求必须落在同一条连接上。
// 若哪天有人把排空整段删掉（"反正内容也不看"），这里会立刻变成两条连接。
func TestRunHTTPActionReusesConnectionAfterBoundedDrain(t *testing.T) {
	// 比 maxActionRespBytes 长（否则第一段读取就已经触到 EOF，排空成了空操作），
	// 又短于 actionDrainLimit（否则排空会主动放弃复用）。
	const bodyLen = 8 << 10
	if bodyLen <= maxActionRespBytes || bodyLen-maxActionRespBytes >= actionDrainLimit {
		t.Fatalf("测试前提不成立：%d 字节的响应体盯不住排空这一步", bodyLen)
	}

	var mu sync.Mutex
	conns := map[string]int{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		conns[r.RemoteAddr]++
		mu.Unlock()
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = io.WriteString(w, strings.Repeat("y", bodyLen))
	}))
	defer srv.Close()

	action := config.CronAction{Params: map[string]string{"url": srv.URL}}
	for i := 0; i < 2; i++ {
		if _, err := runHTTPAction(action, 30, false); err != nil {
			t.Fatalf("第 %d 次请求失败：%v", i+1, err)
		}
	}

	mu.Lock()
	defer mu.Unlock()
	if len(conns) != 1 {
		t.Errorf("两次请求应当复用同一条连接，实际用了 %d 条：%v", len(conns), conns)
	}
}

// 有上限的排空不能把 errcode 那条路弄坏：机器人类接口业务失败时照样回 200，
// 真正的错误藏在响应体开头，而排空只发生在读完那一小段之后。
func TestRunHTTPActionStillReadsErrCodeBeforeDraining(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"errcode":40013,"errmsg":"invalid appid"}`)
		// 后面再跟一大段垃圾，模拟"错误码在前、正文很长"的响应。
		_, _ = io.WriteString(w, strings.Repeat(" ", 1<<20))
	}))
	defer srv.Close()

	action := config.CronAction{Params: map[string]string{"url": srv.URL}}
	_, err := runHTTPAction(action, 30, false)
	if err == nil {
		t.Fatal("接口返回了 errcode，应当报错")
	}
	if !strings.Contains(err.Error(), "40013") || !strings.Contains(err.Error(), "invalid appid") {
		t.Errorf("错误里应当带上 errcode 与 errmsg，实际 %q", err.Error())
	}
}
