package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

// 总览页外网 IP 卡片的检测调度（publicip.go）。要钉住的是：
//   1. 轮询接口从不等检测——检测最坏要等满每个端点的超时，而 /overview 每 3 秒就来一次；
//   2. 同一时刻只有一轮，并发的轮询不会各起一轮去刷第三方端点；
//   3. 取到的结果按期缓存，两族各算各的期；
//   4. 取不到时保留上一次的地址，失败原因另外说明；
//   5. 手动刷新有最小间隔。

// fakeClock 可拨的时钟。
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// fakeDetector 记下每次取址，按族返回预设结果；gate 非 nil 时先等它关闭。
type fakeDetector struct {
	mu    sync.Mutex
	calls map[string]int
	ip    map[string]string
	err   map[string]error
	gate  chan struct{}
}

func newFakeDetector() *fakeDetector {
	return &fakeDetector{
		calls: map[string]int{},
		ip:    map[string]string{"ipv4": "203.0.113.7", "ipv6": "2400:3200::1"},
		err:   map[string]error{},
	}
}

func (d *fakeDetector) detect(ctx context.Context, stack string) (string, error) {
	d.mu.Lock()
	d.calls[stack]++
	gate := d.gate
	d.mu.Unlock()
	if gate != nil {
		select {
		case <-gate:
		case <-ctx.Done():
			return "", ctx.Err()
		}
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if err := d.err[stack]; err != nil {
		return "", err
	}
	return d.ip[stack], nil
}

func (d *fakeDetector) count(stack string) int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.calls[stack]
}

func (d *fakeDetector) set(stack, ip string, err error) {
	d.mu.Lock()
	d.ip[stack], d.err[stack] = ip, err
	d.mu.Unlock()
}

func newWatch() (*publicIPWatch, *fakeDetector, *fakeClock) {
	d := newFakeDetector()
	clk := &fakeClock{t: time.Date(2026, 9, 28, 10, 0, 0, 0, time.Local)}
	return &publicIPWatch{detect: d.detect, now: clk.Now}, d, clk
}

// waitIdle 等这一轮检测结束。
func waitIdle(t *testing.T, w *publicIPWatch) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		w.mu.Lock()
		busy := w.checking
		w.mu.Unlock()
		if !busy {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("检测 5 秒还没结束")
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// 检测卡住的时候，轮询照样立刻返回；并发的轮询只起一轮。
func TestPublicIPViewNeverWaitsAndStartsOneRound(t *testing.T) {
	w, d, _ := newWatch()
	d.gate = make(chan struct{})

	var wg sync.WaitGroup
	start := time.Now()
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if v := w.view(); !v.Checking || v.V4.IP != "" {
				t.Errorf("检测未结束时应返回「检测中」且没有地址：%+v", v)
			}
		}()
	}
	wg.Wait()
	if took := time.Since(start); took > time.Second {
		t.Fatalf("轮询等了检测 %s——它不该等", took)
	}
	close(d.gate)
	waitIdle(t, w)

	if d.count("ipv4") != 1 || d.count("ipv6") != 1 {
		t.Fatalf("20 次并发轮询只该起一轮检测，实际 ipv4=%d ipv6=%d", d.count("ipv4"), d.count("ipv6"))
	}
	v := w.view()
	if v.Checking || v.V4.IP != "203.0.113.7" || v.V6.IP != "2400:3200::1" || v.V4.OKAt == 0 || v.V4.Err != "" {
		t.Fatalf("检测结束后应带上两族地址：%+v", v)
	}
}

// 取到之后按期缓存：期内的轮询不再去问端点，到期才重取。
func TestPublicIPCachedUntilDue(t *testing.T) {
	w, d, clk := newWatch()
	w.view()
	waitIdle(t, w)

	clk.Advance(publicIPTTL - time.Second)
	w.view()
	waitIdle(t, w)
	if d.count("ipv4") != 1 || d.count("ipv6") != 1 {
		t.Fatalf("未到期不该重取：ipv4=%d ipv6=%d", d.count("ipv4"), d.count("ipv6"))
	}

	clk.Advance(2 * time.Second)
	w.view()
	waitIdle(t, w)
	if d.count("ipv4") != 2 || d.count("ipv6") != 2 {
		t.Fatalf("到期应重取两族：ipv4=%d ipv6=%d", d.count("ipv4"), d.count("ipv6"))
	}
}

// 取不到时保留上一次的地址并说明原因；失败的那一族提前重试，另一族不陪着重取。
func TestPublicIPFailureKeepsLastAddress(t *testing.T) {
	w, d, clk := newWatch()
	w.view()
	waitIdle(t, w)
	firstOK := w.view().V6.OKAt

	d.set("ipv6", "", errors.New("公网取址失败（已尝试 4 个端点）：network is unreachable"))
	clk.Advance(publicIPTTL)
	w.view()
	waitIdle(t, w)

	v := w.view()
	if v.V6.IP != "2400:3200::1" || v.V6.OKAt != firstOK {
		t.Fatalf("取不到时应保留上一次的地址与它的时刻：%+v", v.V6)
	}
	if !strings.Contains(v.V6.Err, "network is unreachable") || v.V6.TriedAt <= v.V6.OKAt {
		t.Fatalf("应说明最近一次失败的原因与时刻：%+v", v.V6)
	}
	if v.V4.Err != "" || v.V4.IP != "203.0.113.7" {
		t.Fatalf("另一族不受影响：%+v", v.V4)
	}

	// 失败的那一族隔 publicIPRetry 再试；IPv4 离下次到期还早，不陪着重取。
	clk.Advance(publicIPRetry)
	w.view()
	waitIdle(t, w)
	if d.count("ipv6") != 3 || d.count("ipv4") != 2 {
		t.Fatalf("只该重试失败的那一族：ipv4=%d ipv6=%d", d.count("ipv4"), d.count("ipv6"))
	}
}

// 失败原因有长度上限：它进接口响应、挂在卡片的提示上。
func TestPublicIPErrorIsClamped(t *testing.T) {
	w, d, _ := newWatch()
	d.set("ipv4", "", errors.New(strings.Repeat("端点返回异常 ", 200)))
	w.view()
	waitIdle(t, w)
	if n := len(w.view().V4.Err); n == 0 || n > publicIPErrMax+len("…") {
		t.Fatalf("失败原因应截到 %d 字节以内，实际 %d", publicIPErrMax, n)
	}
}

// 手动刷新不等到期，但两次之间至少隔 publicIPForceGap；正在检测时也不另起一轮。
func TestPublicIPManualRefresh(t *testing.T) {
	w, d, clk := newWatch()
	w.view()
	waitIdle(t, w)

	clk.Advance(time.Second)
	if v := w.refresh(); !v.Checking {
		t.Fatal("手动刷新应立刻起一轮")
	}
	waitIdle(t, w)
	if d.count("ipv4") != 2 || d.count("ipv6") != 2 {
		t.Fatalf("手动刷新应重取两族：ipv4=%d ipv6=%d", d.count("ipv4"), d.count("ipv6"))
	}

	clk.Advance(publicIPForceGap - time.Second)
	if v := w.refresh(); v.Checking {
		t.Fatal("间隔不足时不该再起一轮")
	}
	if d.count("ipv4") != 2 {
		t.Fatalf("间隔不足时不该再去问端点：ipv4=%d", d.count("ipv4"))
	}

	d.gate = make(chan struct{})
	clk.Advance(time.Second)
	w.refresh()
	clk.Advance(publicIPForceGap)
	w.refresh() // 上一轮还没结束
	close(d.gate)
	waitIdle(t, w)
	if d.count("ipv4") != 3 {
		t.Fatalf("检测进行中的手动刷新不该另起一轮：ipv4=%d", d.count("ipv4"))
	}
}

// 刷新接口：立即返回当前结果（检测在后台），数据形态就是界面读的那几个字段。
func TestPublicIPRefreshHandler(t *testing.T) {
	gin.SetMode(gin.TestMode)
	s := &Server{}
	d := newFakeDetector()
	d.gate = make(chan struct{})
	defer close(d.gate)
	s.publicIP.detect = d.detect

	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	ctx.Request = httptest.NewRequest(http.MethodPost, "/overview/public-ip/refresh", nil)
	s.handlePublicIPRefresh(ctx)

	if w.Code != http.StatusOK {
		t.Fatalf("状态码 %d：%s", w.Code, w.Body.String())
	}
	var out struct {
		Data map[string]json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"v4", "v6", "checking"} {
		if _, ok := out.Data[k]; !ok {
			t.Fatalf("响应缺少 %q：%s", k, w.Body.String())
		}
	}
	if string(out.Data["checking"]) != "true" {
		t.Fatalf("刷新之后应处于检测中：%s", w.Body.String())
	}
}
