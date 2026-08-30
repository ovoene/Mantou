package webservice

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"mantou/internal/auth"
	"mantou/internal/config"
)

// okHandler 计数被放行的请求数，用于区分"通过认证"与"被 401 拦下"。
func okHandler(hits *int32) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(hits, 1)
		w.WriteHeader(http.StatusOK)
	})
}

func childWithBasic(on bool, user, pass string) config.WebChild {
	var ch config.WebChild
	ch.Access.BasicAuth = on
	ch.Access.BasicAuthUser = user
	ch.Access.BasicAuthPass = pass
	return ch
}

// TestWithBasicAuthSkipped 覆盖三种"应当整体跳过认证"的配置：开关关闭、账号为空、口令为空。
// 口令为空尤其重要：若退化成"用空口令校验"，就会弹出认证框却对任何空口令放行。
func TestWithBasicAuthSkipped(t *testing.T) {
	hash, err := auth.HashPassword("s3cret")
	if err != nil {
		t.Fatalf("生成哈希失败: %v", err)
	}
	cases := map[string]config.WebChild{
		"开关关闭":   childWithBasic(false, "admin", hash),
		"账号为空":   childWithBasic(true, "", hash),
		"口令为空":   childWithBasic(true, "admin", ""),
		"账号口令皆空": childWithBasic(true, "", ""),
	}
	for name, ch := range cases {
		t.Run(name, func(t *testing.T) {
			var hits int32
			h := withBasicAuth(ch, okHandler(&hits))
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
			if rec.Code != http.StatusOK || hits != 1 {
				t.Fatalf("期望直接放行，实际 code=%d hits=%d", rec.Code, hits)
			}
		})
	}
}

// TestWithBasicAuthHashed 是主路径：配置里存的是 bcrypt 哈希。
func TestWithBasicAuthHashed(t *testing.T) {
	hash, err := auth.HashPassword("s3cret")
	if err != nil {
		t.Fatalf("生成哈希失败: %v", err)
	}
	var hits int32
	h := withBasicAuth(childWithBasic(true, "admin", hash), okHandler(&hits))

	// 无凭证：401 且必须带 WWW-Authenticate，否则浏览器不会弹认证框。
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("无凭证应为 401，实际 %d", rec.Code)
	}
	if got := rec.Header().Get("WWW-Authenticate"); got == "" {
		t.Fatal("401 响应缺少 WWW-Authenticate 头")
	}

	// 错口令 / 错账号：401。
	for _, c := range [][2]string{{"admin", "wrong"}, {"root", "s3cret"}} {
		rec = httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.SetBasicAuth(c[0], c[1])
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("凭证 %v 应被拒绝，实际 %d", c, rec.Code)
		}
	}

	// 正确凭证：放行。
	rec = httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.SetBasicAuth("admin", "s3cret")
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || hits != 1 {
		t.Fatalf("正确凭证应放行，实际 code=%d hits=%d", rec.Code, hits)
	}
}

// TestWithBasicAuthPlaintextCompat 覆盖升级兼容分支：配置里存的仍是历史明文口令
// （一次性迁移还没跑到，或用户直接手改了配置文件），此时也必须能正常校验，
// 否则升级会把站点整站锁死。
func TestWithBasicAuthPlaintextCompat(t *testing.T) {
	var hits int32
	h := withBasicAuth(childWithBasic(true, "admin", "plain-pass"), okHandler(&hits))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.SetBasicAuth("admin", "plain-pass")
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || hits != 1 {
		t.Fatalf("明文口令应能通过，实际 code=%d hits=%d", rec.Code, hits)
	}

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/", nil)
	req.SetBasicAuth("admin", "plain-pas")
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("明文口令不匹配应为 401，实际 %d", rec.Code)
	}
}

// TestBasicAuthCacheHit 验证同一凭证的第二次请求不再触发 bcrypt 比对（compute 只调用一次），
// 这是把"每请求一次 bcrypt"降到"每 5 分钟一次"的关键。
func TestBasicAuthCacheHit(t *testing.T) {
	c := newBasicAuthCache()
	var calls int32
	compute := func() bool { atomic.AddInt32(&calls, 1); return true }
	for i := 0; i < 5; i++ {
		if !c.verify("k", compute) {
			t.Fatal("verify 应返回通过")
		}
	}
	if calls != 1 {
		t.Fatalf("compute 期望调用 1 次，实际 %d 次", calls)
	}
	// 不同凭证各自计算，互不复用。
	if c.verify("other", compute) != true || calls != 2 {
		t.Fatalf("不同键应各算一次，calls=%d", calls)
	}
}

// TestBasicAuthCacheSingleFlight 验证单飞：浏览器并发拉取一个页面里的几十个资源时，
// 同一凭证只应做一次 bcrypt，其余请求等结果。
func TestBasicAuthCacheSingleFlight(t *testing.T) {
	c := newBasicAuthCache()
	var calls int32
	release := make(chan struct{})
	compute := func() bool {
		atomic.AddInt32(&calls, 1)
		<-release // 卡住第一次计算，模拟 bcrypt 的耗时
		return true
	}

	const n = 32
	var wg sync.WaitGroup
	results := make([]bool, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			results[idx] = c.verify("same", compute)
		}(i)
	}
	// 等到确有一个 goroutine 进入 compute 后再放行，确保其余的都已排在 done 上。
	deadline := time.Now().Add(2 * time.Second)
	for atomic.LoadInt32(&calls) == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	close(release)
	wg.Wait()

	if calls != 1 {
		t.Fatalf("并发同凭证期望只算 1 次，实际 %d 次", calls)
	}
	for i, ok := range results {
		if !ok {
			t.Fatalf("第 %d 个请求未复用到通过结果", i)
		}
	}
}

// TestBasicAuthCacheExpiry 验证失败结果只缓存很短时间：条目过期后必须重新计算，
// 否则用户改对口令还要等上一次失败结果自然老化。
func TestBasicAuthCacheExpiry(t *testing.T) {
	c := newBasicAuthCache()
	var calls int32
	compute := func() bool { atomic.AddInt32(&calls, 1); return false }
	if c.verify("k", compute) {
		t.Fatal("verify 应返回不通过")
	}
	// 手工把条目改成已过期，避免测试真的等 30 秒。
	c.mu.Lock()
	c.entries["k"].exp = time.Now().Add(-time.Second)
	c.mu.Unlock()
	if c.verify("k", compute) {
		t.Fatal("verify 应返回不通过")
	}
	if calls != 2 {
		t.Fatalf("过期后应重新计算，calls=%d", calls)
	}
}

// TestBasicAuthCacheSweep 验证条目上限：灌入远超上限的不同凭证后，缓存不会无上限增长。
func TestBasicAuthCacheSweep(t *testing.T) {
	c := newBasicAuthCache()
	compute := func() bool { return false }
	for i := 0; i < basicAuthMaxEntries+200; i++ {
		c.verify(basicAuthKey("u", string(rune(i))+"p", "stored"), compute)
	}
	c.mu.Lock()
	n := len(c.entries)
	c.mu.Unlock()
	if n > basicAuthMaxEntries {
		t.Fatalf("缓存条目 %d 超过上限 %d", n, basicAuthMaxEntries)
	}
}
