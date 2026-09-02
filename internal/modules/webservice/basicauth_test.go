package webservice

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"

	"mantou/internal/auth"
	"mantou/internal/config"
	"mantou/internal/logx"
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
	ch.ID = "ch1"
	ch.Access.BasicAuth = on
	ch.Access.BasicAuthUser = user
	ch.Access.BasicAuthPass = pass
	return ch
}

// basicModule 一个带共享桶表的模块，供 withBasicAuth 记 bcrypt 计算的账。
func basicModule(t *testing.T) *Module {
	t.Helper()
	m := New(logx.New(logx.Options{}))
	t.Cleanup(func() { _ = m.Close() })
	return m
}

// authReq 一个带凭证的请求；来源 IP 固定，好让预算按同一个桶计。
func authReq(user, pass string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "203.0.113.9:40000"
	if user != "" || pass != "" {
		req.SetBasicAuth(user, pass)
	}
	return req
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
			h := withBasicAuth(basicModule(t), ch, okHandler(&hits))
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
	h := withBasicAuth(basicModule(t), childWithBasic(true, "admin", hash), okHandler(&hits))

	// 无凭证：401 且必须带 WWW-Authenticate，否则浏览器不会弹认证框。
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("无凭证应为 401，实际 %d", rec.Code)
	}
	got := rec.Header().Get("WWW-Authenticate")
	if got == "" {
		t.Fatal("401 响应缺少 WWW-Authenticate 头")
	}
	// realm 不许带产品名：它会被扫描器当指纹收走（见 withBasicAuth 的说明）。
	if strings.Contains(strings.ToLower(got), "mantou") {
		t.Fatalf("WWW-Authenticate 泄露了产品名：%q", got)
	}

	// 错口令 / 错账号：401。两次都是新凭证、都要真算一次 bcrypt，
	// 而 basicAuthComputeRPS=3 的预算容得下（这条断言同时钉住"预算不误伤人手输错口令"）。
	for _, c := range [][2]string{{"admin", "wrong"}, {"root", "s3cret"}} {
		rec = httptest.NewRecorder()
		h.ServeHTTP(rec, authReq(c[0], c[1]))
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("凭证 %v 应被拒绝，实际 %d", c, rec.Code)
		}
	}

	// 正确凭证：放行。
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, authReq("admin", "s3cret"))
	if rec.Code != http.StatusOK || hits != 1 {
		t.Fatalf("正确凭证应放行，实际 code=%d hits=%d", rec.Code, hits)
	}
}

// TestWithBasicAuthPlaintextCompat 覆盖升级兼容分支：配置里存的仍是历史明文口令
// （一次性迁移还没跑到，或用户直接手改了配置文件），此时也必须能正常校验，
// 否则升级会把站点整站锁死。
func TestWithBasicAuthPlaintextCompat(t *testing.T) {
	var hits int32
	h := withBasicAuth(basicModule(t), childWithBasic(true, "admin", "plain-pass"), okHandler(&hits))

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, authReq("admin", "plain-pass"))
	if rec.Code != http.StatusOK || hits != 1 {
		t.Fatalf("明文口令应能通过，实际 code=%d hits=%d", rec.Code, hits)
	}

	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, authReq("admin", "plain-pas"))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("明文口令不匹配应为 401，实际 %d", rec.Code)
	}
}

// cheapHash 造一个 bcrypt 代价最低（cost 4）的哈希，专给"要连着算几十次"的用例。
//
// 不用 auth.HashPassword：它取 bcrypt.DefaultCost（10），一次校验约 50~100ms，
// 而整包并行跑测试时 CPU 争抢能把它再放大一个数量级。那会让下面那个用例跑上十几秒，
// 期间令牌桶按秒补充的额度足以把所有请求都放过去——用例于是既红一次、又什么都没验到。
// 代价参数不影响被测逻辑：auth.IsHash 走 bcrypt.Cost，任何合法代价都认，
// 校验也照样是真的 bcrypt 比对。
func cheapHash(t *testing.T, pass string) string {
	t.Helper()
	b, err := bcrypt.GenerateFromPassword([]byte(pass), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("生成哈希失败: %v", err)
	}
	return string(b)
}

// TestWithBasicAuthComputeBudget 是这道闸的本体：攻击者每次换一个新的随机口令，
// 缓存键必然也是新的（键由凭证算出），失败缓存挡不住任何一个请求——
// 不设预算的话每个请求都要做一次 bcrypt（约 50~100ms CPU），
// 一条普通线路就能把整台机器的 CPU 买走，而且不需要任何凭证。
//
// 预期：每个来源每秒只有 basicAuthComputeRPS 次 bcrypt，之后回 429（不是 401），
// 且**一次 bcrypt 都不做**。
func TestWithBasicAuthComputeBudget(t *testing.T) {
	hash := cheapHash(t, "s3cret")
	m := basicModule(t)
	var hits int32
	h := withBasicAuth(m, childWithBasic(true, "admin", hash), okHandler(&hits))

	var okCount, limited int
	// 灌 30 个各不相同的随机口令：远超每秒预算，且没有任何两个能共用缓存。
	start := time.Now()
	for i := 0; i < 30; i++ {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, authReq("admin", "guess-"+strconv.Itoa(i)))
		switch rec.Code {
		case http.StatusUnauthorized:
			okCount++
		case http.StatusTooManyRequests:
			limited++
			if rec.Header().Get("Retry-After") == "" {
				t.Fatal("429 应带 Retry-After，规矩的客户端要靠它退避")
			}
		default:
			t.Fatalf("第 %d 次的状态码意外：%d", i, rec.Code)
		}
	}
	elapsed := time.Since(start)
	// 上限按实测耗时算，而不是假定"这一圈跑得远快于 1 秒"：令牌桶起始满额
	// basicAuthComputeRPS，之后按每秒同样的速率补充，所以真正允许的次数是
	// 「满额 + 这段时间补进来的」。写死一个常数的话，机器一慢用例就红，
	// 而那种红报的不是缺陷（见 cheapHash 的说明）。多给 1 次是边界余量。
	budget := basicAuthComputeRPS + int(elapsed.Seconds()*basicAuthComputeRPS) + 1
	if okCount > budget {
		t.Fatalf("被放去算 bcrypt 的次数 %d 超出预算 %d（耗时 %v）", okCount, budget, elapsed)
	}
	if limited == 0 {
		t.Fatalf("预算没有生效：30 个不同的错口令全都被放去算了 bcrypt（耗时 %v）", elapsed)
	}
	if hits != 0 {
		t.Fatalf("错口令不该放行，hits=%d", hits)
	}

	// 正确凭证在预算耗尽时同样会被挡（429），这是这道闸的代价，必须是"稍后重试"
	// 而不是"口令错误"——否则合法用户会被误导去改口令。
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, authReq("admin", "s3cret"))
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("预算耗尽时应回 429，实际 %d", rec.Code)
	}
}

// TestWithBasicAuthBudgetSkipsCacheHits 预算只管"要真算 bcrypt"的请求。
// 若它挡在缓存之前，一个已经通过认证的用户浏览页面（几十个子资源并发）
// 会在第四个请求上就被 429，等于把这个功能变成不可用。
func TestWithBasicAuthBudgetSkipsCacheHits(t *testing.T) {
	hash, err := auth.HashPassword("s3cret")
	if err != nil {
		t.Fatalf("生成哈希失败: %v", err)
	}
	var hits int32
	h := withBasicAuth(basicModule(t), childWithBasic(true, "admin", hash), okHandler(&hits))
	for i := 0; i < 50; i++ {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, authReq("admin", "s3cret"))
		if rec.Code != http.StatusOK {
			t.Fatalf("第 %d 个请求被挡下（%d）：缓存命中不该消耗预算", i+1, rec.Code)
		}
	}
	if hits != 50 {
		t.Fatalf("50 个请求应全部放行，实际 %d", hits)
	}
}

// TestWithBasicAuthBudgetPerSource 预算按来源 IP 分桶：一个 IP 在爆破，
// 不该把另一个 IP 上的正常登录一起挡掉。
func TestWithBasicAuthBudgetPerSource(t *testing.T) {
	hash, err := auth.HashPassword("s3cret")
	if err != nil {
		t.Fatalf("生成哈希失败: %v", err)
	}
	var hits int32
	h := withBasicAuth(basicModule(t), childWithBasic(true, "admin", hash), okHandler(&hits))

	// A 先把自己的预算用光。
	for i := 0; i < 10; i++ {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, authReq("admin", "guess-"+strconv.Itoa(i)))
		_ = rec
	}
	// B 换一个来源，第一次就该被正常校验并放行。
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "198.51.100.7:40000"
	req.SetBasicAuth("admin", "s3cret")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || hits != 1 {
		t.Fatalf("另一个来源应有自己的预算，实际 code=%d hits=%d", rec.Code, hits)
	}
}

// TestBasicAuthCacheHit 验证同一凭证的第二次请求不再触发 bcrypt 比对（compute 只调用一次），
// 这是把"每请求一次 bcrypt"降到"每 5 分钟一次"的关键。
func TestBasicAuthCacheHit(t *testing.T) {
	c := newBasicAuthCache()
	var calls int32
	compute := func() bool { atomic.AddInt32(&calls, 1); return true }
	for i := 0; i < 5; i++ {
		if ok, _ := c.verify("k", nil, compute); !ok {
			t.Fatal("verify 应返回通过")
		}
	}
	if calls != 1 {
		t.Fatalf("compute 期望调用 1 次，实际 %d 次", calls)
	}
	// 不同凭证各自计算，互不复用。
	if ok, _ := c.verify("other", nil, compute); !ok || calls != 2 {
		t.Fatalf("不同键应各算一次，calls=%d", calls)
	}
}

// TestBasicAuthCacheBudgetGuardsComputeOnly 预算在缓存之后、bcrypt 之前。
// 这是 verify 这个函数唯一的新契约，单独钉一条：命中缓存不问预算，未命中才问；
// 预算说不行就一次 compute 都不做，并且回报 limited。
func TestBasicAuthCacheBudgetGuardsComputeOnly(t *testing.T) {
	c := newBasicAuthCache()
	var calls, asked int32
	compute := func() bool { atomic.AddInt32(&calls, 1); return true }
	allow := func() bool { atomic.AddInt32(&asked, 1); return true }
	deny := func() bool { atomic.AddInt32(&asked, 1); return false }

	if ok, limited := c.verify("k", allow, compute); !ok || limited {
		t.Fatalf("有预算时应正常校验，ok=%v limited=%v", ok, limited)
	}
	if calls != 1 || asked != 1 {
		t.Fatalf("首次应问一次预算、算一次，calls=%d asked=%d", calls, asked)
	}
	// 第二次命中缓存：不该再问预算，也不该再算。
	if ok, limited := c.verify("k", deny, compute); !ok || limited {
		t.Fatalf("缓存命中应直接通过，ok=%v limited=%v", ok, limited)
	}
	if calls != 1 || asked != 1 {
		t.Fatalf("缓存命中不该问预算也不该重算，calls=%d asked=%d", calls, asked)
	}
	// 新键 + 预算耗尽：limited，且不算。
	if ok, limited := c.verify("new", deny, compute); ok || !limited {
		t.Fatalf("预算耗尽应回 limited，ok=%v limited=%v", ok, limited)
	}
	if calls != 1 {
		t.Fatalf("预算耗尽时不该做任何 bcrypt，calls=%d", calls)
	}
	// 被挡下的那次不许在缓存里留任何痕迹：否则下一次（预算恢复了）会命中一条
	// 凭空捏造的失败结果，正确口令要等 30 秒才生效。
	c.mu.Lock()
	_, cached := c.entries["new"]
	c.mu.Unlock()
	if cached {
		t.Fatal("被预算挡下的凭证不该写入缓存")
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
			results[idx], _ = c.verify("same", nil, compute)
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
	if ok, _ := c.verify("k", nil, compute); ok {
		t.Fatal("verify 应返回不通过")
	}
	// 手工把条目改成已过期，避免测试真的等 30 秒。
	c.mu.Lock()
	c.entries["k"].exp = time.Now().Add(-time.Second)
	c.mu.Unlock()
	if ok, _ := c.verify("k", nil, compute); ok {
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
		c.verify(basicAuthKey("u", string(rune(i))+"p", "stored"), nil, compute)
	}
	c.mu.Lock()
	n := len(c.entries)
	c.mu.Unlock()
	if n > basicAuthMaxEntries {
		t.Fatalf("缓存条目 %d 超过上限 %d", n, basicAuthMaxEntries)
	}
}
