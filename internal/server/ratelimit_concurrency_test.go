package server

import (
	"net/http"
	"sync"
	"testing"
	"time"
)

// 原先登录与敏感操作前的密码复核都是「Allowed 问一次 → bcrypt → Fail 记账」：
// 放行与记账之间隔着一次 bcrypt，同一时刻打进来的一批请求全在第一条失败落账之前通过检查，
// 「N 次失败即锁定」于是约束不了一次并发突发——并发多少就能猜多少次。
// Acquire 把进行中的尝试也算进阈值，下面这组测试把它钉住。

// TestLimiterAcquireCountsInFlight 进行中的尝试计入阈值：占满 maxFails 个之后，
// 即使一次失败都还没落账，新来的也进不来。
func TestLimiterAcquireCountsInFlight(t *testing.T) {
	l := newLoginLimiter(5, time.Minute, time.Minute)
	const key = "ip:203.0.113.7"
	for i := 0; i < 5; i++ {
		if ok, _ := l.Acquire(key); !ok {
			t.Fatalf("第 %d 次 Acquire 被拒，阈值之内应当放行", i+1)
		}
	}
	ok, retry := l.Acquire(key)
	if ok {
		t.Fatal("进行中的尝试已达阈值，第 6 次不该放行")
	}
	if retry <= 0 {
		t.Fatalf("被拒时应给出正的重试秒数，实际 %d", retry)
	}

	// 5 次全部以失败收尾：此时应进入锁定，而且是真的锁定（不是"满员"）。
	for i := 0; i < 5; i++ {
		l.Fail(key)
	}
	if ok, _ := l.Allowed(key); ok {
		t.Fatal("5 次失败之后应当处于锁定状态")
	}
}

// TestLimiterReleaseReturnsSlot 没有结论的尝试归还名额，且不留下失败记录。
func TestLimiterReleaseReturnsSlot(t *testing.T) {
	l := newLoginLimiter(2, time.Minute, time.Minute)
	const key = "ip:198.51.100.4"
	l.Acquire(key)
	l.Acquire(key)
	if ok, _ := l.Acquire(key); ok {
		t.Fatal("测试前提不成立：两个名额都占着时第三次应被拒")
	}
	l.Release(key)
	if ok, _ := l.Acquire(key); !ok {
		t.Fatal("归还一个名额之后应当能再占一个")
	}
	l.Release(key)
	l.Release(key)
	if _, ok := l.entries[key]; ok {
		t.Fatal("名额全部归还且没有失败记录时，这条记录应当被就地删掉")
	}
}

// TestLimiterResetReturnsSlot 成功收尾（Reset）同样把名额还回来。
func TestLimiterResetReturnsSlot(t *testing.T) {
	l := newLoginLimiter(1, time.Minute, time.Minute)
	const key = "ip:198.51.100.5"
	if ok, _ := l.Acquire(key); !ok {
		t.Fatal("第一次应当放行")
	}
	l.Reset(key)
	if ok, _ := l.Acquire(key); !ok {
		t.Fatal("成功收尾之后名额应当已经还回来")
	}
}

// TestLimiterStalePendingExpires 漏还的名额过了 pendingTTL 作废，不会把这个键永久锁死。
func TestLimiterStalePendingExpires(t *testing.T) {
	l := newLoginLimiter(2, time.Minute, time.Minute)
	const key = "ip:198.51.100.6"
	l.Acquire(key)
	l.Acquire(key)
	if ok, _ := l.Acquire(key); ok {
		t.Fatal("测试前提不成立：两个名额都占着时第三次应被拒")
	}
	// 把这两个名额拨到很久以前，模拟"占了名额却一直没还"。
	l.entries[key].pendingAt = time.Now().Add(-l.pendingTTL - time.Second)
	if ok, _ := l.Acquire(key); !ok {
		t.Fatal("超过 pendingTTL 的名额应当作废，这一次应当放行")
	}
}

// TestLimiterReleaseWhileDisabled 名额占下之后锁定被关掉，照样要能还回去；
// 否则再打开锁定时，这些早已结束的尝试还挂在账上。
func TestLimiterReleaseWhileDisabled(t *testing.T) {
	l := newLoginLimiter(2, time.Minute, time.Minute)
	const key = "ip:198.51.100.8"
	l.Acquire(key)
	l.Acquire(key)
	l.update(0, time.Minute, time.Minute) // 关掉锁定
	l.Fail(key)
	l.Release(key)
	l.update(2, time.Minute, time.Minute) // 再打开
	if ok, _ := l.Acquire(key); !ok {
		t.Fatal("关掉锁定期间结束的尝试没把名额还回来")
	}
}

// TestLoginConcurrentBurstRespectsMaxFails 一批并发的错误登录，真正跑到 bcrypt 并记为失败的
// 不超过锁定阈值，其余一律 429。
//
// 修复前这里 40 个请求全都会走到 bcrypt（全是 401）：它们都在第一条失败落账之前通过了检查。
func TestLoginConcurrentBurstRespectsMaxFails(t *testing.T) {
	s := newReauthTestServer(t) // 登录限流开着：reauthTestLoginMaxFails 次即锁
	const n = 40
	codes := make([]int, n)
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			codes[i] = postLogin(t, s, "203.0.113.50", testLoginUser, "wrong-password").Code
		}(i)
	}
	close(start)
	wg.Wait()

	unauthorized, limited := 0, 0
	for _, code := range codes {
		switch code {
		case http.StatusUnauthorized:
			unauthorized++
		case http.StatusTooManyRequests:
			limited++
		default:
			t.Fatalf("意外的状态码 %d", code)
		}
	}
	if unauthorized > reauthTestLoginMaxFails {
		t.Fatalf("%d 个并发请求里有 %d 个跑到了密码校验，超过了锁定阈值 %d",
			n, unauthorized, reauthTestLoginMaxFails)
	}
	if unauthorized+limited != n {
		t.Fatalf("状态码合计 %d，期望 %d", unauthorized+limited, n)
	}
	// 突发过后这个来源应当处于锁定（而不只是"满员"），正确的密码也进不来。
	if code := postLogin(t, s, "203.0.113.50", testLoginUser, testLoginPass).Code; code != http.StatusTooManyRequests {
		t.Fatalf("突发之后应当处于锁定，实际状态码 %d", code)
	}
}

// TestReauthConcurrentBurstRespectsMaxFails 同一条会话并发猜当前密码，
// 真正被 bcrypt 判错的不超过复核阈值。这正是这份计数要防的形态：一条被盗的会话。
func TestReauthConcurrentBurstRespectsMaxFails(t *testing.T) {
	s := newReauthTestServer(t)
	const token = "token-burst-session"
	s.sessions.add(token, testLoginUser, time.Hour)

	const n = 60
	codes := make([]int, n)
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			// 账户名对、密码错：走真的 bcrypt，放行与记账之间才有那段窗口。
			codes[i] = callWithSession(t, s.handleVerifyIdentity, "/api/auth/verify", "application/json",
				`{"account":"`+testLoginUser+`","password":"wrong-password"}`, token).Code
		}(i)
	}
	close(start)
	wg.Wait()

	wrong := 0
	for _, code := range codes {
		switch code {
		case http.StatusForbidden:
			wrong++
		case http.StatusTooManyRequests:
		default:
			t.Fatalf("意外的状态码 %d", code)
		}
	}
	if wrong > reauthMaxFails {
		t.Fatalf("%d 个并发复核里有 %d 个跑到了密码校验，超过了阈值 %d", n, wrong, reauthMaxFails)
	}
}

// TestReauthEarlyReturnReleasesSlot 占了名额却在验密码之前就结束的请求（参数不对），
// 名额要还回来，不能一直计入阈值。
func TestReauthEarlyReturnReleasesSlot(t *testing.T) {
	s := newReauthTestServer(t)
	const token = "token-bad-body-session"
	s.sessions.add(token, testLoginUser, time.Hour)

	// 远超阈值次数的坏请求：每一次都在读请求体那一步就回 400。
	for i := 0; i < reauthMaxFails*3; i++ {
		rec := callWithSession(t, s.handleVerifyIdentity, "/api/auth/verify", "application/json", `不是 JSON`, token)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("第 %d 次坏请求的状态码是 %d，期望 400（%s）", i+1, rec.Code, rec.Body.String())
		}
	}
	// 名额都还回来了：正确的密码照常通过。
	rec := callWithSession(t, s.handleVerifyIdentity, "/api/auth/verify", "application/json",
		`{"account":"`+testLoginUser+`","password":"`+testLoginPass+`"}`, token)
	if rec.Code != http.StatusOK {
		t.Fatalf("坏请求之后正确密码的状态码是 %d，期望 200（%s）", rec.Code, rec.Body.String())
	}
}
