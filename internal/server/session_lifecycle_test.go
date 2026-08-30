package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"mantou/internal/config"
)

// 这一组测试锁住会话的两条"提前失效"通道，此前它们一行覆盖都没有：
//
//	通道一 关闭最后一个面板窗口 → 前端信标 → 服务端置入待删除宽限（sessionGrace）。
//	        刷新页面必须能在宽限内把它救活，否则每按一次 F5 就掉线；
//	        真的关掉则必须到期作废，且后台轮询不得把它反复复活。
//	通道二 闲置超时（Auth.SessionIdleMinutes）→ 给通道一兜底。
//	        信标发不出去的情况（浏览器崩溃、强杀、断电、拔网线）由它收尾。
//
// 两者与"令牌时长"（Auth.SessionHours，从登录起算的绝对上限）互不替代，
// 最后一个用例把这层关系也钉住：活跃请求会推后闲置起点，但绝不延长绝对上限。
//
// 测试不去睡 sessionGrace 那 5 秒，而是直接把时间戳挪到过去（见 expireGrace / goIdle）：
// 本机时钟粒度粗，靠真实等待排先后既慢又容易变成偶发失败。只有一处例外，见
// TestRevivedSessionSurvivesItsGraceTimer——那一处要验的正是定时器本身的行为。

const testSessionUser = "admin"

// ---------- 直接读写会话表的测试辅助（同包，故可绕过接口做白盒断言） ----------

// sessionExists 报告会话是否还在表里。判"失效"时一并检查它，才能区分
// "校验被拒但条目还留着"与"确实已被移除"。
func sessionExists(r *sessionRegistry, token string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	_, ok := r.entries[sessionKey(token)]
	return ok
}

// sessionEntryOf 取出会话条目，不存在即让用例当场失败。
func sessionEntryOf(t *testing.T, r *sessionRegistry, token string) *sessionEntry {
	t.Helper()
	r.mu.RLock()
	defer r.mu.RUnlock()
	e, ok := r.entries[sessionKey(token)]
	if !ok {
		t.Fatal("会话不在表里，测试前提不成立")
	}
	return e
}

// sessionPendingDeleteAt 返回待删除宽限的到期时刻；零值表示不在宽限中。
func sessionPendingDeleteAt(t *testing.T, r *sessionRegistry, token string) time.Time {
	t.Helper()
	e := sessionEntryOf(t, r, token)
	r.mu.RLock()
	defer r.mu.RUnlock()
	return e.pendingDeleteAt
}

// sessionExpiresAt 返回绝对过期时刻。
func sessionExpiresAt(t *testing.T, r *sessionRegistry, token string) time.Time {
	t.Helper()
	e := sessionEntryOf(t, r, token)
	r.mu.RLock()
	defer r.mu.RUnlock()
	return e.expiresAt
}

// expireGrace 把待删除宽限的到期时刻挪到过去，模拟"宽限已经走完"。
// 挪成"当前时间减一秒"而不是减去 sessionGrace，是为了与随后那次 valid() 之间
// 有一个确定的先后关系——不依赖本机时钟粒度。
func expireGrace(t *testing.T, r *sessionRegistry, token string) {
	t.Helper()
	r.mu.Lock()
	defer r.mu.Unlock()
	e, ok := r.entries[sessionKey(token)]
	if !ok {
		t.Fatal("会话不在表里，无法让宽限到期")
	}
	if e.pendingDeleteAt.IsZero() {
		t.Fatal("会话并未处于待删除宽限，让宽限到期没有意义")
	}
	e.pendingDeleteAt = time.Now().Add(-time.Second)
}

// sessionLastSeenAt 返回"最后一次见到"的时刻，即闲置倒数的起点。
func sessionLastSeenAt(t *testing.T, r *sessionRegistry, token string) time.Time {
	t.Helper()
	e := sessionEntryOf(t, r, token)
	r.mu.RLock()
	defer r.mu.RUnlock()
	return e.lastSeenAt
}

// goIdle 把闲置倒数的起点往前挪 d，模拟这段时间里一个请求都没来。
//
// 是在原值基础上减，而不是设成"当前时间减 d"——这个区别决定了滑动性质测不测得出来。
// 若按后者写，每次挪动都会覆盖掉上一次 valid() 留下的值，于是"放行时有没有把起点推后"
// 这件事在测试里永远看不见：把 valid() 里那行归零删掉，用例照样全绿。
// 这不是假设，是变异检验里真的发生过一次。
func goIdle(t *testing.T, r *sessionRegistry, token string, d time.Duration) {
	t.Helper()
	r.mu.Lock()
	defer r.mu.Unlock()
	e, ok := r.entries[sessionKey(token)]
	if !ok {
		t.Fatal("会话不在表里，无法模拟闲置")
	}
	e.lastSeenAt = e.lastSeenAt.Add(-d)
}

// newTestRegistry 建一张会话表，并保证清扫协程随用例结束退出。
func newTestRegistry(t *testing.T) *sessionRegistry {
	t.Helper()
	r := newSessionRegistry()
	t.Cleanup(r.close)
	return r
}

// ---------- 通道一：关闭最后一个窗口 ----------

// 信标之后在宽限内刷新页面 → 会话被救活。
// 这是"关窗口即注销"最容易做坏的一头：刷新与关闭在浏览器那边都是页面卸载，
// 若不给宽限、或宽限内不救活，用户每按一次 F5 就会被踢回登录页。
func TestBeaconThenRefreshInsideGraceRevives(t *testing.T) {
	r := newTestRegistry(t)
	const tok = "token-refresh"
	r.add(tok, testSessionUser, time.Hour)

	r.markPendingDelete(tok)
	if sessionPendingDeleteAt(t, r, tok).IsZero() {
		t.Fatal("信标应把会话置入待删除宽限")
	}

	// 宽限内的刷新是一次普通（非静默）鉴权请求，revive=true。
	if _, ok := r.valid(tok, testSessionUser, true, 0); !ok {
		t.Fatal("宽限内刷新应当放行")
	}
	if got := sessionPendingDeleteAt(t, r, tok); !got.IsZero() {
		t.Fatalf("刷新应清除宽限标记，实际仍为 %v", got)
	}
}

// 被救活的会话不会再被原先那个到期定时器删掉。
//
// 全套测试里唯一一处真的等待：markPendingDelete 预约的 time.AfterFunc 是"关窗口注销"
// 真正动手删除的那一步，它到点后会不会误删一个已被刷新救活的会话，只有等它跑过才知道。
// 用挪时间戳的办法绕不过去——定时器认的是自己的到点时刻，不看条目里的值。
func TestRevivedSessionSurvivesItsGraceTimer(t *testing.T) {
	r := newTestRegistry(t)
	const tok = "token-survive"
	r.add(tok, testSessionUser, time.Hour)

	r.markPendingDelete(tok)
	if _, ok := r.valid(tok, testSessionUser, true, 0); !ok {
		t.Fatal("宽限内刷新应当放行")
	}

	// 多等半秒，确保定时器确实已经跑过，而不是刚好还没被调度。
	time.Sleep(sessionGrace + 500*time.Millisecond)

	if !sessionExists(r, tok) {
		t.Fatal("宽限内已被刷新救活，到期定时器不该再删掉它")
	}
	if _, ok := r.valid(tok, testSessionUser, true, 0); !ok {
		t.Fatal("被救活的会话应当仍然有效")
	}
}

// 宽限走完 → 会话作废，连迟到的刷新也捞不回来。
// 这是"关闭最后一个 mantou 窗口，下次访问要重新认证"这条要求的落点。
func TestGraceExpiredSessionIsGoneEvenForRefresh(t *testing.T) {
	r := newTestRegistry(t)
	const tok = "token-closed"
	r.add(tok, testSessionUser, time.Hour)

	r.markPendingDelete(tok)
	expireGrace(t, r, tok)

	// revive=true 是"用户主动操作"那一档，权限最高的一档也必须被拒——
	// 否则一个慢半拍的刷新就能把已经关掉的窗口的会话接回去。
	if _, ok := r.valid(tok, testSessionUser, true, 0); ok {
		t.Fatal("宽限走完之后，迟到的刷新不该把会话捞回来")
	}
	if sessionExists(r, tok) {
		t.Fatal("失效的会话应当已从会话表移除，而不是留着占位")
	}
}

// 后台静默轮询不会把待注销的会话救活。
// 面板页面本身就在周期性打接口，若这些请求算作"用户还在"，关掉窗口的那 5 秒宽限
// 会被最后几个在途请求反复复活，整条注销通道就形同虚设。
func TestSilentPollingDoesNotReviveClosedSession(t *testing.T) {
	r := newTestRegistry(t)
	const tok = "token-silent"
	r.add(tok, testSessionUser, time.Hour)

	r.markPendingDelete(tok)
	before := sessionPendingDeleteAt(t, r, tok)
	if before.IsZero() {
		t.Fatal("信标应把会话置入待删除宽限")
	}

	// 宽限内的静默请求照常放行（在途请求不该突然报错），但不得动宽限标记。
	if _, ok := r.valid(tok, testSessionUser, false, 0); !ok {
		t.Fatal("宽限内的静默请求应当照常放行")
	}
	if got := sessionPendingDeleteAt(t, r, tok); !got.Equal(before) {
		t.Fatalf("静默请求不该改动宽限标记：%v → %v", before, got)
	}

	// 宽限走完之后，静默请求同样被拒。
	expireGrace(t, r, tok)
	if _, ok := r.valid(tok, testSessionUser, false, 0); ok {
		t.Fatal("宽限走完后静默请求也应被拒")
	}
	if sessionExists(r, tok) {
		t.Fatal("失效的会话应当已从会话表移除")
	}
}

// ---------- 通道二：闲置超时 ----------

// 闲置超过阈值 → 会话作废。
// 这一条兜的是信标根本发不出去的情况：浏览器崩溃、被强杀、断电、拔网线。
func TestIdleTimeoutKillsSession(t *testing.T) {
	r := newTestRegistry(t)
	const tok = "token-idle"
	const idle = 10 * time.Minute
	r.add(tok, testSessionUser, time.Hour)

	// 还没到阈值：放行。
	goIdle(t, r, tok, 9*time.Minute)
	if _, ok := r.valid(tok, testSessionUser, true, idle); !ok {
		t.Fatal("闲置未达阈值时应当放行")
	}

	// 超过阈值：作废。注意此时绝对过期时间还远远没到，失效只能来自闲置判定。
	goIdle(t, r, tok, 11*time.Minute)
	if _, ok := r.valid(tok, testSessionUser, true, idle); ok {
		t.Fatal("闲置超过阈值应当判失效")
	}
	if sessionExists(r, tok) {
		t.Fatal("失效的会话应当已从会话表移除")
	}
}

// 闲置起点每来一次请求就归零，不累加。
// 这正是闲置超时与"令牌时长"的分界：它约束的是"多久没人来"，而不是"总共活了多久"，
// 所以把它调短对正常使用没有打扰——只要人还在操作，就永远走不到头。
func TestIdleTimeoutSlidesOnEveryRequest(t *testing.T) {
	r := newTestRegistry(t)
	const idle = 10 * time.Minute

	for _, tc := range []struct {
		name   string
		revive bool
	}{
		{name: "用户操作", revive: true},
		// 静默的后台轮询同样算"浏览器还活着"——它恰好证明了闲置超时要判断的那件事。
		// 这与上面"静默请求不得救活待注销会话"不矛盾：那条走的是宽限标记，两者互不相干。
		{name: "后台轮询", revive: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tok := "token-slide-" + tc.name
			r.add(tok, testSessionUser, time.Hour)

			goIdle(t, r, tok, 9*time.Minute)
			shifted := sessionLastSeenAt(t, r, tok)
			if _, ok := r.valid(tok, testSessionUser, tc.revive, idle); !ok {
				t.Fatal("闲置未达阈值时应当放行")
			}
			// 直接盯住起点本身有没有被推到当前时刻。
			// 拿挪动之后的值（9 分钟前）作比较基准，而不是挪动之前的值：后者与"当前时刻"
			// 只差几十微秒，本机时钟粒度粗到能让两者相等，断言会变成偶发失败。
			if got := sessionLastSeenAt(t, r, tok); !got.After(shifted) {
				t.Fatalf("放行时应把闲置起点推到当前时刻，实际仍为 %v", got)
			}

			// 再挪 9 分钟。这一步是相对原值减，所以只有"上一次请求确实把起点推后了"
			// 才会落在 9 分钟前；否则就是从登录起累加的 18 分钟，早过了阈值。
			goIdle(t, r, tok, 9*time.Minute)
			if _, ok := r.valid(tok, testSessionUser, tc.revive, idle); !ok {
				t.Fatal("闲置起点应被上一次请求推后，而不是从登录起累加")
			}
		})
	}
}

// 闲置超时填 0 表示不启用：闲多久都不因此失效。
func TestIdleTimeoutZeroDisablesIt(t *testing.T) {
	r := newTestRegistry(t)
	const tok = "token-idle-off"
	r.add(tok, testSessionUser, 365*24*time.Hour)

	goIdle(t, r, tok, 30*24*time.Hour)
	if _, ok := r.valid(tok, testSessionUser, true, 0); !ok {
		t.Fatal("闲置超时为 0 表示不启用，闲多久都不该因此失效")
	}
}

// 活跃请求会推后闲置起点，但绝不延长"令牌时长"这个绝对上限。
// 两个时钟的分工全在这个用例里：一个从最后一次访问起算、会归零；
// 另一个从登录起算、永不延长。少了后半句，令牌时长就变成了滑动有效期——
// 一份被复制走的会话只要有人隔一会儿访问一次，就能永远活下去。
func TestActivityDoesNotExtendAbsoluteExpiry(t *testing.T) {
	r := newTestRegistry(t)
	const tok = "token-abs"
	r.add(tok, testSessionUser, time.Hour)

	want := sessionExpiresAt(t, r, tok)
	for i := 0; i < 3; i++ {
		if _, ok := r.valid(tok, testSessionUser, true, 10*time.Minute); !ok {
			t.Fatal("会话应当有效")
		}
	}
	if got := sessionExpiresAt(t, r, tok); !got.Equal(want) {
		t.Fatalf("活跃请求不该延长绝对过期时间：%v → %v", want, got)
	}

	// 绝对过期时间一到就失效，与刚刚有没有访问过无关。
	const stale = "token-abs-expired"
	r.add(stale, testSessionUser, -time.Minute)
	if _, ok := r.valid(stale, testSessionUser, true, time.Hour); ok {
		t.Fatal("已过绝对过期时间的会话应当判失效")
	}
	if sessionExists(r, stale) {
		t.Fatal("失效的会话应当已从会话表移除")
	}
}

// ---------- 端到端：走真实中间件与真实处理函数 ----------

// authTestEngine 挂一条最小路由：一个受保护的探测接口 + 关闭会话接口。
func authTestEngine(s *Server) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	g := r.Group("", s.authRequired())
	g.GET("/ping", func(c *gin.Context) { c.Status(http.StatusOK) })
	g.POST("/close", s.handleSessionClose)
	return r
}

// loginForTest 走一遍真实登录，返回服务端已登记的那条会话 Cookie。
func loginForTest(t *testing.T, s *Server) *http.Cookie {
	t.Helper()
	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	ctx.Request = newSchemeRequest(t, false, http.MethodPost, "/auth/login", testLoginBody)
	s.handleLogin(ctx)
	if w.Code != http.StatusOK {
		t.Fatalf("登录应成功，得到 %d: %s", w.Code, w.Body.String())
	}
	ck := findCookie(w.Result(), sessionCookie)
	if ck == nil {
		t.Fatal("登录未下发会话 Cookie")
	}
	return ck
}

// doAuthed 带上会话 Cookie 发一次请求，silent 为真时加上后台轮询标记头。
func doAuthed(engine *gin.Engine, ck *http.Cookie, method, path string, silent bool) int {
	req := httptest.NewRequest(method, "http://panel.example.com"+path, nil)
	req.AddCookie(ck)
	if silent {
		req.Header.Set("X-Mantou-Silent", "1")
	}
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)
	return w.Code
}

// 端到端串一遍"关闭最后一个窗口"：登录 → 信标 → 后台轮询救不活 → 普通请求能救活
// → 再次关闭并等宽限走完 → 访问被拒。
//
// 前面那些用例直接调 valid()，这里补的是它们看不见的那截接线：
// X-Mantou-Silent 这个头有没有真的落到 revive 参数上、handleSessionClose 有没有真的
// 置入宽限、被拒时中间件回的是不是 401。任一处接错，前面全绿这里照样会红。
func TestSessionCloseEndToEndThroughMiddleware(t *testing.T) {
	s := newAuthTestServer(t)
	engine := authTestEngine(s)
	ck := loginForTest(t, s)

	if code := doAuthed(engine, ck, http.MethodGet, "/ping", false); code != http.StatusOK {
		t.Fatalf("刚登录就该能访问，实际 %d", code)
	}

	// 关闭最后一个窗口：前端信标打到 /close。
	if code := doAuthed(engine, ck, http.MethodPost, "/close", false); code != http.StatusOK {
		t.Fatalf("关闭会话接口应回 200，实际 %d", code)
	}
	if sessionPendingDeleteAt(t, s.sessions, ck.Value).IsZero() {
		t.Fatal("信标应把会话置入待删除宽限")
	}

	// 在途的后台轮询：照常放行，但不得把会话救活。
	if code := doAuthed(engine, ck, http.MethodGet, "/ping", true); code != http.StatusOK {
		t.Fatalf("宽限内的后台轮询应照常放行，实际 %d", code)
	}
	if sessionPendingDeleteAt(t, s.sessions, ck.Value).IsZero() {
		t.Fatal("带 X-Mantou-Silent 的请求不该清除宽限标记")
	}

	// 普通请求（刷新页面）：救活。
	if code := doAuthed(engine, ck, http.MethodGet, "/ping", false); code != http.StatusOK {
		t.Fatalf("宽限内刷新应照常放行，实际 %d", code)
	}
	if got := sessionPendingDeleteAt(t, s.sessions, ck.Value); !got.IsZero() {
		t.Fatalf("刷新应清除宽限标记，实际仍为 %v", got)
	}

	// 真的关掉：宽限走完后再访问，必须重新认证。
	if code := doAuthed(engine, ck, http.MethodPost, "/close", false); code != http.StatusOK {
		t.Fatalf("关闭会话接口应回 200，实际 %d", code)
	}
	expireGrace(t, s.sessions, ck.Value)
	if code := doAuthed(engine, ck, http.MethodGet, "/ping", false); code != http.StatusUnauthorized {
		t.Fatalf("关闭最后一个窗口后再访问应回 401，实际 %d", code)
	}
}

// 端到端验闲置超时：阈值取自配置，不是写死的常量。
// 这一条单独存在的理由是接线——中间件若忘了把 Auth.SessionIdleMinutes 读出来传下去，
// 直接调 valid() 的那些用例一个都不会红。
func TestIdleTimeoutEndToEndReadsConfig(t *testing.T) {
	s := newAuthTestServer(t)
	engine := authTestEngine(s)

	const idleMinutes = 10
	if err := s.deps.Config.Update(func(c *config.Config) {
		c.Auth.SessionIdleMinutes = idleMinutes
	}); err != nil {
		t.Fatal(err)
	}

	ck := loginForTest(t, s)
	if code := doAuthed(engine, ck, http.MethodGet, "/ping", false); code != http.StatusOK {
		t.Fatalf("刚登录就该能访问，实际 %d", code)
	}

	// 阈值内闲置：仍然放行。
	goIdle(t, s.sessions, ck.Value, (idleMinutes-1)*time.Minute)
	if code := doAuthed(engine, ck, http.MethodGet, "/ping", false); code != http.StatusOK {
		t.Fatalf("闲置未达阈值时应放行，实际 %d", code)
	}

	// 超过阈值：必须重新认证。
	goIdle(t, s.sessions, ck.Value, (idleMinutes+1)*time.Minute)
	if code := doAuthed(engine, ck, http.MethodGet, "/ping", false); code != http.StatusUnauthorized {
		t.Fatalf("闲置超过阈值后应回 401，实际 %d", code)
	}

	// 关掉闲置超时后，同样的闲置时长不该再让会话失效。
	if err := s.deps.Config.Update(func(c *config.Config) {
		c.Auth.SessionIdleMinutes = 0
	}); err != nil {
		t.Fatal(err)
	}
	ck2 := loginForTest(t, s)
	goIdle(t, s.sessions, ck2.Value, 30*24*time.Hour)
	if code := doAuthed(engine, ck2, http.MethodGet, "/ping", false); code != http.StatusOK {
		t.Fatalf("闲置超时设为 0 表示不启用，应放行，实际 %d", code)
	}
}

// ---------- 设置接口：闲置超时的读写这条线 ----------

// 设置页改闲置超时能存下来、能读回来，且不会被别处的设置提交顺手关掉。
//
// 上面那些用例都是直接改配置对象，绕过了接口；而用户唯一能改这个值的路径就是设置页。
// 这一条钉的正是它们看不见的那截接线：请求体的字段名、响应里的字段名、以及区间兜底。
// 任一处写错，前面全绿而设置页上这一项形同虚设（读永远显示默认值，或者存不进去）。
func TestUpdateSettingsPersistsSessionIdle(t *testing.T) {
	s := newAuthTestServer(t)

	putSettings := func(body string) {
		t.Helper()
		w := httptest.NewRecorder()
		ctx, _ := gin.CreateTestContext(w)
		ctx.Request = httptest.NewRequest(http.MethodPut, "/settings", strings.NewReader(body))
		ctx.Request.Header.Set("Content-Type", "application/json")
		s.handleUpdateSettings(ctx)
		if w.Code != http.StatusOK {
			t.Fatalf("保存设置失败（%d）：%s", w.Code, w.Body.String())
		}
	}
	idleNow := func() int { return s.deps.Config.Snapshot().Auth.SessionIdleMinutes }

	putSettings(`{"auth":{"sessionIdleMinutes":45}}`)
	if got := idleNow(); got != 45 {
		t.Fatalf("闲置超时没存下来，实际 %d", got)
	}

	// 只改登录失败次数、不带这一项：必须保持原样。
	// 这是这一项用 *int 接收的原因——按值接收的话，任何一次不相关的提交都会把它
	// 重置成 0，也就是静默关掉闲置超时，而设置页上只会显示一个 0。
	putSettings(`{"auth":{"loginMaxFails":3}}`)
	if got := idleNow(); got != 45 {
		t.Fatalf("一次不相关的设置提交把闲置超时改成了 %d", got)
	}

	// 显式填 0：这是「不启用」这个有效选择，必须落下去，不能被当成「没填」。
	putSettings(`{"auth":{"sessionIdleMinutes":0}}`)
	if got := idleNow(); got != 0 {
		t.Fatalf("显式关闭没生效，实际 %d", got)
	}

	// 区间兜底：绕过面板直接调接口传负数或天文数字，也得落到合法值。
	for _, tc := range []struct{ in, want int }{
		{in: -1, want: 0},
		{in: 999999, want: 43200},
	} {
		putSettings(`{"auth":{"sessionIdleMinutes":` + strconv.Itoa(tc.in) + `}}`)
		if got := idleNow(); got != tc.want {
			t.Fatalf("传 %d 应夹到 %d，实际 %d", tc.in, tc.want, got)
		}
	}

	// 读回这一路：字段名要与设置页读的那个键一致，否则界面上永远显示默认值。
	putSettings(`{"auth":{"sessionIdleMinutes":45}}`)
	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	ctx.Request = httptest.NewRequest(http.MethodGet, "/settings", nil)
	s.handleGetSettings(ctx)
	if w.Code != http.StatusOK {
		t.Fatalf("读设置失败（%d）：%s", w.Code, w.Body.String())
	}
	var resp struct {
		Data struct {
			Auth struct {
				SessionIdleMinutes *int `json:"sessionIdleMinutes"`
			} `json:"auth"`
		} `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Data.Auth.SessionIdleMinutes == nil {
		t.Fatal("响应里没有 auth.sessionIdleMinutes 这个键，设置页读不到这一项")
	}
	if *resp.Data.Auth.SessionIdleMinutes != 45 {
		t.Fatalf("读回来是 %d，期望 45", *resp.Data.Auth.SessionIdleMinutes)
	}
}
