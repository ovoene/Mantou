package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"mantou/internal/config"
)

// 这一组测试锁住「令牌有效时长到期后所有窗口自动退出」在服务端的那一半：
// /auth/me 顺带下发本次会话还剩多少秒（expiresIn），前端据此在本地排一个到期闹钟
// （见 web/src/stores/auth.ts）。少了这个字段浏览器无从知道自己该退出——页面上没有
// 请求要发，界面就一直停在原样，直到用户点了什么才被一个 401 弹回登录页。
//
// 要钉住三条性质：
//   - 报的是**绝对过期时间**的余量（Auth.SessionHours 从登录起算、永不延长），
//     而不是每次请求按配置现算一遍——后者恒等于满额，闹钟永远也响不了；
//   - 只读：不刷新闲置起点、不清除待删除宽限。看门狗到点正是拿这个接口去确认的，
//     若这一问顺手保活，闲置超时就被前端自己无限推后了；
//   - 问不到时**不带**这个字段，而不是回 0——0 会被前端读成"立刻到期"。
//
// 与 session_lifecycle_test.go 一样不睡真实时间：把 expiresAt 往前挪即可（见 ageSession）。

// ageSession 把绝对过期时刻往前挪 d，等价于"这条会话已经活过了 d"。
//
// 与 goIdle 的分工对应两条不同的倒数：goIdle 动 lastSeenAt（闲置超时，每个请求归零），
// 这里动 expiresAt（令牌有效时长，永不延长）。前端的到期闹钟只跟后者。
func ageSession(t *testing.T, r *sessionRegistry, token string, d time.Duration) {
	t.Helper()
	r.mu.Lock()
	defer r.mu.Unlock()
	e, ok := r.entries[sessionKey(token)]
	if !ok {
		t.Fatal("会话不在表里，无法模拟会话变老")
	}
	e.expiresAt = e.expiresAt.Add(-d)
}

// meResp 是 /auth/me 解开 { data } 信封后的响应体。
//
// ExpiresIn 用指针：本用例要区分的正是"没有这个字段"与"这个字段是 0"，
// 而值类型会把两者一起读成 0。
type meResp struct {
	Data struct {
		Username  string `json:"username"`
		ExpiresIn *int   `json:"expiresIn"`
	} `json:"data"`
}

// meTestEngine 把 /auth/me 挂在 authRequired 后面，与真实路由表同一条链路。
// 直接调 handleMe 是不够的：它要靠中间件放进 context 的 username，
// 而 expiresIn 又要靠请求里那条 Cookie 反查会话。
func meTestEngine(s *Server) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	g := r.Group("", s.authRequired())
	g.GET("/auth/me", s.handleMe)
	g.GET("/ping", func(c *gin.Context) { c.Status(http.StatusOK) })
	return r
}

// getMe 走一遍 /auth/me，返回状态码与解开信封后的响应体。
func getMe(t *testing.T, engine *gin.Engine, ck *http.Cookie) (int, meResp) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "http://panel.example.com/auth/me", nil)
	req.AddCookie(ck)
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)
	var body meResp
	if w.Code == http.StatusOK {
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
			t.Fatalf("解析 /auth/me 响应失败: %v（原文 %s）", err, w.Body.String())
		}
	}
	return w.Code, body
}

// newMeTestServer 造一个令牌有效时长为 hours 小时的面板 + 对应的测试路由。
func newMeTestServer(t *testing.T, hours int) (*Server, *gin.Engine) {
	t.Helper()
	s := newAuthTestServer(t)
	if err := s.deps.Config.Update(func(c *config.Config) { c.Auth.SessionHours = hours }); err != nil {
		t.Fatal(err)
	}
	return s, meTestEngine(s)
}

// 活着的会话报出剩余时长；不存在的、已过绝对过期时间的都报"没有"。
func TestExpiresInReportsRemainingLifetime(t *testing.T) {
	r := newTestRegistry(t)
	const tok = "token-expires-in"
	const ttl = 2 * time.Hour
	r.add(tok, testSessionUser, ttl)

	d, ok := r.expiresIn(tok)
	if !ok {
		t.Fatal("活着的会话必须报出剩余时长，否则前端排不出到期闹钟")
	}
	// 上界就是 ttl（add 之后时间只会往前走）；下界留一分钟，够容忍任何测试机的卡顿。
	if d > ttl || d < ttl-time.Minute {
		t.Fatalf("剩余时长应约为 %v，实际 %v", ttl, d)
	}

	if _, ok := r.expiresIn("token-never-issued"); ok {
		t.Fatal("不存在的会话不得报出剩余时长")
	}

	// 已过期必须走 (0,false) 这条路：handleMe 正是靠它决定"不下发这个字段"，
	// 而回一个非正数会被前端当成有效期读进去。
	ageSession(t, r, tok, ttl+time.Second)
	if d, ok := r.expiresIn(tok); ok {
		t.Fatalf("已过期的会话不得报出剩余时长，实际得到 %v", d)
	}
}

// expiresIn 是只读的：不推后闲置起点，也不清除待删除宽限。
func TestExpiresInDoesNotKeepSessionAlive(t *testing.T) {
	r := newTestRegistry(t)
	const tok = "token-readonly"
	r.add(tok, testSessionUser, time.Hour)
	r.markPendingDelete(tok)
	goIdle(t, r, tok, 10*time.Minute)

	lastSeen := sessionLastSeenAt(t, r, tok)
	pending := sessionPendingDeleteAt(t, r, tok)
	if pending.IsZero() {
		t.Fatal("会话未进入待删除宽限，测试前提不成立")
	}

	if _, ok := r.expiresIn(tok); !ok {
		t.Fatal("宽限中的会话仍在令牌有效期内，应报出剩余时长")
	}

	if got := sessionLastSeenAt(t, r, tok); !got.Equal(lastSeen) {
		t.Fatalf("expiresIn 不得推后闲置起点：%v → %v。看门狗到点就是拿 /auth/me 去确认的，"+
			"若这一问顺手保活，闲置超时会被前端自己无限推后，而它正是「关窗口没发出信标」时的收尾手段",
			lastSeen, got)
	}
	if got := sessionPendingDeleteAt(t, r, tok); !got.Equal(pending) {
		t.Fatalf("expiresIn 不得动待删除宽限：%v → %v。清掉它等于把已经关掉的窗口捞回来", pending, got)
	}
}

// 端到端：登录后 /auth/me 必须带上 expiresIn，且约等于配置的令牌有效时长。
func TestMeReportsRemainingSessionLifetime(t *testing.T) {
	const hours = 3
	s, engine := newMeTestServer(t, hours)
	ck := loginForTest(t, s)

	code, body := getMe(t, engine, ck)
	if code != http.StatusOK {
		t.Fatalf("/auth/me 应放行，得到 %d", code)
	}
	if body.Data.Username != testLoginUser {
		t.Fatalf("用户名应为 %q，实际 %q", testLoginUser, body.Data.Username)
	}
	if body.Data.ExpiresIn == nil {
		t.Fatal("/auth/me 必须带 expiresIn：前端靠它排到期闹钟，缺了就退回「下次点击被 401 弹走」的老行为")
	}
	want := int((hours * time.Hour).Seconds())
	if got := *body.Data.ExpiresIn; got > want || got < want-60 {
		t.Fatalf("expiresIn 应约为 %d 秒（令牌有效时长 %d 小时），实际 %d", want, hours, got)
	}
}

// expiresIn 跟着绝对过期时间倒数，活跃请求不会把它顶回满额。
//
// 这是整条链路最容易做坏的一处：把它写成"按配置现算"最省事，接口看着也对
// （首次登录时两者本来就相等），但每次轮询都会把前端的闹钟推回满额，于是到点永远不响，
// 而人还停在那个已经作废的界面上——正是这次要修的问题本身。
func TestMeExpiryCountsDownAndActivityDoesNotExtendIt(t *testing.T) {
	const hours = 3
	s, engine := newMeTestServer(t, hours)
	ck := loginForTest(t, s)

	// 这条会话已经活了一小时。
	ageSession(t, s.sessions, ck.Value, time.Hour)
	// 这一小时里用户一直在用面板：普通请求会刷新闲置起点、也能救活宽限中的会话，
	// 但绝不延长绝对上限（见 valid）。
	if code := doAuthed(engine, ck, http.MethodGet, "/ping", false); code != http.StatusOK {
		t.Fatalf("普通请求应放行，得到 %d", code)
	}

	_, body := getMe(t, engine, ck)
	if body.Data.ExpiresIn == nil {
		t.Fatal("/auth/me 必须带 expiresIn")
	}
	want := int(((hours - 1) * time.Hour).Seconds())
	if got := *body.Data.ExpiresIn; got > want || got < want-60 {
		t.Fatalf("会话已活过一小时，expiresIn 应约为 %d 秒，实际 %d。"+
			"若它按配置现算或随请求刷新，前端的到期闹钟就永远不会响", want, got)
	}
}
