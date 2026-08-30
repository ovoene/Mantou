package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

// 这一组测试盯的是 5-F：改密码必须让别处的会话失效。
//
// 原来只有"改用户名"那一支会清会话，只改密码时三道关卡一道都不成立——签名密钥不换、
// 用户名没变、会话表没清——于是"我怀疑密码泄露了，赶紧改一个"这个动作对已经泄露出去的
// 会话毫无影响，它会一直活到 SessionHours 到期。默认 1 小时，但那个值面板上可改。

// loginSession 走一遍真实登录，返回可用于后续请求的会话令牌。
func loginSession(t *testing.T, s *Server) string {
	t.Helper()
	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	ctx.Request = newSchemeRequest(t, false, http.MethodPost, "/auth/login", testLoginBody)
	s.handleLogin(ctx)
	if w.Code != http.StatusOK {
		t.Fatalf("登录应成功，得到 %d：%s", w.Code, w.Body.String())
	}
	ck := findCookie(w.Result(), sessionCookie)
	if ck == nil || ck.Value == "" {
		t.Fatal("登录没有下发会话 Cookie")
	}
	return ck.Value
}

// sessionAlive 拿给定令牌过一遍 authRequired，返回它是否还能通过鉴权。
// 用真中间件而不是直接查会话表：会话是否有效由那三道关卡共同决定，只查表会漏掉另外两道。
func sessionAlive(t *testing.T, s *Server, token string) bool {
	t.Helper()
	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	ctx.Request = newSchemeRequest(t, false, http.MethodGet, "/api/overview", "")
	ctx.Request.AddCookie(&http.Cookie{Name: sessionCookie, Value: token})
	s.authRequired()(ctx)
	return !ctx.IsAborted()
}

// postAccount 以 token 的身份调一次改账户接口。
func postAccount(t *testing.T, s *Server, token, body string) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	ctx.Request = newSchemeRequest(t, false, http.MethodPost, "/auth/account", body)
	ctx.Request.AddCookie(&http.Cookie{Name: sessionCookie, Value: token})
	s.handleChangeAccount(ctx)
	return w
}

// othersRevokedOf 取响应里的 othersRevoked 计数。
func othersRevokedOf(t *testing.T, w *httptest.ResponseRecorder) int {
	t.Helper()
	var body struct {
		Data struct {
			OthersRevoked int `json:"othersRevoked"`
		} `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("响应不是预期的 JSON：%v（%s）", err, w.Body.String())
	}
	return body.Data.OthersRevoked
}

// 只改密码：所有旧会话必须失效，当前这台换一条新的接上。
//
// 换而不是留，是因为会话泄露最常见的形态是 Cookie 值被复制走——那时攻击者手上的令牌
// 与管理员浏览器里的是同一个，"保留当前令牌"等于把攻击者一起保留。
func TestPasswordChangeRevokesOtherSessionsAndRotatesCurrent(t *testing.T) {
	s := newAuthTestServer(t)
	current := loginSession(t, s)
	stolen := loginSession(t, s)
	other := loginSession(t, s)
	if current == stolen || current == other || stolen == other {
		t.Fatal("测试前提不成立：三次登录拿到了相同的令牌")
	}
	if !sessionAlive(t, s, stolen) || !sessionAlive(t, s, other) {
		t.Fatal("测试前提不成立：改密码之前另外两个会话就已经无效")
	}

	w := postAccount(t, s, current, `{"oldPassword":"`+testLoginPass+`","newPassword":"brand-new-passphrase"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("改密码应成功，得到 %d：%s", w.Code, w.Body.String())
	}

	if sessionAlive(t, s, stolen) {
		t.Error("改完密码，别处的会话仍然有效——这正是 5-F 的缺陷")
	}
	if sessionAlive(t, s, other) {
		t.Error("改完密码，第三个会话仍然有效")
	}
	if sessionAlive(t, s, current) {
		t.Error("旧令牌必须一起作废：Cookie 被复制走时，它和攻击者手上的是同一个")
	}
	if got := othersRevokedOf(t, w); got != 2 {
		t.Errorf("应当报告清掉 2 个别处的会话，实际 %d", got)
	}

	// 换发的新 Cookie 必须当场可用，否则用户改完密码就掉线了——那就是操作步骤变了。
	fresh := findCookie(w.Result(), sessionCookie)
	if fresh == nil || fresh.Value == "" {
		t.Fatalf("应当换发一条新的会话 Cookie，Set-Cookie: %v", w.Result().Header.Values("Set-Cookie"))
	}
	if fresh.Value == current {
		t.Error("换发的令牌与旧令牌相同，等于没换")
	}
	if !sessionAlive(t, s, fresh.Value) {
		t.Error("换发的令牌应当立即可用")
	}
}

// 改用户名：全部失效，包括当前这台，并且要下发作废 Cookie。
// 这是原有行为，改动不能把它弄坏。
func TestUsernameChangeRevokesEverySession(t *testing.T) {
	s := newAuthTestServer(t)
	current := loginSession(t, s)
	other := loginSession(t, s)

	w := postAccount(t, s, current, `{"username":"newadmin","oldPassword":"`+testLoginPass+`"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("改用户名应成功，得到 %d：%s", w.Code, w.Body.String())
	}

	if sessionAlive(t, s, current) {
		t.Error("改用户名之后当前会话必须失效")
	}
	if sessionAlive(t, s, other) {
		t.Error("改用户名之后别处的会话必须失效")
	}
	if len(liveCookies(w.Result())) != 0 {
		t.Error("改用户名的响应不该带着仍然有效的会话 Cookie")
	}
}

// 当前密码填错时一个会话都不能动。
//
// 这一条是为了不让修复本身变成新的攻击面：若鉴权失败也会清表，任何拿到会话的人
// 都能靠一串错密码把管理员反复踢下线——把一个失效手段变成一个拒绝服务手段。
func TestFailedPasswordChangeRevokesNothing(t *testing.T) {
	s := newAuthTestServer(t)
	current := loginSession(t, s)
	other := loginSession(t, s)

	w := postAccount(t, s, current, `{"oldPassword":"wrong-password","newPassword":"brand-new-passphrase"}`)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("当前密码错误应当 401，得到 %d：%s", w.Code, w.Body.String())
	}
	if !sessionAlive(t, s, current) || !sessionAlive(t, s, other) {
		t.Error("鉴权失败时不该动任何会话")
	}
}

// revokeAll 的直接测试：keep 非空时只留那一条，keep 为空时清空。
func TestRevokeAllKeepsOnlyGivenToken(t *testing.T) {
	r := newSessionRegistry()
	defer r.close()

	const ttl = time.Hour
	r.add("token-a", "admin", ttl)
	r.add("token-b", "admin", ttl)
	r.add("token-c", "admin", ttl)

	if n := r.revokeAll("token-b"); n != 2 {
		t.Errorf("应当清掉 2 条，实际 %d", n)
	}
	// idle 传 0（不启用闲置超时）：这个用例钉的是 revokeAll 的取舍，
	// 不该被闲置判定掺进来。闲置超时另有专门用例。
	if _, ok := r.valid("token-b", "admin", true, 0); !ok {
		t.Error("被保留的那条应当仍然有效")
	}
	for _, tk := range []string{"token-a", "token-c"} {
		if _, ok := r.valid(tk, "admin", true, 0); ok {
			t.Errorf("%s 应当已经失效", tk)
		}
	}

	if n := r.revokeAll(""); n != 1 {
		t.Errorf("keep 为空应当把最后 1 条也清掉，实际清了 %d", n)
	}
	if _, ok := r.valid("token-b", "admin", true, 0); ok {
		t.Error("keep 为空时不该留下任何会话")
	}

	// 空表上再来一次要安全且返回 0，别处会在"没有别的会话"时正常走到这里。
	if n := r.revokeAll(""); n != 0 {
		t.Errorf("空表上应当返回 0，实际 %d", n)
	}
}
