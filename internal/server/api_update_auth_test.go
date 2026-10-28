package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"mantou/internal/config"
)

// 「关于」页的上传按钮每次都先验一次密码，验对了这条会话拿到一份一次性授权（见 api_update_auth.go）。
// 下面钉住几件事：授权只发给验对了的那条会话；未验签的上传认它、且**只认一次**（不论那次成败）；
// 过期了、用过了都回到"当场带凭据"的老规矩，并告诉人该怎么办；被提前拒掉的上传不白白用掉它。

// jsonData 取出 respondOK 的 {"data":{…}} 信封里那个对象本身。
func jsonData(t *testing.T, body []byte) map[string]any {
	t.Helper()
	var envelope struct {
		Data map[string]any `json:"data"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		t.Fatalf("响应不是合法 JSON：%v（%s）", err, body)
	}
	if envelope.Data == nil {
		t.Fatalf("响应里没有 data：%s", body)
	}
	return envelope.Data
}

// postUpdateAuth 以指定会话调一次「上传前验证密码」。
func postUpdateAuth(t *testing.T, s *Server, token, account, password string) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(map[string]string{"account": account, "password": password})
	if err != nil {
		t.Fatal(err)
	}
	return callWithSession(t, s.handleSelfUpdateAuth, "/api/meta/self-update/auth", "application/json", string(body), token)
}

// hasUpdateGrant 看一眼这条会话手上有没有没过期的授权，不取走它。
// 键用处理器里同一个 reauthKey 现算，而不是在测试里抄一遍算法。
func hasUpdateGrant(t *testing.T, s *Server, token string) bool {
	t.Helper()
	ctx, _ := gin.CreateTestContext(httptest.NewRecorder())
	ctx.Request = httptest.NewRequest(http.MethodGet, "/", nil)
	ctx.Request.AddCookie(&http.Cookie{Name: sessionCookie, Value: token})
	key := s.reauthKey(ctx)
	s.updateAuth.mu.Lock()
	defer s.updateAuth.mu.Unlock()
	until, ok := s.updateAuth.until[key]
	return ok && time.Now().Before(until)
}

// TestUpdateAuthGrantsOneShot 授权取一次就作废，过期的取不到，再验一次是覆盖而不是累加。
func TestUpdateAuthGrantsOneShot(t *testing.T) {
	var g updateAuthGrants // 零值可用：手拼的 Server 壳子里它就是零值
	t0 := time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)

	if g.consume("sess:a", t0) {
		t.Fatal("还没验过就取到了授权")
	}
	if until := g.grant("sess:a", t0); !until.Equal(t0.Add(updateAuthTTL)) {
		t.Fatalf("截止时刻是 %v，期望 %v", until, t0.Add(updateAuthTTL))
	}
	if g.consume("sess:b", t0.Add(time.Second)) {
		t.Fatal("别的会话取到了这条会话的授权")
	}
	if !g.consume("sess:a", t0.Add(time.Minute)) {
		t.Fatal("有效期内第一次取应当取得到")
	}
	if g.consume("sess:a", t0.Add(time.Minute)) {
		t.Fatal("授权被取了第二次：一次验证只该换一次上传")
	}

	// 到点即失效，且取过一次（取不到）之后条目也随之删掉，不留着。
	g.grant("sess:a", t0)
	if g.consume("sess:a", t0.Add(updateAuthTTL)) {
		t.Fatal("到点的授权不该再取得到")
	}
	if n := len(g.until); n != 0 {
		t.Fatalf("取过的过期授权还留在表里：%v", g.until)
	}

	// 再验一次是覆盖：从新的时刻重新起算，而且仍然只有一份。
	g.grant("sess:a", t0)
	g.grant("sess:a", t0.Add(3*time.Minute))
	if !g.consume("sess:a", t0.Add(updateAuthTTL+time.Minute)) {
		t.Fatal("重新验证后应从那一刻起算")
	}
	if g.consume("sess:a", t0.Add(updateAuthTTL+time.Minute)) {
		t.Fatal("验了两次攒下了两份授权")
	}

	// 过期的条目在下一次发放时被清掉：验过却没上传的会话不会有人来删它们。
	g.grant("sess:a", t0)
	g.grant("sess:c", t0.Add(time.Hour))
	if n := len(g.until); n != 1 {
		t.Fatalf("过期条目没被清掉，表里还有 %d 条：%v", n, g.until)
	}
}

// TestSelfUpdateAuthEndpoint 验证接口本身：密码对才发授权，按会话发，失败与成功都留痕。
func TestSelfUpdateAuthEndpoint(t *testing.T) {
	s := newUpdateGateServer(t, nil)
	const tokA, tokB = "token-update-auth-a", "token-update-auth-b"
	ttl := int64(updateAuthTTL / time.Second)

	// 密码不对：403 而不是 401（401 会被前端拦截器当成会话失效、把人踢回登录页），不发授权。
	rec := postUpdateAuth(t, s, tokA, updateTestUser, "wrong-pass")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("密码不对应当 403，实际 %d：%s", rec.Code, rec.Body.String())
	}
	if hasUpdateGrant(t, s, tokA) {
		t.Fatal("密码不对却发了授权")
	}
	mustLogEntry(t, s.deps.Log, "上传前的密码验证失败", "WARN")

	// 请求体都不是 JSON：400，同样不发。
	rec = callWithSession(t, s.handleSelfUpdateAuth, "/api/meta/self-update/auth", "application/json", "不是 JSON", tokA)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("坏请求体应当 400，实际 %d：%s", rec.Code, rec.Body.String())
	}

	// 密码对：200，回的剩余秒数就是一整段有效期（留几秒余量给这次调用本身）。
	rec = postUpdateAuth(t, s, tokA, updateTestUser, updateTestPass)
	if rec.Code != http.StatusOK {
		t.Fatalf("密码正确应当 200，实际 %d：%s", rec.Code, rec.Body.String())
	}
	if got := jsonNum(t, jsonData(t, rec.Body.Bytes()), "expiresIn"); got < ttl-5 || got > ttl {
		t.Fatalf("授权有效期是 %d 秒，期望约 %d", got, ttl)
	}
	if !hasUpdateGrant(t, s, tokA) {
		t.Fatal("验证通过却没有发授权")
	}
	mustLogEntry(t, s.deps.Log, "已发放一次性授权", "INFO")

	// 按会话发：同一个账户的另一条会话不沾光。
	if hasUpdateGrant(t, s, tokB) {
		t.Fatal("另一条会话也拿到了授权")
	}
}

// TestSelfUpdateUnsignedGrantIsOneShot 未验签的上传认这份授权，但只认一次：
// 第二次上传哪怕紧跟着第一次、哪怕第一次失败了，也得重新验密码。
func TestSelfUpdateUnsignedGrantIsOneShot(t *testing.T) {
	skipOnWindows(t)
	s := newUpdateGateServer(t, func(u *config.UpdateConfig) {
		u.AllowUnsignedUpdate = true
		u.AllowUnsignedSince = freshWindowStart()
	})
	const tokA, tokB = "token-update-grant-a", "token-update-grant-b"
	upload := func(token string) *httptest.ResponseRecorder {
		t.Helper()
		return sendWithSession(t, s.handleSelfUpdate, newUpdateUploadRequest(t, "不是真的更新包"), token)
	}
	authOK := func(token string) {
		t.Helper()
		if rec := postUpdateAuth(t, s, token, updateTestUser, updateTestPass); rec.Code != http.StatusOK {
			t.Fatalf("验证密码失败（%d）：%s", rec.Code, rec.Body.String())
		}
	}

	authOK(tokA)
	// 有授权、不带凭据：放行到解包那一步（假内容必然解不开，那是别的测试的事）。
	if rec := upload(tokA); rec.Code == http.StatusForbidden || !strings.Contains(rec.Body.String(), "更新包解析失败") {
		t.Fatalf("凭授权的上传应当走到解包那一步，实际 %d：%s", rec.Code, rec.Body.String())
	}
	// 日志要分得清这次是凭授权放行的，而不是当场验的密码。
	if v, _ := logFieldStr(mustLogEntry(t, s.deps.Log, "收到自更新请求", "INFO"), "auth"); v != "grant" {
		t.Fatalf("凭授权放行的上传，日志里 auth 是 %q，期望 grant", v)
	}

	// 同一条会话紧接着再传一次：授权已经被上一次用掉了（那一次失败了也一样）。
	if rec := upload(tokA); rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "授权已失效") {
		t.Fatalf("用过的授权不该再放行，实际 %d：%s", rec.Code, rec.Body.String())
	}

	// 另一条会话：没验过就是没验过。
	if rec := upload(tokB); rec.Code != http.StatusForbidden {
		t.Fatalf("没验过密码的会话应当被拒，实际 %d：%s", rec.Code, rec.Body.String())
	}

	// 凭授权的上传这一次不验密码，也就不该被复核失败计数拦：先验对拿到授权，再在这条会话上
	// 故意错满一轮，上传照样走到解包。闸要是挪到 needPassword 外面，这里会变成 429。
	authOK(tokA)
	for i := 0; i < reauthMaxFails; i++ {
		postUpdateAuth(t, s, tokA, "不是这台面板的账户", "随便")
	}
	if rec := upload(tokA); rec.Code == http.StatusTooManyRequests || !strings.Contains(rec.Body.String(), "更新包解析失败") {
		t.Fatalf("凭授权的上传被复核计数拦下了，实际 %d：%s", rec.Code, rec.Body.String())
	}

	// 过期：换一条刚验过、没被锁的会话（tokA 已经锁了，那里只会拿到 429），
	// 再直接把截止时刻拨到过去，不真等。
	const tokC = "token-update-grant-c"
	authOK(tokC)
	s.updateAuth.mu.Lock()
	for k := range s.updateAuth.until {
		s.updateAuth.until[k] = time.Now().Add(-time.Second)
	}
	s.updateAuth.mu.Unlock()
	if rec := upload(tokC); rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "授权已失效") {
		t.Fatalf("过期的授权应当 403 并提示重新验证，实际 %d：%s", rec.Code, rec.Body.String())
	}
}

// TestSelfUpdateGrantUseAndKeep 什么时候用掉授权、什么时候留着。
//
// 用掉：真正开始处理的上传，包括配了公钥、根本不需要它的那条路——留着它只是等别的请求来用。
// 留着：在取授权之前就被拒的上传（不收包、或已有一个包正在处理）。那几种拒绝与授权无关，
// 白白用掉的话，用户等前一个包处理完再传，又得输一遍密码。
func TestSelfUpdateGrantUseAndKeep(t *testing.T) {
	skipOnWindows(t)
	const tok = "token-update-grant-keep"
	upload := func(s *Server) *httptest.ResponseRecorder {
		t.Helper()
		return sendWithSession(t, s.handleSelfUpdate, newUpdateUploadRequest(t, "不是真的更新包"), tok)
	}
	authOK := func(s *Server) {
		t.Helper()
		if rec := postUpdateAuth(t, s, tok, updateTestUser, updateTestPass); rec.Code != http.StatusOK {
			t.Fatalf("验证密码失败（%d）：%s", rec.Code, rec.Body.String())
		}
	}

	t.Run("不收包时留着", func(t *testing.T) {
		s := newUpdateGateServer(t, nil) // 默认：没配公钥、开关关着
		authOK(s)
		if rec := upload(s); rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "签名公钥") {
			t.Fatalf("默认配置应当拒收，实际 %d：%s", rec.Code, rec.Body.String())
		}
		if !hasUpdateGrant(t, s, tok) {
			t.Fatal("不收包的拒绝把授权用掉了")
		}
	})

	t.Run("正在处理别的包时留着", func(t *testing.T) {
		s := newUpdateGateServer(t, func(u *config.UpdateConfig) {
			u.AllowUnsignedUpdate = true
			u.AllowUnsignedSince = freshWindowStart()
		})
		authOK(s)
		s.selfUpdateMu.Lock()
		rec := upload(s)
		s.selfUpdateMu.Unlock()
		if rec.Code != http.StatusConflict {
			t.Fatalf("已有一个包在处理时应当 409，实际 %d：%s", rec.Code, rec.Body.String())
		}
		if !hasUpdateGrant(t, s, tok) {
			t.Fatal("409 的拒绝把授权用掉了")
		}
		// 前一个处理完再传：凭的还是这份授权。
		if rec := upload(s); !strings.Contains(rec.Body.String(), "更新包解析失败") {
			t.Fatalf("留着的授权应当还能用，实际 %d：%s", rec.Code, rec.Body.String())
		}
	})

	t.Run("配了公钥的上传也用掉", func(t *testing.T) {
		s := newUpdateGateServer(t, func(u *config.UpdateConfig) { u.SignKey = "dGVzdA==" })
		authOK(s)
		if rec := upload(s); !strings.Contains(rec.Body.String(), "更新包解析失败") {
			t.Fatalf("配了公钥的上传应当走到解包那一步，实际 %d：%s", rec.Code, rec.Body.String())
		}
		if hasUpdateGrant(t, s, tok) {
			t.Fatal("配了公钥的上传没有用掉手上的授权，它会留着等别的请求来用")
		}
	})
}
