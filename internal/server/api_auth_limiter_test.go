package server

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

// handleLogin 过两道限流：ipKey（"ip:"+来源）与 userKey（"ip:"+来源+":user:"+账户名）。
//
// 第二道很容易被当成多余的删掉——它含 IP，所以判定严格弱于 ipKey，永远不会先于 ipKey
// 触发。但它确实多挡一件事，而且只有这一件：**一次成功登录不会清掉其它账户名的失败史**。
// 成功时清的是 ipKey 与「登录成功的那个账户名」的键；同一 IP 上冲着别的账户名累积的
// 失败计数留在原地。在与管理员共用出口 IP 的场景（NAT、同一局域网）里，这条让攻击者
// 没法靠管理员的正常登录把自己的计数反复清零。
//
// 这两条测试就是把那件事钉住，同时钉住它刻意**不做**的那件事（跨 IP 的账户锁定），
// 免得往后有人朝任一方向"顺手改对"：删掉它会丢掉上面那层，把 IP 从键里去掉则会造出
// 一条谁都能打的锁门 DoS——从任意几个地址故意失败几次，真正的管理员就再也登不进来。

// postLogin 以指定来源 IP 发一次登录请求。
func postLogin(t *testing.T, s *Server, ip, user, pass string) *httptest.ResponseRecorder {
	t.Helper()
	body := fmt.Sprintf(`{"username":%q,"password":%q}`, user, pass)
	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	ctx.Request = httptest.NewRequest(http.MethodPost, "http://panel.example.com/auth/login",
		strings.NewReader(body))
	ctx.Request.Header.Set("Content-Type", "application/json")
	// 只给 RemoteAddr，不带任何转发头：ClientIP 会直接取它。
	ctx.Request.RemoteAddr = ip + ":54321"
	s.handleLogin(ctx)
	return w
}

// newLockingAuthServer 造一个真会锁定的测试面板：3 次失败即锁 1 分钟。
//
// newAuthTestServer 给的限流器是关掉的（maxFails≤0），那对本文件毫无用处——
// 关掉时 Allowed 直接返回 true，两个键都测不出来。
func newLockingAuthServer(t *testing.T) *Server {
	t.Helper()
	s := newAuthTestServer(t)
	s.limiter = newLoginLimiter(3, time.Minute, time.Minute)
	return s
}

// TestLoginAccountKeySurvivesSuccessFromSameIP 成功登录清掉的是 ipKey 与「那个账户名」，
// 同一 IP 上冲着别的账户名的失败计数不会跟着清零。
//
// 这是 userKey 唯一比 ipKey 多挡的那件事，也是它存在的全部理由。断言分两半：
// 被爆破的那个账户名要被锁（429），同一 IP 上换个账户名却仍能尝试（401）——
// 后半句证明这次拦截确实来自 userKey 而不是 ipKey，否则整条测试就成了假通过。
func TestLoginAccountKeySurvivesSuccessFromSameIP(t *testing.T) {
	const ip = "203.0.113.7"
	s := newLockingAuthServer(t)

	// 冲着一个不存在的账户名失败两次（离 3 次上限还差一次）。
	for i := 0; i < 2; i++ {
		if w := postLogin(t, s, ip, "ghost", "wrong"); w.Code != http.StatusUnauthorized {
			t.Fatalf("第 %d 次失败登录应是 401，实际 %d：%s", i+1, w.Code, w.Body.String())
		}
	}

	// 管理员从同一个出口 IP 正常登录成功：这会清掉 ipKey。
	if w := postLogin(t, s, ip, testLoginUser, testLoginPass); w.Code != http.StatusOK {
		t.Fatalf("管理员登录应成功，实际 %d：%s", w.Code, w.Body.String())
	}

	// 第三次失败：ipKey 已被清零、还差得远，但 ghost 那个键累到了上限。
	if w := postLogin(t, s, ip, "ghost", "wrong"); w.Code != http.StatusUnauthorized {
		t.Fatalf("第 3 次失败登录本身应是 401，实际 %d：%s", w.Code, w.Body.String())
	}
	w := postLogin(t, s, ip, "ghost", "wrong")
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("该账户名已达失败上限，应被锁定（429），实际 %d：%s\n"+
			"——成功登录不该把它的失败史一并清掉，否则共用出口 IP 时爆破可被无限续命",
			w.Code, w.Body.String())
	}
	if got := w.Header().Get("Retry-After"); got == "" {
		t.Error("429 应带 Retry-After，否则客户端不知道该等多久")
	}

	// 同一 IP 换个账户名仍可尝试：证明上面那一下是 userKey 拦的，不是 ipKey。
	if w := postLogin(t, s, ip, "someone-else", "wrong"); w.Code != http.StatusUnauthorized {
		t.Fatalf("同一 IP 换账户名时 ipKey 尚未触发，应是 401，实际 %d：%s", w.Code, w.Body.String())
	}
}

// TestLoginAccountLockNeverCrossesIP 账户锁定绝不跨 IP。
//
// 这是 userKey 把 IP 写进键里的原因，也是它刻意放弃的能力：若按纯账户名限流，任何人
// 从任意地址对着管理员账户失败几次，就能把真正的管理员锁在门外——而这台面板往往正是
// 他恢复访问的唯一入口。宁可少拦一点。
//
// 用**真实的管理员账户名**来测，因为它才是那条 DoS 会瞄准的目标：先在一个地址上把它
// 打到锁定，再从另一个地址用正确密码登录，必须照样进得去。
func TestLoginAccountLockNeverCrossesIP(t *testing.T) {
	s := newLockingAuthServer(t)

	const attacker = "198.51.100.9"
	for i := 0; i < 3; i++ {
		if w := postLogin(t, s, attacker, testLoginUser, "wrong"); w.Code != http.StatusUnauthorized {
			t.Fatalf("第 %d 次失败登录应是 401，实际 %d", i+1, w.Code)
		}
	}
	// 攻击者自己这一侧确实被锁了（两个键都到上限，谁先触发无所谓）。
	if w := postLogin(t, s, attacker, testLoginUser, "wrong"); w.Code != http.StatusTooManyRequests {
		t.Fatalf("失败达上限的来源应被锁定，实际 %d：%s", w.Code, w.Body.String())
	}
	// 管理员从别的地址用正确密码登录，必须不受影响。
	if w := postLogin(t, s, "203.0.113.20", testLoginUser, testLoginPass); w.Code != http.StatusOK {
		t.Fatalf("账户锁定不该跨 IP，管理员应能从别处登录，实际 %d：%s\n"+
			"——键里含 IP 正是为了这个：否则任何人都能靠故意失败把管理员锁在门外",
			w.Code, w.Body.String())
	}
}
