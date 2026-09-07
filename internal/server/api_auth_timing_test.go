package server

import (
	"net/http"
	"testing"
	"time"
)

// 登录不得因「用户名不存在」而短路掉 bcrypt（审计 S-02）。
//
// 短路版本（`名字对得上 && VerifyPassword(...)`）把"这个用户名存不存在"直接写进了响应耗时：
// 整机实测里错误用户名 1.24 ms 中位、错误密码 95.4 ms 中位，77 倍且区间零重叠，
// 单个请求就能 100% 判定。登录限流拦不住这件事——它限的是次数，不是每次泄露的信息量。
//
// 这条测试拿两条路各自的**最小值**比：取最小而不是平均，是因为噪声只会把耗时往上推，
// 最小值最接近"这条路真正做了多少活"。两条路都跑一遍 bcrypt 时比值应当接近 1；
// 一旦有人把判定改回短路形状，错误用户名那条会掉到毫秒级，比值随之塌到 0.02 上下。
// 阈值定在 1/4 是为了给慢机器、被抢占的 CI 留足余量，同时仍与回归后的量级差两个数量级。
func TestLoginDoesNotShortCircuitOnUnknownUser(t *testing.T) {
	const (
		samples = 5
		ip      = "203.0.113.11"
	)
	s := newAuthTestServer(t) // 限流器关闭，可以连续打多次

	// 先把行为本身钉住：用户名不对时，即使密码是对的也必须 401。
	// 这条与耗时无关，是"照样跑一遍 bcrypt"不能顺带放宽的那件事。
	if w := postLogin(t, s, ip, testLoginUser+"x", testLoginPass); w.Code != http.StatusUnauthorized {
		t.Fatalf("用户名不匹配时即使密码正确也应 401，实际 %d：%s", w.Code, w.Body.String())
	}

	measure := func(user, pass string) time.Duration {
		best := time.Duration(1) << 62
		for i := 0; i < samples; i++ {
			start := time.Now()
			w := postLogin(t, s, ip, user, pass)
			elapsed := time.Since(start)
			if w.Code != http.StatusUnauthorized {
				t.Fatalf("这一次登录应当失败（401），实际 %d：%s", w.Code, w.Body.String())
			}
			if elapsed < best {
				best = elapsed
			}
		}
		return best
	}

	// 顺序刻意错开：先量"用户名不存在"，再量"密码错"。若两者共享某种一次性预热成本，
	// 这个顺序会让被测那条路吃到预热，也就不会靠预热制造出假通过。
	unknownUser := measure("no-such-user", "whatever-wrong")
	wrongPass := measure(testLoginUser, "definitely-wrong")

	// bcrypt 的代价参数是 DefaultCost（见 auth.HashPassword），任何真机上都是几十毫秒量级。
	// 若这里低到毫秒以下，说明这台机器上的前提已经不成立，比值不再有意义——跳过而不是误报。
	if wrongPass < 5*time.Millisecond {
		t.Skipf("密码校验只用了 %v，本机上无法用耗时区分两条路，跳过", wrongPass)
	}
	if unknownUser*4 < wrongPass {
		t.Fatalf("用户名不存在时明显更快（%v vs %v，%.3f 倍），bcrypt 被短路了："+
			"单个请求即可判定用户名是否存在", unknownUser, wrongPass,
			float64(unknownUser)/float64(wrongPass))
	}
}
