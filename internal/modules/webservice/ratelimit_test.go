package webservice

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"mantou/internal/config"
	"mantou/internal/logx"
)

// 每 IP 限流的桶表是模块级的一张，全部子项共用（见 Module.rateLimiter 与 ipx.IPLimiter）。
// 站点子项的个数没有任何上限，原来每个子项各建一张 8192 桶的表，
// "最多 0.9 MB"那句保护就被子项个数乘掉了。
//
// 合成一张表之后要钉住两件事：额度仍然按子项各算各的，以及表不跟着 Reload 重建。

// limitedChild 一个每秒只放行一次的子项。
func limitedChild(id string) config.WebChild {
	ch := config.WebChild{ID: id, Enabled: true, Type: "redirect"}
	ch.Access.RateLimit = 1
	return ch
}

// hitOnce 走一次 withRateLimit 包出来的处理器，返回状态码。
func hitOnce(h http.Handler) int {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "203.0.113.9:40000"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w.Code
}

// passthrough 一个只回 200 的下游，用来看限流放不放行。
func passthrough() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
}

// TestRateLimitCountsPerChild 共用的是表的容量，不是令牌。
//
// 桶键漏掉子项 ID 的话，用户在界面上按子项配的那个"每秒几次"就变成了
// 所有子项合起来的总额度——A 站被刷会连带把 B 站堵死。
func TestRateLimitCountsPerChild(t *testing.T) {
	m := New(logx.New(logx.Options{}))
	t.Cleanup(func() { _ = m.Close() })

	a := withRateLimit(m, limitedChild("ch1"), passthrough())
	b := withRateLimit(m, limitedChild("ch2"), passthrough())

	if code := hitOnce(a); code != http.StatusOK {
		t.Fatalf("子项 A 的首次应放行，实际 %d", code)
	}
	if code := hitOnce(a); code != http.StatusTooManyRequests {
		t.Fatalf("测试前提不成立：子项 A 的额度应已用完，实际 %d", code)
	}
	if code := hitOnce(b); code != http.StatusOK {
		t.Fatalf("子项 B 有自己的额度，实际 %d", code)
	}
}

// TestRateLimitSurvivesRebuild 处理器重建不重置令牌。
//
// 桶表原来挂在处理器上、跟着 Reload 一起重建，于是"保存一次配置"等于把所有来源的
// 令牌重新加满：正在被限流的一方只要等用户按一次保存就能重新开跑。
func TestRateLimitSurvivesRebuild(t *testing.T) {
	m := New(logx.New(logx.Options{}))
	t.Cleanup(func() { _ = m.Close() })

	if code := hitOnce(withRateLimit(m, limitedChild("ch1"), passthrough())); code != http.StatusOK {
		t.Fatalf("首次应放行，实际 %d", code)
	}
	// 重新包一次，相当于 Reload 之后新起的那套处理器。
	if code := hitOnce(withRateLimit(m, limitedChild("ch1"), passthrough())); code != http.StatusTooManyRequests {
		t.Fatalf("重建处理器把令牌重新加满了，实际 %d", code)
	}
}

// TestRateLimitOffIsPassthrough 没配限流的子项不该被包一层。
// 包了也能跑，但每个请求都要多走一次 map 查找与一把锁。
func TestRateLimitOffIsPassthrough(t *testing.T) {
	m := New(logx.New(logx.Options{}))
	t.Cleanup(func() { _ = m.Close() })

	for _, rl := range []int{0, -1} {
		ch := config.WebChild{ID: "ch1", Enabled: true}
		ch.Access.RateLimit = rl
		h := withRateLimit(m, ch, passthrough())
		for i := 0; i < 5; i++ {
			if code := hitOnce(h); code != http.StatusOK {
				t.Fatalf("RateLimit=%d 应不限流，第 %d 次被拒（%d）", rl, i+1, code)
			}
		}
		if m.rateLimiter.Len() != 0 {
			t.Fatalf("RateLimit=%d 不该建任何桶，实际 %d 个", rl, m.rateLimiter.Len())
		}
	}
}
