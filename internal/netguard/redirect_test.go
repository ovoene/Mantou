package netguard

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// 跨主机重定向必须摘掉调用方设的请求头（审计 S-04）。
//
// 这一组是真起两个 httptest 服务端跑完整跳转，而不是直接调 CheckRedirect：
// 要钉住的恰恰是"标准库把头抄过去"这个行为，只有让 http.Client 真的走一遍
// 才能证明钩子插在了对的位置上。两台服务端的主机名一个是 127.0.0.1
// 一个是 localhost，因此对 Client 来说确实是"换了主机"。

// hopHeaders 是第二跳实际收到的请求头。
func redirectHop(t *testing.T, firstHost, secondHost string, hdr map[string]string) http.Header {
	t.Helper()

	got := make(chan http.Header, 1)
	second := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got <- r.Header.Clone()
		w.WriteHeader(http.StatusNoContent)
	}))
	defer second.Close()

	secondURL := swapHost(t, second.URL, secondHost)
	first := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, secondURL, http.StatusFound)
	}))
	defer first.Close()

	req, err := http.NewRequest(http.MethodGet, swapHost(t, first.URL, firstHost), nil)
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := HTTPClient(false, 5*time.Second).Do(req)
	if err != nil {
		t.Fatalf("请求失败：%v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("没走到第二跳，状态码 %d", resp.StatusCode)
	}
	select {
	case h := <-got:
		return h
	case <-time.After(5 * time.Second):
		t.Fatal("第二跳没被访问到")
		return nil
	}
}

// swapHost 把 httptest 给的 127.0.0.1:port 换成指定主机名，端口保留。
func swapHost(t *testing.T, raw, host string) string {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	u.Host = host + ":" + u.Port()
	return u.String()
}

func TestCheckRedirectDropsCustomHeadersAcrossHosts(t *testing.T) {
	h := redirectHop(t, "127.0.0.1", "localhost", map[string]string{
		"Authorization": "Bearer 不该跟过去",
		"X-Api-Key":     "同样不该跟过去", // 标准库自己不管这一类，正是 S-04 的实质
		"X-Auth-Token":  "也不该跟过去",
		"Accept":        "application/json",
		"User-Agent":    "mantou-test",
	})
	for _, name := range []string{"Authorization", "X-Api-Key", "X-Auth-Token"} {
		if v := h.Get(name); v != "" {
			t.Errorf("跨主机跳转后 %s 仍被送出：%q", name, v)
		}
	}
	if got := h.Get("Accept"); got != "application/json" {
		t.Errorf("Accept 属于白名单，应保留，实际 %q", got)
	}
	if got := h.Get("User-Agent"); got != "mantou-test" {
		t.Errorf("User-Agent 属于白名单，应保留，实际 %q", got)
	}
}

// 同主机跳转不能摘头：否则「HTTP 301 到同一台机器的另一个路径」这种最常见的
// 跳转会让凭证凭空消失，功能直接坏掉。这条是上面那条的反向保护。
func TestCheckRedirectKeepsHeadersOnSameHost(t *testing.T) {
	h := redirectHop(t, "127.0.0.1", "127.0.0.1", map[string]string{
		"X-Api-Key": "同主机应保留",
	})
	if got := h.Get("X-Api-Key"); got != "同主机应保留" {
		t.Errorf("同主机跳转不该摘头，实际 %q", got)
	}
}

// keepsHeadersAcross 的判据表：主机名相同**且**没从 https 掉到 http 才留头。
func TestKeepsHeadersAcross(t *testing.T) {
	cases := []struct {
		from, to string
		keep     bool
	}{
		{"https://h.example.com/a", "https://h.example.com/b", true},
		{"http://h.example.com/a", "http://h.example.com/b", true},
		{"http://h.example.com/a", "https://h.example.com/b", true},     // 升级到 https 没问题
		{"https://h.example.com/a", "https://h.example.com:8443", true}, // 换端口仍是同一家
		{"https://H.Example.com/a", "https://h.example.com/b", true},    // 主机名大小写不算区别
		{"https://h.example.com/a", "http://h.example.com/b", false},    // 降级：头会明文过线
		{"https://h.example.com/a", "https://evil.example.com/b", false},
		{"https://h.example.com/a", "https://h.example.com.evil.net/b", false}, // 后缀骗不过全等比较
	}
	for _, c := range cases {
		from, to := mustURL(t, c.from), mustURL(t, c.to)
		if got := keepsHeadersAcross(from, to); got != c.keep {
			t.Errorf("%s → %s 得到 keep=%v，期望 %v", c.from, c.to, got, c.keep)
		}
	}
	if keepsHeadersAcross(nil, mustURL(t, "https://h.example.com/")) {
		t.Error("认不出来源时应按换了地方处理")
	}
}

func mustURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

// 跳数上限必须自己兜住：设了 CheckRedirect 就等于换掉了标准库那道默认的 10 跳，
// 少了它，一条自指的 302 会让请求转到超时为止。
func TestCheckRedirectCapsHopCount(t *testing.T) {
	hits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		http.Redirect(w, r, "/next", http.StatusFound)
	}))
	defer srv.Close()

	_, err := HTTPClient(false, 5*time.Second).Get(srv.URL)
	if err == nil {
		t.Fatal("无限自指跳转应当报错")
	}
	if !strings.Contains(err.Error(), "重定向次数过多") {
		t.Fatalf("错误里应说明是跳数超限，实际：%v", err)
	}
	if hits > maxRedirects+1 {
		t.Fatalf("实际请求了 %d 次，超过上限 %d 跳", hits, maxRedirects)
	}
}
