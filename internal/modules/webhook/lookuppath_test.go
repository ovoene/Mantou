package webhook

import (
	"net/http"
	"net/url"
	"testing"

	"mantou/internal/config"
)

// lookupPath 折出来的键必须与配置里那一套写法完全对齐（见 config.NormalizeWebhookPath）。
//
// 用 url.Parse 造入参而不是直接填 url.URL{Path: …}：百分号编码是在这一步被还原的，
// 手填 Path 就把"编码过的写法也要命中"这半个用例跳过去了。
func TestLookupPathCanonicalizes(t *testing.T) {
	cases := []struct{ raw, want string }{
		{"http://h/hook", "hook"},
		{"http://h/hook/", "hook"},
		{"http://h//hook//", "hook"},
		{"http://h/a/b", "a/b"},
		// 多余的斜杠：粘贴地址时最常带出来的一种。
		{"http://h/a//b", "a/b"},
		{"http://h/a///b/", "a/b"},
		// 点段：有些客户端会把 base 与相对路径拼起来直接发出去。
		{"http://h/./a/b", "a/b"},
		{"http://h/x/../a/b", "a/b"},
		// 往上跳出根也只能落在根上（path.Clean 的行为，这里靠前导 / 拿到它）。
		{"http://h/a/../../../b", "b"},
		// 编码过的斜杠：net/url 还原成普通斜杠后一起折叠。
		{"http://h/a/%2F/b", "a/b"},
		{"http://h/a%2Fb", "a/b"},
		// 空路径与纯斜杠都折成空串。配置侧保证接收器路径非空（见 RandomWebhookPath），
		// 所以空串一定命中不了任何接收器 —— 仍然是 404。
		{"http://h/", ""},
		{"http://h", ""},
	}
	for _, c := range cases {
		u, err := url.Parse(c.raw)
		if err != nil {
			t.Fatalf("%s 解析失败：%v", c.raw, err)
		}
		if got := lookupPath(u); got != c.want {
			t.Errorf("%s → %q，期望 %q", c.raw, got, c.want)
		}
	}
	if got := lookupPath(nil); got != "" {
		t.Errorf("nil URL → %q，期望空串", got)
	}
}

// 折出来的键还必须与配置侧同一个输入的规范化结果一致——两边各写一套规则的话，
// 迟早出现"面板上存的是这个、请求侧折出来的是那个"。
func TestLookupPathAgreesWithConfigNormalization(t *testing.T) {
	for _, raw := range []string{"hook", "a/b", "a//b", " a / b ", "/a/b/"} {
		key := config.NormalizeWebhookPath(raw)
		if key == "" {
			t.Fatalf("%q 规范化成了空串，用例本身有问题", raw)
		}
		u, err := url.Parse("http://h/" + key)
		if err != nil {
			t.Fatal(err)
		}
		if got := lookupPath(u); got != key {
			t.Errorf("配置侧折成 %q，请求 /%s 折成 %q", key, key, got)
		}
	}
}

// 端到端：几种"地址其实是对的"的写法都要命中同一个接收器。
//
// 修复前它们全是 404，而面板上只有一条"入站路径不存在"——第三方系统那头看到的是
// 推送失败，两边都看不出问题在多打了一个斜杠上。
func TestServeMatchesNoncanonicalRequestPaths(t *testing.T) {
	cfg := hookCfg(config.WebhookReceiver{
		ID: "r1", Name: "第三方系统", Enabled: true, Path: "a/b",
		DefaultTargets: []string{"g1"},
	})
	for _, target := range []string{"/a/b", "/a/b/", "/a//b", "/./a/b", "/x/../a/b", "/a%2Fb"} {
		h := newHarness(t, cfg)
		code, body := h.post(t, target, `{"msg":"hi"}`)
		if code != http.StatusOK {
			t.Fatalf("POST %s 得到 %d：%s", target, code, body)
		}
		h.okBody(t, body)
		if got := h.m.received.Load(); got != 1 {
			t.Fatalf("POST %s 后接收数是 %d，期望 1", target, got)
		}
	}
}

// 规范化不是放宽匹配：折完之后仍要与某个接收器**完全相等**才算命中。
// 路径本身是一层凭证（很多第三方系统只能配一个 URL），这条边界不能松。
func TestServeStillRejectsWrongPaths(t *testing.T) {
	cfg := hookCfg(config.WebhookReceiver{
		ID: "r1", Name: "第三方系统", Enabled: true, Path: "a/b",
		DefaultTargets: []string{"g1"},
	})
	h := newHarness(t, cfg)
	for _, target := range []string{"/a", "/a/b/c", "/a/bb", "/b/a", "/", "/a/b/.."} {
		code, _ := h.post(t, target, `{"msg":"hi"}`)
		if code != http.StatusNotFound {
			t.Fatalf("POST %s 得到 %d，期望 404", target, code)
		}
	}
	if got := h.m.received.Load(); got != 0 {
		t.Fatalf("接收数是 %d，期望 0", got)
	}
}
