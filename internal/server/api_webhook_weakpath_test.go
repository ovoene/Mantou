package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	"mantou/internal/config"
)

// 本文件盯确认项 A2：「不校验 + 短路径」这个组合给一条黄色提示，**但不阻止保存**。
//
// 提示本身画在界面上（ReceiverDialog.vue），Go 侧只负责两件事，也正是这里要钉的两件：
//
//  1. 门槛这个数由后端下发。前端另抄一份的结果是常量改了界面没跟着改，
//     于是"多长算短"两边说法不一样。
//  2. 短路径 + 不校验**能存下去**。这条最容易被后来的人"顺手修好"——
//     看到一条安全提示，很自然会想在 validateReceiver 里补一刀拦住它。
//     但改自定义路径往往是对方系统的硬性要求，拦下来等于让人无路可走。

// 门槛与上限都必须就是校验/生成用的那两个常量。
func TestWebhookMetaExposesPathLimits(t *testing.T) {
	_, router := newWebhookAPITest(t)

	w := performJSONRequest(router, http.MethodGet, "/webhook/meta", "")
	if w.Code != http.StatusOK {
		t.Fatalf("元数据接口应成功，实际 %d：%s", w.Code, w.Body.String())
	}
	var resp struct {
		Data struct {
			Limits map[string]int `json:"limits"`
		} `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	for k, want := range map[string]int{
		"pathLen":     config.MaxWebhookPathLen,
		"weakPathLen": config.WeakWebhookPathLen,
	} {
		got, ok := resp.Data.Limits[k]
		if !ok {
			t.Fatalf("元数据里缺少 limits.%s（响应：%s）", k, w.Body.String())
		}
		if got != want {
			t.Fatalf("limits.%s 与常量不一致：%d vs %d", k, got, want)
		}
	}
}

// 随机生成的默认路径必须够长，否则每新建一个接收器都会立刻弹一条提示说自己不安全。
//
// 这不是给人看的算术，是给改常量的人留的一道门：把门槛调到 32 以上，
// 或者把随机路径改短，都会在这里停下来。
func TestRandomPathIsNotWeak(t *testing.T) {
	if config.WebhookPathLen < config.WeakWebhookPathLen {
		t.Fatalf("随机路径 %d 字符短于「算短」的门槛 %d，新建的接收器会立刻提示自己不安全",
			config.WebhookPathLen, config.WeakWebhookPathLen)
	}
	// 生成的路径也得真有那么长——常量对不代表实现跟着它。
	if got := len(config.RandomWebhookPath()); got < config.WeakWebhookPathLen {
		t.Fatalf("实际生成的路径只有 %d 字符，短于门槛 %d", got, config.WeakWebhookPathLen)
	}
}

// 短路径 + 不校验能存下去：这是"只提示、不拦"的另一半。
//
// 顺带把两个相邻情形也带上，防止有人用"路径长度"或"鉴权方式"任一单条件去拦：
// 短路径配了令牌、长路径不校验，这两种都不该有任何变化。
func TestWeakPathStillSaves(t *testing.T) {
	for _, tc := range []struct {
		name, path, authType, token string
	}{
		{name: "短路径且不校验（正是提示针对的组合）", path: "hook", authType: "none"},
		{name: "短到只有一个字符", path: "a", authType: "none"},
		{name: "短路径但配了令牌", path: "hook2", authType: "token", token: "s3cret"},
		{name: "长路径不校验", path: "0123456789abcdef0123456789abcdef", authType: "none"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			manager, router := newWebhookAPITest(t)
			body := fmt.Sprintf(`{"name":"来源A","enabled":true,"path":%q,"authType":%q,"token":%q}`,
				tc.path, tc.authType, tc.token)
			w := performJSONRequest(router, http.MethodPost, "/webhook/receivers", body)
			if w.Code != http.StatusOK {
				t.Fatalf("这条应当能保存（提示归界面，后端不拦），实际 %d：%s", w.Code, w.Body.String())
			}
			recvs := manager.Get().WebhookReceivers
			if len(recvs) != 1 {
				t.Fatalf("应当存下 1 个接收器，实际 %d", len(recvs))
			}
			// 路径必须原样存下：这里若被"顺手规范化"成随机路径，第三方系统那侧就失联了。
			if recvs[0].Path != tc.path {
				t.Fatalf("路径被改动了：%q → %q", tc.path, recvs[0].Path)
			}
		})
	}
}
