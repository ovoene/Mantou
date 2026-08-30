package server

import (
	"fmt"
	"net/http"
	"strings"
	"testing"

	"mantou/internal/config"
)

// 本文件盯的是通知目标那侧的脱敏还原（2.14-A）。
//
// 这套脱敏机制靠一个哨兵值撑着（maskedSecret，字面量 "******"）：列表接口把凭证换成它，
// 前端原样回传表示"这个字段我没动"，保存时再按 ID 还原。地址与加签密钥按 ID 取旧值，稳；
// 请求头多了一层**键名**，而键名恰恰是用户会改的东西，于是那一格会漏。

// createTarget 建一个带请求头的自定义 HTTP 目标，返回它的 ID。
func createTarget(t *testing.T, manager *config.Manager, router http.Handler, headers string) string {
	t.Helper()
	body := fmt.Sprintf(`{"name":"自建接口","enabled":true,"type":"http",`+
		`"url":"https://example.com/in","headers":%s}`, headers)
	w := performJSONRequest(router, http.MethodPost, "/webhook/targets", body)
	if w.Code != http.StatusOK {
		t.Fatalf("新建通知目标应成功，实际 %d：%s", w.Code, w.Body.String())
	}
	list := manager.Get().NotifyTargets
	return list[len(list)-1].ID
}

// 用户没动请求头，原样把占位符提交回来 → 必须还原成原值。
// 这是这套机制的正常路径，先把它钉住，后面几条才说明得清"哪一格漏了"。
func TestTargetMaskedHeaderRestoredWhenKeyUnchanged(t *testing.T) {
	manager, router := newWebhookAPITest(t)
	const secret = "Bearer 真实令牌"
	id := createTarget(t, manager, router, fmt.Sprintf(`{"Authorization":%q}`, secret))

	// 列表里不该出现真值。
	list := performJSONRequest(router, http.MethodGet, "/webhook/targets", "")
	if strings.Contains(list.Body.String(), secret) {
		t.Fatalf("列表接口泄露了请求头的值：%s", list.Body.String())
	}

	back := fmt.Sprintf(`{"id":%q,"name":"自建接口改名","enabled":true,"type":"http",`+
		`"url":%q,"headers":{"Authorization":%q}}`, id, maskedSecret, maskedSecret)
	if w := performJSONRequest(router, http.MethodPut, "/webhook/targets/"+id, back); w.Code != http.StatusOK {
		t.Fatalf("回传占位符应成功，实际 %d：%s", w.Code, w.Body.String())
	}
	got := manager.Get().NotifyTargets
	tg := got[len(got)-1]
	if tg.Headers["Authorization"] != secret {
		t.Fatalf("回传占位符不该改动请求头的值，实际 %q", tg.Headers["Authorization"])
	}
	if tg.URL != "https://example.com/in" {
		t.Fatalf("回传占位符不该改动地址，实际 %q", tg.URL)
	}
	if tg.Name != "自建接口改名" {
		t.Fatalf("其余字段应正常保存，实际 %q", tg.Name)
	}
}

// 2.14-A：只改请求头的名称、不重填值。
//
// 还原是按键名取旧值的，新键名在旧配置里不存在 → 取不到 → 修复前那个字面量
// "******" 就被当成真实凭证存了下去。表现最难查：面板上一切正常（脱敏显示与
// 填对了长得一模一样），而出站请求带着一个错凭证被对方拒掉。
func TestTargetRenamedHeaderKeyRejectsLeftoverPlaceholder(t *testing.T) {
	manager, router := newWebhookAPITest(t)
	const secret = "Bearer 真实令牌"
	id := createTarget(t, manager, router, fmt.Sprintf(`{"X-Token":%q}`, secret))

	// X-Token 改名成 Authorization，值框里仍是占位符。
	renamed := fmt.Sprintf(`{"id":%q,"name":"自建接口","enabled":true,"type":"http",`+
		`"url":%q,"headers":{"Authorization":%q}}`, id, maskedSecret, maskedSecret)
	w := performJSONRequest(router, http.MethodPut, "/webhook/targets/"+id, renamed)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("应被校验拦住，实际 %d：%s", w.Code, w.Body.String())
	}
	// 报错要点名是哪个请求头，否则用户面对一堆头不知道该重填哪一个。
	if !strings.Contains(w.Body.String(), "Authorization") {
		t.Fatalf("报错应点名那个请求头：%s", w.Body.String())
	}
	// 拦住之后配置一个字都不能动——尤其不能把旧的那个头弄丢。
	got := manager.Get().NotifyTargets
	tg := got[len(got)-1]
	if tg.Headers["X-Token"] != secret {
		t.Fatalf("被拦下的保存不该动到已存的请求头：%#v", tg.Headers)
	}
	if _, ok := tg.Headers["Authorization"]; ok {
		t.Fatalf("被拦下的保存不该写入新键：%#v", tg.Headers)
	}
}

// 改了键名并且重填了值：这是用户本来就该走的那条路，必须能存进去。
// 少了这一条，"一律拒绝带占位符的保存"这种改法也能让上面那条绿。
func TestTargetRenamedHeaderWithNewValueSaves(t *testing.T) {
	manager, router := newWebhookAPITest(t)
	id := createTarget(t, manager, router, `{"X-Token":"Bearer 旧令牌"}`)

	renamed := fmt.Sprintf(`{"id":%q,"name":"自建接口","enabled":true,"type":"http",`+
		`"url":%q,"headers":{"Authorization":"Bearer 新令牌"}}`, id, maskedSecret)
	if w := performJSONRequest(router, http.MethodPut, "/webhook/targets/"+id, renamed); w.Code != http.StatusOK {
		t.Fatalf("重填了值应能保存，实际 %d：%s", w.Code, w.Body.String())
	}
	got := manager.Get().NotifyTargets
	tg := got[len(got)-1]
	if tg.Headers["Authorization"] != "Bearer 新令牌" {
		t.Fatalf("新值应存下：%#v", tg.Headers)
	}
	if _, ok := tg.Headers["X-Token"]; ok {
		t.Fatalf("旧键应随之消失：%#v", tg.Headers)
	}
	// 地址那一格仍走的是"按 ID 还原"，不该被这次改动带坏。
	if tg.URL != "https://example.com/in" {
		t.Fatalf("地址应仍是原值，实际 %q", tg.URL)
	}
}

// 新建时提交占位符（「复制一条」出来的条目就是这样，ID 为空、还原步骤整个跳过）。
// 地址、加签密钥、请求头三格都要各自被拦住，且报错要说得出是哪一格。
//
// 断言的是**这一句**报错，不是"有没有 400"：其中两格在修复前也会被拒（地址撞上
// http:// 前缀校验、钉钉的密钥撞上 SEC 前缀校验），只是那两句话说的是格式不对，
// 而实际情况是"这个值没能还原回来"——照着那两句去改，只会把占位符原样再填一遍。
func TestTargetMaskedFieldsOnCreateAreRejected(t *testing.T) {
	cases := []struct {
		name string
		body string
		want string
	}{
		{
			name: "地址",
			body: fmt.Sprintf(`{"name":"复制来的","enabled":true,"type":"http","url":%q}`, maskedSecret),
			want: "地址仍是脱敏占位符",
		},
		{
			name: "钉钉加签密钥",
			body: fmt.Sprintf(`{"name":"复制来的","enabled":true,"type":"dingtalk",`+
				`"url":"https://example.com/in","secret":%q}`, maskedSecret),
			want: "加签密钥仍是脱敏占位符",
		},
		{
			// 非钉钉类型的密钥修复前完全没人管：SEC 前缀那条只在 dingtalk 下生效。
			// 今天这个值不参与投递，但用户把类型改成钉钉的那一刻它就成了真凭证。
			name: "非钉钉类型的密钥",
			body: fmt.Sprintf(`{"name":"复制来的","enabled":true,"type":"wecom",`+
				`"url":"https://example.com/in","secret":%q}`, maskedSecret),
			want: "加签密钥仍是脱敏占位符",
		},
		{
			name: "请求头",
			body: fmt.Sprintf(`{"name":"复制来的","enabled":true,"type":"http",`+
				`"url":"https://example.com/in","headers":{"X-Token":%q}}`, maskedSecret),
			want: "X-Token",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			manager, router := newWebhookAPITest(t)
			before := len(manager.Get().NotifyTargets)

			w := performJSONRequest(router, http.MethodPost, "/webhook/targets", c.body)
			if w.Code != http.StatusBadRequest {
				t.Fatalf("应被校验拦住，实际 %d：%s", w.Code, w.Body.String())
			}
			if !strings.Contains(w.Body.String(), c.want) {
				t.Fatalf("报错应点名 %q：%s", c.want, w.Body.String())
			}
			// 报错要说清"是没还原回来"，而不是让用户以为格式写错了。
			if !strings.Contains(w.Body.String(), "脱敏占位符") {
				t.Fatalf("报错应说明这是脱敏占位符：%s", w.Body.String())
			}
			if got := len(manager.Get().NotifyTargets); got != before {
				t.Fatalf("不该存下任何目标：%d → %d", before, got)
			}
		})
	}
}

// 多个请求头同时留着占位符时，报的必须是同一个（按键名排序），
// 而不是随 map 遍历顺序变。否则用户重试一次就换一句话，会以为自己改的地方不对。
func TestTargetMaskedHeaderErrorIsDeterministic(t *testing.T) {
	tgt := config.NotifyTarget{
		Name: "自建接口", Type: "http", URL: "https://example.com/in",
		Headers: map[string]string{"Z-Last": maskedSecret, "A-First": maskedSecret, "M-Mid": maskedSecret},
	}
	first := ""
	for i := 0; i < 20; i++ {
		err := validateNotifyTarget(tgt)
		if err == nil {
			t.Fatal("留着占位符应报错")
		}
		if i == 0 {
			first = err.Error()
			continue
		}
		if err.Error() != first {
			t.Fatalf("同一份输入报了两句不同的话：\n%s\n%s", first, err.Error())
		}
	}
	if !strings.Contains(first, "A-First") {
		t.Fatalf("应报排序最前的那个键，实际 %q", first)
	}
}
