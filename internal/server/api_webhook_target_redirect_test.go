package server

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
)

// 列表接口把通知目标的加签密钥与请求头脱敏，是为了"光有一条会话读不到它们"。
// 原先保存时只要值是占位符就按 ID 还原，不管地址改没改：一条被盗的会话把地址改成自己的
// 服务器、请求头原样留着占位符、再点一下「测试」，存着的凭证就发到了对方手里。
// 下面几条钉住：地址一改，旧凭证就不再跟着走。

// TestTargetURLChangeDoesNotCarryMaskedHeader 换了地址、请求头仍是占位符：拒绝保存，原配置一个字都不动。
func TestTargetURLChangeDoesNotCarryMaskedHeader(t *testing.T) {
	manager, router := newWebhookAPITest(t)
	const secret = "Bearer 真实令牌"
	id := createTarget(t, manager, router, fmt.Sprintf(`{"Authorization":%q}`, secret))

	moved := fmt.Sprintf(`{"id":%q,"name":"自建接口","enabled":true,"type":"http",`+
		`"url":"https://attacker.example/collect","headers":{"Authorization":%q}}`, id, maskedSecret)
	w := performJSONRequest(router, http.MethodPut, "/webhook/targets/"+id, moved)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("地址改了而请求头仍是占位符，应当拒绝保存，实际 %d：%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "地址已修改") {
		t.Fatalf("报错应说明是因为改了地址，实际：%s", w.Body.String())
	}
	if strings.Contains(w.Body.String(), secret) {
		t.Fatalf("报错把凭证原文带了出去：%s", w.Body.String())
	}
	got := manager.Get().NotifyTargets
	tg := got[len(got)-1]
	if tg.URL != "https://example.com/in" {
		t.Fatalf("被拒的保存改动了地址：%q", tg.URL)
	}
	if tg.Headers["Authorization"] != secret {
		t.Fatalf("被拒的保存改动了请求头：%#v", tg.Headers)
	}
}

// TestTargetURLChangeDoesNotCarryMaskedSecret 加签密钥同理（钉钉机器人）。
func TestTargetURLChangeDoesNotCarryMaskedSecret(t *testing.T) {
	manager, router := newWebhookAPITest(t)
	create := `{"name":"钉钉群","enabled":true,"type":"dingtalk",` +
		`"url":"https://oapi.dingtalk.com/robot/send?access_token=aaa","secret":"SEC真实密钥"}`
	if w := performJSONRequest(router, http.MethodPost, "/webhook/targets", create); w.Code != http.StatusOK {
		t.Fatalf("新建钉钉目标应成功，实际 %d：%s", w.Code, w.Body.String())
	}
	list := manager.Get().NotifyTargets
	id := list[len(list)-1].ID

	moved := fmt.Sprintf(`{"id":%q,"name":"钉钉群","enabled":true,"type":"dingtalk",`+
		`"url":"https://attacker.example/robot","secret":%q}`, id, maskedSecret)
	w := performJSONRequest(router, http.MethodPut, "/webhook/targets/"+id, moved)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("地址改了而加签密钥仍是占位符，应当拒绝保存，实际 %d：%s", w.Code, w.Body.String())
	}
	got := manager.Get().NotifyTargets
	if tg := got[len(got)-1]; tg.Secret != "SEC真实密钥" || !strings.Contains(tg.URL, "oapi.dingtalk.com") {
		t.Fatalf("被拒的保存改动了已存的目标：url=%q", tg.URL)
	}
}

// TestTargetURLChangeWithNewSecretsSaves 换地址并重新填写凭证：这是本来就该走的那条路，必须能存进去。
func TestTargetURLChangeWithNewSecretsSaves(t *testing.T) {
	manager, router := newWebhookAPITest(t)
	id := createTarget(t, manager, router, `{"Authorization":"Bearer 旧令牌"}`)

	moved := fmt.Sprintf(`{"id":%q,"name":"自建接口","enabled":true,"type":"http",`+
		`"url":"https://new.example.com/in","headers":{"Authorization":"Bearer 新令牌"}}`, id)
	if w := performJSONRequest(router, http.MethodPut, "/webhook/targets/"+id, moved); w.Code != http.StatusOK {
		t.Fatalf("换地址并重填凭证应能保存，实际 %d：%s", w.Code, w.Body.String())
	}
	got := manager.Get().NotifyTargets
	tg := got[len(got)-1]
	if tg.URL != "https://new.example.com/in" || tg.Headers["Authorization"] != "Bearer 新令牌" {
		t.Fatalf("新地址与新凭证应存下：url=%q headers=%#v", tg.URL, tg.Headers)
	}
}

// TestTargetSameURLTypedAgainKeepsSecrets 把同一个地址原样再敲一遍（没留占位符）：地址没变，凭证照常沿用。
func TestTargetSameURLTypedAgainKeepsSecrets(t *testing.T) {
	manager, router := newWebhookAPITest(t)
	const secret = "Bearer 真实令牌"
	id := createTarget(t, manager, router, fmt.Sprintf(`{"Authorization":%q}`, secret))

	same := fmt.Sprintf(`{"id":%q,"name":"自建接口","enabled":true,"type":"http",`+
		`"url":"  https://example.com/in ","headers":{"Authorization":%q}}`, id, maskedSecret)
	if w := performJSONRequest(router, http.MethodPut, "/webhook/targets/"+id, same); w.Code != http.StatusOK {
		t.Fatalf("地址没变应能保存，实际 %d：%s", w.Code, w.Body.String())
	}
	got := manager.Get().NotifyTargets
	if tg := got[len(got)-1]; tg.Headers["Authorization"] != secret {
		t.Fatalf("地址没变时凭证应当沿用，实际 %#v", tg.Headers)
	}
}
