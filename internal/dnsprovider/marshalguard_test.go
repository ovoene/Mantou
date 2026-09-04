package dnsprovider

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// 本文件是 A-4 的回归测试：dnsprovider 里 8 处 json 调用曾把 error 丢给 `_`。
// 这一族缺陷的共同形状是"失败之后带着零值继续走"，而零值在这里恰好都是"合法的空"：
// 空请求体照样带签名发出去、空记录列表被读成"这条记录不存在"。

// TestCloudflareRejectsMismatchedResultShape 盯住后果最重的那一处（cloudflare.go 的 do）。
//
// 列表端点的 result 本该是数组。旧代码 `_ = json.Unmarshal(envelope.Result, &out.Result)`
// 在拿到别的结构时静默失败，out.Result 空着返回——调用方读不出与"该名下确实没有记录"
// 的任何区别，于是 SetTXT 会在已经存在同名同值 TXT 的情况下再 POST 一条重复记录。
// 现在必须报错，且不许发出那个 POST。
func TestCloudflareRejectsMismatchedResultShape(t *testing.T) {
	postCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/zones":
			_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "result": []map[string]string{{"id": "zone1"}}})
		case r.URL.Path == "/zones/zone1/dns_records" && r.Method == http.MethodGet:
			// 结构对不上：期望数组，给的是对象。
			_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "result": map[string]string{"id": "record1"}})
		case r.URL.Path == "/zones/zone1/dns_records" && r.Method == http.MethodPost:
			postCount++
			_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "result": map[string]string{"id": "record2"}})
		default:
			t.Errorf("意外请求: %s %s", r.Method, r.URL.String())
		}
	}))
	defer server.Close()
	oldBase := cfAPIBase
	cfAPIBase = server.URL
	defer func() { cfAPIBase = oldBase }()

	provider := &cloudflareProvider{}
	err := provider.SetTXT(context.Background(), TXTRequest{
		Zone:    "example.com",
		FQDN:    "_acme-challenge.example.com",
		Value:   "value",
		Secrets: map[string]string{"apiToken": "token"},
	})
	if err == nil {
		t.Fatal("result 结构对不上时应当报错，实际返回 nil")
	}
	if !strings.Contains(err.Error(), "解析 Cloudflare 记录列表失败") {
		t.Errorf("错误信息应指出是解析记录列表失败，实际: %v", err)
	}
	if postCount != 0 {
		t.Errorf("解析失败后不应再发 POST，实际发了 %d 次（旧代码就是在这里造出重复记录的）", postCount)
	}
}

// TestCloudflareToleratesMissingResultField 划出上一条的边界：要挡的是"结构对不上"，
// 不是"字段没给"。result 整个缺失时 RawMessage 为空，若不加判断，json.Unmarshal 会报
// "unexpected end of JSON input"——那种响应在旧代码里是能正常走完的，这次不顺手改掉它。
func TestCloudflareToleratesMissingResultField(t *testing.T) {
	postCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/zones":
			_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "result": []map[string]string{{"id": "zone1"}}})
		case r.URL.Path == "/zones/zone1/dns_records" && r.Method == http.MethodGet:
			// success 为真但没有 result 字段。
			_ = json.NewEncoder(w).Encode(map[string]any{"success": true})
		case r.URL.Path == "/zones/zone1/dns_records" && r.Method == http.MethodPost:
			postCount++
			_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "result": map[string]string{"id": "record2"}})
		default:
			t.Errorf("意外请求: %s %s", r.Method, r.URL.String())
		}
	}))
	defer server.Close()
	oldBase := cfAPIBase
	cfAPIBase = server.URL
	defer func() { cfAPIBase = oldBase }()

	provider := &cloudflareProvider{}
	if err := provider.SetTXT(context.Background(), TXTRequest{
		Zone:    "example.com",
		FQDN:    "_acme-challenge.example.com",
		Value:   "value",
		Secrets: map[string]string{"apiToken": "token"},
	}); err != nil {
		t.Fatalf("result 字段缺失应当照旧当成空列表，实际报错: %v", err)
	}
	if postCount != 1 {
		t.Errorf("空列表后应当新建记录，POST 次数 = %d，期望 1", postCount)
	}
}

// TestMarshalBodySurfacesError 钉住 marshalBody 的契约：请求体序列化失败要带着原因返回，
// 而不是返回一个空 body 让调用方拿去签名。各 provider 的 payload 都是 map[string]any，
// 类型上不保证可序列化，这里就用一个不可序列化的值把那条路走通。
func TestMarshalBodySurfacesError(t *testing.T) {
	b, err := marshalBody(map[string]any{"bad": func() {}})
	if err == nil {
		t.Fatal("不可序列化的 payload 应当报错")
	}
	if b != nil {
		t.Errorf("出错时不应返回可用的 body，实际 %q", string(b))
	}
	if !strings.Contains(err.Error(), "序列化请求体失败") {
		t.Errorf("错误信息应说明是序列化请求体失败，实际: %v", err)
	}

	// 正常路径不受影响。
	b, err = marshalBody(map[string]any{"ttl": 600})
	if err != nil {
		t.Fatalf("正常 payload 不应报错: %v", err)
	}
	if string(b) != `{"ttl":600}` {
		t.Errorf("序列化结果 = %s", b)
	}
}
