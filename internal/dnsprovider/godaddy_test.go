package dnsprovider

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// gdTestServer 起一个假 GoDaddy 端点，并把 gdAPIBase 指向它（测试结束自动还原）。
// handler 收到的请求会被记录到返回的 *[]gdCall 里，用于断言"到底发了哪些写请求"。
type gdCall struct {
	Method string
	Path   string
	Body   string
}

func gdTestServer(t *testing.T, handler func(w http.ResponseWriter, r *http.Request)) *[]gdCall {
	t.Helper()
	calls := &[]gdCall{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("读取请求体失败: %v", err)
		}
		*calls = append(*calls, gdCall{Method: r.Method, Path: r.URL.Path, Body: string(body)})
		if got := r.Header.Get("Authorization"); got != "sso-key key:secret" {
			t.Errorf("Authorization 头不符: %q", got)
		}
		handler(w, r)
	}))
	t.Cleanup(server.Close)
	oldBase := gdAPIBase
	gdAPIBase = server.URL
	t.Cleanup(func() { gdAPIBase = oldBase })
	return calls
}

func gdTXTRequest() TXTRequest {
	return TXTRequest{
		Zone:    "example.com",
		FQDN:    "_acme-challenge.example.com",
		Value:   "本次挑战的值",
		TTL:     600,
		Secrets: map[string]string{"apiKey": "key", "apiSecret": "secret"},
	}
}

const gdTXTPath = "/domains/example.com/records/TXT/_acme-challenge"

// 同名下还有别的 TXT（泛域名与主域共用挑战名、多张证书同时验证、用户自己的 SPF/站点验证串）时，
// 清理只能剔除本次的值后整体替换——直接 DELETE 会把别人的记录一并抹掉。
func TestGoDaddyRemoveTXTKeepsOtherValuesUnderSameName(t *testing.T) {
	calls := gdTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode([]gdRecord{
			{Type: "TXT", Name: "_acme-challenge", Data: "本次挑战的值", TTL: 600},
			{Type: "TXT", Name: "_acme-challenge", Data: "另一张证书的值", TTL: 300},
			{Type: "TXT", Name: "_acme-challenge", Data: "用户自己的站点验证串", TTL: 3600},
		})
	})

	if err := (&godaddyProvider{}).RemoveTXT(context.Background(), gdTXTRequest()); err != nil {
		t.Fatal(err)
	}

	if len(*calls) != 2 {
		t.Fatalf("期望 GET + PUT 两次请求，实际 %d 次: %+v", len(*calls), *calls)
	}
	if c := (*calls)[0]; c.Method != http.MethodGet || c.Path != gdTXTPath {
		t.Fatalf("第一次请求应为读取现有记录，实际 %s %s", c.Method, c.Path)
	}
	put := (*calls)[1]
	if put.Method != http.MethodPut || put.Path != gdTXTPath {
		t.Fatalf("第二次请求应为 PUT 替换，实际 %s %s", put.Method, put.Path)
	}

	var sent []map[string]any
	if err := json.Unmarshal([]byte(put.Body), &sent); err != nil {
		t.Fatalf("PUT 请求体不是合法 JSON: %v（%q）", err, put.Body)
	}
	if len(sent) != 2 {
		t.Fatalf("PUT 应只保留另外两条记录，实际 %d 条: %+v", len(sent), sent)
	}
	for _, rec := range sent {
		if rec["data"] == "本次挑战的值" {
			t.Fatalf("本次挑战的值仍留在 PUT 内容里: %+v", sent)
		}
		// 该端点按路径确定 type+name，请求体只接受 data/ttl；多余字段会被 GoDaddy 拒绝。
		if _, ok := rec["type"]; ok {
			t.Fatalf("PUT 请求体不应带 type 字段: %+v", rec)
		}
		if _, ok := rec["name"]; ok {
			t.Fatalf("PUT 请求体不应带 name 字段: %+v", rec)
		}
		if _, ok := rec["ttl"]; !ok {
			t.Fatalf("PUT 请求体缺少 ttl: %+v", rec)
		}
	}
}

// 剔除后为空时才允许 DELETE——GoDaddy 的 PUT 不接受空数组。
func TestGoDaddyRemoveTXTDeletesWhenNothingRemains(t *testing.T) {
	calls := gdTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode([]gdRecord{
			{Type: "TXT", Name: "_acme-challenge", Data: "本次挑战的值", TTL: 600},
		})
	})

	if err := (&godaddyProvider{}).RemoveTXT(context.Background(), gdTXTRequest()); err != nil {
		t.Fatal(err)
	}
	if len(*calls) != 2 {
		t.Fatalf("期望 GET + DELETE 两次请求，实际 %d 次: %+v", len(*calls), *calls)
	}
	if c := (*calls)[1]; c.Method != http.MethodDelete || c.Path != gdTXTPath {
		t.Fatalf("唯一一条记录被剔除后应 DELETE，实际 %s %s", c.Method, c.Path)
	}
}

// 记录已不在（重复清理、或已被他方删除）时不得发出任何写请求，且不算失败。
func TestGoDaddyRemoveTXTIsIdempotentWhenValueAbsent(t *testing.T) {
	calls := gdTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("值已不存在时不应发出写请求: %s", r.Method)
			w.WriteHeader(http.StatusOK)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode([]gdRecord{
			{Type: "TXT", Name: "_acme-challenge", Data: "别人的值", TTL: 600},
		})
	})

	if err := (&godaddyProvider{}).RemoveTXT(context.Background(), gdTXTRequest()); err != nil {
		t.Fatal(err)
	}
	if len(*calls) != 1 {
		t.Fatalf("期望只有一次 GET，实际 %d 次: %+v", len(*calls), *calls)
	}
}

// 该名下压根没有 TXT（GoDaddy 返回 404）同样按"已清理"处理。
func TestGoDaddyRemoveTXTTreatsMissingNameAsCleaned(t *testing.T) {
	calls := gdTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("记录名不存在时不应发出写请求: %s", r.Method)
		}
		w.WriteHeader(http.StatusNotFound)
	})

	if err := (&godaddyProvider{}).RemoveTXT(context.Background(), gdTXTRequest()); err != nil {
		t.Fatal(err)
	}
	if len(*calls) != 1 {
		t.Fatalf("期望只有一次 GET，实际 %d 次: %+v", len(*calls), *calls)
	}
}
