package dnsprovider

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// TestAliyunCallKeepsCredentialsOutOfURL 是 M-20 的回归测试：AccessKeyId 与 Signature
// 必须只出现在请求体里。URL 会被出口代理 / CDN 日志、以及 Go 自身的网络错误信息原样记下。
func TestAliyunCallKeepsCredentialsOutOfURL(t *testing.T) {
	var got *http.Request
	var form url.Values
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Errorf("请求体不是合法的表单：%v", err)
		}
		got, form = r, r.PostForm
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"RecordId":"1"}`))
	}))
	defer server.Close()
	old := aliyunEndpoint
	aliyunEndpoint = server.URL
	defer func() { aliyunEndpoint = old }()

	provider := &aliyunProvider{}
	err := provider.call(context.Background(),
		map[string]string{"accessKeyId": "AKID", "accessKeySecret": "SECRET"},
		map[string]string{"Action": "AddDomainRecord", "DomainName": "example.com"}, nil)
	if err != nil {
		t.Fatal(err)
	}

	if got.Method != http.MethodPost {
		t.Errorf("应使用 POST，实际 %s", got.Method)
	}
	if got.URL.RawQuery != "" {
		t.Errorf("URL 不应带任何查询串，实际 %q", got.URL.RawQuery)
	}
	if ct := got.Header.Get("Content-Type"); ct != "application/x-www-form-urlencoded" {
		t.Errorf("Content-Type 应为表单，实际 %q", ct)
	}
	if form.Get("AccessKeyId") != "AKID" {
		t.Errorf("请求体应携带 AccessKeyId，实际 %q", form.Get("AccessKeyId"))
	}
	if form.Get("Signature") == "" {
		t.Error("请求体应携带 Signature")
	}
	if form.Get("Action") != "AddDomainRecord" {
		t.Errorf("业务参数丢失，Action=%q", form.Get("Action"))
	}
}

// TestAliyunSignedFormMatchesSpec 独立复算一遍签名，锁住「POST 动词 + 键升序 + 密钥加 & 后缀」
// 这三处一改就会导致线上全部请求被拒的细节。
func TestAliyunSignedFormMatchesSpec(t *testing.T) {
	ts := time.Date(2026, 8, 19, 3, 4, 5, 0, time.UTC)
	body := aliyunSignedForm("AKID", "SECRET",
		map[string]string{"Action": "AddDomainRecord", "DomainName": "example.com", "Empty": ""},
		ts, "nonce123")

	form, err := url.ParseQuery(body)
	if err != nil {
		t.Fatal(err)
	}
	if form.Has("Empty") {
		t.Error("空值参数不应参与签名与请求体")
	}
	if form.Get("Timestamp") != "2026-08-19T03:04:05Z" {
		t.Errorf("Timestamp 格式错误：%q", form.Get("Timestamp"))
	}

	// 独立复算：规范串就是请求体里 Signature 之前的那一段。
	idx := strings.LastIndex(body, "&Signature=")
	if idx < 0 {
		t.Fatalf("请求体缺少 Signature：%q", body)
	}
	canonical := body[:idx]
	stringToSign := "POST&%2F&" + aliyunEncode(canonical)
	mac := hmac.New(sha1.New, []byte("SECRET&"))
	mac.Write([]byte(stringToSign))
	want := base64.StdEncoding.EncodeToString(mac.Sum(nil))
	if form.Get("Signature") != want {
		t.Errorf("签名不符：实际 %q，期望 %q", form.Get("Signature"), want)
	}
}

// TestAliyunSetTXTSkipsDuplicate 是 M-23（阿里云）的回归测试：同名同值的 TXT 已存在时不再新增。
func TestAliyunSetTXTSkipsDuplicate(t *testing.T) {
	added := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		w.Header().Set("Content-Type", "application/json")
		switch r.PostForm.Get("Action") {
		case "DescribeSubDomainRecords":
			if sub := r.PostForm.Get("SubDomain"); sub != "_acme-challenge.example.com" {
				t.Errorf("查询的子域名不对：%q", sub)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"DomainRecords": map[string]any{
				"Record": []map[string]string{{"RecordId": "r1", "Value": "token", "Type": "TXT"}},
			}})
		case "AddDomainRecord":
			added++
			_, _ = w.Write([]byte(`{"RecordId":"r2"}`))
		default:
			t.Errorf("意外的 Action：%q", r.PostForm.Get("Action"))
		}
	}))
	defer server.Close()
	old := aliyunEndpoint
	aliyunEndpoint = server.URL
	defer func() { aliyunEndpoint = old }()

	provider := &aliyunProvider{}
	req := TXTRequest{
		Zone:    "example.com",
		FQDN:    "_acme-challenge.example.com",
		Value:   "token",
		Secrets: map[string]string{"accessKeyId": "AKID", "accessKeySecret": "SECRET"},
	}
	if err := provider.SetTXT(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	if added != 0 {
		t.Fatalf("重复新增了 %d 条 TXT", added)
	}

	// 值不同则必须真的新增（别把去重写成"有同名记录就跳过"）。
	req.Value = "other"
	if err := provider.SetTXT(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	if added != 1 {
		t.Fatalf("不同值的 TXT 应新增 1 条，实际 %d", added)
	}
}

// TestTencentSetTXTSkipsDuplicate 是 M-23（腾讯云）的回归测试。
func TestTencentSetTXTSkipsDuplicate(t *testing.T) {
	created := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload map[string]any
		_ = json.NewDecoder(r.Body).Decode(&payload)
		w.Header().Set("Content-Type", "application/json")
		switch r.Header.Get("X-TC-Action") {
		case "DescribeRecordList":
			if payload["Subdomain"] != "_acme-challenge" {
				t.Errorf("查询的主机记录不对：%v", payload["Subdomain"])
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"Response": map[string]any{
				"RecordList": []map[string]any{{"RecordId": 11, "Value": "token", "Type": "TXT"}},
			}})
		case "CreateRecord":
			created++
			_, _ = w.Write([]byte(`{"Response":{"RecordId":12}}`))
		default:
			t.Errorf("意外的 Action：%q", r.Header.Get("X-TC-Action"))
		}
	}))
	defer server.Close()
	old := tcEndpoint
	tcEndpoint = server.URL
	defer func() { tcEndpoint = old }()

	provider := &tencentProvider{}
	req := TXTRequest{
		Zone:    "example.com",
		FQDN:    "_acme-challenge.example.com",
		Value:   "token",
		Secrets: map[string]string{"secretId": "ID", "secretKey": "KEY"},
	}
	if err := provider.SetTXT(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	if created != 0 {
		t.Fatalf("重复新增了 %d 条 TXT", created)
	}
	req.Value = "other"
	if err := provider.SetTXT(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	if created != 1 {
		t.Fatalf("不同值的 TXT 应新增 1 条，实际 %d", created)
	}
}

// TestBaiduSetTXTSkipsDuplicate 是 M-23（百度云）的回归测试。
func TestBaiduSetTXTSkipsDuplicate(t *testing.T) {
	created := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.Method {
		case http.MethodGet:
			if rr := r.URL.Query().Get("rr"); rr != "_acme-challenge" {
				t.Errorf("查询的主机记录不对：%q", rr)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"records": []map[string]string{
				{"id": "r1", "rr": "_acme-challenge", "type": "TXT", "value": "token"},
			}})
		case http.MethodPost:
			created++
			_, _ = w.Write([]byte(`{"id":"r2"}`))
		default:
			t.Errorf("意外的方法：%s", r.Method)
		}
	}))
	defer server.Close()
	old := baiduEndpoint
	baiduEndpoint = server.URL
	defer func() { baiduEndpoint = old }()

	provider := &baiduProvider{}
	req := TXTRequest{
		Zone:    "example.com",
		FQDN:    "_acme-challenge.example.com",
		Value:   "token",
		Secrets: map[string]string{"accessKey": "AK", "secretKey": "SK"},
	}
	if err := provider.SetTXT(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	if created != 0 {
		t.Fatalf("重复新增了 %d 条 TXT", created)
	}
	req.Value = "other"
	if err := provider.SetTXT(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	if created != 1 {
		t.Fatalf("不同值的 TXT 应新增 1 条，实际 %d", created)
	}
}
