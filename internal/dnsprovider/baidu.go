package dnsprovider

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"time"
)

// baiduProvider 通过百度智能云「云解析 DNS」（BCE bce-auth-v1 签名）管理解析记录。
// 凭证字段：accessKey、secretKey。
//
// 注意：BCE 签名算法（本文件 sign 部分）严格遵循百度云官方规范；
// 而记录 CRUD 的具体 REST 路径与请求/响应字段（recordEndpoint、listRecords 解析等）
// 依据百度云 DNS 常规约定实现，若与当前官方文档有出入，仅需在本文件集中调整，
// 不影响签名与其他服务商。
type baiduProvider struct{}

func init() {
	Register(&baiduProvider{}, Info{
		Name: "baidu",
		Fields: []Field{
			{Key: "accessKey", Required: true, Secret: false},
			{Key: "secretKey", Required: true, Secret: true},
		},
	})
}

func (p *baiduProvider) Name() string { return "baidu" }

const baiduHost = "dns.baidubce.com"

// baiduEndpoint 实际请求前缀（var 而非 const，仅为让测试指向 httptest 服务）。
// 签名与 Host 头仍取 baiduHost：那是 API 要求签的值，与测试改写请求地址无关。
var baiduEndpoint = "https://" + baiduHost

func (p *baiduProvider) EnsureRecord(ctx context.Context, req RecordRequest) error {
	rr := req.Subdomain
	if rr == "" {
		rr = "@"
	}
	ttl := req.TTL
	if ttl <= 0 {
		ttl = 600
	}
	id, curVal, err := p.findRecord(ctx, req.Secrets, req.Domain, rr, req.RecordType, "")
	if err != nil {
		return err
	}
	payload := map[string]any{"rr": rr, "type": req.RecordType, "value": req.Value, "ttl": ttl}
	if id == "" {
		return p.call(ctx, req.Secrets, http.MethodPost,
			"/v1/dns/zone/"+req.Domain+"/record", nil, payload, nil)
	}
	if curVal == req.Value {
		return nil
	}
	return p.call(ctx, req.Secrets, http.MethodPut,
		"/v1/dns/zone/"+req.Domain+"/record/"+id, nil, payload, nil)
}

func (p *baiduProvider) SetTXT(ctx context.Context, req TXTRequest) error {
	rr := relativeName(req.FQDN, req.Zone)
	ttl := req.TTL
	if ttl <= 0 {
		ttl = 600
	}
	// 同名同值的 TXT 已存在就不再新增（理由同 aliyun/tencent 的 SetTXT）：
	// 重复新增不影响 ACME 验证，但会在用户域名下累积相同记录，而清理只删一条。
	// 查询失败不阻断签发。
	if id, _, err := p.findRecord(ctx, req.Secrets, req.Zone, rr, "TXT", req.Value); err == nil && id != "" {
		return nil
	}
	payload := map[string]any{"rr": rr, "type": "TXT", "value": req.Value, "ttl": ttl}
	return p.call(ctx, req.Secrets, http.MethodPost,
		"/v1/dns/zone/"+req.Zone+"/record", nil, payload, nil)
}

func (p *baiduProvider) RemoveTXT(ctx context.Context, req TXTRequest) error {
	rr := relativeName(req.FQDN, req.Zone)
	id, _, err := p.findRecord(ctx, req.Secrets, req.Zone, rr, "TXT", req.Value)
	if err != nil {
		return err
	}
	if id == "" {
		return nil
	}
	return p.call(ctx, req.Secrets, http.MethodDelete,
		"/v1/dns/zone/"+req.Zone+"/record/"+id, nil, nil, nil)
}

func (p *baiduProvider) findRecord(ctx context.Context, secrets map[string]string, zone, rr, recordType, wantValue string) (id, value string, err error) {
	var out struct {
		Records []struct {
			ID    string `json:"id"`
			RR    string `json:"rr"`
			Type  string `json:"type"`
			Value string `json:"value"`
		} `json:"records"`
	}
	if err := p.call(ctx, secrets, http.MethodGet,
		"/v1/dns/zone/"+zone+"/record", map[string]string{"rr": rr}, nil, &out); err != nil {
		return "", "", err
	}
	for _, r := range out.Records {
		if r.RR != rr || (recordType != "" && r.Type != recordType) {
			continue
		}
		if wantValue != "" {
			if r.Value == wantValue {
				return r.ID, r.Value, nil
			}
			continue
		}
		return r.ID, r.Value, nil
	}
	return "", "", nil
}

// call 组装 bce-auth-v1 签名并发起请求。
func (p *baiduProvider) call(ctx context.Context, secrets map[string]string, method, path string, query map[string]string, payload map[string]any, out any) error {
	ak := secrets["accessKey"]
	sk := secrets["secretKey"]
	if ak == "" || sk == "" {
		return fmt.Errorf("百度云凭证缺少 accessKey/secretKey")
	}

	var bodyBytes []byte
	if payload != nil {
		bodyBytes, _ = json.Marshal(payload)
	}

	timestamp := time.Now().UTC().Format("2006-01-02T15:04:05Z")
	const expire = 1800
	authPrefix := fmt.Sprintf("bce-auth-v1/%s/%s/%d", ak, timestamp, expire)

	// 1) signingKey = hex(HMAC-SHA256(sk, authPrefix))
	signingKey := hex.EncodeToString(hmacSHA256([]byte(sk), authPrefix))

	// 2) canonicalRequest
	canonicalURI := bceURIEncode(path, false)
	canonicalQuery := bceCanonicalQuery(query)
	// 仅签名 host 头。
	canonicalHeaders := "host:" + bceURIEncode(baiduHost, true)
	signedHeaders := "host"
	canonicalRequest := method + "\n" + canonicalURI + "\n" + canonicalQuery + "\n" + canonicalHeaders

	// 3) signature = hex(HMAC-SHA256(signingKey, canonicalRequest))
	signature := hex.EncodeToString(hmacSHA256([]byte(signingKey), canonicalRequest))

	authorization := authPrefix + "/" + signedHeaders + "/" + signature

	rawURL := baiduEndpoint + path
	if canonicalQuery != "" {
		rawURL += "?" + canonicalQuery
	}
	var reqBody io.Reader
	if bodyBytes != nil {
		reqBody = bytes.NewReader(bodyBytes)
	}
	httpReq, err := http.NewRequestWithContext(ctx, method, rawURL, reqBody)
	if err != nil {
		return err
	}
	httpReq.Host = baiduHost
	httpReq.Header.Set("Host", baiduHost)
	httpReq.Header.Set("Authorization", authorization)
	if bodyBytes != nil {
		httpReq.Header.Set("Content-Type", "application/json")
	}

	client := httpClient(20 * time.Second)
	resp, err := client.Do(httpReq)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("百度云 API 失败(%d): %s", resp.StatusCode, string(data))
	}
	if out != nil && len(data) > 0 {
		if err := json.Unmarshal(data, out); err != nil {
			return fmt.Errorf("解析百度云响应失败: %w", err)
		}
	}
	return nil
}

// bceCanonicalQuery 生成 BCE 规范化查询串（按编码后键升序，值做 URI 编码）。
func bceCanonicalQuery(query map[string]string) string {
	if len(query) == 0 {
		return ""
	}
	pairs := make([]string, 0, len(query))
	for k, v := range query {
		if strings.EqualFold(k, "authorization") {
			continue
		}
		pairs = append(pairs, bceURIEncode(k, true)+"="+bceURIEncode(v, true))
	}
	slices.Sort(pairs)
	return strings.Join(pairs, "&")
}

// bceURIEncode 按 BCE 规范做百分号编码；encodeSlash=false 时保留 '/'（用于路径）。
func bceURIEncode(s string, encodeSlash bool) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9',
			c == '-', c == '_', c == '.', c == '~':
			b.WriteByte(c)
		case c == '/' && !encodeSlash:
			b.WriteByte(c)
		default:
			b.WriteString("%")
			b.WriteString(strings.ToUpper(hex.EncodeToString([]byte{c})))
		}
	}
	return b.String()
}
