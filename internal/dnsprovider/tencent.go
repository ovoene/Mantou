package dnsprovider

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// tencentProvider 通过腾讯云 DNSPod（TC3-HMAC-SHA256 签名）管理解析记录。
// 凭证字段：secretId、secretKey。
type tencentProvider struct{}

func init() {
	Register(&tencentProvider{}, Info{
		Name: "tencent",
		Fields: []Field{
			{Key: "secretId", Required: true, Secret: false},
			{Key: "secretKey", Required: true, Secret: true},
		},
	})
}

func (p *tencentProvider) Name() string { return "tencent" }

const (
	tcHost    = "dnspod.tencentcloudapi.com"
	tcService = "dnspod"
	tcVersion = "2021-03-23"
	tcLine    = "默认"
)

// tcEndpoint 实际请求地址（var 而非 const，仅为让测试指向 httptest 服务）。
// 签名里的 host 仍取 tcHost：那是 API 要求签的值，与测试改写请求地址无关。
var tcEndpoint = "https://" + tcHost + "/"

func (p *tencentProvider) EnsureRecord(ctx context.Context, req RecordRequest) error {
	sub := req.Subdomain
	if sub == "" {
		sub = "@"
	}
	recID, curVal, err := p.findRecord(ctx, req.Secrets, req.Domain, sub, req.RecordType, "")
	if err != nil {
		return err
	}
	ttl := req.TTL
	if ttl <= 0 {
		ttl = 600
	}
	line := req.Line
	if line == "" {
		line = tcLine
	}
	if recID == 0 {
		return p.call(ctx, req.Secrets, "CreateRecord", map[string]any{
			"Domain": req.Domain, "SubDomain": sub, "RecordType": req.RecordType,
			"RecordLine": line, "Value": req.Value, "TTL": ttl,
		}, nil)
	}
	if curVal == req.Value {
		return nil
	}
	return p.call(ctx, req.Secrets, "ModifyRecord", map[string]any{
		"Domain": req.Domain, "RecordId": recID, "SubDomain": sub, "RecordType": req.RecordType,
		"RecordLine": line, "Value": req.Value, "TTL": ttl,
	}, nil)
}

func (p *tencentProvider) SetTXT(ctx context.Context, req TXTRequest) error {
	sub := relativeName(req.FQDN, req.Zone)
	ttl := req.TTL
	if ttl <= 0 {
		ttl = 600
	}
	// 同名同值的 TXT 已存在就不再新增：ACME 只要求有一条匹配即可通过，重复新增不影响验证，
	// 但续期重试会让用户域名下累积一堆相同的 _acme-challenge 记录，而清理只删一条。
	// 查询失败不阻断签发（宁可多一条记录，也不能因为查不到就签不出证书）。
	if recID, _, err := p.findRecord(ctx, req.Secrets, req.Zone, sub, "TXT", req.Value); err == nil && recID != 0 {
		return nil
	}
	return p.call(ctx, req.Secrets, "CreateRecord", map[string]any{
		"Domain": req.Zone, "SubDomain": sub, "RecordType": "TXT",
		"RecordLine": tcLine, "Value": req.Value, "TTL": ttl,
	}, nil)
}

func (p *tencentProvider) RemoveTXT(ctx context.Context, req TXTRequest) error {
	sub := relativeName(req.FQDN, req.Zone)
	recID, _, err := p.findRecord(ctx, req.Secrets, req.Zone, sub, "TXT", req.Value)
	if err != nil {
		return err
	}
	if recID == 0 {
		return nil
	}
	return p.call(ctx, req.Secrets, "DeleteRecord", map[string]any{
		"Domain": req.Zone, "RecordId": recID,
	}, nil)
}

func (p *tencentProvider) findRecord(ctx context.Context, secrets map[string]string, domain, sub, recordType, wantValue string) (uint64, string, error) {
	var out struct {
		Response struct {
			RecordList []struct {
				RecordID uint64 `json:"RecordId"`
				Value    string `json:"Value"`
				Type     string `json:"Type"`
			} `json:"RecordList"`
			Error *struct {
				Code    string `json:"Code"`
				Message string `json:"Message"`
			} `json:"Error"`
		} `json:"Response"`
	}
	err := p.call(ctx, secrets, "DescribeRecordList", map[string]any{
		"Domain": domain, "Subdomain": sub, "RecordType": recordType,
	}, &out)
	if err != nil {
		// 无记录时 DNSPod 返回 ResourceNotFound.NoDataOfRecord，视为空结果。
		if strings.Contains(err.Error(), "NoDataOfRecord") {
			return 0, "", nil
		}
		return 0, "", err
	}
	for _, r := range out.Response.RecordList {
		if wantValue != "" {
			if r.Value == wantValue {
				return r.RecordID, r.Value, nil
			}
			continue
		}
		return r.RecordID, r.Value, nil
	}
	return 0, "", nil
}

// call 组装 TC3-HMAC-SHA256 签名并发起请求。
func (p *tencentProvider) call(ctx context.Context, secrets map[string]string, action string, payload map[string]any, out any) error {
	secretID := secrets["secretId"]
	secretKey := secrets["secretKey"]
	if secretID == "" || secretKey == "" {
		return fmt.Errorf("腾讯云凭证缺少 secretId/secretKey")
	}

	body, err := marshalBody(payload)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	timestamp := strconv.FormatInt(now.Unix(), 10)
	date := now.Format("2006-01-02")

	// 1) 规范请求串。
	signedHeaders := "content-type;host;x-tc-action"
	canonicalHeaders := "content-type:application/json; charset=utf-8\n" +
		"host:" + tcHost + "\n" +
		"x-tc-action:" + strings.ToLower(action) + "\n"
	hashedPayload := sha256Hex(body)
	canonicalRequest := strings.Join([]string{
		"POST", "/", "", canonicalHeaders, signedHeaders, hashedPayload,
	}, "\n")

	// 2) 待签名字符串。
	credentialScope := date + "/" + tcService + "/tc3_request"
	stringToSign := strings.Join([]string{
		"TC3-HMAC-SHA256", timestamp, credentialScope, sha256Hex([]byte(canonicalRequest)),
	}, "\n")

	// 3) 计算签名。
	secretDate := hmacSHA256([]byte("TC3"+secretKey), date)
	secretService := hmacSHA256(secretDate, tcService)
	secretSigning := hmacSHA256(secretService, "tc3_request")
	signature := hex.EncodeToString(hmacSHA256(secretSigning, stringToSign))

	authorization := "TC3-HMAC-SHA256 " +
		"Credential=" + secretID + "/" + credentialScope + ", " +
		"SignedHeaders=" + signedHeaders + ", " +
		"Signature=" + signature

	client := httpClient(20 * time.Second)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, tcEndpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	httpReq.Header.Set("Content-Type", "application/json; charset=utf-8")
	httpReq.Header.Set("Host", tcHost)
	httpReq.Header.Set("Authorization", authorization)
	httpReq.Header.Set("X-TC-Action", action)
	httpReq.Header.Set("X-TC-Timestamp", timestamp)
	httpReq.Header.Set("X-TC-Version", tcVersion)

	resp, err := client.Do(httpReq)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024))

	// 先探测统一错误结构。
	var probe struct {
		Response struct {
			Error *struct {
				Code    string `json:"Code"`
				Message string `json:"Message"`
			} `json:"Error"`
		} `json:"Response"`
	}
	if err := json.Unmarshal(data, &probe); err != nil {
		return fmt.Errorf("解析腾讯云响应失败: %w", err)
	}
	if probe.Response.Error != nil {
		return fmt.Errorf("腾讯云 API 失败: %s %s", probe.Response.Error.Code, probe.Response.Error.Message)
	}
	if out != nil {
		if err := json.Unmarshal(data, out); err != nil {
			return fmt.Errorf("解析腾讯云响应失败: %w", err)
		}
	}
	return nil
}

func sha256Hex(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func hmacSHA256(key []byte, data string) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(data))
	return m.Sum(nil)
}
