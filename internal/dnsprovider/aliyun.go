package dnsprovider

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"
)

// aliyunProvider 通过阿里云云解析 Alidns（RPC 风格 + HMAC-SHA1 签名）管理解析记录。
// 凭证字段：accessKeyId、accessKeySecret。
type aliyunProvider struct{}

func init() {
	Register(&aliyunProvider{}, Info{
		Name: "aliyun",
		Fields: []Field{
			{Key: "accessKeyId", Required: true, Secret: false},
			{Key: "accessKeySecret", Required: true, Secret: true},
		},
	})
}

func (p *aliyunProvider) Name() string { return "aliyun" }

// aliyunEndpoint 阿里云云解析 API 端点（var 而非 const，仅为让测试指向 httptest 服务）。
var aliyunEndpoint = "https://alidns.aliyuncs.com/"

func (p *aliyunProvider) EnsureRecord(ctx context.Context, req RecordRequest) error {
	rr := req.Subdomain
	if rr == "" {
		rr = "@"
	}
	fqdn := fqdnOf(req.Subdomain, req.Domain)
	recID, curVal, err := p.findRecord(ctx, req.Secrets, fqdn, req.RecordType, "")
	if err != nil {
		return err
	}
	ttl := req.TTL
	if ttl <= 0 {
		ttl = 600
	}
	params := map[string]string{
		"RR":    rr,
		"Type":  req.RecordType,
		"Value": req.Value,
		"TTL":   strconv.Itoa(ttl),
	}
	if req.Line != "" {
		params["Line"] = req.Line
	}
	if recID == "" {
		params["Action"] = "AddDomainRecord"
		params["DomainName"] = req.Domain
		return p.call(ctx, req.Secrets, params, nil)
	}
	if curVal == req.Value {
		return nil // 无需更新
	}
	params["Action"] = "UpdateDomainRecord"
	params["RecordId"] = recID
	return p.call(ctx, req.Secrets, params, nil)
}

func (p *aliyunProvider) SetTXT(ctx context.Context, req TXTRequest) error {
	rr := relativeName(req.FQDN, req.Zone)
	ttl := req.TTL
	if ttl <= 0 {
		ttl = 600
	}
	// 先查同名同值的 TXT 是否已存在。ACME 允许同名多条 TXT，所以直接新增不会导致验证失败，
	// 但续期重试 / 同一域名反复签发会在用户的 DNS 里累积一堆一模一样的 _acme-challenge 记录，
	// 而清理只删一条 —— 残留会长期挂着。查一次的代价（一个 API 调用）远小于让用户手工清。
	// 查询失败不阻断签发：宁可可能多一条记录，也不能因为"查不到"就签不出证书。
	if recID, _, err := p.findRecord(ctx, req.Secrets, req.FQDN, "TXT", req.Value); err == nil && recID != "" {
		return nil
	}
	return p.call(ctx, req.Secrets, map[string]string{
		"Action":     "AddDomainRecord",
		"DomainName": req.Zone,
		"RR":         rr,
		"Type":       "TXT",
		"Value":      req.Value,
		"TTL":        strconv.Itoa(ttl),
	}, nil)
}

func (p *aliyunProvider) RemoveTXT(ctx context.Context, req TXTRequest) error {
	recID, _, err := p.findRecord(ctx, req.Secrets, req.FQDN, "TXT", req.Value)
	if err != nil {
		return err
	}
	if recID == "" {
		return nil
	}
	return p.call(ctx, req.Secrets, map[string]string{
		"Action":   "DeleteDomainRecord",
		"RecordId": recID,
	}, nil)
}

// findRecord 查询指定子域名的记录，返回首个匹配（或值匹配）的 RecordId 与其当前值。
func (p *aliyunProvider) findRecord(ctx context.Context, secrets map[string]string, fqdn, recordType, wantValue string) (recordID, value string, err error) {
	var out struct {
		DomainRecords struct {
			Record []struct {
				RecordID string `json:"RecordId"`
				Value    string `json:"Value"`
				Type     string `json:"Type"`
			} `json:"Record"`
		} `json:"DomainRecords"`
	}
	err = p.call(ctx, secrets, map[string]string{
		"Action":    "DescribeSubDomainRecords",
		"SubDomain": fqdn,
		"Type":      recordType,
	}, &out)
	if err != nil {
		return "", "", err
	}
	for _, r := range out.DomainRecords.Record {
		if wantValue != "" {
			if r.Value == wantValue {
				return r.RecordID, r.Value, nil
			}
			continue
		}
		return r.RecordID, r.Value, nil
	}
	return "", "", nil
}

// call 组装公共参数、计算签名并发起请求。out 为 nil 时仅校验成功与否。
func (p *aliyunProvider) call(ctx context.Context, secrets, params map[string]string, out any) error {
	ak := secrets["accessKeyId"]
	sk := secrets["accessKeySecret"]
	if ak == "" || sk == "" {
		return fmt.Errorf("阿里云凭证缺少 accessKeyId/accessKeySecret")
	}

	body := aliyunSignedForm(ak, sk, params, time.Now().UTC(), randNonce())

	client := httpClient(15 * time.Second)
	// 关键：走 POST，参数（含 AccessKeyId 与 Signature）放在请求体里，URL 保持干净。
	//
	// 阿里云 RPC 风格接口对 GET / POST 用同一套 1.0 签名，唯一差别就是待签串开头的动词，
	// 因此这里签名算法一字未动。改动的意义在于 AccessKeyId 不再出现在 URL 上：URL 是整条
	// 链路上最容易被顺手记全的东西 —— 企业出口代理与 CDN/WAF 的访问日志、以及 Go 自己的
	// 错误信息（原先形如 `Get "https://alidns.aliyuncs.com/?AccessKeyId=…&Signature=…"`，
	// 一旦网络出错就会被 mantou 记进自己的日志）。SignatureNonce 让签名无法重放，
	// 但 AccessKeyId 是长期标识，不该散落在日志里。请求体不会进这些日志。
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, aliyunEndpoint, strings.NewReader(body))
	if err != nil {
		return err
	}
	httpReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := client.Do(httpReq)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, rerr := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
	if rerr != nil {
		return fmt.Errorf("读取阿里云响应失败: %w", rerr)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("阿里云 API 失败(%d): %s", resp.StatusCode, string(data))
	}
	// 阿里云部分业务错误以 HTTP 200 返回，错误码在响应体顶层 Code 字段；需解析后判定真实成败，
	// 否则会误判「更新成功」。成功响应通常不含 Code 字段，或 Code 为 "Success"。
	var probe struct {
		Code    string `json:"Code"`
		Message string `json:"Message"`
	}
	if err := json.Unmarshal(data, &probe); err == nil && probe.Code != "" && probe.Code != "Success" {
		msg := probe.Message
		if msg == "" {
			msg = probe.Code
		}
		return fmt.Errorf("阿里云 API 错误(%s): %s", probe.Code, msg)
	}
	if out != nil {
		if err := json.Unmarshal(data, out); err != nil {
			return fmt.Errorf("解析阿里云响应失败: %w", err)
		}
	}
	return nil
}

// aliyunSignedForm 按阿里云 POP 1.0 规范拼出「已签名的表单串」，可直接作为
// application/x-www-form-urlencoded 请求体。ts / nonce 作为参数传入，便于测试固定签名。
//
// 三步与官方文档一致：规范化参数串 → 待签串 → HMAC-SHA1(密钥为 AccessKeySecret+"&")。
// 唯一与旧实现不同的是待签串的动词为 POST（因为参数改走请求体）。
func aliyunSignedForm(ak, sk string, params map[string]string, ts time.Time, nonce string) string {
	all := map[string]string{
		"Format":           "JSON",
		"Version":          "2015-01-09",
		"AccessKeyId":      ak,
		"SignatureMethod":  "HMAC-SHA1",
		"Timestamp":        ts.UTC().Format("2006-01-02T15:04:05Z"),
		"SignatureVersion": "1.0",
		"SignatureNonce":   nonce,
	}
	for k, v := range params {
		if v != "" {
			all[k] = v
		}
	}

	// 1) 按键升序拼接规范化参数串。
	keys := make([]string, 0, len(all))
	for k := range all {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	pairs := make([]string, 0, len(keys))
	for _, k := range keys {
		pairs = append(pairs, aliyunEncode(k)+"="+aliyunEncode(all[k]))
	}
	canonical := strings.Join(pairs, "&")

	// 2) stringToSign = POST&%2F&<encoded canonical>
	stringToSign := "POST&" + aliyunEncode("/") + "&" + aliyunEncode(canonical)

	// 3) HMAC-SHA1，密钥为 AccessKeySecret + "&"
	mac := hmac.New(sha1.New, []byte(sk+"&"))
	mac.Write([]byte(stringToSign))
	signature := base64.StdEncoding.EncodeToString(mac.Sum(nil))

	// aliyunEncode 的转义规则（空格为 %20 而非 +）同时满足 form-urlencoded 的解析要求。
	return canonical + "&Signature=" + aliyunEncode(signature)
}

// aliyunEncode 实现阿里云 POP 规范的百分号编码。
func aliyunEncode(s string) string {
	e := url.QueryEscape(s)
	e = strings.ReplaceAll(e, "+", "%20")
	e = strings.ReplaceAll(e, "*", "%2A")
	e = strings.ReplaceAll(e, "%7E", "~")
	return e
}

// randNonce 生成签名随机串。
func randNonce() string {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		return strconv.FormatInt(time.Now().UnixNano(), 10)
	}
	return hex.EncodeToString(b)
}
