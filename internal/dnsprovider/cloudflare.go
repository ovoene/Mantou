package dnsprovider

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sync"
	"time"
)

// cloudflareProvider 通过 Cloudflare API v4 管理解析记录。
// 凭证字段：apiToken（需含 Zone.DNS 编辑权限）。
type cloudflareProvider struct {
	txtMu sync.Mutex
}

func init() {
	Register(&cloudflareProvider{}, Info{
		Name: "cloudflare",
		Fields: []Field{
			{Key: "apiToken", Required: true, Secret: true},
		},
	})
}

func (p *cloudflareProvider) Name() string { return "cloudflare" }

var cfAPIBase = "https://api.cloudflare.com/client/v4"

func (p *cloudflareProvider) token(secrets map[string]string) (string, error) {
	token := secrets["apiToken"]
	if token == "" {
		token = secrets["token"]
	}
	if token == "" {
		return "", fmt.Errorf("Cloudflare 凭证缺少 apiToken")
	}
	return token, nil
}

func (p *cloudflareProvider) EnsureRecord(ctx context.Context, req RecordRequest) error {
	token, err := p.token(req.Secrets)
	if err != nil {
		return err
	}
	client := httpClient(15 * time.Second)
	zoneID, err := p.zoneID(ctx, client, token, req.Domain)
	if err != nil {
		return err
	}
	fqdn := fqdnOf(req.Subdomain, req.Domain)
	ttl := req.TTL
	if ttl <= 0 {
		ttl = 1 // Cloudflare: 1 = automatic
	}
	return p.upsert(ctx, client, token, zoneID, req.RecordType, fqdn, req.Value, ttl, false)
}

func (p *cloudflareProvider) SetTXT(ctx context.Context, req TXTRequest) error {
	p.txtMu.Lock()
	defer p.txtMu.Unlock()

	token, err := p.token(req.Secrets)
	if err != nil {
		return err
	}
	client := httpClient(15 * time.Second)
	zoneID, err := p.zoneID(ctx, client, token, req.Zone)
	if err != nil {
		return err
	}
	ttl := req.TTL
	if ttl <= 0 {
		ttl = 60
	}
	existing, err := p.txtRecords(ctx, client, token, zoneID, req.FQDN, req.Value)
	if err != nil {
		return err
	}
	if len(existing) > 0 {
		return nil
	}
	payload := map[string]any{"type": "TXT", "name": req.FQDN, "content": req.Value, "ttl": ttl}
	body, _ := json.Marshal(payload)
	endpoint := fmt.Sprintf("%s/zones/%s/dns_records", cfAPIBase, zoneID)
	return p.do(ctx, client, token, http.MethodPost, endpoint, bytes.NewReader(body), nil)
}

func (p *cloudflareProvider) RemoveTXT(ctx context.Context, req TXTRequest) error {
	p.txtMu.Lock()
	defer p.txtMu.Unlock()

	token, err := p.token(req.Secrets)
	if err != nil {
		return err
	}
	client := httpClient(15 * time.Second)
	zoneID, err := p.zoneID(ctx, client, token, req.Zone)
	if err != nil {
		return err
	}
	records, err := p.txtRecords(ctx, client, token, zoneID, req.FQDN, req.Value)
	if err != nil {
		return err
	}
	for _, r := range records {
		del := fmt.Sprintf("%s/zones/%s/dns_records/%s", cfAPIBase, zoneID, r.ID)
		if err := p.do(ctx, client, token, http.MethodDelete, del, nil, nil); err != nil {
			return err
		}
	}
	return nil
}

// upsert 创建或更新一条记录（按 type+name 查找）。
func (p *cloudflareProvider) upsert(ctx context.Context, client *http.Client, token, zoneID, recordType, fqdn, value string, ttl int, _ bool) error {
	recordID, err := p.recordID(ctx, client, token, zoneID, recordType, fqdn)
	if err != nil {
		return err
	}
	payload := map[string]any{"type": recordType, "name": fqdn, "content": value, "ttl": ttl}
	body, _ := json.Marshal(payload)
	var method, endpoint string
	if recordID == "" {
		method = http.MethodPost
		endpoint = fmt.Sprintf("%s/zones/%s/dns_records", cfAPIBase, zoneID)
	} else {
		method = http.MethodPut
		endpoint = fmt.Sprintf("%s/zones/%s/dns_records/%s", cfAPIBase, zoneID, recordID)
	}
	return p.do(ctx, client, token, method, endpoint, bytes.NewReader(body), nil)
}

func (p *cloudflareProvider) zoneID(ctx context.Context, client *http.Client, token, domain string) (string, error) {
	endpoint := fmt.Sprintf("%s/zones?name=%s&status=active", cfAPIBase, url.QueryEscape(domain))
	var out cfListResp
	if err := p.do(ctx, client, token, http.MethodGet, endpoint, nil, &out); err != nil {
		return "", err
	}
	if len(out.Result) == 0 {
		return "", fmt.Errorf("Cloudflare 未找到域名 %s 的 Zone", domain)
	}
	return out.Result[0].ID, nil
}

func (p *cloudflareProvider) txtRecords(ctx context.Context, client *http.Client, token, zoneID, fqdn, value string) ([]cfRecord, error) {
	endpoint := fmt.Sprintf("%s/zones/%s/dns_records?type=TXT&name=%s&content=%s",
		cfAPIBase, zoneID, url.QueryEscape(fqdn), url.QueryEscape(value))
	var out cfListResp
	if err := p.do(ctx, client, token, http.MethodGet, endpoint, nil, &out); err != nil {
		return nil, err
	}
	return out.Result, nil
}

func (p *cloudflareProvider) recordID(ctx context.Context, client *http.Client, token, zoneID, recordType, fqdn string) (string, error) {
	endpoint := fmt.Sprintf("%s/zones/%s/dns_records?type=%s&name=%s",
		cfAPIBase, zoneID, url.QueryEscape(recordType), url.QueryEscape(fqdn))
	var out cfListResp
	if err := p.do(ctx, client, token, http.MethodGet, endpoint, nil, &out); err != nil {
		return "", err
	}
	if len(out.Result) == 0 {
		return "", nil
	}
	return out.Result[0].ID, nil
}

func (p *cloudflareProvider) do(ctx context.Context, client *http.Client, token, method, endpoint string, reqBody io.Reader, out *cfListResp) error {
	req, err := http.NewRequestWithContext(ctx, method, endpoint, reqBody)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024))

	var envelope struct {
		Success bool            `json:"success"`
		Result  json.RawMessage `json:"result"`
	}
	if err := json.Unmarshal(data, &envelope); err != nil {
		return fmt.Errorf("解析 Cloudflare 响应失败: %w", err)
	}
	if !envelope.Success {
		// 错误码 81058：「已存在完全相同的记录（An identical record already exists）」，
		// 说明目标解析记录与期望完全一致、无需任何变更。DDNS 场景下视为成功，避免误报失败。
		var cfErr struct {
			Errors []struct {
				Code int `json:"code"`
			} `json:"errors"`
		}
		if json.Unmarshal(data, &cfErr) == nil {
			for _, e := range cfErr.Errors {
				if e.Code == 81058 {
					return nil
				}
			}
		}
		return fmt.Errorf("Cloudflare API 失败: %s", string(data))
	}
	if out != nil {
		_ = json.Unmarshal(envelope.Result, &out.Result)
	}
	return nil
}

type cfRecord struct {
	ID string `json:"id"`
}

type cfListResp struct {
	Result []cfRecord
}
