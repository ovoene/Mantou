package dnsprovider

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// godaddyProvider 通过 GoDaddy v1 API 管理解析记录。
// 凭证字段：apiKey、apiSecret（Authorization: sso-key key:secret）。
type godaddyProvider struct{}

func init() {
	Register(&godaddyProvider{}, Info{
		Name: "godaddy",
		Fields: []Field{
			{Key: "apiKey", Required: true, Secret: false},
			{Key: "apiSecret", Required: true, Secret: true},
		},
	})
}

func (p *godaddyProvider) Name() string { return "godaddy" }

// gdAPIBase GoDaddy v1 API 根地址（变量而非常量，便于测试指向本地假服务端）。
var gdAPIBase = "https://api.godaddy.com/v1"

// gdRecord 是 GoDaddy 记录的最小字段集，用于读取该 type+name 下的现有记录。
type gdRecord struct {
	Data string `json:"data"`
	Name string `json:"name"`
	TTL  int    `json:"ttl"`
	Type string `json:"type"`
}

func (p *godaddyProvider) authHeader(secrets map[string]string) (string, error) {
	key := secrets["apiKey"]
	secret := secrets["apiSecret"]
	if key == "" || secret == "" {
		return "", fmt.Errorf("GoDaddy 凭证缺少 apiKey/apiSecret")
	}
	return "sso-key " + key + ":" + secret, nil
}

func gdTTL(ttl, min int) int {
	if ttl < min {
		return min
	}
	return ttl
}

func (p *godaddyProvider) EnsureRecord(ctx context.Context, req RecordRequest) error {
	auth, err := p.authHeader(req.Secrets)
	if err != nil {
		return err
	}
	name := req.Subdomain
	if name == "" {
		name = "@"
	}
	// PUT 替换该 type+name 下的全部记录，天然幂等（适合单值 A/AAAA）。
	rec := []map[string]any{{"data": req.Value, "ttl": gdTTL(req.TTL, 600)}}
	body, err := marshalBody(rec)
	if err != nil {
		return err
	}
	endpoint := fmt.Sprintf("%s/domains/%s/records/%s/%s", gdAPIBase, req.Domain, req.RecordType, name)
	return p.do(ctx, auth, http.MethodPut, endpoint, bytes.NewReader(body))
}

func (p *godaddyProvider) SetTXT(ctx context.Context, req TXTRequest) error {
	auth, err := p.authHeader(req.Secrets)
	if err != nil {
		return err
	}
	name := relativeName(req.FQDN, req.Zone)
	// 用 PATCH 追加，避免覆盖同名已有 TXT（如通配 + 主域共用 _acme-challenge）。
	rec := []map[string]any{{"type": "TXT", "name": name, "data": req.Value, "ttl": gdTTL(req.TTL, 600)}}
	body, err := marshalBody(rec)
	if err != nil {
		return err
	}
	endpoint := fmt.Sprintf("%s/domains/%s/records", gdAPIBase, req.Zone)
	return p.do(ctx, auth, http.MethodPatch, endpoint, bytes.NewReader(body))
}

// RemoveTXT 只删除本次挑战写下的那一条 TXT。
//
// 不能直接 DELETE /records/TXT/{name}：它会清掉该 name 下的**全部** TXT。而
// _acme-challenge.<domain> 上很可能同时存在别的值——泛域名与主域共用同一挑战名
// （SetTXT 正是为此改用 PATCH 追加）、多张证书同时验证同一子域、或者用户自己在同名下
// 放了 SPF/站点验证串。一把全删会让对方的验证直接失败，也会抹掉用户记录。
//
// GoDaddy v1 没有"按值删除"接口，只能读出现有记录、剔除本次的值后整体替换；
// 剔除后为空时才允许用 DELETE（GoDaddy 的 PUT 不接受空数组）。
func (p *godaddyProvider) RemoveTXT(ctx context.Context, req TXTRequest) error {
	auth, err := p.authHeader(req.Secrets)
	if err != nil {
		return err
	}
	name := relativeName(req.FQDN, req.Zone)
	endpoint := fmt.Sprintf("%s/domains/%s/records/TXT/%s", gdAPIBase, req.Zone, name)

	current, err := p.getRecords(ctx, auth, endpoint)
	if err != nil {
		return err
	}
	remaining := make([]map[string]any, 0, len(current))
	found := false
	for _, r := range current {
		if r.Data == req.Value {
			found = true
			continue
		}
		// 该端点按路径确定 type+name，请求体只接受 data/ttl（与 EnsureRecord 一致）。
		remaining = append(remaining, map[string]any{"data": r.Data, "ttl": gdTTL(r.TTL, 600)})
	}
	if !found {
		// 记录已不在（重复清理，或已被他方删除）：清理动作本身是幂等的，不算失败。
		return nil
	}
	if len(remaining) == 0 {
		return p.do(ctx, auth, http.MethodDelete, endpoint, nil)
	}
	body, err := marshalBody(remaining)
	if err != nil {
		return err
	}
	return p.do(ctx, auth, http.MethodPut, endpoint, bytes.NewReader(body))
}

// getRecords 读取指定 type+name 下的现有记录；该名下没有记录时返回空集合。
func (p *godaddyProvider) getRecords(ctx context.Context, auth, endpoint string) ([]gdRecord, error) {
	status, data, err := p.request(ctx, auth, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	if status == http.StatusNotFound {
		return nil, nil
	}
	if status < 200 || status >= 300 {
		return nil, fmt.Errorf("GoDaddy API 失败(%d): %s", status, string(data))
	}
	var recs []gdRecord
	if err := json.Unmarshal(data, &recs); err != nil {
		return nil, fmt.Errorf("解析 GoDaddy 记录失败: %w", err)
	}
	return recs, nil
}

// do 发起请求并只判定状态码（响应体仅在失败时用于错误信息）。
func (p *godaddyProvider) do(ctx context.Context, auth, method, endpoint string, reqBody io.Reader) error {
	status, data, err := p.request(ctx, auth, method, endpoint, reqBody)
	if err != nil {
		return err
	}
	if status < 200 || status >= 300 {
		return fmt.Errorf("GoDaddy API 失败(%d): %s", status, string(data))
	}
	return nil
}

// request 发起一次 API 请求，返回状态码与（截断后的）响应体。
func (p *godaddyProvider) request(ctx context.Context, auth, method, endpoint string, reqBody io.Reader) (int, []byte, error) {
	client := httpClient(15 * time.Second)
	req, err := http.NewRequestWithContext(ctx, method, endpoint, reqBody)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Authorization", auth)
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 128*1024))
	return resp.StatusCode, data, nil
}
