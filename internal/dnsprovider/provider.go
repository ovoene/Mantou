// Package dnsprovider 提供统一的 DNS 服务商适配层。
//
// 两类调用方共用本包：
//   - DDNS 模块：调用 EnsureRecord 维护 A/AAAA 记录。
//   - 证书 ACME(DNS-01)：调用 SetTXT/RemoveTXT 完成域名所有权验证。
//
// 新增服务商只需实现 Provider 接口，并在各自文件的 init() 中调用 Register 注册，
// 同时提供 Info 描述其凭证字段（供前端动态渲染表单）。
package dnsprovider

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"
)

// RecordRequest 是一次 A/AAAA 记录更新请求（DDNS 使用）。
type RecordRequest struct {
	Domain     string            // 主域名（Zone），如 example.com
	Subdomain  string            // 主机记录，如 home；@ 或空表示根
	RecordType string            // A / AAAA
	Value      string            // 目标 IP
	TTL        int               // 生存时间（秒）
	Line       string            // 解析线路（可选，部分服务商支持）
	Secrets    map[string]string // 凭证字段
}

// TXTRequest 是一次 TXT 记录操作请求（ACME DNS-01 使用）。
type TXTRequest struct {
	Zone    string            // 注册域（Zone），如 example.com
	FQDN    string            // 完整记录名，如 _acme-challenge.sub.example.com（无末尾点）
	Value   string            // TXT 值
	TTL     int               // 生存时间（秒）
	Secrets map[string]string // 凭证字段
}

// Provider 是 DNS 服务商适配器接口。
type Provider interface {
	Name() string
	EnsureRecord(ctx context.Context, req RecordRequest) error
	SetTXT(ctx context.Context, req TXTRequest) error
	RemoveTXT(ctx context.Context, req TXTRequest) error
}

// Field 描述一个凭证字段，供前端渲染表单。
type Field struct {
	Key      string `json:"key"`      // Secrets 中的键名
	Required bool   `json:"required"` // 是否必填
	Secret   bool   `json:"secret"`   // 是否为敏感字段（前端用密码框）
}

// Info 描述一个服务商的元信息。
type Info struct {
	Name   string  `json:"name"`   // 服务商标识
	Fields []Field `json:"fields"` // 所需凭证字段
}

var (
	mu       sync.RWMutex
	registry = make(map[string]Provider)
	infos    = make(map[string]Info)
)

// Register 注册一个服务商及其字段元信息。
func Register(p Provider, info Info) {
	mu.Lock()
	defer mu.Unlock()
	registry[p.Name()] = p
	infos[info.Name] = info
}

// Get 按名称获取服务商。
func Get(name string) (Provider, error) {
	mu.RLock()
	defer mu.RUnlock()
	p, ok := registry[name]
	if !ok {
		return nil, fmt.Errorf("未支持的 DNS 服务商: %s", name)
	}
	return p, nil
}

// Names 返回已注册的服务商名称列表（稳定顺序）。
func Names() []string {
	mu.RLock()
	defer mu.RUnlock()
	out := make([]string, 0, len(registry))
	for name := range registry {
		out = append(out, name)
	}
	slices.Sort(out)
	return out
}

// Infos 返回全部服务商元信息（按名称稳定排序）。
func Infos() []Info {
	mu.RLock()
	defer mu.RUnlock()
	names := make([]string, 0, len(infos))
	for name := range infos {
		names = append(names, name)
	}
	slices.Sort(names)
	out := make([]Info, 0, len(names))
	for _, n := range names {
		out = append(out, infos[n])
	}
	return out
}

// ---------- 共享 HTTP 客户端 ----------

// sharedTransport 是各服务商适配器共用的传输层（连接池所在），首次使用时惰性构造。
//
// 需要说明的是：改用它并非为了「补上缺失的连接复用」——各适配器原本写的是
// `&http.Client{Timeout: N}`，Transport 为 nil 时标准库回落到 http.DefaultTransport，
// 那本就是个进程级共享的池，连接一直是复用的。改动的意义在两点：
//  1. 与进程内其他用途隔离。DefaultTransport 是全局可变变量，任何第三方库都可能就地改它的
//     TLSClientConfig / Proxy；DNS 凭证要经这条链路发出，不该受此影响。
//  2. 池参数显式可见。DefaultTransport 的 MaxIdleConnsPerHost 只有 2，而 ACME DNS-01 会对
//     同一服务商 API 连续发多次请求，这里按实际用量放宽，也省得后来者误以为「没有池」
//     而给每次调用新建一个 Transport（那才是真的丢掉复用）。
var sharedTransport = sync.OnceValue(func() *http.Transport {
	return &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          20,
		MaxIdleConnsPerHost:   4,
		IdleConnTimeout:       60 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: time.Second,
	}
})

// httpClient 返回一个带整体超时的客户端；底层 Transport 全局共享。
// Client 本身只是结构体，每次调用新建的开销可忽略，也便于各服务商保留自己的超时取值。
func httpClient(timeout time.Duration) *http.Client {
	return &http.Client{Timeout: timeout, Transport: sharedTransport()}
}

// ---------- 公共工具 ----------

// fqdnOf 由主机记录与主域名拼出完整域名。
func fqdnOf(subdomain, domain string) string {
	if subdomain == "" || subdomain == "@" {
		return domain
	}
	return subdomain + "." + domain
}

// relativeName 返回 fqdn 相对于 zone 的主机记录部分；等于 zone 时返回 "@"。
func relativeName(fqdn, zone string) string {
	fqdn = strings.TrimSuffix(fqdn, ".")
	zone = strings.TrimSuffix(zone, ".")
	if fqdn == zone {
		return "@"
	}
	return strings.TrimSuffix(fqdn, "."+zone)
}

// marshalBody 序列化请求体，序列化失败即报错。
//
// 存在的唯一理由就是"不许把 json.Marshal 的错误丢掉"。各家 provider 的请求体都是
// map[string]any / []map[string]any，类型上并不保证可序列化（今天塞进去的都是 string 与 int，
// 但那是约定而不是编译器保证）。而这个错误一旦丢掉，body 就是 nil——请求照样带着算好的
// 签名发出去，对方回的是一个看不出原因的 400 或"签名不符"，排查方向会被彻底带偏：
// 看起来像凭据错或时钟偏移，实际是请求体根本没组装出来。
//
// 宁可在这里当场失败并把真正的原因说出来。这属于审计里 A-1 / A-2 那一族
// （失败被静默吞掉、降级方向不安全）；internal/config/silentfail_guard_test.go
// 会挡住重新写回 `body, _ := json.Marshal(...)` 的改法。
func marshalBody(v any) ([]byte, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("序列化请求体失败: %w", err)
	}
	return b, nil
}
