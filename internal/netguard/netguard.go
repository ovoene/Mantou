// Package netguard 为「用户可配置的出站请求」提供内网 / 保留地址防护。
// 开启后，出站连接会在解析出目标 IP 之后、真正建立连接之前做一次校验：
// 若目标落在回环、私有、链路本地、多播、未指定、运营商级 NAT 或其他保留地址段，
// 则直接拒绝。校验实施在拨号层（net.Dialer.Control），因此对 HTTP 重定向、
// 以及域名在解析后指向内网地址的情形同样生效。默认关闭，以兼容「目标本就是内网服务」的自建场景。
package netguard

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"
	"syscall"
	"time"
)

// ErrBlocked 表示一次出站连接因目标为内网 / 保留地址而被防护拦截。
var ErrBlocked = errors.New("已按内网防护策略拦截出站请求")

// reservedNets 列出 net.IP 内置谓词覆盖不到、但同样不应成为「用户可配置出站请求」目标的网段：
//
//   - 100.64.0.0/10   运营商级 NAT（RFC 6598）：家宽常见，可探测到运营商侧设备
//   - 192.0.0.0/24    IETF 协议专用（RFC 6890）：含 DS-Lite 等本机 / 本网用途地址
//   - 192.88.99.0/24  已废弃的 6to4 中继任播（RFC 7526）
//   - 198.18.0.0/15   网络设备基准测试专用（RFC 2544）
//   - 240.0.0.0/4     保留未分配（原 E 类），并顺带覆盖受限广播 255.255.255.255
//   - 64:ff9b::/96    NAT64（RFC 6052）：低 32 位内嵌任意 IPv4，可借此绕开 IPv4 侧校验
//   - 2002::/16       6to4（RFC 3056）：同样内嵌任意 IPv4，且已废弃
//
// 表在包初始化时解析一次，判定时线性遍历。刻意不写成手工位比较：条目数是常量，
// 遍历开销可忽略，而 CIDR 字面量能与 RFC 逐条对照，往后补网段也不会算错掩码。
var reservedNets = []*net.IPNet{
	mustCIDR("100.64.0.0/10"),
	mustCIDR("192.0.0.0/24"),
	mustCIDR("192.88.99.0/24"),
	mustCIDR("198.18.0.0/15"),
	mustCIDR("240.0.0.0/4"),
	mustCIDR("64:ff9b::/96"),
	mustCIDR("2002::/16"),
}

// mustCIDR 解析 CIDR 字面量，失败即 panic。入参全是包内常量，只可能在改代码时写错。
func mustCIDR(s string) *net.IPNet {
	_, n, err := net.ParseCIDR(s)
	if err != nil {
		panic("netguard: 保留网段字面量非法 " + s + ": " + err.Error())
	}
	return n
}

// IsPrivateOrReserved 判断 ip 是否属于不应被用户自定义出站请求访问的地址段：
// 回环 / 私有 / 未指定 / 链路本地（含单播与多播）/ 多播，以及 reservedNets 列出的各保留网段。
// 传入 nil 视为无法归类，按不安全处理返回 true。
func IsPrivateOrReserved(ip net.IP) bool {
	if ip == nil {
		return true
	}
	// 归一到 4 字节形式：IPv4 映射地址（::ffff:a.b.c.d）也要走 IPv4 侧判定，
	// 否则 ::ffff:192.168.1.1 会绕过所有 IPv4 网段检查。
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified() ||
		ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() {
		return true
	}
	for _, n := range reservedNets {
		// Contains 自身会做长度归一，IPv4 地址不会误命中 IPv6 网段，反之亦然。
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// controlBlockPrivate 是 net.Dialer.Control 钩子：在解析出目标地址、连接建立前校验，
// 命中内网 / 保留地址即返回 ErrBlocked 阻断本次连接。
func controlBlockPrivate(_, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		host = address
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return fmt.Errorf("%w：无法解析目标地址 %q", ErrBlocked, address)
	}
	if IsPrivateOrReserved(ip) {
		return fmt.Errorf("%w：目标 %s 属于内网 / 保留地址段", ErrBlocked, ip.String())
	}
	return nil
}

// 共享 Transport 的拨号参数。Transport 一旦跨调用复用，拨号超时就不能再随调用方传入的
// timeout 变化，故固定为一个宽松值；单次请求的整体上限仍由调用方的 context 与
// Client.Timeout 决定（两者都作用于「连接 + 收发」全过程，比单独的拨号超时更严）。
const (
	dialTimeout   = 10 * time.Second
	dialKeepAlive = 30 * time.Second
)

// Transport 的价值全在连接池：每次新建等于彻底放弃连接复用——DDNS 一轮探测最多访问 6 个
// 取址端点、每 60 秒一轮，全都要重付一次 TCP + TLS 握手；被丢弃的旧 Transport 里的空闲连接
// 还会滞留到 IdleConnTimeout 才回收。按 enabled 的两种取值各缓存一个，首次使用时惰性构造。
var (
	guardedTransport = sync.OnceValue(func() *http.Transport { return newTransport(true) })
	plainTransport   = sync.OnceValue(func() *http.Transport { return newTransport(false) })
)

// newDialer 构造拨号器；enabled 为真时挂载内网防护 Control 钩子。
func newDialer(enabled bool) *net.Dialer {
	d := &net.Dialer{Timeout: dialTimeout, KeepAlive: dialKeepAlive}
	if enabled {
		d.Control = controlBlockPrivate
	}
	return d
}

// newTransport 构造一个供全局复用的 Transport。
func newTransport(enabled bool) *http.Transport {
	tr := &http.Transport{
		DialContext:           newDialer(enabled).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          10,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: time.Second,
	}
	if !enabled {
		// 与 acme.go 一致：尊重 HTTP_PROXY / HTTPS_PROXY / NO_PROXY。
		// 在只有代理才能出网的环境里，缺这一行会让 DDNS 取址与计划任务 HTTP 动作直接失败。
		//
		// 但内网防护开启时刻意**不**走代理：防护是靠 Dialer.Control 检查「即将连接的 IP」实现的，
		// 一旦经代理转发，拨号目标就变成代理本身，真实目标由代理去解析——钩子只会去校验代理地址，
		// 防护形同虚设；而代理若部署在内网（127.0.0.1:8080 之类），这一拨号还会被自己拦下。
		// 两种结果都不可接受，故防护路径一律直连。
		tr.Proxy = http.ProxyFromEnvironment
	}
	return tr
}

// HTTPClient 返回一个 *http.Client；enabled 为真时其底层拨号受内网防护约束。
// timeout<=0 表示不设客户端级整体超时（由调用方通过 context 控制）。
// enabled 为假时行为等价于一个带常规连接池的普通客户端。
//
// 返回的 Client 每次新建（它只是个结构体，开销可忽略），但承载连接池的 Transport
// 按 enabled 取值全局共享，因此反复调用本函数不会丢失连接复用。
func HTTPClient(enabled bool, timeout time.Duration) *http.Client {
	tr := plainTransport()
	if enabled {
		tr = guardedTransport()
	}
	return &http.Client{Timeout: timeout, Transport: tr}
}
