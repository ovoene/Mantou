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
	"net/url"
	"os"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"

	"mantou/internal/logx"
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
//   - 2001::/32       Teredo（RFC 4380）：与上面两条同理，低 32 位内嵌客户端 IPv4
//     （按位取反后存放），是第三条能把 IPv4 目标伪装成 IPv6 地址的隧道。
//     只覆盖 2001:0000::/32 这一段，各 RIR 分配给用户的地址在 2001:200::/23 之后，
//     像 2001:4860:4860::8888 这样的公网地址不会被误伤。
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
	mustCIDR("2001::/32"),
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

// DialControl 是 net.Dialer.Control 钩子：在解析出目标地址、连接建立前校验，
// 命中内网 / 保留地址即返回 ErrBlocked 阻断本次连接。
//
// 导出它是为了那些**必须自带 Transport** 的调用方（目前是 ACME 签发，见
// internal/modules/cert/acme.go）：那条路的超时、HTTP/2 开关、连接池参数都是为
// 「CA 不可达要快速失败、且不复用被 CA 单方关闭的 HTTP/2 连接」调过的，换成
// HTTPClient 返回的共享 Transport 会把那些结论一并丢掉。
//
// 挂上它的前提是**直连**。经代理转发时拨号目标变成代理本身，钩子只会去校验代理地址
// （理由同 newTransport 里那段），所以调用方要么直连 + 挂钩子，要么走代理 + 由代理充当
// 出网策略点，不存在"两个都要"的组合。
func DialControl(network, address string, c syscall.RawConn) error {
	return controlBlockPrivate(network, address, c)
}

// controlBlockPrivate 是 net.Dialer.Control 钩子：在解析出目标地址、连接建立前校验，
// 命中内网 / 保留地址即返回 ErrBlocked 阻断本次连接。
//
// 认不出目标 IP 时**拒绝**：这条路是用户显式开启的出网策略，拿不准就拦是对的方向
// （与 BlockLinkLocal 刻意相反，那边的误拦会弄坏反代功能本身）。
func controlBlockPrivate(_, address string, _ syscall.RawConn) error {
	ip := parseDialIP(address)
	if ip == nil {
		return fmt.Errorf("%w：无法解析目标地址 %q", ErrBlocked, address)
	}
	if IsPrivateOrReserved(ip) {
		return fmt.Errorf("%w：目标 %s 属于内网 / 保留地址段", ErrBlocked, ip.String())
	}
	return nil
}

// ErrLinkLocalBlocked 表示一次连接因目标是链路本地地址而被拦截。
//
// 与 ErrBlocked 分开是为了让调用方（以及访问日志的 Reason 字段）能一眼区分两件事：
// 那个是用户主动开启的「内网防护」按策略拦下的，这个是**无条件**生效的窄拦截。
var ErrLinkLocalBlocked = errors.New("已拦截指向链路本地地址的连接")

// IsLinkLocal 判断 ip 是否是链路本地**单播**地址（IPv4 169.254.0.0/16、IPv6 fe80::/10）。
//
// 先做 To4 归一：::ffff:169.254.169.254 这种 IPv4 映射写法必须走 IPv4 侧判定，
// 否则它会从 IPv6 那一支溜过去。
//
// 刻意只覆盖链路本地单播这一段，不含 ULA（fc00::/7）：AWS 的 IPv6 元数据端点
// fd00:ec2::254 落在 ULA 里，但整个 fc00::/7 同时也是用户自建内网大量在用的地址段，
// 把它一并拦掉会把「反代一台 ULA 地址上的内网服务」这种完全正当的用法直接弄坏。
// 那件事该由用户开启的内网防护（IsPrivateOrReserved）去管，不由这道无条件的窄拦截管。
func IsLinkLocal(ip net.IP) bool {
	if ip == nil {
		return false
	}
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}
	return ip.IsLinkLocalUnicast()
}

// BlockLinkLocal 是 net.Dialer.Control 钩子：只拦链路本地地址，其余一律放过。
//
// # 它给谁用
//
// 给那些**必须允许内网目标**的拨号路径：Web 服务的反向代理后端、以及它的主动探测。
// 反代内网服务正是这个功能存在的理由（把 192.168.1.10:8080 发布到公网），所以那条路上
// 不能挂 controlBlockPrivate——那会把功能本身拦死。但「允许内网」不等于「允许一切」：
// 169.254.169.254 是各家云的实例元数据端点，上面挂着这台机器的临时凭证；一条
// `后端 = http://169.254.169.254` 的反代规则等于把云账号的凭证接口发布到公网，
// 而它在界面上跟任何一条正常的内网反代长得一模一样。
//
// # 为什么解析不出 IP 时放过（与 controlBlockPrivate 相反）
//
// 那一个是用户显式开启的出网策略，拿不准就拒绝（fail-closed）是对的。这一个无条件生效，
// 误拦的代价是把一条合法的反代规则弄坏、且用户无从关闭它。Control 钩子拿到的本来就是
// 已解析好的 ip:port，走到"解析不出来"这一支意味着出现了预期外的地址形态——
// 此时少拦一次窄场景，好过把整个反代功能建在一个自己都没把握的判断上。
func BlockLinkLocal(_, address string, _ syscall.RawConn) error {
	ip := parseDialIP(address)
	if ip == nil {
		return nil
	}
	if IsLinkLocal(ip) {
		return fmt.Errorf("%w：目标 %s 属于链路本地地址段（各家云的实例元数据端点就在这一段上）",
			ErrLinkLocalBlocked, ip.String())
	}
	return nil
}

// parseDialIP 从 Control 钩子拿到的 address 里解出目标 IP，解不出返回 nil。
//
// 两件事都不能省：
//   - address 通常是 "ip:port"，但不保证；SplitHostPort 失败时按整串当主机看。
//   - **去掉 %zone**。net.ParseIP 不接受 fe80::1%eth0 这种带区域标识的写法（只有
//     net.ResolveIPAddr 那一族认），而链路本地地址在拨号时恰恰经常带着 zone——
//     不剥掉就会解析成 nil，于是这个地址在两个钩子里都走到"认不出"那一支。
//     对 controlBlockPrivate 那边只是错误文案不准（那一支本就拒绝），
//     对 BlockLinkLocal 那边则是**真的漏拦**：它认不出就放过。
//     `%` 不可能出现在合法的 IP 字面量里，从它那里截断是安全的。
func parseDialIP(address string) net.IP {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		host = address
	}
	host = strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
	if i := strings.IndexByte(host, '%'); i >= 0 {
		host = host[:i]
	}
	return net.ParseIP(host)
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
	if enabled {
		warnProxyIgnored()
	}
	return tr
}

// proxyEnvVars 是可能声明"本机只能经代理出网"的环境变量。
//
// 前两对是 http.ProxyFromEnvironment 真正会读的（Go 只认这两个 + NO_PROXY）。
// ALL_PROXY 一并查是因为它在容器镜像与各类 shell profile 里同样常见，
// 出现它就说明这台机器被人当成"要走代理"的环境配过——这正是要提醒的那件事，
// 至于 Go 认不认它，对判断"用户可能会撞上这个坑"没有影响。
var proxyEnvVars = []string{
	"HTTP_PROXY", "http_proxy",
	"HTTPS_PROXY", "https_proxy",
	"ALL_PROXY", "all_proxy",
}

// warnProxyIgnored 在「内网防护已开启」且环境里配了代理时记一条告警。
//
// # 为什么需要这条
//
// 防护开启时这条路刻意直连（理由见 newTransport 里那段）。在只有代理才能出网的
// 环境里，这个组合的后果是**所有**由用户配置驱动的出站请求一起失败：DDNS 取不到
// 公网地址、计划任务的 HTTP 动作打不通、Webhook 推送发不出去。而用户看到的只是
// 一条条平平无奇的网络错误——超时、连接被拒——上面没有任何地方写着"是那个开关
// 干的"。两个各自都合理的设置撞在一起，症状却指向别处，这种坑必须由程序自己说出来。
//
// # 为什么放在这里而不是启动时检查
//
// 这个开关能在设置页随时改、不必重启，启动时查一遍会漏掉"跑着改开的"那一半。
// 而 guardedTransport 是 sync.OnceValue：它被构造的那一刻，恰好就是"防护路径第一次
// 真的要发请求"的时刻——早一点没意义（开关开着但没人出网，提醒是噪音），
// 晚一点来不及。一个进程里因此最多一条，不会刷屏。
func warnProxyIgnored() {
	var found []string
	for _, k := range proxyEnvVars {
		if strings.TrimSpace(os.Getenv(k)) != "" {
			found = append(found, k)
		}
	}
	if len(found) == 0 {
		return
	}
	logx.L().Warn("内网防护已开启，出站请求一律直连，环境里的代理设置不会被使用；"+
		"若本机只能经代理出网，DDNS 取址、计划任务的 HTTP 动作等会全部失败",
		"ignoredEnv", strings.Join(found, ", "))
}

// ---------- 跨主机重定向时的请求头处置 ----------

// maxRedirects 一次请求允许的跳数上限，取值与标准库默认的 10 跳一致。
//
// 这一行不是新增的限制，而是**补回来**的：一旦给 Client 设了 CheckRedirect，
// 标准库那道默认的 10 跳上限就被整个替换掉了。少了它，两个互相指向的 302
// 能让一次 DDNS 更新原地转圈，直到调用方的 context 或 Client.Timeout 到期为止。
const maxRedirects = 10

// redirectKeepHeaders 是换主机之后仍然带过去的请求头。
//
// 名单刻意写成"保留"而不是"删除"：调用方以后加了什么新头（`X-Api-Key`、
// `X-Auth-Token`、某家服务商自造的签名头），默认就是跨主机时不带过去，
// 而不是等着谁想起来往删除名单里补一条。漏一条的后果是凭证外泄，
// 多删一条的后果只是对方回 401——两边代价差得远，所以往严的那边默认。
//
// 留下的这几个都与身份无关：内容协商三条、请求体类型、Referer（标准库在调用
// 本钩子之前就按 https→http 规则设好了）、以及 User-Agent。
var redirectKeepHeaders = map[string]bool{
	"Accept":          true,
	"Accept-Encoding": true,
	"Accept-Language": true,
	"Content-Type":    true,
	"Referer":         true,
	"User-Agent":      true,
}

// CheckRedirect 是 http.Client.CheckRedirect 钩子：限制跳数，并在跳到别的主机时
// 把调用方自己设的请求头摘掉（审计 S-04）。
//
// # 漏的是哪一面
//
// 拨号闸门（controlBlockPrivate）对**每一跳**都生效，所以"302 到内网"这条早就拦住了。
// 没拦住的是另一面：请求头会跟着跳转走。本项目经这条路发出的请求带着用户填的凭证——
// 通知目标的自定义请求头（`notify/channels.go` 把 `cfg.Headers` 逐条 Set 上去，
// 面板上填 `Authorization: Bearer …` 是最常见的写法）、DNS 服务商的 API 令牌。
// 一个能控制目标地址（或能改自己服务端 302 响应）的人，靠一次跳转就能把这些
// 凭证收到自己的主机上，而面板这一侧只看到"请求成功了"。
//
// 标准库自己会在跨域跳转时丢掉 `Authorization`、`Cookie`、`WWW-Authenticate` 三个头，
// 但只有这三个。`X-Api-Key`、`X-Auth-Token` 这类同样是凭证的自定义头它一概照抄，
// 而那恰恰是国内各家 API 与自建 Webhook 最常用的写法。
//
// # 为什么"同主机但降级到 http"也算换了地方
//
// 头明文过线比换主机更直接：中间任何一跳都读得到。所以判据是
// 「主机名相同**且**没有从 https 掉到 http」，两个条件都满足才留头。
// 端口变了不算（`https://h:443` → `https://h:8443` 仍是同一家的服务）。
func CheckRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= maxRedirects {
		return fmt.Errorf("重定向次数过多（已跳 %d 次）", len(via))
	}
	if keepsHeadersAcross(via[len(via)-1].URL, req.URL) {
		return nil
	}
	// 整份换掉而不是逐个 Del：Header.Del 会先把键规范化，若调用方是直接对 map
	// 赋值（`req.Header["x-api-key"] = …`）那条就删不掉。重建一份只留白名单的，
	// 不管键长什么样都漏不掉。
	kept := make(http.Header, len(redirectKeepHeaders))
	var dropped []string
	for name, vals := range req.Header {
		if redirectKeepHeaders[http.CanonicalHeaderKey(name)] {
			kept[name] = vals
			continue
		}
		dropped = append(dropped, name)
	}
	if len(dropped) > 0 {
		req.Header = kept
		// 只记头的**名字**，绝不记值——这条日志存在的理由就是凭证不能外泄。
		//
		// 值得记一条是因为症状会指向别处：对方 302 到另一台主机、凭证被摘掉、
		// 于是回一个 401，用户在面板上看到的是"认证失败"，只会以为自己填错了令牌。
		// 排序后再记，好让同一次跳转在日志里长得一样。
		slices.Sort(dropped)
		logx.L().Warn("出站请求被重定向到其他主机，已丢弃自定义请求头以防凭证外泄",
			"from", via[len(via)-1].URL.Host, "to", req.URL.Host,
			"droppedHeaders", strings.Join(dropped, ", "))
	}
	return nil
}

// keepsHeadersAcross 判断从 prev 跳到 next 之后，调用方设的请求头能不能继续带着。
func keepsHeadersAcross(prev, next *url.URL) bool {
	if prev == nil || next == nil {
		return false // 认不出就按"换了地方"处理，与本钩子整体的取严方向一致
	}
	if !strings.EqualFold(prev.Hostname(), next.Hostname()) {
		return false
	}
	return !(strings.EqualFold(prev.Scheme, "https") && !strings.EqualFold(next.Scheme, "https"))
}

// HTTPClient 返回一个 *http.Client；enabled 为真时其底层拨号受内网防护约束。
// timeout<=0 表示不设客户端级整体超时（由调用方通过 context 控制）。
// enabled 为假时行为等价于一个带常规连接池的普通客户端。
//
// 返回的 Client 每次新建（它只是个结构体，开销可忽略），但承载连接池的 Transport
// 按 enabled 取值全局共享，因此反复调用本函数不会丢失连接复用。
//
// CheckRedirect 两种取值都挂：跨主机跳转时把调用方设的请求头摘掉这件事，
// 与内网防护开不开没有关系（见 CheckRedirect 的说明，审计 S-04）。
func HTTPClient(enabled bool, timeout time.Duration) *http.Client {
	tr := plainTransport()
	if enabled {
		tr = guardedTransport()
	}
	return &http.Client{Timeout: timeout, Transport: tr, CheckRedirect: CheckRedirect}
}
