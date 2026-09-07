package ipx

import (
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// 「这个目标地址是不是本机」的判定。审计 NEW-1 的修复要用它。
//
// # 它防的是什么
//
// 端口转发（以及反代后端）可以把面板套在一次本机跳转之后：一条
// `ListenPort=8443 → 127.0.0.1:面板端口` 的规则一建，面板收到的每个连接对端都是
// 127.0.0.1，于是
//
//   - 面板入站防护的「仅局域网」、拒绝名单、自动封禁全部失效（decide 无条件放行回环，
//     strike 对回环不计数——那是刻意留的自救通道，见 internal/server/firewall.go）；
//   - 登录限流的两个键都含 IP（见 internal/server/api_auth.go），于是全网攻击者共享
//     同一个 127.0.0.1 桶：爆破仍被限，但合法的本机访问被连带锁死；
//   - 审计日志里来源一律 127.0.0.1，取证能力归零。
//
// 目标写成本机的**局域网地址**（192.168.x.y:面板端口）是同一形状的弱化版：
// 回环豁免不生效，但「仅局域网」这道策略照样被绕过，且所有来源仍塌成同一个 IP。
// 因此这里判的不只是回环，而是「解析到本机」。
//
// # 边界
//
//   - **不做 DNS**。传进来的普通主机名一律返回 false。理由：这个判定用在保存校验上，
//     而 DNS 结果会变（重绑定），保存那一刻查出来的答案不构成运行期的保证；
//     真要靠它，就得在每次拨号时再查一遍，那是另一件事（netguard 那条路才是拨号期判定）。
//     "localhost" 与 .localhost 后缀例外——RFC 6761 规定它们必然指向本机回环，不查也知道。
//   - **未指定地址算本机**：0.0.0.0 / :: 作为拨号目标在 Linux 与 Windows 上都会落到本机。
//   - **失败不算本机**（枚举网卡出错时只认回环那几类）：这个判定的用途是**拒绝保存**，
//     错判成"是本机"会把一条合法规则挡在门外，而错判成"不是"只是少拦一次误配置。
//     两种代价不对称，所以往宽的那侧倒——真正不能绕过的那道在运行期（各模块自己的跳过 + 告警）。
const localAddrTTL = 30 * time.Second

// localAddrCache 缓存本机各网卡上的地址。
//
// 为什么要缓存：net.Interfaces() 与随后逐网卡的 Addrs() 都不便宜，而这个判定会在
// 每次配置 Reload 时对每条规则各跑一遍（端口转发一条规则能展开成上千个运行项）。
// TTL 取 30 秒，与 wol 那边缓存网卡列表的取值一致：网卡地址变动是分钟级的事件，
// 而"刚插上网线的那 30 秒里少拦一次误配置"没有实际影响。
var localAddrCache struct {
	mu   sync.Mutex
	at   time.Time
	set  map[[16]byte]struct{}
	warm bool // 至少成功枚举过一次；失败时不把空集当成"本机没有任何地址"
}

// localAddrSet 返回本机地址集合；第二个返回值为 false 表示这一刻拿不到（枚举失败且无缓存）。
func localAddrSet() (map[[16]byte]struct{}, bool) {
	localAddrCache.mu.Lock()
	defer localAddrCache.mu.Unlock()
	if localAddrCache.warm && time.Since(localAddrCache.at) < localAddrTTL {
		return localAddrCache.set, true
	}
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		// 拿不到就沿用上一次的结果（可能已经过期）。一份过期的地址表远好过没有表：
		// 过期只会让判定慢半拍，没有表则等于这道校验整个消失。
		return localAddrCache.set, localAddrCache.warm
	}
	set := make(map[[16]byte]struct{}, len(addrs))
	for _, a := range addrs {
		var ip net.IP
		switch v := a.(type) {
		case *net.IPNet:
			ip = v.IP
		case *net.IPAddr:
			ip = v.IP
		}
		if ip == nil {
			continue
		}
		set[Key(ip)] = struct{}{}
	}
	localAddrCache.set = set
	localAddrCache.at = time.Now()
	localAddrCache.warm = true
	return set, true
}

// IsLocalIP 报告 ip 是否指向本机：回环、未指定地址，或本机某个网卡上的地址。
func IsLocalIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	if ip.IsLoopback() || ip.IsUnspecified() {
		return true
	}
	set, ok := localAddrSet()
	if !ok {
		return false // 见文件头「失败不算本机」
	}
	_, hit := set[Key(ip)]
	return hit
}

// IsLocalHost 报告目标主机字符串是否指向本机。
//
// 接受的写法：IP 字面量（含 IPv6 的 [::1] 方括号写法与 %zone 后缀）、localhost
// 及其 .localhost 后缀（RFC 6761：必然是回环）。其余主机名返回 false，不查 DNS——
// 理由见文件头。
func IsLocalHost(host string) bool {
	h := strings.TrimSpace(host)
	if h == "" {
		return false
	}
	// [::1] 这类方括号写法：用户从浏览器地址栏复制过来就是这个形状。
	if strings.HasPrefix(h, "[") && strings.HasSuffix(h, "]") {
		h = h[1 : len(h)-1]
	}
	h = stripZone(h)
	if ip := net.ParseIP(h); ip != nil {
		return IsLocalIP(ip)
	}
	lower := strings.ToLower(strings.TrimSuffix(h, "."))
	return lower == "localhost" || strings.HasSuffix(lower, ".localhost")
}

// URLTargetsLocalPort 报告 rawURL 这个后端地址是否指向**本机的 port 端口**。
//
// 反代上游与端口转发目标是同一个形状的问题，只是写法不同：转发那边是分开的
// host + port 字段（见 forwardTargetsPanel），反代这边是一整条 URL。判定的实质
// 一样——「主机指向本机」且「端口正好是面板端口」，命中就意味着面板会从
// 127.0.0.1 收到这个请求，回环豁免、仅局域网、封禁与审计日志一起失效
// （详见文件头「它防的是什么」）。
//
// 端口没写时按 scheme 补默认值（http→80、https→443）。这一条不是锦上添花：
// 面板跑在 80 或 443 上时，用户写出来的上游几乎一定是 `http://127.0.0.1` 这种
// 不带端口的形状，只比对显式端口等于对最可能的那种写法睁眼瞎。
//
// port <= 0、URL 解析不了、主机为空、端口不是数字，一律返回 false——与
// IsLocalHost 一致地「失败不算本机」（理由见文件头最后一条）。
func URLTargetsLocalPort(rawURL string, port int) bool {
	if port <= 0 {
		return false
	}
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || u.Host == "" {
		return false
	}
	if !IsLocalHost(u.Hostname()) {
		return false
	}
	return urlTargetPort(u) == port
}

// urlTargetPort 取 URL 实际会拨号的端口：写了就用写的，没写按 scheme 补。
// 认不出的 scheme 返回 0，于是与任何合法端口都不相等。
func urlTargetPort(u *url.URL) int {
	if p := u.Port(); p != "" {
		n, err := strconv.Atoi(p)
		if err != nil {
			return 0
		}
		return n
	}
	switch strings.ToLower(u.Scheme) {
	case "http":
		return 80
	case "https":
		return 443
	}
	return 0
}
