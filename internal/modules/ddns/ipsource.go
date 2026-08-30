package ddns

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"

	"mantou/internal/config"
	"mantou/internal/netguard"
	"mantou/internal/strutil"
)

// detectIP 依据来源配置探测当前公网/本地 IP。stack 为 ipv4/ipv6。
// blockPrivate 为真时，用户自定义地址的取址请求（type=url）在目标解析到内网/保留地址时会被拒绝。
func detectIP(ctx context.Context, src config.DDNSSource, stack string, blockPrivate bool) (string, error) {
	switch src.Type {
	case "public", "":
		// 公网取址：逐个尝试内置端点，从任意文本中正则提取并按协议栈校验。
		// 端点为固定可信地址，不受内网防护约束。
		return ipFromPublic(ctx, stack)
	case "interface":
		// 网卡取址已在内部按协议栈逐地址筛选，可直接返回。
		return ipFromInterface(src.Iface, stack)
	case "url":
		ip, err := ipFromURL(ctx, src.URL, src.Regex, stack, blockPrivate)
		if err != nil {
			return "", err
		}
		return ip, checkIPStack(ip, stack)
	default:
		return "", fmt.Errorf("不支持的取址方式: %s", src.Type)
	}
}

// 内置公网取址端点（按协议栈分组，逐个尝试，互为冗余）。
// 这些端点只回显访问者出口 IP，返回内容形式不一（纯文本 / JSON / 网页片段），
// 故统一用正则从文本中提取 IP，再按协议栈校验。任一端点不可用或返回异常时
// 会自动跳到下一个，多端点冗余以提升取址成功率。
var publicV4Endpoints = []string{
	"https://ddns.oray.com/checkip",
	"https://myip.ipip.net",
	"https://4.ipw.cn",
	"https://ip.3322.net",
	"https://api.ipify.org",
	"https://ipv4.icanhazip.com",
}

// 全部端点必须是 HTTPS：返回值直接决定写入 DNS 的记录内容，明文 HTTP 下任何中间人
// 都能返回任意地址，把域名指向自己的服务器（并顺带影响所有依赖该域名的服务）。
// 仍保留"取首个成功端点"而非多端点投票：HTTPS 已经解决了中间人问题，
// 而投票会把每轮探测的请求数从 1 个放大到 N 个（默认 60 秒一轮）。
var publicV6Endpoints = []string{
	"https://myip6.ipip.net",
	"https://6.ipw.cn",
	"https://api6.ipify.org",
	"https://ipv6.icanhazip.com",
}

var (
	reIPv4 = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
	// 宽松的 IPv6 匹配（含压缩写法），最终交由 net.ParseIP 精确校验。
	reIPv6 = regexp.MustCompile(`\b(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}\b`)
)

// maxPatternLen 限制用户提供的 IP 提取正则长度，防止异常超长/病态正则拖慢编译与匹配。
const maxPatternLen = 512

// compileIPPattern 编译用户提供的 IP 提取正则。
// 长度超限直接拒绝，避免病态超长正则造成编译/匹配资源浪费。
// 注：Go 的 regexp 基于 RE2 线性引擎，天然免疫回溯型 ReDoS；此处长度限制仅作纵深防御。
// 编译失败返回可读错误，便于在配置期/探测期快速定位问题。
func compileIPPattern(pattern string) (*regexp.Regexp, error) {
	if len(pattern) > maxPatternLen {
		return nil, fmt.Errorf("正则过长（上限 %d 字符）", maxPatternLen)
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, fmt.Errorf("正则无效: %w", err)
	}
	return re, nil
}

// publicProbeTimeout 单个公网端点的最长等待时长；逐端点独立限时，
// 避免某个端点长时间挂起拖垮整轮取址（父 context 通常无截止时间）。
const publicProbeTimeout = 5 * time.Second

// ipFromPublic 逐个请求内置公网端点，返回首个「通过协议栈校验且为公网」的 IP。
// 端点互为冗余：单个端点超时 / 连接失败 / 返回异常都会自动跳到下一个；
// 并拒绝私有 / 保留地址（公网取址结果必须是可路由的公网 IP），兼顾容错与准确性。
func ipFromPublic(ctx context.Context, stack string) (string, error) {
	endpoints := publicV4Endpoints
	re := reIPv4
	if stack == "ipv6" {
		endpoints = publicV6Endpoints
		re = reIPv6
	}

	// client.Timeout 对每次请求独立生效，为单端点兜底超时；底层连接可跨端点复用。
	client := &http.Client{Timeout: publicProbeTimeout}
	var lastErr error
	for _, ep := range endpoints {
		// 父 context 已取消（模块重载 / 退出）时立即停止，不再尝试后续端点。
		if err := ctx.Err(); err != nil {
			return "", err
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, ep, nil)
		if err != nil {
			lastErr = err
			continue
		}
		// 部分端点会依 UA 返回网页；给一个通用 UA 以尽量拿到纯文本/JSON。
		req.Header.Set("User-Agent", "curl/8.0")
		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
		resp.Body.Close()
		if err != nil {
			lastErr = err
			continue
		}
		// 从返回文本中提取所有候选，取首个「协议栈匹配且为公网」的地址。
		for _, cand := range re.FindAllString(string(body), -1) {
			if checkIPStack(cand, stack) != nil {
				continue
			}
			// 公网取址结果必须是可路由的公网 IP：跳过私有/保留地址，
			// 防止端点异常（代理回显、内容被篡改等）把内网地址误当成公网 IP。
			if ip := net.ParseIP(cand); ip == nil || netguard.IsPrivateOrReserved(ip) {
				continue
			}
			return cand, nil
		}
		lastErr = fmt.Errorf("%s 未返回合法的公网 %s 地址", ep, stack)
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("没有可用的公网取址端点")
	}
	return "", fmt.Errorf("公网取址失败（已尝试 %d 个端点）：%w", len(endpoints), lastErr)
}

// checkIPStack 校验取到的地址族是否与规则协议栈一致，避免用 IPv4 去更新 AAAA（或反之）。
// stack 为 "ipv6" 时要求 IPv6，其余（ipv4/留空）要求 IPv4——与记录类型选择逻辑一致。
func checkIPStack(ipStr, stack string) error {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return fmt.Errorf("取到的内容不是合法 IP: %q", truncate(ipStr, 192))
	}
	is6 := ip.To4() == nil
	if stack == "ipv6" && !is6 {
		return fmt.Errorf("规则要求 IPv6，却取到 IPv4 地址: %s", ipStr)
	}
	if stack != "ipv6" && is6 {
		return fmt.Errorf("规则要求 IPv4，却取到 IPv6 地址: %s", ipStr)
	}
	return nil
}

var (
	// ulaNet fc00::/7，IPv6 的唯一本地地址（相当于 IPv4 的 10.0.0.0/8 等内网段）。
	// net.IP.IsGlobalUnicast() 对它返回 true——该方法只排除回环/组播/链路本地/未指定，
	// 因此必须显式排除：否则在有 ULA 的网络里 DDNS 会把纯内网地址写进公网 DNS，
	// 域名解析到 fd00:: 开头的地址、外部完全不可达，而界面上显示的却是"更新成功"。
	ulaNet = net.IPNet{IP: net.ParseIP("fc00::"), Mask: net.CIDRMask(7, 128)}
	// ipv6DocNet 2001:db8::/32，文档示例专用段，同样不可路由。
	ipv6DocNet = net.IPNet{IP: net.ParseIP("2001:db8::"), Mask: net.CIDRMask(32, 128)}
)

// routableIPv6 判断地址是否是可写入公网 DNS 的 IPv6 地址。
func routableIPv6(ip net.IP) bool {
	if ip.To4() != nil || !ip.IsGlobalUnicast() {
		return false
	}
	return !ulaNet.Contains(ip) && !ipv6DocNet.Contains(ip)
}

// stableIP 在同一网卡的多个候选地址中返回确定的一个（按地址字节序取最小）。
//
// 为什么不能取"遍历到的第一个"：启用 IPv6 隐私扩展（RFC 4941，Windows/Android/多数 Linux
// 默认开启）的主机上，网卡会同时持有若干全局地址，且临时地址每天轮换。取首个意味着返回值
// 随轮换跳变 → DDNS 判定"IP 变了"→ 改 DNS；下一轮又取到另一个 → 再改回去，
// 于是反复来回改写同一条记录，既消耗服务商 API 配额，也让解析结果长期不稳定。
//
// 标准库的 Interface.Addrs() 拿不到 IFA_F_TEMPORARY 标志（需读 /proc/net/if_inet6 等
// 平台专有接口），无法区分临时地址与永久地址；退而求其次保证"同一组地址 → 同一个结果"，
// 来回改写即消失（地址集合真的变化时仍会正常更新）。
func stableIP(ips []net.IP) net.IP {
	best := ips[0]
	for _, ip := range ips[1:] {
		if bytes.Compare(ip.To16(), best.To16()) < 0 {
			best = ip
		}
	}
	return best
}

// ipFromInterface 从指定网卡读取地址；iface 为空时遍历所有非回环网卡。
func ipFromInterface(iface, stack string) (string, error) {
	wantV6 := stack == "ipv6"

	var ifaces []net.Interface
	if iface != "" {
		ni, err := net.InterfaceByName(iface)
		if err != nil {
			return "", fmt.Errorf("找不到网卡 %s: %w", iface, err)
		}
		ifaces = []net.Interface{*ni}
	} else {
		all, err := net.Interfaces()
		if err != nil {
			return "", err
		}
		ifaces = all
	}

	onlyLocalV6 := false // 是否只见到内网 IPv6（ULA），用于给出可操作的错误信息
	for _, ni := range ifaces {
		if ni.Flags&net.FlagUp == 0 || ni.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := ni.Addrs()
		if err != nil {
			continue
		}
		var candidates []net.IP
		for _, a := range addrs {
			ipNet, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			ip := ipNet.IP
			if ip.IsLoopback() || ip.IsLinkLocalUnicast() {
				continue
			}
			is6 := ip.To4() == nil
			if is6 != wantV6 {
				continue
			}
			// IPv6 必须是可路由的全局单播地址（排除 ULA / 文档段，见 routableIPv6）。
			if wantV6 && !routableIPv6(ip) {
				if ulaNet.Contains(ip) {
					onlyLocalV6 = true
				}
				continue
			}
			candidates = append(candidates, ip)
		}
		if len(candidates) == 0 {
			continue
		}
		// 同一网卡上可能有多个候选地址，按确定规则挑选，避免返回值来回跳变（见 stableIP）。
		return stableIP(candidates).String(), nil
	}
	if onlyLocalV6 {
		return "", fmt.Errorf("网卡上只有内网 IPv6 地址（ULA，fc00::/7），无法用于公网 DNS 记录")
	}
	return "", fmt.Errorf("未找到匹配的 %s 地址", stack)
}

// ipFromURL 请求第三方接口并可选用正则提取 IP。
// blockPrivate 为真时，请求经由挂载了内网防护的客户端发起：目标解析到内网/保留地址将被拒绝。
func ipFromURL(ctx context.Context, rawURL, pattern, stack string, blockPrivate bool) (string, error) {
	if rawURL == "" {
		// 默认公共取址服务。
		if stack == "ipv6" {
			rawURL = "https://api6.ipify.org"
		} else {
			rawURL = "https://api.ipify.org"
		}
	}

	client := netguard.HTTPClient(blockPrivate, 10*time.Second)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return "", err
	}
	text := strings.TrimSpace(string(body))

	if pattern != "" {
		re, err := compileIPPattern(pattern)
		if err != nil {
			return "", err
		}
		m := re.FindString(text)
		if m == "" {
			return "", fmt.Errorf("正则未匹配到 IP")
		}
		text = m
	}

	if net.ParseIP(text) == nil {
		return "", fmt.Errorf("返回内容不是合法 IP: %q", truncate(text, 192))
	}
	return text, nil
}

// truncate 把过长文本裁剪进错误信息。上限的单位是**字节**且切点回退到字符边界，
// 实现见 strutil.Truncate（原先这里按 rune 数切，需要先把整段响应体转成 []rune，
// 对最需要截断的超长输入正好要多分配约 4 倍内存）。
func truncate(s string, maxBytes int) string {
	return strutil.Truncate(s, maxBytes, "…")
}
