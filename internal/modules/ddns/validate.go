package ddns

import (
	"fmt"
	"net/url"
	"strings"
	"unicode"

	"mantou/internal/config"
)

// 规则的合法性判定只写这一份：保存接口（internal/server 的 validateDDNS）与运行期
// （execute 动手之前）共用。原先保存接口对 DDNS 规则一项都不查，界面上的限制（间隔至少
// 30 秒、记录类型只有 A / AAAA、TTL 从下拉里选）绕过前端直接调接口、或者导入一份配置
// 就全部失效；而运行期拿到什么就往 DNS 服务商那里发什么。

const (
	// MinIntervalSec 探测间隔下限（秒），与界面上那个输入框的 :min 同一个数。
	//
	// 每一拍都要向外请求一次取址接口（第三方的公共服务），间隔填成 1 秒就是每秒一次——
	// 那些服务会按频率封掉本机出口 IP，封了之后表现是"规则看着在跑、域名却不更新"。
	// 家用宽带的地址变化是小时级的事，30 秒已经远比需要的密。
	MinIntervalSec = 30
	// MaxIntervalSec 探测间隔上限：7 天。再长就起不到"跟着地址变化走"的作用了。
	MaxIntervalSec = 7 * 24 * 3600
	// maxTTL 记录 TTL 上限（秒）。各家服务商的上限都不低于一天，填得更大只可能是写错了。
	maxTTL = 86400
	// maxLineLen 解析线路（Line）的长度上限。线路名是服务商给的短标识。
	maxLineLen = 64
)

// ValidateRule 判断一条规则能不能安全地跑起来；不合法时返回一句可以照着改的话。
//
// 不查凭证在不在：那要看整份配置，是保存接口的事（见 internal/server 的 validateDDNS）；
// 运行期找不到凭证本来就会逐个目标报错。
func ValidateRule(r config.DDNSRule) error {
	if r.IntervalSec != 0 && (r.IntervalSec < MinIntervalSec || r.IntervalSec > MaxIntervalSec) {
		return fmt.Errorf("探测间隔需在 %d 秒到 %d 秒之间（0 表示默认 300 秒）", MinIntervalSec, MaxIntervalSec)
	}
	switch r.Stack {
	case "", "ipv4", "ipv6":
	default:
		return fmt.Errorf("协议栈只能是 ipv4 或 ipv6")
	}
	switch r.Source.Type {
	case "", "public", "interface":
	case "url":
		if raw := strings.TrimSpace(r.Source.URL); raw != "" {
			u, err := url.Parse(raw)
			if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
				return fmt.Errorf("取址地址必须是带主机名的 http:// 或 https:// 地址")
			}
		}
		if r.Source.Regex != "" {
			if _, err := compileIPPattern(r.Source.Regex); err != nil {
				return fmt.Errorf("取址正则：%w", err)
			}
		}
	default:
		return fmt.Errorf("不支持的取址方式：%s", r.Source.Type)
	}
	for i, t := range r.Targets {
		if err := ValidateTarget(t, r.Stack); err != nil {
			return fmt.Errorf("第 %d 个更新目标：%w", i+1, err)
		}
	}
	return nil
}

// ValidateTarget 判断一个更新目标的写法。stack 是所属规则的协议栈（决定记录类型能填什么）。
func ValidateTarget(t config.DDNSTarget, stack string) error {
	if err := checkDomainName(strings.TrimSpace(t.Domain), false); err != nil {
		return fmt.Errorf("主域名「%s」%w", t.Domain, err)
	}
	for _, s := range t.Subdomains {
		s = strings.TrimSpace(s)
		if s == "" || s == "@" {
			continue // 与 recordNames 同口径：这两种写法不产生记录
		}
		if err := checkDomainName(s, true); err != nil {
			return fmt.Errorf("主机记录「%s」%w", s, err)
		}
	}
	switch t.RecordType {
	case "":
	case "A":
		if stack == "ipv6" {
			return fmt.Errorf("IPv6 规则的记录类型应为 AAAA")
		}
	case "AAAA":
		if stack != "ipv6" {
			return fmt.Errorf("IPv4 规则的记录类型应为 A")
		}
	default:
		// 值永远是取到的 IP 地址，A / AAAA 之外的类型要么被服务商拒收，
		// 要么写出一条内容与类型对不上的记录。
		return fmt.Errorf("记录类型只能是 A 或 AAAA")
	}
	if t.TTL < 0 || t.TTL > maxTTL {
		return fmt.Errorf("TTL 需在 0 到 %d 秒之间（0 表示由服务商决定）", maxTTL)
	}
	if len(t.Line) > maxLineLen || strings.ContainsFunc(t.Line, unicode.IsControl) {
		return fmt.Errorf("解析线路写法无效")
	}
	return nil
}

// domainForbidden 域名与主机记录里不许出现的字符。
//
// 这两个值会被原样拼进服务商 API 的请求路径（GoDaddy 的 /domains/{域名}/records/{类型}/{主机记录}、
// 百度云的 /v1/dns/zone/{域名}/record），其中带一个 "/"、"?" 或 "#" 就能把请求挪到别的接口上、
// 带着这份凭证去做一件用户没配过的事。其余几个是 URL 与 DNS 里都没有合法用途的符号。
const domainForbidden = `/\?#%@:;,&=+$!'"<>[]{}|^` + "`"

// checkDomainName 校验一个域名或主机记录：点分若干段，每段 1–63 字节，总长不超过 253 字节，
// 不含空白、控制字符与 domainForbidden 里的符号。
//
// 不限定为 ASCII：国内服务商接受中文域名（按 Unicode 原样提交），拦掉会误伤正常配置；
// 要挡的是会改变请求结构的字符，而不是替服务商校验域名是否注册得了。
// allowWildcard 为真时允许首段是单独的 "*"（泛解析主机记录）。
func checkDomainName(s string, allowWildcard bool) error {
	if s == "" {
		return fmt.Errorf("不能为空")
	}
	if len(s) > 253 {
		return fmt.Errorf("过长（上限 253 字节）")
	}
	for i, label := range strings.Split(s, ".") {
		if label == "" {
			return fmt.Errorf("含有空段（连续的点、或以点开头 / 结尾）")
		}
		if len(label) > 63 {
			return fmt.Errorf("有一段超过 63 字节")
		}
		if label == "*" {
			if allowWildcard && i == 0 {
				continue
			}
			return fmt.Errorf("只能在主机记录的第一段使用 *")
		}
		for _, r := range label {
			if unicode.IsSpace(r) || unicode.IsControl(r) || r == '*' || strings.ContainsRune(domainForbidden, r) {
				return fmt.Errorf("含有不允许的字符 %q", r)
			}
		}
	}
	return nil
}
