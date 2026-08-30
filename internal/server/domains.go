package server

import (
	"fmt"
	"net"
	"strings"

	"mantou/internal/config"
)

// 本文件是域名归属校验：同一个端口上，一个域名只能属于一件东西。
//
// 为什么按端口查重、而不是全局查重：HTTP→HTTPS 是最常见的配置——端口 80 上一条重定向、
// 端口 443 上真正的站点，两者用的本来就是同一个域名。全局唯一会把这种配置直接判死。
// 真正让程序分不清的只有"同一条监听上有两个claimant都说这个域名归我"。
//
// 面板域名是唯一的例外，它在任何端口上都被保留：面板就是 mantou 自己，
// 把同一个名字同时指向面板和别的站点，用户敲 https://那个域名 落到哪一边取决于端口，
// 而 Web 服务那一侧还会把 /api/* 转去别处——看起来就像面板坏了。

// sameDomain 域名比较：大小写不敏感（RFC 4343），两端去空白。
func sameDomain(a, b string) bool {
	a = strings.ToLower(strings.TrimSpace(a))
	b = strings.ToLower(strings.TrimSpace(b))
	return a != "" && a == b
}

// checkPanelDomainReserved 面板域名不可被别人占用。who 是调用方的自称，进错误文案。
func checkPanelDomainReserved(cfg *config.Config, domain, who string) error {
	if !sameDomain(domain, cfg.Panel.HTTPS.Domain) {
		return nil
	}
	return fmt.Errorf("域名 %s 是面板的访问域名，不能同时给%s使用；请改用其他域名", domain, who)
}

// checkPortDomainFree 检查 port 上 domain 是否已被别人声明。
// skipServiceID 非空表示排除该 Web 服务父项（正在编辑它自己，它的旧域名不算冲突）；
// skipWebhook 为真表示排除消息路由自己。
func checkPortDomainFree(cfg *config.Config, port int, domain, skipServiceID string, skipWebhook bool) error {
	if domain == "" || port <= 0 {
		return nil
	}
	for _, ws := range cfg.WebServices {
		if ws.ID == skipServiceID || !ws.Enabled || ws.Port != port {
			continue
		}
		for _, ch := range ws.Children {
			if !ch.Enabled {
				continue
			}
			for _, d := range ch.Domains {
				if sameDomain(d, domain) {
					return fmt.Errorf("域名 %s 在端口 %d 上已被 Web 服务「%s」使用，同一端口上的域名不能重复",
						domain, port, nameOrID(ws.Name, ws.ID))
				}
			}
		}
	}
	if !skipWebhook && cfg.Webhook.Enabled && cfg.Webhook.Port == port && sameDomain(cfg.Webhook.Domain, domain) {
		return fmt.Errorf("域名 %s 在端口 %d 上已被消息路由使用，同一端口上的域名不能重复", domain, port)
	}
	return nil
}

// webhookSharePort 判断消息路由要用的端口上有没有 Web 服务，有的话能不能共用。
// 返回的错误直接面向用户；ok 为真表示共用成立（此时必然填了域名）。
//
// 端口 80 / 443 是面板、Web 服务、消息路由都想要的公共端口，谁抢到算谁的显然不行，
// 所以走"Web 服务持有监听、消息路由挂一条域名路由"这一条路（见 config.WebhookSharesWebServicePort）。
// 共用的前提有两条，缺一条都得在保存这一步说清楚，不能等到运行期才发现收不到消息：
// 一是必须有域名（那是唯一的分流依据），二是协议口径必须一致（监听的 TLS 已经定了，改不了）。
//
// 地址族不一致的 Web 服务不算占用（如 IPv6-only 的站点 + 纯 IPv4 的消息路由）：那两个
// 监听各绑各的、互不相干，此时要求填域名或对齐 HTTPS 只会把一份能正常跑的配置拦下来。
func webhookSharePort(cfg *config.Config, port int, domain string, httpsOn bool) (ok bool, err error) {
	name, tlsOn, exists := cfg.WebServiceListenerOnPort(port, cfg.WebhookListenFamily())
	if !exists {
		return false, nil
	}
	if domain == "" {
		return false, fmt.Errorf("端口 %d 已被 Web 服务「%s」占用；若要与它共用这个端口，必须填写访问域名，程序才能按域名把请求分给消息路由", port, name)
	}
	if tlsOn != httpsOn {
		want, got := "HTTP", "HTTPS"
		if tlsOn {
			want, got = "HTTPS", "HTTP"
		}
		return false, fmt.Errorf("端口 %d 上的 Web 服务「%s」用的是 %s，消息路由要与它共用这个端口就得同样用 %s（当前是 %s）",
			port, name, want, want, got)
	}
	return true, nil
}

// checkRouteDomainSyntax 挡住那些"存得下、但永远命中不了"的域名写法。
//
// 域名路由是精确查表：Web 服务把子项域名放进一张 map（见 webservice/listener.go 的
// ls.routes），消息路由共用端口时挂的也是同一张表里的一个键，请求进来拿 Host
// （去掉端口、折小写）原样查。所以这些写法一条都匹配不上，而配置本身看不出毛病——
// 用户看到的只是"明明配好了却 404 / 收不到消息"，最难查的一类问题。
//
// 通配符要单独说清楚：它只在证书那一侧有意义（SNI 用 a.example.com 去命中证书里的
// *.example.com，见 cert.Store.Resolve 与 certCoversDomain），路由这边没有这回事。
// 两件事很容易被混成一件。
//
// 留空不在管辖范围：Web 服务子项留空表示"该端口的默认站点"，消息路由留空表示
// "不按域名分流"，都是有意义的取值，各自的调用方另有判断。
func checkRouteDomainSyntax(domain string) error {
	d := strings.TrimSpace(domain)
	if d == "" {
		return nil
	}
	if strings.Contains(d, "*") {
		return fmt.Errorf("域名 %s 含通配符：域名路由是精确匹配，通配符只能填在证书的域名里；请把实际会被访问到的域名逐条列出", d)
	}
	if strings.Contains(d, "://") {
		return fmt.Errorf("域名 %s 不要带协议前缀，只填主机名（形如 example.com）", d)
	}
	if strings.ContainsAny(d, "/\\?#") {
		return fmt.Errorf("域名 %s 不要带路径或查询串，只填主机名（形如 example.com）", d)
	}
	if strings.ContainsAny(d, " \t") {
		return fmt.Errorf("域名 %s 含空格：多个域名要分成多条填，不能挤在一条里", d)
	}
	// 带端口的写法同样收不到请求（查表用的 Host 已经去掉端口了）。
	// IPv6 字面量本身含冒号，按"去掉方括号后是不是一个 IP"把它放过。
	if strings.Contains(d, ":") && net.ParseIP(strings.Trim(d, "[]")) == nil {
		return fmt.Errorf("域名 %s 不要带端口，端口由监听设置决定", d)
	}
	return nil
}

// mustHaveDomainPort 需要强制填域名的公共端口。
// 这两个端口没有别的选择：它们是浏览器与第三方系统的默认端口，面板、Web 服务、
// 消息路由都可能想要，而一个端口只能被一个进程绑定，只有域名能把请求分开。
func mustHaveDomainPort(port int) bool { return port == 80 || port == 443 }

// checkWebhookPortShare 从 Web 服务这一侧校验"与消息路由共用端口"的两个前提。
// 调用方负责先确认这个父项将处于启用状态。
//
// 两侧都要校验：先配 Web 服务、后配消息路由的用户在消息路由那一侧被拦下，
// 反过来的用户如果这里不拦，看到的就是运行期日志里的"地址已被占用"。
//
// 只在本服务确实会起监听时才管：没有任何启用子项的父项不产生监听（见 webservice.Reload），
// 那个端口仍归消息路由自己绑，谈不上冲突。
//
// 地址族对不上也不管：本服务与消息路由绑的是两族里各自的那一半（IPv6-only 的站点收不到
// IPv4 的请求，反之亦然），两个监听并存不冲突，也就没有"共用"这回事。
func checkWebhookPortShare(cfg *config.Config, ws config.WebService) error {
	if ws.Port <= 0 || !cfg.Webhook.Enabled || cfg.Webhook.Port != ws.Port {
		return nil
	}
	if !config.FamilyServes(ws.IPFamily, cfg.WebhookListenFamily()) {
		return nil
	}
	wsTLS, hasChild := false, false
	for _, ch := range ws.Children {
		if ch.Enabled {
			wsTLS, hasChild = ch.TLS, true
			break
		}
	}
	switch {
	case !hasChild:
		return nil
	case cfg.Webhook.Domain == "":
		return fmt.Errorf("端口 %d 已被消息路由占用；两者要共用这个端口，得先到「消息路由 → 模块设置」填写访问域名，程序才能按域名分辨请求该给谁", ws.Port)
	case wsTLS != cfg.Webhook.HTTPS.Enabled:
		proto := "HTTP"
		if wsTLS {
			proto = "HTTPS"
		}
		return fmt.Errorf("端口 %d 要与消息路由共用，但本服务用的是 %s、消息路由不是；请把两者的 HTTPS 开关调成一致", ws.Port, proto)
	}
	return nil
}
