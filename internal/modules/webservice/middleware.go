package webservice

import (
	"net"
	"net/http"
	"strings"

	"mantou/internal/config"
	"mantou/internal/errpage"
	"mantou/internal/ipx"
)

// applyMiddleware 按子项配置叠加访问控制中间件。
// 包裹顺序自内向外，因此实际执行顺序为：IP 过滤 → 限流 → 安全响应头（含 HTTPS 跳转）→ Basic 认证 → 处理器。
//
// 两处顺序都是有意为之：
//
//   - 限流先于 Basic 认证：Basic 认证要算 bcrypt，把限流放在它前面，开了限流的子项
//     就能在更早的位置把"用海量错口令消耗 CPU"这类请求挡掉。没开限流的子项也不至于
//     裸奔——Basic 认证自己还有一道"算 bcrypt 的预算"（见 basicAuthComputeRPS）。
//   - HTTPS 跳转先于 Basic 认证：反过来的话，明文请求会先收到 401 挑战，
//     浏览器把账号口令**以明文发出来**之后才被跳到 HTTPS——那次跳转要防的事
//     已经发生了。跳转必须在任何凭证被索取之前完成。
//
// m 与 service 用于 IP 过滤拒绝时回写访问日志与程序日志。
func applyMiddleware(m *Module, service string, ch config.WebChild, next http.Handler) http.Handler {
	// Basic 认证未配 TLS 时只告警、不拒绝：面板已经把这个功能限制在"子项启用 TLS 后"才可见，
	// 而"mantou 挂在外层 TLS 终结代理后面"是完全正当的部署方式，后端没有立场替用户否决。
	if ch.Access.BasicAuth && !ch.TLS {
		m.log.Warn("Basic 认证未启用 TLS：账号口令将以明文经网络传输，建议改由 HTTPS 承载",
			"service", service, "childId", ch.ID)
	}
	h := next
	h = withBasicAuth(m, ch, h)
	h = withSecurityHeaders(ch, h)
	h = withRateLimit(m, ch, h)
	h = withIPFilter(m, service, ch, h)
	return h
}

// withIPFilter 实现允许/拒绝名单（拒绝优先）。
// 由 IPFilter 总开关管控：关闭时完全不拦截；开启时按 IPFilterMode 仅启用
// 白名单（allow）或黑名单（deny）一侧，避免两侧名单同时生效造成混淆。
// 命中拒绝时回写一条「被拒」访问日志（event=denied），便于排查谁被拦、因哪条规则。
func withIPFilter(m *Module, service string, ch config.WebChild, next http.Handler) http.Handler {
	if !ch.Access.IPFilter {
		return next
	}
	var allow, deny []string
	if ch.Access.IPFilterMode == "deny" {
		deny = ch.Access.DenyIPs
	} else {
		allow = ch.Access.AllowIPs
	}
	if len(allow) == 0 && len(deny) == 0 {
		return next
	}
	allowNets := ipx.NewMatcher(allow)
	denyNets := ipx.NewMatcher(deny)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := ipx.ClientIP(r)
		// 拿不出对端 IP 时用 RemoteAddr 的原文记账，至少让日志里能看出来源是什么形态。
		who := ipx.RemoteHost(r.RemoteAddr)
		if ip != nil && denyNets.Match(ip) {
			m.recordDenied(service, ch.ID, who, "deny")
			writeIPRejected(w, r)
			return
		}
		// 解不出对端 IP 就按"不在名单里"处理：白名单只能往关的方向失败，
		// 否则一个畸形的 RemoteAddr 就等于把整份白名单绕过去了。
		if !allowNets.Empty() && (ip == nil || !allowNets.Match(ip)) {
			m.recordDenied(service, ch.ID, who, "allow-miss")
			writeIPRejected(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// writeIPRejected 「IP 被规则拦下」。两处拒绝（黑名单命中 / 不在白名单里）共用同一页，
// 措辞刻意不区分——对来访者来说，这两种情况的区别正好是名单本身的内容，
// 那是不该从页面上读出来的。真实原因进访问日志的 denied 事件（recordDenied）。
func writeIPRejected(w http.ResponseWriter, r *http.Request) {
	errpage.Write(w, r, errpage.Page{
		Status: http.StatusForbidden,
		Title:  "访问被拒绝",
		Detail: "这个站点设置了访问来源限制，你的 IP 不在允许范围内。",
		Hint:   "如果你认为这是误拦，请联系站点管理员。",
	})
}

// withRateLimit 实现每子项、按客户端 IP 独立计数的请求速率限制（令牌桶，按秒补充）。
// RateLimit<=0 视为不限制。超限返回 429，防止单客户端刷接口/拖垮后端。
//
// 桶表是模块级的一张，全部子项共用（桶键 = 子项 ID + 来源 IP，见 ipx.IPLimiter）：
// 每个 IP 仍有自己的令牌、彼此不挤占，但"最多 8192 个桶"是整个模块的上限，
// 而不是每个子项各 8192 个。表跨配置重载存活，于是保存一次配置不再等于
// 把所有来源的令牌重新加满。
func withRateLimit(m *Module, ch config.WebChild, next http.Handler) http.Handler {
	if ch.Access.RateLimit <= 0 {
		return next
	}
	limit := float64(ch.Access.RateLimit)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !m.rateLimiter.Allow(ch.ID, ipx.LimitKey(r), limit) {
			// Retry-After 给一秒：令牌桶按秒补充，等一秒必然又有额度。
			// 顺手把它写上，规矩的爬虫与客户端库会照着退避，而不是原地空转。
			w.Header().Set("Retry-After", "1")
			errpage.Write(w, r, errpage.Page{
				Status: http.StatusTooManyRequests,
				Title:  "请求太频繁了",
				Detail: "这个站点限制了每个来源每秒的请求次数，你暂时超出了。",
				Hint:   "等一会儿再刷新即可。",
			})
			return
		}
		next.ServeHTTP(w, r)
	})
}

// withSecurityHeaders 视配置附加 HSTS 与 HTTPS 跳转，并给每个响应带上禁止 MIME 嗅探。
func withSecurityHeaders(ch config.WebChild, next http.Handler) http.Handler {
	trustProxy := ch.TrustProxyHeaders
	frameDeny := ch.FrameDeny
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		// 禁止 MIME 嗅探。无条件加、不给开关：
		//
		// 静态站点的根目录常常同时放着用户上传的东西，而浏览器的嗅探会把一个
		// text/plain 的上传文件当 HTML 执行——于是"能上传文件"直接变成"能在这个域名下
		// 执行脚本"，同域的 Cookie 与已登录会话跟着一起丢。反代那侧同理：后端把附件
		// 原样吐回来时，是不是安全的类型由后端决定，而这道头不需要它配合。
		//
		// 代价基本为零：会被它拦下的只有"类型标错了的脚本与样式表"，而浏览器对样式表
		// 本来就在严格模式下拒收错类型。Go 的 .js 在 Windows 上还额外挡过一层
		// 注册表把它写成 text/plain 的老毛病（mime/type_windows.go 里有专门的例外）。
		// 面板自己的错误页（internal/errpage）一直带着这道头，托管的站点此前反而没有。
		h.Set("X-Content-Type-Options", "nosniff")
		if frameDeny {
			// 两个头一起发：CSP 的 frame-ancestors 是现行标准且优先级更高，
			// X-Frame-Options 留给老浏览器兜底。理由与取值见 config.WebChild.FrameDeny。
			h.Set("X-Frame-Options", "SAMEORIGIN")
			h.Set("Content-Security-Policy", "frame-ancestors 'self'")
		}
		secure := r.TLS != nil || (trustProxy && forwardedHTTPS(r))
		if ch.RedirectHTTPS && !secure {
			target := "https://" + httpsRedirectHost(r.Host) + r.URL.RequestURI()
			http.Redirect(w, r, target, http.StatusTemporaryRedirect)
			return
		}
		if ch.HSTS && secure {
			h.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}
		next.ServeHTTP(w, r)
	})
}

func httpsRedirectHost(hostport string) string {
	host := hostport
	if parsedHost, _, err := net.SplitHostPort(hostport); err == nil {
		host = parsedHost
	}
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		return host
	}
	if strings.Contains(host, ":") {
		return "[" + host + "]"
	}
	return host
}

// forwardedHTTPS 读上游代理声明的协议。只在子项开了 TrustProxyHeaders 时才被调用：
// 这两个头任何客户端都能自己填，无条件采信等于让请求方决定"强制 HTTPS"与 HSTS
// 是否生效——填一个 X-Forwarded-Proto: https 就能让明文访问免于跳转。
func forwardedHTTPS(r *http.Request) bool {
	proto := strings.TrimSpace(strings.Split(r.Header.Get("X-Forwarded-Proto"), ",")[0])
	if strings.EqualFold(proto, "https") {
		return true
	}
	return strings.EqualFold(strings.TrimSpace(r.Header.Get("CF-Visitor")), `{"scheme":"https"}`)
}
