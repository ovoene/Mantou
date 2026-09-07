package server

import (
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"mantou/internal/auth"
	"mantou/internal/errpage"
)

// 会话令牌所用的 Cookie 名——按连接协议分开，**不能两种协议共用一个名字**。
//
// 起因是一个很难自查的故障：面板启用 HTTPS 期间，浏览器为「域名:端口」存下了带 Secure
// 属性的会话 Cookie；之后关闭 HTTPS 改走 http + 同一域名，两件事同时发生——
//  1. 那条旧 Cookie 不会被发送（Secure 的定义就是只走 HTTPS）；
//  2. 新下发的同名 Cookie 会被浏览器**整条丢弃**：按 RFC 6265bis 的 Strict Secure Cookies
//     规则（Chrome 52+ / Firefox 52+ 起强制），非安全来源不得创建或覆盖一条同名、同域、
//     同路径的 Secure Cookie。
//
// 于是 http + 域名 下浏览器一条可用的会话 Cookie 都没有，而 /auth/login 本身无需鉴权、
// 照常返回 200 并写下「登录成功」——日志说成功、界面却进不去（面板渲染一瞬后被自身接口的
// 401 弹回登录页）。换成 IP 访问能用，只是因为 Cookie 按 host 分键、IP 那个 host 上没有残留。
//
// 关键点：服务端**无法**在 HTTP 下清掉那条残留——删除也是一条 Set-Cookie，会被同一条规则
// 丢弃，而非安全来源又不允许设置 Secure。所以唯一可行的解法是换名字绕开同名冲突。
//
// 三个名字各自的角色：
//   - sessionCookie（明文）与 sessionCookieSecure（TLS）：写入用。两者名字不同，
//     因此任何一条都不会同时以「带 Secure」和「不带 Secure」两种形态存在，上述冲突无法再发生。
//   - sessionCookieLegacy：**只读不写**，即修复前两种协议共用的那个名字。留着它有两个作用：
//     升级后已登录的用户不会被强制登出一次；而修复前就已陷入上述状态的浏览器里，
//     残留的 Secure "mantou_session" 也再挡不住新名字的 Cookie——升级即自愈，
//     用户不需要手动清 Cookie。
//
// __Host- 前缀顺带是一道硬化：浏览器强制该前缀的 Cookie 必须带 Secure、来自安全来源、
// Path=/ 且不带 Domain（本代码本来就满足后两条），等于从协议层面禁止它在明文连接上出现。
const (
	sessionCookie       = "mantou_sess"           // 非 TLS 连接（写 + 读）
	sessionCookieSecure = "__Host-mantou_session" // TLS 连接（写 + 读）
	sessionCookieLegacy = "mantou_session"        // 修复前的旧名字（只读，永不写入）
)

// ctxSessionToken 是 authRequired 校验通过后，把「本次请求真正用的那条令牌」
// 存进 gin 上下文的键名。退出登录、关标签信标、改密码换发这些接口都要作用在
// **同一条**令牌上，各自再去请求里猜一遍必然会与鉴权那次的结论分叉（见 extractToken）。
const ctxSessionToken = "sessionToken"

// requestLogger 仅记录服务端异常（5xx）。普通请求（2xx/3xx/4xx）不再逐条刷屏，
// 避免日志被面板访问记录淹没。如需排查访问情况，可将全局日志级别调为 debug，
// 此时访问日志会以 debug 级别输出（默认 info 级别下不出现）。
func (s *Server) requestLogger() gin.HandlerFunc {
	log := s.deps.Log
	return func(c *gin.Context) {
		start := time.Now()
		c.Next()
		args := []any{
			"method", c.Request.Method,
			"host", c.Request.Host,
			"path", c.Request.URL.Path,
			"status", c.Writer.Status(),
			"ms", time.Since(start).Milliseconds(),
			"ip", c.ClientIP(),
		}
		if c.Writer.Status() >= 500 {
			log.Error("面板访问异常", args...)
			return
		}
		log.Debug("面板访问", args...)
	}
}

// securityHeaders 给面板的每一个响应带上四道与内容无关的安全头。
//
// 起因（审计 NEW-3）：这三类头此前只存在于**用户站点**那一侧
// （internal/modules/webservice/middleware.go 的 withSecurityHeaders，由 WebChild.FrameDeny
// 控制），面板自己一个都不发。
//
// # 逐项理由与取值
//
//   - frame-ancestors 'none' + X-Frame-Options: DENY —— 反点击劫持。
//     两个都发：CSP 的 frame-ancestors 是现行标准且优先级更高，X-Frame-Options 留给
//     老浏览器兜底（与 webservice 那侧同一取舍）。取 none/DENY 而不是 self/SAMEORIGIN：
//     面板前端一个 iframe 都不用（web/src 全域无 iframe），没有需要放行的自嵌套场景，
//     那就取最严的一格。
//
//     单独看，这一道今天挡不住什么：会话 Cookie 是 SameSite=Lax，跨站 iframe 里根本
//     带不上 Cookie，被框住的只会是登录页。它的价值在于**不依赖那个前提**——
//     哪天有人为了适配某个反代把 SameSite 放宽成 None，这道头是唯一还站着的那个。
//
//   - Referrer-Policy: same-origin —— 同源请求照旧带完整 Referer（面板内部本来就没人读它，
//     CSRF 判定走 Sec-Fetch-Site / Origin，见 csrfGuard），跨源一律不带。
//     挡的是「关于」页与「Web 服务」页那些 target=_blank 外链把面板 origin + 访问路径前缀
//     （basePath，常被当作一层隐蔽性）送给第三方站点。
//     浏览器默认的 strict-origin-when-cross-origin 仍会送出 origin，不够。
//
//   - X-Content-Type-Options: nosniff —— 此前只有 /uploads/* 与错误页带（server.go:327、
//     internal/errpage），API 的 JSON 与前端静态资源都没有。JSON 里能出现用户填的字符串，
//     被嗅探成 HTML 就是一条同域脚本执行路径；代价只有"类型标错的脚本/样式表会被拦"，
//     而这些资源的 Content-Type 由 buildAssetETags 那一侧的 embed FS 决定，不会标错。
//
// # 为什么不发 default-src / script-src
//
// 那是另一件事（抗 XSS），且面板前端是 Vue + Element Plus：运行期会注入 style 标签，
// 收紧 script-src/style-src 必须配合构建产物一起改并逐页验证。本次只补齐审计点到的三类；
// 真要上完整 CSP，得先有一轮浏览器侧的回归。
//
// # 为什么排在最外层（仅次于恢复中间件）
//
// firewallGuard 的注释写着"除恢复之外没有东西该排在访问控制前面——被拒的来源不该有机会
// 触发日志、压缩、CSRF 判定等任何工作"。这一条是那句话的**唯一例外**，理由是它的成本就是
// 四次 header map 写入，与它自己那句 errpage.Write（渲染 + 写一整页 HTML）差着数量级，
// 谈不上"给被拒的来源做工作"。换来的是一条没有例外的性质：面板发出的每个响应都带这四道头，
// 包括防护自己的 403 与 429、恢复中间件兜下的 500。有例外的话，日后每加一条早退路径
// 都得重新问一遍"这条带不带头"。
func (s *Server) securityHeaders() gin.HandlerFunc {
	return func(c *gin.Context) {
		h := c.Writer.Header()
		h.Set("Content-Security-Policy", "frame-ancestors 'none'")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "same-origin")
		h.Set("X-Content-Type-Options", "nosniff")
		c.Next()
	}
}

// csrfGuard 对状态变更型请求（POST/PUT/DELETE/PATCH）做同源校验，防御跨站请求伪造。
//
// 判定顺序与理由：
//
//  1. Sec-Fetch-Site（Chrome 76+ / Firefox 90+ / Safari 16.4+）。这个头由浏览器自己填，
//     页面脚本改不了，比 Origin 更可信，所以排在最前。取 same-origin 与 none（地址栏、
//     书签这类用户直接发起的导航）为放行；same-site 与 cross-site 一律拒——同站不等于同源，
//     旁边一个子域被拿下就能打过来。
//     顺带修掉一个反代场景：代理改写 Host 时 Origin 比对必然不相等（下面 sameOrigin 比的是
//     u.Host == r.Host），而浏览器在这种部署里照样会给出 same-origin，于是这一步先放行。
//
//  2. 没有 Sec-Fetch-Site 的（旧浏览器、非浏览器客户端）退回 Origin 比对，与之前一致。
//
//  3. 两个头都没有——这是本次收紧的那一格，原先直接放行。放行等于**整道防线可以被绕过**：
//     跨站表单在少数旧浏览器上不带 Origin，而 Cookie 会照常被带上。
//     现在改为：**带着会话 Cookie 就拒**。CSRF 的载体只有 Cookie（浏览器自动附加），
//     靠 Authorization: Bearer 鉴权的请求跨站根本发不出来——自定义头会触发 CORS 预检，
//     本服务不放行任何跨源预检。所以脚本调接口的正确姿势（先 POST /auth/login 拿令牌，
//     此后带 Bearer）完全不受影响，登录那一跳本身也还没有 Cookie、照常通过。
//
// 唯一被这条收紧挡住的是「拿 Cookie 当长期凭据、又不设任何请求头」的非浏览器脚本；
// 那恰好也是唯一在 CSRF 意义上不可区分于攻击者的调用形态。补一个 -H "Origin: <面板地址>"
// 即可，或改用 Bearer。
func (s *Server) csrfGuard() gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Request.Method == http.MethodGet ||
			c.Request.Method == http.MethodHead ||
			c.Request.Method == http.MethodOptions {
			c.Next()
			return
		}
		switch c.GetHeader("Sec-Fetch-Site") {
		case "same-origin", "none":
			c.Next()
			return
		case "same-site", "cross-site":
			s.rejectCrossSite(c)
			return
		}
		if origin := c.GetHeader("Origin"); origin != "" {
			if sameOrigin(c.Request, origin) {
				c.Next()
				return
			}
			s.rejectCrossSite(c)
			return
		}
		if hasSessionCookie(c.Request) {
			s.rejectCrossSite(c)
			return
		}
		c.Next()
	}
}

// rejectCrossSite 拒掉一个来源可疑的状态变更请求。
// 以 WARN 记录：这既可能是真的 CSRF 尝试，也可能是某个脚本升级后开始被拦，
// 两种情况都需要在日志里看得见，否则表现为"面板某个操作莫名 403"。
func (s *Server) rejectCrossSite(c *gin.Context) {
	s.deps.Log.Warn("已拒绝跨站状态变更请求",
		"method", c.Request.Method,
		"path", c.Request.URL.Path,
		"origin", c.GetHeader("Origin"),
		"fetchSite", c.GetHeader("Sec-Fetch-Site"),
		"ip", c.ClientIP(),
	)
	respondError(c, http.StatusForbidden, "请求来源不被允许")
	c.Abort()
}

// sameOrigin 判断 origin 是否与请求 Host 同源（比较 host，含端口）。
func sameOrigin(r *http.Request, origin string) bool {
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" {
		return false
	}
	return u.Host == r.Host
}

// hasSessionCookie 判断请求是否带着会话 Cookie（三个名字任一，见 extractToken）。
// 只看"有没有"，不校验令牌本身——csrfGuard 排在鉴权之前，此处要的只是
// "这次请求会不会被 Cookie 自动鉴权"这一个事实。
func hasSessionCookie(r *http.Request) bool {
	for _, name := range [3]string{sessionCookie, sessionCookieSecure, sessionCookieLegacy} {
		if ck, err := r.Cookie(name); err == nil && ck.Value != "" {
			return true
		}
	}
	return false
}

// authRequired 校验会话令牌；未登录返回 401。
// 校验分两层：先验 JWT 签名与有效期，再验服务端会话状态——
// 关闭最后一个标签 / 显式退出后即使 JWT 未过期也应失效；刷新页面在宽限内复用同一会话则保活。
//
// 请求可能同时带来多条候选令牌（Bearer 头 + 几个名字的 Cookie，见 sessionTokens），
// 这里**逐条试到有一条通过为止**。只认第一条的话，浏览器里任何一条过期或残留的 Cookie
// 都能把同一个请求里那条有效的令牌挡在门外，而使用者看到的只是一个无从解释的 401。
func (s *Server) authRequired() gin.HandlerFunc {
	return func(c *gin.Context) {
		tokens := s.sessionTokens(c)
		if len(tokens) == 0 {
			respondUnauthorized(c, "未登录")
			c.Abort()
			return
		}
		// Snapshot 而非 Get：本中间件在**每个已认证 API 请求**上执行，只读三个字段
		// （JWT 密钥、用户名、闲置超时），没有理由为此深拷贝整份配置（面板轮询本就持续产生请求）。
		cfg := s.deps.Config.Snapshot()
		// 后台轮询/信标请求带 X-Mantou-Silent:1，revive=false → 不触发救活，
		// 使「关闭最后一个标签页」能可靠到期失效，不受周期轮询干扰。
		//
		// 闲置超时按当次请求的配置快照传入，改完设置立刻生效、不必重启面板。
		// 它管的是「面板多久联系不上你就当你已离开」，与令牌时长（从登录起算的绝对上限）
		// 各管一头；用途是给关窗口注销兜底——信标发不出去时（崩溃/强杀/断电）由它收尾。
		silent := c.GetHeader("X-Mantou-Silent") == "1"
		idle := time.Duration(cfg.Auth.SessionIdleMinutes) * time.Minute

		var token, username, reason string
		for _, cand := range tokens {
			name, err := auth.ParseToken(cfg.Auth.JWTSecret, cand)
			if err != nil {
				// 只留第一条（优先级最高那条）的原因：单条候选时与逐条判定的旧行为逐字一致。
				if reason == "" {
					reason = "会话无效或已过期"
				}
				continue
			}
			// 账户主体一致性校验：修改用户名后，旧令牌的 subject 不再等于当前用户名，
			// 其余旧会话应一并失效（此前仅注销当前会话，旧会话因未比对 sub 而残留有效）。
			if name != cfg.Auth.Username {
				if reason == "" {
					reason = "会话已失效，请重新登录"
				}
				continue
			}
			// 服务端会话校验：关闭/退出后失效；刷新场景在宽限内被 valid() 救活。
			// 排在最后一个：它带副作用（保活/救活），不该为一条签名都对不上的候选去碰会话表。
			if _, ok := s.sessions.valid(cand, name, !silent, idle); !ok {
				if reason == "" {
					reason = "会话已失效，请重新登录"
				}
				continue
			}
			token, username = cand, name
			break
		}
		if token == "" {
			respondUnauthorized(c, reason)
			c.Abort()
			return
		}
		c.Set(ctxSessionToken, token)
		c.Set("username", username)
		c.Next()
	}
}

// sessionTokens 收集本次请求带来的候选会话令牌，按「优先采信」的顺序返回，去重。
//
// Bearer 排在 Cookie 之前：请求头是调用方**显式**写上去的，Cookie 是浏览器自动附带的。
// 两者同时出现时，显式的那条才是调用方的意思——反过来排，一条早先留在浏览器里的
// 残留 Cookie 就能永久盖掉脚本手动带上的有效令牌，且没有任何办法从服务端清掉它
// （清除也是一条 Set-Cookie，见本文件顶部三个 Cookie 名字的由来）。
//
// 三个 Cookie 名字都要试，且先试与当前协议相符的那个：协议切换后浏览器可能同时存着多条，
// 只认一个名字会在切回去时拿到另一时期的旧令牌。旧名字排在最后，仅用于让升级前已登录的
// 会话继续有效。
func (s *Server) sessionTokens(c *gin.Context) []string {
	out := make([]string, 0, 4)
	add := func(v string) {
		if v == "" {
			return
		}
		for _, had := range out {
			if had == v {
				return
			}
		}
		out = append(out, v)
	}
	if h := c.GetHeader("Authorization"); strings.HasPrefix(h, "Bearer ") {
		add(strings.TrimSpace(strings.TrimPrefix(h, "Bearer ")))
	}
	names := [3]string{sessionCookie, sessionCookieSecure, sessionCookieLegacy}
	if c.Request.TLS != nil {
		names = [3]string{sessionCookieSecure, sessionCookie, sessionCookieLegacy}
	}
	for _, name := range names {
		if v, err := c.Cookie(name); err == nil {
			add(v)
		}
	}
	return out
}

// extractToken 返回本次请求的会话令牌。
//
// authRequired 跑过之后一律取它验过的那一条：退出登录、关标签信标、改密码换发这几个接口
// 都要作用在鉴权认定的那条令牌上。各自重新猜一遍的话，请求里带着多条候选时就会与鉴权
// 那次的结论分叉——例如改密码那条路上 revokeAll(除本条之外全撤) 会把真正在用的会话撤掉，
// 留下一条早已失效的。
//
// 上下文里没有（未经 authRequired 的直接调用，例如单元测试）时退回候选里优先级最高的一条。
func (s *Server) extractToken(c *gin.Context) string {
	if v, ok := c.Get(ctxSessionToken); ok {
		if tok, _ := v.(string); tok != "" {
			return tok
		}
	}
	if toks := s.sessionTokens(c); len(toks) > 0 {
		return toks[0]
	}
	return ""
}

// respondOK 返回统一的成功响应体。
func respondOK(c *gin.Context, data any) {
	c.JSON(http.StatusOK, gin.H{"data": data})
}

// respondError 返回统一的错误响应体。
func respondError(c *gin.Context, status int, msg string) {
	c.JSON(status, gin.H{"error": msg})
}

// respondUnauthorized 401 的统一出口：人拿浏览器撞上来的给一页「需要先登录」，
// 面板自己的请求仍拿到原来那句 JSON。
//
// 分两种是因为这两类调用方要的东西不一样。面板前端靠状态码跳登录页、靠 error 字段
// 显示原因（见 web/src/api/client.ts），塞一页 HTML 过去只会让提示变成一堆标签；
// 而直接在地址栏敲一个需要鉴权的地址时，一行 {"error":"未登录"} 既不像回应，
// 也不说明下一步该做什么。
//
// 卡片上只有状态码和一句话，四件事刻意都不写：
//   - 不写具体原因。「没带令牌」「令牌过期」「会话已失效」对使用者是同一件事
//     （重新登录），对探测者却是有用的差异——能区分"猜中了一个有效路径但没登录"
//     和"这个令牌曾经有效"。原因照常留在 msg 里给前端和日志。
//   - 不写面板地址、不写登录页在哪。这是本轮明确要求去掉的那类提示：
//     指路等于替对方把找入口这一步做完了。
//   - 不回显请求路径（Where 留空）。对方知道自己敲了什么，写出来只是让这一页
//     看着像"确实有这个东西"。
//   - 不带版本号之类的任何环境信息。
func respondUnauthorized(c *gin.Context, msg string) {
	if !errpage.WantsHTML(c.Request) {
		respondError(c, http.StatusUnauthorized, msg)
		return
	}
	errpage.Write(c.Writer, c.Request, errpage.Page{
		Status: http.StatusUnauthorized,
		Title:  "需要先登录",
		Plain:  msg,
	})
}
