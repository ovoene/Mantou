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

// csrfGuard 对状态变更型请求（POST/PUT/DELETE/PATCH）做轻量同源校验：
// 若请求携带 Origin 头且与当前 Host 不同源，则拒绝，防御跨站请求伪造（CSRF）。
// 同源请求（含本应用前端调用与 sendBeacon 软注销信标）的 Origin 与 Host 一致，不受影响；
// 未携带 Origin 的请求（如部分同源导航）不拦截。
func (s *Server) csrfGuard() gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Request.Method == http.MethodGet ||
			c.Request.Method == http.MethodHead ||
			c.Request.Method == http.MethodOptions {
			c.Next()
			return
		}
		origin := c.GetHeader("Origin")
		if origin == "" || sameOrigin(c.Request, origin) {
			c.Next()
			return
		}
		respondError(c, http.StatusForbidden, "请求来源不被允许")
		c.Abort()
	}
}

// sameOrigin 判断 origin 是否与请求 Host 同源（比较 host，含端口）。
func sameOrigin(r *http.Request, origin string) bool {
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" {
		return false
	}
	return u.Host == r.Host
}

// authRequired 校验会话令牌；未登录返回 401。
// 校验分两层：先验 JWT 签名与有效期，再验服务端会话状态——
// 关闭最后一个标签 / 显式退出后即使 JWT 未过期也应失效；刷新页面在宽限内复用同一会话则保活。
func (s *Server) authRequired() gin.HandlerFunc {
	return func(c *gin.Context) {
		token := s.extractToken(c)
		if token == "" {
			respondUnauthorized(c, "未登录")
			c.Abort()
			return
		}
		// Snapshot 而非 Get：本中间件在**每个已认证 API 请求**上执行，只读三个字段
		// （JWT 密钥、用户名、闲置超时），没有理由为此深拷贝整份配置（面板轮询本就持续产生请求）。
		cfg := s.deps.Config.Snapshot()
		username, err := auth.ParseToken(cfg.Auth.JWTSecret, token)
		if err != nil {
			respondUnauthorized(c, "会话无效或已过期")
			c.Abort()
			return
		}
		// 账户主体一致性校验：修改用户名后，旧令牌的 subject 不再等于当前用户名，
		// 其余旧会话应一并失效（此前仅注销当前会话，旧会话因未比对 sub 而残留有效）。
		if username != cfg.Auth.Username {
			respondUnauthorized(c, "会话已失效，请重新登录")
			c.Abort()
			return
		}
		// 服务端会话校验：关闭/退出后失效；刷新场景在宽限内被 valid() 救活。
		// 后台轮询/信标请求带 X-Mantou-Silent:1，revive=false → 不触发救活，
		// 使「关闭最后一个标签页」能可靠到期失效，不受周期轮询干扰。
		//
		// 闲置超时按当次请求的配置快照传入，改完设置立刻生效、不必重启面板。
		// 它管的是「面板多久联系不上你就当你已离开」，与令牌时长（从登录起算的绝对上限）
		// 各管一头；用途是给关窗口注销兜底——信标发不出去时（崩溃/强杀/断电）由它收尾。
		silent := c.GetHeader("X-Mantou-Silent") == "1"
		idle := time.Duration(cfg.Auth.SessionIdleMinutes) * time.Minute
		if _, ok := s.sessions.valid(token, username, !silent, idle); !ok {
			respondUnauthorized(c, "会话已失效，请重新登录")
			c.Abort()
			return
		}
		c.Set("username", username)
		c.Next()
	}
}

// extractToken 依次从 Cookie 与 Authorization 头提取令牌。
//
// 三个名字都要试，且先试与当前协议相符的那个（见 sessionCookie / sessionCookieSecure /
// sessionCookieLegacy）：协议切换后浏览器可能同时存着多条，只认一个名字会在切回去时
// 拿到另一时期的旧令牌。取相符者优先即可；旧名字排在最后，仅用于让升级前已登录的会话继续有效。
func (s *Server) extractToken(c *gin.Context) string {
	names := [3]string{sessionCookie, sessionCookieSecure, sessionCookieLegacy}
	if c.Request.TLS != nil {
		names = [3]string{sessionCookieSecure, sessionCookie, sessionCookieLegacy}
	}
	for _, name := range names {
		if v, err := c.Cookie(name); err == nil && v != "" {
			return v
		}
	}
	h := c.GetHeader("Authorization")
	if strings.HasPrefix(h, "Bearer ") {
		return strings.TrimSpace(strings.TrimPrefix(h, "Bearer "))
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
