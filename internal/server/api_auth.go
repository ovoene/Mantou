package server

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"mantou/internal/auth"
	"mantou/internal/config"
)

// initStatusResp 描述面板初始化状态。
//
// 这里**只有** initialized 一个字段，不带版本号：这个接口免鉴权，任何人都能取到它的返回值，
// 而精确版本号足以让人对着漏洞列表挑一个来试，且整个过程不留下任何失败痕迹。
// 版本号已挪到登录之后的 /meta/version（见 registerRoutes）。
//
// initialized 必须留在免鉴权这一侧：前端要靠它决定首屏是画初始化向导还是登录页
// （见 web/src/stores/auth.ts 的 checkInit），而那一刻还没有任何会话。
// 它只泄露"这台机器装过没装过"，没有可利用的粒度。
type initStatusResp struct {
	Initialized bool `json:"initialized"`
}

// handleInitStatus 返回是否已完成初始化（是否需要展示初始化向导）。
func (s *Server) handleInitStatus(c *gin.Context) {
	cfg := s.deps.Config.Snapshot()
	respondOK(c, initStatusResp{Initialized: cfg.Auth.Initialized})
}

// initSetupReq 是初始化向导提交的数据。
type initSetupReq struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Language string `json:"language"`
}

// panelHasAdmin 判断面板是否已经有管理员账户。
//
// 初始化接口免鉴权，它放不放行完全取决于这个判断，所以刻意**不只看** Initialized 这一个
// 布尔值：那个标记为假而账户仍在时（手改过的配置、一份缺 auth.initialized 键的备份），
// 只看它就等于把「注册管理员」这道门对整个网络打开，而且注册成功会覆盖掉原有账户。
// config.migrate 已经在「从磁盘加载」与「配置导入」两条路上把这个不变量补齐，
// 这里是第二道——两道都在，才不必要求以后每个新增的配置入口都记得补。
func panelHasAdmin(a config.Auth) bool {
	return a.Initialized || a.Username != "" || a.PasswordHash != ""
}

// handleInitSetup 完成首次初始化：设置管理员账号密码。仅在未初始化时可用。
func (s *Server) handleInitSetup(c *gin.Context) {
	// 限流：面板暴露在网络中但尚未初始化时，防止被恶意抢注管理员账户。
	if ok, retry := s.setupLimiter.Allowed(c.ClientIP()); !ok {
		c.Header("Retry-After", strconv.Itoa(retry))
		respondError(c, http.StatusTooManyRequests, "初始化尝试过于频繁，请稍后再试")
		return
	}
	var req initSetupReq
	if err := c.ShouldBindJSON(&req); err != nil {
		s.setupLimiter.Fail(c.ClientIP())
		respondError(c, http.StatusBadRequest, "请求参数无效")
		return
	}
	req.Username = strings.TrimSpace(req.Username)
	if len(req.Username) < 3 {
		s.setupLimiter.Fail(c.ClientIP())
		respondError(c, http.StatusBadRequest, "用户名至少 3 个字符")
		return
	}
	if len(req.Password) < 6 {
		s.setupLimiter.Fail(c.ClientIP())
		respondError(c, http.StatusBadRequest, "密码至少 6 个字符")
		return
	}

	cfg := s.deps.Config.Snapshot()
	if panelHasAdmin(cfg.Auth) {
		respondError(c, http.StatusConflict, "面板已初始化")
		return
	}

	hash, err := auth.HashPassword(req.Password)
	if err != nil {
		respondError(c, http.StatusInternalServerError, "密码处理失败")
		return
	}

	// 在写锁内再次校验（修复 TOCTOU 竞态）：
	// 上方快速判断与 bcrypt 之间无互斥，两个不同来源 IP 的并发初始化请求可能同时越过快速判断；
	// 必须在 Config.Update 的 mutate 回调（持写锁）内二次确认，避免后到者覆盖先到者、
	// 或攻击者抢先初始化导致管理员再也无法初始化（已 initialized）。
	// 判定与上方同口径走 panelHasAdmin：两处若不一致，宽的那处就是实际生效的那处。
	var alreadyInit bool
	err = s.deps.Config.Update(func(c *config.Config) {
		if panelHasAdmin(c.Auth) {
			alreadyInit = true
			return
		}
		c.Auth.Username = req.Username
		c.Auth.PasswordHash = hash
		c.Auth.Initialized = true
		if req.Language == "en-US" || req.Language == "zh-CN" {
			c.Settings.Language = req.Language
		}
	})
	if err != nil {
		s.setupLimiter.Fail(c.ClientIP())
		respondError(c, http.StatusInternalServerError, "保存配置失败")
		return
	}
	if alreadyInit {
		respondError(c, http.StatusConflict, "面板已初始化")
		return
	}

	s.deps.Log.Info("面板初始化完成", "username", req.Username)
	respondOK(c, gin.H{"ok": true})
}

// loginReq 是登录请求体。
type loginReq struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// handleLogin 校验账号密码，成功后下发会话 Cookie。
func (s *Server) handleLogin(c *gin.Context) {
	var req loginReq
	if err := c.ShouldBindJSON(&req); err != nil {
		respondError(c, http.StatusBadRequest, "请求参数无效")
		return
	}

	ip := c.ClientIP()
	ipKey := "ip:" + ip
	// 复合键：账户锁定与来源 IP 绑定，避免「针对已知管理员账户跨 IP 连续失败」触发全局账户锁定 DoS。
	userKey := "ip:" + ip + ":user:" + strings.TrimSpace(req.Username)
	// 复合限流：既按来源 IP 限制爆破频率，也按被尝试的账户名限制（防止单账户跨 IP 爆破、多账户同 IP 爆破）。
	if ok, retry := s.limiter.Allowed(ipKey); !ok {
		c.Header("Retry-After", strconv.Itoa(retry))
		respondError(c, http.StatusTooManyRequests, "登录尝试过于频繁，请稍后再试")
		return
	}
	if ok, retry := s.limiter.Allowed(userKey); !ok {
		c.Header("Retry-After", strconv.Itoa(retry))
		respondError(c, http.StatusTooManyRequests, "该账户登录尝试过于频繁，请稍后再试")
		return
	}

	cfg := s.deps.Config.Snapshot()
	if !cfg.Auth.Initialized {
		respondError(c, http.StatusConflict, "面板尚未初始化")
		return
	}

	ok := strings.TrimSpace(req.Username) == cfg.Auth.Username && auth.VerifyPassword(cfg.Auth.PasswordHash, req.Password)
	if !ok {
		s.limiter.Fail(ipKey)
		s.limiter.Fail(userKey)
		s.deps.Log.Warn("登录失败", "username", req.Username, "ip", ip)
		respondError(c, http.StatusUnauthorized, "用户名或密码错误")
		return
	}
	s.limiter.Reset(ipKey)
	s.limiter.Reset(userKey)

	ttl := time.Duration(cfg.Auth.SessionHours) * time.Hour
	if ttl <= 0 {
		ttl = time.Hour
	}
	token, err := auth.IssueToken(cfg.Auth.JWTSecret, cfg.Auth.Username, ttl)
	if err != nil {
		respondError(c, http.StatusInternalServerError, "签发会话失败")
		return
	}

	// 注册服务端会话状态（"关闭才退、刷新保活"的前提）。
	s.sessions.add(token, cfg.Auth.Username, ttl)

	// 会话 Cookie：不设置 Max-Age，浏览器/标签页关闭即失效（满足"关闭页面自动退出、下次须重新登录"）。
	// JWT 自身仍带 SessionHours 的服务端有效期作为兜底——即便浏览器一直开着，超过该时长也会失效。
	s.setSessionCookie(c, token)
	s.deps.Log.Info("登录成功", "username", cfg.Auth.Username, "ip", ip)
	// 仅通过 HttpOnly+SameSite Cookie 维持会话；不再在响应体下发 Bearer token，
	// 避免 XSS 读取后绕过 CSRF 守卫。前端已仅依赖 Cookie 访问 API。
	respondOK(c, gin.H{
		"username": cfg.Auth.Username,
	})
}

// handleLogout 显式退出：立即删除服务端会话并清除 Cookie。
func (s *Server) handleLogout(c *gin.Context) {
	username, _ := c.Get("username")
	if token := s.extractToken(c); token != "" {
		s.sessions.remove(token) // 立即失效，不接受宽限救活（与"主动退出"语义一致）。
	}
	s.deps.Log.Info("退出登录", "username", username, "ip", c.ClientIP())
	s.clearSessionCookies(c)
	respondOK(c, gin.H{"ok": true})
}

// handleSessionClose 由前端"关闭最后一个标签"信标调用（navigator.sendBeacon）。
// 将服务端会话标记为待删除（进入宽限），但【不】清除 Cookie——
// 刷新场景在宽限内复用同一会话会被 valid() 救活（保活）；真正关闭则宽限到期才失效。
// 因此刷新页面不会退出，而关闭最后一个标签（或浏览器）后下次访问须重新登录。
func (s *Server) handleSessionClose(c *gin.Context) {
	if token := s.extractToken(c); token != "" {
		s.sessions.markPendingDelete(token)
	}
	username, _ := c.Get("username")
	s.deps.Log.Info("会话待关闭（宽限）", "username", username, "ip", c.ClientIP())
	respondOK(c, gin.H{"ok": true})
}

// handleMe 返回当前登录用户信息。
// 只回 username：二次验证（Auth.TwoFA）本期未实现，曾经下发的 twoFA 字段前端从未使用，
// 留着只会让"接口说有、界面没有"的假象一直存在。真正实现时再连同界面一起加回来。
func (s *Server) handleMe(c *gin.Context) {
	username, _ := c.Get("username")
	respondOK(c, gin.H{"username": username})
}

// setSessionCookie 下发会话 Cookie。
//
// 不设 Max-Age（会话 Cookie，浏览器关闭即失效）；清除走 clearSessionCookies，
// 故这里不再接收 maxAge —— 两个方向的 Cookie 名与 Secure 取值规则并不对称，
// 合成一个函数只会让「清除时要不要按协议选名字」这种问题反复被答错。
//
// Secure 属性与 Cookie 名一律按**本次请求的真实协议**（c.Request.TLS）决定，不读配置：
//   - 面板只有一个监听端口，改 Panel.HTTPS.Enabled 要等重启才换协议。读配置就会在「已保存、
//     尚未重启」这段窗口里给明文连接打上 Secure，浏览器按规范整条丢弃 Set-Cookie，
//     那段时间内谁都登不进来，而日志照样写「登录成功」——正是本次 bug 的同源问题；
//   - 也不看 X-Forwarded-Proto：Router 里 SetTrustedProxies(nil) 是刻意的，任何客户端都能
//     伪造该头，据此决定 Secure 等于把「Cookie 能否在明文里出现」交给攻击者。
//     真正跑在 TLS 反代后面的部署，面板本身收到的是明文连接，此时用非 Secure 的
//     sessionCookie 是唯一能工作的选择。
//
// 顺带把旧名字（sessionCookieLegacy）作废：新会话已落在新名字上，留着旧的只会让浏览器里
// 长期躺着一条谁也不会再用的令牌。明文连接下若那条旧 Cookie 带 Secure（修复前的 HTTPS 时期
// 留下的），这次删除会被浏览器丢弃——删不掉也无妨，它在明文连接上根本不会被发送，
// 而新名字不与它冲突，登录照样成功。
func (s *Server) setSessionCookie(c *gin.Context, token string) {
	secure := c.Request.TLS != nil
	name := sessionCookie
	if secure {
		name = sessionCookieSecure
	}
	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie(name, token, 0, "/", "", secure, true)
	c.SetCookie(sessionCookieLegacy, "", -1, "/", "", secure, true)
}

// clearSessionCookies 清除全部三个名字的会话 Cookie（显式退出用）。
//
// 为什么都清：协议切换后浏览器可能同时存着多条，只清相符的那条会把其余的留到下次
// 切回去时复活（服务端会话已删，表现为「刚退出就被 401 弹回登录页」的多余往返）。
// 明文连接下清不掉带 Secure 的那些（删除同样是一条 Set-Cookie，会被 Strict Secure Cookies
// 规则丢弃），但它们在明文连接上根本不会被发送，且服务端会话已在调用方删除，不影响正确性。
func (s *Server) clearSessionCookies(c *gin.Context) {
	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie(sessionCookie, "", -1, "/", "", false, true)
	c.SetCookie(sessionCookieSecure, "", -1, "/", "", true, true)
	// 旧名字在两种协议下都可能存在，且明文时期那条不带 Secure、HTTPS 时期那条带 Secure，
	// 各发一条删除，能删掉哪条算哪条。
	c.SetCookie(sessionCookieLegacy, "", -1, "/", "", false, true)
	c.SetCookie(sessionCookieLegacy, "", -1, "/", "", true, true)
}
