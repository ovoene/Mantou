package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"

	"mantou/internal/config"
	"mantou/internal/dnsprovider"
	"mantou/internal/errpage"
	"mantou/internal/logx"
	"mantou/internal/metrics"
	"mantou/internal/module"
	"mantou/internal/modules/cert"
	"mantou/internal/modules/cron"
	"mantou/internal/modules/ddns"
	"mantou/internal/modules/notify"
	"mantou/internal/modules/webhook"
	"mantou/internal/modules/webservice"
	"mantou/internal/modules/wol"
	"mantou/internal/runstats"
	"mantou/internal/strutil"
)

// Deps 是服务器的依赖集合。
type Deps struct {
	Config  *config.Manager
	Log     *logx.Logger
	Metrics *metrics.Collector
	Modules *module.Manager
	// WebFS 是打包后的前端静态资源（web/dist 内容）。
	WebFS fs.FS
	// DataDir 是数据目录，用于存放上传的背景图等用户资源。
	DataDir string

	// LogFile 是轮转日志文件句柄，供「手动清空所有日志」接口复用（重置文件而非重建）。
	LogFile *logx.RotatingFile

	// Stats 是列表页上那几个统计数字（最近一次、累计次数）的存放处。
	// 只在内存里、重启归零，所有模块加起来 1 MiB 上限（见 runstats 包说明）。
	// 为 nil 时列表照样返回，统计字段一律是零值——测试里没装它的地方就是这样。
	Stats *runstats.Store

	// 功能模块句柄，用于触发即时动作（唤醒、立即更新、导入/签发证书、立即执行计划任务等）。
	DDNS    *ddns.Module
	WOL     *wol.Module
	Cert    *cert.Module
	Cron    *cron.Module
	Web     *webservice.Module
	Notify  *notify.Module
	Webhook *webhook.Module

	// OnConfigChanged 在配置变更后调用，用于热重载所有模块。
	OnConfigChanged func()
	RestartPanel    func()
	// RestartExec 由 main 注入：请求用磁盘上已替换的新二进制替换当前进程映像
	// （自更新场景）。成功则当前进程被新二进制接管、无需外部守护；返回 error 时调用方回退为 os.Exit。
	// nil 表示未注入，调用方直接 os.Exit(0) 交由外部守护拉起。
	RestartExec func(path string) error
}

// Server 封装 HTTP 服务与路由。
type Server struct {
	deps         Deps
	http         *http.Server
	limiter      *loginLimiter
	setupLimiter *loginLimiter    // 初始化接口限流，防止面板暴露期间被抢注管理员
	wakeLimiter  *wakeLimiter     // 手动网络唤醒限流，按设备计量（见 wakelimit.go）
	sessions     *sessionRegistry // 服务端会话状态（"关闭才退、刷新保活"）
	// firewall 面板入站防火墙：连接层拦截 + 请求层限速/自动封禁（见 firewall.go）。
	// 它自己每次都从配置快照读策略，因此改设置立刻生效、不需要重启面板。
	firewall     *panelFirewall
	dnsProviders []dnsprovider.Info
	basePath     string // 规范化后的访问路径前缀（""或"/xxx"）
	indexHTML    []byte // 注入 base 前缀后的前端入口页（basePath 非空时使用）
	// assetETags 嵌入前端资源的强校验符，键是嵌入 FS 内的相对路径。
	// 启动时算一次（见 assets.go）；只存哈希串，不存文件内容。
	assetETags map[string]string
	panelHTTPS bool
	panelCert  *tls.Certificate
	backupMu   sync.Mutex
	restartMu  sync.Mutex
	restarting bool
	// bodyLimits 上传型路由的请求体上限，键是 gin 的完整路由（含访问路径前缀）。
	// 由 registerUpload 在注册路由时填入；其余路由用 panelBodyLimit。
	bodyLimits map[string]int64
	// resourceCaps 各资源的条数上限，键是资源名（"ddns"、"certs"…）。
	// 由 registerCRUD 在注册路由时填入，之后只读（注册跑在开始服务之前，没有并发写）。
	//
	// 存这一份是为了让界面上那句「最多可添加 N 条」与新增时真正拦人的那个数**同源**。
	// 前端自己抄一个常量也能显示，但抄一遍就有两份：改了后端忘了前端，界面就会写着
	// 一个数、保存时报出另一个数——而这种不一致恰恰只在用户快加满时才暴露。
	resourceCaps map[string]int
}

// New 构建服务器与路由。
func New(deps Deps) *Server {
	if deps.Log == nil {
		deps.Log = logx.L()
	}
	cfg := deps.Config.Snapshot()
	// 登录锁定参数由设置驱动：失败次数上限与锁定时长均可配置（≤0 表示不限制）。
	loginLockFor := time.Duration(cfg.Auth.LoginLockMinutes) * time.Minute
	if loginLockFor <= 0 {
		loginLockFor = 10 * time.Minute
	}
	s := &Server{
		deps:         deps,
		limiter:      newLoginLimiter(cfg.Auth.LoginMaxFails, 5*time.Minute, loginLockFor),
		setupLimiter: newLoginLimiter(10, 10*time.Minute, 10*time.Minute),
		wakeLimiter:  newWakeLimiter(),
		sessions:     newSessionRegistry(),
		firewall:     newPanelFirewall(deps.Config, deps.Log),
		dnsProviders: dnsprovider.Infos(),
		basePath:     normalizeBasePath(cfg.Panel.BasePath),
		panelHTTPS:   cfg.Panel.HTTPS.Enabled,
		bodyLimits:   make(map[string]int64, 3),
		resourceCaps: make(map[string]int, 8),
	}
	if s.panelHTTPS && deps.Cert != nil && cfg.Panel.HTTPS.CertID != "" {
		s.panelCert, _ = deps.Cert.ResolveID(cfg.Panel.HTTPS.CertID)
	}
	s.indexHTML = s.buildIndexHTML()
	s.assetETags = buildAssetETags(deps.WebFS)

	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	// 安全：不信任任何代理（含 X-Forwarded-For / X-Real-IP）。Gin 默认信任所有代理，
	// 会使 c.ClientIP() 取客户端自带的 X-Forwarded-For 头；mantou 部署在多跳 L4 端口转发后，
	// 链路不会注入这些头，若不显式关闭，攻击者可每次伪造 X-Forwarded-For 绕过登录/初始化限流
	// （防爆破、防抢注），并污染审计日志中的来源 IP。置 nil 后 ClientIP() 只取真实对端地址。
	_ = r.SetTrustedProxies(nil)
	r.Use(gin.CustomRecovery(s.recoverPanic))
	// 面板入站防火墙：来源名单 / 访问范围 / 限速 / 自动封禁。
	//
	// 紧跟恢复中间件之后，排在其余一切之前。恢复必须留在最外层（它要兜住这里面的
	// 任何 panic），除此之外没有东西该排在访问控制前面——被拒的来源不该有机会
	// 触发日志、压缩、CSRF 判定等任何工作。
	//
	// 连接层还有更早的一道（见 Start 里的 wrapListener）：那一道在 TLS 握手之前
	// 就把连接关掉，是真正能消掉握手告警的位置。这里管的是握手之后的事——
	// 限速要按请求计数，且 keep-alive 上的旧连接绕得过 Accept。
	r.Use(s.firewallGuard())
	// 面板访问控制（域名限制 / HTTPS 证书域名校验）始终生效。
	r.Use(s.requirePanelCertificateHost())
	r.Use(s.requestLogger())
	// 响应压缩：判定与用户站点静态子项共用一份（见 gzip.go）。
	r.Use(s.compressResponses())
	// 同源校验（防御 CSRF）：仅拦截状态变更型且跨源的请求，同源调用不受影响。
	r.Use(s.csrfGuard())
	// 请求体上限：放在最后一道，紧邻处理器。上面几道都不读请求体，
	// 而处理器一读就已经在分配内存了（见 bodylimit.go）。
	r.Use(s.limitRequestBody())

	s.registerRoutes(r)

	s.http = &http.Server{
		Addr:    addr(cfg.Panel.Listen, cfg.Panel.Port),
		Handler: r,
		// 四道超时/上限一起构成"连接不会被无限占用"的保证；缺任何一条，
		// 一个不读响应或不发完请求头的客户端就能永久占住一个连接与一个 goroutine。
		ReadHeaderTimeout: 10 * time.Second,
		// ReadTimeout 覆盖整个请求（含请求体）。上传类接口（背景图 / 备份导入 / 自更新包）
		// 的正常耗时远超这个值，它们在处理器里用 extendRequestDeadlines 逐请求放宽。
		ReadTimeout: 30 * time.Second,
		// WriteTimeout 从"读完请求头"开始计时，因此它同时也是"处理 + 写响应"的总预算。
		// 面板所有常规接口都是内存/KB 级操作，60 秒是极宽松的上界。
		WriteTimeout: 60 * time.Second,
		// 空闲连接（keep-alive 等待下一个请求）超过该时长即关闭，回收前端页面留下的长连接。
		IdleTimeout: 120 * time.Second,
		// 请求头上限：标准库默认 1 MB，对一个只用单个会话 Cookie 的面板来说过于宽松。
		MaxHeaderBytes: 256 << 10,
		// 面板 HTTPS 正常，但本地探测/客户端中途取消会留下大量良性 TLS 握手 EOF 噪声，
		// 用 NewTLSErrorLog 把这类噪声降级为 DEBUG，真实证书/配置问题仍按 WARN 输出。
		ErrorLog: deps.Log.NewTLSErrorLog(slog.LevelWarn, "面板 TLS 或连接异常"),
	}
	return s
}

// extendRequestDeadlines 把当前请求的读写截止时间统一推到 now+d。
//
// 面板 http.Server 设了全局 ReadTimeout / WriteTimeout 防止连接被无限占用，
// 但上传类接口（背景图 10 MB、备份导入 128 MB、自更新包 20 MB）在慢链路上的正常耗时
// 远超通用值：不逐请求放宽，大文件会在传输中途被服务端掐断，且表现为"上传到一半失败"
// 这种极难归因的错误。放宽仍是有界的——d 到了照样断开。
//
// 依赖 gin 的 ResponseWriter 实现 Unwrap()，ResponseController 才能取到底层连接。
// 若某天不再支持（或运行在不支持 deadline 的连接上），这里会拿到 ErrNotSupported：
// 那只意味着回落到全局超时，功能仍正确，故只记 DEBUG，不打扰用户。
func (s *Server) extendRequestDeadlines(c *gin.Context, d time.Duration) {
	rc := http.NewResponseController(c.Writer)
	until := time.Now().Add(d)
	if err := rc.SetReadDeadline(until); err != nil {
		s.deps.Log.Debug("放宽请求读截止时间失败", "path", c.FullPath(), "err", err.Error())
	}
	if err := rc.SetWriteDeadline(until); err != nil {
		s.deps.Log.Debug("放宽请求写截止时间失败", "path", c.FullPath(), "err", err.Error())
	}
}

// registerRoutes 挂载 API 与前端静态资源（全部位于访问路径前缀之下）。
func (s *Server) registerRoutes(r *gin.Engine) {
	root := r.Group(s.basePath) // basePath 为空时等价于根组
	api := root.Group("/api")
	{
		// 无需鉴权：初始化状态与登录。
		api.GET("/init/status", s.handleInitStatus)
		api.POST("/init/setup", s.handleInitSetup)
		api.POST("/auth/login", s.handleLogin)

		// 需要鉴权的接口。
		authed := api.Group("")
		authed.Use(s.authRequired())
		{
			// 版本信息（版本号 / 官网地址 / 编译时间 / 运行平台）。
			//
			// 这一项原先免鉴权，理由是"非敏感"。但精确版本号是任何人都能匿名取走的一条
			// 指纹：拿到它就能对着已知漏洞列表挑一个来试，而取的过程既不失败也不留痕。
			// 移到登录之后是免费的减面——「关于」页本来就在登录之后才看得到，
			// 前端只在那一页的 onActivated 里拉它（见 web/src/stores/system.ts），功能无变化。
			authed.GET("/meta/version", s.handleVersion)

			// 各资源的条数上限。放在登录之后：这一份说的是"本机能配多少条"，
			// 匿名访客没有理由知道。
			authed.GET("/meta/limits", s.handleResourceLimits)

			authed.POST("/auth/logout", s.handleLogout)
			authed.POST("/auth/session/close", s.handleSessionClose)
			authed.GET("/auth/me", s.handleMe)
			authed.POST("/auth/account", s.handleChangeAccount)
			// 敏感操作动手前先验一次身份（当前用在导入配置的认证弹窗）。
			// 它只负责把失败提前，不替代各接口自己那道校验。
			authed.POST("/auth/verify", s.handleVerifyIdentity)

			authed.GET("/overview", s.handleOverview)
			authed.GET("/overview/series", s.handleSeries)
			authed.GET("/logs", s.handleLogs)

			authed.GET("/settings", s.handleGetSettings)
			authed.PUT("/settings", s.handleUpdateSettings)
			authed.GET("/settings/appearance", s.handleGetAppearance)
			authed.PUT("/settings/appearance", s.handleUpdateAppearance)
			s.registerUpload(authed, "/settings/background", maxBackgroundImageBytes+bodyLimitSlack, s.handleUploadBackground)
			authed.DELETE("/settings/background", s.handleDeleteBackground)
			authed.POST("/settings/export", s.handleExportConfig)
			s.registerUpload(authed, "/settings/import", maxBackupFileSize+bodyLimitSlack, s.handleImportConfig)
			authed.GET("/settings/storage", s.handleGetStorage)
			authed.POST("/settings/storage/cleanup", s.handleCleanupStorage)

			authed.GET("/settings/logs/info", s.handleGetLogInfo)
			authed.POST("/settings/logs/clear", s.handleClearLogs)

			authed.GET("/settings/firewall/bans", s.handleGetFirewallBans)
			authed.POST("/settings/firewall/bans/clear", s.handleClearFirewallBans)

			authed.POST("/settings/restart-now", s.handleRestartNow)

			authed.GET("/meta/update-check", s.handleUpdateCheck)
			s.registerUpload(authed, "/meta/self-update", maxUpdatePackageBytes+maxUpdateSignatureBytes+bodyLimitSlack, s.handleSelfUpdate)

			s.registerResourceRoutes(authed)
		}
	}

	// 用户上传的资源（背景图等），需要登录。
	//
	// 这条路径原先公开可读，理由是"就是张背景图"。但公开的代价不止那张图：http.FileServer
	// 对目录路径会回一页索引，`GET /uploads/` 于是匿名列出所有已上传文件名，还顺带表明
	// 后面是个 Go 文件服务器。而登录页并不需要它——登录页底图是一段 CSS 渐变，用户上传的
	// 背景取自 /api/settings/appearance，那个接口本来就在登录之后。没有例外要开。
	//
	// 不再用 http.FileServer，改为自己开文件交给 ServeContent：目录一律 404（FileServer
	// 对目录回索引页、对不带斜杠的目录回 301，两者都在回答"这个目录存在"）。
	// http.Dir.Open 会把 ".." 清理在根目录以内，这次开文件兼作第二道穿越防护。
	// Cache-Control: private —— 内容现在带鉴权，不能让中途的共享缓存存下来再发给别人。
	// nosniff 保留：配合上传处的魔数校验，纵深防御存储型 XSS。
	if s.deps.DataDir != "" {
		uploadRoot := http.Dir(filepath.Join(s.deps.DataDir, "uploads"))
		root.GET("/uploads/*filepath", s.authRequired(), func(c *gin.Context) {
			c.Header("X-Content-Type-Options", "nosniff")
			c.Header("Cache-Control", "private")
			// 取路由参数而不是剥 URL 前缀：子路径部署（/mantou/uploads/xx）下访问前缀已由
			// gin 匹配时吃掉，这里拿到的就是 /bg-xxx.png，不必再自己拼 basePath。
			f, err := uploadRoot.Open(c.Param("filepath"))
			if err != nil {
				c.Status(http.StatusNotFound)
				return
			}
			defer f.Close()
			st, err := f.Stat()
			if err != nil || st.IsDir() {
				c.Status(http.StatusNotFound)
				return
			}
			http.ServeContent(c.Writer, c.Request, st.Name(), st.ModTime(), f)
		})
	}

	// 前端 SPA：静态资源 + history fallback。
	s.registerFrontend(r)
}

func panelCertificateLeaf(cert *tls.Certificate) (*x509.Certificate, error) {
	if cert == nil || len(cert.Certificate) == 0 {
		return nil, fmt.Errorf("面板 HTTPS 证书为空")
	}
	if cert.Leaf != nil {
		return cert.Leaf, nil
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("解析面板 HTTPS 证书失败: %w", err)
	}
	cert.Leaf = leaf
	return leaf, nil
}

func certificateHostname(hostport string) (string, error) {
	host := strings.TrimSpace(hostport)
	if parsed, _, err := net.SplitHostPort(host); err == nil {
		host = parsed
	} else if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		host = strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
	} else if strings.Contains(host, ":") {
		return "", fmt.Errorf("无效的主机名")
	}
	host = strings.TrimSuffix(host, ".")
	if host == "" {
		return "", fmt.Errorf("主机名为空")
	}
	if net.ParseIP(host) != nil {
		return "", fmt.Errorf("不允许使用 IP 地址")
	}
	return host, nil
}

func normalizePanelDomain(value string) (string, error) {
	host, err := certificateHostname(value)
	if err != nil {
		return "", err
	}
	host = strings.ToLower(host)
	if len(host) > 253 {
		return "", fmt.Errorf("域名长度超过限制")
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", fmt.Errorf("域名格式无效")
		}
		for _, ch := range label {
			if (ch < 'a' || ch > 'z') && (ch < '0' || ch > '9') && ch != '-' {
				return "", fmt.Errorf("域名格式无效")
			}
		}
	}
	return host, nil
}

func (s *Server) panelCertificate() (*tls.Certificate, error) {
	// 每次面板 TLS 握手都会走到这里，用只读快照避免深拷贝（下同）。
	cfg := s.deps.Config.Snapshot()
	if s.deps.Cert != nil && cfg.Panel.HTTPS.CertID != "" {
		if cert, ok := s.deps.Cert.ResolveID(cfg.Panel.HTTPS.CertID); ok {
			return cert, nil
		}
		return nil, fmt.Errorf("面板 HTTPS 证书无法加载")
	}
	if s.panelCert != nil {
		return s.panelCert, nil
	}
	return nil, fmt.Errorf("面板 HTTPS 证书为空")
}

func (s *Server) panelTLSConfig() (*tls.Config, error) {
	cert, err := s.panelCertificate()
	if err != nil {
		return nil, err
	}
	leaf, err := panelCertificateLeaf(cert)
	if err != nil {
		return nil, err
	}
	domain, err := normalizePanelDomain(s.deps.Config.Snapshot().Panel.HTTPS.Domain)
	if err != nil {
		return nil, fmt.Errorf("面板 HTTPS 访问域名无效: %w", err)
	}
	if err := leaf.VerifyHostname(domain); err != nil {
		return nil, fmt.Errorf("面板 HTTPS 访问域名未被证书覆盖: %w", err)
	}
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			// 一律按 SNI 校验，不给任何来源开例外——包括本机回环。
			//
			// 曾经为「本机回环 + 不带 SNI」放过行，那是为容器健康探测准备的：RFC 6066 §3
			// 禁止把 IP 字面量放进 SNI，探测只能连 127.0.0.1，于是 ServerName 恒为空。
			// 健康探测已整体移除（面板不对外提供任何免鉴权端点），这条例外随之收回。
			// 现在空 SNI 一律在此被拒：浏览器直接输 https://IP、公网扫描器、本机进程，
			// 都拿不到面板证书，握手阶段就结束，请求进不到任何中间件。
			serverName, err := normalizePanelDomain(hello.ServerName)
			if err != nil {
				return nil, fmt.Errorf("拒绝面板 TLS 连接: %w", err)
			}
			configured, err := normalizePanelDomain(s.deps.Config.Snapshot().Panel.HTTPS.Domain)
			if err != nil || serverName != configured {
				return nil, fmt.Errorf("SNI 与面板访问域名不匹配")
			}
			current, err := s.panelCertificate()
			if err != nil {
				return nil, err
			}
			currentLeaf, err := panelCertificateLeaf(current)
			if err != nil {
				return nil, err
			}
			if err := currentLeaf.VerifyHostname(configured); err != nil {
				return nil, fmt.Errorf("面板访问域名未被当前证书覆盖: %w", err)
			}
			return current, nil
		},
	}, nil
}

func (s *Server) requirePanelCertificateHost() gin.HandlerFunc {
	return func(c *gin.Context) {
		if !s.panelHTTPS {
			c.Next()
			return
		}
		domain, domainErr := normalizePanelDomain(s.deps.Config.Snapshot().Panel.HTTPS.Domain)
		host, hostErr := normalizePanelDomain(c.Request.Host)
		if domainErr != nil || hostErr != nil || host != domain {
			// 不写「面板」、也不回显应当使用的域名。
			//
			// 走到这里的请求是"连上了这个端口但 Host 不对"的那一类，最常见的来源是
			// 按 IP 扫端口。告诉对方"这是管理面板"、以及"换成 X 这个域名就能进"，
			// 等于替他把剩下的两步补齐。证书里虽然带着域名，但一张通配符证书覆盖
			// 一批主机名时，点出"其中哪一个是管理入口"仍然是多给的信息。
			// 管理员知道自己的地址，不需要这一页来告知（与 writeNotFoundPage 同一个口径）。
			const message = "请使用配置的访问域名"
			// 浏览器拿卡片页，接口调用方（前端 XHR / 脚本）仍拿 JSON：
			// 前端的错误提示是从 error 字段读出来的，塞一页 HTML 过去只会变成一堆标签。
			if errpage.WantsHTML(c.Request) {
				errpage.Write(c.Writer, c.Request, errpage.Page{
					Status: http.StatusForbidden,
					Title:  "请用配置的域名访问",
					Detail: "这个端口只接受使用配置域名的访问。",
					Where:  clipHost(c.Request.Host),
					Plain:  message,
				})
				c.Abort()
				return
			}
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": message})
			return
		}
		c.Next()
	}
}

// Start 启动面板监听（阻塞直至服务器关闭）。
//
// 自己 net.Listen 而不用 ListenAndServe，是为了在监听器外面包一层入站防火墙
// （见 firewall.go）。这一层必须在 TLS 之前：被拒的连接直接 Close，
// 于是既不会产出「TLS handshake error from …」这类告警，也不用为一个注定被拒的
// 来源付一次完整的密钥协商。
func (s *Server) Start() error {
	s.logFirewallState()
	s.deps.Log.Info("面板服务启动", "addr", s.http.Addr, "https", s.panelHTTPS)
	ln, err := net.Listen("tcp", s.http.Addr)
	if err != nil {
		return err
	}
	ln = s.firewall.wrapListener(ln)
	if s.panelHTTPS {
		if _, certErr := s.panelCertificate(); certErr != nil {
			_ = ln.Close()
			return fmt.Errorf("面板 HTTPS 已启用，但所选证书无法加载: %w", certErr)
		}
		s.http.TLSConfig, err = s.panelTLSConfig()
		if err != nil {
			_ = ln.Close()
			return err
		}
		// 证书路径传空串：TLSConfig 里已经有 GetCertificate，标准库据此跳过从文件加载。
		err = s.http.ServeTLS(ln, "", "")
	} else {
		err = s.http.Serve(ln)
	}
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

// Shutdown 优雅关闭 HTTP 服务，并停止会话清扫协程。
func (s *Server) Shutdown(ctx context.Context) error {
	if s.sessions != nil {
		s.sessions.close()
	}
	return s.http.Shutdown(ctx)
}

func (s *Server) requestPanelRestart(message string) {
	s.restartMu.Lock()
	if s.restarting {
		s.restartMu.Unlock()
		return
	}
	s.restarting = true
	s.restartMu.Unlock()

	go func() {
		time.Sleep(1500 * time.Millisecond)
		s.deps.Log.Info(message)
		if s.deps.RestartPanel == nil {
			s.deps.Log.Error("面板重启回调未配置")
			return
		}
		s.deps.RestartPanel()
	}()
}

// registerFrontend 提供前端单页应用；找不到文件时回退到 index.html。
// 支持访问路径前缀：请求路径先剥离前缀再在嵌入 FS 中定位资源。
func (s *Server) registerFrontend(r *gin.Engine) {
	if s.deps.WebFS == nil {
		return
	}
	fileServer := http.FileServer(http.FS(s.deps.WebFS))
	bp := s.basePath

	r.NoRoute(func(c *gin.Context) {
		p := c.Request.URL.Path

		// 剥离访问前缀。
		rel := p
		if bp != "" {
			if p == bp {
				c.Redirect(http.StatusMovedPermanently, bp+"/")
				return
			}
			if strings.HasPrefix(p, bp+"/") {
				rel = strings.TrimPrefix(p, bp)
			} else {
				// 前缀之外的请求：非本应用路径。接口调用方仍拿 JSON（脚本要解析 error 字段），
				// 拿浏览器撞上来的人拿卡片页。
				if strings.Contains(p, "/api/") {
					c.JSON(http.StatusNotFound, gin.H{"error": "资源不存在"})
					return
				}
				s.writeNotFoundPage(c)
				return
			}
		}

		if strings.HasPrefix(rel, "/api/") {
			c.JSON(http.StatusNotFound, gin.H{"error": "接口不存在"})
			return
		}

		trimmed := strings.TrimPrefix(rel, "/")
		if trimmed == "" || trimmed == "index.html" {
			s.serveIndex(c, fileServer)
			return
		}
		if _, err := fs.Stat(s.deps.WebFS, trimmed); err != nil {
			// 未命中静态文件 → 交回前端路由。
			s.serveIndex(c, fileServer)
			return
		}
		// 命中静态资源：装上缓存校验符后，改写为 FS 内的相对路径交给文件服务器。
		// 校验符必须在这一步之前设好——ServeContent 要靠 ETag 比对 If-None-Match 才回得出 304。
		s.setAssetCacheHeaders(c, trimmed)
		c.Request.URL.Path = "/" + trimmed
		fileServer.ServeHTTP(c.Writer, c.Request)
	})
}

// recoverPanic 接住没人处理的 panic。堆栈照旧由 gin 打进日志，这里只管回给用户的那一页：
// gin 自带的 Recovery 回的是一个空的 500，浏览器上就是一屏白，用户分不清是自己网断了
// 还是面板崩了。刻意不把 panic 内容印到页面上——那里面全是内部实现细节。
func (s *Server) recoverPanic(c *gin.Context, _ any) {
	// 已经写出去的响应改不了了（头都发了），只能就此收尾。
	if c.Writer.Written() {
		c.Abort()
		return
	}
	if errpage.WantsHTML(c.Request) {
		errpage.Write(c.Writer, c.Request, errpage.Page{
			Status: http.StatusInternalServerError,
			// 不写「面板」：中间件里的 panic 会让还没通过任何检查的请求也看到这一页。
			Title:  "服务出了点问题",
			Detail: "这次请求在处理过程中意外中断了。",
			Hint:   "请刷新页面重试；若持续出现，请查看服务端日志中这个时间点的错误记录。",
		})
		c.Abort()
		return
	}
	c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "服务内部错误"})
}

// writeNotFoundPage 面板的 404。页面本体在 internal/errpage：面板、Web 服务、消息路由
// 三处的错误页用同一张卡片，用户撞上哪一个都该看得出这是同一个系统。
//
// 只有"前缀之外"的请求会走到这里——前缀之内找不到的路径一律交回前端路由（单页应用
// 自己的 404 更有用，那一页上还有导航）。
//
// 这一页刻意不提面板首页在哪、也不提这台机器上跑的是什么：走到这里的请求恰好是
// "没猜中路径"的那一类，撞上 404 的多半就是在扫路径。把访问前缀写在页面上等于替对方
// 把最后一步补齐。管理员知道自己的地址，不需要这一页来告知。
func (s *Server) writeNotFoundPage(c *gin.Context) {
	errpage.Write(c.Writer, c.Request, errpage.Page{
		Status: http.StatusNotFound,
		Title:  "页面不存在",
		Detail: "这个地址没有对应的内容。",
		Where:  clipHost(c.Request.Host) + clip(c.Request.URL.Path, 120),
		Plain:  "资源不存在",
	})
	c.Abort()
}

// clipHost / clip 截断要回显到页面上的外来字符串。
// 转义由 errpage 负责，长度得在这里管：Host 与路径都由对方决定，
// 一个几 KB 的路径会把这张卡片撑成一屏乱码。
func clipHost(host string) string { return clip(host, 80) }

func clip(s string, max int) string { return strutil.Truncate(s, max, "…") }

// serveIndex 返回前端入口页；始终返回注入了当前运行期基址的版本（basePath="" 时
// 也注入 __MANTOU_BASE__=""，保证前端拿到与后端一致的基址）。
func (s *Server) serveIndex(c *gin.Context, fileServer http.Handler) {
	// index.html 使用 no-store 而非 no-cache：这份 HTML 会按当前 basePath 动态注入
	// 基址变量，必须禁止浏览器任何形式的存储，否则基址变更后浏览器会复用旧 HTML
	// 继续向已废弃的子路径发起 API 请求（典型表现：关于页版本显示「未知」）。
	c.Header("Cache-Control", "no-store")
	if len(s.indexHTML) > 0 {
		c.Data(http.StatusOK, "text/html; charset=utf-8", s.indexHTML)
		return
	}
	// 无访问前缀时直接读取并发送 index.html（同样不缓存），不依赖文件服务器默认缓存策略。
	if s.deps.WebFS != nil {
		if data, err := fs.ReadFile(s.deps.WebFS, "index.html"); err == nil {
			c.Data(http.StatusOK, "text/html; charset=utf-8", data)
			return
		}
	}
	c.Request.URL.Path = "/"
	fileServer.ServeHTTP(c.Writer, c.Request)
}

// buildIndexHTML 读取嵌入的 index.html；始终注入运行期基址变量 window.__MANTOU_BASE__，
// 使前端 basePath 解析始终与后端当前配置一致（空串即根路径），避免浏览器复用了
// 旧 HTML 导致基址错位、API 请求飞到错误路径。子路径部署时额外注入 <base> 标签，
// 让前端资源与路由解析在子路径下正确工作。
func (s *Server) buildIndexHTML() []byte {
	if s.deps.WebFS == nil {
		return nil
	}
	data, err := fs.ReadFile(s.deps.WebFS, "index.html")
	if err != nil {
		return nil
	}
	// 始终注入基址变量；子路径时再加 <base> 标签。
	inject := `<script>window.__MANTOU_BASE__=` + jsString(s.basePath) + `;</script>`
	if s.basePath != "" {
		inject = `<base href="` + s.basePath + `/">` + inject
	}
	html := string(data)
	if idx := strings.Index(html, "<head>"); idx >= 0 {
		pos := idx + len("<head>")
		html = html[:pos] + inject + html[pos:]
	} else {
		html = inject + html
	}
	return []byte(html)
}

// jsString 返回可安全嵌入 <script> 的 JSON 字符串字面量。
func jsString(s string) string {
	b, err := json.Marshal(s)
	if err != nil {
		return `""`
	}
	return string(b)
}

// normalizeBasePath 规范化访问路径前缀：空或"/"→""；否则确保以"/"开头、无末尾"/"。
func normalizeBasePath(bp string) string {
	bp = strings.TrimSpace(bp)
	if bp == "" || bp == "/" {
		return ""
	}
	if !strings.HasPrefix(bp, "/") {
		bp = "/" + bp
	}
	return strings.TrimRight(bp, "/")
}

func addr(host string, port int) string {
	if host == "" {
		host = "0.0.0.0"
	}
	return host + ":" + strconv.Itoa(port)
}
