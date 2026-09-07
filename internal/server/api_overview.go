package server

import (
	"fmt"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"mantou/internal/config"
	"mantou/internal/logx"
	"mantou/internal/version"
)

// handleOverview 返回总览信息：服务器/进程信息、最近一次采样、各模块状态。
func (s *Server) handleOverview(c *gin.Context) {
	// 告知采集器「有人在看」：无人查看时采样会自动降频（见 metrics.Touch）。
	s.deps.Metrics.Touch()
	info := s.deps.Metrics.Info()
	latest, hasLatest := s.deps.Metrics.Latest()

	var statuses any
	if s.deps.Modules != nil {
		statuses = s.deps.Modules.Statuses()
	}

	resp := gin.H{
		"info":     info,
		"statuses": statuses,
		"version":  version.Load().Version,
	}
	if hasLatest {
		resp["latest"] = latest
	}
	respondOK(c, resp)
}

// handleSeries 返回指标时间序列，供图表展示。
//
// 支持增量拉取：带上 since=<最后一个采样点的毫秒时间戳> 时只返回更新的点，
// 响应从约 18 KB 降到约 200 B。响应中的 full 字段说明本次给的是全量还是增量：
// full=true 时前端应整体替换本地序列（首次拉取，或 since 已被环形缓冲淘汰），
// full=false 时直接追加。不带 since 的老客户端行为不变（拿到全量）。
func (s *Server) handleSeries(c *gin.Context) {
	s.deps.Metrics.Touch()
	var since int64
	if v := c.Query("since"); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil {
			since = n
		}
	}
	series, full := s.deps.Metrics.SeriesSince(since)
	respondOK(c, gin.H{"series": series, "full": full})
}

// handleLogs 返回内存环形缓冲中的最近日志。
// 当 home=1 时，按设置中的「总览页日志条数」限量，并在未开启「首页显示日志」时返回空列表，
// 由前端据此决定是否渲染日志面板。
//
// 两个分支的上限都收在「日志最大条数」之内：环里最多就那么多条，
// 允许传更大的 limit 只会让调用方以为能取到更多。
func (s *Server) handleLogs(c *gin.Context) {
	cfg := s.deps.Config.Snapshot()
	maxEntries := logx.NormalizeLogEntries(cfg.Settings.Log.MaxEntries)
	if c.Query("home") == "1" {
		if !cfg.Settings.Log.ShowOnHome {
			respondOK(c, gin.H{"logs": []any{}, "showOnHome": false})
			return
		}
		limit := config.NormalizeLogHomeLimit(cfg.Settings.Log.HomeLimit, maxEntries)
		respondOK(c, gin.H{"logs": s.deps.Log.Recent(limit), "showOnHome": true})
		return
	}
	limit := config.DefaultLogHomeLimit
	if v := c.Query("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			limit = min(n, maxEntries)
		}
	}
	respondOK(c, gin.H{"logs": s.deps.Log.Recent(limit)})
}

// handleGetSettings 返回可编辑的设置（不含敏感字段）。
// 监听地址固定为 0.0.0.0，无实际配置价值，故不在设置中暴露。
func (s *Server) handleGetSettings(c *gin.Context) {
	cfg := s.deps.Config.Snapshot()
	respondOK(c, gin.H{
		"language": cfg.Settings.Language,
		"log": gin.H{
			"levels":     cfg.Settings.Log.Levels,
			"maxEntries": cfg.Settings.Log.MaxEntries,
			"console":    cfg.Settings.Log.Console,
			"showOnHome": cfg.Settings.Log.ShowOnHome,
			"homeLimit":  cfg.Settings.Log.HomeLimit,
		},
		"notify": cfg.Settings.Notify,
		"panel": gin.H{
			"port":     cfg.Panel.Port,
			"basePath": cfg.Panel.BasePath,
			"https": gin.H{
				"enabled": cfg.Panel.HTTPS.Enabled,
				"certId":  cfg.Panel.HTTPS.CertID,
				"domain":  cfg.Panel.HTTPS.Domain,
			},
		},
		"update": updateSettings(cfg.Update, time.Now()),
		"auth": gin.H{
			"sessionHours":       cfg.Auth.SessionHours,
			"sessionIdleMinutes": cfg.Auth.SessionIdleMinutes,
			"loginMaxFails":      cfg.Auth.LoginMaxFails,
			"loginLockMinutes":   cfg.Auth.LoginLockMinutes,
		},
		"security": gin.H{
			"blockPrivateNetwork": cfg.Settings.Security.BlockPrivateNetwork,
			"firewall":            firewallSettings(cfg.Settings.Security.Firewall),
		},
		"restart": restartSettings(cfg.Settings.Restart),
		"certs":   s.certOptions(cfg),
	})
}

// updateSettings 组装「在线更新」那一段设置的响应体。
//
// 逐字段列出而不是直接把 config.UpdateConfig 序列化出去：这一段要在原始字段之外
// 再带上算出来的窗口状态，而且往那个结构里新增字段时也不该顺带出现在接口上。
//
// allowUnsignedUpdate 报的是**此刻是否有效**，而不是配置里那个布尔值。
// 这不是图省事，是必须：界面上那个开关就是拿这个值渲染的，若报原始值，
// 一段已经过期的窗口会显示成"开着"，用户此后在这一页做的任何一次保存都会带上
// allowUnsignedUpdate: true，于是被判成一次"重新打开"、要求输密码——
// 而用户压根没想动这一项。报有效值则这次保存带的是 false，正好把它清干净。
//
// allowUnsignedExpiresAt 是窗口到期的 Unix 秒，没有有效窗口时为 0。
// allowUnsignedTtlHours 让界面上的说明文字与后端的 TTL 取同一个数，不必各写一遍。
func updateSettings(u config.UpdateConfig, now time.Time) gin.H {
	expiresAt := int64(0)
	if u.UnsignedUpdateAllowed(now) {
		if exp, ok := u.UnsignedUpdateExpiry(now); ok {
			expiresAt = exp.Unix()
		}
	}
	return gin.H{
		"manifestUrl":            u.ManifestURL,
		"releaseUrl":             u.ReleaseURL,
		"githubRepo":             u.GitHubRepo,
		"signKey":                u.SignKey,
		"allowUnsignedUpdate":    expiresAt > 0,
		"allowUnsignedExpiresAt": expiresAt,
		"allowUnsignedTtlHours":  int(config.AllowUnsignedUpdateTTL / time.Hour),
		"about":                  u.About,
		"description":            u.Description,
	}
}

// certOption 是「面板 HTTPS → 选择证书」下拉框需要的最小证书信息。
type certOption struct {
	ID      string   `json:"id"`
	Name    string   `json:"name"`
	Domains []string `json:"domains"`
}

// certOptions 供设置页下拉框使用的证书清单。
//
// 之所以随 /settings 一起下发，而不让前端再单独请求 /certs：设置页原先在 onMounted 里
// 并发拉 /settings 与 /certs 两个接口，但下拉框只需要 id/name/domains 三个字段，
// 而 /certs 会把每张证书的完整配置（含 ACME 状态机、续期进度、磁盘路径）都算出来返回。
// 合成一个请求后，设置页的首屏只剩一次往返，也就少一次「等最慢的那个」。
//
// 域名以证书库里实际解析出的 SAN 为准（与 /certs 列表同源），拿不到（尚未签发 / 文件缺失）
// 时回落到配置里填写的域名，保证下拉框不会出现「名称 ()」这种空括号。
func (s *Server) certOptions(cfg *config.Config) []certOption {
	out := make([]certOption, 0, len(cfg.Certs))
	for i := range cfg.Certs {
		opt := certOption{ID: cfg.Certs[i].ID, Name: cfg.Certs[i].Name, Domains: cfg.Certs[i].Domains}
		if s.deps.Cert != nil {
			if domains, _, ok := s.deps.Cert.Info(cfg.Certs[i].ID); ok && len(domains) > 0 {
				opt.Domains = domains
			}
		}
		if opt.Domains == nil {
			opt.Domains = []string{}
		}
		out = append(out, opt)
	}
	return out
}

// updateSettingsReq 是设置更新请求。仅允许更新面向用户的安全字段。
type updateSettingsReq struct {
	Language *string `json:"language"`
	Log      *struct {
		Levels     []string `json:"levels"`
		MaxEntries int      `json:"maxEntries"`
		Console    bool     `json:"console"`
		ShowOnHome bool     `json:"showOnHome"`
		HomeLimit  int      `json:"homeLimit"`
	} `json:"log"`
	Notify *struct {
		Enabled bool `json:"enabled"`
	} `json:"notify"`
	Panel *struct {
		Port     *int    `json:"port"`
		BasePath *string `json:"basePath"`
		HTTPS    *struct {
			Enabled      bool     `json:"enabled"`
			CertID       string   `json:"certId"`
			Domain       string   `json:"domain"`
			AllowedHosts []string `json:"allowedHosts"`
		} `json:"https"`
	} `json:"panel"`
	Update *struct {
		ManifestURL *string `json:"manifestUrl"`
		ReleaseURL  *string `json:"releaseUrl"`
		GitHubRepo  *string `json:"githubRepo"`
		SignKey     *string `json:"signKey"`
		// AllowUnsignedUpdate 用指针而不是 bool：这一项默认关闭，
		// 若按值接收，任何一次没带这个字段的设置提交都会把它重置成关闭。
		AllowUnsignedUpdate *bool   `json:"allowUnsignedUpdate"`
		About               *string `json:"about"`
		// Account / Password 只在「打开 AllowUnsignedUpdate」这一次提交上要求，
		// 其余字段都不需要（见 handleUpdateSettings 里那段口令复核）。
		// 放在 update 这一层而不是请求顶层：它属于这一项改动的凭据，不是整份设置的。
		Account  string `json:"account"`
		Password string `json:"password"`
	} `json:"update"`
	Auth *struct {
		SessionHours *int `json:"sessionHours"`
		// SessionIdleMinutes 用指针：0 在这一项上是「不启用」这个有效选择，
		// 按值接收就分不出「用户主动关掉」与「这次提交没带这个字段」。
		SessionIdleMinutes *int `json:"sessionIdleMinutes"`
		LoginMaxFails      *int `json:"loginMaxFails"`
		LoginLockMinutes   *int `json:"loginLockMinutes"`
	} `json:"auth"`
	Security *struct {
		BlockPrivateNetwork bool         `json:"blockPrivateNetwork"`
		Firewall            *firewallReq `json:"firewall"`
	} `json:"security"`
	Restart *restartReq `json:"restart"`
}

// firewallReq 面板入站防护的提交体。
//
// 数值字段一律用指针：0 在「每秒请求数」上是"不限速"这个有效选择，
// 而在阈值/时长上则代表"没填"（由 normalize 回落到默认值）——两种含义都要求
// 能区分"用户填了 0"与"这次提交没带这个字段"，按值接收就分不出来。
type firewallReq struct {
	Enabled          bool     `json:"enabled"`
	Mode             string   `json:"mode"`
	AllowIPs         []string `json:"allowIps"`
	DenyIPs          []string `json:"denyIps"`
	RateLimit        *int     `json:"rateLimit"`
	AutoBan          bool     `json:"autoBan"`
	AutoBanThreshold *int     `json:"autoBanThreshold"`
	AutoBanMinutes   *int     `json:"autoBanMinutes"`

	// Force 表示用户已经在界面上确认过「这会切断我自己的访问」。
	//
	// 有这个字段是因为自锁校验必须能被越过：一个正从公网管理面板的用户，完全可能
	// 明知会失去当前入口也要切成"只允许局域网"（接下来改走 VPN / SSH 隧道）。
	// 拦死等于替他做决定，而这个决定他有权做。默认拦下、确认后放行，
	// 让"意外锁死"与"有意锁死"分开——前者是这道校验要防的，后者不是。
	Force bool `json:"force"`
}

// policy 把提交体转成配置结构。指针字段缺省时沿用 cur（当前生效值），
// 于是一次只带部分字段的提交不会把没带的那些重置掉。
func (r *firewallReq) policy(cur config.PanelFirewall) config.PanelFirewall {
	out := config.PanelFirewall{
		Enabled:          r.Enabled,
		Mode:             strings.TrimSpace(r.Mode),
		AllowIPs:         r.AllowIPs,
		DenyIPs:          r.DenyIPs,
		AutoBan:          r.AutoBan,
		RateLimit:        cur.RateLimit,
		AutoBanThreshold: cur.AutoBanThreshold,
		AutoBanMinutes:   cur.AutoBanMinutes,
	}
	if r.RateLimit != nil {
		out.RateLimit = *r.RateLimit
	}
	if r.AutoBanThreshold != nil {
		out.AutoBanThreshold = *r.AutoBanThreshold
	}
	if r.AutoBanMinutes != nil {
		out.AutoBanMinutes = *r.AutoBanMinutes
	}
	return out
}

// checkLimits 在规范化之前拦下超限的名单。
//
// 必须在 normalize 之前：normalize 会把超长名单直接截断到上限，截完 Valid 就再也
// 看不到超限，用户多填的那些条目会被静默丢掉（同 restartReq.checkLimits 的理由）。
func (r *firewallReq) checkLimits() error {
	if len(r.AllowIPs) > config.MaxFirewallIPs || len(r.DenyIPs) > config.MaxFirewallIPs {
		return fmt.Errorf("名单最多 %d 条", config.MaxFirewallIPs)
	}
	return nil
}

// firewallSettings 把配置结构转成设置页需要的形状。
func firewallSettings(fw config.PanelFirewall) gin.H {
	allow := fw.AllowIPs
	if allow == nil {
		allow = []string{}
	}
	deny := fw.DenyIPs
	if deny == nil {
		deny = []string{}
	}
	return gin.H{
		"enabled":          fw.Enabled,
		"mode":             fw.Mode,
		"allowIps":         allow,
		"denyIps":          deny,
		"rateLimit":        fw.RateLimit,
		"autoBan":          fw.AutoBan,
		"autoBanThreshold": fw.AutoBanThreshold,
		"autoBanMinutes":   fw.AutoBanMinutes,
		// 计数窗口是固定值，随设置一起下发，好让界面上那句「N 分钟内超限 M 次」
		// 与服务端真正用的那个数同源，而不是前端自己抄一个。
		"autoBanWindowMinutes": config.FirewallAutoBanWindowMinutes(),
		"maxIps":               config.MaxFirewallIPs,
	}
}

// handleUpdateSettings 更新通用设置。端口/路径前缀变更需重启方可生效，响应中以 restartRequired 标记。
func (s *Server) handleUpdateSettings(c *gin.Context) {
	var req updateSettingsReq
	if err := c.ShouldBindJSON(&req); err != nil {
		respondError(c, http.StatusBadRequest, "请求参数无效")
		return
	}

	before := s.deps.Config.Snapshot()
	if req.Panel != nil && req.Panel.HTTPS != nil && req.Panel.HTTPS.Enabled {
		certID := strings.TrimSpace(req.Panel.HTTPS.CertID)
		if certID == "" {
			respondError(c, http.StatusBadRequest, "启用面板 HTTPS 必须选择证书")
			return
		}
		domain := req.Panel.HTTPS.Domain
		if strings.TrimSpace(domain) == "" && len(req.Panel.HTTPS.AllowedHosts) == 1 {
			domain = req.Panel.HTTPS.AllowedHosts[0]
		}
		// 先报写法问题：normalizePanelDomain 只会回一句笼统的"域名格式无效"，
		// 而这里的调用方连那句都吞掉了，用户填了通配符根本看不出错在哪。
		if err := checkRouteDomainSyntax(domain); err != nil {
			respondError(c, http.StatusBadRequest, err.Error())
			return
		}
		normalizedDomain, err := normalizePanelDomain(domain)
		if err != nil {
			respondError(c, http.StatusBadRequest, "启用面板 HTTPS 必须填写有效的单一访问域名")
			return
		}
		configured := false
		certEnabled := false
		for _, item := range before.Certs {
			if item.ID == certID {
				configured = true
				certEnabled = item.Enabled
				break
			}
		}
		if !configured {
			respondError(c, http.StatusBadRequest, "所选证书不存在")
			return
		}
		// 禁用证书不可用于面板 HTTPS（与运行期「禁用即不可引用」硬约束一致）。
		if !certEnabled {
			respondError(c, http.StatusBadRequest, "所选证书已被禁用，无法用于面板 HTTPS；请先到「证书」启用该证书")
			return
		}
		if s.deps.Cert == nil {
			respondError(c, http.StatusServiceUnavailable, "证书模块未就绪")
			return
		}
		if err := s.deps.Cert.ValidateID(certID, time.Now()); err != nil {
			respondError(c, http.StatusBadRequest, err.Error())
			return
		}
		if err := s.deps.Cert.ValidateHostname(certID, normalizedDomain); err != nil {
			respondError(c, http.StatusBadRequest, err.Error())
			return
		}
		req.Panel.HTTPS.CertID = certID
		req.Panel.HTTPS.Domain = normalizedDomain
		req.Panel.HTTPS.AllowedHosts = nil
	}
	// 定时重启：先按加载期同一套规则规范化，再判断这份设置能不能真的跑起来。
	// 校验放在落盘之前——设置是整段提交的，"存下来了但永远不会触发"是最坏的结果：
	// 界面看着已启用，实际一次也不会重启。
	var restartPolicy config.RestartPolicy
	if req.Restart != nil {
		// checkLimits 必须在规范化之前：规范化会把超限的日期列表直接夹到上限，
		// 夹完 Valid 就再也看不到超限，界面上多选的那些日期会被静默丢掉。
		if verr := req.Restart.checkLimits(); verr != nil {
			respondError(c, http.StatusBadRequest, verr.Error())
			return
		}
		restartPolicy = req.Restart.policy()
		if verr := restartPolicy.Valid(); verr != nil {
			respondError(c, http.StatusBadRequest, verr.Error())
			return
		}
	}

	// 面板端口：落盘之前先确认它绑得上。保存成功就会触发面板重启，
	// 而重启时绑不上会让整个进程退出（理由见 panelport.go 顶部）。
	if req.Panel != nil && req.Panel.Port != nil {
		if verr := s.checkPanelPort(before, before.Panel.Port, *req.Panel.Port); verr != nil {
			respondError(c, http.StatusBadRequest, verr.Error())
			return
		}
	}

	// 几个地址字段：留空表示"不用"，填了就得是个能用的 http/https 地址。
	//
	// 原先这几个字段只 TrimSpace 就落盘，连 scheme 都不看：填成一段普通文字也能保存成功，
	// 报错要等到真去请求那一刻，而那时界面上的提示是「检查更新失败」，指不到真正的原因上。
	// 与通知目标、Web 服务、消息路由那边"保存前就把目标校验掉"的做法对齐（见 checkHTTPURL）。
	type urlField struct{ label, raw, example string }
	var urlFields []urlField
	if req.Update != nil {
		if req.Update.ManifestURL != nil {
			urlFields = append(urlFields, urlField{"版本清单地址", *req.Update.ManifestURL, "https://example.com/version.json"})
		}
		if req.Update.ReleaseURL != nil {
			urlFields = append(urlFields, urlField{"更新下载页地址", *req.Update.ReleaseURL, "https://example.com/download"})
		}
	}
	for _, f := range urlFields {
		raw := strings.TrimSpace(f.raw)
		if raw == "" {
			continue // 留空是合法的：表示这一项不启用
		}
		if verr := checkHTTPURL(f.label, raw, f.example); verr != nil {
			respondError(c, http.StatusBadRequest, verr.Error())
			return
		}
	}

	// 版本检测仓库：同一个道理，但它不是 URL 而是被**拼进** URL 的一段路径
	// （https://api.github.com/repos/<这里>/releases/latest），所以校验的是形状而非地址。
	// 填 "../../users/someone" 这类段名能把检测请求挪到另一个接口上，
	// 再把那边返回的 html_url 当作"新版本下载页"显示出来（见 githubRepoOf）。
	// 完整 http(s) 地址仍然收——界面上那个仓库图标本来就支持这种写法。
	if req.Update != nil && req.Update.GitHubRepo != nil {
		if raw := strings.TrimSpace(*req.Update.GitHubRepo); raw != "" && !validGitHubRepoField(raw) {
			respondError(c, http.StatusBadRequest, "项目仓库应填 owner/name（如 ovoene/Mantou）或完整的 http(s) 地址")
			return
		}
	}

	// 打开「允许未验签的更新包」要当场再验一次管理员口令。
	//
	// 这个开关一旦为真，任何一条有效会话都能上传一个 tar.gz 把面板二进制换掉，
	// 也就是在这台机器上执行任意代码。它与「导出/导入备份」同级，用同一套复核
	//（见 handleExportConfig），而不是只靠会话本身——会话是这条链上最容易被拿到的一环
	//（XSS、借来的浏览器、忘了登出的机器），而它下面这一项能把整个程序换掉。
	//
	// 只在**从没有有效窗口到有**这一次要求，理由有两条：其一，关掉它、改清单地址、
	// 填公钥都不需要凭据——那些改动要么在收紧，要么与这道口子无关；其二，窗口已经开着
	// 的时候不再问，否则用户在这一页上动任何一项都要输一遍密码。
	//
	// 用 before 判"当前有没有窗口"，与下面 Update 闭包里的记时判定是同一个口径；
	// 两者之间的并发窗口不影响结论：并发的两次打开里至多一次会记起点，而两次都过了口令。
	unsignedNow := time.Now()
	if req.Update != nil && req.Update.AllowUnsignedUpdate != nil && *req.Update.AllowUnsignedUpdate &&
		!before.Update.UnsignedUpdateAllowed(unsignedNow) {
		// 这次校验与另外五处「已登录之后再验一次当前密码」共用一份失败计数（见 reauth.go）。
		//
		// 闸只包住这一支、不放在处理器开头：这个接口保存的是整页设置，其中绝大多数改动
		// 根本不问密码，把闸提到外面就变成"在别处猜错几次密码，连主题色都改不了"。
		//
		// 提前返回不会留下半套设置：这里还在校验段，落盘的 Update 闭包在后面
		//（与下面那一支 403 同理）。
		if !s.reauthAllowed(c) {
			return
		}
		if !adminCredentialsOK(before.Auth, req.Update.Account, req.Update.Password) {
			s.reauthFail(c)
			// 403 而非 401：401 会让前端拦截器强制登出跳登录页，而这里只是这一项改动的
			// 凭据没对上，应当停在设置页提示（与 handleExportConfig 同）。
			s.deps.Log.Warn("设置：打开「允许未验签的更新包」的身份复核失败，已拒绝",
				"operator", operator(c), "ip", c.ClientIP())
			respondError(c, http.StatusForbidden, "账户或密码错误，「允许未验签的更新包」未打开")
			return
		}
		s.reauthOK(c)
	}

	// 访问路径前缀：它会被原样拼进 gin 的路由组，也会被写进入口页的 <base href>。
	// 两个去处都不容错——冒号星号在路由组里是通配符语法，引号能从 HTML 属性里逃出去，
	// ".." 能把整页的资源引用挪到上一层。所以在这里就把形状挡掉，而不是等
	// normalizeBasePath 把非法值悄悄归零（那样界面上会显示保存成功、前缀却没生效）。
	//
	// 判据直接借用 normalizeBasePath 本身：填了内容却归一化成空，就是非法。
	// 这样校验与落盘用的是同一套规则，不会哪天各自漂走。全是斜杠视同留空（即根路径）。
	if req.Panel != nil && req.Panel.BasePath != nil {
		raw := strings.TrimSpace(*req.Panel.BasePath)
		if strings.Trim(raw, "/") != "" && normalizeBasePath(raw) == "" {
			respondError(c, http.StatusBadRequest, "访问路径前缀只能用字母、数字与 - _ . ~，多级用 / 分隔（如 /mantou 或 /admin/mantou）")
			return
		}
	}

	// 面板入站防护：同样先按加载期的规则规范化，再校验，最后确认它不会把
	// 提交这次改动的人本人关在门外（见 checkFirewallLockout）。
	//
	// 三步的顺序不能换：checkLimits 要看未截断的原始名单，Valid 要看未被 normalize
	// 改写的原始数值（否则用户填的负数会被悄悄夹成别的数、界面上却显示保存成功），
	// 而自锁判断必须基于**规范化之后**的那份——真正生效的是它。
	var firewallPolicy config.PanelFirewall
	if req.Security != nil && req.Security.Firewall != nil {
		fr := req.Security.Firewall
		if verr := fr.checkLimits(); verr != nil {
			respondError(c, http.StatusBadRequest, verr.Error())
			return
		}
		firewallPolicy = fr.policy(before.Settings.Security.Firewall)
		if verr := firewallPolicy.Valid(); verr != nil {
			respondError(c, http.StatusBadRequest, verr.Error())
			return
		}
		config.NormalizePanelFirewall(&firewallPolicy)
		if !fr.Force {
			if verr := checkFirewallLockout(firewallPolicy, c.Request); verr != nil {
				// 409 而不是 400：这不是"参数写错了"，而是"参数没错，但后果需要你确认一次"。
				// 前端据此弹确认框，确认后带 force 重提（见 firewallReq.Force）。
				respondError(c, http.StatusConflict, verr.Error())
				return
			}
		}
	}

	err := s.deps.Config.Update(func(cfg *config.Config) {
		if req.Language != nil && (*req.Language == "zh-CN" || *req.Language == "en-US") {
			cfg.Settings.Language = *req.Language
		}
		if req.Log != nil {
			// 级别白名单过滤：认不出的字符串会在 logx 内部被当成 info，
			// 若原样存下，"levels=[verbose]"就等于悄悄只留 info、关掉其余三档（见 logx.NormalizeLevels）。
			req.Log.Levels = logx.NormalizeLevels(req.Log.Levels)
			cfg.Settings.Log.Levels = req.Log.Levels
			// 「日志最大条数」是全程序日志量的总开关，后端兜底夹进 [100,5000]（≤0 取默认 1000）：
			// 前端输入框已限界，此处防绕过 API 直接传 1 或 10^9 导致内存 / 磁盘失控。
			cfg.Settings.Log.MaxEntries = logx.NormalizeLogEntries(req.Log.MaxEntries)
			cfg.Settings.Log.Console = req.Log.Console
			cfg.Settings.Log.ShowOnHome = req.Log.ShowOnHome
			// 总览页展示条数：≤0 取默认 50，上限 200，且不超过上面刚定下的总条数。
			cfg.Settings.Log.HomeLimit = config.NormalizeLogHomeLimit(req.Log.HomeLimit, cfg.Settings.Log.MaxEntries)
		}
		if req.Notify != nil {
			cfg.Settings.Notify.Enabled = req.Notify.Enabled
		}
		if req.Panel != nil {
			if req.Panel.Port != nil && *req.Panel.Port > 0 && *req.Panel.Port <= 65535 {
				cfg.Panel.Port = *req.Panel.Port
			}
			if req.Panel.BasePath != nil {
				cfg.Panel.BasePath = normalizeBasePath(*req.Panel.BasePath)
			}
			if req.Panel.HTTPS != nil {
				cfg.Panel.HTTPS.Enabled = req.Panel.HTTPS.Enabled
				cfg.Panel.HTTPS.CertID = req.Panel.HTTPS.CertID
				cfg.Panel.HTTPS.Domain = req.Panel.HTTPS.Domain
				cfg.Panel.HTTPS.AllowedHosts = nil
			}
		}
		if req.Update != nil {
			if req.Update.ManifestURL != nil {
				cfg.Update.ManifestURL = strings.TrimSpace(*req.Update.ManifestURL)
			}
			if req.Update.ReleaseURL != nil {
				cfg.Update.ReleaseURL = strings.TrimSpace(*req.Update.ReleaseURL)
			}
			if req.Update.GitHubRepo != nil {
				cfg.Update.GitHubRepo = strings.TrimSpace(*req.Update.GitHubRepo)
			}
			if req.Update.SignKey != nil {
				cfg.Update.SignKey = strings.TrimSpace(*req.Update.SignKey)
			}
			if req.Update.AllowUnsignedUpdate != nil {
				if *req.Update.AllowUnsignedUpdate {
					// 记起点只在此刻没有有效窗口时做：窗口开着的时候不重新计时，
					// 否则这一页上任何一次保存都会顺手把它续期，那这个窗口就又变成
					// 一扇不会关的门了（见 config.UpdateConfig.AllowUnsignedSince）。
					if !cfg.Update.UnsignedUpdateAllowed(unsignedNow) {
						cfg.Update.AllowUnsignedSince = unsignedNow.Unix()
					}
					cfg.Update.AllowUnsignedUpdate = true
				} else {
					// 关闭时把起点一并清掉：留着它只会让下次打开时算出一段
					// 从上次算起、可能早已过期的窗口。
					cfg.Update.AllowUnsignedUpdate = false
					cfg.Update.AllowUnsignedSince = 0
				}
			}
			if req.Update.About != nil {
				cfg.Update.About = *req.Update.About
			}
		}
		if req.Auth != nil {
			if req.Auth.SessionHours != nil && *req.Auth.SessionHours >= 1 && *req.Auth.SessionHours <= 8760 {
				cfg.Auth.SessionHours = *req.Auth.SessionHours
			}
			// 闲置超时：0 表示不启用，上限与锁定时长同取 30 天。
			// 与 clampInt 而非区间判空一致对待——绕过面板直接调 API 传 -1 也得落到合法值。
			if req.Auth.SessionIdleMinutes != nil {
				cfg.Auth.SessionIdleMinutes = clampInt(*req.Auth.SessionIdleMinutes, 0, 43200)
			}
			// 登录锁定参数同样做后端区间兜底：这两个值直接决定爆破防护强度，
			// 绕过面板直接调 API 传 -1 / 10 亿都不该被接受。
			// 0 保留"不限制"语义（与 newLoginLimiter 一致），负数按 0 处理；
			// 上限取 1000 次 / 30 天，超出的部分对防护没有任何额外意义，只会让被锁死的账户无法自愈。
			if req.Auth.LoginMaxFails != nil {
				cfg.Auth.LoginMaxFails = clampInt(*req.Auth.LoginMaxFails, 0, 1000)
			}
			if req.Auth.LoginLockMinutes != nil {
				cfg.Auth.LoginLockMinutes = clampInt(*req.Auth.LoginLockMinutes, 0, 43200)
			}
		}
		if req.Security != nil {
			cfg.Settings.Security.BlockPrivateNetwork = req.Security.BlockPrivateNetwork
			if req.Security.Firewall != nil {
				cfg.Settings.Security.Firewall = firewallPolicy
			}
		}
		if req.Restart != nil {
			// 执行记录沿用现值：它不来自请求（见 restartReq.policy 的说明）。
			restartPolicy.LastRunAt = cfg.Settings.Restart.LastRunAt
			cfg.Settings.Restart = restartPolicy
		}
	})
	if err != nil {
		respondError(c, http.StatusInternalServerError, "保存配置失败")
		return
	}

	// 保存后的实际生效值（各字段已在 Update 内部规范化过，不能直接用 req 里的原始输入）。
	after := s.deps.Config.Snapshot()

	// 日志设置实时应用，全部无需重启。
	if req.Log != nil {
		s.deps.Log.SetLevels(after.Settings.Log.Levels)
		// 「日志最大条数」是总开关，必须一次推给三处存储，否则用户会看到「我调小了、占用没降」：
		//  1. 程序运行日志内存环（缩容时保留最新的那部分，总览页立刻见效）；
		//  2. Web 服务访问事件内存环 —— 这里必须直接调用而不能指望 Module.Reload：
		//     本处理器是唯一不走 afterChange() 的设置保存路径，若只改配置文件，
		//     新条数要等到某个无关配置变更触发 ReloadAll 才会生效；
		//  3. 磁盘日志文件（改的是行数轮转阈值，见 RotatingFile.SetMaxEntries）。
		n := after.Settings.Log.MaxEntries
		s.deps.Log.SetMaxEntries(n)
		if s.deps.Web != nil {
			s.deps.Web.SetAccessCap(n)
		}
		if s.deps.LogFile != nil {
			s.deps.LogFile.SetMaxEntries(n)
		}
	}

	// 登录锁定参数变更：刷新内存限流器（保留既有失败记录）。
	if req.Auth != nil {
		lockFor := time.Duration(after.Auth.LoginLockMinutes) * time.Minute
		if lockFor <= 0 {
			lockFor = 10 * time.Minute
		}
		s.limiter.update(after.Auth.LoginMaxFails, 5*time.Minute, lockFor)
	}

	// 「允许未验签的更新包」的开合留一条审计记录：这一项决定的是「能不能不验签就把
	// 面板二进制换掉」，事后要查得到是谁在什么时候打开的、有效到几点。
	// 打开用 Warn（这是一段主动放宽的时间），关闭用 Info。
	//
	// 判据同时看布尔值与起点：重新打开一段已过期的窗口时布尔值没变，只有起点在动。
	if before.Update.AllowUnsignedUpdate != after.Update.AllowUnsignedUpdate ||
		before.Update.AllowUnsignedSince != after.Update.AllowUnsignedSince {
		if exp, ok := after.Update.UnsignedUpdateExpiry(unsignedNow); ok {
			s.deps.Log.Warn("设置：已打开「允许未验签的更新包」，到期后自动失效",
				"operator", operator(c), "ip", c.ClientIP(), "expiresAt", exp.Format(time.RFC3339))
		} else {
			s.deps.Log.Info("设置：已关闭「允许未验签的更新包」",
				"operator", operator(c), "ip", c.ClientIP())
		}
	}

	restartRequired := before.Panel.Port != after.Panel.Port ||
		normalizeBasePath(before.Panel.BasePath) != normalizeBasePath(after.Panel.BasePath) ||
		before.Panel.HTTPS.Enabled != after.Panel.HTTPS.Enabled ||
		before.Panel.HTTPS.CertID != after.Panel.HTTPS.CertID ||
		before.Panel.HTTPS.Domain != after.Panel.HTTPS.Domain
	// 入站防护**不在**这个清单里：它每次判定都现取配置快照（见 firewall.go 的
	// panelFirewall.current），保存完下一个连接与下一个请求就按新规则走。
	// 把它算进重启项只会让一次"加个白名单"变成一次面板重启。

	// 响应里带上「在线更新」那一段的当前状态：窗口到期时刻是算出来的，
	// 前端拿不到它就只能自己按 TTL 猜一个，两边的时钟一有偏差提示就不对了。
	// 顺带也让「过期后这次保存把开关清掉」这件事在界面上立刻可见，不必重载整页设置
	//（重载会把用户在其它段里还没保存的输入一起冲掉）。
	respondOK(c, gin.H{"ok": true, "restartRequired": restartRequired, "update": updateSettings(after.Update, unsignedNow)})

	if restartRequired {
		s.requestPanelRestart("面板监听或 HTTPS 配置已变更，正在优雅重启面板")
	}
}

// handleGetLogInfo 返回日志文件信息：当前路径、文件个数、合计大小（MB）。
// 统计对象为当前日志文件及其全部历史轮转备份（文件名形如 mantou.log.<时间戳>）。
func (s *Server) handleGetLogInfo(c *gin.Context) {
	if s.deps.LogFile == nil {
		respondError(c, http.StatusServiceUnavailable, "日志文件未就绪")
		return
	}
	path := s.deps.LogFile.Path()
	dir := filepath.Dir(path)
	base := filepath.Base(path)

	total := int64(0)
	count := 0
	if entries, err := os.ReadDir(dir); err == nil {
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			name := e.Name()
			// 仅统计当前文件与历史轮转备份（base 或 base.时间戳），排除同目录其它无关文件。
			if name != base && !strings.HasPrefix(name, base+".") {
				continue
			}
			info, ierr := e.Info()
			if ierr != nil {
				continue
			}
			total += info.Size()
			count++
		}
	}
	sizeMB := math.Round(float64(total)/1024/1024*100) / 100
	respondOK(c, gin.H{
		"path":   path,
		"count":  count,
		"sizeMB": sizeMB,
	})
}

// handleClearLogs 手动清空所有日志：删除当前日志文件 + 历史备份后自动创建新的空日志文件，
// 同时清空内存环形缓冲（UI 实时日志）。无需重启进程即可继续写入新文件。
func (s *Server) handleClearLogs(c *gin.Context) {
	if s.deps.LogFile == nil {
		respondError(c, http.StatusServiceUnavailable, "日志文件未就绪")
		return
	}
	if err := s.deps.LogFile.Reset(); err != nil {
		respondError(c, http.StatusInternalServerError, "清空日志文件失败: "+err.Error())
		return
	}
	s.deps.Log.Clear()
	s.deps.Log.Info("日志已被手动清空", "by", "user")
	respondOK(c, gin.H{"ok": true})
}
