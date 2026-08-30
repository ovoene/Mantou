package server

import (
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
		"update": cfg.Update,
		"auth": gin.H{
			"sessionHours":       cfg.Auth.SessionHours,
			"sessionIdleMinutes": cfg.Auth.SessionIdleMinutes,
			"loginMaxFails":      cfg.Auth.LoginMaxFails,
			"loginLockMinutes":   cfg.Auth.LoginLockMinutes,
		},
		"security": gin.H{
			"blockPrivateNetwork": cfg.Settings.Security.BlockPrivateNetwork,
		},
		"restart": restartSettings(cfg.Settings.Restart),
		"certs":   s.certOptions(cfg),
	})
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
		BlockPrivateNetwork bool `json:"blockPrivateNetwork"`
	} `json:"security"`
	Restart *restartReq `json:"restart"`
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
				cfg.Update.AllowUnsignedUpdate = *req.Update.AllowUnsignedUpdate
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

	restartRequired := before.Panel.Port != after.Panel.Port ||
		normalizeBasePath(before.Panel.BasePath) != normalizeBasePath(after.Panel.BasePath) ||
		before.Panel.HTTPS.Enabled != after.Panel.HTTPS.Enabled ||
		before.Panel.HTTPS.CertID != after.Panel.HTTPS.CertID ||
		before.Panel.HTTPS.Domain != after.Panel.HTTPS.Domain

	respondOK(c, gin.H{"ok": true, "restartRequired": restartRequired})

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
