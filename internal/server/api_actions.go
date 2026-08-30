package server

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"mantou/internal/config"
	"mantou/internal/modules/cron"
	"mantou/internal/modules/wol"
)

// registerActions 挂载资源动作路由。
func (s *Server) registerActions(g *gin.RouterGroup) {
	g.POST("/wol/:id/wake", s.handleWakeDevice)
	g.POST("/ddns/:id/run", s.handleRunDDNS)
	g.POST("/certs/:id/issue", s.handleIssueCert)
	g.GET("/certs/:id/export", s.handleExportCert)
	g.POST("/certs/import", s.handleImportCert)
	g.POST("/certs/:id/toggle", s.handleToggleCert)
	g.POST("/crontasks/:id/run", s.handleRunCronTask)
	g.GET("/meta/providers", s.handleProviders)
	g.GET("/meta/cron-describe", s.handleCronDescribe)
	// 候选网卡列表挂在 /meta 下而不是 /wol/interfaces：后者与 CRUD 的 /wol/:id
	// 在路由树的同一层冲突（同 /web/* 与 /webservices/:id 的取舍）。
	g.GET("/meta/wol-interfaces", s.handleWOLInterfaces)
	// Web 服务运行态：各子项活跃连接数、子项访问（连接）日志。
	// 使用 /web/* 前缀避免与 /webservices/:id 的 CRUD 路由冲突。
	g.GET("/web/stats", s.handleWebStats)
	g.GET("/web/child-status", s.handleWebChildStatus)
	g.GET("/web/child-logs", s.handleWebChildLogs)
	// Web 服务列表内联开关：专用轻量端点，**不写审计日志**（用户硬性要求——
	// "保存一定是所有模块点击保存的时候才会记录"，toggle 是 UI 轻量操作，
	// 编辑弹窗底部「保存」按钮仍走完整 PUT 路径产生审计日志）。
	g.POST("/webservices/:id/toggle", s.handleToggleWebService)
	g.POST("/webservices/:id/children/:cid/toggle", s.handleToggleWebServiceChild)
	g.DELETE("/webservices/:id/children/:cid", s.handleDeleteWebServiceChild)
}

// handleWebStats 返回各 Web 子项当前的活跃连接数（childID -> count）。
func (s *Server) handleWebStats(c *gin.Context) {
	if s.deps.Web == nil {
		respondOK(c, gin.H{})
		return
	}
	respondOK(c, s.deps.Web.Stats())
}

// handleWebChildStatus 返回各 Web 子项的链接状态（childID -> {lastOK, lastErr, lastStatus}），
// 供前端「链接状态」列展示：有正常访问则「连接正常」，最近一次失败则「连接失败（状态码）」，
// 两者皆无则「未访问」。
func (s *Server) handleWebChildStatus(c *gin.Context) {
	if s.deps.Web == nil {
		respondOK(c, gin.H{})
		return
	}
	respondOK(c, s.deps.Web.ChildStatus())
}

// handleWebChildLogs 返回指定 Web 子项的访问（连接）日志。
func (s *Server) handleWebChildLogs(c *gin.Context) {
	if s.deps.Web == nil {
		respondOK(c, []any{})
		return
	}
	childID := c.Query("child")
	limit := 200
	if v := c.Query("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			limit = n
		}
	}
	respondOK(c, s.deps.Web.ChildLogs(childID, limit))
}

// handleWOLInterfaces 返回候选网卡及其分类，供设备设置里的网卡下拉框使用。
//
// auto=true 的那几张就是「自动」模式实际会发出魔术包的网卡。把这件事摆到界面上
// 是这个端点存在的理由：用户看得见「会从这 2 张发出」，才可能发现
// 「怎么还会从 docker0 发出」——而虚拟网卡与公网网卡上的广播既唤不醒设备，
// 又会把目标 MAC 送给容器对端或同机房邻居（见 wol.selectTargets）。
//
// 走缓存的枚举结果（30 秒 TTL），因此这个端点被前端反复轮询也不会每次都去问内核要全表。
func (s *Server) handleWOLInterfaces(c *gin.Context) {
	respondOK(c, wol.Interfaces())
}

// wakeTimeout 手动唤醒接口等待发包完成的上限。
// wol.Wake 是同步的：它逐网卡解析广播地址并写 UDP，其中 net.ResolveUDPAddr 在广播地址
// 被填成域名时会走 DNS 解析，可能长时间不返回。超时只是把控制权还给请求方，
// 不去中断后台的发送——魔术包是一次无连接的 UDP 写入，放任它跑完不留任何需要回收的状态。
const wakeTimeout = 5 * time.Second

// handleWakeDevice 立即向指定设备发送网络唤醒魔术包。
//
// 设备级开关（Enabled）在这里**刻意不检查**：面板上的「唤醒」按钮是用户的显式动作。
// 受该开关约束的是自动化路径——定时唤醒与计划任务（见 app.wakeByID）。
func (s *Server) handleWakeDevice(c *gin.Context) {
	id := c.Param("id")
	cfg := s.deps.Config.Snapshot()
	// 按值拷贝出来再用，不持有指向快照的指针：cfg 是所有并发读者共享的只读快照，
	// 把 &cfg.WOLDevices[i] 带出去，将来一旦有人顺手在这个指针上改字段，
	// 就会就地污染其他读者看到的配置，并绕过 Update 的落盘与脏检查。
	var dev config.WOLDevice
	found := false
	for i := range cfg.WOLDevices {
		if cfg.WOLDevices[i].ID == id {
			dev = cfg.WOLDevices[i]
			found = true
			break
		}
	}
	if !found {
		respondError(c, http.StatusNotFound, "设备不存在")
		return
	}
	// 限流放在存在性检查之后：这样伪造的设备 ID 不会在限流表里留下条目，
	// 表的规模由本机真实设备数封顶，而不是由请求方决定（见 wakeLimiter 的说明）。
	if ok, retry := s.wakeLimiter.allow(id, time.Now()); !ok {
		secs := int((retry + time.Second - 1) / time.Second)
		c.Header("Retry-After", strconv.Itoa(secs))
		respondError(c, http.StatusTooManyRequests,
			fmt.Sprintf("唤醒过于频繁，请 %d 秒后重试", secs))
		return
	}

	// 发包放到后台协程里，本请求最多等 wakeTimeout，免得把 HTTP 处理协程
	// 连同前端那条「正在唤醒…」的提示一起挂死。口径与计划任务路径一致。
	done := make(chan error, 1)
	go func() { done <- wol.WakeDevice(dev) }()
	var err error
	select {
	case err = <-done:
	case <-time.After(wakeTimeout):
		err = fmt.Errorf("等待发送结果超时（%s）", wakeTimeout)
	}

	result := "已发送"
	if err != nil {
		result = "失败: " + err.Error()
	}
	// 记一次唤醒（只在内存里，重启归零，见 internal/runstats）。
	// 与定时调度那条路走同一个方法，免得将来只改了一边。
	s.deps.Stats.Woke(id, nowUnix(), result)
	if err != nil {
		respondError(c, http.StatusInternalServerError, result)
		return
	}
	respondOK(c, gin.H{"ok": true, "result": result})
}

// handleRunDDNS 立即执行一次指定 DDNS 规则。
func (s *Server) handleRunDDNS(c *gin.Context) {
	id := c.Param("id")
	if s.deps.DDNS == nil {
		respondError(c, http.StatusServiceUnavailable, "DDNS 模块未就绪")
		return
	}
	msg, err := s.deps.DDNS.RunOnce(id)
	if err != nil {
		respondError(c, http.StatusInternalServerError, err.Error())
		return
	}
	respondOK(c, gin.H{"ok": true, "result": msg})
}

// issueCertReq 触发证书签发。
// 续期窗口预检：首次（该证书尚无可用证书文件）直接触发申请；
// 已有证书时，若剩余天数大于「提前续期天数」则拒绝并给出明确提示，避免无谓的 ACME 请求。
func (s *Server) handleIssueCert(c *gin.Context) {
	id := c.Param("id")
	if s.deps.Cert == nil {
		respondError(c, http.StatusServiceUnavailable, "证书模块未就绪")
		return
	}
	cfg := s.deps.Config.Snapshot()
	var target *config.Certificate
	for i := range cfg.Certs {
		if cfg.Certs[i].ID == id {
			target = &cfg.Certs[i]
			break
		}
	}
	if target == nil {
		respondError(c, http.StatusNotFound, "证书不存在")
		return
	}

	if err := s.deps.Cert.IssueAsync(id, 30*time.Minute); err != nil {
		respondError(c, http.StatusConflict, err.Error())
		return
	}
	c.JSON(http.StatusAccepted, gin.H{"data": gin.H{"ok": true, "result": "证书签发任务已提交"}})
}

func (s *Server) handleExportCert(c *gin.Context) {
	if s.deps.Cert == nil {
		respondError(c, http.StatusServiceUnavailable, "证书模块未就绪")
		return
	}
	var target *config.Certificate
	for _, cert := range s.deps.Config.Snapshot().Certs {
		if cert.ID == c.Param("id") {
			item := cert
			target = &item
			break
		}
	}
	if target == nil {
		respondError(c, http.StatusNotFound, "证书不存在")
		return
	}
	includePrivateKey := c.Query("includePrivateKey") == "true"
	certPEM, keyPEM, err := s.deps.Cert.Export(*target, includePrivateKey)
	if err != nil {
		respondError(c, http.StatusNotFound, err.Error())
		return
	}
	resp := gin.H{"certPem": string(certPEM)}
	if includePrivateKey {
		resp["keyPem"] = string(keyPEM)
	}
	c.Header("Cache-Control", "no-store")
	respondOK(c, resp)
}

// importCertReq 是证书导入请求。
type importCertReq struct {
	ID      string `json:"id"`
	CertPEM string `json:"certPem"`
	KeyPEM  string `json:"keyPem"`
}

// handleImportCert 导入用户提供的证书与私钥。
func (s *Server) handleImportCert(c *gin.Context) {
	var req importCertReq
	if err := c.ShouldBindJSON(&req); err != nil {
		respondError(c, http.StatusBadRequest, "请求参数无效")
		return
	}
	if s.deps.Cert == nil {
		respondError(c, http.StatusServiceUnavailable, "证书模块未就绪")
		return
	}
	if req.ID == "" || req.CertPEM == "" || req.KeyPEM == "" {
		respondError(c, http.StatusBadRequest, "缺少证书 ID、证书或私钥")
		return
	}
	if err := s.deps.Cert.Import(req.ID, []byte(req.CertPEM), []byte(req.KeyPEM)); err != nil {
		respondError(c, http.StatusBadRequest, "导入失败: "+err.Error())
		return
	}
	respondOK(c, gin.H{"ok": true})
}

// toggleCertReq 是证书启用/禁用切换请求。
type toggleCertReq struct {
	Enabled bool `json:"enabled"`
}

// handleToggleCert 启用或禁用指定证书（列表快捷操作）。
// 禁用时若证书正被面板 HTTPS（Panel.HTTPS.CertID）引用，则拒绝并返回 409，
// 提示用户先到「设置」解绑面板证书，避免面板自身因证书失效而启动失败。
func (s *Server) handleToggleCert(c *gin.Context) {
	id := c.Param("id")
	var req toggleCertReq
	if err := c.ShouldBindJSON(&req); err != nil {
		respondError(c, http.StatusBadRequest, "请求参数无效")
		return
	}
	cfg := s.deps.Config.Snapshot()
	var cur *config.Certificate
	for i := range cfg.Certs {
		if cfg.Certs[i].ID == id {
			cur = &cfg.Certs[i]
			break
		}
	}
	if cur == nil {
		respondError(c, http.StatusNotFound, "证书不存在")
		return
	}
	if !req.Enabled {
		if used, mods := certInUse(cfg, id); used {
			respondError(c, http.StatusConflict, fmt.Sprintf("该证书正被以下模块使用：%s，无法禁用", strings.Join(mods, "、")))
			return
		}
	}
	if err := s.deps.Config.Update(func(c *config.Config) {
		for i := range c.Certs {
			if c.Certs[i].ID == id {
				c.Certs[i].Enabled = req.Enabled
				return
			}
		}
	}); err != nil {
		respondError(c, http.StatusInternalServerError, "保存失败")
		return
	}
	s.afterChange()
	// 敏感操作审计：启用/禁用证书记入 info 级日志（与通用资源审计格式保持一致）。
	if s.deps.Log != nil {
		verb := "禁用"
		if req.Enabled {
			verb = "启用"
		}
		s.logOp(verb, "SSL/TLS 证书", id, cur.Name, "")
	}
	respondOK(c, gin.H{"id": id, "enabled": req.Enabled})
}

// handleProviders 返回可用的 DNS 服务商等元信息，供前端下拉选择。
func (s *Server) handleProviders(c *gin.Context) {
	respondOK(c, gin.H{
		"dns": s.dnsProviders,
	})
}

// handleRunCronTask 立即执行一次指定计划任务。
func (s *Server) handleRunCronTask(c *gin.Context) {
	id := c.Param("id")
	if s.deps.Cron == nil {
		respondError(c, http.StatusServiceUnavailable, "计划任务模块未就绪")
		return
	}
	msg, err := s.deps.Cron.RunTaskByID(id)
	if err != nil {
		respondError(c, http.StatusInternalServerError, err.Error())
		return
	}
	respondOK(c, gin.H{"ok": true, "result": msg})
}

// handleCronDescribe 将 cron 表达式翻译为人类可读描述（zh/en）。
//
// 支持一次问多条：`?expr=A&expr=B&lang=zh-CN`，响应 items 与传入顺序一一对应。
// 计划任务页原先每条规则各发一个请求（N 条规则 = N 次往返，且都排在列表渲染之后），
// 批量之后固定一次往返。
//
// 用「重复的同名参数」而不是逗号拼接一个字符串：cron 表达式本身合法地含逗号
// （例如 `0 0,12 * * *` 表示每天 0 点和 12 点），拼起来就再也切不回来了。
//
// text 字段保留原样（首个 expr 的描述，无 expr 时为空串，与旧实现逐字节一致）：
// 编辑弹窗里的单条实时预览仍走这个字段，不必跟着改。
func (s *Server) handleCronDescribe(c *gin.Context) {
	lang := c.Query("lang")
	if lang == "" {
		lang = s.deps.Config.Snapshot().Settings.Language
	}
	exprs := c.QueryArray("expr")
	// 上限防滥用：翻译是纯字符串计算，但一次几万条照样能占住一个核。
	// 200 远高于任何现实规模的任务条数，正常使用碰不到这个界。
	const maxBatch = 200
	if len(exprs) > maxBatch {
		exprs = exprs[:maxBatch]
	}
	items := make([]string, 0, len(exprs))
	for _, expr := range exprs {
		items = append(items, cron.Describe(expr, lang))
	}
	text := ""
	if len(items) > 0 {
		text = items[0]
	}
	respondOK(c, gin.H{"text": text, "items": items})
}

// toggleWebServiceReq 是 Web 服务启用/禁用切换请求（父项与子项共用 body 形状）。
type toggleWebServiceReq struct {
	Enabled bool `json:"enabled"`
}

// handleToggleWebService 启用或禁用指定 Web 服务父项（列表快捷操作）。
// 审计用"启用/禁用"动词（非"保存"，满足用户"列表操作不写保存日志"），
// 编辑弹窗底部「保存」按钮仍走完整 PUT /webservices/:id 路径产生"保存"条目，互不干扰。
// 启用时若端口与面板冲突则直接拒绝。
func (s *Server) handleToggleWebService(c *gin.Context) {
	id := c.Param("id")
	var req toggleWebServiceReq
	if err := c.ShouldBindJSON(&req); err != nil {
		respondError(c, http.StatusBadRequest, "请求参数无效")
		return
	}
	cfg := s.deps.Config.Snapshot()
	var ws *config.WebService
	for i := range cfg.WebServices {
		if cfg.WebServices[i].ID == id {
			ws = &cfg.WebServices[i]
			break
		}
	}
	if ws == nil {
		respondError(c, http.StatusNotFound, "Web 服务不存在")
		return
	}
	if req.Enabled && ws.Port == cfg.Panel.Port {
		respondError(c, http.StatusBadRequest,
			fmt.Sprintf("Web 服务端口 %d 与面板管理端口冲突，请改用其他端口", ws.Port))
		return
	}
	// 与消息路由共用端口的前提也要在这条快捷路径上校验：否则一键启用之后
	// 这个服务绑不上端口，用户在列表里看不出原因，只有程序日志里一行"地址已被占用"。
	if req.Enabled {
		if err := checkWebhookPortShare(cfg, *ws); err != nil {
			respondError(c, http.StatusBadRequest, err.Error())
			return
		}
	}
	if err := s.deps.Config.Update(func(c *config.Config) {
		for i := range c.WebServices {
			if c.WebServices[i].ID == id {
				c.WebServices[i].Enabled = req.Enabled
				return
			}
		}
	}); err != nil {
		respondError(c, http.StatusInternalServerError, "保存失败")
		return
	}
	s.afterChange()
	// 审计：列表内联开关记入「启用/禁用 Web 服务 下 xxx」info 级日志（与通用资源审计格式一致）。
	// 注意：动词是"启用/禁用"而非"保存"——用户硬性要求"列表操作不写保存日志，只有点保存按钮才写保存"。
	if s.deps.Log != nil {
		verb := "禁用"
		if req.Enabled {
			verb = "启用"
		}
		s.logOp(verb, "Web 服务", id, ws.Name, "")
	}
	respondOK(c, gin.H{"id": id, "enabled": req.Enabled})
}

// handleToggleWebServiceChild 启用或禁用指定 Web 服务子项（列表快捷操作）。
// 与 handleToggleWebService 同：审计用"启用/禁用"动词（非"保存"）。
// 启用时若与同父项下其它已启用子项的 TLS 协议冲突（HTTP/HTTPS 混用）
// 则拒绝（与 validateWebService 在编辑保存时的校验保持一致）。
func (s *Server) handleToggleWebServiceChild(c *gin.Context) {
	pid := c.Param("id")
	cid := c.Param("cid")
	var req toggleWebServiceReq
	if err := c.ShouldBindJSON(&req); err != nil {
		respondError(c, http.StatusBadRequest, "请求参数无效")
		return
	}
	// 在 Update 回调内先改再校验，校验失败则回滚——保证落盘状态始终合法。
	var validErr error
	// 预取父项名 + 子项展示名，供审计日志使用（与 api_resources.childItems 命名一致：
	// 子项名取 note → 域名列表 → 兜底"子项"）。
	parentName := ""
	childName := ""
	if preCfg := s.deps.Config.Snapshot(); preCfg != nil {
		for i := range preCfg.WebServices {
			if preCfg.WebServices[i].ID != pid {
				continue
			}
			parentName = preCfg.WebServices[i].Name
			for j := range preCfg.WebServices[i].Children {
				if preCfg.WebServices[i].Children[j].ID != cid {
					continue
				}
				nm := preCfg.WebServices[i].Children[j].Note
				if nm == "" {
					if ds := preCfg.WebServices[i].Children[j].Domains; len(ds) > 0 {
						nm = strings.Join(ds, "、")
					} else {
						nm = "子项"
					}
				}
				childName = nm
				break
			}
			break
		}
	}
	if err := s.deps.Config.Update(func(c *config.Config) {
		for i := range c.WebServices {
			if c.WebServices[i].ID != pid {
				continue
			}
			for j := range c.WebServices[i].Children {
				if c.WebServices[i].Children[j].ID != cid {
					continue
				}
				c.WebServices[i].Children[j].Enabled = req.Enabled
				if err := validateWebService(c, c.WebServices[i], s.deps.DataDir); err != nil {
					c.WebServices[i].Children[j].Enabled = !req.Enabled // 回滚
					validErr = err
				}
				return
			}
		}
	}); err != nil {
		respondError(c, http.StatusInternalServerError, "保存失败")
		return
	}
	if validErr != nil {
		respondError(c, http.StatusBadRequest, validErr.Error())
		return
	}
	s.afterChange()
	// 审计：列表内联开关记入「启用/禁用 Web 服务 下 父项 的子项 子项名」info 级日志。
	// 同样刻意用"启用/禁用"而非"保存"，与父项开关、toggleCert 保持一致。
	if s.deps.Log != nil {
		verb := "禁用"
		if req.Enabled {
			verb = "启用"
		}
		s.logOp(verb, "Web 服务", pid, parentName+" 的子项 "+childName, "")
	}
	respondOK(c, gin.H{"id": pid, "child": cid, "enabled": req.Enabled})
}

// handleDeleteWebServiceChild 删除指定 Web 服务子项（列表快捷操作）。
// 与 handleToggleWebServiceChild 同：专用轻量端点，审计用"删除"动词（非"保存"）。
// 删除子项只会减少约束，无需再做端口/TLS 校验；成功后热重载回收该子项的监听/路由。
func (s *Server) handleDeleteWebServiceChild(c *gin.Context) {
	pid := c.Param("id")
	cid := c.Param("cid")
	// 预取父项名 + 子项展示名，供审计日志使用（命名同 childItems）。
	parentName := ""
	childName := ""
	var foundChild bool
	if preCfg := s.deps.Config.Snapshot(); preCfg != nil {
		for i := range preCfg.WebServices {
			if preCfg.WebServices[i].ID != pid {
				continue
			}
			parentName = preCfg.WebServices[i].Name
			for j := range preCfg.WebServices[i].Children {
				if preCfg.WebServices[i].Children[j].ID != cid {
					continue
				}
				nm := preCfg.WebServices[i].Children[j].Note
				if nm == "" {
					if ds := preCfg.WebServices[i].Children[j].Domains; len(ds) > 0 {
						nm = strings.Join(ds, "、")
					} else {
						nm = "子项"
					}
				}
				childName = nm
				foundChild = true
				break
			}
			break
		}
	}
	if !foundChild {
		respondError(c, http.StatusNotFound, "子项不存在")
		return
	}
	if err := s.deps.Config.Update(func(c *config.Config) {
		for i := range c.WebServices {
			if c.WebServices[i].ID != pid {
				continue
			}
			out := make([]config.WebChild, 0, len(c.WebServices[i].Children))
			for j := range c.WebServices[i].Children {
				if c.WebServices[i].Children[j].ID != cid {
					out = append(out, c.WebServices[i].Children[j])
				}
			}
			c.WebServices[i].Children = out
			return
		}
	}); err != nil {
		respondError(c, http.StatusInternalServerError, "删除失败")
		return
	}
	s.afterChange()
	if s.deps.Log != nil {
		s.logOp("删除", "Web 服务", pid, parentName+" 的子项 "+childName, "")
	}
	respondOK(c, gin.H{"ok": true})
}
