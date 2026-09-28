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
	// 连私钥一起导出要当场验一次密码，所以是另一条 POST 路由（凭据放请求体，不进地址栏与日志）。
	g.POST("/certs/:id/export", s.handleExportCertWithKey)
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

// handleExportCert 导出证书（不含私钥）。
//
// 连私钥一起导出走 handleExportCertWithKey：那一支要当场验一次当前密码。这里若仍按
// includePrivateKey=true 放行，那道复核就等于没有，所以明确拒绝并说清该怎么做——
// 旧版页面收到这个 403 会自动退回"只导出证书"（见 Certs.vue 的 exportCert）。
func (s *Server) handleExportCert(c *gin.Context) {
	if c.Query("includePrivateKey") == "true" {
		respondError(c, http.StatusForbidden, "导出私钥需要验证当前账户与密码，请刷新页面后重试")
		return
	}
	s.exportCert(c, false)
}

// exportCertKeyReq 导出私钥时的身份复核。
type exportCertKeyReq struct {
	Account  string `json:"account"`
	Password string `json:"password"`
}

// handleExportCertWithKey 导出证书与私钥，动手之前当场验一次当前账户与密码。
//
// 为什么私钥要单独过这一关：这套接口里别的凭证一律不让一条会话读到——域名服务商密钥、
// 通知目标的请求头在列表里脱敏，整份备份导出要验密码（handleExportConfig）——唯独证书私钥
// 原先只凭会话就能整份取走。而它是后果最持久的那一样：会话可以撤、密码可以改，
// 一份带走的私钥却能一直冒充这个域名，直到证书过期为止。
//
// 失败计数与导出备份、改账户等那几处共用一份（见 reauth.go）：都是"拿一条会话反复猜当前密码"。
// 403 而不是 401：会话是好的，只是这一次的凭据没对上，不该让前端把人强制登出。
func (s *Server) handleExportCertWithKey(c *gin.Context) {
	if !s.reauthAllowed(c) {
		return
	}
	defer s.reauthDone(c)
	var req exportCertKeyReq
	if err := c.ShouldBindJSON(&req); err != nil {
		respondError(c, http.StatusBadRequest, "请求参数无效")
		return
	}
	if !adminCredentialsOK(s.deps.Config.Snapshot().Auth, req.Account, req.Password) {
		s.reauthFail(c)
		s.deps.Log.Warn("导出证书私钥的身份复核失败，已拒绝",
			"id", c.Param("id"), "operator", operator(c), "ip", c.ClientIP())
		respondError(c, http.StatusForbidden, "当前账户或密码不正确，私钥未导出")
		return
	}
	s.reauthOK(c)
	s.exportCert(c, true)
}

// exportCert 导出指定证书，includePrivateKey 决定带不带私钥（调用方负责把关）。
func (s *Server) exportCert(c *gin.Context, includePrivateKey bool) {
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
	certPEM, keyPEM, err := s.deps.Cert.Export(*target, includePrivateKey)
	if err != nil {
		respondError(c, http.StatusNotFound, err.Error())
		return
	}
	// 敏感操作审计。导出是这套接口里外泄面最大的一个动作——它把证书、可选连私钥一起
	// 交到浏览器手上，而私钥一旦离开这台机器就再也收不回来了。启用/禁用证书都记了一条
	// （见 handleToggleCert），没有理由这一个不记。
	//
	// 「含私钥」与否必须写进文案：事后追查时"只拿了公钥"和"把私钥也拿走了"是两件完全
	// 不同的事，而请求参数不会留在日志里。来源 IP 同理（面板的 trustedProxies 已置 nil，
	// c.ClientIP() 拿到的是真实对端地址，见 server.go 那段说明）。
	scope := "（仅证书）"
	if includePrivateKey {
		scope = "（含私钥）"
	}
	s.logOp("导出", "SSL/TLS 证书", target.ID, target.Name, scope+"，来源 IP "+c.ClientIP())
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
	// 只能导入到配置里已有的证书条目上。
	//
	// 原先 ID 只校验了"是个合法文件名"：任意一个配置里没有的 ID 也照样写出 <ID>.crt / .key，
	// 并立刻进了内存里的证书索引。那张索引按域名认领，而且"到期更晚的赢"——一张不属于任何
	// 条目的证书于是能抢走真证书的域名；SNI 解析拿到它之后发现这个 ID 不在配置里（按禁用处理），
	// 握手直接失败，站点打不开，直到下一次保存配置重建索引为止。留在磁盘上的两个文件也成了孤儿。
	//
	// 路径方式的证书同样不收：它的内容来自用户指定的磁盘路径（Reload 时从那里读），
	// 往证书目录里写一份只会与真正生效的那份对不上。
	var target *config.Certificate
	for _, cert := range s.deps.Config.Snapshot().Certs {
		if cert.ID == req.ID {
			item := cert
			target = &item
			break
		}
	}
	if target == nil {
		respondError(c, http.StatusNotFound, "证书不存在")
		return
	}
	if target.Method == "path" {
		respondError(c, http.StatusBadRequest, "这张证书是「路径」方式，内容直接读取磁盘上的文件，不能在这里导入；请修改它的证书与私钥路径")
		return
	}
	if err := s.deps.Cert.Import(req.ID, []byte(req.CertPEM), []byte(req.KeyPEM)); err != nil {
		respondError(c, http.StatusBadRequest, "导入失败: "+err.Error())
		return
	}
	// 敏感操作审计，与导出成对。导入换掉的是这个站点对外出示的身份：换进来的证书之后会被
	// 面板 HTTPS 与各 Web 子项直接使用，而这条路径不经过 registerCRUD，没有任何审计记录。
	// 只记 ID / 名称与来源 IP，PEM 内容一个字节都不进日志。
	s.logOp("导入", "SSL/TLS 证书", req.ID, target.Name, "（手动上传证书与私钥），来源 IP "+c.ClientIP())
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
//
// 启用时跑的是与保存**同一套**完整校验（validateWebService），而且是在配置写锁内
// 先翻转、再校验、不过就回滚，与子项开关（handleToggleWebServiceChild）同一形状。
//
// 原先这里只查了两件事（端口撞面板、与消息路由共用端口），而父项的大部分约束恰恰
// 只在"父项启用"时才生效：同一（地址族, 端口）只许一个启用父项、跨父项 TLS 一致、
// 域名在同一端口上的归属与面板域名保留、"默认站点"只能有一个。于是"先存成停用、
// 再点一下列表开关"就能把保存时会被拒的配置开起来——两个父项被静默聚合进同一个监听，
// 一方的 TLS 设置被另一方覆盖，界面上两边都是绿的。
//
// 禁用不校验：关掉一个服务只会减少约束，必须永远走得通。
func (s *Server) handleToggleWebService(c *gin.Context) {
	id := c.Param("id")
	var req toggleWebServiceReq
	if err := c.ShouldBindJSON(&req); err != nil {
		respondError(c, http.StatusBadRequest, "请求参数无效")
		return
	}
	var (
		name     string
		found    bool
		validErr error
	)
	if err := s.deps.Config.Update(func(c *config.Config) {
		for i := range c.WebServices {
			if c.WebServices[i].ID != id {
				continue
			}
			found = true
			name = c.WebServices[i].Name
			was := c.WebServices[i].Enabled
			c.WebServices[i].Enabled = req.Enabled
			if req.Enabled {
				if err := validateWebService(c, c.WebServices[i], s.deps.DataDir); err != nil {
					c.WebServices[i].Enabled = was // 回滚：落盘的状态始终合法
					validErr = err
				}
			}
			return
		}
	}); err != nil {
		respondError(c, http.StatusInternalServerError, "保存失败")
		return
	}
	if !found {
		respondError(c, http.StatusNotFound, "Web 服务不存在")
		return
	}
	if validErr != nil {
		respondError(c, http.StatusBadRequest, validErr.Error())
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
		s.logOp(verb, "Web 服务", id, name, "")
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
