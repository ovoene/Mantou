package app

import (
	"errors"
	"path/filepath"
	"time"

	"mantou/internal/config"
	"mantou/internal/inboundfw"
	"mantou/internal/logx"
	"mantou/internal/module"
	"mantou/internal/modules/cert"
	"mantou/internal/modules/cron"
	"mantou/internal/modules/ddns"
	"mantou/internal/modules/forward"
	"mantou/internal/modules/notify"
	"mantou/internal/modules/webhook"
	"mantou/internal/modules/webservice"
	"mantou/internal/modules/wol"
	"mantou/internal/netguard"
	"mantou/internal/runstats"
	"mantou/internal/server"
)

// App 组装并持有全部功能模块与服务器依赖。
type App struct {
	Log     *logx.Logger
	CfgMgr  *config.Manager
	Modules *module.Manager

	// Stats 是列表页上那几个统计数字的存放处：只在内存里，重启归零，
	// 所有模块加起来有 1 MiB 的上限（见 runstats 包说明）。
	// 在这里建一份、传给需要的模块与接口层，不做成全局单例——那样测试之间会串数。
	Stats *runstats.Store

	DDNS       *ddns.Module
	WebService *webservice.Module
	Forward    *forward.Module
	WOL        *wol.Module
	Cron       *cron.Module
	Cert       *cert.Module
	Notify     *notify.Module
	Webhook    *webhook.Module

	// GlobalFirewall 服务防护（连接层）的运行态，创建一次、共享给 Web 服务、消息路由与
	// 服务器接口层——封禁表只有一份（见 internal/inboundfw）。
	GlobalFirewall *inboundfw.Firewall
}

// Build 创建并注册所有功能模块，返回可用于装配服务器的 App。
func Build(log *logx.Logger, cfgMgr *config.Manager, dataDir string) *App {
	modMgr := module.NewManager(log)
	stats := runstats.New()

	ddnsMod := ddns.New(log, cfgMgr)
	webMod := webservice.New(log)
	fwdMod := forward.New(log, cfgMgr)
	wolMod := wol.New(log, stats)
	cronMod := cron.New(log, cfgMgr)
	certMod := cert.New(log, filepath.Join(dataDir, "certs"), cfgMgr)
	notifyMod := notify.New(log, stats)
	webhookMod := webhook.New(log, stats, filepath.Join(dataDir, "logs", "webhook.log"))

	// 服务防护（连接层）：创建一份、共享给 Web 服务与消息路由两个监听，以及服务器接口层。
	// 它在 Accept 处拦截、并把 TLS 握手异常回灌进自动封禁计数，与面板入站防护是两套独立机制
	// （后者只管面板端口）。独立于业务模块创建，避免业务模块反向依赖防火墙包之外的编排逻辑。
	gfw := inboundfw.New(cfgMgr, log)
	webMod.SetGlobalFirewall(gfw)
	webhookMod.SetGlobalFirewall(gfw)

	// 证书解析器注入到 Web 服务（供 HTTPS 站点按 SNI 取证书）。
	webMod.SetCertResolver(certMod.Resolver())

	// 消息路由三处装配：出站能力、证书（模块自带 HTTPS 监听）、
	// 以及把出站结果回灌进入站的执行历史——这样"收到 → 命中规则 → 各目标投递结果"
	// 能在同一个列表里按事件 ID 串起来，排查时不用在两处日志之间来回对。
	webhookMod.SetNotifier(notifyMod)
	webhookMod.SetCertResolver(certMod.ResolveID)
	notifyMod.SetResultSink(webhookMod.RecordDelivery)

	// 消息路由的端口撞上某个 Web 服务时（80 / 443 是三方都想要的公共端口），
	// 由 Web 服务那一个监听按域名把请求转进来，消息路由自己不绑端口。
	// 注入模块而非处理器：Web 服务在绑定共享端口前要先叫它让出端口（见 webservice.WebhookPeer）。
	webMod.SetWebhookPeer(webhookMod)

	// 装配 ACME 自动签发器（DNS-01，复用 DNS 服务商适配层）。
	certMod.SetIssuer(cert.NewACMEIssuer(cfgMgr, log))

	// 计划任务动作处理器：解耦地调用各模块能力。
	// 每个处理器都必须遵守任务配置的超时（timeoutSec）：robfig 为每次触发单独起 goroutine，
	// 一个吊住不返回的动作不会拖垮调度器，但会让该任务此后每一轮都因「上一轮仍在执行中」被跳过，
	// 表现为任务静默停摆。
	cronMod.RegisterHandler("ddns.refresh", func(a config.CronAction, timeoutSec int) (string, error) {
		// DDNS 一轮包含取公网 IP + 调用服务商接口，两者都是网络调用，默认兜底 5 分钟。
		ctx, cancel := actionContext(timeoutSec, 5*time.Minute)
		defer cancel()
		return ddnsMod.RunOnceCtx(ctx, a.Params["ruleId"])
	})
	cronMod.RegisterHandler("wol.wake", func(a config.CronAction, timeoutSec int) (string, error) {
		ctx, cancel := actionContext(timeoutSec, 30*time.Second)
		defer cancel()
		return wakeByID(ctx, cfgMgr, a.Params["deviceId"])
	})
	cronMod.RegisterHandler("cert.renew", func(a config.CronAction, timeoutSec int) (string, error) {
		ctx, cancel := actionContext(timeoutSec, 10*time.Minute)
		defer cancel()
		return certMod.RenewDue(ctx)
	})
	// HTTP 动作：受任务超时约束，超时后主动终止，不阻塞调度器。
	cronMod.RegisterHandler("http", func(a config.CronAction, timeoutSec int) (string, error) {
		// 内网防护开关（默认关闭）：开启后 HTTP 动作目标解析到内网/保留地址将被拒绝。
		blockPrivate := cfgMgr.Snapshot().Settings.Security.BlockPrivateNetwork
		res, err := runHTTPAction(a, timeoutSec, blockPrivate)
		if err != nil && errors.Is(err, netguard.ErrBlocked) {
			// 拦截属安全事件，以 WARN 记录便于审计。
			log.Warn("内网防护已拦截计划任务 HTTP 请求", "task", a.Params["url"], "err", err.Error())
		}
		return res, err
	})

	// 通知动作：让计划任务能直接推一条消息（巡检报告、定时提醒这类用途）。
	// 走同步 Send 而不是入队：任务需要在自己的执行记录里看到投递结果，
	// 入队会让每次执行都显示"成功"，哪怕消息其实没发出去。
	cronMod.RegisterHandler("notify.send", func(a config.CronAction, timeoutSec int) (string, error) {
		ctx, cancel := actionContext(timeoutSec, 2*time.Minute)
		defer cancel()
		return sendNotifyAction(ctx, notifyMod, a)
	})

	// 注册顺序即重载顺序：证书先于 Web 服务，保证 HTTPS 站点可取到证书；
	// 出站先于消息路由，保证路由开始收消息时投递目标已经就绪。
	modMgr.Register(certMod)
	modMgr.Register(ddnsMod)
	modMgr.Register(webMod)
	modMgr.Register(fwdMod)
	modMgr.Register(wolMod)
	modMgr.Register(cronMod)
	modMgr.Register(notifyMod)
	modMgr.Register(webhookMod)

	return &App{
		Log:            log,
		CfgMgr:         cfgMgr,
		Modules:        modMgr,
		Stats:          stats,
		DDNS:           ddnsMod,
		WebService:     webMod,
		Forward:        fwdMod,
		WOL:            wolMod,
		Cron:           cronMod,
		Cert:           certMod,
		Notify:         notifyMod,
		Webhook:        webhookMod,
		GlobalFirewall: gfw,
	}
}

// ReloadAll 用当前配置重载全部模块。
func (a *App) ReloadAll() {
	a.Modules.ReloadAll(a.CfgMgr.Get())
}

// CloseAll 关闭全部模块。
func (a *App) CloseAll() {
	a.Modules.CloseAll()
}

// ServerDeps 构造服务器依赖，包含模块句柄与配置变更回调。
func (a *App) ServerDeps(base server.Deps) server.Deps {
	base.Modules = a.Modules
	base.DDNS = a.DDNS
	base.WOL = a.WOL
	base.Cert = a.Cert
	base.Cron = a.Cron
	base.Web = a.WebService
	base.Notify = a.Notify
	base.Webhook = a.Webhook
	base.GlobalFirewall = a.GlobalFirewall
	base.Stats = a.Stats
	base.OnConfigChanged = a.ReloadAll
	return base
}
