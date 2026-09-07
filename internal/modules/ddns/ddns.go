package ddns

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"mantou/internal/config"
	"mantou/internal/dnsprovider"
	"mantou/internal/logx"
	"mantou/internal/module"
	"mantou/internal/netguard"
)

// errNoRecord 表示目标既未配置任何主机记录、也未允许更新根域名。
var errNoRecord = errors.New("未配置任何主机记录（也未允许更新根域名）")

// Module 管理所有 DDNS 规则：按各自间隔探测 IP 并更新解析记录。
type Module struct {
	mu      sync.Mutex
	log     *logx.Logger
	cfgMgr  ConfigWriter
	runners map[string]*ruleRunner // key = rule.ID
}

// ConfigWriter 供模块回写规则运行状态（LastIP/LastStatus 等）。
// 运行状态一律走 UpdateState：它只更新内存并合并落盘到 state.json，
// 不会为一次探测结果重写整份 config.json（见 config/state.go）。
// 读取一律用 Snapshot：本模块从不在配置副本上改东西（改动全走 UpdateState 的回调），
// 而 Get 每次都要把整份配置序列化再反序列化一遍——每条规则每轮探测都做一次纯属浪费。
type ConfigWriter interface {
	UpdateState(mutate func(c *config.Config)) error
	Snapshot() *config.Config
}

// New 创建 DDNS 模块。cfgMgr 用于回写最近状态。
func New(log *logx.Logger, cfgMgr ConfigWriter) *Module {
	return &Module{
		log:     log,
		cfgMgr:  cfgMgr,
		runners: make(map[string]*ruleRunner),
	}
}

// Name 实现 module.Module。
func (m *Module) Name() string { return "ddns" }

// Reload 差量启停各规则的探测循环。
func (m *Module) Reload(cfg *config.Config) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	desired := make(map[string]config.DDNSRule)
	for _, r := range cfg.DDNS {
		if r.Enabled {
			desired[r.ID] = r
		}
	}

	for id, run := range m.runners {
		if _, ok := desired[id]; !ok {
			run.stop()
			delete(m.runners, id)
		}
	}

	for id, rule := range desired {
		if existing, ok := m.runners[id]; ok {
			existing.update(rule)
			continue
		}
		run := newRuleRunner(rule, m.log, m.cfgMgr)
		run.start()
		m.runners[id] = run
	}
	return nil
}

// closeGrace 是 Close 等待各规则那一轮探测收尾的上限。
//
// 5 秒足够：cancel 之后剩下的活儿只有把当次结果写进 state.json（各 DNS 服务商的
// HTTP 请求都带 ctx，见 dnsprovider，取消即刻返回）。给出上限而不是无限等，
// 是因为"关不掉"比"少等一轮"严重——进程退不出去没有任何补救办法。
const closeGrace = 5 * time.Second

// Close 停止全部规则，并给正在执行的那一轮留一点收尾时间。
//
// 只 cancel 不等的话，被掐断的那一轮会一边跑一边和配置管理器的最后一次落盘赛跑：
// 它末尾的 setStatus 要写 state.json，而那时管理器可能已经 flush 完了。
//
// 等待放在锁外：一轮探测里可能压着多次 DNS 接口调用，占着 m.mu 会把同时到来的
// Status 查询（总览页）一起卡住。
func (m *Module) Close() error {
	m.mu.Lock()
	runners := make([]*ruleRunner, 0, len(m.runners))
	for id, run := range m.runners {
		runners = append(runners, run)
		delete(m.runners, id)
	}
	m.mu.Unlock()

	for _, run := range runners {
		run.stop()
	}
	// 一个共享的截止时刻，而不是每条规则各等 closeGrace：规则数没有上界，
	// 逐条计时会让"关闭最多花 5 秒"变成"最多花 5 秒 × 规则数"。
	deadline := time.After(closeGrace)
	for _, run := range runners {
		select {
		case <-run.done:
		case <-deadline:
			m.log.Warn("DDNS 探测未在关闭窗口内结束，放弃等待", "timeout", closeGrace.String())
			return nil
		}
	}
	return nil
}

// Status 实现 module.StatusReporter。
//
// Total 是正在跑的规则数（停用的规则不建 runner），Active 是其中最近一轮成功的那些——
// 与端口转发模块同一口径（见 forward.Module.Status）：两个模块的形态相同（每条规则一个
// 带健康状态的 runner），报出来的数就该是同一种意思。原先 Active 直接取 len(m.runners)，
// 于是总览页永远显示"N / N"，一条规则连着失败也看不出来，Healthy 那个布尔又只说得出
// "有没有出问题"、说不出"几条出了问题"。
func (m *Module) Status() module.Status {
	m.mu.Lock()
	defer m.mu.Unlock()
	active := 0
	healthy := true
	for _, run := range m.runners {
		if run.lastOK() {
			active++
		} else {
			healthy = false
		}
	}
	return module.Status{
		Name:    "ddns",
		Total:   len(m.runners),
		Active:  active,
		Healthy: healthy,
	}
}

// RunOnce 立即执行一次指定规则（供手动触发调用，不设超时上限）。
func (m *Module) RunOnce(ruleID string) (string, error) {
	return m.RunOnceCtx(context.Background(), ruleID)
}

// RunOnceCtx 立即执行一次指定规则，整个过程（取公网 IP、调用 DNS 服务商接口）受 ctx 约束。
// 规则未在运行（已禁用或尚未加载）时，从配置查找并临时执行一次，便于用户在启用前先行验证配置。
//
// 计划任务走这条路径：任务配置的超时必须能真正掐断执行，否则一个吊住不返回的
// DNS 接口会让该任务的 goroutine 长期挂着，也让「上一轮仍在执行中」的跳过逻辑永久生效。
func (m *Module) RunOnceCtx(ctx context.Context, ruleID string) (string, error) {
	m.mu.Lock()
	run := m.runners[ruleID]
	m.mu.Unlock()
	if run != nil {
		return run.execute(ctx)
	}

	cfg := m.cfgMgr.Snapshot()
	for _, rule := range cfg.DDNS {
		if rule.ID == ruleID {
			tmp := newRuleRunner(rule, m.log, m.cfgMgr)
			defer tmp.stop()
			return tmp.execute(ctx)
		}
	}
	return "", fmt.Errorf("规则不存在: %s", ruleID)
}

// ruleRunner 承载单条 DDNS 规则的探测循环。
type ruleRunner struct {
	mu     sync.Mutex
	rule   config.DDNSRule
	log    *logx.Logger
	cfgMgr ConfigWriter

	ctx    context.Context
	cancel context.CancelFunc
	// done 在探测协程退出后关闭，供 Close 等待收尾。
	// 只有 start() 起过协程的 runner 会关闭它；RunOnceCtx 里那个临时 runner
	// 不进 m.runners，也就没人等它。
	done chan struct{}

	lastIP    string
	lastOKVal bool
}

func newRuleRunner(rule config.DDNSRule, log *logx.Logger, cfgMgr ConfigWriter) *ruleRunner {
	ctx, cancel := context.WithCancel(context.Background())
	return &ruleRunner{
		rule:      rule,
		log:       log,
		cfgMgr:    cfgMgr,
		ctx:       ctx,
		cancel:    cancel,
		done:      make(chan struct{}),
		lastIP:    rule.LastIP, // 从持久化基准播种：使「首次增加」才强制同步，重启不再误判为首次
		lastOKVal: true,
	}
}

func (r *ruleRunner) update(rule config.DDNSRule) {
	r.mu.Lock()
	r.rule = rule
	r.mu.Unlock()
}

func (r *ruleRunner) lastOK() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.lastOKVal
}

func (r *ruleRunner) interval() time.Duration {
	r.mu.Lock()
	sec := r.rule.IntervalSec
	r.mu.Unlock()
	if sec <= 0 {
		sec = 300
	}
	return time.Duration(sec) * time.Second
}

// name 返回规则名称。必须经由此访问器取值而不能直接读 r.rule.Name：
// Reload 会在探测协程运行期间调用 update() 整体替换 r.rule（持有 r.mu），
// 若在协程里裸读字段就与之构成数据竞争——string 是「指针+长度」双字结构，
// 非同步读可能取到指针与长度来自不同次写入的撕裂值，进而越界 panic。
func (r *ruleRunner) name() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.rule.Name
}

func (r *ruleRunner) start() {
	go func() {
		defer close(r.done)
		// 启动后先立即执行一次。
		if _, err := r.execute(r.ctx); err != nil {
			r.log.Warn("DDNS 首次执行失败", "rule", r.name(), "err", err.Error())
		}
		ticker := time.NewTicker(r.interval())
		defer ticker.Stop()
		for {
			select {
			case <-r.ctx.Done():
				return
			case <-ticker.C:
				if _, err := r.execute(r.ctx); err != nil {
					r.log.Warn("DDNS 执行失败", "rule", r.name(), "err", err.Error())
				}
				// 间隔可能被更新，重置 ticker。
				ticker.Reset(r.interval())
			}
		}
	}()
}

func (r *ruleRunner) stop() { r.cancel() }

// stoppedEarly 判断这一轮是不是被外部掐断的（模块 Close、Reload 删掉了这条规则）。
//
// 掐断的那一轮什么也没测出来，它的"失败"不该被写进 state.json 当成规则的最近状态——
// 否则每次正常退出都会给当时在跑的规则留下一句「取址失败: context canceled」，
// 下次启动面板上就显示成一条出错的规则，而它其实好得很。
//
// 只看 ctx 不看返回的 error：取消会穿过 http 客户端、服务商实现好几层包装回来，
// 哪一层有没有保住 errors.Is 的链子说不准，而 ctx 自己的状态是确定的。
//
// 只认 Canceled、不认 DeadlineExceeded：后者是"给了预算而没跑完"（计划任务那条路会设，
// 见 RunOnceCtx），那是一个真实结果，该记下来让用户看见。
func stoppedEarly(ctx context.Context) bool { return errors.Is(ctx.Err(), context.Canceled) }

// execute 探测 IP 并在变化时更新全部目标。
func (r *ruleRunner) execute(ctx context.Context) (string, error) {
	r.mu.Lock()
	rule := r.rule
	prevIP := r.lastIP
	r.mu.Unlock()

	cfg := r.cfgMgr.Snapshot()
	blockPrivate := cfg.Settings.Security.BlockPrivateNetwork

	ip, err := detectIP(ctx, rule.Source, rule.Stack, blockPrivate)
	if err != nil {
		if stoppedEarly(ctx) {
			return "", err
		}
		if errors.Is(err, netguard.ErrBlocked) {
			// 内网防护拦截属安全事件，以 WARN 记录，便于审计是否有人试图诱导服务端访问内网。
			r.log.Warn("内网防护已拦截取址请求", "rule", rule.Name, "source", rule.Source.Type, "err", err.Error())
		}
		r.setStatus(false, "取址失败: "+err.Error(), false)
		return "", err
	}

	// 首次同步（无历史基准）必须执行；之后仅在检测到 IP 变化时才同步。
	isFirst := prevIP == ""
	if !isFirst && ip == prevIP {
		// IP 未变化：不执行任何 DNS 更新，也绝不刷新「最近更新」时间。
		r.setStatus(true, "IP 未变化", false)
		return "IP 未变化: " + ip, nil
	}

	recordType := "A"
	if rule.Stack == "ipv6" {
		recordType = "AAAA"
	}

	var firstErr error
	anyUpdated := false // 是否真正向 DNS 写入了记录（仅此时才刷新「最近更新」）
	for _, t := range rule.Targets {
		secrets, provName, serr := resolveSecrets(cfg, t.CredentialRef)
		if serr != nil {
			firstErr = serr
			continue
		}
		provider := t.Provider
		if provider == "" {
			provider = provName
		}
		p, perr := dnsprovider.Get(provider)
		if perr != nil {
			firstErr = perr
			continue
		}
		rt := t.RecordType
		if rt == "" {
			rt = recordType
		}
		// 计算本目标需要更新的记录名列表：
		// 各主机记录（二级域名）逐个更新；仅当显式打开 AllowRoot 时才附加根域名(@)。
		names := recordNames(t)
		if len(names) == 0 {
			firstErr = errNoRecord
			r.log.Warn("DDNS 目标未配置任何主机记录", "rule", rule.Name, "domain", t.Domain)
			continue
		}
		for _, name := range names {
			uerr := p.EnsureRecord(ctx, dnsprovider.RecordRequest{
				Domain:     t.Domain,
				Subdomain:  name,
				RecordType: rt,
				Value:      ip,
				TTL:        t.TTL,
				Line:       t.Line,
				Secrets:    secrets,
			})
			if uerr != nil {
				firstErr = uerr
				r.log.Warn("DDNS 更新目标失败", "rule", rule.Name, "domain", fqdnOf(t.Domain, name), "err", uerr.Error())
				continue
			}
			r.log.Info("DDNS 已更新", "rule", rule.Name, "domain", fqdnOf(t.Domain, name), "ip", ip)
			anyUpdated = true
		}
	}

	// 仅在确有记录写入成功（anyUpdated）时才推进内存/配置中的「最近同步 IP」，
	// 失败分支保留上一次成功的值，使下一轮能继续重试失败的更新，避免记录永久失步。
	if anyUpdated {
		r.mu.Lock()
		r.lastIP = ip
		r.mu.Unlock()
	}

	if firstErr != nil {
		if stoppedEarly(ctx) {
			return ip, firstErr
		}
		// 部分目标更新失败：仅当确有记录被成功写入时才刷新时间。
		r.setStatus(false, "部分目标更新失败: "+firstErr.Error(), anyUpdated)
		return ip, firstErr
	}
	r.setStatus(true, "已更新到 "+ip, anyUpdated)
	return "已更新到 " + ip, nil
}

// setStatus 回写运行状态到配置。updated=true 时才刷新「最近更新」时间，
// 保证该时间只在真实执行了 DNS 记录更新（IP 确已变化）时推进。
func (r *ruleRunner) setStatus(ok bool, msg string, updated bool) {
	r.mu.Lock()
	r.lastOKVal = ok
	ruleID := r.rule.ID
	ip := r.lastIP
	r.mu.Unlock()

	// 回写运行状态（仅运行态，不触碰配置字段）。
	_ = r.cfgMgr.UpdateState(func(c *config.Config) {
		for i := range c.DDNS {
			if c.DDNS[i].ID == ruleID {
				c.DDNS[i].LastIP = ip
				// 状态文本来自 DNS 服务商响应/取址响应，长度不可控，需裁剪后再持久化。
				c.DDNS[i].LastStatus = config.TruncateStatus(msg)
				if updated {
					c.DDNS[i].LastUpdateAt = time.Now().Unix()
				}
				return
			}
		}
	})
}

// recordNames 计算一个目标需要更新的记录名列表：
// 依次取各主机记录（二级域名，去空白后非空且非 "@"），
// 仅当显式打开 AllowRoot 时附加根域名 "@"。
func recordNames(t config.DDNSTarget) []string {
	var names []string
	seen := map[string]bool{}
	for _, s := range t.Subdomains {
		s = strings.TrimSpace(s)
		if s == "" || s == "@" {
			continue
		}
		if seen[s] {
			continue
		}
		seen[s] = true
		names = append(names, s)
	}
	if t.AllowRoot {
		names = append(names, "@")
	}
	return names
}

// fqdnOf 由主域名与记录名拼出完整域名（记录名为空或 "@" 时即主域名）。
func fqdnOf(domain, name string) string {
	if name == "" || name == "@" {
		return domain
	}
	return name + "." + domain
}

// resolveSecrets 依据凭证引用从配置中查找凭证 Secrets 及其服务商。
func resolveSecrets(cfg *config.Config, credRef string) (map[string]string, string, error) {
	for _, c := range cfg.Credentials {
		if c.ID == credRef {
			return c.Secrets, c.Provider, nil
		}
	}
	return nil, "", fmt.Errorf("找不到凭证: %s", credRef)
}
