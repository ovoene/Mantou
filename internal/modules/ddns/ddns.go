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

// Close 停止全部规则。
func (m *Module) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for id, run := range m.runners {
		run.stop()
		delete(m.runners, id)
	}
	return nil
}

// Status 实现 module.StatusReporter。
func (m *Module) Status() module.Status {
	m.mu.Lock()
	defer m.mu.Unlock()
	healthy := true
	for _, run := range m.runners {
		if !run.lastOK() {
			healthy = false
		}
	}
	return module.Status{
		Name:    "ddns",
		Total:   len(m.runners),
		Active:  len(m.runners),
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
