package cert

import (
	"context"
	"crypto/tls"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"mantou/internal/config"
	"mantou/internal/logx"
	"mantou/internal/module"
)

// Module 管理证书：导入、ACME 自动签发与续期，并为其他模块提供证书解析。
type Module struct {
	mu      sync.Mutex
	log     *logx.Logger
	store   *Store
	cfgMgr  ConfigWriter
	issuer  Issuer // ACME 签发器；未装配时为 nil
	issuing map[string]bool

	// baseCtx 是所有后台签发/续期的父 context，renewCancel 取消它即可同时停掉
	// 续期循环与在飞的 IssueAsync。IssueAsync 原先用 context.Background()，
	// 与模块生命周期完全脱钩：进程退出时那些协程还在跑（超时上限 30 分钟），
	// 而它们随后写文件、回写配置的对象都已经在关闭流程里了。
	baseCtx     context.Context
	renewCancel context.CancelFunc // 停止内置续期循环与在飞签发

	// inflight 统计「正在签发/续期」的任务数（含同步的 Issue、续期循环里的续期、
	// IssueAsync 的后台协程），Close 靠它等待收尾；closed 置位后不再受理新任务。
	// 计数在持有 mu 的 beginIssue 里递增，因此不会出现「Close 已开始 Wait 又被 Add」的竞态。
	inflight sync.WaitGroup
	closed   bool

	// startupChecked 记录本进程是否已经做过那次「启动检查」（见 startupCheck）。
	// Reload 在每次配置变更后都会被调用（见 app 里的 OnConfigChanged），而那条日志只该在
	// 进程起来时记一次；这个标志用来区分「第一次加载配置」与「此后的每一次改动」。
	startupChecked bool

	// lastRenewCheck 记录每张证书最近一次「已到续期时刻并完成检查」的日期（YYYY-MM-DD，本地时区）。
	// 判定用「今天是否已检查过」而非「当前分钟是否恰好等于续期时刻」：一分钟 ticker 只保证
	// 「至少 1 分钟」，GC 停顿、容器 CPU 限流、宿主休眠都会让某一分钟被整个跳过，
	// 从而当天完全不检查续期；漂移若是系统性的还会连续多天错过。
	// 改为「过了时刻且今天没跑过就补跑」后，这些情形都能在下一次心跳里自动补上。
	lastRenewCheck map[string]string

	total   int
	expired int
}

// ConfigWriter 供模块回写证书状态。
// Snapshot 返回只读共享快照（不可修改），供每次 TLS 握手都要走的启用状态判定使用；
// Get 返回深拷贝，供需要在副本上改动的路径（如把签发生成的 ACME 账户私钥写回）使用。
// 签发/续期进度属于运行态，走 UpdateState 合并落盘到 state.json；而 ACME 账户私钥
// 是配置数据，必须由 acme.go 经 Update 同步落盘（见 config/state.go）。
type ConfigWriter interface {
	Update(mutate func(c *config.Config)) error
	UpdateState(mutate func(c *config.Config)) error
	Get() *config.Config
	Snapshot() *config.Config
}

// Issuer 是 ACME 自动签发器接口。基于 golang.org/x/crypto/acme 实现（见 acme.go）。
// dnsProvider 为 DNS-01 验证所用的服务商标识（来自凭证）。
// progress 用于回报阶段进度（如「正在写入 DNS 验证记录」），可为 nil；实现方应保证其轻量、
// 且不在内部长期持有锁。传入的 progress 会在 issue 流程中把当前阶段写入证书的「正在签发」状态，
// 避免面板一直显示静止的 running 而无从判断卡在哪一步。
type Issuer interface {
	Issue(ctx context.Context, c config.Certificate, account *config.ACMEAccount, dnsProvider string, secrets map[string]string, progress func(string)) (certPEM, keyPEM []byte, err error)
}

// New 创建证书模块。dir 为证书存储目录（data/certs）。
// 同时启动内置的每日续期循环：对启用自动续期且临近到期的证书自动重新签发，
// 不依赖计划任务模块（用户也可另建 cert.renew 计划任务手动/定时触发）。
func New(log *logx.Logger, dir string, cfgMgr ConfigWriter) *Module {
	m := &Module{
		log:            log,
		store:          NewStore(dir),
		cfgMgr:         cfgMgr,
		issuing:        make(map[string]bool),
		lastRenewCheck: make(map[string]string),
	}
	ctx, cancel := context.WithCancel(context.Background())
	m.baseCtx = ctx
	m.renewCancel = cancel
	m.inflight.Add(1)
	go func() {
		defer m.inflight.Done()
		m.renewLoop(ctx)
	}()
	return m
}

// renewLoop 周期性检查并续期临近到期的证书。启动后先延迟数分钟（待证书加载与 ACME 装配就绪），
// 之后每分钟检查一次；每张证书在其「续期时间」(RenewTime，默认 03:00) 之后的首次心跳触发一次
// 续期窗口检查，当天此后不再重复（见 lastRenewCheck）。
// 因此「每天 09:00 检查」的含义是「每天 09:00 起、当天最早的一次机会执行」——
// 机器在 09:00 处于关机/休眠状态时，开机后的首次心跳（即这里的 5 分钟延迟）会把它补上。
// ctx 取消时退出。
func (m *Module) renewLoop(ctx context.Context) {
	first := time.NewTimer(5 * time.Minute)
	defer first.Stop()
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-first.C:
			m.runRenewDue(ctx)
		case <-ticker.C:
			m.runRenewDue(ctx)
		}
	}
}

// runRenewDue 执行一次续期检查；未装配 ACME 签发器时直接跳过（无自动续期能力）。
// 仅对「续期时间」已到达（或当天默认时刻已到）的证书评估续期窗口，避免每秒/每分钟无谓请求。
func (m *Module) runRenewDue(parent context.Context) {
	m.mu.Lock()
	issuer := m.issuer
	m.mu.Unlock()
	if issuer == nil {
		return
	}
	ctx, cancel := context.WithTimeout(parent, 30*time.Minute)
	defer cancel()

	now := time.Now()
	var due []config.Certificate
	cfg := m.cfgMgr.Snapshot()
	for _, c := range cfg.Certs {
		if !c.AutoRenew {
			continue
		}
		// 仅 ACME 证书可自动续期：file/path 方式的证书由用户自行更新源文件，
		// 若也进入续期流程只会每天固定失败一次并刷出无意义的告警。
		if c.Method != "acme" {
			continue
		}
		if !m.renewCheckDue(c.ID, c.RenewTime, now) {
			continue
		}
		due = append(due, c)
	}
	if len(due) == 0 {
		return
	}

	renewed := 0
	cut := false
	outcomes := make([]renewOutcome, 0, len(due))
	for _, c := range due {
		// 关机（Close 取消 baseCtx）或整轮超时后立即收手：继续往下走只会让每张待续期证书
		// 各自失败一次，在关机日志里刷出一串无意义的「证书续期失败」。
		// 用 break 而不是 return，是为了把已经查过的那几张照常汇报出去——
		// 它们已被 renewCheckDue 记为「今天查过」，今天不会再查第二次，
		// 这里不汇报就等于这几张证书今天在日志里凭空消失了。
		if ctx.Err() != nil {
			cut = true
			break
		}
		label := certLabel(c)
		before := renewBeforeDays(c.RenewBeforeDays)
		_, notAfter, loaded := m.store.Info(c.ID)
		if !loaded {
			// 配置里有这张证书，但内存里没有对应的证书链（首次签发尚未完成、
			// 或文件在外部被删掉了）。原先这种情况与「不必续期」走同一条分支，
			// 于是日志里看不出区别——而这两件事要做的处置完全不同。
			outcomes = append(outcomes, renewOutcome{label: label, state: renewStateUnloaded})
			continue
		}
		if !renewalDueAt(notAfter, c.RenewBeforeDays, now) {
			outcomes = append(outcomes, renewOutcome{
				label: label, state: renewStateOK, known: true,
				remaining: remainingDays(notAfter, now), before: before,
			})
			continue
		}
		if _, err := m.issueExclusive(ctx, c.ID, true); err != nil {
			m.log.Warn("证书续期失败", "cert", c.Name, "err", err.Error())
			outcomes = append(outcomes, renewOutcome{label: label, state: renewStateFailed})
			continue
		}
		renewed++
		// 续期后重新读一次到期时间：续期的全部意义就在于这个数变了，
		// 拿续期前的旧值去汇报「当前剩余有效期」等于没续。
		out := renewOutcome{label: label, state: renewStateRenewed, before: before}
		if _, na, ok := m.store.Info(c.ID); ok {
			out.known = true
			out.remaining = remainingDays(na, time.Now())
		}
		outcomes = append(outcomes, out)
	}
	if len(outcomes) == 0 {
		// 首张就撞上关机/超时，什么都没查成，没有可汇报的内容。
		return
	}
	m.log.Info(renewSummary(outcomes, cut), "checked", len(outcomes), "renewed", renewed)
}

// 一张证书本轮检查的结果。
const (
	renewStateOK       = "ok"       // 不必续期，证书正常
	renewStateRenewed  = "renewed"  // 本轮续过了
	renewStateFailed   = "failed"   // 该续但没续成（详情另有一条 Warn）
	renewStateUnloaded = "unloaded" // 配置里有，内存里没有对应证书
)

// maxSummaryCerts 那条「检查完成」日志里最多逐张点名多少张证书。
//
// 单条日志的消息文本上限 2 KB（logx.maxLogValueBytes），一张证书一句约 80 字节，
// 撑满要二十几张。8 张就收口不是为了那个上限，是为了日志面板上的可读性：
// 一行长到要横向拖动，等于谁都不会去看。剩下的用一句「另有 N 张」交代。
const maxSummaryCerts = 8

// renewOutcome 一张证书本轮检查的结果，用来拼那条「证书自动续期检查完成」的日志。
type renewOutcome struct {
	label string
	state string

	// known 为真时 remaining/before 才有意义：
	// remaining 是刚读到的剩余有效期天数，before 是配置里的「提前几天续期」。
	// 续期刚成功却读不到新的到期时间时 known 为假——那时报「剩余 0 天」是错的。
	known     bool
	remaining int
	before    int
}

// clause 这张证书在日志里占的那一句。
func (o renewOutcome) clause() string {
	switch o.state {
	case renewStateRenewed:
		if !o.known {
			return o.label + " 已完成续期"
		}
		return fmt.Sprintf("%s 已完成续期，当前剩余有效期 %d 天，%s", o.label, o.remaining, o.nextHint())
	case renewStateFailed:
		return o.label + " 续期失败"
	case renewStateUnloaded:
		return o.label + " 尚未加载到证书，暂无法判断有效期"
	default:
		return fmt.Sprintf("%s 证书正常，当前剩余有效期 %d 天，%s", o.label, o.remaining, o.nextHint())
	}
}

// nextHint 「什么时候会自动续期」那半句。
//
// 差值不为正时不硬凑成「将在 0 天后」：那是"下一次检查就会续"的意思，直说更清楚。
// 走到这一支的只有刚续完却算出剩余有效期偏短的情形（签发方给的有效期短于
// 用户设的提前续期天数），此时确实是下一轮就会再续一次。
func (o renewOutcome) nextHint() string {
	if n := o.remaining - o.before; n > 0 {
		return fmt.Sprintf("将在 %d 天后自动续期", n)
	}
	return "下次检查时将自动续期"
}

// renewSummary 把本轮各张证书的结果拼成一条日志。
//
// 第一张用「，」接在「检查完成」后面，此后各张之间用「；」——因为每一句里面本身就有逗号，
// 全用逗号连的话，两张证书的信息会糊成一句读不断的话。
//
// cut 为真表示本轮是被关机或整轮超时打断的，后面还有没查到的证书。那时开头不能写
// 「检查完成」：这条日志汇报的只是已经查过的那几张，写「完成」等于说其余的也查过了。
func renewSummary(outcomes []renewOutcome, cut bool) string {
	var b strings.Builder
	if cut {
		b.WriteString("证书自动续期检查提前结束")
	} else {
		b.WriteString("证书自动续期检查完成")
	}
	shown := min(len(outcomes), maxSummaryCerts)
	for i := 0; i < shown; i++ {
		if i == 0 {
			b.WriteString("，")
		} else {
			b.WriteString("；")
		}
		b.WriteString(outcomes[i].clause())
	}
	if rest := len(outcomes) - shown; rest > 0 {
		b.WriteString(fmt.Sprintf("；另有 %d 张证书检查完成", rest))
	}
	b.WriteString("。")
	return b.String()
}

// certLabel 日志里指代一张证书用的名字：优先用户起的名字，其次首个域名。
// 两个都空只可能来自外部直接改写配置文件，这时给一个固定说法，
// 而不是把内部 ID 印到日志里——那对读日志的人没有意义。
func certLabel(c config.Certificate) string {
	if s := strings.TrimSpace(c.Name); s != "" {
		return s
	}
	for _, d := range c.Domains {
		if s := strings.TrimSpace(d); s != "" {
			return s
		}
	}
	return "未命名证书"
}

// defaultRenewTime 未设置「续期时间」时使用的每日检查时刻（本地时区）。
const defaultRenewTime = "03:00"

// renewCheckDue 判断某张证书今天的续期检查是否应当在此刻执行：
// 当前时间已到（或已过）该证书的续期时刻，且今天尚未检查过。
// 返回 true 时立即把今天记为已检查，因此同一天只会触发一次——
// 包括续期失败的情况：ACME 有按域名计的签发配额，失败后当天反复重试只会更快耗尽配额，
// 留给下一天（或用户手动点击续期）更合适。
func (m *Module) renewCheckDue(id, renewTime string, now time.Time) bool {
	today := now.Format("2006-01-02")
	rt := strings.TrimSpace(renewTime)
	if rt == "" {
		rt = defaultRenewTime
	}
	target, err := time.ParseInLocation("2006-01-02 15:04", today+" "+rt, now.Location())
	if err != nil {
		// 续期时刻非法（历史脏数据或外部直接改写配置）：退回默认时刻，
		// 而不是让这张证书从此永远不检查续期。
		target, err = time.ParseInLocation("2006-01-02 15:04", today+" "+defaultRenewTime, now.Location())
		if err != nil {
			return false
		}
	}
	if now.Before(target) {
		return false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.lastRenewCheck[id] == today {
		return false
	}
	m.lastRenewCheck[id] = today
	return true
}

// SetIssuer 注入 ACME 签发器（可选）。
func (m *Module) SetIssuer(i Issuer) {
	m.mu.Lock()
	m.issuer = i
	m.mu.Unlock()
}

// Name 实现 module.Module。
func (m *Module) Name() string { return "cert" }

// Resolver 返回可注入到 Web 服务/面板 HTTPS 的证书解析函数。
// 硬约束：被禁用的证书一律不参与解析——无论面板 HTTPS（按 ID）还是 Web 服务（按 SNI 域名），
// 一旦证书被禁用，所有模块都无法再引用/使用它。
func (m *Module) Resolver() func(string) (*tls.Certificate, bool) {
	return func(serverName string) (*tls.Certificate, bool) {
		cert, id, ok := m.store.ResolveWithID(serverName)
		if !ok {
			return nil, false
		}
		if !m.enabledInConfig(id) {
			return nil, false
		}
		return cert, true
	}
}

func (m *Module) Info(id string) ([]string, time.Time, bool) {
	return m.store.Info(id)
}

// ResolveID 返回指定 ID 的证书；若证书被禁用则返回未命中，确保禁用证书不可被任何模块引用。
func (m *Module) ResolveID(id string) (*tls.Certificate, bool) {
	if !m.enabledInConfig(id) {
		return nil, false
	}
	return m.store.ResolveID(id)
}

// enabledInConfig 返回该 ID 的证书在当前配置中是否处于启用状态，
// 用于「禁用证书不可被引用」的硬约束（解析 / ResolveID 均经此判定）。
//
// 用 Snapshot 而非 Get：本函数在**每次 TLS 握手**上都会被调用（面板 HTTPS 与每个 Web 服务
// 的 SNI 解析都要判定启用位），而 Get 是整份配置的 JSON 深拷贝——为读一个 bool 把所有规则、
// 凭据、证书重新分配一遍，在证书较多或握手密集时成为可观的 GC 压力。
// 快照只读，这里也只读，因而语义完全等价：仍是「取当前配置判定」，不缓存、不存在陈旧窗口。
func (m *Module) enabledInConfig(id string) bool {
	cfg := m.cfgMgr.Snapshot()
	for i := range cfg.Certs {
		if cfg.Certs[i].ID == id {
			return cfg.Certs[i].Enabled
		}
	}
	return false
}

func (m *Module) ValidateID(id string, now time.Time) error {
	m.store.mu.RLock()
	defer m.store.mu.RUnlock()
	sc, ok := m.store.byID[id]
	if !ok {
		return fmt.Errorf("所选证书无法加载")
	}
	if now.Before(sc.leaf.NotBefore) {
		return fmt.Errorf("所选证书尚未生效")
	}
	if !now.Before(sc.notAfter) {
		return fmt.Errorf("所选证书已过期")
	}
	return nil
}

func (m *Module) ValidateHostname(id, hostname string) error {
	m.store.mu.RLock()
	defer m.store.mu.RUnlock()
	sc, ok := m.store.byID[id]
	if !ok {
		return fmt.Errorf("所选证书无法加载")
	}
	if err := sc.leaf.VerifyHostname(hostname); err != nil {
		return fmt.Errorf("访问域名 %s 未被所选证书覆盖", hostname)
	}
	return nil
}

// Reload 加载已知证书并刷新状态统计。
func (m *Module) Reload(cfg *config.Config) error {
	// 清理上一次运行残留的「进行中」状态（如进程重启/崩溃导致证书永远卡在 running）。
	m.recoverInterrupted()

	// 索引整份重建，但旧索引在换上新的之前一直对外服务：中间这段要读磁盘
	// （路径证书逐个 os.ReadFile），期间照旧能取到证书握手，见 beginIndexSwap。
	m.store.beginIndexSwap()
	fileIDs := make([]string, 0, len(cfg.Certs))
	for _, c := range cfg.Certs {
		if c.Method == "path" {
			// 路径方式：直接从用户指定的磁盘路径加载（保持与源文件同步）。
			if err := m.store.LoadFromFiles(c.ID, c.CertPath, c.KeyPath); err != nil {
				m.log.Warn("加载路径证书失败", "cert", c.Name, "err", err.Error())
			}
			continue
		}
		fileIDs = append(fileIDs, c.ID)
	}
	m.store.LoadAll(fileIDs)
	m.store.commitIndex()

	total, expired := 0, 0
	now := time.Now()
	for _, c := range cfg.Certs {
		total++
		if _, notAfter, ok := m.store.Info(c.ID); ok && now.After(notAfter) {
			expired++
		}
	}
	valid := make(map[string]bool, len(cfg.Certs))
	for _, c := range cfg.Certs {
		valid[c.ID] = true
	}
	m.mu.Lock()
	m.total = total
	m.expired = expired
	// 本进程第一次加载配置时补一次启动检查（见 startupCheck）。
	firstLoad := !m.startupChecked
	m.startupChecked = true
	// 清理已删除证书残留的续期检查记录（见 lastRenewCheck）。
	for id := range m.lastRenewCheck {
		if !valid[id] {
			delete(m.lastRenewCheck, id)
		}
	}
	m.mu.Unlock()
	if firstLoad {
		m.startupCheck(cfg, now)
	}
	return nil
}

// startupCheck 把全部证书的剩余有效期写进日志，每次进程启动时执行一次。
//
// 为什么要专门有这一条：到期时间平时只在证书页上看得到，而那一页得点进去才看。
// 证书过期的后果是引用它的站点整体打不开，偏偏这件事是慢慢逼近、过程中毫无动静的——
// 等浏览器弹出警告才发现就已经晚了。每次启动记一条，首页的日志面板必然显示一次，
// 事后翻日志文件也查得到「那天启动时还剩几天」。
//
// 与续期检查（runRenewDue）的三点不同：
//   - 覆盖全部证书，而不只是「自动续期 + 自动签发」那一部分：过期与添加方式无关，
//     导入的、指向磁盘路径的那些同样会过期，而它们恰恰没有自动续期兜着。
//   - 只读内存里已经加载好的证书链，不联网、不签发，因此可以直接在启动路径上跑完。
//   - 不受「续期时刻」与「今天已经检查过」这两道闸门约束——它就是要每次启动都记一条。
//
// 一张证书都没有时不记：那时没有可报的内容，而一条「共 0 张」会在此后每次启动都占掉
// 首页日志里本就不多的一行。
func (m *Module) startupCheck(cfg *config.Config, now time.Time) {
	outcomes := make([]startupOutcome, 0, len(cfg.Certs))
	expired := 0
	for _, c := range cfg.Certs {
		label := certLabel(c)
		if !c.Enabled {
			// 标出停用：停用的证书不被任何模块引用（见 enabledInConfig），它临近到期
			// 并不需要处置。不标的话读日志的人会为一张根本没在用的证书白紧张一场。
			label += "（已停用）"
		}
		_, notAfter, loaded := m.store.Info(c.ID)
		switch {
		case !loaded:
			outcomes = append(outcomes, startupOutcome{label: label, state: startupStateUnloaded})
		case !now.Before(notAfter):
			expired++
			outcomes = append(outcomes, startupOutcome{label: label, state: startupStateExpired})
		default:
			outcomes = append(outcomes, startupOutcome{
				label: label, state: startupStateOK, remaining: remainingDays(notAfter, now),
			})
		}
	}
	if len(outcomes) == 0 {
		return
	}
	// 按紧迫程度排序：逐张点名只到 maxSummaryCerts 为止，排过序之后被折叠掉的
	// 一定是最不着急的那几张，而不是配置文件里恰好排在后面的几张。
	sortStartupOutcomes(outcomes)
	m.log.Info(startupSummary(outcomes), "certs", len(outcomes), "expired", expired)
}

// 启动检查里一张证书的三种结果。
const (
	startupStateOK       = "ok"       // 有效，剩余 remaining 天
	startupStateExpired  = "expired"  // 已过期
	startupStateUnloaded = "unloaded" // 配置里有，内存里却没有对应的证书链
)

// startupOutcome 一张证书在启动检查里的结果。
type startupOutcome struct {
	label     string
	state     string
	remaining int // 仅 startupStateOK 时有意义
}

// rank 排序档位：先已过期的，再按剩余天数从少到多，最后是加载不出来的。
// 加载不出来的排在最后而不是最前：那更多是「这张还没签发过」，不是「这张出事了」。
func (o startupOutcome) rank() int {
	switch o.state {
	case startupStateExpired:
		return 0
	case startupStateOK:
		return 1
	default:
		return 2
	}
}

// sortStartupOutcomes 就地按紧迫程度排序（档位见 rank，同档内剩余天数少的在前）。
func sortStartupOutcomes(outcomes []startupOutcome) {
	slices.SortStableFunc(outcomes, func(a, b startupOutcome) int {
		if a.rank() != b.rank() {
			return a.rank() - b.rank()
		}
		return a.remaining - b.remaining
	})
}

// clause 这张证书在日志里占的那一句。
func (o startupOutcome) clause() string {
	switch o.state {
	case startupStateExpired:
		return o.label + " 已过期"
	case startupStateUnloaded:
		return o.label + " 尚未加载到证书，暂无法判断有效期"
	default:
		return fmt.Sprintf("%s 剩余有效期 %d 天", o.label, o.remaining)
	}
}

// startupSummary 把各张证书的结果拼成那条启动检查日志。
//
// 逐张点名到 maxSummaryCerts 为止，余下的用一句交代。因为 outcomes 已按紧迫程度排过序，
// 这一句还能顺带给出「余下那些至少还有多少天」这个下界，见 foldedLowerBound。
func startupSummary(outcomes []startupOutcome) string {
	var b strings.Builder
	fmt.Fprintf(&b, "证书启动检查完成，共 %d 张证书", len(outcomes))
	shown := min(len(outcomes), maxSummaryCerts)
	for i := 0; i < shown; i++ {
		b.WriteString("；")
		b.WriteString(outcomes[i].clause())
	}
	if rest := len(outcomes) - shown; rest > 0 {
		if days, ok := foldedLowerBound(outcomes, shown); ok {
			fmt.Fprintf(&b, "；另有 %d 张证书剩余有效期不少于 %d 天", rest, days)
		} else {
			fmt.Fprintf(&b, "；另有 %d 张证书已检查", rest)
		}
	}
	b.WriteString("。")
	return b.String()
}

// foldedLowerBound 给出被折叠掉那些证书（outcomes[shown:]）的剩余天数下界。
//
// 只有当这些证书全都是「有效」那一档时才给得出：过期的没有剩余天数可言，加载不出来的
// 更是压根不知道。排序把三档排成了连续的三段（已过期、有效、未加载，见 rank），所以
// 只要首尾两张都是「有效」，中间就不会夹进另外两档——这是这里只看两头的依据。
//
// 取的是首张而非末张：同档内按剩余天数升序，被折叠的第一张就是它们当中最少的那个，
// 这个下界既成立又最紧。
func foldedLowerBound(outcomes []startupOutcome, shown int) (int, bool) {
	if shown >= len(outcomes) {
		return 0, false
	}
	if outcomes[shown].state != startupStateOK || outcomes[len(outcomes)-1].state != startupStateOK {
		return 0, false
	}
	return outcomes[shown].remaining, true
}

// recoverInterrupted 在模块重载（含进程启动）时，清理上一次运行残留的「进行中」状态。
// 若配置中某证书的签发/续期状态仍为 running/pending，但本进程并未在对其执行操作
// （m.issuing 中无该 ID），说明上一次进程在操作中被重启或崩溃，状态残留在进行中。
// 此时将其重置为 failed，避免面板永久显示「正在签发 / 正在续期」而无法重试。
//
// 数据竞争防护：m.issuing 由 m.mu 保护，这里先加锁拷贝一份「在途」集合快照，
// 后续统一用快照判断，避免在 Reload 期间与并发的 beginIssue/endIssue 产生竞态。
// 另外，证书的自身状态更新走 cfgMgr.Update，并不会触发 OnConfigChanged（Reload 的入口），
// 因此正在进行的签发不会被本函数误清。
func (m *Module) recoverInterrupted() {
	m.mu.Lock()
	inFlight := make(map[string]bool, len(m.issuing))
	for id := range m.issuing {
		inFlight[id] = true
	}
	m.mu.Unlock()

	snapshot := m.cfgMgr.Snapshot()
	needFix := false
	for i := range snapshot.Certs {
		c := &snapshot.Certs[i]
		if inFlight[c.ID] {
			continue
		}
		if c.IssueStatus.State == "running" || c.IssueStatus.State == "pending" ||
			c.RenewStatus.State == "running" || c.RenewStatus.State == "pending" {
			needFix = true
			break
		}
	}
	if !needFix {
		return
	}
	_ = m.cfgMgr.UpdateState(func(c *config.Config) {
		now := time.Now().Unix()
		for i := range c.Certs {
			cc := &c.Certs[i]
			if inFlight[cc.ID] {
				continue
			}
			if cc.IssueStatus.State == "running" || cc.IssueStatus.State == "pending" {
				cc.IssueStatus = config.CertificateOperationStatus{
					State:     "failed",
					Message:   "interrupted",
					UpdatedAt: now,
				}
				cc.Status = "failed"
			}
			if cc.RenewStatus.State == "running" || cc.RenewStatus.State == "pending" {
				cc.RenewStatus = config.CertificateOperationStatus{
					State:     "failed",
					Message:   "interrupted",
					UpdatedAt: now,
				}
			}
		}
	})
}

// closeGrace 是 Close 等待在飞签发收尾的上限（var 而非 const，仅为让测试把它调小）。
//
// 取 30 秒是有依据的：取消 baseCtx 后，ACME 的网络调用会立刻返回，剩下的时间几乎全部
// 花在 acme.go 里注册的 TXT 清理回调上——它刻意用 context.Background() + 30 秒超时，
// 好让「进程要退出了」不至于把 _acme-challenge 记录永久留在用户的域名上。
var closeGrace = 30 * time.Second

// Close 停止内置续期循环，并等待在飞的签发/续期收尾（上限 closeGrace）。
//
// 为什么必须等：签发是个跨越数十秒到数分钟的多步过程（建订单 → 写 TXT → 等传播 →
// CA 验证 → 落盘证书 → 回写配置）。进程在中途被拔掉，代价不是"少签一张证书"那么轻：
// 已写入的 _acme-challenge TXT 记录没人清理（下次签发时残留记录还可能干扰验证）、
// 证书/私钥可能只写了一半、Let's Encrypt 那边的失败验证还要占用限流配额。
// 先取消 context 让各步骤快速返回，再给清理逻辑一个有界的收尾窗口，是这里唯一
// 既不无限期挂住关机、又不撕断签发流程的做法。
//
// 可重复调用；第二次及以后为空操作（自更新路径会先显式 CloseAll 再 exec，
// exec 失败时 defer 里还会再调一次）。
func (m *Module) Close() error {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return nil
	}
	m.closed = true
	cancel := m.renewCancel
	pending := len(m.issuing)
	m.mu.Unlock()

	if cancel != nil {
		cancel()
	}
	if pending > 0 {
		m.log.Info("等待在飞的证书签发/续期收尾", "count", pending, "timeout", closeGrace.String())
	}

	done := make(chan struct{})
	go func() {
		m.inflight.Wait()
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-time.After(closeGrace):
		// 不返回 error：这不是"关闭失败"，而是"某个签发没能在窗口内收尾"。
		// 上层 CloseAll 会把 error 记为 Error 级并继续关别的模块，语义上过重；
		// 这里用 Warn 说明遗留了什么，然后放手让进程退出。
		m.log.Warn("证书签发/续期未在关闭窗口内结束，放弃等待", "timeout", closeGrace.String())
		return nil
	}
}

// Status 实现 module.StatusReporter。
func (m *Module) Status() module.Status {
	m.mu.Lock()
	defer m.mu.Unlock()
	return module.Status{
		Name:    "cert",
		Total:   m.total,
		Active:  m.total - m.expired,
		Healthy: m.expired == 0,
	}
}

// Import 导入用户提供的证书与私钥 PEM。
func (m *Module) Import(id string, certPEM, keyPEM []byte) error {
	return m.store.Save(id, certPEM, keyPEM)
}

func (m *Module) Paths(c config.Certificate) (string, string, error) {
	if c.Method == "path" {
		certPath, err := filepath.Abs(c.CertPath)
		if err != nil {
			return "", "", err
		}
		keyPath, err := filepath.Abs(c.KeyPath)
		if err != nil {
			return "", "", err
		}
		return certPath, keyPath, nil
	}
	return m.store.Paths(c.ID)
}

func (m *Module) Export(c config.Certificate, includePrivateKey bool) ([]byte, []byte, error) {
	if c.Method != "path" {
		return m.store.Export(c.ID, includePrivateKey)
	}
	certPath, keyPath, err := m.Paths(c)
	if err != nil {
		return nil, nil, err
	}
	// 路径证书的两个路径由用户在界面上填，而这里读到的内容会被导出接口原样回给调用方。
	// 原来是直接 os.ReadFile 两个路径，于是「新建一张 path 证书指向 /etc/shadow →
	// 调一次导出」就是一次任意文件读，读取权限等于面板进程权限（常是 root）。
	//
	// 改成只导出真的解析得出来的证书对：证书要能解析成 X.509，私钥要能与它配上。
	// 不含私钥导出时也一样要求配得上——否则「导出证书」这一支仍然能读走磁盘上任意一份
	// 能解析成证书的文件。能用的路径证书本来就满足这个条件（否则 Reload 加载不了它、
	// 面板里也用不上），备份那侧在 Export 之后一直做着同一道 tls.X509KeyPair 校验，
	// 所以这道校验不改变任何一份可用配置的行为。
	certPEM, keyPEM, err := m.store.ReadVerifiedPair(certPath, keyPath)
	if err != nil {
		return nil, nil, err
	}
	if !includePrivateKey {
		return certPEM, nil, nil
	}
	return certPEM, keyPEM, nil
}

func (m *Module) IssueAsync(certID string, timeout time.Duration) error {
	cfg := m.cfgMgr.Snapshot()
	var target *config.Certificate
	for i := range cfg.Certs {
		if cfg.Certs[i].ID == certID {
			target = &cfg.Certs[i]
			break
		}
	}
	if target == nil {
		return fmt.Errorf("找不到证书: %s", certID)
	}
	_, notAfter, certLoaded := m.store.Info(certID)
	now := time.Now()
	// renewal 仅在「已存在有效且未过期证书」时为真：用于「未到续期时间则跳过」的预检、
	// 操作状态文案（renew-pending）与 issue 的 renewal 参数；其余情况（首次签发 / 已过期 / 未加载）
	// 一律按首次签发处理，避免把"已加载"误当作"续期"导致预检与状态错乱。
	renewal := certLoaded && !notAfter.IsZero() && now.Before(notAfter)
	if renewal && !renewalDueAt(notAfter, target.RenewBeforeDays, now) {
		return fmt.Errorf("当前剩余 %d 天，大于设定的提前 %d 天续期；若要提前续期，请修改提前续期天数", remainingDays(notAfter, now), renewBeforeDays(target.RenewBeforeDays))
	}
	if timeout <= 0 {
		timeout = 30 * time.Minute
	}
	if err := m.beginIssue(certID); err != nil {
		return err
	}
	message := "issue-pending"
	if renewal {
		message = "renew-pending"
	}
	if err := m.updateOperationStatus(certID, renewal, "pending", message, 0); err != nil {
		m.endIssue(certID)
		return fmt.Errorf("保存操作状态失败: %w", err)
	}
	go func() {
		defer m.endIssue(certID)
		// 兜底：签发过程若发生意料之外的 panic，确保释放 in-flight 锁并把状态置为失败，
		// 避免证书永久卡在「正在签发」。
		defer func() {
			if r := recover(); r != nil {
				m.log.Error("证书签发或续期异常中断", "cert", certID, "panic", fmt.Sprintf("%v", r))
				_ = m.updateOperationStatus(certID, renewal, "failed", "interrupted", 0)
			}
		}()
		// 父 context 用模块级的 baseCtx 而非 context.Background()：Close 取消它之后，
		// 这里的 ACME 调用会立刻返回并走到 TXT 清理，而不是抱着 30 分钟的超时空转。
		ctx, cancel := context.WithTimeout(m.baseCtx, timeout)
		defer cancel()
		if _, err := m.issue(ctx, certID, renewal); err != nil {
			m.log.Warn("证书签发或续期失败", "cert", certID, "err", err.Error())
		}
	}()
	return nil
}

// Issue 使用已装配的 ACME 签发器签发指定证书。
func (m *Module) Issue(ctx context.Context, certID string) (string, error) {
	return m.issueExclusive(ctx, certID, false)
}

func (m *Module) issueExclusive(ctx context.Context, certID string, renewal bool) (string, error) {
	if err := m.beginIssue(certID); err != nil {
		return "", err
	}
	defer m.endIssue(certID)
	return m.issue(ctx, certID, renewal)
}

func (m *Module) beginIssue(certID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return fmt.Errorf("模块正在关闭，已拒绝新的签发请求")
	}
	if m.issuer == nil {
		return fmt.Errorf("未装配 ACME 签发器，请导入证书或在构建时启用 ACME 支持")
	}
	if m.issuing[certID] {
		return fmt.Errorf("证书正在签发或续期中")
	}
	m.issuing[certID] = true
	// 在持有 mu 时 Add，与 Close 里「先在 mu 内置 closed，再 Wait」形成互斥，
	// 保证不会在 Wait 已经开始之后又冒出一个计数。
	m.inflight.Add(1)
	return nil
}

func (m *Module) endIssue(certID string) {
	m.mu.Lock()
	delete(m.issuing, certID)
	m.mu.Unlock()
	m.inflight.Done()
}

func (m *Module) issue(ctx context.Context, certID string, renewal bool) (string, error) {
	m.mu.Lock()
	issuer := m.issuer
	m.mu.Unlock()
	if issuer == nil {
		return "", fmt.Errorf("未装配 ACME 签发器，请导入证书或在构建时启用 ACME 支持")
	}

	cfg := m.cfgMgr.Get()
	var target *config.Certificate
	for i := range cfg.Certs {
		if cfg.Certs[i].ID == certID {
			target = &cfg.Certs[i]
			break
		}
	}
	if target == nil {
		return "", fmt.Errorf("找不到证书: %s", certID)
	}

	var account config.ACMEAccount
	for _, a := range cfg.ACMEAccounts {
		if a.ID == target.ACMEAccountRef {
			account = a
			break
		}
	}
	var secrets map[string]string
	var dnsProvider string
	for _, c := range cfg.Credentials {
		if c.ID == target.CredentialRef {
			secrets = c.Secrets
			dnsProvider = c.Provider
			break
		}
	}

	// 预检：在向 CA 下单之前先确认配置自洽。
	// 放在 Issue 之前而不是只在之后校验，是因为 ACME 签发受 CA 限流约束
	//（Let's Encrypt 同一域名组合每周 5 张）：等签完才发现「凭证不存在」之类的配置错误，
	// 会白白消耗一次配额并可能留下无用的 DNS TXT 记录。签发后的 validateIssueConfig 仍保留，
	// 用于拦截「签发期间配置被改动」的 TOCTOU 情形。
	if err := precheckIssue(*target, account, dnsProvider); err != nil {
		m.updateOperationStatus(certID, renewal, "failed", err.Error(), 0)
		return "", err
	}

	message := "issue-running"
	if renewal {
		message = "renew-running"
	}
	if err := m.updateOperationStatus(certID, renewal, "running", message, 0); err != nil {
		return "", fmt.Errorf("保存操作状态失败: %w", err)
	}
	certPEM, keyPEM, err := issuer.Issue(ctx, *target, &account, dnsProvider, secrets, func(msg string) {
		// 把阶段进度实时写入「正在签发/续期」状态，避免面板一直显示静止的 running。
		_ = m.updateOperationStatus(certID, renewal, "running", msg, 0)
	})
	if err != nil {
		m.updateOperationStatus(certID, renewal, "failed", err.Error(), 0)
		return "", err
	}
	if err := m.validateIssueConfig(certID, *target, &account, dnsProvider, secrets); err != nil {
		m.updateOperationStatus(certID, renewal, "failed", err.Error(), 0)
		return "", err
	}
	if err := m.store.Save(certID, certPEM, keyPEM); err != nil {
		m.updateOperationStatus(certID, renewal, "failed", err.Error(), 0)
		return "", err
	}

	_, notAfter, _ := m.store.Info(certID)
	message = "issue-success"
	if renewal {
		message = "renew-success"
	}
	if err := m.updateOperationStatus(certID, renewal, "success", message, notAfter.Unix()); err != nil {
		return "", fmt.Errorf("保存操作状态失败: %w", err)
	}
	return message, nil
}

// RenewDue 对启用自动续期且临近到期的证书触发续期（供计划任务调用）。
func (m *Module) RenewDue(ctx context.Context) (string, error) {
	cfg := m.cfgMgr.Snapshot()
	now := time.Now()
	renewed := 0
	for _, c := range cfg.Certs {
		// 同 runRenewDue：ctx 已取消就不要再逐张失败一遍。
		if ctx.Err() != nil {
			return fmt.Sprintf("已续期 %d 张证书，剩余未处理", renewed), ctx.Err()
		}
		// 与内置续期循环一致：非 ACME 证书不参与自动续期（见 runRenewDue）。
		if !c.AutoRenew || c.Method != "acme" || !m.renewalDue(c, now) {
			continue
		}
		if _, err := m.issueExclusive(ctx, c.ID, true); err != nil {
			m.log.Warn("证书续期失败", "cert", c.Name, "err", err.Error())
			continue
		}
		renewed++
	}
	return fmt.Sprintf("已续期 %d 张证书", renewed), nil
}

func (m *Module) renewalDue(c config.Certificate, now time.Time) bool {
	_, notAfter, ok := m.store.Info(c.ID)
	return ok && renewalDueAt(notAfter, c.RenewBeforeDays, now)
}

func renewBeforeDays(days int) int {
	if days <= 0 {
		return 30
	}
	return days
}

func renewalDueAt(notAfter time.Time, days int, now time.Time) bool {
	return remainingDays(notAfter, now) <= renewBeforeDays(days)
}

func remainingDays(notAfter, now time.Time) int {
	remaining := notAfter.Sub(now)
	if remaining <= 0 {
		return 0
	}
	day := 24 * time.Hour
	return int((remaining + day - 1) / day)
}

// certStatusFromState 依据操作状态与是否续期，返回稳定的证书状态码（与前端 i18n 映射对应）。
// 早期版本直接写入中文展示串，导致状态无法随界面语言切换；改为状态码后由前端按 locale 翻译。
func certStatusFromState(state string, renewal bool) string {
	switch state {
	case "success":
		return "valid"
	case "running":
		if renewal {
			return "renewing"
		}
		return "issuing"
	case "pending":
		if renewal {
			return "pending-renew"
		}
		return "pending-issue"
	default:
		return "failed"
	}
}

// precheckIssue 在向 CA 下单之前校验 ACME 签发所需配置是否齐备（纯本地判断，不访问网络）。
// 这些错误一旦发生，签发必然失败，因此必须在消耗 CA 配额之前拦截。
func precheckIssue(target config.Certificate, account config.ACMEAccount, dnsProvider string) error {
	if target.Method != "acme" {
		return fmt.Errorf("证书的添加方式不是「自动签发」，无法执行 ACME 签发")
	}
	if len(target.Domains) == 0 {
		return fmt.Errorf("未配置域名")
	}
	if _, err := normalizeDomains(target.Domains); err != nil {
		return fmt.Errorf("域名配置无效: %w", err)
	}
	if strings.TrimSpace(target.ACMEAccountRef) == "" || account.ID == "" {
		return fmt.Errorf("未选择有效的 ACME 账户")
	}
	if caDirectoryURL(account.CA) == "" {
		return fmt.Errorf("ACME 目录地址必须使用 https（当前账户 CA 为 %q）", account.CA)
	}
	// 仅支持 DNS-01：凭证缺失时 DNS 记录无从写入，必然在验证阶段失败。
	if strings.TrimSpace(target.CredentialRef) == "" || dnsProvider == "" {
		return fmt.Errorf("DNS-01 验证需要选择有效的 DNS 服务商凭证")
	}
	return nil
}

func (m *Module) validateIssueConfig(certID string, issued config.Certificate, issuedAccount *config.ACMEAccount, issuedProvider string, issuedSecrets map[string]string) error {
	cfg := m.cfgMgr.Snapshot()
	var current *config.Certificate
	for i := range cfg.Certs {
		if cfg.Certs[i].ID == certID {
			current = &cfg.Certs[i]
			break
		}
	}
	if current == nil {
		return fmt.Errorf("证书配置已不存在: %s", certID)
	}
	issuedDomains, err := normalizeDomains(issued.Domains)
	if err != nil {
		return fmt.Errorf("签发期间证书配置校验失败: %w", err)
	}
	currentDomains, err := normalizeDomains(current.Domains)
	if err != nil {
		return fmt.Errorf("签发期间证书配置校验失败: %w", err)
	}
	if issued.Method != current.Method || !sameStrings(issuedDomains, currentDomains) || issued.ACMEChallenge != current.ACMEChallenge || issued.ACMEAccountRef != current.ACMEAccountRef || issued.CredentialRef != current.CredentialRef {
		return fmt.Errorf("签发期间证书的关键 ACME 配置已变更")
	}
	var currentAccount config.ACMEAccount
	accountFound := false
	for _, item := range cfg.ACMEAccounts {
		if item.ID == current.ACMEAccountRef {
			currentAccount = item
			accountFound = true
			break
		}
	}
	if !accountFound || issuedAccount.ID != currentAccount.ID || issuedAccount.CA != currentAccount.CA || issuedAccount.Email != currentAccount.Email || issuedAccount.EABKid != currentAccount.EABKid || issuedAccount.EABHMAC != currentAccount.EABHMAC || issuedAccount.PrivateKeyPEM != currentAccount.PrivateKeyPEM {
		return fmt.Errorf("签发期间 ACME 账户配置已变更")
	}
	for _, item := range cfg.Credentials {
		if item.ID == current.CredentialRef {
			if item.Provider != issuedProvider || !sameStringMap(item.Secrets, issuedSecrets) {
				return fmt.Errorf("签发期间 DNS 凭证配置已变更")
			}
			return nil
		}
	}
	return fmt.Errorf("签发期间 DNS 凭证配置已不存在")
}

func sameStringMap(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for key, value := range a {
		if b[key] != value {
			return false
		}
	}
	return true
}

func (m *Module) updateOperationStatus(certID string, renewal bool, state, message string, notAfter int64) error {
	found := false
	err := m.cfgMgr.UpdateState(func(c *config.Config) {
		for i := range c.Certs {
			if c.Certs[i].ID == certID {
				found = true
				now := time.Now().Unix()
				// message 可能是 ACME 服务器返回的完整 problem detail，长度不可控，需裁剪后再持久化。
				operation := config.CertificateOperationStatus{State: state, Message: config.TruncateStatus(message), UpdatedAt: now}
				if renewal {
					c.Certs[i].RenewStatus = operation
					c.Certs[i].LastRenewAt = now
				} else {
					c.Certs[i].IssueStatus = operation
				}
				c.Certs[i].Status = certStatusFromState(state, renewal)
				if notAfter > 0 {
					c.Certs[i].NotAfter = notAfter
				}
				return
			}
		}
	})
	if err != nil {
		return err
	}
	if !found {
		return fmt.Errorf("找不到证书: %s", certID)
	}
	return nil
}
