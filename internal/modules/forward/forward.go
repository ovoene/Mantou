package forward

import (
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"mantou/internal/config"
	"mantou/internal/logx"
	"mantou/internal/module"
)

// 极简端口转发：一条规则 = 监听端口 → 目标地址:端口（TCP/UDP，支持 IPv6↔IPv4）。
// 不再暴露连接数/超时等细项，改用下列内置默认值。
const (
	// tcpKeepAlivePeriod TCP 连接的 keepalive 探测周期，是空闲/半开连接的回收机制（见 pipe）。
	tcpKeepAlivePeriod = 30 * time.Second
	udpIdleTimeout     = 60 * time.Second // UDP 会话空闲超时
	dialTimeout        = 10 * time.Second // 连接后端超时
	// maxConnsPerRunner 单个监听端口允许的最大并发 TCP 连接数 / UDP 活跃会话数，
	// 防止单条规则被海量连接拖垮内存与文件描述符；达到上限后新连接被直接拒绝。
	maxConnsPerRunner = 1024
	// maxConnsTotal 本模块**所有规则合计**的活跃连接上限（TCP 连接 + UDP 会话同池）。
	//
	// 光有 maxConnsPerRunner 是不够的：它守的是"每个监听端口"，而一条规则可以写
	// 20000-21000 这样的端口范围、展开出 1000 个 runner，那句保护于是被端口数乘掉
	// （1024 × 1000 ≈ 一百万条）。这个数字把乘法变回加法。
	//
	// 取值按文件描述符与缓冲预算定：一条 TCP 连接占 2 个 fd（客户端侧 + 后端侧），
	// 4096 条即 8192 个，现代系统装得下（Go 1.19 起运行时会把 RLIMIT_NOFILE 的
	// 软上限抬到硬上限）；没有 splice 的平台上每条连接每方向一块 32 KiB 缓冲，
	// 全部同时在拷贝的极端情况是 4096 × 64 KiB = 256 MiB，仍然是可预算的数。
	// 参照：面板自己的两个监听各 512 条（见 webservice / webhook 的 maxConns）。
	maxConnsTotal = 4096
	// copyBufSize 回退拷贝路径的缓冲大小（走 splice 的平台不会用到，见 copyBufPool）。
	copyBufSize = 32 * 1024
	// udpDatagramMax 单个 UDP 数据报的理论上限，读缓冲不能小于它，否则超长数据报会被截断。
	udpDatagramMax = 64 * 1024
)

// ConfigWriter 供模块回写规则运行态（LastError）。
// Snapshot 返回只读共享快照（不可修改），用于每次连接失败都要执行的"错误是否变化"比对；
// UpdateState 只更新内存并合并落盘到 state.json，不会重写 config.json（见 config/state.go）。
type ConfigWriter interface {
	UpdateState(mutate func(c *config.Config)) error
	Get() *config.Config
	Snapshot() *config.Config
}

// Module 管理所有端口转发规则的生命周期。
// 每条启用的规则会启动对应的 TCP/UDP 监听器；配置变更时按 ID 差量重建。
type Module struct {
	mu      sync.Mutex
	log     *logx.Logger
	cfgMgr  ConfigWriter
	runners map[string]*runner // key = rule.ID
	// conns 所有规则共用的活跃连接总闸（见 maxConnsTotal）。
	// 挂在 Module 而不是包级变量：包级的那份会被同一个进程里的多个 Module 共用，
	// 测试之间互相污染，而这里恰恰要测"名额有没有还回来"。
	conns connGate
}

// connGate 活跃连接总数闸。
//
// 写法与 runner.activeConns 保持一致（先加、超了再退回去），不换成 CAS 循环：
// 这个"先加再判"版本从不让超过上限的连接继续往下走，只是计数会短暂虚高，
// 而两处相邻的代码用同一个惯用法比省掉那点虚高更要紧。
type connGate struct {
	cur atomic.Int64
}

// enter 占一个名额，占不到返回 false。
func (g *connGate) enter() bool {
	if g.cur.Add(1) > maxConnsTotal {
		g.cur.Add(-1)
		return false
	}
	return true
}

// leave 归还名额。
func (g *connGate) leave() { g.cur.Add(-1) }

// New 创建端口转发模块。
func New(log *logx.Logger, cfgMgr ConfigWriter) *Module {
	return &Module{
		log:     log,
		cfgMgr:  cfgMgr,
		runners: make(map[string]*runner),
	}
}

// Name 实现 module.Module。
func (m *Module) Name() string { return "forward" }

// Reload 依据配置差量启停转发规则。
// 单条规则可声明端口范围（ListenPort..ListenPortEnd）：内部展开为若干单端口 runner，
// 键为 "ruleID#listenPort"，目标端口按相同偏移从 TargetPort 递增，或（SameTargetPort）全部共用 TargetPort。
// 各端口的启动错误按父规则 ID 聚合后回写到规则 LastError。
func (m *Module) Reload(cfg *config.Config) error {
	m.mu.Lock()

	// 展开期望运行项。
	desired := make(map[string]expandedRule)
	for _, r := range cfg.Forwards {
		if !r.Enabled {
			continue
		}
		for _, er := range expandRule(r) {
			desired[er.key] = er
		}
	}

	// 停止已删除 / 已禁用 / 范围收缩掉的运行项。
	// 仅在锁内把 runner 从 map 摘除，真正的 stop()（含 wg.Wait，繁忙连接需等到连接自身结束）
	// 放到解锁后进行，避免持锁长时间等待阻塞 Status/其他 Reload。
	var toStop []*runner
	for key, run := range m.runners {
		if _, ok := desired[key]; !ok {
			toStop = append(toStop, run)
			delete(m.runners, key)
		}
	}

	// 启动或重建规则，按父规则聚合启动错误。
	errsByRule := make(map[string][]string)
	for key, er := range desired {
		existing, ok := m.runners[key]
		if ok && existing.signature == ruleSignature(er.rule) {
			continue // 未变化
		}
		if ok {
			// 重建：同样先摘除，stop 延后到解锁后，避免持锁等待。
			delete(m.runners, key)
			toStop = append(toStop, existing)
		}
		run := newRunner(er.rule, m.log, &m.conns)
		if err := run.start(); err != nil {
			m.log.Error("端口转发启动失败", "rule", er.rule.Name, "listen", er.rule.ListenPort, "err", err.Error())
			errsByRule[er.parentID] = append(errsByRule[er.parentID], fmt.Sprintf("端口 %d：%s", er.rule.ListenPort, err.Error()))
			continue
		}
		m.runners[key] = run
	}

	// 回写每条规则的运行态错误：
	//   启用中 —— 写本轮聚合到的启动错误（无错则清空）；
	//   已禁用 —— 一律清空。否则禁用一条曾报错的规则后它已不再运行，列表却仍挂着
	//   一条永不更新的旧错误（状态列红点 +「上次错误」标签）。setLastError 取值不变即不落盘，
	//   所以对早已为空的禁用项这趟是免费的。
	for i := range cfg.Forwards {
		r := &cfg.Forwards[i]
		if !r.Enabled {
			m.setLastError(r.ID, "")
			continue
		}
		msg := ""
		if errs := errsByRule[r.ID]; len(errs) > 0 {
			msg = strings.Join(errs, "; ")
		}
		m.setLastError(r.ID, msg)
	}

	m.mu.Unlock()
	// 锁外停止旧运行项，避免长阻塞持锁。
	for _, run := range toStop {
		run.stop()
	}
	return nil
}

// expandedRule 是端口范围展开后的单端口运行项。
type expandedRule struct {
	key      string // "ruleID#listenPort"
	parentID string // 所属规则 ID
	rule     config.ForwardRule
}

// maxRangePorts 单条规则允许展开的最大端口数，防止误配置导致海量监听。
// 单一取值放在 config，保存接口的范围校验（validateForward）与这里的展开兜底共用它。
const maxRangePorts = config.MaxForwardRangePorts

// expandRule 把一条规则展开为若干单端口运行项。
// ListenPortEnd<=ListenPort 视为单端口。目标端口按 SameTargetPort 决定映射：
// false（默认）时按 (listen-起点) 偏移从 TargetPort 递增；true 时所有监听端口共用同一个 TargetPort。
// 超出 65535 的监听/目标端口会被跳过。
func expandRule(r config.ForwardRule) []expandedRule {
	start := r.ListenPort
	end := r.ListenPortEnd
	if end <= start {
		end = start
	}
	if end-start+1 > maxRangePorts {
		end = start + maxRangePorts - 1
	}
	out := make([]expandedRule, 0, end-start+1)
	for p := start; p <= end; p++ {
		if p < 1 || p > 65535 {
			continue
		}
		// 多对一：所有监听端口都落到同一个 TargetPort，不加偏移。
		tp := r.TargetPort
		if !r.SameTargetPort {
			tp = r.TargetPort + (p - start)
		}
		if tp < 1 || tp > 65535 {
			continue
		}
		sr := r
		sr.ListenPort = p
		sr.ListenPortEnd = 0
		sr.TargetPort = tp
		out = append(out, expandedRule{
			key:      fmt.Sprintf("%s#%d", r.ID, p),
			parentID: r.ID,
			rule:     sr,
		})
	}
	return out
}

// setLastError 仅在取值变化时回写，避免无谓的磁盘写入。
func (m *Module) setLastError(ruleID, msg string) {
	if m.cfgMgr == nil {
		return
	}
	// 用只读快照比对：每条连接失败都会走到这里（例如后端宕机时的连接风暴），
	// 为读一个字符串深拷贝整份配置纯属浪费。仅在取值确有变化时才走 Update 落盘。
	msg = config.TruncateStatus(msg)
	cur := ""
	for _, r := range m.cfgMgr.Snapshot().Forwards {
		if r.ID == ruleID {
			cur = r.LastError
			break
		}
	}
	if cur == msg {
		return
	}
	_ = m.cfgMgr.UpdateState(func(c *config.Config) {
		for i := range c.Forwards {
			if c.Forwards[i].ID == ruleID {
				c.Forwards[i].LastError = msg
				return
			}
		}
	})
}

// Close 停止所有转发。
func (m *Module) Close() error {
	m.mu.Lock()
	var toStop []*runner
	for id, run := range m.runners {
		toStop = append(toStop, run)
		delete(m.runners, id)
	}
	m.mu.Unlock()
	// 锁外停止，避免持锁等待 wg.Wait。
	for _, run := range toStop {
		run.stop()
	}
	return nil
}

// Status 实现 module.StatusReporter。
func (m *Module) Status() module.Status {
	m.mu.Lock()
	defer m.mu.Unlock()
	active := 0
	healthy := true
	for _, run := range m.runners {
		if run.healthy() {
			active++
		} else {
			healthy = false
		}
	}
	return module.Status{
		Name:    "forward",
		Total:   len(m.runners),
		Active:  active,
		Healthy: healthy,
	}
}

// ruleSignature 生成规则关键字段的指纹，用于判断是否需要重建。
// 包含 Bind（监听绑定地址）：改绑地址（如 0.0.0.0 → 127.0.0.1）需能热重载。
func ruleSignature(r config.ForwardRule) string {
	return fmt.Sprintf("%s|%s|:%d/%s|%s:%d", r.Protocol, strings.TrimSpace(r.Bind), r.ListenPort, r.Family, r.TargetHost, r.TargetPort)
}

// runner 承载单条规则的运行态。
type runner struct {
	rule      config.ForwardRule
	signature string
	log       *logx.Logger
	// conns 模块级的连接总闸，所有 runner 共用一个（见 maxConnsTotal）。
	conns *connGate

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	tcpLn   net.Listener
	udpConn *net.UDPConn

	failed         atomic.Bool
	activeConns    atomic.Int64 // 当前活跃 TCP 连接数，用于并发上限判定
	firstTCPLogged atomic.Bool  // 是否已记录首条 TCP 连接（用于日志降级）
	firstUDPLogged atomic.Bool  // 是否已记录首条 UDP 会话（用于日志降级）
	capWarned      atomic.Bool  // 是否已就并发达上限告警过一次（避免刷屏）
	totalWarned    atomic.Bool  // 是否已就模块级连接总数达上限告警过一次
}

func newRunner(rule config.ForwardRule, log *logx.Logger, conns *connGate) *runner {
	ctx, cancel := context.WithCancel(context.Background())
	return &runner{
		rule:      rule,
		signature: ruleSignature(rule),
		log:       log,
		conns:     conns,
		ctx:       ctx,
		cancel:    cancel,
	}
}

func (r *runner) healthy() bool { return !r.failed.Load() }

// logConnEstablished 记录一条「转发连接建立」：每种协议仅首条以 INFO 记录，其余降级为 DEBUG。
// 参考 Web 服务日志「首次记录、后续抑制」的策略，避免高频短连接把日志刷满。
func (r *runner) logConnEstablished(proto, remote string, first *atomic.Bool) {
	if first.CompareAndSwap(false, true) {
		r.log.Info("转发连接建立", "rule", r.rule.Name, "remote", remote, "target", r.targetAddr(), "proto", proto)
	} else {
		r.log.Debug("转发连接建立", "rule", r.rule.Name, "remote", remote, "target", r.targetAddr(), "proto", proto)
	}
}

// logCapReached 在并发达上限而拒绝新连接时记录：首次以 WARN 提示瓶颈，其后降级为 DEBUG。
func (r *runner) logCapReached(proto, remote string) {
	if r.capWarned.CompareAndSwap(false, true) {
		r.log.Warn("转发并发连接已达上限，暂时拒绝新连接", "rule", r.rule.Name, "remote", remote, "proto", proto, "limit", maxConnsPerRunner)
	} else {
		r.log.Debug("转发并发连接已达上限，拒绝新连接", "rule", r.rule.Name, "remote", remote, "proto", proto, "limit", maxConnsPerRunner)
	}
}

// logTotalCapReached 在模块级连接总数达上限而拒绝新连接时记录。
//
// 与 logCapReached 分成两条而不是共用一条：这两种"满了"的下一步动作完全不同——
// 单端口满了通常是那条规则自己的流量问题，而总数满了意味着全部规则加起来触到了
// 进程预算，要看的是别的规则。日志里不写清楚，排查会从错的地方开始。
func (r *runner) logTotalCapReached(proto, remote string) {
	if r.totalWarned.CompareAndSwap(false, true) {
		r.log.Warn("转发连接总数已达上限，暂时拒绝新连接", "rule", r.rule.Name, "remote", remote, "proto", proto, "limit", maxConnsTotal)
	} else {
		r.log.Debug("转发连接总数已达上限，拒绝新连接", "rule", r.rule.Name, "remote", remote, "proto", proto, "limit", maxConnsTotal)
	}
}

// listenAddr 返回监听地址。bind 留空则监听所有本机地址（0.0.0.0/::，具体地址族由网络类型决定）；
// 填具体 IP（如 127.0.0.1）则仅该网卡可访问——避免把内部转发无差别暴露在 0.0.0.0 上。
func (r *runner) listenAddr() string {
	bind := strings.TrimSpace(r.rule.Bind)
	return net.JoinHostPort(bind, fmt.Sprintf("%d", r.rule.ListenPort))
}

// targetAddr 目标地址；拨号时用基础网络（tcp/udp）自动选择 v4/v6，天然支持 IPv6↔IPv4。
func (r *runner) targetAddr() string {
	return net.JoinHostPort(r.rule.TargetHost, fmt.Sprintf("%d", r.rule.TargetPort))
}

// start 依据协议启动监听。任一子协议启动失败时回滚已启动的监听，避免（如 both 模式下
// TCP 已起、UDP 失败）监听器与 accept 协程泄漏——调用方 Reload 在出错时直接丢弃 runner。
func (r *runner) start() error {
	proto := r.rule.Protocol
	if proto == "tcp" || proto == "both" || proto == "" {
		if err := r.startTCP(); err != nil {
			r.stop() // 回滚（此时尚无已启动项，安全幂等）
			return err
		}
	}
	if proto == "udp" || proto == "both" {
		if err := r.startUDP(); err != nil {
			r.stop() // 回滚：关闭可能已启动的 TCP 监听与其 accept 协程
			return err
		}
	}
	r.log.Info("端口转发已启动", "rule", r.rule.Name, "listen", r.listenAddr(),
		"target", r.targetAddr(), "proto", proto)
	return nil
}

func (r *runner) stop() {
	r.cancel()
	if r.tcpLn != nil {
		_ = r.tcpLn.Close()
	}
	if r.udpConn != nil {
		_ = r.udpConn.Close()
	}
	r.wg.Wait()
}

// ---------- TCP ----------

func (r *runner) startTCP() error {
	ln, err := net.Listen(tcpNetwork(r.rule.Family), r.listenAddr())
	if err != nil {
		r.failed.Store(true)
		return fmt.Errorf("TCP 监听失败: %w", err)
	}
	r.tcpLn = ln
	r.wg.Add(1)
	go r.acceptTCP(ln)
	return nil
}

func (r *runner) acceptTCP(ln net.Listener) {
	defer r.wg.Done()
	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-r.ctx.Done():
				return
			default:
				r.log.Warn("TCP accept 失败", "rule", r.rule.Name, "err", err.Error())
				return
			}
		}
		// 并发上限：超过则立即关闭本次连接并跳过，避免连接无限堆积。
		// 两道闸：本端口的（maxConnsPerRunner）与全部规则合计的（maxConnsTotal）。
		// 先判本端口的——它是本地计数，且"某条规则自己太忙"是更常见的情形。
		if r.activeConns.Add(1) > maxConnsPerRunner {
			r.activeConns.Add(-1)
			_ = conn.Close()
			r.logCapReached("tcp", conn.RemoteAddr().String())
			continue
		}
		if !r.conns.enter() {
			r.activeConns.Add(-1) // 上一道闸已经加过了，这里要一并退回去
			_ = conn.Close()
			r.logTotalCapReached("tcp", conn.RemoteAddr().String())
			continue
		}
		r.wg.Add(1)
		go r.handleTCP(conn)
	}
}

func (r *runner) handleTCP(client net.Conn) {
	defer r.wg.Done()
	defer r.activeConns.Add(-1)
	defer r.conns.leave()
	defer client.Close()

	started := time.Now()
	upstream, err := net.DialTimeout("tcp", r.targetAddr(), dialTimeout)
	if err != nil {
		r.log.Warn("转发连接失败", "rule", r.rule.Name, "remote", client.RemoteAddr().String(), "target", r.targetAddr(), "err", err.Error())
		// 这条连接已经注定失败了。如果对面是浏览器发来的网页请求，回一页统一样式的
		// 错误页再关，免得只看到浏览器自己那句"无法访问此网站"（见 httperr.go）。
		r.replyBackendDown(client)
		return
	}
	defer upstream.Close()

	// 两端都开 keepalive：客户端侧防止半开连接长期占用配额，后端侧让对端消失时拷贝能返回。
	setupTCPConn(client)
	setupTCPConn(upstream)

	r.logConnEstablished("tcp", client.RemoteAddr().String(), &r.firstTCPLogged)
	pipe(r.ctx, client, upstream)
	r.log.Debug("转发连接关闭", "rule", r.rule.Name, "remote", client.RemoteAddr().String(), "target", r.targetAddr(), "proto", "tcp", "ms", time.Since(started).Milliseconds())
}

// ---------- UDP ----------

func (r *runner) startUDP() error {
	network := udpNetwork(r.rule.Family)
	udpAddr, err := net.ResolveUDPAddr(network, r.listenAddr())
	if err != nil {
		r.failed.Store(true)
		return fmt.Errorf("解析 UDP 地址失败: %w", err)
	}
	conn, err := net.ListenUDP(network, udpAddr)
	if err != nil {
		r.failed.Store(true)
		return fmt.Errorf("UDP 监听失败: %w", err)
	}
	r.udpConn = conn
	r.wg.Add(1)
	go r.serveUDP(conn)
	return nil
}

// udpSession 记录一个客户端地址到后端连接的映射。
type udpSession struct {
	upstream *net.UDPConn
	lastSeen time.Time
}

// udpBufPool 复用 UDP 数据报缓冲。64 KiB 是单个数据报的理论上限，不能取更小值，
// 而会话在存活期间会一直持有自己的缓冲，因此池化并不降低并发峰值占用；
// 它省掉的是会话频繁建立/销毁时的反复分配——典型如 DNS 转发，
// 每次查询都来自一个新的客户端端口，即一个新会话。
var udpBufPool = sync.Pool{New: func() any { b := make([]byte, udpDatagramMax); return &b }}

func (r *runner) serveUDP(conn *net.UDPConn) {
	defer r.wg.Done()

	sessions := make(map[string]*udpSession)
	var smu sync.Mutex
	bufp := udpBufPool.Get().(*[]byte)
	defer udpBufPool.Put(bufp)
	buf := *bufp

	// 会话的删除有三处（退出清理、空闲清理、后端读出错），而每删一条都要连带归还一个
	// 模块级名额，所以归还只写在这一个地方。三处各写一遍必然会漏，而漏一次就是名额
	// 永久少一个：泄够 maxConnsTotal 个之后整个模块再也接不进新连接，且没有任何报错。
	//
	// dropLocked 要求调用方持有 smu；drop 是给不持锁的调用方（udpReturn）用的包装。
	// only 非 nil 时只在会话仍是那条后端连接时才动手——那条会话可能已经被空闲清理
	// 摘掉、同一个客户端地址又建了新的一条，此时旧的读循环不该把新会话删掉。
	dropLocked := func(key string, s *udpSession) {
		_ = s.upstream.Close()
		delete(sessions, key)
		r.conns.leave()
	}
	drop := func(key string, only *net.UDPConn) {
		smu.Lock()
		defer smu.Unlock()
		if s := sessions[key]; s != nil && (only == nil || s.upstream == only) {
			dropLocked(key, s)
		}
	}

	// 退出时（stop 关闭监听或取消 ctx）关闭全部后端连接，立即解除 udpReturn 的阻塞读，
	// 使 wg.Wait 快速返回，避免最长等待一个空闲超时周期。
	defer func() {
		smu.Lock()
		for k, s := range sessions {
			dropLocked(k, s)
		}
		smu.Unlock()
	}()

	// 清理空闲会话。
	ticker := time.NewTicker(udpIdleTimeout)
	defer ticker.Stop()
	go func() {
		for {
			select {
			case <-r.ctx.Done():
				return
			case <-ticker.C:
				smu.Lock()
				for k, s := range sessions {
					if time.Since(s.lastSeen) > udpIdleTimeout {
						dropLocked(k, s)
					}
				}
				smu.Unlock()
			}
		}
	}()

	for {
		n, clientAddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			select {
			case <-r.ctx.Done():
				return
			default:
				return
			}
		}
		key := clientAddr.String()

		smu.Lock()
		s := sessions[key]
		if s == nil {
			// 并发上限：活跃会话数达上限时丢弃本次数据报，避免会话表无限膨胀。
			// 与 TCP 同样两道闸，先判本端口的（见 serveTCP 里那段说明）。
			if len(sessions) >= maxConnsPerRunner {
				smu.Unlock()
				r.logCapReached("udp", key)
				continue
			}
			if !r.conns.enter() {
				smu.Unlock()
				r.logTotalCapReached("udp", key)
				continue
			}
			up, derr := net.DialTimeout("udp", r.targetAddr(), dialTimeout)
			if derr != nil {
				r.conns.leave() // 名额已经占了，会话没建起来，就在这里还掉
				smu.Unlock()
				r.log.Warn("转发连接失败", "rule", r.rule.Name, "remote", key, "target", r.targetAddr(), "proto", "udp", "err", derr.Error())
				continue
			}
			udpUp, ok := up.(*net.UDPConn)
			if !ok {
				_ = up.Close()
				r.conns.leave()
				smu.Unlock()
				continue
			}
			now := time.Now()
			s = &udpSession{upstream: udpUp, lastSeen: now}
			sessions[key] = s
			r.logConnEstablished("udp", key, &r.firstUDPLogged)
			r.wg.Add(1)
			go r.udpReturn(conn, udpUp, clientAddr, key, drop)
		}
		s.lastSeen = time.Now()
		up := s.upstream
		smu.Unlock()

		_, _ = up.Write(buf[:n])
	}
}

// udpReturn 把后端回包写回客户端，直到后端读出错或超时。
//
// drop 由 serveUDP 提供：它是唯一会摘掉会话的入口，也是唯一归还模块级名额的地方。
func (r *runner) udpReturn(client *net.UDPConn, upstream *net.UDPConn, clientAddr *net.UDPAddr, key string, drop func(string, *net.UDPConn)) {
	defer r.wg.Done()
	defer func() {
		r.log.Debug("转发连接关闭", "rule", r.rule.Name, "remote", key, "target", r.targetAddr(), "proto", "udp")
	}()
	bufp := udpBufPool.Get().(*[]byte)
	defer udpBufPool.Put(bufp)
	buf := *bufp
	for {
		select {
		case <-r.ctx.Done():
			return
		default:
		}
		_ = upstream.SetReadDeadline(time.Now().Add(udpIdleTimeout))
		n, err := upstream.Read(buf)
		if err != nil {
			// 传 upstream 是那个身份判断：这条会话可能已经被空闲清理摘掉、
			// 同一个客户端地址又建了新的一条，不能把新的那条删掉。
			drop(key, upstream)
			return
		}
		_, _ = client.WriteToUDP(buf[:n], clientAddr)
	}
}

// ---------- 工具 ----------

// copyBufPool 复用回退拷贝路径的缓冲。
// Linux 下 TCP↔TCP 走 splice(2)，io.CopyBuffer 根本不会碰这块缓冲（它先检查
// WriteTo/ReadFrom 快路径）；只有 Windows/macOS 等没有 splice 的平台才真正用到。
// 池化的意义在于把「每条连接每个方向新分配 32 KiB」变成按并发峰值复用：
// 1024 条连接原本意味着 64 MB 一次性分配，且连接结束即成垃圾。
// 池里存 *[]byte 而非 []byte，避免每次 Put 把 slice header 装箱再分配一次。
var copyBufPool = sync.Pool{New: func() any { b := make([]byte, copyBufSize); return &b }}

// pipe 在两个连接间双向转发，直到**两个方向都结束**（或 ctx 取消）。
//
// 拷贝用 io.CopyBuffer 而非手写 Read/Write 循环：Linux 下双方同为 *net.TCPConn 时
// 会走 (*TCPConn).WriteTo → splice(2)，数据在内核管道内直接转移，不进用户态、
// 也不使用这里传入的缓冲；其余平台退化为普通拷贝，缓冲来自 copyBufPool。
//
// 关于空闲超时：旧实现在每次 Read 前重设读超时，代价是每 32 KiB 两次 netpoll 定时器堆操作，
// 且彻底放弃了 splice。更要紧的是它会把「安静但活着」的会话——空闲的 SSH、RDP、
// 数据库长连接——在 5 分钟后误杀。现改为依赖 TCP keepalive 由内核探测对端存活
// （见 setupTCPConn）：splice 期间用户态看不到任何进度，无法在其上实现真正的空闲判定，
// 而 keepalive 正是内核为此提供的机制；判定时长与旧的 300 秒上限相当。
func pipe(ctx context.Context, a, b net.Conn) {
	done := make(chan struct{}, 2)
	cp := func(dst, src net.Conn) {
		defer func() { done <- struct{}{} }()
		buf := copyBufPool.Get().(*[]byte)
		_, _ = io.CopyBuffer(dst, src, *buf)
		copyBufPool.Put(buf)
		// 单向读到 EOF 时只关闭写方向：客户端发完请求后 shutdown(SHUT_WR) 是合法且常见的
		// 模式（FTP 数据连接、部分 RPC、nc 管道、无 Content-Length 的 HTTP/1.0 响应），
		// 直接双向关闭会把对端还没发出的响应截断。
		closeWrite(dst)
	}
	go cp(a, b)
	go cp(b, a)

	// 两个方向都结束后才真正关闭连接；ctx 取消（模块重载 / 进程退出）时强制关闭，
	// 以唤醒仍阻塞在读上的方向，否则 runner.stop 的 wg.Wait 会一直等下去。
	remaining := 2
	for remaining > 0 {
		select {
		case <-done:
			remaining--
		case <-ctx.Done():
			_ = a.Close()
			_ = b.Close()
			// 连接已关闭，两个方向正常会立即返回；仍加一秒上限兜底，避免异常情况卡住调用方。
			for ; remaining > 0; remaining-- {
				select {
				case <-done:
				case <-time.After(time.Second):
					return
				}
			}
			return
		}
	}
	_ = a.Close()
	_ = b.Close()
}

// closeWrite 关闭连接的写方向（TCP 半关闭）。非 TCP 连接没有这个语义，直接忽略。
func closeWrite(c net.Conn) {
	if tc, ok := c.(*net.TCPConn); ok {
		_ = tc.CloseWrite()
	}
}

// setupTCPConn 为转发用的 TCP 连接开启 keepalive，作为空闲/半开连接的回收机制。
// Linux 下首个探测在静默 tcpKeepAlivePeriod 后发出、之后按同一周期重试（默认 9 次），
// 即约 30 + 9×30 = 300 秒判定对端消失，使阻塞的拷贝返回、连接与协程被释放；
// 与旧实现的 300 秒空闲上限相当，区别是不会误杀仍然存活、只是没有数据的连接。
func setupTCPConn(c net.Conn) {
	tc, ok := c.(*net.TCPConn)
	if !ok {
		return
	}
	_ = tc.SetKeepAlive(true)
	_ = tc.SetKeepAlivePeriod(tcpKeepAlivePeriod)
}

func tcpNetwork(family string) string {
	switch family {
	case "v4":
		return "tcp4"
	case "v6":
		return "tcp6"
	default:
		return "tcp"
	}
}

func udpNetwork(family string) string {
	switch family {
	case "v4":
		return "udp4"
	case "v6":
		return "udp6"
	default:
		return "udp"
	}
}
