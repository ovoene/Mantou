package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"sync"
	"time"

	"mantou/internal/logx"
)

// 本文件实现「配置」与「运行态」的分离持久化。
//
// 问题：DDNS 的每次探测、计划任务的每次执行、端口转发的每次连接失败、证书签发的每一步进度，
// 都会把一小段运行状态（最近 IP、最近结果、下次执行时间、签发阶段……）回写到磁盘。
// 这些字段原本与配置同处 data/config.json，于是每次状态变化都要把**整份配置**
// （面板设置、全部规则、DNS 凭据、ACME 账户私钥）重新序列化并原子替换一遍：
//   - 写放大：几十字节的状态变化触发数十 KB 的全量重写；
//   - 风险面：真正需要谨慎持久化的配置文件被高频改写，崩溃窗口被无谓放大；
//   - 噪声：配置文件的修改时间与内容始终在跳动，无法用于判断"配置是否被改过"。
//
// 方案：运行态迁出到 data/state.json，由本文件的 State 独立承载。
//   - 写入合并：运行态变更只标记脏位，由 stateFlushInterval 的合并窗口统一落盘，
//     一个探测周期内的多次状态变化只产生一次写入；
//   - 权威归属：加载时以 state.json 覆盖配置中的运行态字段，写出 config.json 时把运行态清零，
//     两个文件各有唯一职责，不会互相覆盖；
//   - 兼容升级：首次启动若无 state.json，则以 config.json 中已有的运行态为迁移源写出一份，
//     历史状态不丢失（见 loadStateLocked）。
//
// 代价与取舍：进程若在合并窗口内被强杀，最多丢失 stateFlushInterval 一个窗口内的运行态变化。
// 留在这个文件里的字段全部是「下一个探测/执行周期就会重新写上来」的，其中 DDNS 的 lastIP、
// 证书的到期时间、计划任务的下次执行时刻还是运行期的判断依据，所以必须持久化。
// 纯展示的计数（接收器收了几条、通知目标发了几条、设备唤醒过几次）不在这里——
// 它们的写入频率不由本程序决定，已经搬到内存里（见 internal/runstats）。
// 配置数据本身仍是每次 Update 同步落盘，不受影响。

// StateVersion 是 state.json 的结构版本，供将来迁移使用。
const StateVersion = 1

// stateFlushInterval 运行态落盘的合并窗口：窗口内的多次变更合并为一次写入。
//
// 取 5 秒是因为运行态的产生速率本就不高（DDNS 默认 300 秒一轮、计划任务最快每分钟一次），
// 真正需要合并的是突发场景：端口转发的目标宕机时每条失败连接都会尝试回写，
// 证书签发过程中每个阶段都会推进一次进度。5 秒足以把这类突发压成单次写入，
// 又不至于让面板上的状态显示明显滞后（面板轮询读的是内存，永远是最新值；
// 这个窗口只影响"进程被强杀时磁盘上留下的状态有多旧"）。
//
// 曾经还有一个 60 秒的宽窗口，专给「时间范围」唤醒那种 1 秒一拍的纯计数回写用——
// 那条路径会让脏位从不熄灭，5 秒窗口于是变成「每 5 秒雷打不动写一次盘」。
// 现在那些计数根本不落盘了，宽窗口连同它的调用方一起删掉：留着一个没人走的第二条
// 路径，只会让下一个人以为「高频回写走那边就行」，而正确答案是不要落盘。
const stateFlushInterval = 5 * time.Second

// State 是运行态的持久化形态：按条目 ID 索引，与配置里的条目顺序无关。
// 用 map 而非数组是为了让「配置里增删条目」与「运行态落盘」彻底解耦——
// 条目被删除后其运行态会在下一次落盘时自然消失（extractState 只遍历当前配置）。
type State struct {
	Version  int                     `json:"version"`
	DDNS     map[string]DDNSState    `json:"ddns,omitempty"`
	Forwards map[string]ForwardState `json:"forwards,omitempty"`
	Cron     map[string]CronState    `json:"cronTasks,omitempty"`
	Certs    map[string]CertState    `json:"certs,omitempty"`
}

// DDNSState 一条动态域名规则的运行态。
type DDNSState struct {
	LastIP       string `json:"lastIP,omitempty"`
	LastUpdateAt int64  `json:"lastUpdateAt,omitempty"`
	LastStatus   string `json:"lastStatus,omitempty"`
}

func ddnsStateOf(r *DDNSRule) DDNSState {
	return DDNSState{LastIP: r.LastIP, LastUpdateAt: r.LastUpdateAt, LastStatus: r.LastStatus}
}

func (s DDNSState) applyTo(r *DDNSRule) {
	r.LastIP = s.LastIP
	r.LastUpdateAt = s.LastUpdateAt
	r.LastStatus = s.LastStatus
}

// ForwardState 一条端口转发规则的运行态。
type ForwardState struct {
	LastError string `json:"lastError,omitempty"`
}

func forwardStateOf(r *ForwardRule) ForwardState {
	return ForwardState{LastError: r.LastError}
}

func (s ForwardState) applyTo(r *ForwardRule) {
	r.LastError = s.LastError
}

// CronState 一条计划任务的运行态。
type CronState struct {
	LastRunAt  int64  `json:"lastRunAt,omitempty"`
	NextRunAt  int64  `json:"nextRunAt,omitempty"`
	LastStatus string `json:"lastStatus,omitempty"`
}

func cronStateOf(t *CronTask) CronState {
	return CronState{LastRunAt: t.LastRunAt, NextRunAt: t.NextRunAt, LastStatus: t.LastStatus}
}

func (s CronState) applyTo(t *CronTask) {
	t.LastRunAt = s.LastRunAt
	t.NextRunAt = s.NextRunAt
	t.LastStatus = s.LastStatus
}

// CertState 一张证书的运行态（签发/续期进度与到期时间）。
type CertState struct {
	NotAfter    int64                      `json:"notAfter,omitempty"`
	Status      string                     `json:"status,omitempty"`
	IssueStatus CertificateOperationStatus `json:"issueStatus"`
	RenewStatus CertificateOperationStatus `json:"renewStatus"`
	LastRenewAt int64                      `json:"lastRenewAt,omitempty"`
}

func certStateOf(c *Certificate) CertState {
	return CertState{
		NotAfter:    c.NotAfter,
		Status:      c.Status,
		IssueStatus: c.IssueStatus,
		RenewStatus: c.RenewStatus,
		LastRenewAt: c.LastRenewAt,
	}
}

func (s CertState) applyTo(c *Certificate) {
	c.NotAfter = s.NotAfter
	c.Status = s.Status
	c.IssueStatus = s.IssueStatus
	c.RenewStatus = s.RenewStatus
	c.LastRenewAt = s.LastRenewAt
}

// 列表页上那几个统计数字原先也在这个文件里：接收器的 lastReceivedAt / receivedCount、
// 通知目标的 lastSentAt / sentCount / failCount、设备的 lastWakeAt / wakeCount。
// 现在它们存在内存里、重启归零，不再进这个文件——三者的写入频率都不由本程序决定
// （入站看公网、投递看扇出量、时间范围唤醒最快 1 秒一拍），写进这里等于让外部
// 决定本机的落盘频率；而这些数丢了不影响任何行为，全项目只有列表页在看。
// 见 internal/runstats 包的说明。

// extractState 从配置中抽取全部运行态。只遍历当前存在的条目，
// 因此已删除条目的运行态不会被再次写出（等价于自动清理）。
func extractState(c *Config) *State {
	st := &State{Version: StateVersion}
	if len(c.DDNS) > 0 {
		st.DDNS = make(map[string]DDNSState, len(c.DDNS))
		for i := range c.DDNS {
			st.DDNS[c.DDNS[i].ID] = ddnsStateOf(&c.DDNS[i])
		}
	}
	if len(c.Forwards) > 0 {
		st.Forwards = make(map[string]ForwardState, len(c.Forwards))
		for i := range c.Forwards {
			st.Forwards[c.Forwards[i].ID] = forwardStateOf(&c.Forwards[i])
		}
	}
	if len(c.CronTasks) > 0 {
		st.Cron = make(map[string]CronState, len(c.CronTasks))
		for i := range c.CronTasks {
			st.Cron[c.CronTasks[i].ID] = cronStateOf(&c.CronTasks[i])
		}
	}
	if len(c.Certs) > 0 {
		st.Certs = make(map[string]CertState, len(c.Certs))
		for i := range c.Certs {
			st.Certs[c.Certs[i].ID] = certStateOf(&c.Certs[i])
		}
	}
	return st
}

// applyState 把运行态覆盖到配置对应条目上。
// 语义是**整体覆盖**而非合并：st 中没有记录的条目，其运行态字段被清零。
// 这一点是"state.json 为运行态唯一权威来源"的保证——否则 config.json 里的历史残留
// 会与 state.json 混合，出现两个文件各说一半的局面。
// st 为 nil 时等价于清零全部运行态（stripRuntimeState 即以此实现）。
func applyState(c *Config, st *State) {
	if st == nil {
		st = &State{}
	}
	for i := range c.DDNS {
		st.DDNS[c.DDNS[i].ID].applyTo(&c.DDNS[i])
	}
	for i := range c.Forwards {
		st.Forwards[c.Forwards[i].ID].applyTo(&c.Forwards[i])
	}
	for i := range c.CronTasks {
		st.Cron[c.CronTasks[i].ID].applyTo(&c.CronTasks[i])
	}
	for i := range c.Certs {
		st.Certs[c.Certs[i].ID].applyTo(&c.Certs[i])
	}
}

// preserveRuntimeState 把 src 的运行态原样贴回 dst（按条目 ID 匹配）。
// 用于 Update / Replace：配置写入路径**不得**改动运行态，否则面板提交的表单
// （其中并不包含 lastIP / lastStatus 这类只读字段）会把运行态抹成空值。
// dst 中新增的条目（src 里没有对应 ID）运行态为零值，符合"新建条目尚无运行状态"的预期。
func preserveRuntimeState(src, dst *Config) {
	applyState(dst, extractState(src))
}

// stripRuntimeState 清零配置中的全部运行态字段，用于写出 config.json 之前。
func stripRuntimeState(c *Config) {
	applyState(c, nil)
}

// configForDisk 返回一份运行态已清零的配置副本，供写出 config.json 使用。
// 只复制需要就地改动的那几个切片（其余字段共享，因为不会被就地修改），
// 避免为一次落盘做整份配置的 JSON 深拷贝。需要复制的有三类：
//   - 运行态清零涉及的切片（DDNS/Forwards/CronTasks/Certs）；
//   - 敏感字段加密涉及的 Credentials 与 ACMEAccounts，以及带凭证字段的
//     WebhookReceivers/NotifyTargets（见 secret.go）；
//   - 上述两类里带 map 字段的条目，还要克隆 map 本身——map 是引用类型，不克隆就会把
//     内存中的明文原地换成密文。Credentials.Secrets 若漏了，之后 DDNS 拿去更新解析的
//     就是一段密文；NotifyTarget.Headers 若漏了，之后投递时带出去的 Authorization
//     就是一段 enc:v1: 文本，而且一直错到进程重启为止（重启后从磁盘解密才恢复正常）。
//
// WOLDevices 不在这里：它已经没有任何要在落盘前就地改动的字段（唤醒记录搬去了
// internal/runstats，没有凭证要加密），共享那条切片即可。
func configForDisk(c *Config) *Config {
	out := *c
	out.DDNS = append([]DDNSRule(nil), c.DDNS...)
	out.Forwards = append([]ForwardRule(nil), c.Forwards...)
	out.CronTasks = append([]CronTask(nil), c.CronTasks...)
	out.Certs = append([]Certificate(nil), c.Certs...)
	out.ACMEAccounts = append([]ACMEAccount(nil), c.ACMEAccounts...)
	out.WebhookReceivers = append([]WebhookReceiver(nil), c.WebhookReceivers...)
	if c.Credentials != nil {
		out.Credentials = make([]Credential, len(c.Credentials))
		for i, cred := range c.Credentials {
			cred.Secrets = maps.Clone(cred.Secrets)
			out.Credentials[i] = cred
		}
	}
	if c.NotifyTargets != nil {
		out.NotifyTargets = make([]NotifyTarget, len(c.NotifyTargets))
		for i, t := range c.NotifyTargets {
			t.Headers = maps.Clone(t.Headers)
			out.NotifyTargets[i] = t
		}
	}
	stripRuntimeState(&out)
	return &out
}

// loadState 读取 state.json。文件不存在时返回 (nil, nil)。
// 内容损坏（如断电留下的半截文件）不视为致命错误：运行态是展示性数据，
// 为此拒绝启动毫无意义，故记一条警告后按"不存在"处理，随后会被重新写出。
func loadState(path string) (*State, error) {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		logx.L().Warn("读取运行态文件失败，将按初始状态处理", "path", path, "err", err.Error())
		return nil, nil
	}
	st := &State{}
	if err := json.Unmarshal(data, st); err != nil {
		logx.L().Warn("解析运行态文件失败，将按初始状态处理", "path", path, "err", err.Error())
		return nil, nil
	}
	return st, nil
}

// marshalState 序列化运行态。
//
// 刻意用 json.Marshal 而非 MarshalIndent：state.json 是纯机器文件——只在启动时被
// loadStateLocked 读一次，运行期面板读的全是内存值。缩进对它没有任何价值，
// 却要为每个字段多写一串空格与换行，而它恰好是本项目里写入最频繁的文件。
// config.json 相反：它是设计上要给人看、必要时手工修的（见 secret.go 顶部），故保持缩进。
func marshalState(st *State) ([]byte, error) {
	data, err := json.Marshal(st)
	if err != nil {
		return nil, fmt.Errorf("序列化运行态失败: %w", err)
	}
	return data, nil
}

// writeStateFile 以「临时文件 + 原子替换」写出已序列化的运行态。
// 不 fsync：运行态是可丢数据，理由见 config.skipFsync。
func writeStateFile(path string, data []byte) error {
	if err := writeFileAtomic(path, data, 0o600, skipFsync); err != nil {
		return fmt.Errorf("写入运行态失败: %w", err)
	}
	return nil
}

// saveState 序列化并写出运行态。
func saveState(path string, st *State) error {
	data, err := marshalState(st)
	if err != nil {
		return err
	}
	return writeStateFile(path, data)
}

// ---------- Manager 的运行态落盘调度 ----------

// stateFlusher 承载运行态的脏位与合并落盘定时器，内嵌于 Manager。
type stateFlusher struct {
	// mu 只保护脏位与定时器这几个字段，不覆盖磁盘写入本身，
	// 以免模块协程标记脏位时被一次磁盘写入阻塞。
	mu     sync.Mutex
	dirty  bool
	timer  *time.Timer
	closed bool

	// windowOverride 为零值时取 stateFlushInterval。存在的意义只有一个：测试能把窗口
	// 缩到毫秒级，从而不必真等 5 秒就能验证合并行为。生产路径从不赋值。
	windowOverride time.Duration

	// flushMu 串行化实际的落盘动作（定时器触发与显式 Flush/Close 可能并发）。
	flushMu sync.Mutex

	// lastWritten 是上一次成功写出 state.json 的字节内容，用于跳过「脏位置上、
	// 但序列化结果与磁盘上完全一致」的落盘。只在持有 flushMu 时访问——FlushState 是唯一读写者。
	//
	// 进程启动后首次落盘时它仍是 nil（Load 期间的迁移写出不经过 flushMu，不便在那里记账），
	// 因此每次启动最多多写一次，与修复前行为相同。
	lastWritten []byte
}

func (f *stateFlusher) window() time.Duration {
	if f.windowOverride > 0 {
		return f.windowOverride
	}
	return stateFlushInterval
}

// markStateDirty 记录运行态已变更，并保证在 stateFlushInterval 之内至少落盘一次。
// 窗口内的后续变更只是复用已排定的这一次落盘，不会各自触发写入。
func (m *Manager) markStateDirty() {
	window := m.state.window()
	m.state.mu.Lock()
	defer m.state.mu.Unlock()
	m.state.dirty = true
	// 已关闭：不再排定新的落盘（Close 已做过最后一次 Flush）。脏位仍然置上，
	// 以便调用方在关闭后显式 FlushState 时仍能写出。
	if m.state.closed {
		return
	}
	// 已有排定就复用它，**不重排**。
	//
	// 这里曾是「只许提前、不许推后」：那时有两个窗口（5 秒与 60 秒），后到的紧急变更
	// 算出来的到期时刻可能早于已排定的那次，于是要把定时器 Reset 到更早。窗口只剩一个
	// 之后那个分支再也走不到——同一个窗口下，后到的变更算出来的到期时刻必然更晚。
	// 连同它记账用的 dueAt 一起删了，留下这句话是因为「重排一下更直观」正是这里最容易
	// 犯的错：每次变更都 Reset，等于让「每秒标一次脏」的调用方无限期推迟落盘——
	// 脏位一直在、盘一直不写。这里的取舍是「至多晚一个窗口落一次盘」，
	// 不是「最后一次变更之后再等一个窗口」。
	if m.state.timer != nil {
		return
	}
	m.state.timer = time.AfterFunc(window, func() {
		m.state.mu.Lock()
		m.state.timer = nil
		m.state.mu.Unlock()
		if err := m.FlushState(); err != nil {
			logx.L().Warn("运行态落盘失败", "path", m.statePath, "err", err.Error())
		}
	})
}

// FlushState 立即把尚未落盘的运行态写出；无变更时为空操作。
// 落盘失败会保留脏位，交由下一次合并窗口或显式调用重试。
func (m *Manager) FlushState() error {
	m.state.flushMu.Lock()
	defer m.state.flushMu.Unlock()

	m.state.mu.Lock()
	dirty := m.state.dirty
	m.state.dirty = false
	m.state.mu.Unlock()
	if !dirty {
		return nil
	}

	// Snapshot 是只读共享视图，extractState 只读取标量字段，无需持有配置锁。
	data, err := marshalState(extractState(m.Snapshot()))
	if err != nil {
		m.remarkStateDirty()
		return err
	}
	// 脏位只说明"有人动过运行态"，并不说明"动出来的结果与磁盘上不同"。二者会分叉：
	// 状态文本被 TruncateStatus 截成同一个值、计数增减后回到原值、或某条规则的
	// 回写把字段设成它本来就有的值——这些都会置脏位，而落盘写的是同一串字节。
	// 比较几 KB 内存比一次原子替换（建临时文件 + 写 + rename）便宜得多，值得先问一句。
	if m.state.lastWritten != nil && bytes.Equal(m.state.lastWritten, data) {
		return nil
	}
	if err := writeStateFile(m.statePath, data); err != nil {
		m.remarkStateDirty()
		return err
	}
	m.state.lastWritten = data
	return nil
}

// remarkStateDirty 把脏位退回，使这次未能完成的落盘会被后续窗口或显式调用重试。
func (m *Manager) remarkStateDirty() {
	m.state.mu.Lock()
	m.state.dirty = true
	m.state.mu.Unlock()
}

// Close 停止合并落盘定时器，并把最后一批运行态写出。
// 应在进程退出前调用（含自更新的 exec 替换路径——syscall.Exec 不执行 defer）。
func (m *Manager) Close() error {
	m.state.mu.Lock()
	m.state.closed = true
	if m.state.timer != nil {
		m.state.timer.Stop()
		m.state.timer = nil
	}
	m.state.mu.Unlock()
	return m.FlushState()
}
