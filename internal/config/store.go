package config

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"mantou/internal/logx"
)

// CurrentVersion 是当前配置结构版本，用于将来做迁移。
const CurrentVersion = 11

// Manager 负责配置的加载、持久化与线程安全访问。
type Manager struct {
	mu   sync.RWMutex
	path string
	cfg  *Config
	// rev 是配置版本号，每次成功替换 m.cfg 时自增（单调递增，供版本追踪；Update/Replace 均在写锁内串行完成）。
	rev uint64
	// snap 是当前配置的只读共享快照，与 m.cfg 始终指向同一份数据。
	// 存在的意义：Get() 是深拷贝（整份配置的 JSON 序列化 + 反序列化），而热路径上
	// 每个 TLS 握手、每个已认证 API 请求都只是读一两个字段（JWT 密钥、面板域名、证书启用位），
	// 却要为此把整份配置连同全部规则、凭据、证书重新分配一遍。快照让这些读取降为一次原子加载。
	snap atomic.Pointer[Config]

	// statePath 是运行态文件（state.json）路径，与配置文件同目录。
	// 运行态与配置分文件持久化的原因、合并落盘策略见 state.go 顶部说明。
	statePath string
	state     stateFlusher

	// keyPath 是主密钥文件（master.key）路径，与配置文件同目录；
	// box 是据此构造的字段加解密器，首次用到时才初始化（见 boxLocked）。
	// 二者只在持有 m.mu 写锁时访问。敏感字段的加密边界见 secret.go 顶部说明。
	keyPath string
	box     *secretBox
}

// NewManager 创建一个绑定到指定文件路径的配置管理器。
// 运行态文件固定为同目录下的 state.json，主密钥固定为同目录下的 master.key。
func NewManager(path string) *Manager {
	dir := filepath.Dir(path)
	return &Manager{
		path:      path,
		statePath: filepath.Join(dir, "state.json"),
		keyPath:   filepath.Join(dir, masterKeyName),
	}
}

// KeyPath 返回主密钥文件路径。
func (m *Manager) KeyPath() string { return m.keyPath }

// StatePath 返回运行态文件路径。
func (m *Manager) StatePath() string { return m.statePath }

// Path 返回配置文件路径。
func (m *Manager) Path() string { return m.path }

// Rev 返回配置版本号：每次配置内容真正发生变化（Load / Update 有实际变更 / Replace）时自增。
// 供调用方判断"自上次读取以来配置是否变过"，无需比较内容。
func (m *Manager) Rev() uint64 {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.rev
}

// Snapshot 返回当前配置的**只读**共享快照：一次原子指针加载，不拷贝。
//
// 调用方**绝不能**修改返回值，也不能修改其中任何 slice/map 元素——它由所有并发读者共享，
// 就地改动会同时污染其他读者看到的配置，且绕过 Update 的落盘与脏检查。
// 需要在副本上改动（例如把签发得到的账户私钥写回）时必须用 Get()，写入配置一律走 Update()。
//
// 快照本身是不可变的：Update/Replace 从不就地修改已发布的配置，而是克隆、改副本、
// 再整体替换指针，因此持有旧快照的读者始终看到一份自洽的历史配置。
func (m *Manager) Snapshot() *Config {
	if cfg := m.snap.Load(); cfg != nil {
		return cfg
	}
	// 尚未 Load（仅在初始化竞态或未调用 Load 的测试里出现）。这里刻意**不**走 Get()：
	// Get 会因克隆失败而返回 error，而 Snapshot 必须保证非 nil；且 Snapshot 的契约本就是
	// 「共享只读」，直接交出内存里那份指针正合语义（Update/Replace 从不就地改已发布的配置）。
	m.mu.RLock()
	cfg := m.cfg
	m.mu.RUnlock()
	if cfg == nil {
		return &Config{}
	}
	return cfg
}

// publishLocked 发布 m.cfg 为新的只读快照，调用方需已持有写锁。
func (m *Manager) publishLocked() {
	m.snap.Store(m.cfg)
}

// Load 从磁盘读取配置；文件不存在时使用默认配置并落盘。
func (m *Manager) Load() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	data, err := os.ReadFile(m.path)
	if os.IsNotExist(err) {
		m.cfg = Default()
		m.rev++
		m.publishLocked()
		return m.saveLocked()
	}
	if err != nil {
		return fmt.Errorf("读取配置失败: %w", err)
	}

	cfg := Default()
	if err := json.Unmarshal(data, cfg); err != nil {
		return fmt.Errorf("解析配置失败: %w", err)
	}
	migrate(cfg)
	// 敏感字段解密：必须在此处完成，之后内存中的配置一律是明文（见 secret.go）。
	if err := m.openSecretsLocked(cfg); err != nil {
		return err
	}
	m.cfg = cfg
	// 运行态以 state.json 为准（见 state.go）：必须在模块启动之前完成叠加，
	// 否则 DDNS 会拿不到上次的 lastIP 基准而把首轮探测误判为"首次同步"。
	m.loadStateLocked()
	// 保证运行期必需的密钥存在（如首次从旧配置升级）。
	if m.cfg.Auth.JWTSecret == "" {
		m.cfg.Auth.JWTSecret = randomHex(32)
		m.rev++
		m.publishLocked()
		if err := m.saveLocked(); err != nil {
			return err
		}
		return nil
	}
	m.rev++
	m.publishLocked()
	return nil
}

// loadStateLocked 把 state.json 的运行态叠加到已加载的配置上，调用方需已持有写锁。
// state.json 不存在时视为从旧版本首次升级：此时运行态仍留在 config.json 里，
// 以其为迁移源写出一份 state.json，历史状态不丢失；此后 config.json 不再保存运行态。
func (m *Manager) loadStateLocked() {
	st, _ := loadState(m.statePath)
	if st == nil {
		if err := saveState(m.statePath, extractState(m.cfg)); err != nil {
			logx.L().Warn("初始化运行态文件失败", "path", m.statePath, "err", err.Error())
		}
		return
	}
	applyState(m.cfg, st)
}

// Get 返回配置的深拷贝，避免调用方在锁外修改共享状态。
// 只读场景（尤其是每请求/每握手的热路径）应改用 Snapshot()：Get 每次都要把整份配置
// 序列化再反序列化一遍，在 TLS 握手与鉴权中间件里属于纯粹的浪费。
//
// **深拷贝失败时返回 nil**（见 clone），调用方必须判空并放弃这次操作。这里不改成
// 返回 (*Config, error)，是因为那会让近百个只读调用点各写一段永远不会执行的错误处理；
// 而真正会造成损失的两条路——Update / UpdateState 的「落盘 + 换内存」——已经在各自
// 内部拿到并返回了这个 error，不经过 Get。
func (m *Manager) Get() *Config {
	m.mu.RLock()
	defer m.mu.RUnlock()
	clone, err := m.cfg.clone()
	if err != nil {
		// 返回 nil 而不是空 Config：空 Config 会被下游当成"用户真的什么都没配"，
		// 于是合并出一份空配置再存回去，正是这条缺陷最初的后果。
		logx.L().Error("复制配置失败", "err", err.Error())
		return nil
	}
	return clone
}

// Update 在写锁保护下对配置执行修改函数，成功后原子落盘。
// 采用「克隆 → 在副本上变更 → 锁内写盘 → 原子替换 m.cfg」策略：
// 落盘失败时内存配置不被半生效修改；写盘串行化避免并发丢失更新与内存/磁盘不一致。
//
// 运行态字段（lastIP / lastStatus / nextRunAt / issueStatus …）不受本方法影响：
// mutate 对它们的改动会被 preserveRuntimeState 还原。要改运行态请用 UpdateState。
func (m *Manager) Update(mutate func(c *Config)) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	clone, err := m.cfg.clone()
	if err != nil {
		// 克隆失败即放弃：不落盘、不换内存。紧接着的 writeLocked 会把 clone 写进
		// config.json，若这里放一个残缺副本过去，一次「保存设置」就成了「清空配置」。
		return err
	}
	mutate(clone)
	// 运行态只归 UpdateState / state.json 管辖，配置写入路径一律原样保留。
	// 否则面板保存表单（PUT 会整体替换条目，而表单里并不包含这些只读字段）
	// 会把规则的最近状态、下次执行时间、签发进度一并抹掉。
	preserveRuntimeState(m.cfg, clone)
	// 写盘在写锁内串行完成。此前的「克隆 → 锁外写盘 → 按 rev 原子交换」在并发下会
	// 丢失更新并造成内存/磁盘不一致：两个并发 Update 基于同一基准克隆，后写盘者覆盖磁盘、
	// 但 rev 比对只让先提交者进入内存，导致重启后某次改动被永久丢弃（DDNS/端口转发/计划任务等
	// 状态回写会与管理员保存并发触发）。配置文件仅 KB 级，锁内写盘开销可忽略，串行化换取正确性。
	// 脏检查：若变更后内容与当前配置完全一致（典型如面板重复提交同一份表单），
	// 跳过磁盘写盘与内存替换，消除无谓的写放大。
	if configEqual(m.cfg, clone) {
		return nil
	}
	if err := m.writeLocked(clone); err != nil {
		return err
	}
	m.cfg = clone
	m.rev++
	m.publishLocked()
	return nil
}

// UpdateState 更新**运行态**字段：立即在内存生效，磁盘写入合并到 stateFlushInterval
// 的窗口里批量完成（见 state.go）。
//
// 仅可用于运行态字段（DDNS 的最近 IP/状态、端口转发的启动错误、WOL 的最近唤醒、
// 计划任务的执行时间与结果、证书的签发/续期进度）。mutate 若改动了配置字段，
// 该改动只存在于内存中、永远不会落盘，重启即丢失——配置变更必须走 Update。
func (m *Manager) UpdateState(mutate func(c *Config)) error {
	m.mu.Lock()
	clone, err := m.cfg.clone()
	if err != nil {
		m.mu.Unlock()
		// 与 Update 同一取舍：宁可这一拍运行态不更新，也不能把残缺副本换进内存——
		// 它随后会被 state.json 的批量落盘写出去。
		return err
	}
	mutate(clone)
	// 脏检查：状态未实际变化（典型如 DDNS 轮询「IP 未变化」、计划任务空跑）时直接返回，
	// 既不换出内存配置也不标记落盘。
	if configEqual(m.cfg, clone) {
		m.mu.Unlock()
		return nil
	}
	m.cfg = clone
	m.rev++
	m.publishLocked()
	m.mu.Unlock()

	m.markStateDirty()
	return nil
}

// 列表页上那几个统计数字的回写路径原先都在这里：UpdateWebhookState（接收器收了几条）、
// UpdateWOLState（设备唤醒过几次）、UpdateNotifyState（通知目标发成功几条）。
// 三个都删掉了——那些数搬去了 internal/runstats，只在内存里，重启归零。
//
// 留这段话是为了记住删的理由，免得下一次「列表上想多显示一个数」时又照原样加回来：
//
//   - 三条路径的调用频率都不由本程序决定。接收器是每条入站请求一次（公网说了算，
//     包括被限流挡掉的 429 与令牌不对的 401——于是限流器挡住了「进流水线」，却没挡住
//     「回写运行态」，被拒的请求反而只做这一件最贵的事）；通知目标是一条消息扇出到
//     N 个目标就 N 次；网络唤醒的「时间范围」模式最快 1 秒一拍、每台设备各一条协程。
//   - 每次回写都要换一份配置、涨一次 rev、发布一次快照、标一次脏等着落盘，而全局
//     只有一把配置写锁。这几条路曾为此各自绕开泛型的 UpdateState（那个每次做四趟
//     全量配置 JSON），改成「浅拷贝 Config + 只重建一条切片」，又给落盘另开了一个
//     60 秒的宽窗口。实测 100 台设备（配置 32 KB）走泛型路径是每秒 150 ms 锁内 CPU
//     加 17 MB 垃圾，500 台时是每秒 334 ms 与 442 MB——优化过后仍然是「频率 × 条目数」
//     两头放大，只是系数小了。
//   - 而这些数丢了不影响任何行为：grep 过全项目，除了列表页显示，没有任何逻辑读它们。
//
// 所以正确的做法不是把这条路修得更快，是让它根本不落盘。反例是 DDNS 的 lastIP、
// 证书的到期时间、计划任务的下次执行时刻——那些是运行期的判断依据，仍走 markStateDirty。
//
// 上面那组数字出自 wolstate_bench_test.go 的 BenchmarkWOLStateWrite，它跟着被测代码
// 一起删了：留一个测不到任何现存代码的基准，只会在下次有人跑 -bench 时白占几分钟。
// 换掉它的是 runstats 的 TestWriteCostIgnoresTableSize——那条盯的正是新路径不该再有的
// 那个性质：单次写入的代价与表里有多少条目无关。

// configEqual 判断两份配置是否等价（经 JSON 序列化后逐字节比较）。
// 用以在 Update 中识别「无实际变化的变更」从而跳过写盘。JSON 序列化对 map/slice 顺序确定，
// 故比较结果稳定可靠；任一序列化失败则视为不等（走正常写盘路径）。
func configEqual(a, b *Config) bool {
	if a == nil || b == nil {
		return a == b
	}
	ab, err1 := json.Marshal(a)
	if err1 != nil {
		return false
	}
	bb, err2 := json.Marshal(b)
	if err2 != nil {
		return false
	}
	return bytes.Equal(ab, bb)
}

// Replace 用给定配置整体替换当前配置并落盘（用于配置导入）。
// 会执行版本迁移；若导入配置缺少运行期必需字段（JWT 密钥/端口），则保留当前值或补齐默认值，
// 以避免导入后无法登录或监听端口非法。
func (m *Manager) Replace(cfg *Config) error {
	if cfg == nil {
		return fmt.Errorf("配置为空")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	migrate(cfg)
	// 安全：导入的配置一律忽略其 JWTSecret，强制沿用当前运行中（或重新生成）的密钥，
	// 防止攻击者构造「已知 JWTSecret」的备份导入后伪造会话令牌实现持久化账户接管。
	if m.cfg != nil && m.cfg.Auth.JWTSecret != "" {
		cfg.Auth.JWTSecret = m.cfg.Auth.JWTSecret
	} else {
		cfg.Auth.JWTSecret = randomHex(32)
	}
	if cfg.Panel.Port <= 0 || cfg.Panel.Port > 65535 {
		cfg.Panel.Port = 25666
	}
	// 运行态不随备份导入：沿用本机当前的运行态（ID 匹配者保留，新增条目为空）。
	// 导入一份别处导出的备份时，其中的"最近状态/最近 IP"描述的是那台机器的历史，
	// 覆盖进来只会显示误导性信息；而本机仍在运行的规则状态没有理由被清空。
	if m.cfg != nil {
		preserveRuntimeState(m.cfg, cfg)
	} else {
		stripRuntimeState(cfg)
	}
	previous := m.cfg
	m.cfg = cfg
	if err := m.saveLocked(); err != nil {
		m.cfg = previous
		return err
	}
	m.rev++
	m.publishLocked()
	// 导入可能删除了条目：标记落盘以便 state.json 丢掉那些条目的运行态。
	m.markStateDirty()
	return nil
}

// Migrate 对一份**外部来源**的配置执行版本迁移与规范化。
//
// 供选择性导入使用：那条路径只取备份里的一部分字段合并进当前配置，而合并结果的
// version 是当前版本，Replace 内部的 migrate 不会再为这些字段补旧版缺失项。
// 因此必须在"切片"之前先把整份备份迁到最新，否则一份旧备份里的 DDNS / Web 服务
// 会以未迁移的形态被搬进一份新版配置——那是启动时才会暴露的静默数据损坏。
//
// migrate 是幂等的（版本块按 version 判定，其余是规范化），重复调用安全。
func Migrate(cfg *Config) {
	if cfg == nil {
		return
	}
	migrate(cfg)
}

// saveLocked 采用「临时文件 + 原子替换」写入，调用方需已持有写锁。
func (m *Manager) saveLocked() error {
	return m.writeLocked(m.cfg)
}

// writeLocked 把给定配置加密敏感字段后落盘，调用方需已持有写锁。
func (m *Manager) writeLocked(cfg *Config) error {
	box, err := m.boxLocked(true)
	if err != nil {
		return err
	}
	return saveConfig(m.path, cfg, box)
}

// boxLocked 返回字段加解密器，首次调用时加载主密钥；调用方需已持有写锁。
// create 为真时密钥文件不存在会生成一把新的（见 loadMasterKey 对此的说明）。
func (m *Manager) boxLocked(create bool) (*secretBox, error) {
	if m.box != nil {
		return m.box, nil
	}
	key, err := loadMasterKey(m.keyPath, create)
	if err != nil {
		return nil, err
	}
	box, err := newSecretBox(key)
	if err != nil {
		return nil, err
	}
	m.box = box
	return box, nil
}

// openSecretsLocked 解密刚从磁盘读入的配置；调用方需已持有写锁。
//
// 配置里没有任何密文时（全新安装、或从加密前的版本升级）直接返回，此时**不生成**主密钥——
// 留给后续落盘去生成，避免"只是读了一下配置"就在磁盘上留下密钥文件。
//
// 解密失败一律返回错误、绝不降级为空值：凭证字段解不开却照常启动，
// 面板上看到的是"凭证已配置"，而 DDNS 与证书续期会在下一个周期以"鉴权失败"的面目零散报错，
// 排查成本远高于启动时直接说清楚。
func (m *Manager) openSecretsLocked(cfg *Config) error {
	if !hasSealedSecret(cfg) {
		return nil
	}
	box, err := m.boxLocked(false)
	if errors.Is(err, errMasterKeyMissing) {
		return fmt.Errorf("配置中的凭证字段已加密，但主密钥 %s 不存在。"+
			"该文件是解开这些字段的唯一钥匙：请恢复原来的 master.key；"+
			"若已丢失，可用面板导出的加密备份重新导入（备份内含完整凭证），"+
			"或删除 config.json 中以 %s 开头的字段值后重新填写凭证", m.keyPath, sealPrefix)
	}
	if err != nil {
		return err
	}
	if err := box.openSecrets(cfg); err != nil {
		return fmt.Errorf("解密配置中的凭证字段失败（主密钥 %s 与配置不匹配，或配置被改动过）: %w", m.keyPath, err)
	}
	return nil
}

// saveConfig 将给定配置以「临时文件 + fsync + 原子替换」方式写入 path，调用方需保证并发安全。
// 运行态字段在写出前被清零（configForDisk）：它们由 state.json 独占持有，
// 让同一份数据出现在两个文件里必然导致"哪个为准"的歧义。
// 敏感字段在同一份副本上就地加密（configForDisk 已为此深拷贝了相关字段），内存配置不受影响。
func saveConfig(path string, cfg *Config, box *secretBox) error {
	out := configForDisk(cfg)
	if err := box.sealSecrets(out); err != nil {
		return fmt.Errorf("加密配置中的凭证字段失败: %w", err)
	}
	data, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return fmt.Errorf("序列化配置失败: %w", err)
	}
	// 配置是「丢了要人工恢复」的数据，且只在管理员改动时才写，故付 fsync 的代价。
	if err := writeFileAtomic(path, data, 0o600, fsyncData); err != nil {
		return fmt.Errorf("写入配置失败: %w", err)
	}
	return nil
}

// fsyncPolicy 决定 writeFileAtomic 是否为「新内容确实落到盘上」付 fsync 的代价。
// 取值按**数据的价值**选，不按写入频率选——理由见两个常量各自的说明。
type fsyncPolicy bool

const (
	// fsyncData：替换前 fsync 临时文件、替换后 fsync 目录。
	// 用于「丢了就要人工恢复」的文件：config.json（全部配置）与 master.key（凭证的唯一钥匙）。
	fsyncData fsyncPolicy = true
	// skipFsync：只保证原子替换，不保证新内容已经持久化。
	// 仅用于 state.json——它从设计上就声明了可丢（见 state.go 顶部与 loadState 对损坏内容的处理）。
	skipFsync fsyncPolicy = false
)

// onFsync 仅供测试观测：writeFileAtomic 每做一次 fsync 就以被同步的路径调用它一次。
// 生产路径始终为 nil，代价是一次 nil 判断；换来的是「config.json 仍然 fsync、
// state.json 不再 fsync」这条性质能被测试锁住，而不是只靠代码走查维持。
// 测试须在使用前设置、用完置回 nil，且不得并行使用。
var onFsync func(path string)

func notifyFsync(path string) {
	if onFsync != nil {
		onFsync(path)
	}
}

// writeFileAtomic 以「临时文件 →（可选 fsync）→ 原子替换 →（可选 fsync 目录）」写入文件。
//
// 为什么需要 fsync：仅靠 WriteFile + Rename 是不够的。rename 保证的是"读到的要么是旧内容
// 要么是新内容"，而不保证新内容已经落到盘上。在 ext4 的 data=ordered 默认挂载下，
// rename 元数据可能先于文件数据提交，断电后重启会得到一个**长度为 0 的文件**——
// 旧内容已经没了，新内容还没写下去。对 config.json 而言这等于丢掉全部配置。
// 故 policy 为 fsyncData 时：先 fsync 临时文件的数据，再 rename，最后 fsync 目录
// 使目录项本身持久化。
//
// policy 为 skipFsync 时保留原子替换、放弃持久化保证，即上面那个断电窗口不再被堵住。
// 这不是"为了快而降低安全性"，而是按数据价值定价：唯一的使用者是 state.json，
// 那份数据本身就是可丢的（丢了下一个探测/执行周期就重新写上来，面板读的始终是内存），
// 而它的写入频率比 config.json 高好几个数量级——一台每秒一拍的唤醒设备就是每天 1440 次落盘。
// 为一份声明了可丢的数据付两次 fsync，在 SD 卡 / eMMC 上是纯粹的寿命消耗。
//
// 目录 fsync 的失败被刻意忽略：Windows 不支持对目录句柄做 flush（返回 Access is denied），
// 而这一步只是加固，失败不影响已经 fsync 过的文件数据。
func writeFileAtomic(path string, data []byte, perm os.FileMode, policy fsyncPolicy) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("创建目录失败: %w", err)
	}
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, perm)
	if err != nil {
		return fmt.Errorf("创建临时文件失败: %w", err)
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(tmp)
		return fmt.Errorf("写入临时文件失败: %w", err)
	}
	if policy == fsyncData {
		if err := f.Sync(); err != nil {
			f.Close()
			os.Remove(tmp)
			return fmt.Errorf("同步临时文件失败: %w", err)
		}
		notifyFsync(tmp)
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("关闭临时文件失败: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("替换文件失败: %w", err)
	}
	if policy == fsyncData {
		if d, err := os.Open(dir); err == nil {
			_ = d.Sync()
			_ = d.Close()
			notifyFsync(dir)
		}
	}
	return nil
}

// Default 返回一份带合理默认值的配置。
func Default() *Config {
	return &Config{
		Version: CurrentVersion,
		Panel: Panel{
			Listen: "0.0.0.0",
			Port:   25666,
			HTTPS:  PanelHTTPS{Enabled: false},
		},
		Auth: Auth{
			SessionHours:       1,
			SessionIdleMinutes: DefaultSessionIdleMinutes,
			JWTSecret:          randomHex(32),
			Initialized:        false,
			LoginMaxFails:      5,
			LoginLockMinutes:   10,
		},
		Settings: Settings{
			Language: "zh-CN",
			Log: LogConfig{
				Levels:     []string{"info", "warn", "error"}, // 默认勾选信息/警告/错误；空数组=不记录任何级别，nil=记录所有
				MaxEntries: logx.DefaultLogEntries,            // 日志最大条数：内存两环 + 磁盘文件共用，默认 1000 条
				Console:    true,
				ShowOnHome: true,                // 默认在总览页显示日志
				HomeLimit:  DefaultLogHomeLimit, // 总览页日志默认显示最近 50 条
			},
			Appearance: defaultAppearance(),
			Security:   Security{Firewall: defaultPanelFirewall()},
			Restart:    defaultRestart(),
		},
		GlobalFirewall: defaultGlobalFirewall(),
		Credentials:    []Credential{},
		DDNS:           []DDNSRule{},
		WebServices:    []WebService{},
		Forwards:       []ForwardRule{},
		WOLDevices:     []WOLDevice{},
		CronTasks:      []CronTask{},
		Certs:          []Certificate{},
		ACMEAccounts:   []ACMEAccount{},

		Webhook: WebhookServer{
			Enabled:        false,
			Listen:         "0.0.0.0",
			Port:           DefaultWebhookPort,
			HTTPS:          WebhookHTTPS{Enabled: false},
			SourceRetainMB: DefaultSourceRetainMB,
		},
		WebhookReceivers: []WebhookReceiver{},
		NotifyTargets:    []NotifyTarget{},
		MessageTemplates: []MessageTemplate{},
	}
}

// defaultRestart 返回默认的定时重启设置：关闭。
//
// 各字段仍给出一组可用的初值（每周日 04:00），这样用户在界面上打开开关时看到的是
// 一个完整可保存的表单，而不是「周几没选、时刻是 00:00」这种得先补齐才能用的状态。
// 凌晨 4 点是按"这时候重启影响最小"选的，不是随手填的默认值。
func defaultRestart() RestartPolicy {
	return RestartPolicy{
		Enabled:   false,
		Mode:      RestartModeWeekly,
		Weekdays:  []int{0},
		EveryDays: 7,
		Hour:      4,
		Minute:    0,
	}
}

// defaultAppearance 返回默认外观（浅色、柔和毛玻璃卡片）。
//
// 这里是「网站默认外观」的出处：全新安装时写进配置文件，前端登录后取到的就是它。
// 前端 web/src/stores/appearanceTypes.ts 里有一份同样的值，供**还没拿到这份**的时候顶着用
// （外观接口要登录，没登录过的设备取不到）。两份必须一致，改这里要同步改那边 ——
// 曾经不一致过，表现是首次访问的设备颜色与默认的不一样、要登录后刷新一次才对。
func defaultAppearance() Appearance {
	return Appearance{
		ThemeMode: "light",
		Colors: AppearanceColors{
			Primary: "#4f7cff",
			Accent:  "#22c1a6",
			Success: "#22c55e",
			Warning: "#f59e0b",
			Danger:  "#ef4444",
		},
		Background: AppearanceBackground{
			Type:           "gradient",
			Value:          "linear-gradient(135deg,#e6efff 0%,#f3f0ff 100%)",
			Blur:           0,
			OverlayOpacity: 0.15,
			Fit:            "cover",
			Position:       "center",
		},
		Card: AppearanceCard{
			Opacity: 0.72,
			Blur:    14,
			Radius:  14,
			Shadow:  "md",
		},
		Font: AppearanceFont{
			Family: "system",
			Scale:  1.0,
			Weight: 400,
		},
		Layout: AppearanceLayout{
			Sidebar: "expanded",
			Density: "comfortable",
		},
	}
}

// migrate 将旧版本配置升级到当前版本。
//
// 版本相关的升级动作按「c.Version < N」分块，各块只做该版本引入的那一件事，
// 且必须幂等——因为版本号在最后统一提升，同一块可能在一次加载里对不同来源的配置反复执行
// （Load 与导入的 Replace 都会走这里）。
// 注意不要把不同版本的动作混在同一个块里：例如 v2 的「旧配置无启用字段，统一置为启用」
// 若跟着后来的版本号一起再跑一遍，就会把用户手动禁用的证书重新启用。
func migrate(c *Config) {
	if c.Version < 2 {
		// v2 升级：证书新增「启用/禁用」开关，旧配置无此字段，统一默认启用，
		// 避免升级后全部证书被误判为禁用。
		for i := range c.Certs {
			c.Certs[i].Enabled = true
		}
		// v2 升级：「总览显示日志」开关默认开启。
		c.Settings.Log.ShowOnHome = true
	}
	if c.Version < 3 {
		// v3 升级：Web 服务子项的 Basic 认证从「填了用户名即启用」改为独立开关。
		// 旧配置里凡填了用户名的一律置为启用，否则升级会静默摘掉这些站点的认证。
		for i := range c.WebServices {
			for j := range c.WebServices[i].Children {
				access := &c.WebServices[i].Children[j].Access
				if access.BasicAuthUser != "" {
					access.BasicAuth = true
				}
			}
		}
	}
	// v4 升级：静态站点新增 gzip 开关。它对静态托管是纯收益（只压可压缩类型），
	// 面板新建站点默认开启；但旧配置里没有这个字段，反序列化后会是 false，
	// 不补真就等于「升级后所有既有静态站点静默失去压缩」。
	// 真正赋值必须等 migrateWebServices 把旧「扁平」模型转成父项/子项之后（见下方子项遍历），
	// 否则 v3 之前的配置此刻还没有 Children 可改，故这里只记标记。
	staticGzipDefault := c.Version < 4
	// v5 只是引入消息路由模块（Webhook 接收 / 通知目标 / 模板），没有需要换算的旧数据：
	// 新增字段的零值本身就是正确的初始状态（模块关闭、列表为空），
	// 一切默认值与边界由下方无条件调用的 normalizeWebhook 负责，不需要版本块。
	// 版本号仍然提升，好让将来的 v6 迁移块有一个准确的分界点。
	//
	// v6 把消息路由的访问域名从 webhook.https.domain 上移到 webhook.domain
	// （端口 80 与 Web 服务共享时没有 HTTPS 也要靠域名分流）。同样不需要版本块：
	// normalizeWebhook 无条件把旧字段折上去并清空，手改配置和导入旧备份都能覆盖到。
	if c.Version < 7 {
		// v7 升级：消息路由模块设置新增「已创建」标记（webhook.created），
		// 未创建时那一页是空列表，接收器也无法启用（见 WebhookServer.Created）。
		//
		// 无条件置真，不去看端口/域名/备注是否填过：升级前那一行**一直**存在，
		// 按内容猜测会让"装好但还没配过消息路由"的用户在升级后突然发现那一行不见了，
		// 而这个标记本来只是想让「删除」有个可回到的状态。想让它消失，点删除即可。
		c.Webhook.Created = true
	}
	if c.Version < 8 {
		// v8 升级：入站原文留存的额度变成界面上可调的一个数（webhook.sourceRetainMb），
		// 而在这之前它是代码里写死的 2 MiB。
		//
		// 这一条**必须**有版本块，不能靠 normalizeWebhook 补默认值：0 在这个字段上
		// 是"不留存"这个有效选择，而不是"没填"。旧配置里根本没有这个键，
		// 反序列化后就是 0——若把 0 当成"用默认值"，用户就永远选不出"关掉"；
		// 若不补这一块，升级后所有人的原文留存会静默关闭，而界面上看不出发生了什么。
		c.Webhook.SourceRetainMB = DefaultSourceRetainMB
	}
	if c.Version < 9 {
		// v9 升级：会话新增「闲置超时」（auth.sessionIdleMinutes），旧配置里没有这个键。
		//
		// 和上面 v8 一样必须用版本块，不能靠下面的 clamp 补默认值：0 在这个字段上是
		// 「不启用」这个有效选择，而不是「没填」。若把 0 当成"用默认值"，用户就永远
		// 关不掉它；若这一块不写，升级后所有人的闲置超时会静默处于关闭状态，
		// 而设置页上只会显示一个 0，看不出发生过什么。
		c.Auth.SessionIdleMinutes = DefaultSessionIdleMinutes
	}
	if c.Version < 10 {
		// v10 升级：新增面板入站防护（settings.security.firewall）。
		//
		// 这一块把它显式置为**关闭**，而全新安装（Default）是**开启 + 只允许局域网**。
		// 两边不一致是有意的，也是这次改动里唯一一处刻意的偏离，理由：
		//
		// 从公网管理面板是一种正当且常见的部署（VPS 上装一台就是这样）。如果升级把
		// "只允许局域网"一并打开，这批用户会在重启后**立刻失去唯一的入口**，
		// 而失去的方式还特别难查——不是报错页，是连接直接被关掉，看起来就像服务没起来。
		// 一次版本升级不该有能力做这个决定。
		//
		// 反过来对全新安装启用默认值则没有这个问题：那台机器还没有人在用它，
		// 装完第一件事本来就是打开面板做初始化，此刻发现"外网进不来"是一条明确的信息，
		// 而不是一次失联。启动日志也会把放开的办法直接写出来（server.logFirewallState）。
		//
		// 其余字段仍写入默认值：开关关着的时候它们不影响任何行为，
		// 但用户进设置页打开这个开关时，看到的应该是一组合理的初值而不是一排 0。
		c.Settings.Security.Firewall = defaultPanelFirewall()
		c.Settings.Security.Firewall.Enabled = false
	}
	if c.Version < 11 {
		// v11 升级：新增服务防护（连接层）（globalFirewall），整段重置为默认值。
		//
		// 这里可以放心整段覆盖，理由是这个功能与 v10 的面板入站防护**同一批**加进来、
		// 还没有发布过任何带它的版本，因此不存在"用户已经配过一版"的情况。
		// 若将来要改它的默认值，就不能再这么写了——那时候必须只补缺失的键。
		//
		// 必须有这一块，不能只靠加载期的 normalizeGlobalFirewall 兜底：AutoBan 是布尔值，
		// 旧配置里没有这个键，反序列化后是 false，而 normalize 无法区分"没填"与"用户关了它"。
		// 不写这一块的结果是：全新安装拿到 AutoBan=true，升级上来的拿到 AutoBan=false，
		// 而界面上（在这次改动之前）根本没有这个开关，于是那批用户永远打不开自动封禁。
		//
		// 默认关闭这一点两边一致（见 defaultGlobalFirewall），所以升级不会给任何人
		// 突然带上一道会掐连接的防护——这与 v10 那一块刻意让"升级"与"全新安装"取值不同的
		// 情况正好相反，因为这次连全新安装都是关着的。
		c.GlobalFirewall = defaultGlobalFirewall()
	}
	if c.Version < CurrentVersion {
		c.Version = CurrentVersion
	}
	// 「有管理员账户 ⇒ 已初始化」是一条不变量，这里无条件补齐。
	//
	// 它护住的是 /api/init/setup 那道免鉴权入口：那个接口放不放行只看 Auth.Initialized
	// 一个布尔值。这个值为假而账户仍在时，面板会同时坏在两头——正确的账号密码登不进来
	//（handleLogin 直接回「尚未初始化」），而网络上任何人都能走一遍初始化向导注册新管理员、
	// 把原账户覆盖掉。先锁死自己，再对外敞开。
	//
	// 这个状态没有合法来源：handleInitSetup 三个字段一次写入，改账号不动这个标记。
	// 但外部来源的配置能把它带进来——手改过的 config.json，或一份缺 auth.initialized
	// 这个键的备份（DecryptBackup 反序列化到零值 Config，缺键即为假，而导入只校验了
	// 用户名与口令哈希非空，见 server.handleImportConfig）。
	//
	// 放在 migrate 里而不是导入处：从磁盘加载与选择性导入都要过这里，一处覆盖两个入口，
	// 将来新增的"外部配置入口"也不必记得再补一遍。
	if c.Auth.Username != "" && c.Auth.PasswordHash != "" {
		c.Auth.Initialized = true
	}
	// 证书添加方式从旧枚举(dns01/http01/import)迁移到新枚举(file/path/acme)。
	// HTTP-01 从未实现（签发时直接报错），现已彻底移除：所有 ACME 证书的验证方式
	// 统一规范为 dns01，避免配置里残留一个永远走不通的死值。
	for i := range c.Certs {
		switch c.Certs[i].Method {
		case "import":
			c.Certs[i].Method = "file"
		case "dns01", "http01":
			c.Certs[i].Method = "acme"
		}
		if c.Certs[i].Method == "acme" {
			c.Certs[i].ACMEChallenge = "dns01"
		}
	}
	// 「日志最大条数」是全程序日志量的总开关，旧配置里它可能不存在（反序列化后为 0），
	// 也可能是语义扩大前存下的越界值（旧下限是 1）。这里就地规范化成合法值
	//（≤0 → 默认 1000，其余夹进 [100,5000]），而不是只在启动时把 0 当默认值用——
	// 否则设置页会显示成「0 条」，用户一保存就把 0 原样存回去，看起来像是自己关掉了日志。
	c.Settings.Log.MaxEntries = logx.NormalizeLogEntries(c.Settings.Log.MaxEntries)
	// 总览页展示条数同理规范化，并且不得超过环里实际能有的条数（见 NormalizeLogHomeLimit）。
	c.Settings.Log.HomeLimit = NormalizeLogHomeLimit(c.Settings.Log.HomeLimit, c.Settings.Log.MaxEntries)
	// 面板监听地址固定 0.0.0.0（不再由 UI 编辑）。
	if c.Panel.Listen == "" {
		c.Panel.Listen = "0.0.0.0"
	}
	if c.Panel.HTTPS.Domain == "" {
		for _, host := range c.Panel.HTTPS.AllowedHosts {
			if host != "" {
				c.Panel.HTTPS.Domain = host
				break
			}
		}
	}
	if c.Panel.HTTPS.Domain == "" && c.Panel.HTTPS.Enabled {
		for _, certificate := range c.Certs {
			if certificate.ID != c.Panel.HTTPS.CertID {
				continue
			}
			for _, domain := range certificate.Domains {
				if domain != "" && !strings.Contains(domain, "*") {
					c.Panel.HTTPS.Domain = domain
					break
				}
			}
			break
		}
	}
	c.Panel.HTTPS.AllowedHosts = nil
	// Web 服务从旧「扁平」模型迁移到「父项(端口+族) / 子项」模型。
	migrateWebServices(c)
	for i := range c.WebServices {
		// 主动探测间隔默认 60 秒（用户未设置或非法值时回退默认，避免过短间隔打爆后端）。
		if c.WebServices[i].ProbeInterval <= 0 {
			c.WebServices[i].ProbeInterval = 60
		}
		for j := range c.WebServices[i].Children {
			ch := &c.WebServices[i].Children[j]
			// 仅允许 1.2 / 1.3；空值或低于 1.2 的旧配置（1.0/1.1）统一抬升到 1.2 下限。
			if ch.TLSMinVersion != "1.3" {
				ch.TLSMinVersion = "1.2"
			}
			// 启用 TLS 即强制开启 HTTPS 跳转（面板把该开关锁成开启状态，这里兜住手改配置
			// 与导入的旧备份）：子项既然已提供 HTTPS，就不该再放任明文访问同一端口。
			if ch.TLS {
				ch.RedirectHTTPS = true
			}
			// v4 的静态站点 gzip 默认值（标记在上方版本块里取，此处才有 Children 可改）。
			if staticGzipDefault && ch.Type == "static" {
				ch.Static.Gzip = true
			}
		}
	}
	// DDNS 目标从旧「单一主机记录」迁移到「多主机记录 + 根域名开关」。
	migrateDDNS(c)
	// 定时唤醒：夹住越界数值，并把旧「时间段内均匀 N 次」换算为新的「按间隔发送」。
	migrateWOL(c)
	// 裁剪历史配置里已经膨胀的运行状态文本（见 MaxStatusMessageLen）。
	// 写入路径现已统一裁剪，但旧 config.json 中可能已存着整页 HTML 错误响应，
	// 那部分文本会在每次 Get() 深拷贝时被重新分配一遍，故在加载时一并清理。
	for i := range c.DDNS {
		c.DDNS[i].LastStatus = TruncateStatus(c.DDNS[i].LastStatus)
	}
	for i := range c.CronTasks {
		c.CronTasks[i].LastStatus = TruncateStatus(c.CronTasks[i].LastStatus)
	}
	for i := range c.Certs {
		c.Certs[i].IssueStatus.Message = TruncateStatus(c.Certs[i].IssueStatus.Message)
		c.Certs[i].RenewStatus.Message = TruncateStatus(c.Certs[i].RenewStatus.Message)
	}
	// 日志级别白名单：手改 config.json 或导入外部备份都可能带进认不出的级别名，
	// 而 logx 会把认不出的名字当成 info，等于静默只留 info 一档（见 logx.NormalizeLevels）。
	// 在加载期统一过滤，落盘后配置与实际行为一致。
	c.Settings.Log.Levels = logx.NormalizeLevels(c.Settings.Log.Levels)
	// 登录锁定参数区间兜底，与设置接口保持同一组边界（0 表示不限制）。
	c.Auth.LoginMaxFails = clampInt(c.Auth.LoginMaxFails, 0, 1000)
	c.Auth.LoginLockMinutes = clampInt(c.Auth.LoginLockMinutes, 0, 43200)
	// 闲置超时同样夹进设置接口的那组边界：手改 config.json、导入外部备份都可能
	// 带进 -1 或天文数字。0 是「不启用」这个有效选择，所以下限是 0 而不是 1。
	c.Auth.SessionIdleMinutes = clampInt(c.Auth.SessionIdleMinutes, 0, 43200)
	// 消息路由：补默认值、夹边界、整理路径与条件（见 webhook.go 顶部说明）。
	normalizeWebhook(c)
	// 定时重启：统一模式取值、夹住时刻与间隔、整理星期与日期（见 restart.go 顶部说明）。
	// 无条件执行而不放进版本块：旧配置里没有这一段（反序列化后是零值，mode 为空、
	// 时刻 00:00），手改的 config.json 与外来的备份同样可能带进越界值。
	if restartUnset(c.Settings.Restart) {
		c.Settings.Restart = defaultRestart()
	}
	normalizeRestart(&c.Settings.Restart)
	// 面板入站防护：统一模式取值、夹住数值、整理名单（见 firewall.go 顶部说明）。
	// 无条件执行的理由同上，但这一处更要紧——它是访问控制：
	// 一个手改成 "Lan" 的 mode、一个负数限速、或一份两万条的名单，
	// 都不该让「谁能进面板」这件事变成未定义行为。
	normalizePanelFirewall(&c.Settings.Security.Firewall)
	// 服务防护（连接层）：统一档位取值、夹住数值、整理名单（见 firewall_global.go 顶部说明）。
	normalizeGlobalFirewall(&c.GlobalFirewall)
}

// clampInt 把 v 夹到 [lo, hi] 区间内。
func clampInt(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

// migrateDDNS 将旧版 DDNSTarget.Subdomain（单一主机记录）迁移为新版
// Subdomains（多主机记录）+ AllowRoot（是否允许更新根域名）。
// 迁移规则：
//   - 旧值为空或 "@" → 视为根域名，置 AllowRoot=true，Subdomains 留空；
//   - 其它非空值 → 作为唯一主机记录放入 Subdomains，AllowRoot 保持 false。
//
// 已是新模型（Subdomains 非空或 AllowRoot 为真）或旧值为空的条目按规则处理后清空旧字段。
func migrateDDNS(c *Config) {
	for i := range c.DDNS {
		for j := range c.DDNS[i].Targets {
			t := &c.DDNS[i].Targets[j]
			// 已迁移到新模型则仅清理旧字段。
			if len(t.Subdomains) > 0 || t.AllowRoot {
				t.LegacySubdomain = ""
				continue
			}
			sub := t.LegacySubdomain
			if sub == "" || sub == "@" {
				// 空主机记录旧语义即根域名；为兼容旧行为置 AllowRoot。
				if t.LegacySubdomain == "@" {
					t.AllowRoot = true
				}
			} else {
				t.Subdomains = []string{sub}
			}
			t.LegacySubdomain = ""
		}
	}
}

// migrateWOL 修正历史 / 外部写入的定时唤醒配置。
//
// 一、越界的「一秒内发包次数」直接夹到上限（见 MaxWOLWakeCount），使配置落盘后与调度器
// 实际行为一致，避免「界面显示 100000、实际只发 100 次」的割裂。
//
// 二、「时间范围」模式的语义改版迁移。旧语义是「在 [Start, End] 内均匀发送 Count 次」，
// 新语义是「从 Start 到 End 每 IntervalSec 秒发一个包」——Count 在新语义下不再参与计算。
// 若不迁移，一条旧的「08:00–18:00 ×5」会按遗留的 IntervalSec（旧前端默认 5）被解读成
// 「每 5 秒一个包」，一天七千多个包，与用户当初的设置差三个数量级。
//
// 换算办法：旧的 Count 次均匀铺在跨度上，相邻两次相隔 (End-Start)/(Count-1) 秒，
// 取这个值作为新的间隔，换算后的触发时刻与旧行为逐拍重合。换算完把 Count 归零——
// 归零本身就是「已迁移」的标记（新版保存路径也会为 range 模式归零 Count），
// 故本函数可重复执行（幂等）。
func migrateWOL(c *Config) {
	for i := range c.WOLDevices {
		s := &c.WOLDevices[i].Schedule
		if s.Count > MaxWOLWakeCount {
			s.Count = MaxWOLWakeCount
		}
		if s.IntervalSec < 0 {
			s.IntervalSec = 0
		}
		if s.Mode == "range" && s.Count > 0 {
			s.IntervalSec = legacyRangeIntervalSec(s.Start, s.End, s.Count)
			s.Count = 0
		}
	}
}

// legacyRangeIntervalSec 把旧「时间段内均匀 Count 次」换算成等价的发送间隔（秒）。
//
// Count<=1 的旧配置表示「只在 Start 发一次」，此时取「跨度 + 1 秒」，使 [Start, End] 内
// 只命中 Start 这一拍：数字看着突兀（如 36001），但行为与旧配置逐拍一致，
// 且用户填的 End 不会被悄悄改写。
// 时间字段非法时回退 1 秒——调度器对非法时间本就当天不发送，间隔取什么都不影响。
func legacyRangeIntervalSec(start, end string, count int) int {
	ss, ok1 := clockSecondsOfDay(start)
	es, ok2 := clockSecondsOfDay(end)
	if !ok1 || !ok2 {
		return 1
	}
	span := es - ss
	if span <= 0 {
		return 1 // 结束不晚于开始：旧行为只发一次，新语义同样只会命中 Start 这一拍
	}
	if count <= 1 {
		return span + 1
	}
	step := span / (count - 1)
	if step < 1 {
		step = 1
	}
	return step
}

// clockSecondsOfDay 把 "HH:MM" 解析为当日零点起的秒数。
func clockSecondsOfDay(s string) (int, bool) {
	parts := strings.SplitN(strings.TrimSpace(s), ":", 2)
	if len(parts) != 2 {
		return 0, false
	}
	h, err1 := strconv.Atoi(strings.TrimSpace(parts[0]))
	m, err2 := strconv.Atoi(strings.TrimSpace(parts[1]))
	if err1 != nil || err2 != nil || h < 0 || h > 23 || m < 0 || m > 59 {
		return 0, false
	}
	return h*3600 + m*60, true
}

// migrateWebServices 将旧版扁平 WebService（listens/domains/type/upstreams… 在顶层）
// 迁移为新版父/子模型：一个父项 = 一个 (端口, 地址族) 监听，其下挂一个由旧字段构成的子项。
// 旧配置若一个服务监听多个端口，则拆成多个父项（各带同一子项副本）。
// 已是新模型（含 Children 或 Port>0）或无旧字段的条目原样保留，仅清理残留的旧字段。
func migrateWebServices(c *Config) {
	if len(c.WebServices) == 0 {
		return
	}
	var extra []WebService
	for i := range c.WebServices {
		ws := &c.WebServices[i]
		// 判定是否为需要迁移的旧条目：尚无子项、端口未设置，但存在旧字段痕迹。
		hasLegacy := len(ws.LegacyListens) > 0 || ws.LegacyType != "" ||
			len(ws.LegacyDomains) > 0 || len(ws.LegacyUpstreams) > 0
		if len(ws.Children) > 0 || ws.Port > 0 || !hasLegacy {
			clearLegacy(ws)
			continue
		}

		child := legacyChild(ws)

		// 收集旧监听涉及的端口及其 TLS 标志（同端口多监听取 TLS 的或）。
		type portInfo struct {
			port int
			tls  bool
		}
		var ports []portInfo
		seen := map[int]int{} // port -> index in ports
		for _, ln := range ws.LegacyListens {
			p := ln.Port
			if p <= 0 {
				continue
			}
			if idx, ok := seen[p]; ok {
				if ln.TLS {
					ports[idx].tls = true
				}
				continue
			}
			seen[p] = len(ports)
			ports = append(ports, portInfo{port: p, tls: ln.TLS})
		}
		if len(ports) == 0 {
			ports = append(ports, portInfo{port: 80, tls: false})
		}

		// 第一个端口沿用当前父项；其余端口另建父项（复制子项）。
		for k, pi := range ports {
			ch := child
			ch.TLS = pi.tls
			if k == 0 {
				ch.ID = ws.ID + "-c"
				ws.Port = pi.port
				ws.IPFamily = "both"
				ws.Children = []WebChild{ch}
				clearLegacy(ws)
			} else {
				ch.ID = randomHex(6)
				extra = append(extra, WebService{
					ID:       randomHex(6),
					Name:     ws.Name,
					Enabled:  ws.Enabled,
					Port:     pi.port,
					IPFamily: "both",
					Children: []WebChild{ch},
				})
			}
		}
	}
	if len(extra) > 0 {
		c.WebServices = append(c.WebServices, extra...)
	}
}

// legacyChild 由旧扁平字段构造一个子项（不含 TLS，由调用方按端口设置）。
func legacyChild(ws *WebService) WebChild {
	ch := WebChild{
		Enabled:       true,
		Domains:       ws.LegacyDomains,
		Type:          ws.LegacyType,
		Upstreams:     ws.LegacyUpstreams,
		LB:            ws.LegacyLB,
		Headers:       ws.LegacyHeaders,
		TLSMinVersion: ws.LegacyTLSMinVersion,
		RedirectHTTPS: ws.LegacyRedirectHTTPS,
		HSTS:          ws.LegacyHSTS,
	}
	if ch.Type == "" {
		ch.Type = "proxy"
	}
	if ws.LegacyStatic != nil {
		ch.Static = *ws.LegacyStatic
	}
	if ws.LegacyRedirect != nil {
		ch.Redirect = *ws.LegacyRedirect
	}
	if ws.LegacyProxy != nil {
		ch.Proxy = *ws.LegacyProxy
	}
	if ws.LegacyAccess != nil {
		ch.Access = *ws.LegacyAccess
	}
	return ch
}

// clearLegacy 清空迁移用的旧字段，避免其再次落盘。
func clearLegacy(ws *WebService) {
	ws.LegacyListens = nil
	ws.LegacyDomains = nil
	ws.LegacyType = ""
	ws.LegacyUpstreams = nil
	ws.LegacyLB = ""
	ws.LegacyStatic = nil
	ws.LegacyRedirect = nil
	ws.LegacyProxy = nil
	ws.LegacyHeaders = nil
	ws.LegacyAccess = nil
	ws.LegacyRedirectHTTPS = false
	ws.LegacyHSTS = false
	ws.LegacyTLSMinVersion = ""
}

// clone 通过 JSON 往返做一次深拷贝。
//
// 返回 error 而不是像早先那样用 `_` 把 json 的错误丢掉：Update 紧接着就会把克隆结果
// 落盘并换进内存，一旦序列化失败而这里静默返回一个空 Config，那一次「保存设置」
// 就等于**清空全部配置**，而且全程不留任何日志。
//
// 当前 Config 的字段类型（string / int / bool / map[string]string / 三个 float64）
// 保证 Marshal 不会失败，因此这条错误路径今天不可达。但挡住它的是字段类型集合，
// 不是代码里的判断：将来任何人给 Config 加一个 any / chan 字段，它立刻变成活的。
func (c *Config) clone() (*Config, error) {
	data, err := json.Marshal(c)
	if err != nil {
		return nil, fmt.Errorf("序列化配置失败: %w", err)
	}
	out := &Config{}
	if err := json.Unmarshal(data, out); err != nil {
		return nil, fmt.Errorf("解析配置副本失败: %w", err)
	}
	return out, nil
}

// randomHex 生成 n 字节的随机十六进制字符串。
//
// crypto/rand.Read 自 Go 1.24 起被文档保证**永不返回错误**（熵源不可用时运行时直接
// 终止进程），所以下面这条分支不可达。仍然写它、并且写成 panic，是因为旧实现在这里
// 返回的是空串：三个调用点之一是 Auth.JWTSecret，而 auth 侧对空密钥没有任何拒绝逻辑，
// 于是「取不到随机数」会静默降级成「任何人都能离线伪造会话令牌」——方向完全反了。
//
// 不改成返回 (string, error) 是刻意的取舍：调用点在 Default() 与 migrate 的规范化里，
// 让它们全部改签名会给十几个调用方各加一段永远不会执行的错误处理。一条不可达的
// panic 分支同样保住了「失败就停下」的方向，代价为零。空密钥的兜底另有一道，
// 在 auth.IssueToken / auth.ParseToken 的前置校验里。
func randomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("config: 无法获取随机数: " + err.Error())
	}
	return hex.EncodeToString(b)
}
