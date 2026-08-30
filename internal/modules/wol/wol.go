package wol

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	"mantou/internal/config"
	"mantou/internal/logx"
	"mantou/internal/module"
	"mantou/internal/netguard"
)

// autoBroadcast 「自动」模式的哨兵值。留空与它等价：都表示逐网卡定向广播 + 补发一次全局广播。
// 它同时也是全局广播地址本身（受限广播，RFC 919），因此在发送路径上原样使用。
const autoBroadcast = "255.255.255.255"

// ValidBroadcast 校验网络唤醒的目标地址是否可用。
//
// 允许的范围恰好是 netguard.IsPrivateOrReserved 判为「内网 / 保留」的那一部分——
// 也就是用户可配置的出站 HTTP 请求**不允许**访问的那一部分，两者互为补集。
// 这不是巧合：网络唤醒的语义本就限定在本机所在的局域网内（魔术包是二层广播，
// 跨路由不转发），而「往任意公网地址发 UDP」是另一件完全不同的事。
//
// 不做这层限制的后果：本模块会变成一个可用的任意 UDP 发包器。目标 IP 与端口（1-65535）
// 都由配置决定，102 字节负载中的 96 字节由 MAC 字段决定，而三条唤醒入口
// （面板按钮 / 定时调度 / 计划任务）都不经过 netguard——于是面板上那条
// 「禁止访问内网地址」的出站防护被整体绕开，方向还正好相反：
// 定时唤醒可以按每秒一个包的节奏持续向某个公网地址发送，一台设备一条协程。
//
// 代价说明：把广播地址填成自己家的公网 IP 来做「跨公网唤醒」的用法会被拒。
// 这个用法本来也走不通——校验要求是 IP 字面量，DDNS 域名早就通不过，
// 而家宽公网 IP 是会变的；正确做法是把 mantou 部署在目标设备所在局域网内。
func ValidBroadcast(broadcast string) error {
	b := strings.TrimSpace(broadcast)
	if b == "" || b == autoBroadcast {
		return nil
	}
	ip := net.ParseIP(b)
	if ip == nil {
		return fmt.Errorf("广播地址需为合法 IP，如 192.168.1.255；留空表示自动逐网卡广播")
	}
	if !netguard.IsPrivateOrReserved(ip) {
		return fmt.Errorf(
			"广播地址 %s 是公网地址，不能作为唤醒目标：魔术包是二层广播，跨路由不转发。"+
				"请填目标设备所在网段的广播地址（如 192.168.1.255）或该设备的内网 IP，"+
				"留空则自动逐网卡广播", b)
	}
	return nil
}

// StatsWriter 记设备的唤醒统计：最近一次是什么时候、结果是什么、累计几次。
// 由 runstats.Store 实现，数字只在内存里、重启归零（原因见 runstats 包说明）。
//
// 原先这里声明的是 config 的运行态回写方法，唤醒记录跟着设备条目一起存。问题是
// 「时间范围」模式最快 1 秒一拍、每台设备各一条协程，而每次回写都要换一份配置、
// 涨一次 rev、等一次落盘——全局只有一把配置写锁，设备越多、拍得越快，面板越卡。
// 这三个数没有任何逻辑会读，只有列表页在看，没有理由为它们付这个代价。
type StatsWriter interface {
	Woke(id string, at int64, result string)
}

// Module 实现网络唤醒（Wake-on-LAN）。
// 手动唤醒是无状态操作；此外模块按各设备的 Schedule 运行定时唤醒调度器。
type Module struct {
	mu      sync.RWMutex
	devices []config.WOLDevice
	log     *logx.Logger
	stats   StatsWriter

	// lifeMu 串行化整个生命周期操作（Reload / Close），与 mu 分开持有。
	//
	// 为什么不能只靠 mu：Reload 与 Close 都是「取出旧 cancel → 调用它 → 等旧代退出 → 起新代」
	// 的多步序列，而 mu 只覆盖其中读写字段的那一瞬间。两者交错会同时产生两种故障：
	//   1. Close 在 Reload 把 m.cancel 置 nil 之后、写回新 cancel 之前读到 nil，于是什么都没取消，
	//      而 Reload 随后起的那一代调度协程再也没有人能停下它——关闭之后仍在发包、仍在写运行态。
	//   2. Reload 的 m.wg.Add 与 Close 的 m.wg.Wait 并发时，若 Wait 已观测到计数归零而尚未返回，
	//      Add 会触发运行时硬 panic「sync: WaitGroup is reused before previous Wait has returned」。
	//      该 panic 发生在 Close/Reload 自身的调用栈上（不是 gin 处理器），Recovery 拦不到，
	//      而 CloseAll 的调用点之一是自更新换进程——崩在「旧监听已释放、新进程尚未起」的空档里。
	// 上层 module.Manager 也不提供这层互斥：ReloadAll 只持 reloadMu，CloseAll 只持自己的 mu，
	// 两者之间没有任何约束，所以互斥必须由模块自己保证。
	//
	// lifeMu 与 mu 分开的原因：Reload/Close 全程持 lifeMu（含 m.wg.Wait()），而 Status() 只取
	// mu.RLock；若合用一把锁，总览页轮询会被重载时的 Wait 阻塞。
	lifeMu sync.Mutex
	closed bool // Close 之后置位：此后 Reload 只更新设备清单，不再起新的调度代

	cancel context.CancelFunc // 当前调度代的取消函数
	sig    string             // 当前调度代所依据的设备签名，见 schedulingSig；与 cancel 同生共死
	wg     sync.WaitGroup     // 当前调度代的协程
}

// schedulingSig 返回设备清单中「影响调度」的那一部分的签名，用于判断能否保留当前调度代。
//
// 为什么需要它：Reload 由**任意**配置保存触发（OnConfigChanged → ReloadAll，
// 见 app.go:106 与 api_resources.go:907），改一条 DDNS 记录、加一条端口转发、
// 换一次外观主题都会走到这里。无条件重建的代价：
//   - 一拍可能被打断。取消发生在 fireScheduled 连发途中时，固定时间模式那一秒内该发的
//     Count 个包只发出一部分；更糟的是取消恰好发生在固定时间模式的那一拍上时，
//     新一代重新推导得到的 firstTickAfter 已越过 start==end，当天不再触发——
//     一次无关的配置保存，让这台设备当天整个漏发。
//   - 每台设备一次协程取消 + 汇合 + 重建。Reload 全程持 lifeMu 并 m.wg.Wait()，
//     而 fireScheduled 里的发包与运行态回写都不可取消，于是这次等待要一直等到
//     当前这一拍走完；ReloadAll 是串行的，这段等待会连带推迟其后所有模块的重载。
//   - 当日汇总日志丢失（runPlanDay 被取消时直接返回，不记汇总），
//     且新一代的 ticks 从 1 重新开始，「首拍」日志会重复出现。
//
// 签名覆盖的范围 = 调度协程按值捕获并**实际读取**的字段：ID（回写匹配）、
// Enabled 与 Schedule.Enabled（是否需要这条协程）、Name（日志标签）、
// MAC/Broadcast/Interface/Port（发送目标）、以及整个 Schedule（时刻推导）。
// 覆盖不足的方向是危险的：漏掉一个字段就意味着用户改了它却不生效。
//
// 签名不含 Note（协程从不读它）。唤醒记录（最近一次 / 结果 / 累计次数）也不在里面，
// 而且现在连字段都不在配置上了——它们存在内存的统计库里（见 internal/runstats）。
// 这一点比省一次落盘更要紧：那些数由调度协程每拍回写，而 ReloadAll 拿到的正是含新值的
// 当前配置，若它们计入签名，「正在定时唤醒的设备」每次比较都必然不同，
// 这个优化对最需要它的场景恰好完全失效。
//
// 顺序敏感：调整设备顺序会被判为变化。CRUD 是追加与按 ID 增删改，正常不会产生纯重排，
// 真出现了也只是多重建一次，不会错。
func schedulingSig(devices []config.WOLDevice) string {
	var b strings.Builder
	b.Grow(len(devices) * 96)
	// putStr 带长度前缀，让整个签名对字段内容单射：Name / MAC / Mode 等都由用户填写，
	// 若用固定分隔符拼接，「a|b」与「a」+「|b」会撞成同一个签名——
	// 那意味着某些改动被判为「未变」而不生效。
	putStr := func(s string) {
		b.WriteString(strconv.Itoa(len(s)))
		b.WriteByte(':')
		b.WriteString(s)
	}
	putBool := func(v bool) {
		if v {
			b.WriteByte('1')
		} else {
			b.WriteByte('0')
		}
	}
	for i := range devices {
		d := &devices[i]
		s := &d.Schedule
		putStr(d.ID)
		putStr(d.Name)
		putStr(d.MAC)
		putStr(d.Broadcast)
		putStr(d.Interface)
		putStr(strconv.Itoa(d.Port))
		putBool(d.Enabled)
		putBool(s.Enabled)
		putBool(s.CalendarEnabled)
		putStr(s.Mode)
		putStr(s.StartDate)
		putStr(s.EndDate)
		putStr(s.Time)
		putStr(s.Start)
		putStr(s.End)
		putStr(strconv.Itoa(s.Count))
		putStr(strconv.Itoa(s.IntervalSec))
	}
	return b.String()
}

// New 创建 WOL 模块。
func New(log *logx.Logger, stats StatsWriter) *Module {
	return &Module{log: log, stats: stats}
}

// Name 实现 module.Module。
func (m *Module) Name() string { return "wol" }

// Reload 保存最新设备清单，并在调度相关字段发生变化时重建定时唤醒调度器。
func (m *Module) Reload(cfg *config.Config) error {
	m.lifeMu.Lock()
	defer m.lifeMu.Unlock()

	sig := schedulingSig(cfg.WOLDevices)

	m.mu.Lock()
	m.devices = append([]config.WOLDevice(nil), cfg.WOLDevices...)
	closed := m.closed
	// 调度相关字段一字未变：保留当前这一代协程，直接返回（原因见 schedulingSig）。
	// 设备清单已经更新完，Status() 与下一次比较都用新值——被保留的只是协程，不是数据。
	//
	// closed 之后 m.cancel 恒为 nil（Close 置 nil，且关闭后的 Reload 不再赋值），
	// 因此 m.cancel != nil 已隐含「尚未关闭」；这里仍显式判 closed，
	// 免得将来改动 Close 时这条捷径悄悄变成「关闭后跳过一切处理」。
	if !closed && m.cancel != nil && sig == m.sig {
		m.mu.Unlock()
		return nil
	}
	oldCancel := m.cancel
	m.cancel = nil
	m.sig = ""
	m.mu.Unlock()

	// 停止旧调度代。
	if oldCancel != nil {
		oldCancel()
	}
	m.wg.Wait()
	// 已关闭：设备清单照常更新（Status 仍需如实反映配置），但不再起新的调度代，
	// 否则这一代协程的 cancel 无人持有，会一直发包到进程结束。
	if closed {
		return nil
	}

	// 启动新调度代。
	ctx, cancel := context.WithCancel(context.Background())
	m.mu.Lock()
	m.cancel = cancel
	m.sig = sig
	m.mu.Unlock()

	for _, d := range cfg.WOLDevices {
		if d.Enabled && d.Schedule.Enabled {
			m.wg.Add(1)
			go m.runSchedule(ctx, d)
		}
	}
	return nil
}

// Close 停止调度并释放。可重复调用；返回后保证不再有本模块的调度协程在发包。
func (m *Module) Close() error {
	m.lifeMu.Lock()
	defer m.lifeMu.Unlock()

	m.mu.Lock()
	m.closed = true
	c := m.cancel
	m.cancel = nil
	m.sig = "" // 与 cancel 同生共死，避免残留签名让将来的 Reload 误判「未变」
	m.mu.Unlock()
	if c != nil {
		c()
	}
	m.wg.Wait()
	return nil
}

// Status 实现 module.StatusReporter。
//
// Active 的口径是「真的有一条调度协程在跑的设备数」，判据与 Reload 里起协程的条件
// 逐字一致（Enabled && Schedule.Enabled）；Total 是配置里的设备总数。
//
// 总览页把这两个数展示成「活跃 A / 总数 T」。把 A 直接写成设备总数，这一栏就恒等于
// 「全部活跃」——于是它想回答的那个问题（有几台设备的定时唤醒真的在跑）永远得不到答案：
// 关掉某台设备的开关、或关掉它的定时唤醒，面板上一点变化都没有，而这恰恰是
// 「定时唤醒怎么没生效」排查时第一眼要看的地方。
func (m *Module) Status() module.Status {
	m.mu.RLock()
	defer m.mu.RUnlock()
	active := 0
	// 已关闭、以及 Reload 换代的空档里（旧代已取消、新代未启动），一条协程都没有，如实报 0。
	if !m.closed && m.cancel != nil {
		for i := range m.devices {
			if m.devices[i].Enabled && m.devices[i].Schedule.Enabled {
				active++
			}
		}
	}
	return module.Status{
		Name:    "wol",
		Total:   len(m.devices),
		Active:  active,
		Healthy: true,
	}
}

// Wake 向指定 MAC 发送魔术包。port 为 0 时使用 9。
//
// broadcast 的取值语义：
//   - 显式指定（如 192.168.1.255 或某台设备的单播地址）：只向该地址发送一次，行为可预期。
//   - 留空或 255.255.255.255：视为「自动」，枚举本机网卡并按 selectTargets 的规则筛选，
//     对每张选中的网卡绑定其源地址后各发两个包：一个发往该网卡的定向广播地址，
//     一个发往全局广播地址 255.255.255.255（部分设备/网络栈只响应后者）。
//     这样可解决多网卡主机上「魔术包只从默认路由网卡发出、到不了目标设备所在二层网段」
//     的问题（魔术包幂等，重复发送无副作用）。网卡枚举结果带 30 秒缓存，
//     因此网络拓扑变化最多迟 30 秒被察觉（见 targetCacheTTL）。
//
// iface 为网卡名，非空表示只从这张网卡发出（见 selectTargets）。
//
// 全局广播刻意**绑定源地址**逐网卡各发一次，而不是不绑定地发一次让内核选路：
// 不绑定时内核按默认路由决定出口，而默认路由通常就是公网网卡——那正是
// selectTargets 要排除的那一张，一次不绑定的发送就把前面的筛选全部作废。
// 代价是包数从「网卡数 + 1」变成「网卡数 × 2」，绝大多数主机上是 2 个包。
//
// 注意：容器若使用默认的 bridge 网络，容器内只能看到 docker0 网段，任何广播都不会到达
// 宿主机 LAN，网络唤醒必然失败；此时需以 --network host 运行（或用 macvlan 接入宿主网卡）。
func Wake(mac, broadcast string, port int, iface string) error {
	hw, err := parseMAC(mac)
	if err != nil {
		return err
	}
	// 在发送路径上（而不是只在 API 校验里）再拦一次目标地址：config.json 可以被手工编辑、
	// 也可以整份导入，而这里是三条唤醒入口（面板按钮 / 定时调度 / 计划任务）唯一的汇合点。
	if err := ValidBroadcast(broadcast); err != nil {
		return err
	}
	if port == 0 {
		port = 9
	}
	packet := buildMagicPacket(hw)

	if target := strings.TrimSpace(broadcast); target != "" && target != autoBroadcast {
		// 目标是具体地址：由内核按目的地选路即可。但用户若同时指定了网卡，
		// 仍要绑定到那张网卡的源地址，否则「指定网卡」在这条路径上形同虚设。
		src, err := srcForIface(iface)
		if err != nil {
			return err
		}
		return sendPacket(packet, src, target, port)
	}

	targets, err := autoTargets(iface)
	if err != nil {
		return err
	}

	var sent int
	var firstErr error
	for _, t := range targets {
		// 定向广播 + 全局广播，两者都绑定该网卡的源地址。
		for _, dst := range [2]string{t.broadcast, autoBroadcast} {
			if err := sendPacket(packet, t.src, dst, port); err != nil {
				if firstErr == nil {
					firstErr = err
				}
				continue
			}
			sent++
		}
	}
	if sent == 0 {
		// 一个包也没发出去，缓存里的源地址很可能已经失效（网卡被拔掉、IP 变了、
		// 虚拟网卡被销毁——此时 DialUDP 会报「无法指定被请求的地址」）。
		// 作废缓存，让下一次尝试立刻重新枚举，而不是把这个错误状态维持满一个 TTL。
		invalidateTargetCache()
		if firstErr == nil {
			firstErr = errors.New("未找到可用于广播的网卡")
		}
		return firstErr
	}
	return nil
}

// WakeDevice 按设备配置发送魔术包。三条唤醒入口都走这里，
// 免得将来给 WOLDevice 加了影响发送的字段却漏掉某一条入口。
func WakeDevice(d config.WOLDevice) error {
	return Wake(d.MAC, d.Broadcast, d.Port, d.Interface)
}

// autoTargets 返回自动模式下本次要发往的网卡集合。
//
// 筛完为空时会先作废缓存重试一次：网卡列表带 30 秒缓存，刚插上网线 / 刚拿到 DHCP 地址
// 的那半分钟内缓存里可能确实没有可用项，直接报错会让用户以为配置错了。
func autoTargets(iface string) ([]wakeTarget, error) {
	all := cachedBroadcastTargets()
	sel := selectTargets(all, iface)
	if len(sel) == 0 {
		invalidateTargetCache()
		all = cachedBroadcastTargets()
		sel = selectTargets(all, iface)
	}
	if len(sel) > 0 {
		return sel, nil
	}
	return nil, noUsableTargetError(all, iface)
}

// noUsableTargetError 组装「没有可用网卡」的报错。
//
// 单独成函数是为了让文案本身可被确定性地测到：autoTargets 在筛空后必定会重新枚举
// 一次真实网卡（刚插网线的场景需要它），于是在一台有可用网卡的机器上永远走不到这里。
// 而这段文案正是本项修复交付给用户的东西——排除了什么、为什么、以及怎么办。
func noUsableTargetError(all []wakeTarget, iface string) error {
	if name := strings.TrimSpace(iface); name != "" {
		return fmt.Errorf("网卡 %s 不存在、未启用或没有 IPv4 广播地址；"+
			"可在设备设置里改回「自动」，或换一张网卡", name)
	}
	if len(all) == 0 {
		return errors.New("未找到可用于广播的网卡")
	}
	// 有网卡但全被筛掉：说明本机只有虚拟网卡和/或公网网卡。
	// 报错里逐张列出来，否则用户面对「没有可用网卡」而 ip a 明明有一堆，无从下手。
	return fmt.Errorf("未找到可用于唤醒的内网网卡（已排除虚拟网卡与公网网卡）：%s。"+
		"魔术包是二层广播，往这些网卡发既唤不醒设备、又会把目标 MAC 泄露给容器或同机房邻居；"+
		"确实需要用其中某一张，请在设备设置里显式指定网卡", describeTargets(all))
}

// srcForIface 返回指定网卡的源地址；iface 为空时返回 nil（交由内核选路）。
func srcForIface(iface string) (*net.UDPAddr, error) {
	name := strings.TrimSpace(iface)
	if name == "" {
		return nil, nil
	}
	sel := selectTargets(cachedBroadcastTargets(), name)
	if len(sel) == 0 {
		invalidateTargetCache()
		sel = selectTargets(cachedBroadcastTargets(), name)
	}
	if len(sel) == 0 {
		return nil, fmt.Errorf("网卡 %s 不存在、未启用或没有 IPv4 地址", name)
	}
	return sel[0].src, nil
}

// describeTargets 把网卡列表拼成「名字(地址,标记)」的可读串，用于错误信息。
func describeTargets(all []wakeTarget) string {
	var b strings.Builder
	for i, t := range all {
		if i > 0 {
			b.WriteString("、")
		}
		b.WriteString(t.iface)
		b.WriteString("(")
		if t.src != nil {
			b.WriteString(t.src.IP.String())
		}
		if t.virtual {
			b.WriteString(" 虚拟网卡")
		}
		if !t.private {
			b.WriteString(" 公网")
		}
		b.WriteString(")")
	}
	return b.String()
}

// InterfaceInfo 供界面展示的候选网卡。
type InterfaceInfo struct {
	Name      string `json:"name"`
	IP        string `json:"ip"`
	Broadcast string `json:"broadcast"`
	Virtual   bool   `json:"virtual"` // 虚拟网卡（容器网桥 / 虚拟机 / 隧道）
	Public    bool   `json:"public"`  // 公网地址
	Auto      bool   `json:"auto"`    // 「自动」模式下会实际用到这一张
}

// Interfaces 列出候选网卡及其分类，供设备设置里的网卡下拉框使用。
//
// 报告里点明的那句话是这个接口存在的理由：把「自动模式实际会用到哪几张网卡」
// 摆在界面上，比任何文档都有效——用户看得见「会从这 2 张发出」，
// 才可能发现「怎么还会从 docker0 发出」。
func Interfaces() []InterfaceInfo {
	all := cachedBroadcastTargets()
	auto := selectTargets(all, "")
	autoSet := make(map[string]bool, len(auto))
	for _, t := range auto {
		autoSet[t.iface+"/"+t.broadcast] = true
	}
	out := make([]InterfaceInfo, 0, len(all))
	for _, t := range all {
		ip := ""
		if t.src != nil {
			ip = t.src.IP.String()
		}
		out = append(out, InterfaceInfo{
			Name:      t.iface,
			IP:        ip,
			Broadcast: t.broadcast,
			Virtual:   t.virtual,
			Public:    !t.private,
			Auto:      autoSet[t.iface+"/"+t.broadcast],
		})
	}
	return out
}

// wakeTarget 一个待发送目标：src 为绑定的本地源地址（nil 表示交由内核选路），
// broadcast 为目标广播地址。
type wakeTarget struct {
	iface     string       // 网卡名，供筛选、日志与界面展示
	src       *net.UDPAddr // 绑定的本地源地址
	broadcast string       // 该网卡所在网段的定向广播地址
	virtual   bool         // 命中虚拟网卡前缀，见 isVirtualIface
	private   bool         // 源地址属于内网 / 保留网段
}

// virtualIfacePrefixes 已知的虚拟网卡名前缀。
//
// 这些网卡上广播魔术包没有任何意义（对端不是要唤醒的设备），却会把目标设备的 MAC
// 送给容器、虚拟机与隧道对端。逐前缀匹配而不是查驱动类型：Go 的 net.Interface
// 不暴露链路类型，而这些名字是 Docker / libvirt / VMware / VirtualBox / OpenVPN
// 各自固定的命名约定，比任何启发式都可靠。
//
// 刻意不含 "eth"、"en"、"wl"：容器内的 eth0、macvlan 接入的网卡都是真实出口。
// 也不含 "wg"/"tun"（WireGuard、OpenVPN 的路由模式）——它们通常没有 FlagBroadcast，
// 在上一层就被排除了；"tap" 保留在列表里，因为 TAP 模式的隧道确实是广播型的。
//
// Windows 上 net.Interface.Name 给的是**显示名**而不是设备名，命名风格完全不同
// （"VMware Network Adapter VMnet1"、"vEthernet (WSL)"、"VirtualBox Host-Only Network"），
// 故列表里同时收录了这几种写法。发布产物只有 Linux，但开发与自建都会在 Windows 上跑。
var virtualIfacePrefixes = []string{
	"docker",  // Docker 默认网桥 docker0
	"br-",     // Docker 自定义网络的网桥
	"veth",    // 容器 veth pair 宿主机侧；Windows 的 "vEthernet (WSL)" 也在此命中
	"virbr",   // libvirt 默认网桥
	"vmnet",   // VMware（Linux 下的设备名）
	"vmware",  // VMware（Windows 显示名 "VMware Network Adapter VMnet8"）
	"vboxnet", // VirtualBox 仅主机网络（Linux）
	"virtualbox",
	"tap", // TAP 模式隧道（广播型，故不会被 FlagBroadcast 排除）
	"cni", // CNI 插件（k8s）
	"flannel",
	"kube",
	"lxcbr", // LXC
	"zt",    // ZeroTier
}

// isVirtualIface 判断网卡名是否命中虚拟网卡前缀。
func isVirtualIface(name string) bool {
	n := strings.ToLower(name)
	for _, p := range virtualIfacePrefixes {
		if strings.HasPrefix(n, p) {
			return true
		}
	}
	return false
}

// selectTargets 从枚举结果里挑出本次真正要发往的网卡。
//
// iface 非空 = 用户显式指定：只用这一张，不做任何过滤。显式选择就该被原样尊重，
// 包括「就是要往这张虚拟网卡/公网网卡发」这种明知故犯的用法。
//
// iface 为空 = 自动：只用「内网且非虚拟」的网卡，且**不做退化回落**。
// 为什么不回落到更宽的集合（这是本修复的要点）：
//   - 虚拟网卡（docker0、br-*、veth*）上的对端不是要唤醒的设备，发过去纯属把目标设备的
//     MAC 送给容器与虚拟机。MAC 在魔术包的 102 字节里重复 16 次，被动嗅探极易识别，
//     且前 3 字节 OUI 直接暴露硬件厂商。
//   - 公网网卡更严重：VPS 部署时它的「定向广播地址」就是该机房子网的广播地址，
//     魔术包会被广播给同机房同子网的所有邻居主机。范围模式下这是每秒一次、全天候的持续外泄。
//   - 而这两类网卡上的广播**本来也唤不醒任何设备**（魔术包是二层广播，跨路由不转发），
//     所以排除它们不损失任何真实功能。
//
// 筛完为空时返回空切片，由调用方报错而不是回落到「发给所有网卡」——
// 静默回落等于这层防护在最需要它的场景（VPS 上只有公网网卡）恰好失效。
// 用户仍有明确出路：在设备设置里显式指定网卡。
//
// 无需过滤时原样返回入参切片，不做拷贝：绝大多数主机只有一张可用网卡，
// 这条路径每个魔术包都要走一次（见 targetCache 的放大关系说明）。
func selectTargets(all []wakeTarget, iface string) []wakeTarget {
	want := strings.TrimSpace(iface)
	if want != "" {
		if n := countMatch(all, func(t wakeTarget) bool { return t.iface == want }); n == len(all) {
			return all
		} else if n == 0 {
			return nil
		}
		out := make([]wakeTarget, 0, 4)
		for _, t := range all {
			if t.iface == want {
				out = append(out, t)
			}
		}
		return out
	}

	keep := func(t wakeTarget) bool { return t.private && !t.virtual }
	if n := countMatch(all, keep); n == len(all) {
		return all
	} else if n == 0 {
		return nil
	}
	out := make([]wakeTarget, 0, 4)
	for _, t := range all {
		if keep(t) {
			out = append(out, t)
		}
	}
	return out
}

func countMatch(all []wakeTarget, pred func(wakeTarget) bool) int {
	n := 0
	for _, t := range all {
		if pred(t) {
			n++
		}
	}
	return n
}

// targetCacheTTL 网卡枚举结果的缓存有效期。
//
// 取 30 秒是一个折中：网卡的增删与地址变更（插拔网线、Wi-Fi 切换、Docker 起停网桥、
// DHCP 续租换 IP）在这之后最多迟 30 秒才被察觉，而这类变更本身以分钟计，
// 迟一会儿不影响任何人；相对地，「每个魔术包都重新枚举一遍网卡」的代价是实打实的。
// 另有一条更快的纠正路径：一次发送若一个包都没成功，缓存立即作废（见 Wake）。
const targetCacheTTL = 30 * time.Second

// targetCache 缓存 broadcastTargets 的结果。
//
// 为什么必须缓存：net.Interfaces() 与随后逐网卡的 Addrs() 都不是廉价调用，
// 它们要向内核索取完整的适配器表——Windows 上走 GetAdaptersAddresses，
// 每次调用重新拉取全表，实测 10 张网卡 / 23 个地址一轮要 305 毫秒
// （其中 Interfaces() 31 毫秒，逐网卡 Addrs() 合计 261 毫秒），
// 折算下来单次自动模式的 Wake 有 137 毫秒花在枚举上、真正写 UDP 只占 0.4 毫秒。
// Linux 走 netlink 会快很多，但「每个包重新拉一遍全表」这个结构性浪费是一样的。
//
// 放大关系：固定时间模式一秒内最多连发 100 个包，时间范围模式最快 1 秒一拍、
// 每台设备各一条协程。缓存前，这些包的耗时全部由枚举支配，「一秒内发 100 次」
// 实际要跑十几秒（远远超出「一秒内」的语义），且每次枚举各自分配约 292 KB。
//
// 枚举期间刻意持锁不放：这样并发的多台设备同时唤醒时只有第一个真的去枚举，
// 其余在锁上等一下就直接拿到结果，天然形成单飞（single-flight），
// 而不是 N 条协程同时向内核要 N 份适配器表。
var targetCache struct {
	mu   sync.Mutex
	at   time.Time
	list []wakeTarget
}

// cachedBroadcastTargets 返回带 TTL 缓存的网卡枚举结果。
//
// 返回的切片与其中的 *net.UDPAddr 由所有调用方共享，**只读**：
// sendPacket 只把它交给 net.DialUDP 作为本地地址，不会改动它。
func cachedBroadcastTargets() []wakeTarget {
	targetCache.mu.Lock()
	defer targetCache.mu.Unlock()
	if len(targetCache.list) > 0 && time.Since(targetCache.at) < targetCacheTTL {
		return targetCache.list
	}
	list := broadcastTargets()
	// 枚举失败或一张可用网卡都没找到时不写入缓存：否则一次瞬时失败
	// （网卡正在重置、系统刚启动尚未拿到地址）会被固定整整一个 TTL。
	if len(list) == 0 {
		return nil
	}
	targetCache.list = list
	targetCache.at = time.Now()
	return list
}

// invalidateTargetCache 作废网卡枚举缓存，使下一次唤醒重新枚举。
func invalidateTargetCache() {
	targetCache.mu.Lock()
	targetCache.list = nil
	targetCache.at = time.Time{}
	targetCache.mu.Unlock()
}

// broadcastTargets 枚举所有已启用、非回环、支持广播的网卡，计算各自的 IPv4 定向广播地址，
// 并标注筛选所需的分类信息（虚拟 / 内网，见 selectTargets）。
// WOL 魔术包只走 IPv4 广播，故忽略 IPv6 地址。
// 调用代价高（见 targetCache 的说明），正常路径应走 cachedBroadcastTargets。
func broadcastTargets() []wakeTarget {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	out := make([]wakeTarget, 0, 4)
	for _, ifi := range ifaces {
		if ifi.Flags&net.FlagUp == 0 || ifi.Flags&net.FlagLoopback != 0 {
			continue
		}
		if ifi.Flags&net.FlagBroadcast == 0 {
			continue
		}
		addrs, err := ifi.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipnet, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			ip4 := ipnet.IP.To4()
			mask := net.IP(ipnet.Mask).To4()
			if ip4 == nil || mask == nil {
				continue
			}
			bc := make(net.IP, 4)
			for i := 0; i < 4; i++ {
				bc[i] = ip4[i] | ^mask[i]
			}
			out = append(out, wakeTarget{
				iface:     ifi.Name,
				src:       &net.UDPAddr{IP: ip4},
				broadcast: bc.String(),
				virtual:   isVirtualIface(ifi.Name),
				// 判据与 ValidBroadcast 同源：内网 / 保留网段之外的一律视为公网。
				private: netguard.IsPrivateOrReserved(ip4),
			})
		}
	}
	return out
}

// sendPacket 从 src（可为 nil）向 host:port 发送一个 UDP 数据包。
// src 非 nil 时强制走 udp4，以保证数据包从指定网卡发出。
func sendPacket(packet []byte, src *net.UDPAddr, host string, port int) error {
	network := "udp"
	if src != nil {
		network = "udp4"
	}
	udpAddr, err := net.ResolveUDPAddr(network, net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return fmt.Errorf("解析广播地址 %s 失败: %w", host, err)
	}
	conn, err := net.DialUDP(network, src, udpAddr)
	if err != nil {
		return fmt.Errorf("创建 UDP 连接（目标 %s）失败: %w", host, err)
	}
	defer conn.Close()

	if _, err := conn.Write(packet); err != nil {
		return fmt.Errorf("发送魔术包到 %s 失败: %w", host, err)
	}
	return nil
}

// isMACHexDigit 判断是否为十六进制数字字符。
func isMACHexDigit(r rune) bool {
	return (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')
}

// isMACSeparator 判断某个字符是否可作为 MAC 的分组分隔符而被忽略。
//
// 这里刻意放宽到 ASCII 之外。原实现用正则 `[:\-\s]` 做替换，只认半角冒号、半角连字符和
// ASCII 空白（Go 的 \s 仅为 [\t\n\f\r ]），于是下面这些实际会出现的输入全被判成「格式无效」：
//
//   - 中文输入法处于中文标点状态时打出的全角冒号「：」与全角连字符「－」。这是最常见的一种，
//     且冒号与连字符两种写法会同时中招——用户看到的现象正是「XX:XX 和 XX-XX 都提示不正确」。
//   - 从路由器管理页 / 聊天记录 / 文档里复制粘贴时带上的不换行空格、零宽字符与 BOM。
//   - Unicode 各式连字符与减号（U+2010..U+2015、U+2212），以及 Cisco 风格的点分写法
//     e86a.643b.5d95。
//
// 这些字符渲染出来与半角写法几乎无从分辨，用户看着一个「正确」的 MAC 却只能得到一句
// 「格式无效」，无法自查。分隔符本身不携带信息，一律忽略即可。
// 末尾回落到 unicode.IsSpace，它覆盖 ASCII 空白、不换行空格 U+00A0 与全角空格 U+3000；
// 零宽字符不属于 White_Space，故仍需在上面显式列出。
func isMACSeparator(r rune) bool {
	switch r {
	case ':', '-', '.', '_':
		return true
	case '：', '－', '．', '＿': // 全角冒号 / 连字符 / 句点 / 下划线
		return true
	case '\u200b', '\u200c', '\u200d', '\ufeff': // 零宽空格 / 零宽非连接符 / 零宽连接符 / BOM（复制粘贴时带入，肉眼不可见）
		return true
	case '‐', '‑', '‒', '–', '—', '―', '−': // 各式连字符与减号
		return true
	}
	return unicode.IsSpace(r)
}

// parseMAC 解析多种分隔符格式的 MAC 地址为 6 字节。
// 接受 AA:BB:CC:DD:EE:FF、AA-BB-CC-DD-EE-FF、aabbccddeeff 及点分/空格分隔等写法，
// 大小写不敏感，分隔符见 isMACSeparator。
func parseMAC(mac string) ([]byte, error) {
	var clean strings.Builder
	clean.Grow(12)
	for _, r := range mac {
		switch {
		case isMACHexDigit(r):
			clean.WriteRune(r)
		case isMACSeparator(r):
			// 分隔符不携带信息，忽略。
		default:
			// 指名道姓地报出这个字符：否则用户面对一个看起来完全正确的 MAC 无从下手。
			return nil, fmt.Errorf("MAC 地址包含非法字符 %q", r)
		}
	}
	s := clean.String()
	if len(s) != 12 {
		return nil, fmt.Errorf(
			"MAC 地址应为 6 组两位十六进制数（如 AA:BB:CC:DD:EE:FF 或 AA-BB-CC-DD-EE-FF），实际解析到 %d 位十六进制字符",
			len(s),
		)
	}
	hw, err := hex.DecodeString(s)
	if err != nil {
		// 上面已逐字符校验过，正常到不了这里；保留以防校验与解码口径将来出现偏差。
		return nil, errors.New("MAC 地址包含非法字符")
	}
	return hw, nil
}

// ParseMAC 校验并解析 MAC 地址。导出以供 API 层在保存时提前拒绝非法值——
// 否则错误只会等到真正唤醒时才浮现（表现为列表里一条「失败: …」）。
func ParseMAC(mac string) ([]byte, error) { return parseMAC(mac) }

// NormalizeMAC 把任意可接受写法规整为规范形式（大写、冒号分隔）。
// 解析不通过时原样返回（仅去除首尾空白），把报错留给校验层，不静默丢弃用户输入。
func NormalizeMAC(mac string) string {
	hw, err := parseMAC(mac)
	if err != nil {
		return strings.TrimSpace(mac)
	}
	return strings.ToUpper(net.HardwareAddr(hw).String())
}

// buildMagicPacket 构造魔术包：6 字节 0xFF + 16 次重复的目标 MAC。
func buildMagicPacket(hw []byte) []byte {
	packet := make([]byte, 0, 102)
	for i := 0; i < 6; i++ {
		packet = append(packet, 0xFF)
	}
	for i := 0; i < 16; i++ {
		packet = append(packet, hw...)
	}
	return packet
}

// ---------- 定时唤醒调度 ----------

// wakePlan 某一天的发包安排，由 planForDay 从 WOLSchedule 推导。
// 两种触发方式被统一表达为「从 start 起、每 interval 一拍、直到 end，每拍连发 burst 个包」：
//   - 固定时间：start == end，全天只有一拍；burst 即用户设置的「一秒内发包次数」。
//   - 时间范围：burst 恒为 1，发包密度完全由 interval 决定。
type wakePlan struct {
	start    time.Time
	end      time.Time
	interval time.Duration
	burst    int
}

// clampCount 把「一秒内发包次数」夹到 [1, MaxWOLWakeCount]。
func clampCount(n int) int {
	if n < 1 {
		return 1
	}
	if n > config.MaxWOLWakeCount {
		return config.MaxWOLWakeCount
	}
	return n
}

// clampInterval 把发送间隔夹到 [1s, MaxWOLIntervalSec]。
// 0 与负数一律按 1 秒处理：interval 为 0 会让统一的节拍循环原地死转。
func clampInterval(sec int) time.Duration {
	if sec < 1 {
		return time.Second
	}
	if sec > config.MaxWOLIntervalSec {
		return time.Duration(config.MaxWOLIntervalSec) * time.Second
	}
	return time.Duration(sec) * time.Second
}

// atClock 返回 day 这一天的 h:m 时刻（day 为当天 00:00，取其所在时区）。
//
// 刻意不写成 day.Add(h*time.Hour + m*time.Minute)：Add 加的是**绝对时长**，
// 而「当天的 8 点」是**墙钟时刻**，两者在夏令时切换日会差一小时。
// 以 America/New_York 为例：
//   - 春季 2026-03-08 当天 02:00 直接跳到 03:00，这一天只有 23 小时。
//     day.Add(8h) 得到的是 09:00 EDT——用户设的 08:00 变成了 9 点才发。
//   - 秋季 2026-11-01 当天 01:00 重复一次，这一天有 25 小时。
//     day.Add(8h) 得到的是 07:00 EST——提前一小时发。
//
// time.Date 按墙钟构造，不受这一天的实际长度影响，用户设的 08:00 就是 08:00。
// 中国大陆自 1991 年起不用夏令时，因此默认时区下这个差别观察不到；
// 但容器的 TZ 是可配置的，海外部署或把 TZ 设成有夏令时的时区就会中招——
// 而现象是「每年有两天，定时唤醒早一小时或晚一小时触发」，极难自查。
//
// 附带修正了跨越切换点的时间范围模式：春季那天 00:00-23:59 的安排，
// 用 Add 算出的 end 会落到次日 00:59，越过当天边界；runSchedule 随后按
// startOfDay(now).AddDate(0,0,1) 睡到"次日"，于是把真正的次日整个跳过。
//
// 两种切换日的边角情形都在此处显式定下口径，不留给 time.Date 的未定义行为：
//   - 请求的时刻在这一天**不存在**（落在春季被跳过的那一小时里）：顺延到之后第一个
//     真实存在的瞬时。见 firstRealClock。
//   - 请求的时刻在这一天出现**两次**（落在秋季重复的那一小时里）：只发一次。
//     time.Date 取其中一个瞬时，两者都是真实的该墙钟时刻，取哪个都对；
//     而 runSchedule 每天只推导一次 plan，因此不会因为这一小时重复而发两遍。
func atClock(day time.Time, h, m int) time.Time {
	y, mo, d := day.Date()
	loc := day.Location()
	at := time.Date(y, mo, d, h, m, 0, 0, loc)
	if hh, mm, _ := at.Clock(); hh != h || mm != m {
		return firstRealClock(y, mo, d, h, m, loc)
	}
	return at
}

// dstGapProbeMinutes 探测夏令时空档长度的上限。
// 现实中的空档几乎都是 60 分钟，也有 30 分钟的（Australia/Lord_Howe）；
// 历史上最大的一次是 1942 年 Kwajalein 的 24 小时，但那种量级不值得为之付代价。
// 3 小时足以覆盖所有在用的时区规则，同时给循环一个明确的上界。
const dstGapProbeMinutes = 180

// firstRealClock 返回 y-mo-d 这一天里、不早于 h:m 的第一个**真实存在**的墙钟时刻。
//
// 用于春季夏令时切换日：那一小时（如 America/New_York 2026-03-08 的 02:00-02:59）
// 在本地时间轴上根本不存在。time.Date 对这种输入只保证返回一个合理的瞬时，
// 具体取哪个偏移是未定义的——实测会回退到 01:30 EST，即比用户设定**提前**一小时触发。
//
// 与其接受这个未定义结果，不如显式顺延到跳变发生的那一刻（上例为 03:00 EDT）：
// 这与 cron 类调度器的惯例一致，也符合「设了就该发、且不该提前发」的直觉。
// 那一小时确实不存在，但不该因此漏发或早发。
//
// 逐分钟探测而不是去查时区规则：Go 不提供公开的时区跳变查询接口，
// 而空档有明确上界（见 dstGapProbeMinutes），一年最多命中一次，代价可以忽略。
func firstRealClock(y int, mo time.Month, d, h, m int, loc *time.Location) time.Time {
	for i := 1; i <= dstGapProbeMinutes; i++ {
		total := h*60 + m + i
		if total >= 24*60 {
			break // 已越过当天边界：不再顺延，退回下面的兜底
		}
		cand := time.Date(y, mo, d, total/60, total%60, 0, 0, loc)
		if hh, mm, _ := cand.Clock(); hh == total/60 && mm == total%60 {
			return cand
		}
	}
	// 探不到（时区规则异常，或空档一直延到当天结束）：退回 time.Date 的结果。
	// 它仍是一个自洽的瞬时，只是具体取值由标准库决定。
	return time.Date(y, mo, d, h, m, 0, 0, loc)
}

// planForDay 推导给定日期（day 为当天 00:00）的发包安排。
// ok 为 false 表示时间字段非法，当天不安排任何发送（调度器随即睡到次日）。
func planForDay(s config.WOLSchedule, day time.Time) (wakePlan, bool) {
	if !dateInSchedule(s, day) {
		return wakePlan{}, false
	}
	switch s.Mode {
	case "range":
		sh, sm, ok1 := parseHM(s.Start)
		eh, em, ok2 := parseHM(s.End)
		if !ok1 || !ok2 {
			return wakePlan{}, false
		}
		start := atClock(day, sh, sm)
		end := atClock(day, eh, em)
		if !end.After(start) {
			// 结束不晚于开始：退化为只在开始时刻发一次（与改版前同一口径）。
			//
			// 这里**刻意不支持跨零点**（22:00→06:00 这类「夜间反复试着唤醒」的意图），不是漏了。
			// 看上去一行就能修（end = end.AddDate(0, 0, 1)），但那一行会同时撞坏三处结构，
			// 且症状比现在的退化更难查：
			//   - runSchedule 是「按天推导 + 睡到次日 00:00」的循环。一天的安排跨到次日之后，
			//     节拍走完时真实时间已经在次日，下一轮 startOfDay(time.Now()).AddDate(0,0,1)
			//     指向的是第三天——真正的次日被整个跳过。这不是推测，夏令时那次修复
			//     踩的就是同一个坑（见 atClock 的说明：end 越过当天边界导致次日被跳过）；
			//   - dateInSchedule 是按天判定的。日历范围最后一天的夜间安排会溢出到范围之外，
			//     而范围结束次日的 00:00–06:00 又不属于任何一天的安排，接缝两侧都不对；
			//   - 「一天一段」这个前提还被前端的次数预览（Wol.vue 的 rangeTicks）与
			//     Status 的下次触发时刻共用，改了要一起改。
			//
			// 用户侧的办法是拆成两条设备（22:00–23:59 与 00:00–06:00）：两条各自都是一天内的
			// 普通范围，上面三处结构一处都不用动。这一点在两个地方告知用户——面板编辑时的
			// rangeEndBeforeStart 提示（web/src/views/Wol.vue），以及 runSchedule 起调度时
			// 记的那条警告（手工编辑 config.json 或整份导入的配置绕过了前端校验，
			// 而「每天只在 22:00 发一个包」这个症状在日志里与正常单拍毫无区别）。
			end = start
		}
		return wakePlan{start: start, end: end, interval: clampInterval(s.IntervalSec), burst: 1}, true
	default: // fixed
		h, mnt, ok := parseHM(s.Time)
		if !ok {
			return wakePlan{}, false
		}
		at := atClock(day, h, mnt)
		// 固定时间全天只有一拍：start == end 让统一的节拍循环走完一轮即退出；
		// interval 取 1 秒仅为满足「必须为正」的前提，不参与语义。
		return wakePlan{start: at, end: at, interval: time.Second, burst: clampCount(s.Count)}, true
	}
}

// firstTickAfter 返回不早于 now 的第一拍。
// 从 start 逐拍 +interval 地跳过已过时刻在极端配置下代价可观（间隔 1 秒、跨度 24 小时
// 要空转 8 万多次），这里用一次整除直接算到位。
func firstTickAfter(p wakePlan, now time.Time) time.Time {
	if p.interval <= 0 || !p.start.Before(now) {
		return p.start
	}
	elapsed := now.Sub(p.start)
	steps := int64(elapsed / p.interval)
	if elapsed%p.interval != 0 {
		steps++
	}
	return p.start.Add(p.interval * time.Duration(steps))
}

// runSchedule 按设备计划循环发送唤醒包。每天重新推导当日的发包安排。
func (m *Module) runSchedule(ctx context.Context, d config.WOLDevice) {
	defer m.wg.Done()
	warnedDegraded := false
	for {
		day := startOfDay(time.Now())
		if dateInSchedule(d.Schedule, day) {
			if p, ok := planForDay(d.Schedule, day); ok {
				// 时间范围退化成单拍（结束不晚于开始）：提醒一次，并给出可行的替代做法。
				// 判据取自推导出的 plan 而不是重新解析一遍时间字段，这样退化规则将来若有调整，
				// 这条提醒不会悄悄说错话。范围模式下 start == end 只可能来自 planForDay 的那次退化。
				//
				// 只记一次而不是每天一次：这是配置层面的事实，不是每天新发生的事件。
				if !warnedDegraded && d.Schedule.Mode == "range" && p.start.Equal(p.end) {
					warnedDegraded = true
					m.log.Warn("时间范围的结束时刻不晚于开始时刻，每天只在开始时刻发一拍；跨零点请拆成两条设备（如 22:00–23:59 与 00:00–06:00）",
						"device", d.Name, "start", d.Schedule.Start, "end", d.Schedule.End)
				}
				if !m.runPlanDay(ctx, d, p) {
					return
				}
			}
		}
		// 睡到次日 00:00 后重新计算。
		// 这里必须用「当前真实时间」而不是循环开始时的时间：时间范围模式的最后一拍可能落在
		// 23:59:59，等节拍走完时循环开头的那个「今天」已经成了昨天，用它 +1d 得到的是已经
		// 过去的时刻，会导致一次无意义的立即重算。
		next := startOfDay(time.Now()).AddDate(0, 0, 1)
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Until(next)):
		}
	}
}

// runPlanDay 按节拍走完当天的发包安排，返回 false 表示 ctx 已取消、调度应结束。
//
// 触发时刻刻意不预先展开成切片：时间范围模式下「间隔 1 秒、跨度 24 小时」是 8 万多个元素，
// 而逐拍等待是 O(1) 内存且语义完全一致。
//
// 落后的节拍一律丢弃，不做补发。节拍时刻的推进是纯算术的（at += interval），一旦某一拍的
// 实际处理耗时超过 interval，at 就会永久落在真实时间后面，此后每次 time.Until(at) 都是负数、
// 每拍立即触发——结果是把积压的所有拍以零间隔连续打完（休眠 2 小时 + 间隔 5 秒 = 恢复瞬间
// 连打 1440 个包，并连带触发 1440 次运行态回写）。这种「追赶」还会自我维持：追赶期间每拍更贵，
// 落后量不会自然收敛，直到越过 end 才结束。而补发本身毫无价值——魔术包幂等，目标要么早已开机、
// 要么当时就没收到，晚几十分钟补一个包不改变任何结果。
// 能让一拍超时的原因不止一种：主机休眠 / 虚拟机挂起恢复、网卡枚举耗时、配置写锁被长期占用、
// 系统时钟被 NTP 向前跳。
//
// 日志按「首拍一条 + 成败变化时一条 + 当日汇总一条」记，而不是每个包一条：范围模式下一天
// 可能有几千拍，逐包写日志会把日志环（容量即「访问日志最大条数」）整个挤满，
// 把其他模块的记录全冲掉。
func (m *Module) runPlanDay(ctx context.Context, d config.WOLDevice, p wakePlan) bool {
	if p.interval <= 0 {
		p.interval = time.Second // 兜底：防止将来 interval 允许为 0 时在此死转
	}
	var ticks, okCount, skipped int
	lastErr := ""
	// 首拍的宽容度要和循环里的一致（见下面的 wait < -p.interval）：落后不足一整拍算抖动、照常
	// 发。这个 -p.interval 不能省，否则 firstTickAfter 会把「刚刚过去几毫秒」的那拍向上取整到
	// 下一拍，于是「全天只有一拍」的固定时间模式（start == end）整天一拍都不发——runSchedule
	// 是在日切定时器醒来之后才推导当天计划的，唤醒时刻配成 00:00 的设备必然差那么几毫秒，
	// 而差多少又取决于系统时钟粒度，表现就成了「有时发有时不发」。
	for at := firstTickAfter(p, time.Now().Add(-p.interval)); !at.After(p.end); {
		// 每轮开头先看一眼取消信号。少了这一下，「上一拍超时」的情况下会多发一个包：
		// 超时量落在 (interval, 2*interval] 区间时下面算出的 wait 在 [-interval, 0]，
		// 被判为正常抖动而立即触发——完全绕过唯一的那个 ctx 检查点。
		// 后果有两重：取消之后仍有一个包发出去（Close 的契约是「返回后不再发包」），
		// 且 Reload/Close 的 m.wg.Wait() 要等两拍而不是一拍才能返回。
		select {
		case <-ctx.Done():
			return false
		default:
		}
		wait := time.Until(at)
		// 落后超过一整拍：丢弃这些拍，并把 at 重新对齐到当前时间之后的第一拍。
		// 重新对齐必须复用 firstTickAfter 的整除，不能写成逐拍 +interval 追平——
		// 间隔 1 秒、落后 2 小时就是 7200 次空循环（正是 firstTickAfter 存在的理由）。
		if wait < -p.interval {
			next := firstTickAfter(wakePlan{start: at, end: p.end, interval: p.interval}, time.Now())
			if n := int(next.Sub(at) / p.interval); n > 0 {
				skipped += n
			}
			at = next
			continue
		}
		// wait <= 0 且落后不足一拍：属于正常抖动，立即触发，不必等待也不算跳过。
		if wait > 0 {
			select {
			case <-ctx.Done():
				return false
			case <-time.After(wait):
			}
		}
		sent, err := m.fireScheduled(ctx, d, p.burst)
		ticks++
		cur := ""
		if err != nil {
			cur = err.Error()
		} else {
			okCount++
		}
		switch {
		case cur != "" && (ticks == 1 || cur != lastErr):
			m.log.Warn("定时网络唤醒失败", "device", d.Name, "mac", d.MAC, "sent", sent, "want", p.burst, "err", cur)
		case cur == "" && ticks == 1:
			m.log.Info("已发送定时网络唤醒", "device", d.Name, "mac", d.MAC, "sent", sent)
		case cur == "" && lastErr != "":
			m.log.Info("定时网络唤醒已恢复", "device", d.Name, "mac", d.MAC, "sent", sent)
		}
		lastErr = cur
		at = at.Add(p.interval)
	}
	// 范围模式一天多拍时补一条汇总，便于回看「今天到底发了多少」。
	// skipped 必须出现在汇总里：否则「今天为什么只发了 300 次而不是 1440 次」无从查证。
	if ticks > 1 || skipped > 0 {
		m.log.Info("定时网络唤醒当日结束", "device", d.Name, "ticks", ticks, "ok", okCount, "failed", ticks-okCount, "skipped", skipped)
	}
	return true
}

// fireScheduled 执行一拍：连发 burst 个魔术包并回写设备的最近唤醒状态。
//
// burst > 1 只出现在固定时间模式，语义是「在这一秒内发这么多个包」，因此把它们均匀铺在
// 1 秒内发完，而不是背靠背瞬时打出——后者在交换机上更容易被当作突发流量整片丢弃，
// 而「一秒内 N 次」本就是按秒计的密度。
//
// 返回实际成功发出的包数与最后一次错误。ctx 在连发途中被取消时提前收尾，
// 但仍照常回写状态，不把已经发生的事实丢掉。
func (m *Module) fireScheduled(ctx context.Context, d config.WOLDevice, burst int) (int, error) {
	if burst < 1 {
		burst = 1
	}
	gap := time.Second / time.Duration(burst)
	sent := 0
	var lastErr error
	for i := 0; i < burst; i++ {
		if i > 0 {
			stop := false
			select {
			case <-ctx.Done():
				stop = true
			case <-time.After(gap):
			}
			if stop {
				break
			}
		}
		if err := WakeDevice(d); err != nil {
			lastErr = err
		} else {
			sent++
		}
	}

	result := "已发送"
	if burst > 1 {
		result = fmt.Sprintf("已发送 %d 次（1 秒内）", sent)
	}
	if lastErr != nil {
		result = "失败: " + lastErr.Error()
	}
	if m.stats != nil {
		// 设备在这一拍执行期间被删掉了也无所谓：统计库里那条键会在下次删除时被
		// Forget 掉，或者到了条数上限时按「最久没动静」淘汰。
		m.stats.Woke(d.ID, time.Now().Unix(), result)
	}
	return sent, lastErr
}

// startOfDay 返回当天 00:00（本地时区）。
func dateInSchedule(s config.WOLSchedule, day time.Time) bool {
	if !s.CalendarEnabled {
		return true
	}
	date := day.Format("2006-01-02")
	if s.StartDate == "" || s.EndDate == "" {
		return false
	}
	return date >= s.StartDate && date <= s.EndDate
}

func startOfDay(t time.Time) time.Time {
	y, mo, d := t.Date()
	return time.Date(y, mo, d, 0, 0, 0, 0, t.Location())
}

// parseHM 解析 "HH:MM"。
func parseHM(s string) (h, m int, ok bool) {
	parts := strings.SplitN(strings.TrimSpace(s), ":", 2)
	if len(parts) != 2 {
		return 0, 0, false
	}
	h, err1 := strconv.Atoi(strings.TrimSpace(parts[0]))
	m, err2 := strconv.Atoi(strings.TrimSpace(parts[1]))
	if err1 != nil || err2 != nil || h < 0 || h > 23 || m < 0 || m > 59 {
		return 0, 0, false
	}
	return h, m, true
}

// ValidClockHM 判断一个 "HH:MM" 字符串能否被调度器解析。
// 导出而不是让 API 层自己写一份，是为了让「保存时的校验」与「调度时的解析」严格同口径：
// 两处口径若有偏差，就会出现「保存通过但当天永远不触发」这种查无可查的现象。
func ValidClockHM(s string) bool {
	_, _, ok := parseHM(s)
	return ok
}
