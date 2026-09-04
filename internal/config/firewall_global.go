package config

import "fmt"

// 本文件是「服务防护（连接层）」这份设置的数据层规则：取值边界、名单整理、以及一份设置是否可用。
//
// 与 firewall.go（面板入站防护）同一套分工：配置有三条写入路径（面板保存、整份导入、
// 手改 config.json），只有第一条经过接口校验。因此边界必须在加载期也兜一遍——
// 加载期不能因为一份不合理的设置就拒绝启动（那会把"填错一个数"升级成"面板起不来"），
// 但可以夹住。于是"界面上能存下的"与"程序实际会执行的"永远是同一套判断。

// BanEntriesForMemoryMB 由内存上限（MB）折算封禁表条目上限，面板入站防护与服务防护用同一份换算。
//
// 封禁表的键是**攻击者选的**地址，一个 IPv6 /64 就能提供 1.8e19 个来源，无上限等于把内存分配权交给对方。
// 一条记录的实际开销约 176 字节（entry 结构体 136 + map 桶里的键 16 + 指针 8 + 展示用 IP 字符串的底层数组），
// 留一点余量按 192 字节/条折算，于是：
//
//	n = mb * 1024 * 1024 / 192
//
// 下限 1024 防极小额度算出 0 导致表一满就拒计数；上限 1<<22 防一个被手改到离谱的额度把地址空间吃穿。
//
// 注意它是**每张表**的上限，不是两张表的总额：面板入站防护与服务防护各有一张封禁表，
// 两张都按同一个 MemoryMB 换算，最坏情况下的总占用是填进去的两倍。
// 这样写是刻意的——两张表的容量应当一致（同样的攻击面、同样的地址空间），
// 而"把一个额度切成两半"会让每一侧都只剩一半的抗压能力，却省不下多少内存。
//
// mb<=0 回落默认：归一化已保证 MemoryMB 落在 [DefaultGlobalFirewallMemoryMB, MaxGlobalFirewallMemoryMB]，
// 这里再兜一层，是为了让"读到的快照还没归一化"这类边缘情况也不会算出 0。
func BanEntriesForMemoryMB(mb int) int {
	if mb <= 0 {
		mb = DefaultGlobalFirewallMemoryMB
	}
	n := mb * 1024 * 1024 / 192
	if n < 1024 {
		n = 1024
	}
	if n > 1<<22 {
		n = 1 << 22
	}
	return n
}

// BanEntryBytes 一条封禁记录的近似内存占用，供界面展示"已用内存"。
//
// 与 BanEntriesForMemoryMB 的 192 分开写：那个是**折算容量**用的（含余量，宁可少装几条），
// 这个是**报告实际占用**用的，取实测值。两个数各有用途，混用会让界面上的"已用"
// 永远等于"上限 × 占比"，看不出真实水位。
const BanEntryBytes = 176

// defaultGlobalFirewall 全新安装的初值：**关闭**，均衡档，自动封禁开启。
//
// 默认关闭是刻意的。它拦的是连接，而"拦掉"在浏览器里长得和"服务没起来"一模一样：
// 一旦误伤，用户看到的是无法连接，而不是一个能读的错误页——这种失败方式不该由默认值带来。
// 更要紧的是判据来自 TLS 握手失败，而握手失败并不只有扫描器会产生：一台配置得不太对的
// 客户端、一个反复重试的探活脚本、一个用旧 TLS 版本的老设备，都能持续踩中阈值。
// 是否接受这个代价应当由用户在读过说明之后决定，而不是装完就已经替他决定了。
//
// 其余字段仍写成一组合理初值（均衡档 + 自动封禁开 + 默认内存额度）：开关关着时它们不影响
// 任何行为，但用户进模块页打开开关时，看到的应该是一组能直接用的值而不是一排 0。
//
// 与面板入站防护的不同：这里没有"仅局域网"模式——Web 服务本就是要对外暴露的，
// 限制来源范围那是面板入站防护（管面板端口）的职责，两者各管各的范围。
func defaultGlobalFirewall() GlobalFirewall {
	g := GlobalFirewall{
		Enabled: false,
		Level:   GlobalFirewallLevelBalanced,
		AutoBan: true,
	}
	applyGlobalFirewallLevel(&g)
	g.MemoryMB = DefaultGlobalFirewallMemoryMB
	return g
}

// GlobalFirewallPreset 一个检测档位对应的具体数值。
//
// 它是导出的，因为接口层要把整张预设表下发给前端：前端换档位时要立刻把数值显示出来
// （用户"点了档位却什么都没变"正是这个功能之前最大的毛病），而把三组数字抄一份到
// 前端就意味着两边可以各改各的、而且没人会发现。下发它，前端就只有一个来源。
type GlobalFirewallPreset struct {
	Level         string `json:"level"`
	WindowSeconds int    `json:"windowSeconds"`
	WindowLimit   int    `json:"windowLimit"`
	BurstSeconds  int    `json:"burstSeconds"`
	BurstLimit    int    `json:"burstLimit"`
	BanMinutes    int    `json:"banMinutes"`
}

// globalFirewallPresets 三个预设档位的数值，顺序即界面上的排列顺序（松 → 严）。
// custom 不在表里：它的语义正是"不套预设"。
var globalFirewallPresets = []GlobalFirewallPreset{
	{GlobalFirewallLevelLoose, gfwLooseWindowSeconds, gfwLooseWindowLimit, gfwLooseBurstSeconds, gfwLooseBurstLimit, gfwLooseBanMinutes},
	{GlobalFirewallLevelBalanced, gfwBalancedWindowSeconds, gfwBalancedWindowLimit, gfwBalancedBurstSeconds, gfwBalancedBurstLimit, gfwBalancedBanMinutes},
	{GlobalFirewallLevelStrict, gfwStrictWindowSeconds, gfwStrictWindowLimit, gfwStrictBurstSeconds, gfwStrictBurstLimit, gfwStrictBanMinutes},
}

// GlobalFirewallPresets 返回预设表的副本（调用方拿去序列化，不该能改到这张表）。
func GlobalFirewallPresets() []GlobalFirewallPreset {
	out := make([]GlobalFirewallPreset, len(globalFirewallPresets))
	copy(out, globalFirewallPresets)
	return out
}

// globalFirewallPreset 按档位取预设；custom 与认不出的值返回 ok=false。
func globalFirewallPreset(level string) (GlobalFirewallPreset, bool) {
	for _, p := range globalFirewallPresets {
		if p.Level == level {
			return p, true
		}
	}
	return GlobalFirewallPreset{}, false
}

// applyGlobalFirewallLevel 把档位解析成具体的窗口 / 阈值 / 封禁时长。
//
// 落库存的永远是解析后的数值，运行态（internal/inboundfw）因此不必认识"档位"这个概念。
// 认不出的档位（含空值）一律落到 balanced：未知取值往"适中"落而不是往极端落，
// 避免一份手改的配置把防护强度悄悄推到最松或最严。custom 由调用方单独处理，不会走到这里。
func applyGlobalFirewallLevel(g *GlobalFirewall) {
	p, ok := globalFirewallPreset(g.Level)
	if !ok {
		g.Level = GlobalFirewallLevelBalanced
		p, _ = globalFirewallPreset(GlobalFirewallLevelBalanced)
	}
	g.WindowSeconds, g.WindowLimit = p.WindowSeconds, p.WindowLimit
	g.BurstSeconds, g.BurstLimit = p.BurstSeconds, p.BurstLimit
	g.BanMinutes = p.BanMinutes
}

// normalizeGlobalFirewall 就地规范化一份服务防护设置：按档位定数值、夹住越界值、整理名单。
// 幂等——对同一份设置跑两次与跑一次结果相同（迁移块与加载期都会调它）。
//
// 档位是权威值：选了预设档位，数值就**一定**被重写成该档位的预设。
// 这一条替换掉了原先"数值全为零时才套预设"的判断，那个判断实际上永远不成立——
// 前端提交的表单必然带着上一次的数值，于是换档位从来没生效过，三个档位点下去数值一模一样。
// 想手填数值请选 custom，那是一个明确的选择，而不是靠猜"这组数是不是被人动过"。
func normalizeGlobalFirewall(g *GlobalFirewall) {
	if g.Level == GlobalFirewallLevelCustom {
		g.WindowSeconds = clampInt(g.WindowSeconds, MinGlobalFirewallWindowSeconds, MaxGlobalFirewallWindowSeconds)
		g.WindowLimit = clampInt(g.WindowLimit, MinGlobalFirewallLimit, MaxGlobalFirewallLimit)
		g.BurstSeconds = clampInt(g.BurstSeconds, MinGlobalFirewallWindowSeconds, MaxGlobalFirewallWindowSeconds)
		g.BurstLimit = clampInt(g.BurstLimit, MinGlobalFirewallLimit, MaxGlobalFirewallLimit)
		g.BanMinutes = clampInt(g.BanMinutes, 1, MaxGlobalFirewallBanMinutes)
	} else {
		applyGlobalFirewallLevel(g) // 含"认不出的档位落到 balanced"
	}
	// 内存上限：0 是有意义的"取默认"，夹到 [1, 最大] 之外时回落默认而非 0——
	// 0 在这里没有"不限"的语义（封禁表必须有硬上限），因此不当作有效值。
	g.MemoryMB = clampInt(g.MemoryMB, 0, MaxGlobalFirewallMemoryMB)
	if g.MemoryMB == 0 {
		g.MemoryMB = DefaultGlobalFirewallMemoryMB
	}
	g.AllowIPs = normalizeIPList(g.AllowIPs)
	g.DenyIPs = normalizeIPList(g.DenyIPs)
}

// Valid 判断这份设置是否"能真的跑起来"。关闭状态一律放过——关着的防火墙填成什么样都不影响行为，
// 拦下来只会让用户没法先关掉再慢慢改。
//
// 校验的是**用户提交的原始值**（接口层在 normalize 之前调用），因此它能把"填了个负数"
// 报回界面，而不是被 normalize 悄悄改成别的数之后让人以为存对了。
//
// 数值只在 custom 档位下校验：预设档位的数值由服务端重写，用户提交的那几个数根本不作数，
// 为它们报错等于拿一个不会生效的值挡住保存。
func (g GlobalFirewall) Valid() error {
	if !g.Enabled {
		return nil
	}
	if len(g.AllowIPs) > GlobalFirewallMaxIPs || len(g.DenyIPs) > GlobalFirewallMaxIPs {
		return fmt.Errorf("名单最多 %d 条", GlobalFirewallMaxIPs)
	}
	// 档位必须认得出。归一化会把认不出的值落到 balanced，但那是给"手改的配置文件"兜底的；
	// 接口层收到一个拼错的档位应当报错，否则用户选了什么、最后跑的是什么，两者可以不一致。
	if _, ok := globalFirewallPreset(g.Level); !ok && g.Level != GlobalFirewallLevelCustom && g.Level != "" {
		return fmt.Errorf("检测档位无效")
	}
	if g.AutoBan && g.Level == GlobalFirewallLevelCustom {
		if g.WindowSeconds < MinGlobalFirewallWindowSeconds || g.WindowSeconds > MaxGlobalFirewallWindowSeconds {
			return fmt.Errorf("常规窗口时长需在 %d-%d 秒之间", MinGlobalFirewallWindowSeconds, MaxGlobalFirewallWindowSeconds)
		}
		if g.WindowLimit < MinGlobalFirewallLimit || g.WindowLimit > MaxGlobalFirewallLimit {
			return fmt.Errorf("常规窗口命中次数需在 %d-%d 之间", MinGlobalFirewallLimit, MaxGlobalFirewallLimit)
		}
		if g.BurstSeconds < MinGlobalFirewallWindowSeconds || g.BurstSeconds > MaxGlobalFirewallWindowSeconds {
			return fmt.Errorf("突发窗口时长需在 %d-%d 秒之间", MinGlobalFirewallWindowSeconds, MaxGlobalFirewallWindowSeconds)
		}
		if g.BurstLimit < MinGlobalFirewallLimit || g.BurstLimit > MaxGlobalFirewallLimit {
			return fmt.Errorf("突发窗口命中次数需在 %d-%d 之间", MinGlobalFirewallLimit, MaxGlobalFirewallLimit)
		}
		if g.BanMinutes < 1 || g.BanMinutes > MaxGlobalFirewallBanMinutes {
			return fmt.Errorf("自动封禁时长需在 1-%d 分钟之间", MaxGlobalFirewallBanMinutes)
		}
	}
	// 内存上限与档位无关，两个档位都要校验：0 是"取默认"，负数与超上限则是填错了。
	if g.MemoryMB < 0 || g.MemoryMB > MaxGlobalFirewallMemoryMB {
		return fmt.Errorf("内存上限需在 1-%d MB 之间", MaxGlobalFirewallMemoryMB)
	}
	return nil
}

// NormalizeGlobalFirewall 对**外部提交**的服务防护设置执行与加载期完全相同的规范化。
// 面板保存前调用它，使"存进去的"与"加载后跑的"是同一份值。
func NormalizeGlobalFirewall(g *GlobalFirewall) {
	if g == nil {
		return
	}
	normalizeGlobalFirewall(g)
}
