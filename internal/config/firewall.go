package config

import (
	"fmt"
	"strings"

	"mantou/internal/ipx"
)

// 本文件是「面板入站防护」这份设置的数据层规则：取值边界、名单整理、以及一份设置是否可用。
//
// 与 restart.go 同一套分工，理由也一样：配置有三条写入路径（面板保存、整份导入、
// 手改 config.json），只有第一条经过接口校验。因此边界必须在加载期也兜一遍——
// 加载期不能因为一份不合理的设置就拒绝启动（那会把"填错一个数"升级成"面板起不来"），
// 但可以夹住。于是"界面上能存下的"与"程序实际会执行的"永远是同一套判断。

// 防火墙的两种来源范围。取值同时是接口契约（前端按这些字符串提交）。
const (
	// FirewallModeLAN 只允许局域网（判定见 ipx.IsLAN）。
	FirewallModeLAN = "lan"
	// FirewallModeAll 不限来源；名单、限速、自动封禁仍然生效。
	FirewallModeAll = "all"
)

// firewallAutoBanWindow 自动封禁的「超限次数」计数窗口（分钟）。
//
// 固定值、不开放给用户：这个数与阈值是同一件事的两个面，两个都能调只会让人调不明白
// （"10 分钟内 20 次"是一句能读懂的话，"N 分钟内 M 次"要先想一会儿）。
// 10 分钟与 ipx 限流桶、logSuppressor 的空闲窗口一致，纯属让全局的时间尺度保持一个数量级。
const firewallAutoBanWindow = 10

// FirewallAutoBanWindowMinutes 暴露给上层（服务端计时、界面提示）的计数窗口。
func FirewallAutoBanWindowMinutes() int { return firewallAutoBanWindow }

// defaultPanelFirewall 全新安装的防火墙初值：**开启，且只允许局域网**。
//
// 默认开着是这份设计的主张：面板监听 0.0.0.0，装完就能被公网扫到，而绝大多数
// 自建场景根本不需要从公网直连面板。默认关着等于把这个判断推给"记得去开的人"，
// 而被扫爆的恰恰是没去开的那批人。
//
// 代价要说清楚：装在 VPS 上、只能从公网访问的用户，第一次启动就进不来面板。
// 因此启动时会打一条 WARN 说明如何放开（见 server.logFirewallState），
// 且**升级上来的旧配置不会被这条默认值波及**（见 store.go 的 v10 迁移块）。
func defaultPanelFirewall() PanelFirewall {
	return PanelFirewall{
		Enabled:          true,
		Mode:             FirewallModeLAN,
		RateLimit:        DefaultFirewallRateLimit,
		AutoBan:          true,
		AutoBanThreshold: DefaultFirewallAutoBanThreshold,
		AutoBanMinutes:   DefaultFirewallAutoBanMinutes,
	}
}

// normalizePanelFirewall 就地规范化一份防火墙设置：统一模式取值、夹住越界数值、整理名单。
// 幂等——对同一份设置跑两次与跑一次结果相同（迁移块与加载期都会调它）。
//
// **不判断这份设置会不会把当前管理员关在门外**：那要知道"当前请求来自哪里"，
// 是接口层的事（见 server.checkFirewallLockout）。
func normalizePanelFirewall(f *PanelFirewall) {
	switch f.Mode {
	case FirewallModeLAN, FirewallModeAll:
	default:
		// 空值与认不出的值一律落到 lan。未知取值往严的方向落是安全设置的通例：
		// 反过来的话，把 mode 手改成一个错别字就等于把防火墙的范围限制整个关掉。
		f.Mode = FirewallModeLAN
	}

	// 限速：0 是有意义的取值（不限速），只夹掉负数与溢出。
	f.RateLimit = clampInt(f.RateLimit, 0, MaxFirewallRateLimit)

	// 阈值与时长：0 **不是**"关闭"（关闭是 AutoBan 那个开关），因此非正值回落到默认值而不是夹到 0。
	// 夹到 0 的后果分别是"一次超限就封"和"封了立刻过期"，两个都不是用户想表达的意思。
	if f.AutoBanThreshold <= 0 {
		f.AutoBanThreshold = DefaultFirewallAutoBanThreshold
	}
	f.AutoBanThreshold = clampInt(f.AutoBanThreshold, 1, MaxFirewallAutoBanThreshold)
	if f.AutoBanMinutes <= 0 {
		f.AutoBanMinutes = DefaultFirewallAutoBanMinutes
	}
	f.AutoBanMinutes = clampInt(f.AutoBanMinutes, 1, MaxFirewallAutoBanMinutes)

	f.AllowIPs = normalizeIPList(f.AllowIPs)
	f.DenyIPs = normalizeIPList(f.DenyIPs)
}

// normalizeIPList 去空白、去重、丢掉解析不出来的条目、截断到 MaxFirewallIPs。
//
// **丢掉写错的条目**是刻意的，与 restart 的日期同理，但这里的代价更高所以更值得做：
// 一条 ipx.ParseCIDRs 认不出的写法在匹配时本来就永远不命中，留在名单里只会让人
// 以为它生效了。放到防火墙的语境里，那意味着用户把自己的办公室 IP 写错一个字符、
// 存进允许名单、然后放心地切成"只允许局域网"——下一次刷新就把自己关在门外了。
// 存完之后那一条从列表里消失，是唯一能在**做出锁死决定之前**看到的反馈。
//
// 不排序：名单是用户手写的，顺序里可能有他自己的分组含义（匹配与顺序无关）。
func normalizeIPList(items []string) []string {
	if len(items) == 0 {
		return nil
	}
	seen := make(map[string]bool, len(items))
	out := make([]string, 0, len(items))
	for _, raw := range items {
		s := strings.TrimSpace(raw)
		if s == "" || seen[s] {
			continue
		}
		if len(ipx.ParseCIDRs([]string{s})) == 0 {
			continue
		}
		seen[s] = true
		out = append(out, s)
		if len(out) >= MaxFirewallIPs {
			break
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// Valid 判断这份设置是否"能真的跑起来"。关闭状态一律放过——关着的防火墙填成什么样都不影响行为，
// 拦下来只会让用户没法先关掉再慢慢改。
//
// 校验的是**用户提交的原始值**（接口层在 normalize 之前调用），因此它能把"填了个负数"
// 报回界面，而不是被 normalize 悄悄改成别的数之后让人以为存对了。
func (f PanelFirewall) Valid() error {
	if !f.Enabled {
		return nil
	}
	switch f.Mode {
	case FirewallModeLAN, FirewallModeAll:
	default:
		return fmt.Errorf("访问范围无效")
	}
	if f.RateLimit < 0 || f.RateLimit > MaxFirewallRateLimit {
		return fmt.Errorf("每秒请求数需在 0-%d 之间（0 表示不限）", MaxFirewallRateLimit)
	}
	if len(f.AllowIPs) > MaxFirewallIPs || len(f.DenyIPs) > MaxFirewallIPs {
		return fmt.Errorf("名单最多 %d 条", MaxFirewallIPs)
	}
	if f.AutoBan {
		if f.AutoBanThreshold < 1 || f.AutoBanThreshold > MaxFirewallAutoBanThreshold {
			return fmt.Errorf("自动封禁阈值需在 1-%d 之间", MaxFirewallAutoBanThreshold)
		}
		if f.AutoBanMinutes < 1 || f.AutoBanMinutes > MaxFirewallAutoBanMinutes {
			return fmt.Errorf("自动封禁时长需在 1-%d 分钟之间", MaxFirewallAutoBanMinutes)
		}
	}
	return nil
}

// NormalizePanelFirewall 对**外部提交**的防火墙设置执行与加载期完全相同的规范化。
// 面板保存前调用它，使"存进去的"与"加载后跑的"是同一份值。
func NormalizePanelFirewall(f *PanelFirewall) {
	if f == nil {
		return
	}
	normalizePanelFirewall(f)
}
