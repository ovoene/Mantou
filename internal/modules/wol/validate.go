package wol

import (
	"fmt"

	"mantou/internal/config"
)

// MaxIfaceNameLen 网卡名长度上限。Linux 的 IFNAMSIZ 是 16（含结尾 0），
// Windows 的「友好名称」可以很长（如「以太网 2」「Intel(R) Wi-Fi 6 AX201 160MHz」），
// 故取一个宽松但有限的值，只用于拦住明显异常的输入。
const MaxIfaceNameLen = 128

// ValidateTarget 校验一台设备「往哪发」的参数：MAC、广播地址、端口，以及网卡名长度。
//
// 这三项与「什么时候发」（定时唤醒的时间/次数/间隔，见 server.validateWOL）分开，
// 因为两者出错的后果完全不同：
//   - 时间字段写坏，调度器当天不发送，是个静默但无害的哑火；
//   - 这里的三项写坏，后果是「每秒往一个不该发的地址持续发 102 字节 UDP」
//     （原因见 ValidBroadcast）或「白发一整天唤不醒任何东西的包」。
//
// 因此只有这一组会在配置加载 / 整份导入之后被重新校验一遍，非法项直接禁用
// （见 InvalidDevices）——手工编辑 config.json 与导入备份这两条路径都不经过接口层校验。
//
// 网卡名刻意**不校验是否真实存在**：配置可能是从另一台机器导入 / 恢复的，
// 也可能网卡此刻正好没插网线。名字不存在的后果发生在发送时，会带着
// 「网卡 X 不存在、未启用或没有 IPv4 广播地址」落到列表的结果列上——可见且可自查。
func ValidateTarget(d config.WOLDevice) error {
	if _, err := ParseMAC(d.MAC); err != nil {
		return err
	}
	if d.Port != 0 && (d.Port < 1 || d.Port > 65535) {
		return fmt.Errorf("端口需在 1-65535 之间，留空（0）表示使用默认 9")
	}
	if err := ValidBroadcast(d.Broadcast); err != nil {
		return err
	}
	if len(d.Interface) > MaxIfaceNameLen {
		return fmt.Errorf("网卡名过长（上限 %d 字符）", MaxIfaceNameLen)
	}
	return nil
}

// InvalidDevice 一台发送参数非法的设备，用于告警与禁用。
type InvalidDevice struct {
	ID     string
	Name   string
	Reason string
}

// InvalidDevices 挑出**已启用**且发送参数非法的设备。只读，不改动入参。
//
// 只看已启用的：用户主动关掉的设备无论字段对不对都不会发包，为它告警只是每次启动刷一行日志。
// 这同时让「告警 + 禁用」这套动作天然幂等——禁用之后本函数就不再报它了。
func InvalidDevices(devices []config.WOLDevice) []InvalidDevice {
	var bad []InvalidDevice
	for i := range devices {
		if !devices[i].Enabled {
			continue
		}
		if err := ValidateTarget(devices[i]); err != nil {
			bad = append(bad, InvalidDevice{
				ID:     devices[i].ID,
				Name:   devices[i].Name,
				Reason: err.Error(),
			})
		}
	}
	return bad
}

// DisableInvalidDevices 就地关掉发送参数非法的设备的开关，返回被关掉的清单（供调用方逐条告警）。
//
// 为什么是禁用而不是丢弃或原样运行：
//   - 丢弃会让用户的配置在一次升级 / 导入后凭空少了几台设备，且无从得知少了什么；
//   - 原样运行则意味着带病发包（往公网地址、或每次都失败），而界面上看不出异常。
//
// 禁用保住了配置本体：设备还在列表里，开关是关的，用户改好字段再打开即可。
func DisableInvalidDevices(devices []config.WOLDevice) []InvalidDevice {
	bad := InvalidDevices(devices)
	if len(bad) == 0 {
		return nil
	}
	disable := make(map[string]bool, len(bad))
	for _, b := range bad {
		disable[b.ID] = true
	}
	for i := range devices {
		// 按 ID 匹配，同时再确认一次它确实非法：ID 为空的历史条目（match 到同一个 ""）
		// 不会因为别人非法而被连带关掉。
		if disable[devices[i].ID] && devices[i].Enabled && ValidateTarget(devices[i]) != nil {
			devices[i].Enabled = false
		}
	}
	return bad
}
