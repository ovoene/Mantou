package server

import (
	"strings"
	"testing"

	"mantou/internal/config"
)

// 端口转发的**监听端口**不得撞上面板管理端口（审计 L-01）。
//
// 这一条与 validate_forward_panel_test.go 里那组是对称的两半：那边管「目标」，
// 这边管「监听」。监听侧的后果更重——面板监听 0.0.0.0（Panel.Listen 固定值，
// 不在设置 UI 暴露），而模块的 ReloadAll 跑在面板 Start 之前，先绑端口的是转发：
//
//   - Linux：面板随后 bind 失败，进程以「listen tcp …: address already in use」退出，
//     面板自锁，只能手工改 config.json 才能恢复；
//   - Windows：两者共存，回环仍回面板但所有非回环网卡落到转发上，远程管理入口静默消失。
//
// 这组用例盯四处最容易在日后退化的地方：
//
//  1. **端口范围要盖住整段**。`26098-26102` 这种"范围里恰好盖住面板端口"的写法必须拦，
//     那是最不容易被用户自己发现的一种。
//  2. **与 Bind 无关**。面板绑 0.0.0.0，所以填什么 Bind 都撞得上；写成"只有 Bind 为空
//     才拦"会漏掉 Windows 上那种"两者共存、远程入口丢失"的形状。
//  3. **只看启用的规则**。禁用规则不绑端口，撞不上；而"存着禁用 → 回头再打开"由
//     registerCRUD 的 toggle 兜住（它在启用侧调 validate），所以放行不留口子。
//  4. **不能拦过头**。面板端口以外的监听端口、整段避开面板端口的范围都得放行。
func TestValidateForwardRejectsPanelListenPort(t *testing.T) {
	const panelPort = 9000
	cfg := &config.Config{}
	cfg.Panel.Port = panelPort

	// base 能通过其余所有校验；各用例只改与「监听端口是否撞面板端口」有关的字段。
	// 目标固定指向远端主机，避免被目标侧那条校验提前拦下。
	base := config.ForwardRule{
		Enabled: true, Protocol: "tcp",
		ListenPort: panelPort, TargetHost: "203.0.113.9", TargetPort: 8080,
	}

	cases := []struct {
		name    string
		mod     func(r *config.ForwardRule)
		wantErr bool
	}{
		// —— 必须拒绝 ——
		{"单端口正好是面板端口", func(r *config.ForwardRule) {}, true},
		{
			"端口段盖住面板端口（面板端口在中间）",
			func(r *config.ForwardRule) { r.ListenPort, r.ListenPortEnd = panelPort-2, panelPort+2 },
			true,
		},
		{
			"端口段的起点就是面板端口",
			func(r *config.ForwardRule) { r.ListenPort, r.ListenPortEnd = panelPort, panelPort+4 },
			true,
		},
		{
			"端口段的终点就是面板端口",
			func(r *config.ForwardRule) { r.ListenPort, r.ListenPortEnd = panelPort-4, panelPort },
			true,
		},
		{
			// 面板绑 0.0.0.0，指定 Bind 一样撞得上（Windows 上表现为静默抢走非回环网卡）。
			"指定了 Bind 也照样拒",
			func(r *config.ForwardRule) { r.Bind = "127.0.0.1" },
			true,
		},
		{"UDP 也拒（面板端口不分协议保留）", func(r *config.ForwardRule) { r.Protocol = "udp" }, true},

		// —— 必须放行 ——
		{"面板端口 +1", func(r *config.ForwardRule) { r.ListenPort = panelPort + 1 }, false},
		{"面板端口 -1", func(r *config.ForwardRule) { r.ListenPort = panelPort - 1 }, false},
		{
			"端口段整段在面板端口之上",
			func(r *config.ForwardRule) { r.ListenPort, r.ListenPortEnd = panelPort+1, panelPort+5 },
			false,
		},
		{
			"端口段整段在面板端口之下",
			func(r *config.ForwardRule) { r.ListenPort, r.ListenPortEnd = panelPort-5, panelPort-1 },
			false,
		},
		{
			// 禁用规则不绑端口，撞不上；能存下来才不会把一份手改过的配置锁死在
			// 「改也改不动、关也关不掉」里（与列表条数上限只拦新增是同一个道理）。
			"禁用的规则可以存下来",
			func(r *config.ForwardRule) { r.Enabled = false },
			false,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := base
			c.mod(&r)
			err := validateForward(cfg, r)
			if (err != nil) != c.wantErr {
				t.Fatalf("validateForward 返回 err=%v，wantErr=%v", err, c.wantErr)
			}
			if c.wantErr && !strings.Contains(err.Error(), "监听端口") {
				// 拒是拒了，但如果是被别的校验拦下的，这条用例就没测到东西。
				t.Fatalf("拒绝理由里没提到监听端口，可能被其他校验提前拦下：%v", err)
			}
		})
	}
}

// TestValidateForwardListenPanelPortUnsetPassesThrough 面板端口缺失时这条校验不生效。
//
// 与目标侧同一个边界（见 TestValidateForwardPanelPortUnsetPassesThrough 的说明）：
// 接口层永远传 Snapshot()，Panel.Port 由 config 默认值兜底不可能为 0；
// 而"没有面板端口"这个前提下本就无从判断撞不撞，此时拒绝反而会挡住合法规则。
func TestValidateForwardListenPanelPortUnsetPassesThrough(t *testing.T) {
	r := config.ForwardRule{
		Enabled: true, Protocol: "tcp",
		ListenPort: 9000, TargetHost: "203.0.113.9", TargetPort: 8080,
	}
	if err := validateForward(nil, r); err != nil {
		t.Fatalf("cfg 为 nil 时不应因面板端口被拒：%v", err)
	}
	if err := validateForward(&config.Config{}, r); err != nil {
		t.Fatalf("面板端口为 0 时不应被拒：%v", err)
	}
}
