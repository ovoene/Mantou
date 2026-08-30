package server

import (
	"fmt"
	"net"
	"strings"

	"mantou/internal/config"
)

// 面板端口是全项目唯一一个"改错了就没法在界面上改回来"的配置。
//
// 保存之后的链路是：respondOK → requestPanelRestart → RestartPanel → 关掉旧监听 →
// 用新端口重建 → 绑定失败 → servePanels 收到错误直接返回 → **整个进程退出**。
// 而这个进程里住着八个模块：证书续期、DDNS、端口转发、反向代理、消息路由一起下线；
// 面板也已经不在了，唯一的恢复方式是登机器手改 config.json。
//
// 触发条件很平凡：端口被本机另一个程序占了，或者普通用户想绑 80。
// 所以这一步必须在落盘之前做完（见 5-J / 2.13-A）。

// checkPanelPort 在新端口写进配置之前确认它能用。返回的错误直接面向用户。
//
// cfg 是这次要落盘的那份配置：试绑用的监听地址、以及"同进程里还有谁占着这个端口"都以它为准。
// running 是进程此刻正在监听的端口，与它相同就放行且不试绑——自己正占着，试绑必然失败。
// 超出范围的值同样放行：保存逻辑会跳过它（既有行为，不在这一步改）。
func (s *Server) checkPanelPort(cfg *config.Config, running, port int) error {
	if port <= 0 || port > 65535 || port == running {
		return nil
	}
	// 先查同进程内的其他监听。这两种冲突试绑也能发现，但报得出"是谁占着"
	// 比丢一句系统级的"地址已在使用"有用得多，用户看完就知道该怎么办。
	//
	// 地址族传空串（不限）：面板绑的是 Panel.Listen，可能是双栈，与任何一族的
	// Web 服务监听都撞得上。这里宁可多报一个"可能撞"，也不要漏掉一个真会撞的。
	if name, _, ok := cfg.WebServiceListenerOnPort(port, ""); ok {
		// 没起名字的服务只说"Web 服务"，不要留一对空引号。
		who := "Web 服务"
		if name = strings.TrimSpace(name); name != "" {
			who = "Web 服务「" + name + "」"
		}
		return fmt.Errorf("端口 %d 已被%s占用，请换一个端口", port, who)
	}
	if cfg.Webhook.Enabled && cfg.Webhook.Port == port {
		return fmt.Errorf("端口 %d 已被消息路由占用，请换一个端口", port)
	}
	// 再真绑一次。本机其他程序占用、以及"普通账户绑不了 1024 以下"这两种情况
	// 只有这一步能发现——配置校验看不出来，而等到重启时才发现就已经太晚了。
	//
	// 绑定地址必须与面板真正会用的那个一致（Panel.Listen 是可配的），
	// 否则"0.0.0.0 上能绑"并不能说明"127.0.0.1 上也能绑"，反之亦然。
	if err := probeListen(addr(cfg.Panel.Listen, port)); err != nil {
		s.deps.Log.Warn("面板端口预试绑定失败，已拒绝保存", "port", port, "err", err)
		hint := "可能已被本机其他程序占用"
		if port < 1024 {
			hint = "可能已被本机其他程序占用，或当前账户没有权限绑定 1024 以下的端口"
		}
		return fmt.Errorf("端口 %d 无法绑定：%s。配置未保存，面板仍在原端口上", port, hint)
	}
	return nil
}

// probeListen 试着监听一下再立刻关掉。
//
// 这一步与真正的绑定之间存在时间差：中间被别的程序抢走，重启依然会失败。
// 它挡不住这种竞争，挡的是"保存时就已经绑不上"——那才是实际会发生的情形。
func probeListen(address string) error {
	ln, err := net.Listen("tcp", address)
	if err != nil {
		return err
	}
	return ln.Close()
}
