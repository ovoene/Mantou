package webservice

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"syscall"

	"mantou/internal/ipx"
	"mantou/internal/netguard"
)

// 本文件是反代与主动探测共用的那道拨号闸（审计 S-05）。
//
// # 为什么要在拨号期再判一次
//
// 「后端不许指向本机的面板管理端口」这件事已经有两道：保存期拒绝
// （internal/server 的 validateWebService）与 Reload 期跳过并告警（webservice.go）。
// 两道都调 config.WebChild.UpstreamTargetingLocalPort，而它**刻意不查 DNS**
//（理由见 internal/ipx/local.go 文件头：保存那一刻的解析结果不构成运行期的保证）。
//
// 于是留了一个口子：后端写成 `http://nas.lan:25666` 这样一个解析到本机的**域名**时，
// 前两道都判不出来——字符串既不是 IP 字面量也不是 localhost。请求照样打到面板上，
// 面板看到的来源仍然是 127.0.0.1，回环豁免、拒绝名单、自动封禁、「仅局域网」、
// 审计日志一起失效（这一组失效的完整说明在 internal/ipx/local.go 文件头）。
//
// 拨号期是唯一能补上这一刀的地方：Control 钩子拿到的是**已经解析好**的 ip:port，
// 域名到这里已经变成了地址，重绑定也躲不过——每次拨号都会重新判一遍。
//
// # 为什么探测也要挂同一个
//
// 与 netguard.BlockLinkLocal 挂两处是同一个理由（见 webservice.go 的 newProbeClient）：
// 探测与真实转发必须走同一条红线。只在转发侧拦的话，面板上那一栏会显示「链接正常」
//（探测放行），而真实访问是 502——最难排查的正是这种界面与实际不一致。

// ErrPanelPortDial 表示一次后端拨号因目标是本机的面板管理端口而被拦下。
//
// 与 netguard 那两个错误分开，是为了让访问日志的 Reason 字段能一眼认出是哪一道闸：
// 那两个一个是用户开的内网防护、一个是无条件的链路本地拦截，这一个是「后端指向面板」。
var ErrPanelPortDial = errors.New("已拦截指向面板管理端口的后端连接")

// dialGuard 是反代 Transport 与主动探测客户端共用的 net.Dialer.Control 钩子：
// 先过链路本地那道窄拦截，再判「解析后的目标是不是本机的面板端口」。
//
// 顺序无所谓（两道互不重叠），按 BlockLinkLocal 在前是因为它是无条件生效的那一道。
func (m *Module) dialGuard(network, address string, c syscall.RawConn) error {
	if err := netguard.BlockLinkLocal(network, address, c); err != nil {
		return err
	}
	return m.blockPanelPortDial(address)
}

// blockPanelPortDial 拦下「解析后指向本机面板管理端口」的拨号。
//
// 判据两条都要满足：端口等于面板端口，且地址属于本机（回环、未指定、或本机任一网卡上的
// 地址——局域网地址那一种是同一个洞的弱化版，同样要拦，见 ipx.IsLocalIP）。
//
// 拿不准时**放过**，与 BlockLinkLocal 同向而与 netguard.controlBlockPrivate 相反：
// 这一道无条件生效、用户关不掉，误拦的代价是一条合法的反代规则打不开而且没处关。
// 面板端口没配（panelPort <= 0，只可能出现在还没 Reload 过的模块上）同理放过。
func (m *Module) blockPanelPortDial(address string) error {
	panelPort := int(m.panelPort.Load())
	if panelPort <= 0 {
		return nil
	}
	host, portStr, err := net.SplitHostPort(address)
	if err != nil {
		return nil
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port != panelPort {
		return nil
	}
	// 端口对上了才去查本机地址表：IsLocalHost 里那一步要枚举网卡（带 30 秒缓存），
	// 而绝大多数拨号的端口根本不是面板端口，先比端口能让这条路上多数请求不碰它。
	if !ipx.IsLocalHost(host) {
		return nil
	}
	return fmt.Errorf("%w：目标 %s 解析到本机的面板管理端口 %d（面板会把所有请求都当成本机来源，"+
		"入站防护与审计日志将全部失效）", ErrPanelPortDial, strings.TrimSpace(address), panelPort)
}
