package server

import (
	"fmt"
	"net"
	"net/http"

	"github.com/gin-gonic/gin"

	"mantou/internal/config"
	"mantou/internal/ipx"
)

// 面板入站防火墙的接口层：自锁校验 + 自动封禁名单的查看与解除。
// 判定逻辑本身在 firewall.go，配置规则在 internal/config/firewall.go。

// fwBanListLimit 「当前封禁」接口一次最多返回多少条。
//
// 封禁表最多 fwBanMaxEntries（4096）条，全量下发对一个只是想看看谁被拦了的
// 设置页没有意义，且会让这个接口的响应体随攻击规模膨胀。
// 总数另行返回（total 字段），不会因为截断而看不出实际规模。
const fwBanListLimit = 200

// checkFirewallLockout 判断这份**已规范化**的防火墙设置会不会把提交它的人本人挡在外面。
//
// 这道校验存在的理由很直接：这个功能唯一严重的失败模式就是用户把自己关在门外，
// 而它发生得毫无征兆——保存成功、页面正常，直到下一次刷新才发现连不上，
// 那时已经没有入口可以改回来了（面板自己就是唯一的配置界面）。
// 剩下的补救手段是登录宿主机手改 config.json，而"能登录宿主机"恰恰是很多用户没有的前提。
//
// 判定复用 decide 的同一套顺序，因此它与真正生效的规则不可能走偏：
// 拒绝名单 → 回环 → 允许名单 → 访问范围。限速与自动封禁不参与——
// 那两项都会自愈（等一秒 / 等到期），不构成"锁死"。
// 范围那一步同样按「不是 all 就算受限」判（与 decide 同向，理由见那里）。
//
// 拿不到对端 IP 时**放行**这次保存。这一处与 decide 的失败关闭方向相反，
// 是有意的：这里的"失败"意味着我们无法判断，而无法判断时拦下用户改自己的设置，
// 等于凭一个解析错误剥夺他的配置权。真正的访问控制仍然是失败关闭的，
// 这一道只是提醒，越过它的代价由 Force 那条路径显式承担。
func checkFirewallLockout(fw config.PanelFirewall, r *http.Request) error {
	if !fw.Enabled {
		return nil
	}
	ip := ipx.ClientIP(r)
	if ip == nil {
		return nil
	}
	who := ip.String()
	if ipx.NewMatcher(fw.DenyIPs).Match(ip) {
		return fmt.Errorf("拒绝名单包含你当前的来源地址 %s，保存后你将无法访问面板", who)
	}
	if ip.IsLoopback() {
		return nil
	}
	if ipx.NewMatcher(fw.AllowIPs).Match(ip) {
		return nil
	}
	if fw.Mode != config.FirewallModeAll && !ipx.IsLAN(ip) {
		return fmt.Errorf("你当前从 %s 访问面板，它不属于局域网；改为「仅局域网」后你将无法访问面板。"+
			"如需继续，请先把该地址加入允许名单", who)
	}
	return nil
}

// handleGetFirewallBans 返回当前仍在生效的自动封禁。
//
// 只读内存，不落盘：自动封禁本来就只存在于内存（理由见 config.PanelFirewall.AutoBanMinutes）。
func (s *Server) handleGetFirewallBans(c *gin.Context) {
	if s.firewall == nil {
		respondError(c, http.StatusServiceUnavailable, "防火墙未就绪")
		return
	}
	list := s.firewall.banList(fwBanListLimit)
	total := s.firewall.banCount()
	if list == nil {
		list = []fwBanView{}
	}
	respondOK(c, gin.H{
		"items": list,
		"total": total,
		"limit": fwBanListLimit,
	})
}

// handleClearFirewallBans 解除自动封禁：带 ip 参数解除单个，不带则全部解除。
//
// 需要这个口子是因为自动封禁是机器下的判断，一定会有误伤——
// 家里几个人共用一个出口 IP、某个客户端在重试风暴里刷爆了限速，都会撞上。
// 没有解除入口的话，误伤只能等封禁自然到期，而用户此刻多半正被挡在门外
// （他得先能进来才能点这个按钮——所以真正的自救仍然是回环豁免与 Force 确认那两条）。
func (s *Server) handleClearFirewallBans(c *gin.Context) {
	if s.firewall == nil {
		respondError(c, http.StatusServiceUnavailable, "防火墙未就绪")
		return
	}
	var req struct {
		IP string `json:"ip"`
	}
	// 请求体可以为空（表示全部解除），因此解析失败不当错误处理。
	_ = c.ShouldBindJSON(&req)
	if req.IP != "" {
		if net.ParseIP(req.IP) == nil {
			respondError(c, http.StatusBadRequest, "IP 地址无效")
			return
		}
		ok := s.firewall.unban(req.IP)
		s.deps.Log.Info("面板防火墙解除封禁", "ip", req.IP, "wasBanned", ok)
		respondOK(c, gin.H{"ok": true, "cleared": boolToInt(ok)})
		return
	}
	n := s.firewall.clearBans()
	s.deps.Log.Info("面板防火墙清空封禁名单", "cleared", n)
	respondOK(c, gin.H{"ok": true, "cleared": n})
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
