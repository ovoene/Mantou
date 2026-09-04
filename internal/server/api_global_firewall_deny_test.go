package server

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/gin-gonic/gin"

	"mantou/internal/config"
	"mantou/internal/inboundfw"
	"mantou/internal/logx"
)

// 本文件钉住「把自动封禁的来源升级成拒绝名单」这条口子（POST /global-firewall/bans/deny）。
//
// 它做的是两件必须同生共死的事：把地址写进配置里的拒绝名单（永久、落盘），
// 以及解除那条临时封禁。做坏的方式各有各的难看，且都不会在界面上直接暴露：
//   - 名单有 GlobalFirewallMaxIPs 条硬上限，封禁表能装上万条。截断若不报出来，
//     用户会以为"一键"之后所有来源都封死了，实际后半截当场恢复访问；
//   - 因名单满而没写进去的地址若也被解除封禁，那就是**主动**放走了确认过的攻击者；
//   - "一键"取的必须是全部生效封禁，不是界面上那 gfwBanListLimit 条。

// denyResp 是 /global-firewall/bans/deny 解开 { data } 信封后的响应体。
type denyResp struct {
	Data struct {
		Added    int      `json:"added"`
		Skipped  int      `json:"skipped"`
		Capped   bool     `json:"capped"`
		MaxIps   int      `json:"maxIps"`
		Unbanned int      `json:"unbanned"`
		DenyIPs  []string `json:"denyIps"`
	} `json:"data"`
}

// newDenyTestServer 造一个"服务防护开着、一次握手异常即封"的面板。
//
// 刻意走 custom 档位并把突发阈值压到 1：预设档位下这组数值由服务端按档位重写，
// 而这些用例要的只是"封禁表里有确定的几条"，不关心封禁是怎么攒出来的。
func newDenyTestServer(t *testing.T) *Server {
	t.Helper()
	gin.SetMode(gin.TestMode)
	m := config.NewManager(filepath.Join(t.TempDir(), "config.json"))
	if err := m.Load(); err != nil {
		t.Fatal(err)
	}
	if err := m.Update(func(cfg *config.Config) {
		cfg.GlobalFirewall = config.GlobalFirewall{
			Enabled: true, Level: config.GlobalFirewallLevelCustom, AutoBan: true,
			WindowSeconds: 60, WindowLimit: config.MaxGlobalFirewallLimit,
			BurstSeconds: 60, BurstLimit: 1,
			BanMinutes: 10, MemoryMB: config.DefaultGlobalFirewallMemoryMB,
		}
	}); err != nil {
		t.Fatal(err)
	}
	log := logx.New(logx.Options{})
	return &Server{deps: Deps{Config: m, Log: log}, gfw: inboundfw.New(m, log)}
}

// banSource 把一个来源打进封禁表（走真实的 Note 路径，不去动内部字段）。
func banSource(t *testing.T, s *Server, ip string) {
	t.Helper()
	if !s.gfw.Note(net.ParseIP(ip), "") {
		t.Fatalf("%s 应当场被封禁，测试前提不成立", ip)
	}
}

// postDeny 调一次升级接口，返回状态码与解开信封后的响应体。
func postDeny(t *testing.T, s *Server, body string) (int, denyResp) {
	t.Helper()
	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	ctx.Request = newSchemeRequest(t, false, http.MethodPost, "/global-firewall/bans/deny", body)
	s.handleDenyGlobalFirewallBans(ctx)
	var out denyResp
	if w.Code == http.StatusOK {
		if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
			t.Fatalf("解析响应失败: %v（原文 %s）", err, w.Body.String())
		}
	}
	return w.Code, out
}

// denyListOf 取配置里当前的拒绝名单。
func denyListOf(s *Server) []string {
	return s.deps.Config.Snapshot().GlobalFirewall.DenyIPs
}

func containsStr(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}

// 单个升级：写进名单、解除封禁，且只动它自己。
func TestDenyBanSingleAddsAndUnbans(t *testing.T) {
	s := newDenyTestServer(t)
	const target, bystander = "203.0.113.7", "198.51.100.5"
	banSource(t, s, target)
	banSource(t, s, bystander)

	code, res := postDeny(t, s, `{"ip":"`+target+`"}`)
	if code != http.StatusOK {
		t.Fatalf("应成功，得到 %d", code)
	}
	if res.Data.Added != 1 || res.Data.Skipped != 0 || res.Data.Capped {
		t.Fatalf("应为新增 1 条：added=%d skipped=%d capped=%v",
			res.Data.Added, res.Data.Skipped, res.Data.Capped)
	}
	if res.Data.Unbanned != 1 {
		t.Fatalf("加入拒绝名单后那条临时封禁就没有意义了，应顺手解除，unbanned=%d", res.Data.Unbanned)
	}
	if !containsStr(res.Data.DenyIPs, target) {
		t.Fatalf("回传的名单里应有 %s，实际 %v", target, res.Data.DenyIPs)
	}
	// 落盘的那份才是判定用的（下次加载、以及 decide 读的都是它）。
	if !containsStr(denyListOf(s), target) {
		t.Fatalf("配置里的拒绝名单应有 %s，实际 %v", target, denyListOf(s))
	}
	// 没被点到的那条必须原样封着：升级是逐条的，不能顺手清了整张表。
	if n := s.gfw.BanCount(); n != 1 {
		t.Fatalf("应只解除目标那一条，封禁表剩 %d 条（期望 1）", n)
	}
	if containsStr(denyListOf(s), bystander) {
		t.Fatalf("%s 没被点到，不该进拒绝名单", bystander)
	}
}

// 重复升级同一个来源：算 skipped，名单里不留重复条目。
//
// 这条路一定会被走到：名单是永久的，而同一个来源过一阵子又被封一次是常态。
func TestDenyBanTwiceDeduplicates(t *testing.T) {
	s := newDenyTestServer(t)
	const target = "203.0.113.9"
	banSource(t, s, target)

	if _, res := postDeny(t, s, `{"ip":"`+target+`"}`); res.Data.Added != 1 {
		t.Fatalf("首次应新增 1 条，实际 added=%d", res.Data.Added)
	}
	_, res := postDeny(t, s, `{"ip":"`+target+`"}`)
	if res.Data.Added != 0 || res.Data.Skipped != 1 {
		t.Fatalf("重复升级应算 skipped：added=%d skipped=%d", res.Data.Added, res.Data.Skipped)
	}
	if res.Data.Unbanned != 0 {
		t.Fatalf("上一轮已解除封禁，这次无可解除，unbanned=%d", res.Data.Unbanned)
	}
	n := 0
	for _, v := range denyListOf(s) {
		if v == target {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("拒绝名单里 %s 出现了 %d 次，应恰好 1 次：名单有硬上限，重复条目等于白占位置", target, n)
	}
}

// 一键升级取的是**全部**生效封禁，不是界面上那 gfwBanListLimit 条。
//
// 刻意封满 gfwBanListLimit+1 条：若实现照界面那份限额去办，用户点完"一键加入黑名单"
// 会看到列表清空、以为都封死了，而多出来的那些当场恢复访问。
func TestDenyBansAllCoversWholeTableNotJustTheDisplayedPage(t *testing.T) {
	s := newDenyTestServer(t)
	total := gfwBanListLimit + 1
	if total > config.GlobalFirewallMaxIPs {
		t.Skipf("名单上限 %d 装不下 %d 条，本用例的前提不成立", config.GlobalFirewallMaxIPs, total)
	}
	for i := 0; i < total; i++ {
		banSource(t, s, fmt.Sprintf("203.0.113.%d", i+1))
	}
	if n := s.gfw.BanCount(); n != total {
		t.Fatalf("封禁表应有 %d 条，实际 %d", total, n)
	}

	code, res := postDeny(t, s, `{"all":true}`)
	if code != http.StatusOK {
		t.Fatalf("应成功，得到 %d", code)
	}
	if res.Data.Added != total || res.Data.Capped {
		t.Fatalf("应全部写入名单：added=%d（期望 %d）capped=%v", res.Data.Added, total, res.Data.Capped)
	}
	if res.Data.Unbanned != total {
		t.Fatalf("写入名单的都该解除封禁，unbanned=%d（期望 %d）", res.Data.Unbanned, total)
	}
	if n := s.gfw.BanCount(); n != 0 {
		t.Fatalf("封禁表应清空，实际剩 %d 条", n)
	}
}

// 名单满了：截断必须报出来，而没写进去的来源必须**保持封禁**。
//
// 这是整条口子最要紧的一条。悄悄丢掉后半截会让用户以为都封死了；
// 而把没写进名单的来源一并解封，等于亲手放走确认过的攻击者——两者都不会有任何界面提示。
func TestDenyBansAllReportsCapAndKeepsUnlistedBanned(t *testing.T) {
	s := newDenyTestServer(t)
	// 预先把名单填到只剩一个位置。
	prefill := make([]string, 0, config.GlobalFirewallMaxIPs-1)
	for i := 0; i < config.GlobalFirewallMaxIPs-1; i++ {
		prefill = append(prefill, fmt.Sprintf("198.18.%d.%d", i/254, i%254+1))
	}
	if err := s.deps.Config.Update(func(cfg *config.Config) {
		cfg.GlobalFirewall.DenyIPs = prefill
	}); err != nil {
		t.Fatal(err)
	}
	banSource(t, s, "203.0.113.21")
	banSource(t, s, "203.0.113.22")

	_, res := postDeny(t, s, `{"all":true}`)
	if res.Data.Added != 1 || !res.Data.Capped {
		t.Fatalf("名单只剩一个位置，应写入 1 条并报截断：added=%d capped=%v",
			res.Data.Added, res.Data.Capped)
	}
	if res.Data.MaxIps != config.GlobalFirewallMaxIPs {
		t.Fatalf("maxIps 应为 %d，实际 %d：界面用它告诉用户还能装多少条",
			config.GlobalFirewallMaxIPs, res.Data.MaxIps)
	}
	if res.Data.Unbanned != 1 {
		t.Fatalf("只有写进名单的那条该解封，unbanned=%d（期望 1）", res.Data.Unbanned)
	}
	// 剩下的那条是谁取决于封禁表的排序，用例不去猜；要钉的是"它还封着、且没进名单"。
	items, _ := s.gfw.BanSnapshot(0)
	if len(items) != 1 {
		t.Fatalf("没写进名单的来源必须保持封禁，封禁表实际剩 %d 条（期望 1）", len(items))
	}
	if containsStr(denyListOf(s), items[0].IP) {
		t.Fatalf("%s 因名单已满而未被接收，却出现在名单里", items[0].IP)
	}
	if n := len(denyListOf(s)); n != config.GlobalFirewallMaxIPs {
		t.Fatalf("名单应正好填满 %d 条，实际 %d", config.GlobalFirewallMaxIPs, n)
	}
}

// banWithMinutes 用指定封禁时长打一条封禁。
//
// 时长各不相同，是为了让 BanSnapshot 的顺序可预期：它按到期时刻倒序排（见 BanSnapshot），
// 于是"谁先被处理"由用例说了算，而不是靠同一毫秒内建表的先后碰运气。
func banWithMinutes(t *testing.T, s *Server, ip string, minutes int) {
	t.Helper()
	if err := s.deps.Config.Update(func(cfg *config.Config) {
		cfg.GlobalFirewall.BanMinutes = minutes
	}); err != nil {
		t.Fatal(err)
	}
	banSource(t, s, ip)
}

// 名单满了之后，排在后面的来源仍要逐个处理完。
//
// 这一条钉的是那句 continue（而不是 break）：撞上上限就跳出循环的话，排在后面
// 那些"本来就已在名单里"的来源会被整段跳过——既不算 skipped，也不会解除封禁，
// 于是它们明明已被永久拒绝，却还占着有容量上限的封禁表。
// 界面上看不出区别：加起来的条数对得上，只是有些封禁再也不会消失。
func TestDenyBansAllKeepsScanningPastTheCap(t *testing.T) {
	s := newDenyTestServer(t)
	const listed = "203.0.113.53" // 已在拒绝名单里，且当下又被封了一次
	prefill := make([]string, 0, config.GlobalFirewallMaxIPs-1)
	prefill = append(prefill, listed)
	for i := 0; len(prefill) < config.GlobalFirewallMaxIPs-1; i++ {
		prefill = append(prefill, fmt.Sprintf("198.18.%d.%d", i/254, i%254+1))
	}
	if err := s.deps.Config.Update(func(cfg *config.Config) {
		cfg.GlobalFirewall.DenyIPs = prefill
	}); err != nil {
		t.Fatal(err)
	}
	// 处理顺序：先填满最后一个位置，再撞上限，最后才轮到那个已在名单里的。
	banWithMinutes(t, s, "203.0.113.51", 30)
	banWithMinutes(t, s, "203.0.113.52", 20)
	banWithMinutes(t, s, listed, 10)

	_, res := postDeny(t, s, `{"all":true}`)
	if res.Data.Added != 1 || !res.Data.Capped {
		t.Fatalf("应写入 1 条并报截断：added=%d capped=%v", res.Data.Added, res.Data.Capped)
	}
	if res.Data.Skipped != 1 {
		t.Fatalf("撞上限之后那条已在名单里的来源仍应算 skipped，实际 skipped=%d", res.Data.Skipped)
	}
	if res.Data.Unbanned != 2 {
		t.Fatalf("新写入的与本来就在名单里的都该解除封禁，unbanned=%d（期望 2）", res.Data.Unbanned)
	}
	items, _ := s.gfw.BanSnapshot(0)
	if len(items) != 1 || items[0].IP != "203.0.113.52" {
		t.Fatalf("只有没进名单的 203.0.113.52 该继续封着，实际 %v", items)
	}
}

// 参数不合法时既不写名单也不解封禁。
//
// 空请求体单独列一条：它不是"手写 curl 才会出现"的输入——前端把 all 传成 false
// （或者哪天漏传）就正好是这一形状，而"什么都不指定"绝不能被当成"全部"。
func TestDenyBansRejectsBadInput(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
	}{
		{"没指定目标", `{}`},
		{"all 为假", `{"all":false}`},
		{"IP 写法无效", `{"ip":"203.0.113.999"}`},
		{"IP 是段而非地址", `{"ip":"203.0.113.0/24"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newDenyTestServer(t)
			banSource(t, s, "203.0.113.31")

			code, _ := postDeny(t, s, tc.body)
			if code != http.StatusBadRequest {
				t.Fatalf("应回 400，得到 %d", code)
			}
			if n := len(denyListOf(s)); n != 0 {
				t.Fatalf("参数不合法不该动名单，实际写入 %d 条: %v", n, denyListOf(s))
			}
			if n := s.gfw.BanCount(); n != 1 {
				t.Fatalf("参数不合法不该解封禁，封禁表剩 %d 条（期望 1）", n)
			}
		})
	}
}

// 一键升级在服务防护尚未就绪时回 503，而不是把"没有封禁"当成"全部升级完毕"。
func TestDenyBansAllRequiresFirewall(t *testing.T) {
	s := newDenyTestServer(t)
	s.gfw = nil

	code, _ := postDeny(t, s, `{"all":true}`)
	if code != http.StatusServiceUnavailable {
		t.Fatalf("应回 503，得到 %d", code)
	}
	if n := len(denyListOf(s)); n != 0 {
		t.Fatalf("取不到封禁表时不该动名单，实际写入 %d 条", n)
	}
}

// 单个升级即使在服务防护未就绪时也应写进名单：名单是配置，不依赖运行态。
// 界面上这条路只从封禁列表出发，因此实际不会走到；钉住它是为了让"两步要么都做要么都不做"
// 的取舍留在写盘那一侧——写盘失败才回错，而"没有封禁可解"不是失败。
func TestDenyBanSingleWorksWithoutFirewall(t *testing.T) {
	s := newDenyTestServer(t)
	s.gfw = nil

	code, res := postDeny(t, s, `{"ip":"203.0.113.41"}`)
	if code != http.StatusOK {
		t.Fatalf("应成功，得到 %d", code)
	}
	if res.Data.Added != 1 || res.Data.Unbanned != 0 {
		t.Fatalf("应写入 1 条且无可解封：added=%d unbanned=%d", res.Data.Added, res.Data.Unbanned)
	}
	if !containsStr(denyListOf(s), "203.0.113.41") {
		t.Fatalf("名单里应有 203.0.113.41，实际 %v", denyListOf(s))
	}
}
