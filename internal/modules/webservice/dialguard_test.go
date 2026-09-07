package webservice

import (
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"mantou/internal/config"
	"mantou/internal/logx"
	"mantou/internal/netguard"
)

// 本文件盯住那道拨号闸（审计 S-05）：后端解析到本机面板管理端口时必须在拨号期被拦下。
//
// 分两层测，两层都不能省：
//   - 判据本身（blockPanelPortDial / dialGuard）：直接组装 Module 即可，覆盖各种地址写法；
//   - 它是否真的挂在反代那条 Transport 上：跑一次完整的反代请求。
//     后一层才是最容易在重构里悄悄丢掉的——判据留着、钩子没挂，测试却全绿。

// panelPortModule 造一个只用于判据测试的模块：拨号闸只读 panelPort，别的字段都用不到。
func panelPortModule(port int) *Module {
	m := &Module{}
	m.panelPort.Store(int64(port))
	return m
}

func TestBlockPanelPortDialJudgement(t *testing.T) {
	const panelPort = 25666
	m := panelPortModule(panelPort)
	cases := []struct {
		address string
		blocked bool
		why     string
	}{
		{"127.0.0.1:25666", true, "回环 + 面板端口，正是要拦的那个形状"},
		{"[::1]:25666", true, "IPv6 回环同样是本机"},
		{"0.0.0.0:25666", true, "未指定地址作为拨号目标会落到本机"},
		{"127.0.0.1:25667", false, "端口不是面板端口"},
		{"8.8.8.8:25666", false, "端口对上了但不是本机地址"},
		{"192.0.2.10:25666", false, "内网/公网后端一律放过，反代它们正是本功能的用途"},
		{"example.com:25666", false, "拨号期拿到的应是 IP；主机名不查 DNS，拿不准就放过"},
		{"127.0.0.1", false, "拆不出端口时放过（见 blockPanelPortDial 的说明）"},
		{"127.0.0.1:abc", false, "端口不是数字时放过"},
	}
	for _, c := range cases {
		err := m.blockPanelPortDial(c.address)
		if c.blocked {
			if !errors.Is(err, ErrPanelPortDial) {
				t.Errorf("%s 应被拦下（%s），实际 err=%v", c.address, c.why, err)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s 应放过（%s），实际 err=%v", c.address, c.why, err)
		}
	}
}

// 本机网卡上的局域网地址是同一个洞的弱化版：回环豁免不生效，但「仅局域网」这道策略
// 照样被绕过，且所有来源仍塌成同一个 IP（见 internal/ipx/local.go 文件头），所以也要拦。
// 地址取自本机实际网卡；没有非回环地址的环境（纯离线容器）跳过。
func TestBlockPanelPortDialBlocksOwnInterfaceAddress(t *testing.T) {
	const panelPort = 25666
	ip := firstNonLoopbackIP()
	if ip == "" {
		t.Skip("本机没有非回环地址，跳过")
	}
	m := panelPortModule(panelPort)
	addr := net.JoinHostPort(ip, strconv.Itoa(panelPort))
	if err := m.blockPanelPortDial(addr); !errors.Is(err, ErrPanelPortDial) {
		t.Fatalf("%s 是本机网卡上的地址，应被拦下，实际 err=%v", addr, err)
	}
}

// firstNonLoopbackIP 取本机第一个非回环地址，取不到返回空串。
func firstNonLoopbackIP() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return ""
	}
	for _, a := range addrs {
		n, ok := a.(*net.IPNet)
		if !ok || n.IP == nil || n.IP.IsLoopback() || n.IP.IsLinkLocalUnicast() {
			continue
		}
		return n.IP.String()
	}
	return ""
}

// 面板端口还没写进来（模块刚建、尚未 Reload）时不拦。这一道无条件生效、用户关不掉，
// 拿不准时放过才是对的方向：误拦的代价是一条合法反代打不开而且没处关。
func TestBlockPanelPortDialAllowsWhenPanelPortUnset(t *testing.T) {
	m := &Module{} // panelPort 取零值
	if err := m.blockPanelPortDial("127.0.0.1:25666"); err != nil {
		t.Fatalf("面板端口未知时应放过，实际 err=%v", err)
	}
}

// dialGuard 是两道合起来的一道闸：新增面板端口判定之后，链路本地那一道不能丢。
func TestDialGuardKeepsBothGates(t *testing.T) {
	m := panelPortModule(25666)
	if err := m.dialGuard("tcp4", "169.254.169.254:80", nil); !errors.Is(err, netguard.ErrLinkLocalBlocked) {
		t.Errorf("云元数据端点应仍被链路本地那道拦下，实际 err=%v", err)
	}
	if err := m.dialGuard("tcp4", "127.0.0.1:25666", nil); !errors.Is(err, ErrPanelPortDial) {
		t.Errorf("面板端口应被新增那道拦下，实际 err=%v", err)
	}
	if err := m.dialGuard("tcp4", "192.168.1.10:8080", nil); err != nil {
		t.Errorf("正常的内网后端必须放过，实际 err=%v", err)
	}
}

// 拨号闸必须真的挂在反代那条 Transport 上，并且拦得住「后端写成一个解析到本机的域名」
// ——那正是保存期与 Reload 期两道判定漏掉的形状（两处都不查 DNS，见 dialguard.go 文件头）。
//
// 后端主机名用 localhost：到拨号期它已经变成 127.0.0.1 / ::1，两个都是本机。
// 一对正反用例才说得清「是这道闸拦下的」：面板端口等于后端端口时请求打不通、后端一次都没
// 被访问到；面板端口换成别的数，同一条配置照样通——把"其实是别的原因失败了"排除掉。
func TestProxyDialGuardBlocksBackendResolvingToPanelPort(t *testing.T) {
	var hits atomic.Int64
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()
	backendPort := mustPort(t, backend.URL)

	// 走一次完整请求，返回状态码与访问日志里记下的原因。
	run := func(t *testing.T, panelPort int) (int, string) {
		t.Helper()
		m := New(logx.New(logx.Options{}))
		t.Cleanup(func() { _ = m.Close() })
		m.panelPort.Store(int64(panelPort))
		ch := config.WebChild{
			ID: "ch-proxy", Enabled: true, Type: "proxy",
			Domains:   []string{"site.example.com"},
			Upstreams: []config.WebUpstream{{URL: "http://localhost:" + strconv.Itoa(backendPort), Weight: 1}},
			Proxy:     config.WebProxyOptions{AccessLog: true},
		}
		h, _ := buildChildHandler(m, "站点", ch)
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Host = "site.example.com"
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		var reason string
		for _, e := range m.ChildLogs("ch-proxy", 10) {
			if e.Reason != "" {
				reason = e.Reason
				break
			}
		}
		return w.Code, reason
	}

	t.Run("后端解析到面板端口", func(t *testing.T) {
		before := hits.Load()
		code, reason := run(t, backendPort)
		if code != http.StatusBadGateway {
			t.Fatalf("应回 502，实际 %d", code)
		}
		if got := hits.Load() - before; got != 0 {
			t.Fatalf("后端被访问了 %d 次，这一刀本该落在建连之前", got)
		}
		if !strings.Contains(reason, "面板管理端口") {
			t.Fatalf("访问日志的原因里应说明是哪一道闸，实际 %q", reason)
		}
	})

	t.Run("后端不指向面板端口", func(t *testing.T) {
		before := hits.Load()
		// 端口取 backendPort-1：httptest 拿到的都是临时端口（≥1024），减一不会越界，
		// 且这个值只参与数值比较、不会有人去连它。
		code, _ := run(t, backendPort-1)
		if code != http.StatusOK {
			t.Fatalf("同一条配置换个面板端口就该通，实际 %d", code)
		}
		if got := hits.Load() - before; got != 1 {
			t.Fatalf("后端应被访问一次，实际 %d 次", got)
		}
	})
}

// mustPort 从 httptest 的 URL 里取端口。
func mustPort(t *testing.T, raw string) int {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	p, err := strconv.Atoi(u.Port())
	if err != nil {
		t.Fatalf("取不到端口：%v", err)
	}
	return p
}
