package forward

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"

	"mantou/internal/config"
	"mantou/internal/logx"
)

// Reload 的运行期防御：目标指向**本机面板端口**的运行项一律不启动（审计 NEW-1）。
//
// 保存接口已经拦过一道（internal/server 的 validateForward / forwardTargetsPanel），
// 这里是第二道。为什么两道都要有：配置还能经整份导入、版本迁移、手改 config.json
// 三条路进来，而那三条都不走保存校验。与 webservice 模块对「服务端口撞面板端口」的
// 处理同一形状——跳过该项 + 告警 + 回写规则错误，而不是让整次 Reload 失败。
//
// 本组用例同时钉住"不能拦过头"：同一次 Reload 里，目标是本机其他端口的、目标是远端
// 主机同一端口号的，都必须照常启动。把这道防御写成"凡回环一律跳过"会打死端口转发最
// 常见的用法（转到本机跑的服务上）。

// panelGuardWriter 是最小 ConfigWriter：Snapshot 与 UpdateState 共用同一份配置，
// 好让用例直接读到回写后的 LastError。
type panelGuardWriter struct {
	mu  sync.Mutex
	cfg *config.Config
}

func (w *panelGuardWriter) Snapshot() *config.Config {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.cfg
}

func (w *panelGuardWriter) UpdateState(mutate func(c *config.Config)) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	mutate(w.cfg)
	return nil
}

// freeListenPorts 取 n 个当前空闲的本地端口。
// 同时持有全部监听再一起释放，避免内核把同一个端口连着发两次。
func freeListenPorts(t *testing.T, n int) []int {
	t.Helper()
	lns := make([]net.Listener, 0, n)
	ports := make([]int, 0, n)
	for i := 0; i < n; i++ {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		lns = append(lns, ln)
		ports = append(ports, ln.Addr().(*net.TCPAddr).Port)
	}
	for _, ln := range lns {
		ln.Close()
	}
	return ports
}

// lastErrorOf 读回写后的规则运行态错误。
func lastErrorOf(w *panelGuardWriter, id string) string {
	w.mu.Lock()
	defer w.mu.Unlock()
	for _, r := range w.cfg.Forwards {
		if r.ID == id {
			return r.LastError
		}
	}
	return "<无此规则>"
}

func TestReloadSkipsPanelPortTarget(t *testing.T) {
	// 目标端口在本测试里从不被真正连接，取固定值即可；只有监听端口需要确实空闲。
	const panelPort = 9000
	listen := freeListenPorts(t, 3)

	cfg := &config.Config{
		Forwards: []config.ForwardRule{
			// 撞面板端口：必须跳过。
			{ID: "collide", Name: "撞面板", Enabled: true, Protocol: "tcp",
				ListenPort: listen[0], TargetHost: "127.0.0.1", TargetPort: panelPort},
			// 本机的其他端口：必须照常启动。
			{ID: "localOther", Name: "本机其他端口", Enabled: true, Protocol: "tcp",
				ListenPort: listen[1], TargetHost: "127.0.0.1", TargetPort: panelPort + 1},
			// 远端主机的同一端口号：必须照常启动（面板端口只对本机有意义）。
			{ID: "remoteSame", Name: "远端同端口", Enabled: true, Protocol: "tcp",
				ListenPort: listen[2], TargetHost: "203.0.113.9", TargetPort: panelPort},
		},
	}
	cfg.Panel.Port = panelPort

	w := &panelGuardWriter{cfg: cfg}
	m := New(logx.New(logx.Options{}), w)
	t.Cleanup(func() { m.Close() })

	if err := m.Reload(cfg); err != nil {
		t.Fatalf("Reload 返回错误：%v", err)
	}

	m.mu.Lock()
	_, collideUp := m.runners[fmt.Sprintf("collide#%d", listen[0])]
	_, localUp := m.runners[fmt.Sprintf("localOther#%d", listen[1])]
	_, remoteUp := m.runners[fmt.Sprintf("remoteSame#%d", listen[2])]
	total := len(m.runners)
	m.mu.Unlock()

	if collideUp {
		t.Errorf("目标 127.0.0.1:%d 是面板端口，该运行项不应启动", panelPort)
	}
	if !localUp {
		t.Errorf("目标 127.0.0.1:%d 只是本机的其他端口，应照常启动", panelPort+1)
	}
	if !remoteUp {
		t.Errorf("目标 203.0.113.9:%d 在远端主机上，应照常启动", panelPort)
	}
	if total != 2 {
		t.Errorf("应有 2 个运行项，实际 %d", total)
	}

	// 被跳过的那条要让用户在列表里看得见，否则规则"配了却不生效"且毫无提示。
	if msg := lastErrorOf(w, "collide"); !strings.Contains(msg, "面板端口") {
		t.Errorf("撞面板的规则 LastError 应说明原因，实际 %q", msg)
	}
	for _, id := range []string{"localOther", "remoteSame"} {
		if msg := lastErrorOf(w, id); msg != "" {
			t.Errorf("规则 %s 正常启动，LastError 应为空，实际 %q", id, msg)
		}
	}
}

// TestReloadSkipsPanelPortTargetInRange 端口范围规则同样逐项判定。
//
// 范围规则是这道防御最需要覆盖的形状：一条 `20000-21000 → 127.0.0.1:面板端口` 里，
// 用户看到的是"一段端口"，而其中每一个都是一条通往面板的隧道。
// 这里让整段都撞上（多对一映射），于是一个 runner 都不该起——也就不需要真的占用端口。
func TestReloadSkipsPanelPortTargetInRange(t *testing.T) {
	const (
		panelPort = 9000
		start     = 20000
		end       = 20002
	)
	cfg := &config.Config{
		Forwards: []config.ForwardRule{{
			ID: "range", Name: "整段撞面板", Enabled: true, Protocol: "tcp",
			ListenPort: start, ListenPortEnd: end,
			TargetHost: "localhost", TargetPort: panelPort, SameTargetPort: true,
		}},
	}
	cfg.Panel.Port = panelPort

	w := &panelGuardWriter{cfg: cfg}
	m := New(logx.New(logx.Options{}), w)
	t.Cleanup(func() { m.Close() })

	if err := m.Reload(cfg); err != nil {
		t.Fatalf("Reload 返回错误：%v", err)
	}

	m.mu.Lock()
	total := len(m.runners)
	m.mu.Unlock()
	if total != 0 {
		t.Fatalf("整段都指向面板端口，不应有任何运行项，实际 %d 个", total)
	}

	// 三个端口各记一条，好让用户知道是哪几个被跳过的（消息总长在 MaxStatusMessageLen 内）。
	msg := lastErrorOf(w, "range")
	for p := start; p <= end; p++ {
		if !strings.Contains(msg, fmt.Sprintf("%d", p)) {
			t.Errorf("LastError 未提到被跳过的端口 %d：%q", p, msg)
		}
	}
}

// TestReloadSkipsPanelPortListen Reload 的运行期防御：**监听端口**撞面板端口的运行项不启动（审计 L-01）。
//
// 这一道是「已经存进去的坏配置」唯一的解药。保存接口那道（validateForward /
// forwardListensOnPanel）只管住 API 这一条路，而配置还能经整份导入、版本迁移、
// 手改 config.json 三条路进来。少了这里，面板在 Linux 上会因端口被抢而直接退出，
// 用户连界面都进不去、改不回来。
//
// 同时钉住"不能拦过头"：同一次 Reload 里监听在其他端口的规则必须照常启动。
func TestReloadSkipsPanelPortListen(t *testing.T) {
	listen := freeListenPorts(t, 2)
	panelPort := listen[0] // 面板端口取一个确实空闲的端口，好让"没被跳过"时真的会抢绑

	cfg := &config.Config{
		Forwards: []config.ForwardRule{
			// 监听端口撞面板端口：必须跳过。
			{ID: "brick", Name: "抢面板端口", Enabled: true, Protocol: "tcp",
				ListenPort: panelPort, TargetHost: "203.0.113.9", TargetPort: 8080},
			// 监听在别的端口：必须照常启动。
			{ID: "fine", Name: "正常规则", Enabled: true, Protocol: "tcp",
				ListenPort: listen[1], TargetHost: "203.0.113.9", TargetPort: 8080},
		},
	}
	cfg.Panel.Port = panelPort

	w := &panelGuardWriter{cfg: cfg}
	m := New(logx.New(logx.Options{}), w)
	t.Cleanup(func() { m.Close() })

	if err := m.Reload(cfg); err != nil {
		t.Fatalf("Reload 返回错误：%v", err)
	}

	m.mu.Lock()
	_, brickUp := m.runners[fmt.Sprintf("brick#%d", panelPort)]
	_, fineUp := m.runners[fmt.Sprintf("fine#%d", listen[1])]
	total := len(m.runners)
	m.mu.Unlock()

	if brickUp {
		t.Errorf("监听端口 %d 就是面板端口，该运行项不应启动", panelPort)
	}
	if !fineUp {
		t.Errorf("监听端口 %d 与面板无关，应照常启动", listen[1])
	}
	if total != 1 {
		t.Errorf("应有 1 个运行项，实际 %d", total)
	}

	// 面板端口必须仍然可绑——这正是这道防御要保住的东西。
	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", panelPort))
	if err != nil {
		t.Fatalf("面板端口 %d 已被转发抢走，面板将无法启动：%v", panelPort, err)
	}
	ln.Close()

	if msg := lastErrorOf(w, "brick"); !strings.Contains(msg, "面板") {
		t.Errorf("被跳过的规则 LastError 应说明原因，实际 %q", msg)
	}
	if msg := lastErrorOf(w, "fine"); msg != "" {
		t.Errorf("正常规则的 LastError 应为空，实际 %q", msg)
	}
}

// TestReloadSkipsPanelPortListenInRange 端口范围里只有一个端口撞面板时，只跳过那一个。
//
// 范围规则展开成若干独立运行项，防御必须逐项判定：整条跳掉会让用户白丢一段可用端口，
// 一个都不跳则面板起不来。
func TestReloadSkipsPanelPortListenInRange(t *testing.T) {
	ports := freeListenPorts(t, 3)
	// 取一段连续端口，让面板端口落在中间。用连续段是因为范围规则按 start..end 展开。
	start := ports[0]
	end := start + 2
	panelPort := start + 1
	cfg := &config.Config{
		Forwards: []config.ForwardRule{{
			ID: "range", Name: "范围盖住面板", Enabled: true, Protocol: "tcp",
			ListenPort: start, ListenPortEnd: end,
			TargetHost: "203.0.113.9", TargetPort: 8080, SameTargetPort: true,
		}},
	}
	cfg.Panel.Port = panelPort

	w := &panelGuardWriter{cfg: cfg}
	m := New(logx.New(logx.Options{}), w)
	t.Cleanup(func() { m.Close() })

	if err := m.Reload(cfg); err != nil {
		t.Fatalf("Reload 返回错误：%v", err)
	}

	m.mu.Lock()
	_, panelUp := m.runners[fmt.Sprintf("range#%d", panelPort)]
	total := len(m.runners)
	m.mu.Unlock()

	if panelUp {
		t.Errorf("范围里的 %d 就是面板端口，该运行项不应启动", panelPort)
	}
	if total != 2 {
		t.Errorf("应只跳过面板端口那一个、其余 2 个照常启动，实际起了 %d 个", total)
	}
	if msg := lastErrorOf(w, "range"); !strings.Contains(msg, fmt.Sprintf("%d", panelPort)) {
		t.Errorf("LastError 未提到被跳过的端口 %d：%q", panelPort, msg)
	}
}
