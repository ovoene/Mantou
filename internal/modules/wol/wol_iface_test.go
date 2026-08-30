package wol

import (
	"bytes"
	"net"
	"strings"
	"testing"
	"time"

	"mantou/internal/config"
)

// tgt 造一个用于筛选测试的 wakeTarget。
// src 一律指向回环：这样「假如没被筛掉就会真的发出去」在测试里是可观测的
// （见 TestWakeAutoSkipsVirtualAndPublic）——若给虚拟/公网项一个不可绑定的源地址，
// 即便筛选失效，DialUDP 也会失败，测试就会以错误的理由通过。
func tgt(name string, virtual, private bool) wakeTarget {
	return wakeTarget{
		iface:     name,
		src:       &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)},
		broadcast: "127.0.0.1",
		virtual:   virtual,
		private:   private,
	}
}

// withTargetCache 把给定网卡列表塞进枚举缓存，测试结束后作废。
// 缓存是本模块唯一的枚举入口，注入它就等于注入了「本机有哪些网卡」这件事，
// 于是筛选逻辑可以脱离真实主机的网卡拓扑被确定性地验证。
func withTargetCache(t *testing.T, list []wakeTarget) {
	t.Helper()
	targetCache.mu.Lock()
	targetCache.list = list
	targetCache.at = time.Now()
	targetCache.mu.Unlock()
	t.Cleanup(invalidateTargetCache)
}

// TestIsVirtualIface 虚拟网卡前缀表。
// 表里每一项都对应一个真实存在的命名约定，而不是猜测。
func TestIsVirtualIface(t *testing.T) {
	virtual := []struct{ name, why string }{
		{"docker0", "Docker 默认网桥"},
		{"docker_gwbridge", "Docker swarm 网关网桥"},
		{"br-1a2b3c4d5e6f", "Docker 自定义网络的网桥"},
		{"veth1a2b3c4", "容器 veth pair 宿主机侧"},
		{"virbr0", "libvirt 默认网桥"},
		{"virbr0-nic", "libvirt 网桥的哑接口"},
		{"vmnet1", "VMware 仅主机网络（Linux 设备名）"},
		{"VMware Network Adapter VMnet8", "VMware（Windows 显示名）"},
		{"vboxnet0", "VirtualBox 仅主机网络"},
		{"VirtualBox Host-Only Network", "VirtualBox（Windows 显示名）"},
		{"vEthernet (WSL)", "Hyper-V/WSL 虚拟交换机（Windows 显示名，命中 veth 前缀）"},
		{"tap0", "TAP 模式隧道（广播型，不会被 FlagBroadcast 排除）"},
		{"cni0", "k8s CNI 网桥"},
		{"flannel.1", "flannel VXLAN"},
		{"kube-ipvs0", "kube-proxy IPVS 哑接口"},
		{"lxcbr0", "LXC 网桥"},
		{"zt0", "ZeroTier"},
		{"DOCKER0", "大小写不敏感"},
		{"Br-abc", "大小写不敏感"},
	}
	for _, c := range virtual {
		if !isVirtualIface(c.name) {
			t.Errorf("%q（%s）应判为虚拟网卡", c.name, c.why)
		}
	}

	// 这些必须**不**被判为虚拟：它们是真实出口，误判会让自动模式无网卡可用。
	real := []struct{ name, why string }{
		{"eth0", "物理网卡；容器内的 eth0 也是真实出口"},
		{"eth1", "第二张物理网卡"},
		{"enp3s0", "systemd 可预测命名"},
		{"ens160", "systemd 可预测命名（虚拟机里的 VMXNET3 也算真实出口）"},
		{"en0", "macOS 物理网卡"},
		{"wlan0", "无线网卡"},
		{"wlp2s0", "无线网卡（可预测命名）"},
		{"bond0", "链路聚合"},
		{"br0", "宿主机自建的桥接网卡：桥到物理网卡上，广播能出去（前缀是 br- 而非 br）"},
		{"以太网", "Windows 的中文网卡名"},
		{"vlan10", "VLAN 子接口"},
		{"macvlan0", "macvlan 接入宿主网卡，是真实出口"},
	}
	for _, c := range real {
		if isVirtualIface(c.name) {
			t.Errorf("%q（%s）不应判为虚拟网卡", c.name, c.why)
		}
	}
}

// TestSelectTargetsAutoExcludesVirtualAndPublic 锁定 W-6 的核心：
// 自动模式只用「内网且非虚拟」的网卡。
func TestSelectTargetsAutoExcludesVirtualAndPublic(t *testing.T) {
	all := []wakeTarget{
		tgt("eth0", false, true),     // 应保留
		tgt("docker0", true, true),   // 虚拟：对端是容器，不是要唤醒的设备
		tgt("br-abc123", true, true), // 虚拟
		tgt("eth1", false, false),    // 公网：定向广播会发给同机房邻居
		tgt("wlan0", false, true),    // 应保留
		tgt("virbr0", true, true),    // 虚拟
	}
	var names []string
	for _, s := range selectTargets(all, "") {
		names = append(names, s.iface)
	}
	if got := strings.Join(names, ","); got != "eth0,wlan0" {
		t.Fatalf("自动模式选中 [%s]，应为 [eth0,wlan0]", got)
	}
}

// TestSelectTargetsAutoNoFallback 全被筛掉时必须返回空，**不得**退化回落到全集。
//
// 这条是整个 W-6 里最要紧的一条：静默回落等于这层防护在最需要它的场景
// （VPS 上只有一张公网网卡、或纯容器宿主机上只剩网桥）恰好失效，
// 而那正是魔术包会被广播给同机房邻居 / 容器对端的场景。
func TestSelectTargetsAutoNoFallback(t *testing.T) {
	cases := []struct {
		why string
		all []wakeTarget
	}{
		{"只有公网网卡（VPS）", []wakeTarget{tgt("eth0", false, false)}},
		{"只有虚拟网卡（容器宿主）", []wakeTarget{tgt("docker0", true, true), tgt("br-a", true, true)}},
		{"公网 + 虚拟", []wakeTarget{tgt("eth0", false, false), tgt("docker0", true, true)}},
		{"虚拟且公网", []wakeTarget{tgt("zt0", true, false)}},
	}
	for _, c := range cases {
		if sel := selectTargets(c.all, ""); len(sel) != 0 {
			t.Errorf("%s：应返回空让调用方报错，实际回落到 %d 张网卡", c.why, len(sel))
		}
	}
}

// TestSelectTargetsExplicitHonoredVerbatim 显式指定网卡 = 原样尊重，不做任何过滤。
// 「就是要往这张虚拟网卡/公网网卡发」是用户的明知故犯，也是自动模式报错后唯一的出路。
func TestSelectTargetsExplicitHonoredVerbatim(t *testing.T) {
	all := []wakeTarget{
		tgt("eth0", false, true),
		tgt("docker0", true, true),
		tgt("eth1", false, false),
	}
	for _, name := range []string{"eth0", "docker0", "eth1"} {
		sel := selectTargets(all, name)
		if len(sel) != 1 || sel[0].iface != name {
			t.Fatalf("显式指定 %s 应只选中它自己，实际 %d 项", name, len(sel))
		}
	}
	// 带空白也要认：normalizeWOL 会 trim，但手工编辑的 config.json 不会。
	if sel := selectTargets(all, "  eth0  "); len(sel) != 1 || sel[0].iface != "eth0" {
		t.Fatal("显式网卡名两侧的空白应被忽略")
	}
	// 同一张网卡有多个 IPv4 地址时，每个地址都要发（各自的定向广播不同）。
	multi := []wakeTarget{
		{iface: "eth0", src: &net.UDPAddr{IP: net.IPv4(192, 168, 1, 2)}, broadcast: "192.168.1.255", private: true},
		{iface: "eth0", src: &net.UDPAddr{IP: net.IPv4(10, 0, 0, 2)}, broadcast: "10.0.0.255", private: true},
		tgt("docker0", true, true),
	}
	if sel := selectTargets(multi, "eth0"); len(sel) != 2 {
		t.Fatalf("一张网卡上的多个 IPv4 地址应全部选中，实际 %d 项", len(sel))
	}
}

// TestSelectTargetsExplicitMissing 指定了不存在的网卡：返回空，由调用方给出可操作的报错。
func TestSelectTargetsExplicitMissing(t *testing.T) {
	all := []wakeTarget{tgt("eth0", false, true)}
	if sel := selectTargets(all, "eth9"); len(sel) != 0 {
		t.Fatalf("不存在的网卡名不得匹配到任何目标，实际 %d 项", len(sel))
	}
	// 前缀相同也不算命中：网卡名必须精确匹配，否则 "eth" 会连带匹配 eth0/eth1。
	if sel := selectTargets(all, "eth"); len(sel) != 0 {
		t.Fatal("网卡名必须精确匹配，不能按前缀匹配")
	}
	if sel := selectTargets(all, "eth00"); len(sel) != 0 {
		t.Fatal("网卡名必须精确匹配")
	}
}

// TestSelectTargetsNoCopyWhenNothingFiltered 无需过滤时原样返回入参，不额外分配。
// 这条路径每个魔术包都要走一次（固定时间模式一秒 100 个包），
// 而绝大多数主机上只有一张可用网卡、全都保留。
func TestSelectTargetsNoCopyWhenNothingFiltered(t *testing.T) {
	all := []wakeTarget{tgt("eth0", false, true), tgt("wlan0", false, true)}
	if sel := selectTargets(all, ""); len(sel) != 2 || &sel[0] != &all[0] {
		t.Fatal("全部保留时应原样返回入参切片，不做拷贝")
	}
	one := []wakeTarget{tgt("eth0", false, true)}
	if sel := selectTargets(one, "eth0"); len(sel) != 1 || &sel[0] != &one[0] {
		t.Fatal("显式指定且全部命中时应原样返回入参切片")
	}
	if n := testing.AllocsPerRun(50, func() { _ = selectTargets(all, "") }); n != 0 {
		t.Fatalf("无需过滤的快路径不应有分配，实测 %.0f 次/轮", n)
	}
}

// TestDescribeTargets 报错里必须逐张列出网卡并标注它为什么被排除，
// 否则用户面对「没有可用网卡」而 ip a 明明有一堆，无从下手。
func TestDescribeTargets(t *testing.T) {
	all := []wakeTarget{
		{iface: "eth0", src: &net.UDPAddr{IP: net.IPv4(203, 0, 113, 7)}, broadcast: "203.0.113.255"},
		tgt("docker0", true, true),
	}
	got := describeTargets(all)
	for _, want := range []string{"eth0", "203.0.113.7", "公网", "docker0", "虚拟网卡"} {
		if !strings.Contains(got, want) {
			t.Errorf("网卡描述 %q 缺少 %q", got, want)
		}
	}
}

// TestNoUsableTargetErrorNamesInterfaces 自动模式无网卡可用时的报错要说清三件事：
// 排除了什么、为什么、以及怎么办。逐张列出网卡是关键——否则用户面对
// 「没有可用网卡」而 ip a 明明有一堆，无从下手。
func TestNoUsableTargetErrorNamesInterfaces(t *testing.T) {
	all := []wakeTarget{
		tgt("docker0", true, true),
		{iface: "ens5", src: &net.UDPAddr{IP: net.IPv4(203, 0, 113, 7)}, broadcast: "203.0.113.255"},
	}
	err := noUsableTargetError(all, "")
	if err == nil {
		t.Fatal("只有虚拟网卡与公网网卡时，自动模式应报错而不是照发")
	}
	for _, want := range []string{"虚拟网卡", "公网", "显式指定网卡", "docker0", "ens5", "203.0.113.7"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("报错 %q 缺少 %q", err.Error(), want)
		}
	}
	// 一张网卡都没有（网线全拔 / 容器 none 网络）是另一码事，不该抛出那段长解释。
	if e := noUsableTargetError(nil, ""); e == nil || strings.Contains(e.Error(), "已排除") {
		t.Errorf("无网卡时的报错应简短直白，实际: %v", e)
	}
}

// TestAutoTargetsRejectsAllFiltered autoTargets 必须把上面那条报错真的抛出来，
// 而不是静默回落到「发给所有网卡」。
func TestAutoTargetsRejectsAllFiltered(t *testing.T) {
	invalidateTargetCache()
	t.Cleanup(invalidateTargetCache)
	// autoTargets 筛空后会作废缓存重新枚举一次（刚插网线 / 刚拿到 DHCP 地址的场景需要它），
	// 于是本机若有可用网卡，重试就会拿到它——这条集成路径只在没有可用网卡的机器上可验证。
	if len(selectTargets(cachedBroadcastTargets(), "")) > 0 {
		t.Skip("本机有可用的内网物理网卡，重试路径会拿到它；文案由 TestNoUsableTargetErrorNamesInterfaces 锁定")
	}
	withTargetCache(t, []wakeTarget{tgt("docker0", true, true), tgt("ens5", false, false)})
	if _, err := autoTargets(""); err == nil {
		t.Fatal("只有虚拟网卡与公网网卡时，自动模式应报错而不是照发")
	}
}

// TestAutoTargetsExplicitMissingError 指定了不存在的网卡时，报错要带上网卡名与出路。
func TestAutoTargetsExplicitMissingError(t *testing.T) {
	_, err := autoTargets("iface-does-not-exist-zzz")
	if err == nil {
		t.Fatal("指定不存在的网卡应报错")
	}
	for _, want := range []string{"iface-does-not-exist-zzz", "自动"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("报错 %q 缺少 %q", err.Error(), want)
		}
	}
}

// listenUDP 在回环上开一个 UDP 接收端，返回端口与「读走这段时间内所有到达的包」的函数。
func listenUDP(t *testing.T) (int, func(wait time.Duration) [][]byte) {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Skipf("无法在回环上监听 UDP: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	port := conn.LocalAddr().(*net.UDPAddr).Port
	return port, func(wait time.Duration) [][]byte {
		var got [][]byte
		deadline := time.Now().Add(wait)
		for {
			if err := conn.SetReadDeadline(deadline); err != nil {
				return got
			}
			buf := make([]byte, 256)
			n, err := conn.Read(buf)
			if err != nil {
				return got
			}
			got = append(got, buf[:n])
		}
	}
}

// loTarget 造一个「定向广播指向回环接收端」的目标：
// 收到几个包就等于往几张网卡发过，与真实网卡拓扑无关。
func loTarget(name string, virtual, private bool) wakeTarget {
	w := tgt(name, virtual, private)
	w.broadcast = "127.0.0.1"
	return w
}

// measurePerNIC 量出「一张选中的网卡会让接收端收到几个包」。
//
// 发送路径对每张选中网卡发两个包（定向广播 + 全局广播），但全局广播那一个
// 是否会被一个绑定在 127.0.0.1 上的套接字收到，随平台而异
// （Windows 会，Linux 上绑定了具体单播地址的套接字不收广播）。
// 所以先用「只有一张网卡」的场景标定这个倍数，再拿它去校验多网卡场景，
// 断言就不必依赖平台行为。
func measurePerNIC(t *testing.T, port int, drain func(time.Duration) [][]byte) int {
	t.Helper()
	withTargetCache(t, []wakeTarget{loTarget("eth0", false, true)})
	if err := Wake("AA:BB:CC:DD:EE:FF", "", port, ""); err != nil {
		t.Fatalf("标定用的发送失败: %v", err)
	}
	n := len(drain(400 * time.Millisecond))
	if n == 0 {
		t.Skip("回环上收不到自己发出的包，无法用收包数校验网卡筛选")
	}
	return n
}

// TestWakeAutoSkipsVirtualAndPublic 端到端锁定 W-6：
// 枚举结果里有 4 张网卡（1 张内网物理 + 2 张虚拟 + 1 张公网），
// 自动模式只应有 1 张真的发出去。
//
// 修复前这里会收到 4 倍的包——每张网卡各一份，包括 docker0 与公网网卡，
// 而 102 字节里目标 MAC 重复 16 次、前 3 字节 OUI 直接暴露硬件厂商。
func TestWakeAutoSkipsVirtualAndPublic(t *testing.T) {
	port, drain := listenUDP(t)
	perNIC := measurePerNIC(t, port, drain)

	withTargetCache(t, []wakeTarget{
		loTarget("eth0", false, true),
		loTarget("docker0", true, true),
		loTarget("br-1a2b3c", true, true),
		loTarget("ens5", false, false),
	})

	const mac = "AA:BB:CC:DD:EE:FF"
	if err := Wake(mac, "", port, ""); err != nil {
		t.Fatalf("自动模式发送失败: %v", err)
	}
	got := drain(400 * time.Millisecond)
	if len(got) != perNIC {
		t.Fatalf("自动模式发往了 %d 张网卡（收到 %d 个包，单张网卡为 %d 个），应只有 1 张："+
			"另 3 张是虚拟/公网网卡，往它们广播既唤不醒设备、"+
			"又会把目标 MAC 泄露给容器对端或同机房邻居",
			len(got)/perNIC, len(got), perNIC)
	}
	hw, _ := parseMAC(mac)
	if want := buildMagicPacket(hw); !bytes.Equal(got[0], want) {
		t.Fatalf("包内容不是 %s 的魔术包", mac)
	}
}

// TestWakeExplicitIfaceBindsThatIface 显式指定网卡时只从那一张发出，
// 即便它是虚拟网卡（自动模式会排除、显式指定则原样尊重）。
func TestWakeExplicitIfaceBindsThatIface(t *testing.T) {
	port, drain := listenUDP(t)
	perNIC := measurePerNIC(t, port, drain)

	withTargetCache(t, []wakeTarget{
		loTarget("eth0", false, true),
		loTarget("docker0", true, true),
		loTarget("eth1", false, true),
	})

	if err := Wake("AA:BB:CC:DD:EE:FF", "", port, "docker0"); err != nil {
		t.Fatalf("显式指定虚拟网卡应被允许: %v", err)
	}
	if got := drain(400 * time.Millisecond); len(got) != perNIC {
		t.Fatalf("显式指定单张网卡时发往了 %d 张（收到 %d 个包，单张为 %d 个），应只有 1 张",
			len(got)/perNIC, len(got), perNIC)
	}
}

// TestWakeExplicitAddressStillBindsIface 目标是具体地址时也要绑定指定网卡，
// 否则「指定网卡」在这条路径上形同虚设（内核按目的地选路，很可能走默认路由）。
func TestWakeExplicitAddressStillBindsIface(t *testing.T) {
	err := Wake("AA:BB:CC:DD:EE:FF", "192.168.1.255", 9, "iface-does-not-exist-zzz")
	if err == nil {
		t.Fatal("指定了不存在的网卡却仍把包发了出去：绑定被跳过了")
	}
	if !strings.Contains(err.Error(), "iface-does-not-exist-zzz") {
		t.Fatalf("报错未指出是哪张网卡: %v", err)
	}
}

// TestWakeDeviceUsesInterfaceField WakeDevice 必须把设备上的网卡字段透传下去。
// 三条唤醒入口都走 WakeDevice，漏传就等于「指定网卡」这个设置项在某条入口上失效。
func TestWakeDeviceUsesInterfaceField(t *testing.T) {
	dev := config.WOLDevice{
		MAC:       "AA:BB:CC:DD:EE:FF",
		Broadcast: "192.168.1.255",
		Port:      9,
		Interface: "iface-does-not-exist-zzz",
	}
	err := WakeDevice(dev)
	if err == nil || !strings.Contains(err.Error(), "iface-does-not-exist-zzz") {
		t.Fatalf("WakeDevice 未使用设备的 Interface 字段: %v", err)
	}
}

// TestInterfacesAutoFlagMatchesSelection 界面上的 auto 标记必须与实际发送口径一致，
// 否则「自动模式会从哪几张网卡发出」的提示就是在骗人。
func TestInterfacesAutoFlagMatchesSelection(t *testing.T) {
	withTargetCache(t, []wakeTarget{
		tgt("eth0", false, true),
		tgt("docker0", true, true),
		tgt("ens5", false, false),
	})
	list := Interfaces()
	if len(list) != 3 {
		t.Fatalf("应列出全部 3 张网卡（含被排除的，否则用户看不到它们为何不被使用），实际 %d 张", len(list))
	}
	for _, in := range list {
		wantAuto := in.Name == "eth0"
		if in.Auto != wantAuto {
			t.Errorf("%s: auto=%v，应为 %v", in.Name, in.Auto, wantAuto)
		}
		if in.IP == "" {
			t.Errorf("%s: 未给出 IP，界面上无从区分同名多地址", in.Name)
		}
	}
	if list[1].Name != "docker0" || !list[1].Virtual {
		t.Error("docker0 应被标记为虚拟网卡")
	}
	if list[2].Name != "ens5" || !list[2].Public {
		t.Error("ens5 应被标记为公网网卡")
	}
}

// TestInterfacesRealHostConsistency 真实主机上的一致性检查：
// 被标 auto 的必须既非虚拟也非公网，且数量与 selectTargets 的结果相等。
func TestInterfacesRealHostConsistency(t *testing.T) {
	invalidateTargetCache()
	t.Cleanup(invalidateTargetCache)
	all := cachedBroadcastTargets()
	if len(all) == 0 {
		t.Skip("本机没有可广播的网卡")
	}
	list := Interfaces()
	if len(list) != len(all) {
		t.Fatalf("Interfaces 列出 %d 张，枚举结果 %d 张", len(list), len(all))
	}
	autoCount := 0
	for _, in := range list {
		if !in.Auto {
			continue
		}
		autoCount++
		if in.Virtual || in.Public {
			t.Errorf("%s 被标为自动可用，但 virtual=%v public=%v", in.Name, in.Virtual, in.Public)
		}
	}
	if want := len(selectTargets(all, "")); autoCount != want {
		t.Fatalf("标为自动的有 %d 张，实际发送会用 %d 张", autoCount, want)
	}
	t.Logf("本机 %d 张可广播网卡，自动模式会用 %d 张：%s", len(all), autoCount, describeTargets(all))
}
