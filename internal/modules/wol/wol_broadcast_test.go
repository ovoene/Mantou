package wol

import (
	"strings"
	"testing"
)

// TestValidBroadcastAllows 允许的目标：自动模式、各类内网 / 保留地址与其定向广播地址。
func TestValidBroadcastAllows(t *testing.T) {
	cases := []struct {
		in  string
		why string
	}{
		{"", "留空 = 自动逐网卡广播"},
		{"   ", "只有空白 = 自动"},
		{"255.255.255.255", "受限广播（全局广播）"},
		{" 255.255.255.255 ", "带空白的受限广播"},
		{"192.168.1.255", "家用网段的定向广播"},
		{"192.168.1.50", "内网单播（只唤醒这一台）"},
		{"10.0.0.255", "10/8 定向广播"},
		{"10.255.255.255", "10/8 全网段广播"},
		{"172.16.5.255", "172.16/12 定向广播"},
		{"172.31.255.255", "172.16/12 上界"},
		{"169.254.1.255", "链路本地"},
		{"127.0.0.1", "回环（测试用）"},
		{"100.64.0.255", "运营商级 NAT（家宽常见）"},
		{"224.0.0.1", "链路本地多播"},
		{"::1", "IPv6 回环"},
		{"fe80::1", "IPv6 链路本地"},
		{"fd00::1", "IPv6 唯一本地地址"},
	}
	for _, c := range cases {
		if err := ValidBroadcast(c.in); err != nil {
			t.Errorf("%q（%s）应被允许，却报错: %v", c.in, c.why, err)
		}
	}
}

// TestValidBroadcastRejectsPublic 锁定 W-5：公网地址不得作为唤醒目标。
// 放开它等于让本模块变成一个绕过 netguard 的任意 UDP 发包器。
func TestValidBroadcastRejectsPublic(t *testing.T) {
	cases := []struct {
		in  string
		why string
	}{
		{"8.8.8.8", "公共 DNS"},
		{"1.1.1.1", "公共 DNS"},
		{"93.184.216.34", "任意公网主机"},
		{"100.63.255.255", "紧邻运营商级 NAT 下界之外，属公网"},
		{"100.128.0.1", "紧邻运营商级 NAT 上界之外，属公网"},
		{"172.32.0.1", "紧邻 172.16/12 上界之外，属公网"},
		{"192.169.0.1", "紧邻 192.168/16 之外，属公网"},
		{"11.0.0.1", "紧邻 10/8 之外，属公网"},
		{"2001:4860:4860::8888", "公网 IPv6"},
	}
	for _, c := range cases {
		err := ValidBroadcast(c.in)
		if err == nil {
			t.Errorf("%q（%s）应被拒绝", c.in, c.why)
			continue
		}
		// 报错必须说清为什么以及该怎么填，否则用户只会看到一句「不允许」。
		if !strings.Contains(err.Error(), "公网地址") {
			t.Errorf("%q 的报错未说明原因: %v", c.in, err)
		}
	}
}

// TestValidBroadcastRejectsMalformed 非 IP 字面量一律拒绝。
// 域名尤其重要：net.ResolveUDPAddr 会对它做 DNS 解析，
// 而 wol.Wake 是同步的——一次慢解析就会把调用方挂住。
func TestValidBroadcastRejectsMalformed(t *testing.T) {
	for _, in := range []string{
		"example.com",
		"wol.example.com",
		"192.168.1.999",
		"192.168.1",
		"192.168.1.255/24",
		"not an ip",
		"0x7f000001",
	} {
		if err := ValidBroadcast(in); err == nil {
			t.Errorf("%q 应被拒绝（非法 IP 字面量）", in)
		}
	}
}

// TestWakeRejectsPublicTarget 发送路径本身也必须拦：
// config.json 可以被手工编辑、也可以整份导入，两条路都不经过 API 校验。
func TestWakeRejectsPublicTarget(t *testing.T) {
	err := Wake("AA:BB:CC:DD:EE:FF", "8.8.8.8", 9, "")
	if err == nil {
		t.Fatal("Wake 应拒绝公网目标：手工编辑 / 导入配置可以绕过 API 校验")
	}
	if !strings.Contains(err.Error(), "公网地址") {
		t.Fatalf("报错未说明原因: %v", err)
	}
}

// TestWakeChecksTargetBeforeSending 目标非法时不得发出任何包，
// 且报错要早于（也不依赖）网卡枚举。
func TestWakeChecksTargetBeforeSending(t *testing.T) {
	// MAC 非法优先于目标地址报错：先拦最便宜的那一层。
	if err := Wake("不是MAC", "8.8.8.8", 9, ""); err == nil {
		t.Fatal("MAC 非法时应报错")
	} else if strings.Contains(err.Error(), "公网地址") {
		t.Fatalf("应先报 MAC 的错，实际报了目标地址的错: %v", err)
	}
}
