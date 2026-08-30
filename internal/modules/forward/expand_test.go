package forward

import (
	"testing"

	"mantou/internal/config"
)

// expandRule 是端口范围 → 单端口运行项的唯一映射点，两种目标端口映射（递增 / 多对一）都在这里分叉。
// 本测试只钉这层纯计算：给定监听段与映射方式，展开出的 监听端口→目标端口 对是否精确符合预期。
// 无网络、无时钟，故不受本机时钟粒度影响（见记忆 go-test-time-now-ties 的坑）。
func TestExpandRuleTargetMapping(t *testing.T) {
	// portMap 把展开结果压成 监听端口→目标端口，顺带校验 key/父 ID 与端口一致。
	portMap := func(t *testing.T, rule config.ForwardRule) map[int]int {
		t.Helper()
		m := make(map[int]int)
		for _, er := range expandRule(rule) {
			if er.parentID != rule.ID {
				t.Fatalf("parentID = %q，应为 %q", er.parentID, rule.ID)
			}
			if er.rule.ListenPortEnd != 0 {
				t.Fatalf("展开后单端口项的 ListenPortEnd 应清零，得 %d", er.rule.ListenPortEnd)
			}
			m[er.rule.ListenPort] = er.rule.TargetPort
		}
		return m
	}

	base := config.ForwardRule{ID: "r1", Name: "t", Protocol: "tcp", TargetHost: "127.0.0.1"}

	cases := []struct {
		name string
		mod  func(r *config.ForwardRule)
		want map[int]int
	}{
		{
			name: "递增：监听段每个端口按偏移映射",
			mod:  func(r *config.ForwardRule) { r.ListenPort, r.ListenPortEnd, r.TargetPort = 8000, 8002, 9000 },
			want: map[int]int{8000: 9000, 8001: 9001, 8002: 9002},
		},
		{
			name: "多对一：监听段所有端口都落到同一个目标端口",
			mod: func(r *config.ForwardRule) {
				r.ListenPort, r.ListenPortEnd, r.TargetPort, r.SameTargetPort = 8000, 8002, 9000, true
			},
			want: map[int]int{8000: 9000, 8001: 9000, 8002: 9000},
		},
		{
			name: "单端口：无范围时映射方式不影响结果",
			mod:  func(r *config.ForwardRule) { r.ListenPort, r.TargetPort, r.SameTargetPort = 8000, 9000, true },
			want: map[int]int{8000: 9000},
		},
		{
			// 递增下目标端口一旦越过 65535 就跳过那一项；多对一恒等于 TargetPort，不受偏移溢出影响。
			name: "边界：递增溢出 65535 被跳过",
			mod:  func(r *config.ForwardRule) { r.ListenPort, r.ListenPortEnd, r.TargetPort = 65534, 65535, 65535 },
			want: map[int]int{65534: 65535},
		},
		{
			name: "边界：多对一在同一区间两个端口都保留",
			mod: func(r *config.ForwardRule) {
				r.ListenPort, r.ListenPortEnd, r.TargetPort, r.SameTargetPort = 65534, 65535, 65535, true
			},
			want: map[int]int{65534: 65535, 65535: 65535},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := base
			c.mod(&r)
			got := portMap(t, r)
			if len(got) != len(c.want) {
				t.Fatalf("展开出 %d 项，应为 %d 项：%v", len(got), len(c.want), got)
			}
			for lp, tp := range c.want {
				if got[lp] != tp {
					t.Errorf("监听 %d → 目标 %d，应为 %d", lp, got[lp], tp)
				}
			}
		})
	}
}
