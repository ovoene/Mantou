package server

import (
	"testing"

	"mantou/internal/config"
)

// validateForward 是保存端口转发规则时唯一的关卡。这里只钉「端口范围」这一段新加的校验：
// 展开层（forward.expandRule）对越界 / 倒置 / 超上限 / 递增溢出都会静默兜底，保存这一关要把
// 这些明确拦下，别让用户配了一整段却只生效一截而毫无提示。纯校验、无网络无时钟。
func TestValidateForwardRange(t *testing.T) {
	// base 是一条能通过其余所有校验的单端口规则，各用例只改与范围相关的字段。
	base := config.ForwardRule{Protocol: "tcp", ListenPort: 8000, TargetHost: "127.0.0.1", TargetPort: 9000}

	cases := []struct {
		name    string
		mod     func(r *config.ForwardRule)
		wantErr bool
	}{
		{"单端口：无范围放行", func(r *config.ForwardRule) {}, false},
		{"递增范围正常放行", func(r *config.ForwardRule) { r.ListenPortEnd = 8009 }, false},
		{"多对一范围正常放行", func(r *config.ForwardRule) { r.ListenPortEnd = 8009; r.SameTargetPort = true }, false},
		{"范围正好到上限放行", func(r *config.ForwardRule) { r.ListenPortEnd = r.ListenPort + config.MaxForwardRangePorts - 1 }, false},
		{"终点小于起点被拒", func(r *config.ForwardRule) { r.ListenPortEnd = 7999 }, true},
		{"终点越界被拒", func(r *config.ForwardRule) { r.ListenPortEnd = 70000 }, true},
		{"范围超过上限被拒", func(r *config.ForwardRule) { r.ListenPortEnd = r.ListenPort + config.MaxForwardRangePorts }, true},
		{"递增目标溢出 65535 被拒", func(r *config.ForwardRule) { r.ListenPortEnd = 8100; r.TargetPort = 65500 }, true},
		{"多对一同区间不受溢出影响放行", func(r *config.ForwardRule) { r.ListenPortEnd = 8100; r.TargetPort = 65500; r.SameTargetPort = true }, false},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := base
			c.mod(&r)
			err := validateForward(nil, r)
			if (err != nil) != c.wantErr {
				t.Fatalf("validateForward 返回 err=%v，wantErr=%v", err, c.wantErr)
			}
		})
	}
}
