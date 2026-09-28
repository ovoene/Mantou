package ddns

import (
	"context"
	"strings"
	"testing"
	"time"

	"mantou/internal/config"
)

// 保存接口原先对 DDNS 规则一项都不查，运行期拿到什么就往服务商那里发什么。
// 下面钉住 ValidateRule 的判定，以及运行期在动手之前就把坏规则拦下。

func validRule() config.DDNSRule {
	return config.DDNSRule{
		ID: "r", Name: "r", Enabled: true, Stack: "ipv4", IntervalSec: 300,
		Source: config.DDNSSource{Type: "public"},
		Targets: []config.DDNSTarget{{
			CredentialRef: "c1", Domain: "example.com", Subdomains: []string{"home", "*.lab"},
			RecordType: "A", TTL: 600,
		}},
	}
}

func TestValidateRuleAcceptsNormalRule(t *testing.T) {
	if err := ValidateRule(validRule()); err != nil {
		t.Fatalf("正常的规则不该被拒：%v", err)
	}
	// 中文域名按 Unicode 原样提交给服务商，不能误伤。
	r := validRule()
	r.Targets[0].Domain = "例子.中国"
	if err := ValidateRule(r); err != nil {
		t.Fatalf("中文域名不该被拒：%v", err)
	}
	// 0 表示默认间隔。
	r = validRule()
	r.IntervalSec = 0
	if err := ValidateRule(r); err != nil {
		t.Fatalf("间隔 0（取默认）不该被拒：%v", err)
	}
}

func TestValidateRuleRejects(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(r *config.DDNSRule)
		want   string
	}{
		{"间隔过短", func(r *config.DDNSRule) { r.IntervalSec = 1 }, "探测间隔"},
		{"协议栈无效", func(r *config.DDNSRule) { r.Stack = "ipx" }, "协议栈"},
		{"取址方式无效", func(r *config.DDNSRule) { r.Source.Type = "shell" }, "取址方式"},
		{"取址地址协议不对", func(r *config.DDNSRule) { r.Source = config.DDNSSource{Type: "url", URL: "file:///etc/passwd"} }, "取址地址"},
		{"正则写错", func(r *config.DDNSRule) { r.Source = config.DDNSSource{Type: "url", Regex: "("} }, "正则"},
		{"域名带斜杠", func(r *config.DDNSRule) { r.Targets[0].Domain = "example.com/../v1/domains" }, "主域名"},
		{"域名带问号", func(r *config.DDNSRule) { r.Targets[0].Domain = "example.com?x=1" }, "主域名"},
		{"域名为空", func(r *config.DDNSRule) { r.Targets[0].Domain = " " }, "主域名"},
		{"域名空段", func(r *config.DDNSRule) { r.Targets[0].Domain = "example..com" }, "主域名"},
		{"主机记录带斜杠", func(r *config.DDNSRule) { r.Targets[0].Subdomains = []string{"a/b"} }, "主机记录"},
		{"主机记录中间的通配", func(r *config.DDNSRule) { r.Targets[0].Subdomains = []string{"a.*"} }, "主机记录"},
		{"记录类型无效", func(r *config.DDNSRule) { r.Targets[0].RecordType = "CNAME" }, "记录类型"},
		{"记录类型与协议栈不符", func(r *config.DDNSRule) { r.Stack = "ipv6" }, "AAAA"},
		{"TTL 越界", func(r *config.DDNSRule) { r.Targets[0].TTL = -1 }, "TTL"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := validRule()
			tc.mutate(&r)
			err := ValidateRule(r)
			if err == nil {
				t.Fatalf("应当被拒")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("错误里应说明 %q，实际：%v", tc.want, err)
			}
		})
	}
}

// TestExecuteRejectsInvalidRule 运行期动手之前就拦下坏规则：导入与手改的配置没经过保存校验，
// 停用中的规则也能被手动「立即执行」。拦下时要留一条状态让用户看见原因。
func TestExecuteRejectsInvalidRule(t *testing.T) {
	bad := validRule()
	bad.Targets[0].Domain = "example.com/evil"
	fake := &fakeCfg{rules: []config.DDNSRule{bad}}
	r := newRuleRunner(bad, quietLog(), fake)
	defer r.stop()

	_, err := r.execute(context.Background())
	if err == nil || !strings.Contains(err.Error(), "主域名") {
		t.Fatalf("坏规则应在动手前被拒，实际 err=%v", err)
	}
	n, last := fake.stats()
	if n != 1 || !strings.Contains(last.LastStatus, "规则配置无效") {
		t.Fatalf("应回写一条说明原因的状态，实际写了 %d 次：%q", n, last.LastStatus)
	}
}

// TestIntervalClampedToFloor 导入或手改进来的过短间隔在运行期被夹到下限。
func TestIntervalClampedToFloor(t *testing.T) {
	r := newRuleRunner(config.DDNSRule{IntervalSec: 1}, quietLog(), &fakeCfg{})
	defer r.stop()
	if got := r.interval(); got != MinIntervalSec*time.Second {
		t.Fatalf("间隔 1 秒应被夹到 %d 秒，实际 %s", MinIntervalSec, got)
	}
}
