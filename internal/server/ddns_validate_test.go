package server

import (
	"strings"
	"testing"

	"mantou/internal/config"
)

// DDNS 规则的保存校验：写法判定委托给 ddns.ValidateRule（那边有完整用例），
// 这里钉住只有保存接口才判得了的几条，以及"只在启用时校验"这个口径。

func ddnsTestCfg() *config.Config {
	return &config.Config{Credentials: []config.Credential{{ID: "c1", Name: "cf", Provider: "cloudflare"}}}
}

func ddnsTestRule() config.DDNSRule {
	return config.DDNSRule{
		ID: "r1", Name: "home", Enabled: true, Stack: "ipv4", IntervalSec: 300,
		Source:  config.DDNSSource{Type: "public"},
		Targets: []config.DDNSTarget{{CredentialRef: "c1", Domain: "example.com", Subdomains: []string{"home"}}},
	}
}

func TestValidateDDNSAcceptsNormalRule(t *testing.T) {
	if err := validateDDNS(ddnsTestCfg(), ddnsTestRule()); err != nil {
		t.Fatalf("正常规则不该被拒：%v", err)
	}
}

func TestValidateDDNSRejects(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(r *config.DDNSRule)
		want   string
	}{
		{"没有目标", func(r *config.DDNSRule) { r.Targets = nil }, "至少需要一个更新目标"},
		{"凭证不存在", func(r *config.DDNSRule) { r.Targets[0].CredentialRef = "gone" }, "凭证不存在"},
		{"没选凭证", func(r *config.DDNSRule) { r.Targets[0].CredentialRef = "" }, "凭证不存在"},
		{"没有任何记录", func(r *config.DDNSRule) { r.Targets[0].Subdomains = []string{"@", " "} }, "主机记录"},
		{"写法不合法", func(r *config.DDNSRule) { r.Targets[0].Domain = "example.com/x" }, "主域名"},
		{"间隔过短", func(r *config.DDNSRule) { r.IntervalSec = 5 }, "探测间隔"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := ddnsTestRule()
			tc.mutate(&r)
			err := validateDDNS(ddnsTestCfg(), r)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("应因 %q 被拒，实际：%v", tc.want, err)
			}
		})
	}
}

// TestValidateDDNSDisabledAlwaysSaves 停用中的规则不校验：列表开关走整行 PUT，
// 一份导入进来的坏规则若连"关掉"都被拦下，就成了走不出去的死角。
func TestValidateDDNSDisabledAlwaysSaves(t *testing.T) {
	r := ddnsTestRule()
	r.Enabled = false
	r.IntervalSec = 1
	r.Targets[0].CredentialRef = "gone"
	if err := validateDDNS(ddnsTestCfg(), r); err != nil {
		t.Fatalf("停用中的规则不该被校验拦下：%v", err)
	}
}
