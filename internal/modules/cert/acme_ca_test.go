package cert

import (
	"strings"
	"testing"

	"mantou/internal/config"
)

// caDirectoryURL 原先在"认不出来"时回落到 Let's Encrypt。那条回落最坏的形态是：
// 用户想用私有 CA，把地址写成 acme.corp.internal/directory（漏了 https://），
// 于是域名清单和账户密钥发给了 Let's Encrypt，证书还真签出来了——从头到尾没有一处
// 看起来不对。本文件钉住"认不出来一律拒绝"，同时反向钉住四个内置名字和合法的
// https:// 自定义地址必须照旧能用。

func TestCADirectoryURL(t *testing.T) {
	const custom = "https://acme.corp.internal/directory"
	for _, tc := range []struct {
		name string
		ca   string
		want string // 空串=期望被拒
	}{
		{name: "空按默认 CA", ca: "", want: letsEncryptDirectoryURL},
		{name: "默认 CA", ca: "letsencrypt", want: letsEncryptDirectoryURL},
		{name: "两侧空白照样认", ca: "  letsencrypt  ", want: letsEncryptDirectoryURL},
		{name: "测试环境", ca: "letsencrypt-staging", want: "https://acme-staging-v02.api.letsencrypt.org/directory"},
		{name: "ZeroSSL", ca: "zerossl", want: "https://acme.zerossl.com/v2/DV90"},
		{name: "Buypass", ca: "buypass", want: "https://api.buypass.com/acme/directory"},
		{name: "自定义 https 目录", ca: custom, want: custom},
		// 协议名不区分大小写，url.Parse 也会归一化，不该因为一个大写就被拒。
		{name: "大写协议名", ca: "HTTPS://acme.corp.internal/directory", want: "HTTPS://acme.corp.internal/directory"},

		{name: "明文目录", ca: "http://acme.corp.internal/directory"},
		{name: "大写的明文目录", ca: "HTTP://acme.corp.internal/directory"},
		{name: "漏写协议", ca: "acme.corp.internal/directory"},
		{name: "只有主机名", ca: "acme.corp.internal"},
		{name: "内置名字打错", ca: "letsencryp"},
		{name: "大小写不同的内置名字", ca: "LetsEncrypt"},
		{name: "协议名打错", ca: "htps://acme.corp.internal/directory"},
		{name: "短到装不下协议头", ca: "https:/"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := caDirectoryURL(tc.ca)
			if got != tc.want {
				if tc.want == "" {
					t.Fatalf("CA %q 应当被拒（返回空串），实际拿到 %q", tc.ca, got)
				}
				t.Fatalf("CA %q 期望 %q，实际 %q", tc.ca, tc.want, got)
			}
		})
	}
}

// 预检必须在下单之前就把认不出来的 CA 拦住，并且报错里要带上那个值本身——
// 用户看到的是自己填错的那一串，才知道该改哪里。
func TestPrecheckIssueRejectsUnrecognizedCA(t *testing.T) {
	target := config.Certificate{
		Method:         "acme",
		Domains:        []string{"example.com"},
		ACMEAccountRef: "account1",
		CredentialRef:  "credential1",
	}
	bad := config.ACMEAccount{ID: "account1", CA: "acme.corp.internal/directory"}
	err := precheckIssue(target, bad, "cloudflare")
	if err == nil {
		t.Fatal("漏写协议的自定义 CA 应当在预检阶段就被拦下")
	}
	if !strings.Contains(err.Error(), bad.CA) {
		t.Errorf("报错里应当带上填错的那个值，实际：%v", err)
	}
	if !strings.Contains(err.Error(), "https://") {
		t.Errorf("报错里应当说清自定义目录要以 https:// 开头，实际：%v", err)
	}

	// 反向：合法的 https 自定义目录不能被这道闸挡住。
	ok := config.ACMEAccount{ID: "account1", CA: "https://acme.corp.internal/directory"}
	if err := precheckIssue(target, ok, "cloudflare"); err != nil {
		t.Errorf("合法的自定义 https 目录应当通过预检，实际：%v", err)
	}
}
