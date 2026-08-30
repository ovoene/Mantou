package server

import (
	"strings"
	"testing"

	"mantou/internal/config"
)

// 本文件盯的是通知目标地址的保存时校验（2.14-D 的可修部分）。
//
// 原先只判前缀（strings.HasPrefix(url, "http://")），于是 "http://" 这么一个串
// 就能存进去：保存成功、界面上一切正常，而每一次投递都在 http.NewRequest 那里失败，
// 报的还是一句看不出跟地址有关的话。钉钉那一侧更绕——dingSignedURL 要先解析地址，
// 解析不开连签都算不出来。

// urlTarget 造一条只改了地址的 type=http 目标。
func urlTarget(raw string) config.NotifyTarget {
	return config.NotifyTarget{Name: "自建接口", Type: "http", URL: raw}
}

func TestNotifyTargetURLValidation(t *testing.T) {
	cases := []struct {
		name string
		url  string
		want string // 空表示应当通过
	}{
		{name: "正常地址", url: "https://example.com/hook", want: ""},
		{name: "带查询串", url: "https://example.com/hook?token=abc&x=1", want: ""},
		{name: "带端口", url: "http://example.com:8080/in", want: ""},
		{name: "带基本认证", url: "https://u:p@example.com/in", want: ""},
		// 大写 scheme 照样发得出去，原先被前缀判断拦着，属于白拦。
		{name: "大写 scheme", url: "HTTPS://example.com/hook", want: ""},
		// 内网地址**不**在这里拦：那是「内网防护」开关的事，而它默认关闭正是为了
		// 兼容接收端本就在内网的自建场景。这一条是防止有人把主机黑名单加到这里，
		// 那会让一批正常配置突然存不下，而用户完全不知道为什么。
		{name: "内网地址不在这里拦", url: "http://127.0.0.1:9200/in", want: ""},
		{name: "只有 scheme", url: "http://", want: "缺少主机名"},
		{name: "主机名是空的", url: "https:///hook", want: "缺少主机名"},
		{name: "不支持的 scheme", url: "ftp://example.com/in", want: "必须以 http:// 或 https:// 开头"},
		{name: "没有 scheme", url: "example.com/in", want: "必须以 http:// 或 https:// 开头"},
		// 控制字符让 url.Parse 直接报错，走的是同一句提示。
		{name: "地址里有换行", url: "http://exa\nmple.com/in", want: "必须以 http:// 或 https:// 开头"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := validateNotifyTarget(urlTarget(c.url))
			if c.want == "" {
				if err != nil {
					t.Fatalf("%q 应能保存，实际 %v", c.url, err)
				}
				return
			}
			if err == nil {
				t.Fatalf("%q 应被拒", c.url)
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Fatalf("%q 的报错应包含 %q，实际 %q", c.url, c.want, err.Error())
			}
		})
	}
}

// 缺主机名与 scheme 不对要报**两句不同的话**。
//
// 合成一句"地址不合法"的话，填了 "http://" 的人会去检查开头那几个字母——
// 而那里恰恰是对的，错的是后面什么都没填。
func TestNotifyTargetURLErrorsAreDistinct(t *testing.T) {
	noHost := validateNotifyTarget(urlTarget("http://"))
	badScheme := validateNotifyTarget(urlTarget("ftp://example.com"))
	if noHost == nil || badScheme == nil {
		t.Fatal("两种都应被拒")
	}
	if noHost.Error() == badScheme.Error() {
		t.Fatalf("两种毛病报了同一句话：%q", noHost.Error())
	}
	if strings.Contains(noHost.Error(), "http:// 或 https://") {
		t.Fatalf("缺主机名却在说开头写错了：%q", noHost.Error())
	}
}
