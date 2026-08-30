package server

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"mantou/internal/config"
)

// 本文件盯的是设置里几个「程序会主动去请求它」的地址字段的保存时校验（5-L / 2.13-F）。
//
// 原先它们只 TrimSpace 就落盘，连 scheme 都不看：填成一段普通文字也能保存成功，
// 报错要等到真去请求那一刻，而那时界面上写的是「检查更新失败」，指不到真正的原因上。

// settingsURLFields 两个字段各给一份「怎么把这个值包成请求体」和「保存后从配置里怎么读回来」。
//
// 原先还有第三个「通知地址」（Settings.Notify.WebhookURL）。它只被这个保存接口写入、
// 没有任何一处读取，前端也从不引用，是早期留下的空壳，已随字段一并删除——
// 给一个谁都不读的字段做校验，收益是 0。
var settingsURLFields = []struct {
	name string
	body func(string) string
	read func(*config.Config) string
}{
	{
		name: "版本清单地址",
		body: func(v string) string { return `{"update":{"manifestUrl":` + jsonStr(v) + `}}` },
		read: func(c *config.Config) string { return c.Update.ManifestURL },
	},
	{
		name: "更新下载页地址",
		body: func(v string) string { return `{"update":{"releaseUrl":` + jsonStr(v) + `}}` },
		read: func(c *config.Config) string { return c.Update.ReleaseURL },
	},
}

func jsonStr(v string) string {
	b, _ := json.Marshal(v)
	return string(b)
}

func TestSettingsURLValidation(t *testing.T) {
	cases := []struct {
		name string
		url  string
		want string // 空表示应当保存成功
	}{
		{name: "正常地址", url: "https://example.com/v.json", want: ""},
		{name: "http 也可以", url: "http://example.com:8080/v.json", want: ""},
		// 大写 scheme 照样请求得出去（url.Parse 会折成小写），拦下来属于白拦。
		{name: "大写 scheme", url: "HTTPS://example.com/v.json", want: ""},
		// 内网地址**不**在这里拦：那是「内网防护」开关的事，自建部署的清单地址
		// 本来就可能在内网。这一条是防止有人把主机黑名单加到这里。
		{name: "内网地址不在这里拦", url: "http://192.168.1.9/v.json", want: ""},
		{name: "留空表示不启用", url: "", want: ""},
		{name: "只有空白也算留空", url: "   ", want: ""},
		{name: "只有 scheme", url: "http://", want: "缺少主机名"},
		{name: "主机名是空的", url: "https:///v.json", want: "缺少主机名"},
		{name: "不支持的 scheme", url: "ftp://example.com/v.json", want: "必须以 http:// 或 https:// 开头"},
		{name: "file 协议", url: "file:///etc/passwd", want: "必须以 http:// 或 https:// 开头"},
		{name: "没有 scheme", url: "example.com/v.json", want: "必须以 http:// 或 https:// 开头"},
		{name: "压根不是地址", url: "改成我们内网那个", want: "必须以 http:// 或 https:// 开头"},
		{name: "地址里有换行", url: "http://exa\nmple.com/v.json", want: "必须以 http:// 或 https:// 开头"},
	}
	for _, f := range settingsURLFields {
		for _, c := range cases {
			t.Run(f.name+"/"+c.name, func(t *testing.T) {
				s, cfg := panelPortEnv(t)
				before := f.read(cfg.Snapshot())
				rec := putSettings(t, s, f.body(c.url))
				if c.want != "" {
					if rec.Code != http.StatusBadRequest {
						t.Fatalf("%q 应被拒，实际 %d：%s", c.url, rec.Code, rec.Body.String())
					}
					if !strings.Contains(rec.Body.String(), c.want) {
						t.Fatalf("%q 的报错应包含 %q，实际 %s", c.url, c.want, rec.Body.String())
					}
					// 被拒的值一个字都不该落盘。
					if got := f.read(cfg.Snapshot()); got != before {
						t.Fatalf("%q 被拒了却还是存进了配置：%q", c.url, got)
					}
					return
				}
				if rec.Code != http.StatusOK {
					t.Fatalf("%q 应能保存，实际 %d：%s", c.url, rec.Code, rec.Body.String())
				}
				// 存下来的应当是去掉首尾空白之后的值：校验判的是这个形态，
				// 存的却是原样，就会出现"存下来的跟刚校验过的不是一个"。
				if got, want := f.read(cfg.Snapshot()), strings.TrimSpace(c.url); got != want {
					t.Fatalf("存下来的是 %q，应为 %q", got, want)
				}
			})
		}
	}
}

// TestSettingsURLErrorNamesTheField 报错要点出是哪个字段，不能只说"地址不合法"。
//
// 这一页上有三个地址输入框，报一句不带字段名的话，用户得逐个试。
func TestSettingsURLErrorNamesTheField(t *testing.T) {
	for _, f := range settingsURLFields {
		s, _ := panelPortEnv(t)
		rec := putSettings(t, s, f.body("ftp://example.com"))
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("%s：应被拒，实际 %d", f.name, rec.Code)
		}
		if !strings.Contains(rec.Body.String(), f.name) {
			t.Fatalf("%s 的报错里没提这个字段：%s", f.name, rec.Body.String())
		}
	}
}

// TestSettingsURLRejectionKeepsOldValue 一次提交里有个地址不合法，别的字段也不许落盘。
//
// 校验放在 Config.Update 之前就是为了这个：中途 respondError 返回，配置文件压根没被改过。
func TestSettingsURLRejectionKeepsOldValue(t *testing.T) {
	s, cfg := panelPortEnv(t)
	if rec := putSettings(t, s, `{"update":{"manifestUrl":"https://good.example.com/v.json"}}`); rec.Code != http.StatusOK {
		t.Fatalf("前提：正常地址应能存下，实际 %d：%s", rec.Code, rec.Body.String())
	}
	rec := putSettings(t, s, `{"language":"en-US","update":{"manifestUrl":"不是地址","githubRepo":"someone/thing"}}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("应被拒，实际 %d：%s", rec.Code, rec.Body.String())
	}
	after := cfg.Snapshot()
	if after.Update.ManifestURL != "https://good.example.com/v.json" {
		t.Fatalf("清单地址被那次失败的提交改掉了：%q", after.Update.ManifestURL)
	}
	if after.Update.GitHubRepo != "" {
		t.Fatalf("同一次提交里的其它字段也不该落盘，仓库变成了 %q", after.Update.GitHubRepo)
	}
	if after.Settings.Language == "en-US" {
		t.Fatal("同一次提交里的语言也不该落盘")
	}
}
