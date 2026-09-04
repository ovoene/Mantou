package server

import (
	"testing"

	"mantou/internal/config"
)

// 这一组盯 B-5：Update.GitHubRepo 会被**拼进** GitHub API 地址
// （https://api.github.com/repos/<repo>/releases/latest），所以它的形状必须先校验。
//
// 主机名换不掉（authority 早已闭合），能改的是路径：填 "../../users/someone" 这类段名
// 可以把检测请求挪到另一个接口，再把那边返回的 html_url 当"新版本下载页"显示在面板上。

func TestGitHubRepoRejectsPathEscapes(t *testing.T) {
	bad := []string{
		"../../users/someone",       // 目录穿越：换掉整个接口
		"../..",                     // 同上，最短形式
		"ovoene/../../gists/public", // 前半段看着正常，后半段跑了
		"ovoene/Mantou/../../orgs",  // 多一层路径
		"ovoene/Mantou?x=1",         // 带查询串
		"ovoene/Mantou#frag",        // 带片段
		"ovoene",                    // 少一段
		"ovoene/",                   // 空仓库名
		"/Mantou",                   // 空 owner
		"ovoene//Mantou",            // 空中间段
		"ovoene/Man tou",            // 含空格
		"ovoene/Mantou/extra",       // 三段
		".",
		"..",
		"./Mantou",
		"ovoene/.",
		"ovoene/..",
		"a%2f/b",     // 百分号编码的斜杠
		"a\\b/c",     // 反斜杠
		"a@b/c",      // 会被 url.Parse 当 userinfo 的字符
		"a:b/c",      // 冒号
		"http://x/y", // 完整地址不是合法的 owner/name（另有 validGitHubRepoField 收它）
	}
	for _, r := range bad {
		if validGitHubRepo(r) {
			t.Errorf("%q 被判为合法的 owner/name——它能改写 GitHub API 请求的路径", r)
		}
	}
}

func TestGitHubRepoAcceptsRealNames(t *testing.T) {
	good := []string{
		"ovoene/Mantou",
		"golang/go",
		"a/b",
		"some-org/some.repo",
		"some-org/some_repo",
		"Org123/repo-4.5_6",
	}
	for _, r := range good {
		if !validGitHubRepo(r) {
			t.Errorf("%q 是个正常的仓库标识，不该被拒", r)
		}
	}
}

// githubRepoOf 是真正的使用点，所有来源（手改 config.json、导入备份、写入接口）
// 最后都汇到它。不合法必须退回默认仓库，而不是照原样拼进 URL。
func TestGitHubRepoOfFallsBackOnJunk(t *testing.T) {
	cases := []struct {
		raw  string
		want string
	}{
		{raw: "", want: defaultGitHubRepo},
		{raw: "   ", want: defaultGitHubRepo},
		{raw: "../../users/someone", want: defaultGitHubRepo},
		{raw: "not a repo", want: defaultGitHubRepo},
		{raw: "ovoene/Mantou", want: "ovoene/Mantou"},
		{raw: "  ovoene/Mantou  ", want: "ovoene/Mantou"},
		// 前端允许把这一项填成完整地址；github.com 的地址要能抽出 owner/name，
		// 否则界面上的仓库链接指向用户填的仓库、版本检测却在查默认仓库，两处对不上。
		{raw: "https://github.com/golang/go", want: "golang/go"},
		{raw: "https://github.com/golang/go/", want: "golang/go"},
		{raw: "https://www.github.com/golang/go", want: "golang/go"},
		{raw: "https://github.com/golang/go.git", want: "golang/go"},
		{raw: "https://github.com/golang/go/releases", want: "golang/go"},
		// 别的站点抽不出对应关系，退回默认。
		{raw: "https://example.com/golang/go", want: defaultGitHubRepo},
		{raw: "https://github.com/onlyowner", want: defaultGitHubRepo},
		// 借 github.com 前缀做穿越的也要退回默认。
		{raw: "https://github.com/../../gists", want: defaultGitHubRepo},
	}
	for _, tc := range cases {
		cfg := &config.Config{}
		cfg.Update.GitHubRepo = tc.raw
		if got := githubRepoOf(cfg); got != tc.want {
			t.Errorf("githubRepoOf(%q) = %q，期望 %q", tc.raw, got, tc.want)
		}
	}
}

// 写入接口收两种写法，但不收其它协议：这个值会变成页面上的 href。
func TestGitHubRepoFieldAcceptsURLsButNotOtherSchemes(t *testing.T) {
	for _, ok := range []string{"ovoene/Mantou", "https://github.com/golang/go", "http://git.example.com/a/b"} {
		if !validGitHubRepoField(ok) {
			t.Errorf("%q 应当可以保存", ok)
		}
	}
	for _, bad := range []string{"javascript:alert(1)", "data:text/html,x", "file:///etc/passwd", "../../users/someone", "ftp://example.com/x"} {
		if validGitHubRepoField(bad) {
			t.Errorf("%q 不该被保存：它会变成页面上的链接", bad)
		}
	}
}
