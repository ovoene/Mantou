package server

import (
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"mantou/internal/config"
)

// 静态站点根目录那道闸原先只比字面的 "/data"，于是它**只在容器镜像里生效**：
// 原生部署的数据目录可以在任何地方（--data ./data、D:\mantou\data），把它填成
// 站点根就能通过校验，然后 config.json 与证书私钥（.key 是明文存的）
// 就成了公开可取的静态资源。
//
// 本文件钉住两件事：按本进程实际的数据目录比，且两个方向都拦
// （根目录在数据目录里面 / 数据目录在根目录里面）。

func TestValidateStaticRootAgainstDataDir(t *testing.T) {
	base := t.TempDir()
	data := filepath.Join(base, "data")
	cases := []struct {
		name    string
		root    string
		dataDir string
		want    string // 期望错误里出现的字样；空串=必须通过
	}{
		{name: "空", root: "  ", dataDir: data, want: "不能为空"},
		{name: "系统根", root: "/", dataDir: data, want: "系统根目录"},
		{name: "当前目录", root: ".", dataDir: data, want: "系统根目录"},
		// 容器里数据目录固定在 /data，这一条对任何平台都先拦一道。
		{name: "容器数据目录", root: "/data", dataDir: "", want: "数据目录"},
		{name: "容器数据目录的子目录", root: "/data/uploads", dataDir: "", want: "数据目录"},

		{name: "就是数据目录本身", root: data, dataDir: data, want: "数据目录"},
		{name: "数据目录的子目录", root: filepath.Join(data, "uploads"), dataDir: data, want: "数据目录"},
		{name: "数据目录未尾斜杠归一化", root: data + string(filepath.Separator), dataDir: data, want: "数据目录"},
		// 反方向：把整个项目目录当站点根，data/ 就成了它下面的一个子路径，
		// /data/config.json 直接可取——不看方向的话这条会漏。
		{name: "包含数据目录", root: base, dataDir: data, want: "数据目录"},

		{name: "同级的另一个目录", root: filepath.Join(base, "www"), dataDir: data},
		{name: "名字是数据目录前缀但不是它的子目录", root: data + "-backup", dataDir: data},
		{name: "没给数据目录时按老规矩放过", root: filepath.Join(base, "www"), dataDir: ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateStaticRoot(tc.root, tc.dataDir)
			if tc.want == "" {
				if err != nil {
					t.Fatalf("应当通过，实际报错：%v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("应当报错（含 %q），实际通过了", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("错误里应含 %q，实际：%v", tc.want, err)
			}
		})
	}

	// Windows 上路径不区分大小写，只按字符串比会被换个大小写绕过；
	// 另外 filepath.Clean 会把 "/" 变成 `\`，盘符根要单独认。
	if runtime.GOOS == "windows" {
		if err := validateStaticRoot(strings.ToUpper(data), data); err == nil {
			t.Error("大小写不同的同一个目录应当仍被拦下")
		}
		for _, root := range []string{`C:\`, "C:", `\`, `\data`, `\data\certs`} {
			if err := validateStaticRoot(root, data); err == nil {
				t.Errorf("%q 应当被拦下", root)
			}
		}
	}
}

// 走一遍真正的保存期校验：这道闸挂在 validateWebService 上，
// 上面那些用例只测到函数本身，接线断了照样全绿。
func TestValidateWebServiceRejectsDataDirAsStaticRoot(t *testing.T) {
	data := t.TempDir()
	ws := wsParent("ws1", 8080, config.WebChild{
		ID: "ch1", Enabled: true, Type: "static", Domains: []string{"site.example.com"},
		TLSMinVersion: "1.2",
		Static:        config.WebStatic{Root: data, Index: "index.html"},
	})
	if err := validateWebService(domainCfg(), ws, data); err == nil {
		t.Fatal("把数据目录填成静态站点根应当保存不了")
	} else if !strings.Contains(err.Error(), "数据目录") {
		t.Errorf("错误里应当说清是数据目录，实际：%v", err)
	}
	// 换成别处就该放过——否则上面那条只是"静态站点一律保存不了"。
	ws.Children[0].Static.Root = filepath.Join(data, "..", "www")
	if err := validateWebService(domainCfg(), ws, data); err != nil {
		t.Errorf("同级目录应当能保存，实际：%v", err)
	}
}
