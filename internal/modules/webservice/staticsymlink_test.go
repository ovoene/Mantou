package webservice

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"mantou/internal/config"
)

// 这一组盯 B-4：站点根里的符号链接不许把访客带到根外。
//
// 旧实现走 http.Dir，它只把**路径字符串**收敛在根内，落到磁盘那一步照样跟着链接走。
// 于是 `site/pub -> <base>` 之后，GET /pub/outside.txt 的路径检查全是过的
// （"/pub/outside.txt" 规规矩矩），文件却来自站点外。现在改用 os.Root，由内核拒绝。
//
// 指向根内的链接必须继续可用——`current -> ./releases/v3` 是常见部署方式，
// 一并挡掉就不是修缺陷而是砍功能了。

// symlinkOrSkip 建一条符号链接；建不了就跳过（Windows 上非管理员且未开开发者模式时不允许）。
func symlinkOrSkip(t *testing.T, target, link string) {
	t.Helper()
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("本机不允许创建符号链接，跳过：%v", err)
	}
}

func TestStaticSymlinkCannotEscapeRoot(t *testing.T) {
	root := siteTree(t)
	base := filepath.Dir(root) // siteTree 把 outside.txt 放在站点根的上一级

	// 三种形状各来一条：链到上一级目录、链到具体文件、链到文件系统根。
	symlinkOrSkip(t, base, filepath.Join(root, "pub"))
	symlinkOrSkip(t, filepath.Join(base, "outside.txt"), filepath.Join(root, "leak.txt"))

	h := siteHandler(root, config.WebStatic{Index: "index.html", DirList: true})

	for _, target := range []string{"/pub/outside.txt", "/leak.txt", "/pub/", "/pub"} {
		rec := getPath(h, target)
		if strings.Contains(rec.Body.String(), outsideSecret) {
			t.Errorf("%s 把站点外的文件内容发出来了（%d）：%s", target, rec.Code, rec.Body.String())
		}
		if rec.Code >= 200 && rec.Code < 300 {
			t.Errorf("%s 返回了 %d：指向站点外的链接不该有正常响应", target, rec.Code)
		}
	}
}

// SPA 回退这条分支也要挡住：它遇到取不到的路径会去发首页，
// 不该因为"链接打不开"而漏出别的行为差异。顺带确认站点自己的文件仍然正常。
func TestStaticSymlinkEscapeBlockedWithSPA(t *testing.T) {
	root := siteTree(t)
	base := filepath.Dir(root)
	symlinkOrSkip(t, filepath.Join(base, "outside.txt"), filepath.Join(root, "leak.txt"))

	h := siteHandler(root, config.WebStatic{Index: "index.html", SPAFallback: true})

	rec := getPath(h, "/leak.txt")
	if strings.Contains(rec.Body.String(), outsideSecret) {
		t.Fatalf("SPA 站上指向站点外的链接漏了内容：%s", rec.Body.String())
	}
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "index") {
		t.Errorf("SPA 站上取不到的路径应当回首页，实际 %d %q", rec.Code, rec.Body.String())
	}
	// 站点自己的文件不受影响。
	if rec := getPath(h, "/hello.txt"); rec.Code != 200 {
		t.Errorf("站内文件被一起挡了：%d", rec.Code)
	}
}

// 指向根内的链接照常能用。少了这条，把 open() 改成"见到链接就拒"也能让上面两条通过，
// 而那是把功能砍掉而不是把缺陷修掉。
//
// 注意链接目标写的是相对路径。os.Root 跟随根内的相对链接，但把**任何绝对路径目标**
// 都判成逃逸——即使它指回根内（下一条测试钉的就是这个）。
func TestStaticSymlinkInsideRootStillWorks(t *testing.T) {
	root := siteTree(t)
	// current -> sub，站点内的相对链接，常见的发布目录切换写法。
	symlinkOrSkip(t, "sub", filepath.Join(root, "current"))

	h := siteHandler(root, config.WebStatic{Index: "index.html", DirList: true})

	rec := getPath(h, "/current/inner.txt")
	if rec.Code != 200 {
		t.Fatalf("指向站点内的链接应当照常可用，实际 %d", rec.Code)
	}
	if got := rec.Body.String(); got != "inner" {
		t.Errorf("内容不对：%q", got)
	}
	if rec := getPath(h, "/current/"); rec.Code != 200 || !strings.Contains(rec.Body.String(), "inner.txt") {
		t.Errorf("指向站点内目录的链接应当能列清单，实际 %d %q", rec.Code, rec.Body.String())
	}
}

// 这条钉的是这次改动**已知的行为收窄**，写成测试是为了它以后被人碰到时能查到原因，
// 而不是当成新缺陷去查。
//
// os.Root 不跟随绝对路径的链接目标，哪怕目标就在根里：它的约束模型是逐段 openat
// + 不许离开根，绝对路径一进来就没法在这个模型里表达。所以站点根里写成绝对目标的
// 链接（`current -> /srv/www/releases/v3`）在这次改动后取不到了，改成相对目标
// （`current -> releases/v3`）即可。
//
// 不为它加回退（比如失败后用 EvalSymlinks 判一下是否仍在根内，再按普通路径打开）是刻意的：
// 那等于在"检查"和"打开"之间留一个可被替换链接的时间窗，而能往站点根里写链接的人
// 正是这条缺陷唯一的攻击者。宁可少支持一种写法。
func TestStaticAbsoluteSymlinkInsideRootIsRefused(t *testing.T) {
	root := siteTree(t)
	symlinkOrSkip(t, filepath.Join(root, "sub"), filepath.Join(root, "abscurrent"))

	h := siteHandler(root, config.WebStatic{Index: "index.html"})
	if rec := getPath(h, "/abscurrent/inner.txt"); rec.Code != 404 {
		t.Errorf("绝对目标的链接预期取不到（404），实际 %d——"+
			"若 os.Root 的语义变了，请一并更新 open() 上的说明", rec.Code)
	}
}

// 目录清单是自己渲染的（不再把请求交回 http.FileServer），所以点开头的条目
// 不该出现在清单里——它们本来就取不到，列出名字只是白告诉访客这里有个 .env。
func TestStaticDirectoryListingHidesDotEntries(t *testing.T) {
	root := siteTree(t)
	h := siteHandler(root, config.WebStatic{Index: "nonexistent.html", DirList: true})

	rec := getPath(h, "/")
	if rec.Code != 200 {
		t.Fatalf("根目录应当列清单，实际 %d", rec.Code)
	}
	body := rec.Body.String()
	if strings.Contains(body, ".git") {
		t.Errorf("清单里出现了 .git：%s", body)
	}
	if !strings.Contains(body, "hello.txt") {
		t.Errorf("清单里没有 hello.txt，列表根本没生效：%s", body)
	}
	// 目录条目要带尾斜杠，否则点进去要多跳一次 301。
	if !strings.Contains(body, "sub/") {
		t.Errorf("清单里的目录条目应当带尾斜杠：%s", body)
	}
}
