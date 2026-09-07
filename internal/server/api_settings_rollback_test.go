package server

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// 造一个"目录里有内容"的目录，内容用于分辨换回来的到底是哪一份。
func mkdirWithMark(t *testing.T, path, mark string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(path, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(path, "sub", "mark.txt"), []byte(mark), 0o600); err != nil {
		t.Fatal(err)
	}
}

func readMark(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(path, "sub", "mark.txt"))
	if err != nil {
		t.Fatalf("读取 %s 的标记失败（目录被换成了什么？）：%v", path, err)
	}
	return string(data)
}

// 正常回滚：原件换回原位，被否决的导入数据和 restore-old 目录都不留在盘上。
func TestRestoreDirectoryPutsOriginalBack(t *testing.T) {
	dir := t.TempDir()
	root := filepath.Join(dir, "uploads")
	old := filepath.Join(dir, "uploads.restore-old-17000")
	mkdirWithMark(t, root, "imported")
	mkdirWithMark(t, old, "original")

	if err := restoreDirectory(root, old); err != nil {
		t.Fatalf("回滚失败：%v", err)
	}
	if got := readMark(t, root); got != "original" {
		t.Fatalf("uploads/ 里是 %q，期望回滚成 original", got)
	}
	if _, err := os.Stat(old); !os.IsNotExist(err) {
		t.Fatalf("restore-old 目录还在：%v", err)
	}
	// 挪开的那份必须被删掉。留着不算数据丢失，但会在数据目录里堆一份完整的 uploads 副本。
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "uploads" {
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Fatalf("回滚后数据目录里还有别的东西：%v", names)
	}
}

// 回滚**失败**时不许把目录变没了。
//
// 这条测试盯的是 restoreDirectory 里那个顺序：先把 root 挪开、再把 old 换回来。
// 先删 root 的写法在这里会直接把 uploads/ 删光——old 换不回来（这里用"old 压根不存在"
// 来确定性地触发失败），于是两份都没了，而这正是审计里那个崩溃窗口的非崩溃版本。
func TestRestoreDirectoryKeepsRootWhenOriginalCannotComeBack(t *testing.T) {
	dir := t.TempDir()
	root := filepath.Join(dir, "uploads")
	mkdirWithMark(t, root, "imported")
	missing := filepath.Join(dir, "uploads.restore-old-17000")

	if err := restoreDirectory(root, missing); err == nil {
		t.Fatal("原件不存在却报回滚成功")
	}
	if got := readMark(t, root); got != "imported" {
		t.Fatalf("uploads/ 里是 %q，期望原地保留 imported——回滚失败也不能把目录整个弄没", got)
	}
}

// 备份是"从无到有"（导入前本来没有这个目录）时，回滚就是把导入进来的删掉。
func TestRestoreDirectoryRemovesRootWhenThereWasNoOriginal(t *testing.T) {
	dir := t.TempDir()
	root := filepath.Join(dir, "uploads")
	mkdirWithMark(t, root, "imported")

	if err := restoreDirectory(root, ""); err != nil {
		t.Fatalf("回滚失败：%v", err)
	}
	if _, err := os.Stat(root); !os.IsNotExist(err) {
		t.Fatalf("导入进来的目录没被删掉：%v", err)
	}
}

// 挪开那份的名字必须同时满足两件事，否则回滚会各留一个坑：
//   - 被「存储占用」认成可清理的残留（不然它残留下来就是一份没人看得见的完整副本）；
//   - **不**长得像 <目录名>.restore-old-<纳秒>，否则启动期回收会把用户否决掉的那份导入
//     数据当成原件装回去（见 app.ReclaimRestoreLeftovers）。
//
// 名字取自生产代码同一个来源（restoreDiscardPath），不手写字面量。
func TestRestoreDiscardNameIsCleanableButNotReclaimable(t *testing.T) {
	for _, base := range []string{"uploads", "certs"} {
		name := filepath.Base(restoreDiscardPath(filepath.Join("/data", base)))
		if kind := storageLeftoverKind(name, true); kind != "restore" {
			t.Fatalf("%s 的分类是 %q，期望 restore：残留下来就没人清得掉", name, kind)
		}
		if strings.HasPrefix(name, base+".restore-old-") {
			t.Fatalf("%s 撞上了启动期回收认的名字：被否决的导入数据会被当成原件装回去", name)
		}
	}
}
