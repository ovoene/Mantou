package app

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"mantou/internal/logx"
)

func writeMark(t *testing.T, dir, mark string) string {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(dir, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "sub", "mark.txt"), []byte(mark), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

func markOf(t *testing.T, dir string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, "sub", "mark.txt"))
	if err != nil {
		t.Fatalf("读取 %s 的标记失败：%v", dir, err)
	}
	return string(data)
}

func exists(t *testing.T, path string) bool {
	t.Helper()
	_, err := os.Stat(path)
	return err == nil
}

// 崩溃恢复：导入回滚在"目录已挪开、原件还没换回来"的瞬间被杀掉，启动时必须把原件捡回来。
//
// 修复前这份数据只剩在 <目录名>.restore-old-<纳秒> 里，启动期没有任何代码碰它：
// 面板起来后 uploads/ 是空的（背景图全丢）、certs/ 不存在（私钥全丢），
// 而「存储占用」还把那个目录标成"可清理"，用户一点就真删了。
func TestReclaimRestoreLeftoversRecoversAfterCrash(t *testing.T) {
	dir := t.TempDir()
	writeMark(t, filepath.Join(dir, "uploads.restore-old-17000"), "uploads-original")
	writeMark(t, filepath.Join(dir, "certs.restore-old-17000"), "certs-original")
	log := logx.New(logx.Options{})

	ReclaimRestoreLeftovers(dir, log)

	for name, want := range map[string]string{"uploads": "uploads-original", "certs": "certs-original"} {
		if got := markOf(t, filepath.Join(dir, name)); got != want {
			t.Fatalf("%s/ 里是 %q，期望 %q", name, got, want)
		}
		if exists(t, filepath.Join(dir, name+".restore-old-17000")) {
			t.Fatalf("%s 的残留目录没被消化掉，下次启动还会再来一遍", name)
		}
	}
	// 这件事必须留痕：用户的背景图/证书在他不知道的时候消失过一次。
	var found bool
	for _, e := range log.Recent(50) {
		if strings.Contains(e.Message, "导入回滚未完成") {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("回收动作没写日志：事后无从知道目录被换回来过")
	}
}

// 多个残留时取时间戳最新的那个：那才是造成当前缺口的这一次回滚留下的。
func TestReclaimRestoreLeftoversPicksNewest(t *testing.T) {
	dir := t.TempDir()
	writeMark(t, filepath.Join(dir, "uploads.restore-old-17000"), "older")
	writeMark(t, filepath.Join(dir, "uploads.restore-old-17009"), "newer")

	ReclaimRestoreLeftovers(dir, logx.New(logx.Options{}))

	if got := markOf(t, filepath.Join(dir, "uploads")); got != "newer" {
		t.Fatalf("捡回来的是 %q，期望 newer", got)
	}
	// 旧的那个不动它：它是更早一次导入的原件，由「存储占用」交给用户处置，
	// 回收只负责补上缺口，不做清理。
	if !exists(t, filepath.Join(dir, "uploads.restore-old-17000")) {
		t.Fatal("更早的残留被顺手删了：回收不该替用户做清理")
	}
}

// 现役目录在位时一律不动手。此时旁边的 restore-old 要么是等着被 commit 删掉的原件，
// 要么是上一次导入成功后留下的备份——两种情况下现役数据都是对的，碰它就是把好数据换成旧数据。
func TestReclaimRestoreLeftoversLeavesLiveDirectoryAlone(t *testing.T) {
	dir := t.TempDir()
	writeMark(t, filepath.Join(dir, "uploads"), "live")
	writeMark(t, filepath.Join(dir, "uploads.restore-old-17000"), "stale")

	ReclaimRestoreLeftovers(dir, logx.New(logx.Options{}))

	if got := markOf(t, filepath.Join(dir, "uploads")); got != "live" {
		t.Fatalf("现役目录被换成了 %q", got)
	}
	if !exists(t, filepath.Join(dir, "uploads.restore-old-17000")) {
		t.Fatal("旁边的备份目录被删了：那是 commit 的活，不是回收的活")
	}
}

// 只认 <目录名>.restore-old-<纳秒>。另外两种名字都不能捡：
//   - .uploads-restore-<随机>：没启用的暂存，可能只写了一半；
//   - .uploads-restore-discard-<纳秒>：回滚挪开的、已被用户否决的导入数据（见 server.restoreDirectory）；
//   - 时间戳解析不出来的：不是本程序生成的，无从判断新旧。
func TestReclaimRestoreLeftoversIgnoresStagingAndDiscarded(t *testing.T) {
	dir := t.TempDir()
	ignored := []string{
		".uploads-restore-abc123",
		".uploads-restore-discard-17000",
		"uploads.restore-old-",
		"uploads.restore-old-nope",
	}
	for _, name := range ignored {
		writeMark(t, filepath.Join(dir, name), name)
	}

	ReclaimRestoreLeftovers(dir, logx.New(logx.Options{}))

	if exists(t, filepath.Join(dir, "uploads")) {
		t.Fatalf("uploads/ 被这些名字之一顶上了：%v", ignored)
	}
	for _, name := range ignored {
		if !exists(t, filepath.Join(dir, name)) {
			t.Fatalf("%s 被动了", name)
		}
	}
}

// 首次启动：什么都没有，也不该报错或建出目录来。
func TestReclaimRestoreLeftoversOnFreshDataDir(t *testing.T) {
	dir := t.TempDir()
	ReclaimRestoreLeftovers(dir, logx.New(logx.Options{}))
	ReclaimRestoreLeftovers("", logx.New(logx.Options{}))
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("空数据目录被写进了东西：%v", entries)
	}
}
