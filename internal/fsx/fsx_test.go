package fsx

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// data 目录的权限位是一条只在"没人看"的时候才有用的防线：它拦的是同机的另一个用户
// 顺手 ls 一下 data/certs 就知道面板管着哪些域名、data 里有没有 master.key。
// 这类问题不会有任何症状——目录敞着与关着，面板跑起来一模一样，所以只能靠测试盯。
//
// 下面这组用例分两层：新建目录拿到 0700（EnsureDir），以及**既有**目录被收紧
// （Tighten）。后者才是这次修复的重点：升级上来的安装里那几个目录早就以 0755 存在了，
// 光把 MkdirAll 的参数改掉对它们毫无作用。

// skipUnlessPOSIXPerms 在不按 POSIX 权限位办事的平台上跳过。
//
// Windows 的 os.Stat 对目录一律报 0777，os.Chmod 也只认「只读」这一位——那边的访问控制
// 走 ACL。断言权限位在那里只会得到一条与实现无关的失败。
func skipUnlessPOSIXPerms(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("Windows 不按 POSIX 权限位表达目录权限（走 ACL）")
	}
}

// perm 读一个已存在路径的权限位。
func perm(t *testing.T, path string) os.FileMode {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return fi.Mode().Perm()
}

// TestEnsureDirCreatesPrivateDir 新建的目录（含中间各级）都是 0700。
//
// 中间各级也要盯：uploads / logs / certs 都是 data 下的一层，而 data 本身可能是
// 这次 MkdirAll 顺手建出来的——只关上最后一层，等于没关。
func TestEnsureDirCreatesPrivateDir(t *testing.T) {
	root := t.TempDir()
	nested := filepath.Join(root, "data", "certs", "sub")
	if err := EnsureDir(nested); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(nested)
	if err != nil {
		t.Fatalf("目录没建出来：%v", err)
	}
	if !fi.IsDir() {
		t.Fatal("建出来的不是目录")
	}

	skipUnlessPOSIXPerms(t)
	for _, dir := range []string{
		filepath.Join(root, "data"),
		filepath.Join(root, "data", "certs"),
		nested,
	} {
		if got := perm(t, dir); got != DirMode {
			t.Fatalf("%s 的权限是 %#o，期望 %#o", dir, got, DirMode)
		}
	}
}

// TestEnsureDirTightensExistingDir 目录已经存在时也要收紧——这条是 F-06 的正主。
//
// os.MkdirAll 对已存在的目录不动权限，所以只改它的 mode 参数救不了任何一个已装好的实例。
func TestEnsureDirTightensExistingDir(t *testing.T) {
	skipUnlessPOSIXPerms(t)
	dir := filepath.Join(t.TempDir(), "data")
	// 0777 而不是 0755：连"组可写"这种更宽的情况一起盯住。
	if err := os.MkdirAll(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o777); err != nil { // 绕开 umask，确保起点真的是 0777
		t.Fatal(err)
	}
	if err := EnsureDir(dir); err != nil {
		t.Fatal(err)
	}
	if got := perm(t, dir); got != DirMode {
		t.Fatalf("既有目录没被收紧：%#o，期望 %#o", got, DirMode)
	}
}

// TestEnsureDirKeepsContents 收紧权限不动目录里的东西。
//
// 这一步发生在每次保存配置、每次写日志、每次存证书的路上，一旦它会碰内容，
// 代价就不是"权限没关"而是"数据没了"。
func TestEnsureDirKeepsContents(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "data")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(dir, "config.json")
	if err := os.WriteFile(file, []byte(`{"version":12}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := EnsureDir(dir); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(file)
	if err != nil {
		t.Fatalf("目录里的文件不见了：%v", err)
	}
	if string(data) != `{"version":12}` {
		t.Fatalf("文件内容被改了：%q", data)
	}
	if runtime.GOOS != "windows" {
		if got := perm(t, file); got != 0o600 {
			t.Fatalf("文件权限被改了：%#o", got)
		}
	}
}

// TestTightenOnlyNarrows 只收紧、不放宽：属主那三位与 setgid/sticky 一概照原样留着。
func TestTightenOnlyNarrows(t *testing.T) {
	skipUnlessPOSIXPerms(t)
	cases := []struct {
		name  string
		start os.FileMode
		want  os.FileMode
	}{
		// 常见的两种起点。
		{"0755", 0o755, 0o700},
		{"0750", 0o750, 0o700},
		// 属主自己就没有写权限（有人刻意锁过这个目录）：不该被"收紧"成 0700，
		// 那是放宽。收紧只负责去掉后两组，属主那一组不是这一步该管的事。
		{"0555", 0o555, 0o500},
		{"0500", 0o500, 0o500},
		// 已经收紧的原样返回。
		{"0700", 0o700, 0o700},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "d")
			if err := os.Mkdir(dir, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(dir, tc.start); err != nil {
				t.Fatal(err)
			}
			// 属主无写权限的目录清不掉，t.TempDir 的清理会失败——先还回去。
			t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
			if err := Tighten(dir); err != nil {
				t.Fatal(err)
			}
			if got := perm(t, dir); got != tc.want {
				t.Fatalf("%#o 收紧后是 %#o，期望 %#o", tc.start, got, tc.want)
			}
		})
	}
}

// TestTightenKeepsStickyBit sticky 位不能被顺手抹掉。
//
// 它与权限位存在同一个 mode 里，而 os.Chmod 是整体覆盖：写 0700 就等于同时声明
// "没有 sticky"。共享目录上的 sticky 是有意为之的，抹掉它会让别人能删这里的文件。
func TestTightenKeepsStickyBit(t *testing.T) {
	skipUnlessPOSIXPerms(t)
	dir := filepath.Join(t.TempDir(), "d")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, os.ModeSticky|0o777); err != nil {
		t.Fatal(err)
	}
	if err := Tighten(dir); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != DirMode {
		t.Fatalf("权限是 %#o，期望 %#o", fi.Mode().Perm(), DirMode)
	}
	if fi.Mode()&os.ModeSticky == 0 {
		t.Fatalf("sticky 位被抹掉了：%v", fi.Mode())
	}
}

// TestTightenMissingDir 目录不存在时报错，不假装成功。
//
// EnsureDir 把这个错误吞掉是刻意的（权限没收紧不该中断启动），但 Tighten 本身
// 必须说实话——main 那边靠它的返回值决定要不要记一条告警。
func TestTightenMissingDir(t *testing.T) {
	if err := Tighten(filepath.Join(t.TempDir(), "nope")); err == nil {
		t.Fatal("目录不存在时应当报错")
	}
}

// TestEnsureDirFailsOnFile 路径已经被一个文件占着时，EnsureDir 必须失败。
//
// 这是它唯一会返回错误的情形，也必须返回：接下来的写入一定会失败，
// 在这里停下比让调用方拿着一个"创建成功了"的假象往下走要好。
func TestEnsureDirFailsOnFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "occupied")
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := EnsureDir(path); err == nil {
		t.Fatal("路径是个文件时应当报错")
	}
}

// looseDir 造一个权限故意敞开的目录。MkdirAll 的 mode 会被 umask 削掉，所以要显式 chmod。
func looseDir(t *testing.T, path string, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(path, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

// TestTightenTreeReachesLazyDirs 这条盯的是"惰性收紧"那个缺口。
//
// certs/ 与 uploads/ 只在第一次写入时才被 EnsureDir 建起来（保存证书 / 上传背景图），
// 所以升级上来的安装里它们会一直停在 0755——只收紧 data 根碰不到它们，而一个只用
// 端口转发的实例可能一年都不写这两个目录一次，里面却躺着证书私钥。
//
// 顺带盯三件事：子目录（uploads/sub）也要收；导入回滚残留（uploads.restore-old-*）
// 里是同一批用户数据，也要收；比 0700 更严的目录（0500）不能被"收紧"反而放宽。
func TestTightenTreeReachesLazyDirs(t *testing.T) {
	skipUnlessPOSIXPerms(t)
	root := t.TempDir()
	for _, rel := range []string{"certs", "uploads", filepath.Join("uploads", "sub"), "logs", "uploads.restore-old-123"} {
		looseDir(t, filepath.Join(root, rel), 0o777)
	}
	locked := filepath.Join(root, "readonly")
	looseDir(t, locked, 0o500)
	keep := filepath.Join(root, "uploads", "sub", "bg.png")
	if err := os.WriteFile(keep, []byte("image"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(root, 0o755); err != nil {
		t.Fatal(err)
	}

	if err := TightenTree(root); err != nil {
		t.Fatalf("收紧整棵树不该报错: %v", err)
	}

	for _, rel := range []string{".", "certs", "uploads", filepath.Join("uploads", "sub"), "logs", "uploads.restore-old-123"} {
		if got := perm(t, filepath.Join(root, rel)); got != DirMode {
			t.Errorf("%s 权限是 %04o，期望 %04o", rel, got, DirMode)
		}
	}
	if got := perm(t, locked); got != 0o500 {
		t.Errorf("比 0700 更严的目录被改动了：%04o", got)
	}
	// 只动目录：里面的文件权限与内容都不该被碰。
	if got := perm(t, keep); got != 0o644 {
		t.Errorf("文件权限被改动了：%04o", got)
	}
	if body, err := os.ReadFile(keep); err != nil || string(body) != "image" {
		t.Fatalf("文件内容被破坏: %q err=%v", body, err)
	}
}

// TestTightenTreeMissingRoot 根目录不存在时返回 nil。
//
// 与 Tighten 不同：那个是"你给的这一层收紧失败了"，必须说实话；这个走的是整棵树，
// 而"树不存在"正是首次启动的正常形态，报错只会换来一条谁也处理不了的告警。
func TestTightenTreeMissingRoot(t *testing.T) {
	if err := TightenTree(filepath.Join(t.TempDir(), "nope")); err != nil {
		t.Fatalf("根目录不存在时不该报错: %v", err)
	}
}
