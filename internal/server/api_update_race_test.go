package server

import (
	"bytes"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"mantou/internal/config"
)

// 自更新的验签与"改名覆盖"之间隔着冒烟测试与备份。原先候选文件名只到秒级、以 O_TRUNC 打开，
// 同一秒里的两个上传写的是同一个文件：第一个传一个验签能过的正式包，第二个在它验完签之后
// 把内容换掉，被装上去的就是没验过签的那份。下面两道各自都能挡住这件事，分别钉住。

// TestExtractExecutableRefusesExistingFile 候选文件以 O_EXCL 创建：目标已存在就失败，
// 不会把内容写进（也就不会覆盖）一个已经在那里的文件。
func TestExtractExecutableRefusesExistingFile(t *testing.T) {
	dir := t.TempDir()
	binDst := filepath.Join(dir, "candidate")
	const original = "已经验过签的那一份"
	if err := os.WriteFile(binDst, []byte(original), 0o700); err != nil {
		t.Fatal(err)
	}

	pkg := buildUpdateTarGz(t, [][2]string{{"mantou", "想换进来的另一份"}})
	if err := extractExecutable(bytes.NewReader(pkg), "mantou", binDst, ""); err == nil {
		t.Fatal("目标文件已存在时解包应当失败，而不是覆盖它")
	}
	got, err := os.ReadFile(binDst)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != original {
		t.Fatalf("已存在的文件被改写了：%q", got)
	}
}

// TestWriteFileOwnerOnly 候选文件在验签与冒烟测试通过之前只给属主权限。
func TestWriteFileOwnerOnly(t *testing.T) {
	skipOnWindows(t) // Windows 上没有 POSIX 权限位
	path := filepath.Join(t.TempDir(), "candidate")
	if err := writeFile(path, strings.NewReader("x"), 16); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := st.Mode().Perm(); perm&0o077 != 0 {
		t.Fatalf("候选文件权限是 %o，组与其他人不该有任何权限", perm)
	}
}

// TestRandomSuffixUnique 候选文件名的随机后缀不重复。
func TestRandomSuffixUnique(t *testing.T) {
	seen := make(map[string]bool)
	for i := 0; i < 256; i++ {
		s, err := randomSuffix()
		if err != nil {
			t.Fatal(err)
		}
		if len(s) != 16 {
			t.Fatalf("后缀长度 %d，期望 16 个 hex 字符", len(s))
		}
		if seen[s] {
			t.Fatalf("随机后缀重复：%s", s)
		}
		seen[s] = true
	}
}

// TestSelfUpdateRejectsConcurrentUpload 已有一个更新包在处理时，第二个直接 409，
// 且拒在读请求体与密码复核之前。
func TestSelfUpdateRejectsConcurrentUpload(t *testing.T) {
	skipOnWindows(t) // Windows 上处理器第一行就返回 501
	s := newUpdateGateServer(t, func(u *config.UpdateConfig) { u.SignKey = "dGVzdA==" })

	s.selfUpdateMu.Lock() // 模拟"前一个更新包正在处理"
	code, body := postSelfUpdate(t, s, "不是真的更新包")
	s.selfUpdateMu.Unlock()

	if code != http.StatusConflict {
		t.Fatalf("并发上传应当 409，实际 %d：%s", code, body)
	}
	if strings.Contains(body, "更新包解析失败") {
		t.Fatal("被拒的请求不该走到解包那一步")
	}

	// 锁放开之后照常处理（走到解包，因为内容是假的）。
	code, body = postSelfUpdate(t, s, "不是真的更新包")
	if code == http.StatusConflict {
		t.Fatalf("前一个处理结束后不该再被拒：%s", body)
	}
	if !strings.Contains(body, "更新包解析失败") {
		t.Fatalf("应当已经走到解包那一步，实际：%s", body)
	}
}
