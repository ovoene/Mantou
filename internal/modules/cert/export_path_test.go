package cert

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"mantou/internal/config"
)

// Method="path" 的证书，两个路径由用户在界面上填，而导出接口会把读到的内容原样回给调用方。
// 原来是直接 os.ReadFile，于是「指向 /etc/shadow → 调一次导出」就是一次任意文件读。
// 下面这组测试钉住两件事：读到的东西必须是「一张证书 + 与之配套的私钥」，
// 以及读多少是有上限的（见 5-I）。

// newPathCert 造一张 Method="path" 的证书配置，两个文件内容由调用方给。
func newPathCert(t *testing.T, certContent, keyContent []byte) config.Certificate {
	t.Helper()
	dir := t.TempDir()
	certPath := filepath.Join(dir, "server.crt")
	keyPath := filepath.Join(dir, "server.key")
	if err := os.WriteFile(certPath, certContent, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, keyContent, 0o600); err != nil {
		t.Fatal(err)
	}
	return config.Certificate{ID: "c1", Method: "path", CertPath: certPath, KeyPath: keyPath}
}

// newExportModule 只装配 Export 用得到的部分：不走 New，避免起续期协程。
func newExportModule(t *testing.T) *Module {
	t.Helper()
	return &Module{store: NewStore(t.TempDir())}
}

// TestExportPathRefusesNonCertificateFile 指向一个不是证书的文件时不导出内容。
//
// 用的是 /etc/shadow 那一行的形状：这条路径的价值就在于读走这种文件，
// 所以顺带断言报错里也不能把读到的内容带出来。
func TestExportPathRefusesNonCertificateFile(t *testing.T) {
	const secret = "root:$6$abcdefgh$0123456789:19000:0:99999:7:::"
	m := newExportModule(t)
	c := newPathCert(t, []byte(secret+"\n"), []byte(secret+"\n"))

	for _, includeKey := range []bool{false, true} {
		// 不含私钥那一支也必须拒：否则「导出证书」仍然能读走磁盘上任意一份文件。
		certPEM, keyPEM, err := m.Export(c, includeKey)
		if err == nil {
			t.Fatalf("includePrivateKey=%v：不是证书的文件也导出了", includeKey)
		}
		if len(certPEM) != 0 || len(keyPEM) != 0 {
			t.Fatalf("includePrivateKey=%v：出错时仍返回了内容（cert %d 字节、key %d 字节）",
				includeKey, len(certPEM), len(keyPEM))
		}
		if strings.Contains(err.Error(), secret) {
			t.Fatalf("报错里带出了文件内容：%v", err)
		}
	}
}

// TestExportPathRefusesUnrelatedPrivateKey 私钥文件与证书配不上时不导出。
//
// 这一条挡的是「指向 /root/.ssh/id_rsa」——它本身是合法 PEM，只看格式的话过得去，
// 必须要求它是这张证书的私钥才拦得住。
func TestExportPathRefusesUnrelatedPrivateKey(t *testing.T) {
	certPEM, _ := newStoreTestCertificate(t, "a.example.com", 1)
	_, otherKeyPEM := newStoreTestCertificate(t, "b.example.com", 2)

	m := newExportModule(t)
	c := newPathCert(t, certPEM, otherKeyPEM)

	for _, includeKey := range []bool{false, true} {
		if _, _, err := m.Export(c, includeKey); err == nil {
			t.Fatalf("includePrivateKey=%v：私钥与证书配不上也导出了", includeKey)
		}
	}
}

// TestExportPathReturnsRealPairUnchanged 反向钉住：正常的路径证书导出的还是原字节。
//
// 这次改动加的是校验而不是加工，能用的配置必须一字不差地照旧导出。
func TestExportPathReturnsRealPairUnchanged(t *testing.T) {
	certPEM, keyPEM := newStoreTestCertificate(t, "real.example.com", 3)
	m := newExportModule(t)
	c := newPathCert(t, certPEM, keyPEM)

	gotCert, gotKey, err := m.Export(c, false)
	if err != nil {
		t.Fatal(err)
	}
	if string(gotCert) != string(certPEM) {
		t.Fatal("不含私钥导出：证书内容与磁盘上的不一致")
	}
	if gotKey != nil {
		t.Fatal("不含私钥导出：仍然返回了私钥")
	}

	gotCert, gotKey, err = m.Export(c, true)
	if err != nil {
		t.Fatal(err)
	}
	if string(gotCert) != string(certPEM) || string(gotKey) != string(keyPEM) {
		t.Fatal("含私钥导出：内容与磁盘上的不一致")
	}
}

// TestExportPathRefusesOversizedFile 文件超过上限时拒绝，且不是因为解析失败。
//
// 填充放在合法证书之后：PEM 解析会忽略尾部的非 PEM 数据，也就是说没有上限时这一份
// 是能导出成功的。于是这条测试量的确实是上限本身，而不是顺带被解析挡下。
func TestExportPathRefusesOversizedFile(t *testing.T) {
	certPEM, keyPEM := newStoreTestCertificate(t, "big.example.com", 4)
	padded := append(append([]byte(nil), certPEM...), []byte(strings.Repeat("#", maxCertFileBytes))...)

	m := newExportModule(t)
	// 前提：这一份除了体积之外是完全合法的。
	if _, _, err := m.Export(newPathCert(t, certPEM, keyPEM), true); err != nil {
		t.Fatalf("测试前提不成立：未加填充的同一对证书就导不出来：%v", err)
	}

	gotCert, gotKey, err := m.Export(newPathCert(t, padded, keyPEM), true)
	if err == nil {
		t.Fatalf("证书文件 %d 字节仍然导出了", len(padded))
	}
	if !strings.Contains(err.Error(), "超过") {
		t.Fatalf("报错应指向体积上限，实际：%v", err)
	}
	if len(gotCert) != 0 || len(gotKey) != 0 {
		t.Fatal("出错时仍返回了内容")
	}
}

// TestReadCertFileCapBoundary 上限是「刚好等于放行、多一个字节拒绝」。
//
// 这一个字节的差别值得单独钉：多读 1 字节判超限是实现里唯一容易写反的地方，
// 写反了就是一份正好卡在上限上的证书链忽然导不出来。
func TestReadCertFileCapBoundary(t *testing.T) {
	dir := t.TempDir()
	atCap := filepath.Join(dir, "at-cap")
	overCap := filepath.Join(dir, "over-cap")
	if err := os.WriteFile(atCap, []byte(strings.Repeat("x", maxCertFileBytes)), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(overCap, []byte(strings.Repeat("x", maxCertFileBytes+1)), 0o600); err != nil {
		t.Fatal(err)
	}

	data, err := readCertFile(atCap)
	if err != nil {
		t.Fatalf("刚好等于上限应放行：%v", err)
	}
	if len(data) != maxCertFileBytes {
		t.Fatalf("读到 %d 字节，期望 %d", len(data), maxCertFileBytes)
	}
	if _, err := readCertFile(overCap); err == nil {
		t.Fatal("超出上限 1 字节应拒绝")
	}
}

// TestLoadFromFilesCapsRead 加载路径证书时同样有上限。
//
// 上限在加载这一侧比在导出那一侧更要紧：导出要人点一下，加载是每次配置变更自动跑的，
// 而 os.ReadFile 对 /dev/zero 这类 Stat 报告大小为 0 的文件会一直把缓冲区扩下去。
func TestLoadFromFilesCapsRead(t *testing.T) {
	certPEM, keyPEM := newStoreTestCertificate(t, "load.example.com", 5)
	padded := append(append([]byte(nil), certPEM...), []byte(strings.Repeat("#", maxCertFileBytes))...)

	dir := t.TempDir()
	certPath := filepath.Join(dir, "server.crt")
	keyPath := filepath.Join(dir, "server.key")
	if err := os.WriteFile(certPath, padded, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}

	store := NewStore(t.TempDir())
	if err := store.LoadFromFiles("c1", certPath, keyPath); err == nil {
		t.Fatal("超限的证书文件仍被加载")
	}
	if _, _, ok := store.Info("c1"); ok {
		t.Fatal("加载失败却建了索引")
	}
}
