package config

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// 这些常量既当测试数据用，也用来在整份 config.json 的字节里搜"明文有没有漏出去"。
// 取值刻意做成不会与 JSON 结构或其他字段撞车的字符串。
const (
	testAPIToken   = "cf-token-明文不得落盘-9F3A"
	testAPISecret  = "cf-secret-明文不得落盘-77BE"
	testACMEKey    = "-----BEGIN EC PRIVATE KEY-----\nACME账户私钥明文不得落盘\n-----END EC PRIVATE KEY-----\n"
	testTOTPSecret = "JBSWY3DPEHPK3PXP"
)

// newSecretTestManager 建一个带凭证/ACME 私钥/二次验证密钥的实例，并保证测试不受
// 开发机上可能已存在的 MANTOU_MASTER_KEY 影响（否则密钥不会落到 t.TempDir 里）。
func newSecretTestManager(t *testing.T) (*Manager, string) {
	t.Helper()
	t.Setenv(masterKeyEnv, "")
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	manager := NewManager(path)
	if err := manager.Load(); err != nil {
		t.Fatal(err)
	}
	if err := manager.Update(func(cfg *Config) {
		cfg.Credentials = []Credential{{
			ID:       "cred1",
			Name:     "我的 Cloudflare",
			Provider: "cloudflare",
			Secrets:  map[string]string{"apiToken": testAPIToken, "apiSecret": testAPISecret},
		}}
		cfg.ACMEAccounts = []ACMEAccount{{ID: "acc1", Email: "a@example.com", PrivateKeyPEM: testACMEKey}}
		cfg.Auth.TwoFA = TwoFA{Enabled: true, Secret: testTOTPSecret}
	}); err != nil {
		t.Fatal(err)
	}
	return manager, path
}

// readRaw 读出磁盘上的 config.json 原文。
func readRaw(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// 核心断言：凭证不得以明文出现在 config.json 里，而内存中的配置必须仍是明文
// （否则 DDNS 拿去调服务商 API 的就是一段密文）。
func TestSaveEncryptsSecretsAndKeepsMemoryPlaintext(t *testing.T) {
	manager, path := newSecretTestManager(t)

	raw := readRaw(t, path)
	for _, secret := range []string{testAPIToken, testAPISecret, testACMEKey, testTOTPSecret} {
		if strings.Contains(raw, secret) {
			t.Fatalf("敏感字段以明文落盘了: %q", secret)
		}
	}
	if !strings.Contains(raw, sealPrefix) {
		t.Fatalf("config.json 里没有任何密文标记 %q，加密未生效", sealPrefix)
	}
	// 值级加密的意义之一：文件结构仍然可读，非敏感字段能直接看、能手工修。
	if !strings.Contains(raw, `"provider": "cloudflare"`) || !strings.Contains(raw, `"name": "我的 Cloudflare"`) {
		t.Fatalf("非敏感字段应保持明文可读，实际内容:\n%s", raw)
	}

	got := manager.Get()
	if got.Credentials[0].Secrets["apiToken"] != testAPIToken {
		t.Fatalf("内存中的凭证不是明文: %q", got.Credentials[0].Secrets["apiToken"])
	}
	if got.ACMEAccounts[0].PrivateKeyPEM != testACMEKey {
		t.Fatalf("内存中的 ACME 私钥不是明文")
	}
	if got.Auth.TwoFA.Secret != testTOTPSecret {
		t.Fatalf("内存中的二次验证密钥不是明文: %q", got.Auth.TwoFA.Secret)
	}
	// Snapshot 与 Get 是同一份数据的两种视图，同样必须是明文。
	if manager.Snapshot().Credentials[0].Secrets["apiSecret"] != testAPISecret {
		t.Fatalf("快照中的凭证不是明文")
	}

	// 主密钥就在同目录，且是 32 字节的 hex。
	keyRaw, err := os.ReadFile(manager.KeyPath())
	if err != nil {
		t.Fatalf("主密钥未生成: %v", err)
	}
	key, err := hex.DecodeString(strings.TrimSpace(string(keyRaw)))
	if err != nil || len(key) != masterKeyLen {
		t.Fatalf("主密钥文件内容不是 %d 字节 hex: %q", masterKeyLen, keyRaw)
	}
}

// 落盘不得改动内存里的凭证：Secrets 是 map（引用类型），漏了克隆就会把内存中的明文
// 原地换成密文——第一次保存后一切正常，直到下一次续期/更新才以"鉴权失败"暴露。
// 连续保存两次后重新加载，必须还能还原出原始明文（若被就地改动，这里会拿到二次加密的结果）。
func TestRepeatedSavesDoNotCorruptSecrets(t *testing.T) {
	manager, path := newSecretTestManager(t)
	for i := 0; i < 3; i++ {
		if err := manager.Update(func(cfg *Config) { cfg.Update.About = fmt.Sprintf("第 %d 次改动", i) }); err != nil {
			t.Fatal(err)
		}
		if got := manager.Get().Credentials[0].Secrets["apiToken"]; got != testAPIToken {
			t.Fatalf("第 %d 次保存后内存凭证被改动: %q", i+1, got)
		}
	}

	t.Setenv(masterKeyEnv, "")
	reloaded := NewManager(path)
	if err := reloaded.Load(); err != nil {
		t.Fatal(err)
	}
	cfg := reloaded.Get()
	if cfg.Credentials[0].Secrets["apiToken"] != testAPIToken || cfg.Credentials[0].Secrets["apiSecret"] != testAPISecret {
		t.Fatalf("重新加载后凭证不一致: %+v", cfg.Credentials[0].Secrets)
	}
	if cfg.ACMEAccounts[0].PrivateKeyPEM != testACMEKey {
		t.Fatalf("重新加载后 ACME 私钥不一致")
	}
	if cfg.Auth.TwoFA.Secret != testTOTPSecret {
		t.Fatalf("重新加载后二次验证密钥不一致")
	}
}

// 会话签名密钥同样要加密：拿到它就能签发任意管理员令牌，绕过整个登录流程。
func TestJWTSecretIsEncryptedOnDisk(t *testing.T) {
	t.Setenv(masterKeyEnv, "")
	path := filepath.Join(t.TempDir(), "config.json")
	manager := NewManager(path)
	if err := manager.Load(); err != nil {
		t.Fatal(err)
	}
	secret := manager.Get().Auth.JWTSecret
	if len(secret) != 64 {
		t.Fatalf("首次启动应生成 32 字节的会话密钥，实际 %q", secret)
	}
	raw := readRaw(t, path)
	if strings.Contains(raw, secret) {
		t.Fatalf("会话签名密钥以明文落盘")
	}

	t.Setenv(masterKeyEnv, "")
	reloaded := NewManager(path)
	if err := reloaded.Load(); err != nil {
		t.Fatal(err)
	}
	if got := reloaded.Get().Auth.JWTSecret; got != secret {
		t.Fatalf("重新加载后会话密钥变了（会导致所有人被登出）: %q != %q", got, secret)
	}
}

// 主密钥丢失时必须启动失败并说清原因，绝不能"解不开就当空值"静默继续：
// 那样面板上凭证看着还在，而 DDNS 与证书续期会在下一个周期才零散报错。
func TestLoadFailsWhenMasterKeyIsMissing(t *testing.T) {
	manager, path := newSecretTestManager(t)
	if err := os.Remove(manager.KeyPath()); err != nil {
		t.Fatal(err)
	}
	before := readRaw(t, path)

	t.Setenv(masterKeyEnv, "")
	broken := NewManager(path)
	err := broken.Load()
	if err == nil {
		t.Fatal("主密钥丢失时必须报错")
	}
	if !strings.Contains(err.Error(), "master.key") {
		t.Fatalf("错误信息应指明主密钥文件: %v", err)
	}
	// 失败不得顺手把配置改写或清空（否则原本还能靠恢复密钥救回来的数据就真的没了）。
	if after := readRaw(t, path); after != before {
		t.Fatal("加载失败后 config.json 被改动了")
	}
	if _, err := os.Stat(manager.KeyPath()); !os.IsNotExist(err) {
		t.Fatal("解密路径不应生成新的主密钥")
	}
}

// 换了一把主密钥（例如误把别的实例的 master.key 拷过来）同样必须报错。
func TestLoadFailsWhenMasterKeyMismatches(t *testing.T) {
	manager, path := newSecretTestManager(t)
	other := make([]byte, masterKeyLen)
	for i := range other {
		other[i] = byte(i + 1)
	}
	if err := os.WriteFile(manager.KeyPath(), []byte(hex.EncodeToString(other)), 0o600); err != nil {
		t.Fatal(err)
	}

	t.Setenv(masterKeyEnv, "")
	broken := NewManager(path)
	if err := broken.Load(); err == nil || !strings.Contains(err.Error(), "不匹配") {
		t.Fatalf("主密钥不匹配时必须报错，实际 err=%v", err)
	}
}

// 加密上线前的旧配置（凭证是明文）必须能照常加载，并在下一次落盘时自动加密。
func TestLoadAcceptsPlaintextConfigAndEncryptsOnNextSave(t *testing.T) {
	t.Setenv(masterKeyEnv, "")
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	legacy := `{"version":2,"panel":{"port":25666},"auth":{"username":"admin","jwtSecret":"legacy-secret"},` +
		`"credentials":[{"id":"c1","name":"旧凭证","provider":"cloudflare","secrets":{"apiToken":"` + testAPIToken + `"}}]}`
	if err := os.WriteFile(path, []byte(legacy), 0o600); err != nil {
		t.Fatal(err)
	}

	manager := NewManager(path)
	if err := manager.Load(); err != nil {
		t.Fatal(err)
	}
	if got := manager.Get().Credentials[0].Secrets["apiToken"]; got != testAPIToken {
		t.Fatalf("明文旧配置应原样读入: %q", got)
	}
	// 只读加载不应该在磁盘上留下密钥文件。
	if _, err := os.Stat(manager.KeyPath()); !os.IsNotExist(err) {
		t.Fatal("仅加载明文配置时不应生成主密钥")
	}

	if err := manager.Update(func(cfg *Config) { cfg.Settings.Language = "en-US" }); err != nil {
		t.Fatal(err)
	}
	if raw := readRaw(t, path); strings.Contains(raw, testAPIToken) || !strings.Contains(raw, sealPrefix) {
		t.Fatalf("下一次落盘应把明文凭证加密，实际内容:\n%s", raw)
	}
	if _, err := os.Stat(manager.KeyPath()); err != nil {
		t.Fatalf("落盘时应生成主密钥: %v", err)
	}
}

// 用环境变量提供主密钥时，磁盘上不应出现 master.key（供容器 secret / systemd credential 部署）。
func TestMasterKeyFromEnvKeepsNothingOnDisk(t *testing.T) {
	key := make([]byte, masterKeyLen)
	for i := range key {
		key[i] = byte(0xA0 + i)
	}
	t.Setenv(masterKeyEnv, hex.EncodeToString(key))

	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	manager := NewManager(path)
	if err := manager.Load(); err != nil {
		t.Fatal(err)
	}
	if err := manager.Update(func(cfg *Config) {
		cfg.Credentials = []Credential{{ID: "c1", Provider: "cloudflare", Secrets: map[string]string{"apiToken": testAPIToken}}}
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(manager.KeyPath()); !os.IsNotExist(err) {
		t.Fatal("已通过环境变量提供密钥时不应生成 master.key")
	}
	if raw := readRaw(t, path); strings.Contains(raw, testAPIToken) {
		t.Fatal("环境变量密钥下凭证仍以明文落盘")
	}
	// 同一把环境变量密钥能解开。
	reloaded := NewManager(path)
	if err := reloaded.Load(); err != nil {
		t.Fatal(err)
	}
	if got := reloaded.Get().Credentials[0].Secrets["apiToken"]; got != testAPIToken {
		t.Fatalf("环境变量密钥无法解开自己加密的内容: %q", got)
	}
}

// AAD 绑定字段用途：把一段密文挪到别的字段里必须解不开。
// 否则攻击者能在不知道明文的前提下，把会话签名密钥换成某个已知值的密文。
func TestSealBindsFieldPurpose(t *testing.T) {
	key := make([]byte, masterKeyLen)
	box, err := newSecretBox(key)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := box.seal(testAPIToken, aadCredential)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := box.open(sealed, aadCredential); err != nil || got != testAPIToken {
		t.Fatalf("同一用途应能解开: got=%q err=%v", got, err)
	}
	if _, err := box.open(sealed, aadJWTSecret); err == nil {
		t.Fatal("换用途后必须解不开")
	}
	// 空值不加密：加密只会让"这个字段是不是空的"变得难以判断。
	if got, err := box.seal("", aadCredential); err != nil || got != "" {
		t.Fatalf("空值应原样返回: %q %v", got, err)
	}
	// 明文（无前缀）原样通过，这是兼容旧配置的关键。
	if got, err := box.open("plain-token", aadCredential); err != nil || got != "plain-token" {
		t.Fatalf("无前缀的值应原样返回: %q %v", got, err)
	}
}

// 主密钥文件同时接受 hex 与 base64（外部密钥管理系统多半给 base64）。
func TestDecodeMasterKeyAcceptsHexAndBase64(t *testing.T) {
	key := make([]byte, masterKeyLen)
	for i := range key {
		key[i] = byte(i)
	}
	for _, text := range []string{
		hex.EncodeToString(key),
		"  " + hex.EncodeToString(key) + "\n",
		base64.StdEncoding.EncodeToString(key),
		base64.RawURLEncoding.EncodeToString(key),
	} {
		got, err := decodeMasterKey(text)
		if err != nil {
			t.Fatalf("%q 应被接受: %v", text, err)
		}
		if string(got) != string(key) {
			t.Fatalf("%q 解出的密钥不对", text)
		}
	}
	for _, bad := range []string{"", "not-a-key", hex.EncodeToString(key[:16])} {
		if _, err := decodeMasterKey(bad); err == nil {
			t.Fatalf("%q 应被拒绝", bad)
		}
	}
}

// 密文被改过一个字节就必须解不开（GCM 的认证性），而不是解出一段垃圾。
func TestOpenRejectsTamperedCiphertext(t *testing.T) {
	box, err := newSecretBox(make([]byte, masterKeyLen))
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := box.seal(testAPIToken, aadCredential)
	if err != nil {
		t.Fatal(err)
	}
	b := []byte(sealed)
	b[len(b)-1] ^= 0x01
	if _, err := box.open(string(b), aadCredential); err == nil {
		t.Fatal("被改动的密文必须解不开")
	}
	if _, err := box.open(sealPrefix+"这不是 base64", aadCredential); err == nil {
		t.Fatal("非法 base64 必须报错")
	}
	if _, err := box.open(sealPrefix, aadCredential); err == nil {
		t.Fatal("空密文必须报错")
	}
}

// hasSealedSecret 只是探测，不能改动配置内容。
func TestHasSealedSecretDoesNotMutate(t *testing.T) {
	cfg := Default()
	cfg.Credentials = []Credential{{ID: "c1", Secrets: map[string]string{"apiToken": testAPIToken}}}
	cfg.Auth.JWTSecret = "plain"
	before, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if hasSealedSecret(cfg) {
		t.Fatal("全明文配置不应被判定为含密文")
	}
	after, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatal("探测过程改动了配置")
	}

	cfg.Credentials[0].Secrets["apiToken"] = sealPrefix + "abc"
	if !hasSealedSecret(cfg) {
		t.Fatal("含密文的配置应被识别")
	}
}
