package server

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"mantou/internal/config"
)

// 备份信封原来只认证密文，头里那一串字段（v / app / kdf / iter / salt / nonce /
// certs / uploads）一个都没被认证。certs、uploads 改了只影响界面上的显示数字；
// iter、salt、nonce 改了会让解密失败，而那句报错说的是"账户名或密码不正确"，
// 把一份被改动过的文件说成用户记错了口令。v3 起把整个头绑进 AAD。
//
// 本文件钉三件事：新备份确实带 AAD 且改一个字节就检出；v1/v2 的老备份照样解得开；
// iter 的取值区间真的拦得住区间外的数。

func backupTestConfig() *config.Config {
	return &config.Config{Auth: config.Auth{Username: "admin", PasswordHash: "hash"}}
}

// reopenEnvelope 把一份备份解成信封结构、交给 mutate 改动，再原样序列化回去。
func reopenEnvelope(t *testing.T, data []byte, mutate func(env *cryptEnvelope)) []byte {
	t.Helper()
	var env cryptEnvelope
	if err := json.Unmarshal(data, &env); err != nil {
		t.Fatal(err)
	}
	mutate(&env)
	out, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// TestBackupEnvelopeUsesCurrentVersion 新备份必须写当前版本号。
// 这一条是给 AAD 兜底的：版本号退回 2 就等于悄悄关掉了下面那道认证。
func TestBackupEnvelopeUsesCurrentVersion(t *testing.T) {
	data, err := EncryptBackup("admin", "password", backupTestConfig(), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	var env cryptEnvelope
	if err := json.Unmarshal(data, &env); err != nil {
		t.Fatal(err)
	}
	if env.V != cryptEnvelopeVersion {
		t.Fatalf("新备份写的版本是 %d，应为 %d", env.V, cryptEnvelopeVersion)
	}
	if env.Iter != cryptIter {
		t.Fatalf("新备份写的迭代次数是 %d，应为 %d", env.Iter, cryptIter)
	}
	if cryptIter > cryptIterMax || cryptIter < cryptIterMin {
		t.Fatalf("cryptIter=%d 落在解密可接受区间 [%d, %d] 之外，自己生成的备份都解不开",
			cryptIter, cryptIterMin, cryptIterMax)
	}
}

// TestDecryptBackupDetectsHeaderTampering 头里任何一处改动都要被标签检出，
// 且报错要提到"文件被改动"这一种可能——否则用户只会以为自己记错了口令。
func TestDecryptBackupDetectsHeaderTampering(t *testing.T) {
	data, err := EncryptBackup("admin", "password", backupTestConfig(), []CertBackup{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	// 先确认原件是解得开的，免得下面每一条都因为别的原因失败。
	if _, _, _, err := DecryptBackup(data, "admin", "password"); err != nil {
		t.Fatalf("测试前提不成立，原件就解不开: %v", err)
	}

	cases := []struct {
		name   string
		mutate func(env *cryptEnvelope)
	}{
		// certs / uploads 是纯展示字段：改了它们从前一点反应都没有。
		{"证书计数", func(env *cryptEnvelope) { env.Certs = 99 }},
		{"上传文件计数", func(env *cryptEnvelope) { env.Uploads = 99 }},
		{"版本号", func(env *cryptEnvelope) { env.V = 1 }},
		{"程序标记", func(env *cryptEnvelope) { env.App = cryptAppTag }}, // 不变，用于对照
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tampered := reopenEnvelope(t, data, tc.mutate)
			_, _, _, err := DecryptBackup(tampered, "admin", "password")
			if tc.name == "程序标记" {
				// 对照组：什么都没改，必须仍然解得开——证明上面几条失败是改动本身导致的，
				// 而不是"重新序列化一遍就解不开了"。
				if err != nil {
					t.Fatalf("未改动的信封重新序列化后解不开了: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatal("改了信封头却照样解开了")
			}
			if !strings.Contains(err.Error(), "改动") {
				t.Fatalf("报错没提到文件可能被改动，用户只会以为口令记错了: %v", err)
			}
		})
	}
}

// legacyEnvelope 手工造一份 v2 信封：封的时候不带 AAD，正如 v3 之前的所有备份。
func legacyEnvelope(t *testing.T, version int, account, password string, cfg *config.Config) []byte {
	t.Helper()
	salt := bytes.Repeat([]byte{0x07}, cryptSaltLen)
	nonce := bytes.Repeat([]byte{0x09}, cryptNonceLen)
	plain, err := json.Marshal(backupPayload{Config: cfg})
	if err != nil {
		t.Fatal(err)
	}
	// 用区间下限的迭代次数：老备份正是这一档，同时让这个测试跑得快些。
	block, err := aes.NewCipher(deriveKey(account, password, salt, cryptIterMin))
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	env := cryptEnvelope{
		Encrypted: true,
		V:         version,
		App:       cryptAppTag,
		KDF:       cryptKDF,
		Iter:      cryptIterMin,
		Salt:      base64.StdEncoding.EncodeToString(salt),
		Nonce:     base64.StdEncoding.EncodeToString(nonce),
		Cipher:    gcm.Seal(nil, nonce, plain, nil), // 关键：AAD 为 nil
	}
	out, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// TestDecryptBackupAcceptsLegacyEnvelopes v1 / v2 的备份已经在用户手里，
// 解密不能因为新增 AAD 而把它们全部拒之门外。
func TestDecryptBackupAcceptsLegacyEnvelopes(t *testing.T) {
	for _, v := range []int{1, 2} {
		data := legacyEnvelope(t, v, "admin", "password", backupTestConfig())
		cfg, _, _, err := DecryptBackup(data, "admin", "password")
		if err != nil {
			t.Fatalf("v%d 的老备份解不开了: %v", v, err)
		}
		if cfg.Auth.Username != "admin" {
			t.Fatalf("v%d 解出来的账户名是 %q", v, cfg.Auth.Username)
		}
	}
}

// TestDecryptBackupRejectsIterOutsideRange iter 由文件说了算，而派生密钥必须在
// 校验标签之前完成——这笔 CPU 一定会先付出去。区间外的数必须在派生之前就被挡掉。
func TestDecryptBackupRejectsIterOutsideRange(t *testing.T) {
	data, err := EncryptBackup("admin", "password", backupTestConfig(), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, iter := range []int{cryptIterMin - 1, cryptIterMax + 1, 0, -1, 1 << 30} {
		tampered := reopenEnvelope(t, data, func(env *cryptEnvelope) { env.Iter = iter })
		_, _, _, err := DecryptBackup(tampered, "admin", "password")
		if err == nil {
			t.Fatalf("iter=%d 落在 [%d, %d] 之外，却被接受了", iter, cryptIterMin, cryptIterMax)
		}
		if !strings.Contains(err.Error(), "不支持的备份加密参数") {
			t.Fatalf("iter=%d 应在派生密钥之前就被参数校验挡掉，实际报错: %v", iter, err)
		}
	}
}

// TestIsEncryptedEnvelopeProbe 探测只看两个字段，且要认得出各种"没有密文"的形态。
//
// 它跑在导入路径最前面、每份上传都要过一遍，所以刻意不解 cipher 的内容
// （一份 128 MB 的备份几乎全在那个字段里）。
func TestIsEncryptedEnvelopeProbe(t *testing.T) {
	real, err := EncryptBackup("admin", "password", backupTestConfig(), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		data string
		want bool
	}{
		{"真备份", string(real), true},
		{"密文为空串", `{"encrypted":true,"cipher":""}`, false},
		{"密文为 null", `{"encrypted":true,"cipher":null}`, false},
		{"密文是数字", `{"encrypted":true,"cipher":12345}`, false},
		{"没有 encrypted", `{"cipher":"AAAAAAAAAAAAAAAAAAAAAA=="}`, false},
		{"明文配置", `{"auth":{"username":"admin"}}`, false},
		{"根本不是 JSON", "not json at all", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsEncryptedEnvelope([]byte(tc.data)); got != tc.want {
				t.Fatalf("探测结果 %v，应为 %v", got, tc.want)
			}
		})
	}
}

// TestCipherBytesRoundTripHandlesEscapes 密文字段就地解 base64，因此要自己认得
// JSON 的转义：base64 字母表里的 "/" 正是有些编码器会写成 "\/" 的字符。
func TestCipherBytesRoundTripHandlesEscapes(t *testing.T) {
	// 0xFF 0xFF 0xFF 编码成 "////"，正好落在会被转义的那个字符上。
	raw := cipherBytes{0xFF, 0xFF, 0xFF}
	encoded, err := json.Marshal(raw)
	if err != nil {
		t.Fatal(err)
	}
	if string(encoded) != `"////"` {
		t.Fatalf("编码结果是 %s，应为 \"////\"", encoded)
	}
	for _, in := range []string{`"////"`, `"\/\/\/\/"`} {
		var got cipherBytes
		if err := json.Unmarshal([]byte(in), &got); err != nil {
			t.Fatalf("%s 解不开: %v", in, err)
		}
		if !bytes.Equal(got, raw) {
			t.Fatalf("%s 解出 %x，应为 %x", in, got, raw)
		}
	}
	// 坏 base64 必须报错，而不是静默解出一段短内容。
	var bad cipherBytes
	if err := json.Unmarshal([]byte(`"!!!!"`), &bad); err == nil {
		t.Fatal("非 base64 内容被接受了")
	}
}
