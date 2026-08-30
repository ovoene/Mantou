package server

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"golang.org/x/crypto/pbkdf2"

	"mantou/internal/config"
)

// 本文件实现**备份文件**的加密：整份备份（配置 + 证书 PEM + 上传的图片）用
// 「管理员账号 + 用户输入的备份口令」派生的密钥整体加密成一个信封。
//
// 与 internal/config/secret.go 的磁盘字段加密是两套独立机制，职责不同，不要混淆：
//   - 磁盘字段加密：密钥是本机的 data/master.key，只加密 config.json 里的凭证字段，
//     目的是"文件被整体带走时凭证不泄露"；
//   - 备份加密（本文件）：密钥来自人记得的口令，加密的是整份可移植的备份，
//     目的是"备份能在另一台机器上解开并完整还原"。
//
// 正因如此，备份里存的是**明文凭证**（由备份口令保护），而不是 master.key 加密后的密文：
// 否则换台机器导入备份时，新机器没有原来的 master.key，所有凭证都会变成解不开的乱码，
// 用户还得回去逐个重填——"导入即可用"这条要求就不成立了。备份口令因此必须足够强。

const (
	cryptAppTag = "mantou"
	cryptKDF    = "pbkdf2-sha256"
	// cryptIter 为新备份采用的 PBKDF2 迭代次数；解密时改用信封内记录的 iter，
	// 因此提升本值不影响历史备份的解开（旧备份仍以其自身 iter 派生密钥）。
	cryptIter = 600000
	// 解密时接受的迭代次数区间：兼容历史较低迭代（如 200000）的备份，
	// 同时为异常值设上限，避免超大 iter 导致解密时 CPU 被恶意拖垮。
	cryptIterMin  = 100000
	cryptIterMax  = 4000000
	cryptKeyLen   = 32
	cryptSaltLen  = 16
	cryptNonceLen = 12
)

type cryptEnvelope struct {
	Encrypted bool   `json:"encrypted"`
	V         int    `json:"v"`
	App       string `json:"app"`
	KDF       string `json:"kdf"`
	Iter      int    `json:"iter"`
	Salt      string `json:"salt"`
	Nonce     string `json:"nonce"`
	Cipher    string `json:"cipher"`
	Certs     int    `json:"certs"`
	Uploads   int    `json:"uploads,omitempty"`
}

type CertBackup struct {
	ID      string `json:"id"`
	Method  string `json:"method,omitempty"`
	CertPEM string `json:"certPem"`
	KeyPEM  string `json:"keyPem"`
}

type FileBackup struct {
	Path string `json:"path"`
	Data []byte `json:"data"`
}

type backupPayload struct {
	Config  *config.Config `json:"config"`
	Certs   []CertBackup   `json:"certs"`
	Uploads []FileBackup   `json:"uploads"`
}

func deriveKey(account, password string, salt []byte, iter int) []byte {
	material := strings.ToLower(strings.TrimSpace(account)) + "\n" + password
	return pbkdf2.Key([]byte(material), salt, iter, cryptKeyLen, sha256.New)
}

func EncryptBackup(account, password string, cfg *config.Config, certs []CertBackup, uploads []FileBackup) ([]byte, error) {
	if cfg == nil {
		return nil, errors.New("配置为空")
	}
	salt := make([]byte, cryptSaltLen)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, err
	}
	plain, err := json.Marshal(backupPayload{Config: cfg, Certs: certs, Uploads: uploads})
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(deriveKey(account, password, salt, cryptIter))
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, cryptNonceLen)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	ct := gcm.Seal(nil, nonce, plain, nil)
	env := cryptEnvelope{
		Encrypted: true,
		V:         2,
		App:       cryptAppTag,
		KDF:       cryptKDF,
		Iter:      cryptIter,
		Salt:      base64.StdEncoding.EncodeToString(salt),
		Nonce:     base64.StdEncoding.EncodeToString(nonce),
		Cipher:    base64.StdEncoding.EncodeToString(ct),
		Certs:     len(certs),
		Uploads:   len(uploads),
	}
	return json.MarshalIndent(env, "", "  ")
}

func IsEncryptedEnvelope(data []byte) bool {
	var env cryptEnvelope
	if err := json.Unmarshal(data, &env); err != nil {
		return false
	}
	return env.Encrypted && env.Cipher != ""
}

func DecryptBackup(data []byte, account, password string) (*config.Config, []CertBackup, []FileBackup, error) {
	var env cryptEnvelope
	if err := json.Unmarshal(data, &env); err != nil {
		return nil, nil, nil, fmt.Errorf("备份格式不正确: %w", err)
	}
	if !env.Encrypted || env.Cipher == "" {
		return nil, nil, nil, errors.New("这不是加密备份文件")
	}
	if env.App != cryptAppTag {
		return nil, nil, nil, errors.New("非本程序生成的加密备份")
	}
	if env.V < 1 || env.V > 2 || env.KDF != cryptKDF || env.Iter < cryptIterMin || env.Iter > cryptIterMax {
		return nil, nil, nil, errors.New("不支持的备份加密参数")
	}
	salt, err := base64.StdEncoding.DecodeString(env.Salt)
	if err != nil || len(salt) != cryptSaltLen {
		return nil, nil, nil, errors.New("备份 salt 字段损坏")
	}
	nonce, err := base64.StdEncoding.DecodeString(env.Nonce)
	if err != nil || len(nonce) != cryptNonceLen {
		return nil, nil, nil, errors.New("备份 nonce 字段损坏")
	}
	ct, err := base64.StdEncoding.DecodeString(env.Cipher)
	if err != nil || len(ct) < 16 {
		return nil, nil, nil, errors.New("备份 cipher 字段损坏")
	}
	block, err := aes.NewCipher(deriveKey(account, password, salt, env.Iter))
	if err != nil {
		return nil, nil, nil, errors.New("解密密钥派生失败")
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, nil, errors.New("解密算法初始化失败")
	}
	plain, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return nil, nil, nil, errors.New("解密失败：账户名或密码不正确")
	}
	var payload backupPayload
	if err := json.Unmarshal(plain, &payload); err == nil && payload.Config != nil {
		return payload.Config, payload.Certs, payload.Uploads, nil
	}
	var cfg config.Config
	if err := json.Unmarshal(plain, &cfg); err != nil {
		return nil, nil, nil, fmt.Errorf("解密后的配置解析失败: %w", err)
	}
	return &cfg, nil, nil, nil
}
