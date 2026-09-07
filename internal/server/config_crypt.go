package server

import (
	"bytes"
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
	cryptIterMin = 100000
	// cryptIterMax 的取值只为一件事服务：iter 是信封里的字段，由**文件**说了算，
	// 而派生密钥必须在校验 AEAD 标签之前完成——这笔 CPU 一定会先付出去，
	// 标签最后对不对都一样。原来留到 4000000，是本程序实际使用的 600000 的近七倍，
	// 而本程序从未生成过 iter 高于 cryptIter 的备份，这七倍没有任何东西需要它：
	// 它只是让一份手改过 iter 的文件把每次导入的固定开销放大七倍
	//（在 512MB 那类小主机上是十几秒的满核）。
	//
	// 收到 1000000：仍高于 cryptIter，留下一档提升余量。把 cryptIter 提到这个数以上时，
	// 必须在同一次改动里把本值一起提上去；而本值只能升不能降——降了会让已经在
	// 用户手里的备份变成"不支持的加密参数"。
	cryptIterMax  = 1000000
	cryptKeyLen   = 32
	cryptSaltLen  = 16
	cryptNonceLen = 12
)

// 备份口令的长度约束。下限对**实际用于派生密钥的那个口令**生效：
// 导出时另设了独立口令就管那个，没设则管沿用的登录密码（审计 S-01；两处都在
// handleExportConfig 里）。上限只对独立口令有意义——登录密码受 bcrypt 的
// 72 字节限制，本来就到不了 256。
//
// 下限刻意比登录密码的 6 位严：登录有限流器挡着（5 次失败即锁定），
// 而一份备份文件是离线的，拿到手就能不限次数地猜，60 万次 PBKDF2 是唯一的减速带。
// 而备份里存的是**明文凭证**（见本文件头的说明），猜开的代价是整台机器的所有凭据。
// 这个理由与口令来自哪一侧无关，所以两条路都得套同一个下限。
//
// 上限不是 bcrypt 那个 72 字节——那是登录密码的限制，PBKDF2 没有。
// 定 256 只为让"填错了一整段文本进来"得到一句清楚的报错，而不是一个能用却记不住的备份。
const (
	minBackupPassphraseLen = 8
	maxBackupPassphraseLen = 256
)

// cryptEnvelopeVersion 新备份写入的信封版本。
//
// v3 与 v2 的唯一区别是把信封头绑进了 AEAD 的附加认证数据（见 envelopeAAD）。
// 解密仍然接受 v1 / v2：那两版封的时候没有 AAD，解的时候也必须传 nil，
// 否则已经在用户手里的历史备份会一夜之间全部打不开。
const cryptEnvelopeVersion = 3

type cryptEnvelope struct {
	Encrypted bool   `json:"encrypted"`
	V         int    `json:"v"`
	App       string `json:"app"`
	KDF       string `json:"kdf"`
	Iter      int    `json:"iter"`
	Salt      string `json:"salt"`
	Nonce     string `json:"nonce"`
	// Cipher 是这个信封里唯一按备份体积增长的字段（128 MB 的备份几乎全在这里），
	// 所以它不是 string：cipherBytes 在 JSON 解码时就地解出字节，
	// 省掉一份与整个密文等大的 base64 字符串。见该类型的说明。
	Cipher  cipherBytes `json:"cipher"`
	Certs   int         `json:"certs"`
	Uploads int         `json:"uploads,omitempty"`
}

// cipherBytes 是信封里那段 base64 密文，解码时**就地**解成字节。
//
// 存在的理由只有体积。备份文件上限 128 MB（maxBackupFileSize），先解成 string
// 再 base64.DecodeString，等于同一份数据同时占着 base64 与二进制两份，
// 约 128 MB 加 96 MB，而导入这条路上还压着请求体本身那 128 MB。
// UnmarshalJSON 拿到的是原始 JSON 片段的切片，本类型不留下它，直接解进自己的缓冲。
type cipherBytes []byte

func (b cipherBytes) MarshalJSON() ([]byte, error) {
	out := make([]byte, 0, base64.StdEncoding.EncodedLen(len(b))+2)
	out = append(out, '"')
	out = base64.StdEncoding.AppendEncode(out, b)
	return append(out, '"'), nil
}

func (b *cipherBytes) UnmarshalJSON(data []byte) error {
	if string(data) == "null" {
		*b = nil
		return nil
	}
	if len(data) < 2 || data[0] != '"' || data[len(data)-1] != '"' {
		return errors.New("cipher 字段不是字符串")
	}
	raw := data[1 : len(data)-1]
	// 退路：JSON 字符串允许转义，而 base64 字母表里的 "/" 正是有些编码器会写成 "\/" 的字符。
	// 本程序生成的备份不会带转义（Go 的 encoder 不转义 /），手工改过的文件可能带，
	// 那时先交给标准库把转义解开——多一份字符串，但只发生在这种文件上。
	if bytes.IndexByte(raw, '\\') >= 0 {
		var s string
		if err := json.Unmarshal(data, &s); err != nil {
			return err
		}
		raw = []byte(s)
	}
	out := make([]byte, base64.StdEncoding.DecodedLen(len(raw)))
	n, err := base64.StdEncoding.Decode(out, raw)
	if err != nil {
		return errors.New("cipher 字段不是有效的 base64")
	}
	*b = out[:n]
	return nil
}

// envelopeProbe 只回答"这是不是一份加密信封"，刻意不把 cipher 的内容留下来。
//
// IsEncryptedEnvelope 在导入路径的最前面跑一遍，只为看两个布尔值；
// 拿 cryptEnvelope 去解会连那 96 MB 密文一起解出来，再整份扔掉。
type envelopeProbe struct {
	Encrypted bool        `json:"encrypted"`
	Cipher    nonEmptyStr `json:"cipher"`
}

// nonEmptyStr 记下这个 JSON 字段"是不是一个非空字符串"，不保留内容。
type nonEmptyStr bool

func (b *nonEmptyStr) UnmarshalJSON(data []byte) error {
	// 最短的非空 JSON 字符串是 `""` 两个字节；null、数字、空串一律算没有。
	*b = nonEmptyStr(len(data) > 2 && data[0] == '"')
	return nil
}

// envelopeAAD 把信封头拼成 AEAD 的附加认证数据。
//
// v2 之前头里一个字段都没被认证：certs / uploads 那两个计数改了只影响界面上的显示，
// 而 iter / salt / nonce 改了会让解密失败——失败本身不算错，但那句报错说的是
// "账户名或密码不正确"，把一份被改动过的文件说成用户记错了口令。绑进 AEAD 之后
// 任何一处改动都由标签检出，报错也就能把两种可能一起说清。
//
// 拼法与字段在 JSON 里的顺序无关（对象的键序不保证），所以按固定顺序逐字段写死，
// 而不是拿信封的 JSON 原文当 AAD。往信封里加新字段时记得一并加到这里来。
func envelopeAAD(env cryptEnvelope) []byte {
	return []byte(fmt.Sprintf("%s|v=%d|app=%s|kdf=%s|iter=%d|salt=%s|nonce=%s|certs=%d|uploads=%d",
		cryptAppTag, env.V, env.App, env.KDF, env.Iter, env.Salt, env.Nonce, env.Certs, env.Uploads))
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
	env := cryptEnvelope{
		Encrypted: true,
		V:         cryptEnvelopeVersion,
		App:       cryptAppTag,
		KDF:       cryptKDF,
		Iter:      cryptIter,
		Salt:      base64.StdEncoding.EncodeToString(salt),
		Nonce:     base64.StdEncoding.EncodeToString(nonce),
		Certs:     len(certs),
		Uploads:   len(uploads),
	}
	// 头先填好、再封：AAD 认的就是上面这些字段（见 envelopeAAD），
	// 所以 Seal 必须排在信封头定稿之后，中间不能再改动它们。
	env.Cipher = gcm.Seal(nil, nonce, plain, envelopeAAD(env))
	return json.MarshalIndent(env, "", "  ")
}

func IsEncryptedEnvelope(data []byte) bool {
	var probe envelopeProbe
	if err := json.Unmarshal(data, &probe); err != nil {
		return false
	}
	return probe.Encrypted && bool(probe.Cipher)
}

func DecryptBackup(data []byte, account, password string) (*config.Config, []CertBackup, []FileBackup, error) {
	var env cryptEnvelope
	if err := json.Unmarshal(data, &env); err != nil {
		return nil, nil, nil, fmt.Errorf("备份格式不正确: %w", err)
	}
	if !env.Encrypted || len(env.Cipher) == 0 {
		return nil, nil, nil, errors.New("这不是加密备份文件")
	}
	if env.App != cryptAppTag {
		return nil, nil, nil, errors.New("非本程序生成的加密备份")
	}
	if env.V < 1 || env.V > cryptEnvelopeVersion || env.KDF != cryptKDF || env.Iter < cryptIterMin || env.Iter > cryptIterMax {
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
	ct := env.Cipher
	if len(ct) < 16 {
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
	// v1 / v2 的密文封的时候没有 AAD，解的时候也必须传 nil（见 cryptEnvelopeVersion）。
	var aad []byte
	if env.V >= 3 {
		aad = envelopeAAD(env)
	}
	// 就地解密：ct 与备份等大（最大约 96 MB），另开一份输出等于同时占两份，
	// 而这条路上还压着请求体那 128 MB。ct 的容量来自 cipherBytes 的解码缓冲，
	// 一定放得下短 16 字节的明文，不会因为 append 而重新分配。
	plain, err := gcm.Open(ct[:0], nonce, ct, aad)
	if err != nil {
		// 三种可能都要说出来：口令不对、账户名不对、文件被改过。
		// 特别是第一种——导出时可以另设一个独立的备份口令（见 handleExportConfig），
		// 那时这里要填的不是登录密码，而人最容易先试登录密码然后以为备份坏了。
		return nil, nil, nil, errors.New("解密失败：账户名或备份口令不正确，或备份文件已被改动" +
			"（导出时若另设了独立的备份口令，这里要填那一个，不是登录密码）")
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
