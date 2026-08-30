package config

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"

	"mantou/internal/logx"
)

// 本文件实现 config.json 中**敏感字段的值级加密**。
//
// 问题：DNS 服务商凭证（可改写整个域名的解析）、ACME 账户私钥（可代表你签发证书）、
// 会话签名密钥（可伪造任意管理员令牌）原本以明文躺在 data/config.json 里。
// 该文件权限是 0600，但这只防住"同机其他普通用户"——真正常见的泄露路径是**文件被整体带走**：
// 复制整个 data 目录去做备份、把 data 卷挂到别处排障、误把 data/ 提交进仓库、
// 宿主机快照/镜像被分发。这些场景下文件权限完全不起作用，而一份明文凭证意味着域名被接管。
//
// 方案：把凭证字段单独用 AES-256-GCM 加密，密钥放在同目录的 master.key（0600，首次启动生成）。
//   - 值级而非整文件加密：config.json 结构仍然可读，端口写错、规则重复这类问题依旧可以直接看文件排障，
//     出问题时也能手工修复非敏感字段——整文件加密会把这条排障路径彻底堵死；
//   - 加解密只发生在磁盘边界（Load 时解、saveConfig 时加），config.Manager 内存中永远是明文，
//     因此所有业务模块（DDNS 更新、证书续期、面板接口）代码零改动，也不存在
//     "拿到的是密文还没解开"这类只在续期时才会暴露的时序问题；
//   - 备份导出的是内存里的明文，随后被备份口令整体加密（见 internal/server/config_crypt.go）。
//     这保证了"换台机器导入备份即完全一致"：master.key 是本机的东西，不进备份、也不需要进备份，
//     导入方用自己的 master.key 重新加密落盘即可。
//
// 威胁模型边界（务实起见明说）：攻击者若能同时拿到 config.json 和 master.key，加密不构成障碍——
// 两个文件同目录同权限。本方案挡的是"只拿到 config.json"的那一大类场景（备份、卷、快照、误提交），
// 以及"凭证明文出现在任何被 grep/日志/网盘索引的地方"。想要更强的隔离，
// 可用 MANTOU_MASTER_KEY 把密钥交给外部密钥管理（容器 secret、systemd credential），
// 此时磁盘上根本不存在 master.key。

const (
	// masterKeyEnv 用环境变量提供主密钥（hex 或 base64 的 32 字节），优先于密钥文件。
	// 供不希望密钥落在磁盘上的部署使用：容器 secret、systemd LoadCredential 等。
	masterKeyEnv = "MANTOU_MASTER_KEY"
	// masterKeyName 主密钥文件名，与 config.json 同目录。
	masterKeyName = "master.key"
	// masterKeyLen AES-256 要求 32 字节。
	masterKeyLen = 32
	// sealPrefix 密文标记：带此前缀的字段值需要解密，不带的按明文处理（兼容旧配置）。
	// 版本号留在前缀里，将来换算法/换封装时可按前缀分流而不必猜测。
	sealPrefix = "enc:v1:"
)

// 附加认证数据（AAD）按**字段用途**取值，而不带条目 ID。
//
// 带上用途可以阻止"把一段密文挪到另一种字段里"——例如把某个 DNS token 的密文粘到
// auth.jwtSecret 位置上，从而在不知道明文的情况下把会话密钥换成一个已知值。
// 不带条目 ID 是刻意的取舍：ID 一旦进 AAD，用户手工整理 config.json（重排凭证、改 ID、
// 把一条凭证复制成两条）就会让密文再也解不开，而这类整理是合理操作；
// 而"把凭证 A 的密文挪到凭证 B"造成的后果只是 B 用了 A 的凭证，攻击者本来就能做到
// （直接把 A、B 的整个条目对调即可），AAD 拦不住也没必要拦。
const (
	aadJWTSecret  = "auth.jwtSecret"
	aadTOTPSecret = "auth.twoFA.secret"
	aadACMEKey    = "acme.privateKeyPem"
	aadCredential = "credential.secret"
	// 消息路由模块的三类凭证。
	//
	// aadWebhookToken 入站接收器的令牌：拿到它就能冒充第三方系统往面板推消息。
	// aadNotifyURL 出站目标地址：钉钉与企业微信把 access_token 直接放在 query 里，
	//   这个 URL **本身**就是凭证，泄露即等于获得往群里发任意消息的能力，故整段加密。
	// aadNotifySecret 钉钉机器人加签密钥。
	// aadNotifyHeader 自定义 HTTP 目标的附加请求头值（常见形态是 Authorization: Bearer …）。
	aadWebhookToken = "webhook.receiver.token"
	aadNotifyURL    = "notify.target.url"
	aadNotifySecret = "notify.target.secret"
	aadNotifyHeader = "notify.target.header"
)

// errMasterKeyMissing 密钥文件不存在（且未要求生成）。
var errMasterKeyMissing = errors.New("主密钥文件不存在")

// errSealMismatch 密文无法用当前密钥解开：密钥被换过、或密文被改动过。
// GCM 的认证失败不区分这两种情况，也不应该区分（区分本身就是一种预言机）。
var errSealMismatch = errors.New("密文与当前主密钥不匹配")

// decodeMasterKey 解析 32 字节密钥的文本表示，同时接受 hex 与 base64。
// 两种都收是因为密钥要经手人类：文件里写的是 hex（便于肉眼比对/抄录），
// 而外部密钥管理系统（容器 secret、云厂商 KMS 导出）多半给的是 base64。
func decodeMasterKey(text string) ([]byte, error) {
	s := strings.TrimSpace(text)
	if s == "" {
		return nil, fmt.Errorf("内容为空")
	}
	if key, err := hex.DecodeString(s); err == nil && len(key) == masterKeyLen {
		return key, nil
	}
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if key, err := enc.DecodeString(s); err == nil && len(key) == masterKeyLen {
			return key, nil
		}
	}
	return nil, fmt.Errorf("必须是 %d 字节密钥的 hex（%d 字符）或 base64 表示", masterKeyLen, masterKeyLen*2)
}

// loadMasterKey 取得主密钥：环境变量优先，其次密钥文件；
// create 为真且文件不存在时生成一把新的并落盘（0600 + 原子替换，与 config.json 同等对待）。
//
// create 为假时返回 errMasterKeyMissing 而不是"顺手生成一把"，这一点很关键：
// 配置里已有密文却找不到密钥，说明用户丢了密钥文件或只恢复了 config.json。
// 此时生成新密钥只会让错误从"解不开"变成"解开后是空的"——凭证静默丢失，
// 而 DDNS/证书续期要到下一个周期才会以"鉴权失败"的面目暴露出来。
func loadMasterKey(path string, create bool) ([]byte, error) {
	if raw := strings.TrimSpace(os.Getenv(masterKeyEnv)); raw != "" {
		key, err := decodeMasterKey(raw)
		if err != nil {
			return nil, fmt.Errorf("环境变量 %s 无效: %w", masterKeyEnv, err)
		}
		return key, nil
	}

	data, err := os.ReadFile(path)
	switch {
	case err == nil:
		key, err := decodeMasterKey(string(data))
		if err != nil {
			return nil, fmt.Errorf("主密钥文件 %s 无效: %w", path, err)
		}
		return key, nil
	case !os.IsNotExist(err):
		return nil, fmt.Errorf("读取主密钥失败: %w", err)
	case !create:
		return nil, errMasterKeyMissing
	}

	key := make([]byte, masterKeyLen)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("生成主密钥失败: %w", err)
	}
	// 主密钥是解开配置中凭证字段的唯一钥匙，且一生只写一次：必须 fsync。
	if err := writeFileAtomic(path, []byte(hex.EncodeToString(key)+"\n"), 0o600, fsyncData); err != nil {
		return nil, fmt.Errorf("写入主密钥失败: %w", err)
	}
	logx.L().Warn("已生成配置主密钥，它是解开配置中凭证字段的唯一钥匙，请与配置一并备份（或用面板的加密导出）",
		"path", path)
	return key, nil
}

// secretBox 用主密钥对单个字段值做加解密。
type secretBox struct {
	aead cipher.AEAD
}

func newSecretBox(key []byte) (*secretBox, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("初始化主密钥失败: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("初始化认证加密失败: %w", err)
	}
	return &secretBox{aead: aead}, nil
}

// seal 加密单个字段值，输出 sealPrefix + base64(nonce || ciphertext)。
// 空值原样返回：没有内容就没有秘密，加密只会让"这个字段是不是空的"变得难以判断。
//
// 每次调用都用新的随机 nonce，因此同一份配置反复落盘会得到不同的密文。
// 这让 config.json 的字节内容不再稳定，但脏检查（configEqual）比较的是**内存中的明文**，
// 所以并不会因此产生额外写盘。
func (b *secretBox) seal(plain, aad string) (string, error) {
	if plain == "" {
		return "", nil
	}
	nonce := make([]byte, b.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("生成随机数失败: %w", err)
	}
	sealed := b.aead.Seal(nonce, nonce, []byte(plain), []byte(aad))
	return sealPrefix + base64.RawStdEncoding.EncodeToString(sealed), nil
}

// open 解密单个字段值；不带 sealPrefix 的值按明文原样返回（兼容加密前的旧配置，
// 以及用户手工填进去的凭证——下一次落盘会自动把它们加密）。
func (b *secretBox) open(value, aad string) (string, error) {
	if !strings.HasPrefix(value, sealPrefix) {
		return value, nil
	}
	raw, err := base64.RawStdEncoding.DecodeString(strings.TrimPrefix(value, sealPrefix))
	if err != nil {
		return "", fmt.Errorf("密文不是合法的 base64: %w", err)
	}
	ns := b.aead.NonceSize()
	if len(raw) <= ns {
		return "", fmt.Errorf("密文长度不足")
	}
	plain, err := b.aead.Open(nil, raw[:ns], raw[ns:], []byte(aad))
	if err != nil {
		return "", errSealMismatch
	}
	return string(plain), nil
}

// walkSecrets 遍历 cfg 中所有需要加密的字段，对每个值调用 fn(值, 用途)，并把返回值写回原位。
//
// 加密与解密共用这一份遍历，是为了不让两边的字段清单发生漂移：漏在加密侧意味着
// 凭证继续明文落盘、且不会有任何报错；漏在解密侧则是启动即失败。共用一份就只有一处要维护。
//
// **调用方必须保证 cfg 是可以就地改动的副本**：本函数直接改写 cfg（含 Secrets map 的值）。
// 加密路径上这份副本由 configForDisk 提供。
func walkSecrets(cfg *Config, fn func(value, aad string) (string, error)) error {
	if cfg == nil {
		return nil
	}
	apply := func(ptr *string, aad, what string) error {
		next, err := fn(*ptr, aad)
		if err != nil {
			return fmt.Errorf("%s: %w", what, err)
		}
		*ptr = next
		return nil
	}
	if err := apply(&cfg.Auth.JWTSecret, aadJWTSecret, "会话签名密钥"); err != nil {
		return err
	}
	if err := apply(&cfg.Auth.TwoFA.Secret, aadTOTPSecret, "二次验证密钥"); err != nil {
		return err
	}
	for i := range cfg.ACMEAccounts {
		acc := &cfg.ACMEAccounts[i]
		if err := apply(&acc.PrivateKeyPEM, aadACMEKey, "ACME 账户 "+acc.Email+" 的私钥"); err != nil {
			return err
		}
	}
	// map 的值取不到地址，单独处理。range 中只改已有键的值，不新增键，是安全的。
	for i := range cfg.Credentials {
		cred := &cfg.Credentials[i]
		for k, v := range cred.Secrets {
			next, err := fn(v, aadCredential)
			if err != nil {
				return fmt.Errorf("凭证 %s 的 %s 字段: %w", credLabel(cred), k, err)
			}
			cred.Secrets[k] = next
		}
	}
	// 消息路由：入站令牌。
	for i := range cfg.WebhookReceivers {
		r := &cfg.WebhookReceivers[i]
		if err := apply(&r.Token, aadWebhookToken, "Webhook 接收器 "+itemLabel(r.Name, r.ID)+" 的令牌"); err != nil {
			return err
		}
	}
	// 消息路由：出站目标的地址、加签密钥与自定义请求头。
	for i := range cfg.NotifyTargets {
		t := &cfg.NotifyTargets[i]
		label := itemLabel(t.Name, t.ID)
		if err := apply(&t.URL, aadNotifyURL, "通知目标 "+label+" 的地址"); err != nil {
			return err
		}
		if err := apply(&t.Secret, aadNotifySecret, "通知目标 "+label+" 的加签密钥"); err != nil {
			return err
		}
		// 同 Credentials.Secrets：map 值不可寻址，单独一轮。
		// 依赖 configForDisk 已经克隆过这个 map——否则这里会把内存中的请求头原地换成密文，
		// 之后投递时带出去的就是一段 enc:v1: 文本（见 state.go 的 configForDisk）。
		for k, v := range t.Headers {
			next, err := fn(v, aadNotifyHeader)
			if err != nil {
				return fmt.Errorf("通知目标 %s 的请求头 %s: %w", label, k, err)
			}
			t.Headers[k] = next
		}
	}
	return nil
}

// itemLabel 给条目一个可读标识用于错误信息（名称为空时退回 ID）。
// 只用于错误信息，绝不能把凭证内容拼进去。
func itemLabel(name, id string) string {
	if name != "" {
		return name
	}
	return id
}

// credLabel 给凭证一个可读标识用于错误信息（名称为空时退回 ID）。
// 只用于错误信息，绝不能把 Secrets 的内容拼进去。
func credLabel(c *Credential) string {
	if c.Name != "" {
		return c.Name
	}
	return c.ID
}

// hasSealedSecret 判断配置里是否已经存在密文字段。
// 用于区分两种"没有密钥文件"的处境：全新安装/旧版明文配置（正常，生成密钥即可）
// 与密钥丢失（必须报错，不能静默丢凭证）。
func hasSealedSecret(cfg *Config) bool {
	found := false
	// fn 原样返回入参，故这次遍历不改变任何字段（写回的是同一个值）。
	_ = walkSecrets(cfg, func(v, _ string) (string, error) {
		if strings.HasPrefix(v, sealPrefix) {
			found = true
		}
		return v, nil
	})
	return found
}

// sealSecrets 就地加密 cfg（必须是副本）中的敏感字段。
func (b *secretBox) sealSecrets(cfg *Config) error {
	return walkSecrets(cfg, b.seal)
}

// openSecrets 就地解密 cfg 中的敏感字段。
func (b *secretBox) openSecrets(cfg *Config) error {
	return walkSecrets(cfg, b.open)
}
