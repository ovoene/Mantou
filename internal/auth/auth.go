package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// 常见错误。
var (
	ErrInvalidToken = errors.New("会话令牌无效")
	ErrTokenExpired = errors.New("会话已过期")
	// ErrNoSecret 签名密钥为空。这不是"令牌无效"的一种，而是服务端状态不对：
	// 空密钥下 HMAC-SHA256 退化成一个所有人都能算出来的固定函数，于是任何人都能离线
	// 造出通得过校验的令牌。所以空密钥既不签发也不校验，一律当失败处理（fail closed）。
	//
	// 这道闸的意义在于它不问密钥"为什么"是空的：随机源异常、导入了一份被裁剪过的备份、
	// 有人手改了 config.json、将来某次重构漏了一条赋值路径——所有路径都在这里被挡住，
	// 而不是各自去堵。密钥正常时它的成本是一次字符串长度比较。
	ErrNoSecret = errors.New("会话签名密钥未配置")
)

// MaxPasswordBytes bcrypt 能实际参与计算的口令字节数。
//
// 这不是本项目挑的数字，而是 bcrypt 算法本身的界：超过 72 字节的部分不进哈希，
// 而 golang.org/x/crypto/bcrypt 对超长输入直接返回 ErrPasswordTooLong（早期版本是静默截断，
// 两种行为都不该让调用方去猜）。导出它是为了让上层接口在**收到请求时**就能给出
// 一句说得清的提示，而不是把一个 500「密码处理失败」抛给正在做初始化的用户——
// 那一步卡住就没有下一步了，而错误里看不出问题出在长度上。
const MaxPasswordBytes = 72

// HashPassword 使用 bcrypt 生成密码哈希。
func HashPassword(password string) (string, error) {
	b, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// VerifyPassword 校验明文密码与哈希是否匹配。
func VerifyPassword(hash, password string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
}

// IsHash 判断给定字符串是否已是一个合法的 bcrypt 哈希。
//
// 用途：把「用户刚输入的明文口令」与「配置里已存着的哈希」区分开，
// 从而让同一个字段既能接受表单提交的明文（存前哈希），又能原样回传已存的哈希（不重复哈希）。
// 判定交给 bcrypt.Cost：它会完整校验前缀、代价参数与长度，
// 比自己比对 "$2a$" 前缀更严格——被截断/改过一两个字符的哈希会被判为明文，
// 从而走「当作新口令重新哈希」的路径，而不是留下一个永远也验不过的死哈希。
func IsHash(s string) bool {
	_, err := bcrypt.Cost([]byte(s))
	return err == nil
}

// claims 是会话令牌承载的数据。
type claims struct {
	Sub string `json:"sub"` // 用户名
	Exp int64  `json:"exp"` // 过期时间（Unix 秒）
	Iat int64  `json:"iat"` // 签发时间
	Jti string `json:"jti"` // 随机串，只为让每次签发的令牌互不相同
}

// tokenNonceBytes jti 的随机字节数。它不参与任何校验，只提供唯一性，96 位足够。
const tokenNonceBytes = 12

// MaxTokenTTL 单个会话令牌允许覆盖的最长时间跨度。
//
// 取值与接口层对 Auth.SessionHours 的上限同源（8760 小时 = 365 天，见
// internal/server/api_overview.go 的 handleUpdateSettings 对 sessionHours 的区间判断，
// 以及 web/src/views/Settings.vue 里那个 :max="8760"）。**必须不小于那个上限**：
// 小于就意味着面板允许保存的配置能签发出连自己都验不过的令牌，用户一登录就被踢，
// 而两处限制分别在两个包里、谁都不会报错。
//
// 加这道界是为了让「令牌自称的有效期」不再是无界的：签名密钥泄露的场景下它限制不了什么
// （有密钥就能重签），它限制的是**时钟出过错**的那段历史——机器时间曾被设到很远的未来时
// 签发的令牌，时间校正回来后按原逻辑还能再用上十几年。
const MaxTokenTTL = 8760 * time.Hour

// IssueToken 使用 secret 为 username 签发一个有效期 ttl 的会话令牌。
//
// jti 是必须的。签发时间只精确到秒，若令牌里只有 sub/exp/iat，同一秒内为同一用户签发的
// 两个令牌会**逐字节相同**——而服务端会话表以令牌的哈希为键，于是这两次登录会共用一条记录：
// 一边点退出，另一边跟着掉线；"关闭最后一个标签"的信标也会连带把另一边标成待删除。
// 更要紧的是它让"改密码时给当前浏览器换一条新会话"变成空操作，旧令牌的副本照旧有效。
//
// username 为空不签发：令牌里的 sub 是上层唯一能拿来比对账户的东西（见
// internal/server/middleware.go 的 authRequired），空 sub 的令牌不指向任何账户，
// 签出来只可能是调用方出了错。校验侧同样拒空（见 ParseToken），两侧一致。
//
// ttl 超过 MaxTokenTTL 时**夹到上限**而不是报错：这条路径上的 ttl 来自
// Auth.SessionHours，而那个值可以由手改的 config.json 提供（加载期不夹）。报错等于
// 让一份写大了的配置把登录整条堵死；夹住则退化成"最长一年"，用户能登进来再改回去。
func IssueToken(secret, username string, ttl time.Duration) (string, error) {
	if secret == "" {
		return "", ErrNoSecret // 见 ErrNoSecret：空密钥的签名等于没有签名
	}
	if username == "" {
		return "", ErrInvalidToken
	}
	if ttl > MaxTokenTTL {
		ttl = MaxTokenTTL
	}
	nonce := make([]byte, tokenNonceBytes)
	if _, err := rand.Read(nonce); err != nil {
		return "", err // 取不到随机数就不签发，不退回可预测的形式
	}
	now := time.Now()
	c := claims{
		Sub: username,
		Exp: now.Add(ttl).Unix(),
		Iat: now.Unix(),
		Jti: base64.RawURLEncoding.EncodeToString(nonce),
	}
	payload, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	body := base64.RawURLEncoding.EncodeToString(payload)
	sig := sign(secret, body)
	return body + "." + sig, nil
}

// ParseToken 校验令牌签名与有效期，返回其中的用户名。
// jti 不参与校验：它只是签发时掺进去的随机串，升级前签发的令牌没有这个字段也照样能解。
//
// # 为什么签名验过了还要查 claims
//
// 签名保证「这串东西是持有密钥的一方产出的」，不保证「里面的数字讲得通」。
// 而这个函数是整个鉴权链的第一环，它返回的 sub 会被上层直接拿去比对账户名——
// 越靠前的原语越不该把"载荷内容合不合理"留给调用方判断，因为将来新增的调用方
// 会理所当然地认为它已经判过了。下面四条都是纯粹的自洽性检查，不依赖当前时钟：
//
//  1. sub 非空——空 sub 的令牌不指向任何账户。今天不构成越权（authRequired 还要
//     比对 cfg.Auth.Username，而已初始化的实例那个值非空），但那是**别人的**防线。
//  2. iat 必须存在且为正——没有它，下面两条无从判断。历史令牌一律带 iat
//     （IssueToken 从第一版起就在写），因此这条不会把任何在用的会话踢下线。
//  3. exp 不得早于 iat——"签发即过期"的令牌是构造出来的，不是签发出来的。
//  4. exp-iat 不得超过 MaxTokenTTL——给"令牌自称的有效期"加一道硬界。
//
// 第五条要看时钟：exp 距**现在**也不得超过 MaxTokenTTL。它挡的是"签发时机器时间
// 在很远的未来"那种历史（见 MaxTokenTTL 的说明）；代价是系统时间若倒退超过一年，
// 既有会话会一并失效——那是重新登录就能恢复的方向，可以接受。
func ParseToken(secret, token string) (string, error) {
	if secret == "" {
		// 校验侧也要拦。只拦签发是不够的：攻击者手上的令牌不必由本进程签发，
		// 空密钥下他自己就能算出正确签名。
		return "", ErrNoSecret
	}
	parts := strings.SplitN(token, ".", 2)
	if len(parts) != 2 {
		return "", ErrInvalidToken
	}
	body, sig := parts[0], parts[1]
	expected := sign(secret, body)
	if subtle.ConstantTimeCompare([]byte(sig), []byte(expected)) != 1 {
		return "", ErrInvalidToken
	}
	raw, err := base64.RawURLEncoding.DecodeString(body)
	if err != nil {
		return "", ErrInvalidToken
	}
	var c claims
	if err := json.Unmarshal(raw, &c); err != nil {
		return "", ErrInvalidToken
	}
	if c.Sub == "" || c.Iat <= 0 || c.Exp < c.Iat {
		return "", ErrInvalidToken
	}
	maxTTL := int64(MaxTokenTTL / time.Second)
	if c.Exp-c.Iat > maxTTL {
		return "", ErrInvalidToken
	}
	now := time.Now().Unix()
	if now > c.Exp {
		return "", ErrTokenExpired
	}
	// 剩余寿命也要在界内。归到 ErrInvalidToken 而不是 ErrTokenExpired：
	// 这条令牌不是"过期了"，是它自称的到期时刻不可信。
	if c.Exp-now > maxTTL {
		return "", ErrInvalidToken
	}
	return c.Sub, nil
}

// sign 计算 HMAC-SHA256 签名并做 URL-safe base64 编码。
func sign(secret, body string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(body))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}
