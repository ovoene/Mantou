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
)

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

// IssueToken 使用 secret 为 username 签发一个有效期 ttl 的会话令牌。
//
// jti 是必须的。签发时间只精确到秒，若令牌里只有 sub/exp/iat，同一秒内为同一用户签发的
// 两个令牌会**逐字节相同**——而服务端会话表以令牌的哈希为键，于是这两次登录会共用一条记录：
// 一边点退出，另一边跟着掉线；"关闭最后一个标签"的信标也会连带把另一边标成待删除。
// 更要紧的是它让"改密码时给当前浏览器换一条新会话"变成空操作，旧令牌的副本照旧有效。
func IssueToken(secret, username string, ttl time.Duration) (string, error) {
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
func ParseToken(secret, token string) (string, error) {
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
	if time.Now().Unix() > c.Exp {
		return "", ErrTokenExpired
	}
	return c.Sub, nil
}

// sign 计算 HMAC-SHA256 签名并做 URL-safe base64 编码。
func sign(secret, body string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(body))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}
