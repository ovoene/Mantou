package auth

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"
	"time"
)

// TestEmptySecretRejected 是 A-1 的回归测试：空签名密钥必须在两侧都被拒。
//
// 起因：config.randomHex 在随机源失败时曾返回空串，而它的调用点之一是 Auth.JWTSecret。
// 空密钥下 hmac.New(sha256.New, nil) 是一个所有人都能复现的固定函数，任何人都可以离线
// 造出通得过校验的令牌。修法有两层：randomHex 不再静默降级（见 config），
// 以及这里——不问密钥为什么是空的，空就一律失败。
func TestEmptySecretRejected(t *testing.T) {
	if _, err := IssueToken("", "admin", time.Hour); !errors.Is(err, ErrNoSecret) {
		t.Errorf("空密钥签发应返回 ErrNoSecret，实际 %v", err)
	}

	// 先用一把正常密钥签出一个真令牌，再把密钥换成空去校验：模拟"密钥丢了"之后
	// 旧令牌仍被递上来的情形，此时也必须失败。
	tok, err := IssueToken("s3cret", "admin", time.Hour)
	if err != nil {
		t.Fatalf("正常签发失败: %v", err)
	}
	if _, err := ParseToken("", tok); !errors.Is(err, ErrNoSecret) {
		t.Errorf("空密钥校验应返回 ErrNoSecret，实际 %v", err)
	}

	// 关键一条：攻击者用空密钥**自签**的令牌同样进不来。这里直接用包内的 sign 复现
	// 「离线伪造」，绕过 IssueToken 的前置校验——旧代码在这条路上会把令牌判为有效。
	now := time.Now()
	payload, err := json.Marshal(claims{Sub: "admin", Exp: now.Add(time.Hour).Unix(), Iat: now.Unix()})
	if err != nil {
		t.Fatalf("构造 payload 失败: %v", err)
	}
	body := base64.RawURLEncoding.EncodeToString(payload)
	forged := body + "." + sign("", body)
	if _, err := ParseToken("", forged); !errors.Is(err, ErrNoSecret) {
		t.Errorf("空密钥自签令牌应被拒，实际 %v", err)
	}
}

// TestNormalSecretStillWorks 确认这道闸没有影响正常路径。
func TestNormalSecretStillWorks(t *testing.T) {
	tok, err := IssueToken("s3cret", "admin", time.Hour)
	if err != nil {
		t.Fatalf("签发失败: %v", err)
	}
	sub, err := ParseToken("s3cret", tok)
	if err != nil {
		t.Fatalf("校验失败: %v", err)
	}
	if sub != "admin" {
		t.Errorf("sub = %q，期望 admin", sub)
	}
	if _, err := ParseToken("other", tok); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("换密钥应判无效，实际 %v", err)
	}
}
