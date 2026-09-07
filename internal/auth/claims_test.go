package auth

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

// 载荷自洽性校验（审计 F-09）。
//
// 签名验过了不等于载荷讲得通：签名保证「这串东西出自持有密钥的一方」，
// 不保证里面的数字合理。这一组用例全部**自己拿真密钥签名**，因此它们验证的
// 只有 claims 检查那一段——签名那道关卡在每个用例里都是通过的。
//
// 为什么必须钉住：ParseToken 是整个鉴权链的第一环，它返回的 sub 会被
// internal/server/middleware.go 的 authRequired 直接拿去比对账户名。
// 今天那一侧还有一道"必须等于 cfg.Auth.Username"的比对兜着，但那是别人的防线；
// 越靠前的原语越不该把"内容合不合理"留给调用方，因为将来新增的调用方
// 会理所当然地认为它已经判过了。

// signClaims 用真密钥签出一个指定载荷的令牌。
// 刻意走 map 而不是 claims 结构体：要能造出"字段缺失"这种结构体表达不出来的载荷。
func signClaims(secret string, payload map[string]any) string {
	raw, err := json.Marshal(payload)
	if err != nil {
		panic(err)
	}
	body := base64.RawURLEncoding.EncodeToString(raw)
	return body + "." + sign(secret, body)
}

func TestParseTokenRejectsMalformedClaims(t *testing.T) {
	const secret = "test-secret"
	now := time.Now().Unix()
	maxTTL := int64(MaxTokenTTL / time.Second)

	cases := []struct {
		name    string
		payload map[string]any
		want    error
		why     string
	}{
		{
			name:    "sub 为空串",
			payload: map[string]any{"sub": "", "iat": now, "exp": now + 3600},
			want:    ErrInvalidToken,
			why:     "空 sub 不指向任何账户，返回它等于把判断推给调用方",
		},
		{
			name:    "缺 sub 字段",
			payload: map[string]any{"iat": now, "exp": now + 3600},
			want:    ErrInvalidToken,
			why:     "字段缺失与空串同义，两条都要拦",
		},
		{
			name:    "缺 iat 字段",
			payload: map[string]any{"sub": "admin", "exp": now + 3600},
			want:    ErrInvalidToken,
			why:     "没有 iat，有效期跨度就无从判断，MaxTokenTTL 那道界会被绕过",
		},
		{
			name:    "iat 为 0",
			payload: map[string]any{"sub": "admin", "iat": 0, "exp": now + 3600},
			want:    ErrInvalidToken,
			why:     "0 与缺字段在 JSON 解码后不可区分，必须同样处理",
		},
		{
			name:    "iat 为负",
			payload: map[string]any{"sub": "admin", "iat": -1, "exp": now + 3600},
			want:    ErrInvalidToken,
			why:     "负的签发时间不是任何真实时钟能产出的值",
		},
		{
			name:    "exp 早于 iat",
			payload: map[string]any{"sub": "admin", "iat": now, "exp": now - 1},
			want:    ErrInvalidToken,
			why:     "「签发即过期」的令牌是构造出来的，归到 invalid 而不是 expired",
		},
		{
			name:    "有效期跨度超过 MaxTokenTTL",
			payload: map[string]any{"sub": "admin", "iat": now, "exp": now + maxTTL + 1},
			want:    ErrInvalidToken,
			why:     "令牌自称的有效期必须有界，否则一条令牌可以自称有效一百年",
		},
		{
			name: "iat 在很远的未来（时钟曾被设错）",
			// 跨度本身合法（正好一年），但到期时刻距现在远超上限。
			// 这正是 MaxTokenTTL 要挡的那段历史：机器时间曾被设到未来时签发的令牌，
			// 时间校正回来后按旧逻辑还能再用上十几年。
			payload: map[string]any{"sub": "admin", "iat": now + 10*maxTTL, "exp": now + 11*maxTTL},
			want:    ErrInvalidToken,
			why:     "剩余寿命也要在界内，否则跨度检查可以靠把 iat 一起推到未来来绕开",
		},
		{
			name:    "已过期",
			payload: map[string]any{"sub": "admin", "iat": now - 7200, "exp": now - 1},
			want:    ErrTokenExpired,
			why:     "过期仍要报 ErrTokenExpired，不能被新增的检查改掉分类",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tok := signClaims(secret, tc.payload)
			sub, err := ParseToken(secret, tok)
			if !errors.Is(err, tc.want) {
				t.Fatalf("应返回 %v（%s），实际 err=%v sub=%q", tc.want, tc.why, err, sub)
			}
			if sub != "" {
				t.Errorf("被拒的令牌不得返回用户名，实际 %q", sub)
			}
		})
	}
}

// 合法载荷不能被上面那些检查连带拦掉。
// 边界取"正好等于上限"：跨度恰好 MaxTokenTTL 必须放行，否则接口层允许保存的
// sessionHours=8760 一登录就被自己拒掉。
func TestParseTokenAcceptsBoundaryClaims(t *testing.T) {
	const secret = "test-secret"
	now := time.Now().Unix()
	maxTTL := int64(MaxTokenTTL / time.Second)

	cases := []struct {
		name    string
		payload map[string]any
	}{
		{"常规一小时", map[string]any{"sub": "admin", "iat": now, "exp": now + 3600}},
		{"跨度正好是上限", map[string]any{"sub": "admin", "iat": now, "exp": now + maxTTL}},
		{"iat 与 exp 同秒（还没到期）", map[string]any{"sub": "admin", "iat": now, "exp": now}},
		{"iat 略早于现在", map[string]any{"sub": "admin", "iat": now - 60, "exp": now + 3600}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sub, err := ParseToken(secret, signClaims(secret, tc.payload))
			if err != nil {
				t.Fatalf("合法载荷应当通过，实际 %v", err)
			}
			if sub != "admin" {
				t.Errorf("用户名应为 admin，实际 %q", sub)
			}
		})
	}
}

// 签发侧与校验侧必须对同一份配置给出一致的判断。
//
// 这是 MaxTokenTTL 最容易出错的地方：Auth.SessionHours 能由手改的 config.json 提供
// （加载期不夹），若 IssueToken 照原样签、ParseToken 按上限拒，用户会在"登录成功"
// 之后立刻被弹回登录页，而两侧限制分别在两个包里、谁都不报错。
// 因此 IssueToken 必须夹住 ttl——这条用例就是那个夹子的锁。
func TestIssueTokenClampsTTLSoParseAccepts(t *testing.T) {
	const secret = "test-secret"
	for _, ttl := range []time.Duration{MaxTokenTTL, MaxTokenTTL + time.Hour, 100 * MaxTokenTTL} {
		tok, err := IssueToken(secret, "admin", ttl)
		if err != nil {
			t.Fatalf("ttl=%v 应当签发成功（夹到上限而不是报错）：%v", ttl, err)
		}
		sub, err := ParseToken(secret, tok)
		if err != nil {
			t.Fatalf("ttl=%v 签出的令牌自己却验不过：%v", ttl, err)
		}
		if sub != "admin" {
			t.Errorf("ttl=%v：用户名应为 admin，实际 %q", ttl, sub)
		}
	}
}

// 空用户名不签发：签出来的令牌 sub 为空，校验侧一定拒（见上面那组用例），
// 那就不该让它先被签出来在系统里流转一圈。
func TestIssueTokenRejectsEmptyUsername(t *testing.T) {
	if _, err := IssueToken("test-secret", "", time.Hour); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("空用户名应返回 ErrInvalidToken，实际 %v", err)
	}
}

// 签出来的令牌里 exp-iat 确实等于请求的 ttl（夹之后的值），
// 免得将来有人把夹子写成"改 exp 不改 iat"这类只让测试过、语义已经变了的形式。
func TestIssuedTokenSpanMatchesTTL(t *testing.T) {
	tok, err := IssueToken("test-secret", "admin", 2*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	body, _, ok := strings.Cut(tok, ".")
	if !ok {
		t.Fatalf("令牌格式不对：%q", tok)
	}
	raw, err := base64.RawURLEncoding.DecodeString(body)
	if err != nil {
		t.Fatal(err)
	}
	var c claims
	if err := json.Unmarshal(raw, &c); err != nil {
		t.Fatal(err)
	}
	if got := c.Exp - c.Iat; got != int64(2*time.Hour/time.Second) {
		t.Errorf("exp-iat 应为 7200 秒，实际 %d", got)
	}
}
