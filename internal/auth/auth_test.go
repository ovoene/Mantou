package auth

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// 同一秒内为同一用户签发的令牌必须互不相同。
//
// 令牌里只有 sub/exp/iat 时它们会逐字节相同（三个字段都只到秒），而服务端会话表以
// 令牌的哈希为键：两次登录会共用一条记录，一边退出另一边跟着掉线；更要紧的是
// "改密码时给当前浏览器换一条新会话"会变成空操作，旧令牌的副本照旧有效。
func TestIssueTokenUniquePerCall(t *testing.T) {
	const secret = "test-secret"
	seen := map[string]bool{}
	for i := 0; i < 200; i++ {
		tok, err := IssueToken(secret, "admin", time.Hour)
		if err != nil {
			t.Fatalf("第 %d 次签发失败：%v", i, err)
		}
		if seen[tok] {
			t.Fatalf("第 %d 次签发出了重复的令牌", i)
		}
		seen[tok] = true
	}
	// 200 次全在同一秒内跑完的可能性很高，但不必依赖这一点：重复即失败，与耗时无关。
	if len(seen) != 200 {
		t.Fatalf("应当有 200 个不同的令牌，实际 %d", len(seen))
	}
}

// 令牌照旧能解开，且 sub 正确——加了 jti 不能把解析弄坏。
func TestIssueTokenStillParses(t *testing.T) {
	const secret = "test-secret"
	tok, err := IssueToken(secret, "admin", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	name, err := ParseToken(secret, tok)
	if err != nil {
		t.Fatalf("解析自己签发的令牌失败：%v", err)
	}
	if name != "admin" {
		t.Errorf("用户名应为 admin，实际 %q", name)
	}
	if _, err := ParseToken("another-secret", tok); err == nil {
		t.Error("换一个密钥应当验不过签名")
	}
}

// 升级前签发的令牌（载荷里没有 jti）必须继续能解开，否则升级一次就把所有人踢下线。
func TestParseTokenAcceptsPayloadWithoutJti(t *testing.T) {
	const secret = "test-secret"
	payload := `{"sub":"admin","exp":` + itoa(time.Now().Add(time.Hour).Unix()) + `,"iat":` + itoa(time.Now().Unix()) + `}`
	body := base64.RawURLEncoding.EncodeToString([]byte(payload))
	old := body + "." + sign(secret, body)

	name, err := ParseToken(secret, old)
	if err != nil {
		t.Fatalf("没有 jti 的旧令牌应当仍然可解：%v", err)
	}
	if name != "admin" {
		t.Errorf("用户名应为 admin，实际 %q", name)
	}
}

// 签发出来的令牌里确实带着 jti，且不是空串。
// 若哪天有人把这个字段删了或写成常量，上面那条唯一性测试要跑很多次才可能露出来，
// 这一条直接盯住字段本身。
func TestIssuedTokenCarriesNonEmptyJti(t *testing.T) {
	tok, err := IssueToken("test-secret", "admin", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	body, _, ok := strings.Cut(tok, ".")
	if !ok {
		t.Fatalf("令牌格式不对：%q", tok)
	}
	raw, err := base64.RawURLEncoding.DecodeString(body)
	if err != nil {
		t.Fatalf("载荷不是合法的 base64：%v", err)
	}
	var c claims
	if err := json.Unmarshal(raw, &c); err != nil {
		t.Fatalf("载荷不是合法的 JSON：%v", err)
	}
	if c.Jti == "" {
		t.Error("载荷里必须带 jti，否则同一秒内签发的令牌会撞在一起")
	}
	if n, err := base64.RawURLEncoding.DecodeString(c.Jti); err != nil || len(n) != tokenNonceBytes {
		t.Errorf("jti 应当是 %d 字节的随机串，实际 %q", tokenNonceBytes, c.Jti)
	}
}

// itoa 只为拼旧格式载荷用，避免为此引入 strconv。
func itoa(v int64) string {
	if v == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	return string(buf[i:])
}
