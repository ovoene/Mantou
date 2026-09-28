package server

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"strings"
	"testing"

	"mantou/internal/config"
)

// 配了签名公钥之后，上传更新包不再问密码——签名本身即授权（见 handleSelfUpdate）。
// 于是"换公钥"与"打开未验签开关"是同一量级的动作：一条被盗的会话只要能把公钥换成
// 自己的，就能用自己的私钥签包、不问密码地换掉面板二进制。
// 下面这组测试钉住：换成新公钥要当场验密码，而清空、原样保存不打扰人。

// newSignKey 生成一把真实可用的 Ed25519 公钥的 base64 写法。
func newSignKey(t *testing.T) string {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(pub)
}

// TestUpdateSettingsSignKeyChangeRequiresPassword 换成一把新公钥：凭据不对一律 403，且一个字节都不落盘。
func TestUpdateSettingsSignKeyChangeRequiresPassword(t *testing.T) {
	key := newSignKey(t)
	for _, tc := range []struct {
		name  string
		extra string
	}{
		{"不带凭据", ``},
		{"密码不对", `,"account":"` + updateTestUser + `","password":"wrong-pass"`},
		{"账户不对", `,"account":"root","password":"` + updateTestPass + `"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newUpdateGateServer(t, nil)
			w := putSettings(t, s, `{"update":{"signKey":"`+key+`"`+tc.extra+`}}`)
			if w.Code != http.StatusForbidden {
				t.Fatalf("换公钥不验密码就该拒绝，实际 %d：%s", w.Code, w.Body.String())
			}
			if !strings.Contains(w.Body.String(), "签名公钥未修改") {
				t.Fatalf("拒绝原因应指向公钥这一项，实际：%s", w.Body.String())
			}
			if got := s.deps.Config.Snapshot().Update.SignKey; got != "" {
				t.Fatalf("被拒的提交仍把公钥写进了配置：%q", got)
			}
			mustLogEntry(t, s.deps.Log, "更换更新包签名公钥的身份复核失败", "WARN")
		})
	}
}

// TestUpdateSettingsSignKeyReplaceRequiresPassword 已经配着一把公钥时，换成另一把同样要验密码。
// 这正是攻击形态：管理员配好了自己的公钥，被盗的会话想把它换掉。
func TestUpdateSettingsSignKeyReplaceRequiresPassword(t *testing.T) {
	old := newSignKey(t)
	s := newUpdateGateServer(t, func(u *config.UpdateConfig) { u.SignKey = old })

	w := putSettings(t, s, `{"update":{"signKey":"`+newSignKey(t)+`"}}`)
	if w.Code != http.StatusForbidden {
		t.Fatalf("替换已有公钥不验密码就该拒绝，实际 %d：%s", w.Code, w.Body.String())
	}
	if got := s.deps.Config.Snapshot().Update.SignKey; got != old {
		t.Fatalf("被拒的提交改动了公钥：%q，期望仍是 %q", got, old)
	}
}

// TestUpdateSettingsSignKeyChangeWithPassword 凭据正确时公钥落盘，并留一条带指纹的审计记录。
func TestUpdateSettingsSignKeyChangeWithPassword(t *testing.T) {
	s := newUpdateGateServer(t, nil)
	key := newSignKey(t)
	w := putSettings(t, s, `{"update":{"signKey":"`+key+`","account":"`+updateTestUser+
		`","password":"`+updateTestPass+`"}}`)
	if w.Code != http.StatusOK {
		t.Fatalf("凭据正确应当保存成功，实际 %d：%s", w.Code, w.Body.String())
	}
	if got := s.deps.Config.Snapshot().Update.SignKey; got != key {
		t.Fatalf("公钥没存下来：%q", got)
	}
	e := mustLogEntry(t, s.deps.Log, "已更换自更新包签名公钥", "WARN")
	if fp, _ := logFieldStr(e, "fingerprint"); fp != signKeyFingerprint(key) {
		t.Fatalf("审计记录里的指纹是 %q，期望 %q", fp, signKeyFingerprint(key))
	}
}

// TestUpdateSettingsSignKeyNoPasswordWhenUnchangedOrCleared 原样回传与清空都不问密码。
//
// 设置页每次保存「在线更新」这一段都会带上当前公钥；若原样回传也要密码，
// 改一下清单地址就得输一次密码——那会把人逼得干脆不配公钥。清空是收紧方向，同理不拦。
func TestUpdateSettingsSignKeyNoPasswordWhenUnchangedOrCleared(t *testing.T) {
	key := newSignKey(t)

	t.Run("原样回传", func(t *testing.T) {
		s := newUpdateGateServer(t, func(u *config.UpdateConfig) { u.SignKey = key })
		w := putSettings(t, s, `{"update":{"signKey":" `+key+` ","manifestUrl":"https://example.com/v.json"}}`)
		if w.Code != http.StatusOK {
			t.Fatalf("原样回传同一把公钥不该要密码，实际 %d：%s", w.Code, w.Body.String())
		}
		if got := s.deps.Config.Snapshot().Update.ManifestURL; got != "https://example.com/v.json" {
			t.Fatalf("同一次提交里的其它字段没存下来：%q", got)
		}
	})

	t.Run("清空", func(t *testing.T) {
		s := newUpdateGateServer(t, func(u *config.UpdateConfig) { u.SignKey = key })
		w := putSettings(t, s, `{"update":{"signKey":""}}`)
		if w.Code != http.StatusOK {
			t.Fatalf("清空公钥不该要密码，实际 %d：%s", w.Code, w.Body.String())
		}
		if got := s.deps.Config.Snapshot().Update.SignKey; got != "" {
			t.Fatalf("公钥没被清空：%q", got)
		}
	})
}

// TestUpdateSettingsSignKeyRejectsMalformed 格式不对的公钥在保存时就拦下，而不是等到每次上传都失败。
// 校验排在口令复核之前：格式错了不该消耗一次密码失败计数。
func TestUpdateSettingsSignKeyRejectsMalformed(t *testing.T) {
	for _, bad := range []string{"dGVzdA==", "not base64!", base64.StdEncoding.EncodeToString(make([]byte, 31))} {
		s := newUpdateGateServer(t, nil)
		w := putSettings(t, s, `{"update":{"signKey":"`+bad+`","account":"`+updateTestUser+
			`","password":"`+updateTestPass+`"}}`)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("公钥 %q 格式不对应当 400，实际 %d：%s", bad, w.Code, w.Body.String())
		}
		if got := s.deps.Config.Snapshot().Update.SignKey; got != "" {
			t.Fatalf("格式不对的公钥被写进了配置：%q", got)
		}
	}
}
