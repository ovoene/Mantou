package server

import "testing"

// Web 服务子项的 TLS 最低版本只接受 1.2 / 1.3（审计 L-06）。
//
// 这条不是"弱加密可选"那种漏洞——服务端本来就是严的，两道一起兜着：保存这一关只放
// 1.2/1.3（validateWebService），加载期又把非 1.3 的写法统一抬到 1.2（config 的 Load，
// 覆盖手改配置、导入的旧备份、版本迁移这三条不走保存校验的路）。
//
// L-06 是界面与后端不一致：下拉框里曾经还留着 TLS 1.0 / TLS 1.1 两项，选了必然拿到
// 一句 400。这组用例把「服务端到底认哪几个值」钉住，好让下拉框日后再有人加项时，
// 先在这里看到该加的到底是什么。
//
// 反向也要钉：空值必须能存。它是界面上的"自动"，normalizeWebService 会把它补成 1.2，
// 一旦这里连空值都拒，"自动"这一项就成了第二个死选项。
func TestValidateWebServiceTLSMinVersionSet(t *testing.T) {
	cases := []struct {
		ver     string
		wantErr bool
	}{
		{"1.2", false},
		{"1.3", false},
		{"1.0", true},
		{"1.1", true},
		{"1.4", true},
		{"tls1.2", true},
		{"", true}, // 直接调 validate 时空值是非法的；界面上的"自动"由 normalize 先补成 1.2
	}
	for _, tc := range cases {
		t.Run("ver="+tc.ver, func(t *testing.T) {
			child := wsChild("c1", true, "site.example.com")
			child.TLSMinVersion = tc.ver
			err := validateWebService(domainCfg(), wsParent("ws1", 8443, child), "")
			if (err != nil) != tc.wantErr {
				t.Fatalf("tlsMinVersion=%q 得到 err=%v，wantErr=%v", tc.ver, err, tc.wantErr)
			}
			if tc.wantErr {
				assertErrContains(t, err, "TLS 最低版本")
			}
		})
	}
}

// TestNormalizeWebServiceFillsAutoTLSVersion 界面上的"自动"（空值）走得通：
// normalizeWebService 把它补成 1.2，随后的校验才过得去。
//
// 与上面那条合起来说明一件事：下拉框里可以有"自动"，但不能有 1.0/1.1。
func TestNormalizeWebServiceFillsAutoTLSVersion(t *testing.T) {
	child := wsChild("c1", true, "site.example.com")
	child.TLSMinVersion = ""
	ws := wsParent("ws1", 8443, child)

	normalizeWebService(&ws)
	if got := ws.Children[0].TLSMinVersion; got != "1.2" {
		t.Fatalf("空值应被补成 1.2，实际 %q", got)
	}
	if err := validateWebService(domainCfg(), ws, ""); err != nil {
		t.Fatalf("补完默认值后应能通过校验：%v", err)
	}
}
