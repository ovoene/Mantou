package cert

import (
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"mantou/internal/logx"
	"mantou/internal/netguard"
)

// ACME 目录的出站也归「内网防护」管（审计 F-01）。
//
// 此前这条出站用的是裸 net.Dialer：同一份配置里 DDNS 取址、计划任务 HTTP 动作、通知推送、
// 更新清单拉取全都经 netguard 约束，只有它不受约束，而自定义 CA 目录是用户可填的任意
// https 地址。填一个内网地址进去，面板就会代为发起请求，由响应差异反推内网存活。
//
// 这一组用例盯三件事：
//
//  1. **开关语义**。防护关闭时行为与从前完全一致——私有 CA 的自建场景照旧可用。
//     这一条比"拦得住"更容易在日后被改坏（顺手把判断改成无条件），所以每个用例都带反面。
//  2. **两层各管一段**。IP 字面量在建连前就拒（acmeDirectoryBlocked），域名留给拨号期的
//     Control 钩子（域名会因 DNS 重绑定在保存与拨号之间变样，提前判没有意义）。
//  3. **代理那一格**。有代理时不挂钩子——挂了两头空：钩子只能校验代理地址，而代理常在
//     127.0.0.1:8080 这类地址上，于是签发会被自己拦下。这是刻意的取舍，不是漏判。

func TestACMEDirectoryBlocked(t *testing.T) {
	cases := []struct {
		name         string
		directoryURL string
		blockPrivate bool
		wantBlocked  bool
	}{
		// —— 防护开启：IP 字面量指向内网 / 保留段，建连前就拒 ——
		{"回环字面量", "https://127.0.0.1/directory", true, true},
		{"回环字面量带端口", "https://127.0.0.1:8443/directory", true, true},
		{"私有段 10/8", "https://10.0.0.5:8443/directory", true, true},
		{"私有段 192.168/16", "https://192.168.1.10/directory", true, true},
		{"链路本地（云元数据端点那一段）", "https://169.254.169.254/directory", true, true},
		{"运营商级 NAT", "https://100.64.0.1/directory", true, true},
		{"IPv6 回环", "https://[::1]/directory", true, true},
		{"IPv4 映射地址", "https://[::ffff:192.168.1.1]/directory", true, true},

		// —— 防护开启：这些不该在这一层拒 ——
		{"公网 IP 字面量", "https://8.8.8.8/directory", true, false},
		{"内置 CA（域名）", letsEncryptDirectoryURL, true, false},
		{
			// 域名一律交给拨号期的钩子：保存那一刻的解析结果不构成运行期保证。
			"内网域名（留给拨号期钩子）", "https://acme.corp.internal/directory", true, false,
		},

		// —— 防护关闭：一律放行，保持开关语义 ——
		{"防护关闭 + 回环", "https://127.0.0.1/directory", false, false},
		{"防护关闭 + 元数据端点", "https://169.254.169.254/directory", false, false},
		{"防护关闭 + 内置 CA", letsEncryptDirectoryURL, false, false},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := acmeDirectoryBlocked(c.directoryURL, c.blockPrivate)
			if (err != nil) != c.wantBlocked {
				t.Fatalf("acmeDirectoryBlocked(%q, %v) = %v，wantBlocked=%v",
					c.directoryURL, c.blockPrivate, err, c.wantBlocked)
			}
			if c.wantBlocked && !errors.Is(err, netguard.ErrBlocked) {
				// 归到 netguard.ErrBlocked 才能让上层按"被防护拦下"统一处理（见 ddns.go:296、app.go:114）。
				t.Fatalf("拦截错误应可用 errors.Is 判成 netguard.ErrBlocked，实际 %v", err)
			}
		})
	}
}

// TestACMEGuardDialDecision 四种组合各走一遍：开关 × 有无代理。
func TestACMEGuardDialDecision(t *testing.T) {
	noProxy := func(*http.Request) (*url.URL, error) { return nil, nil }
	viaProxy := func(*http.Request) (*url.URL, error) {
		return &url.URL{Scheme: "http", Host: "127.0.0.1:8080"}, nil
	}
	proxyErr := func(*http.Request) (*url.URL, error) { return nil, errors.New("坏掉的 proxy 配置") }

	cases := []struct {
		name         string
		blockPrivate bool
		proxy        func(*http.Request) (*url.URL, error)
		wantGuard    bool
		wantProxy    bool // 是否应当返回"因为这个代理才不挂钩子"
	}{
		{"防护关闭 + 无代理：不挂钩子且不告警", false, noProxy, false, false},
		{"防护关闭 + 有代理：不挂钩子且不告警", false, viaProxy, false, false},
		{"防护开启 + 无代理：直连并挂钩子", true, noProxy, true, false},
		{"防护开启 + 有代理：保留代理、不挂钩子、记告警", true, viaProxy, false, true},
		{"防护开启 + 代理探测出错：按无代理处理（往严的那侧倒）", true, proxyErr, true, false},
		{"防护开启 + 探测器为 nil：挂钩子", true, nil, true, false},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			guard, p := acmeGuardDial(letsEncryptDirectoryURL, c.blockPrivate, c.proxy)
			if guard != c.wantGuard {
				t.Errorf("guard = %v，应为 %v", guard, c.wantGuard)
			}
			if (p != nil) != c.wantProxy {
				t.Errorf("viaProxy = %v，wantProxy=%v", p, c.wantProxy)
			}
		})
	}
}

// TestACMETransportBlocksLoopbackDial 端到端一条：防护开启时，指向本机的 ACME 目录连不上。
//
// 前两组测的是决策，这一条测钩子真的挂进了拨号路径——只验函数返回值的话，
// 哪天有人把 dialer.Control 那行删了、决策函数照旧返回 true，前两组仍然全绿。
//
// 用回环地址还有一个好处：http.ProxyFromEnvironment 对回环目标一律不走代理
// （httpproxy 的 NO_PROXY 语义内置了 localhost / 回环），所以这条用例不受运行环境里
// HTTP_PROXY 是否设置的影响。
func TestACMETransportBlocksLoopbackDial(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	i := &acmeIssuer{log: logx.New(logx.Options{})}

	// 防护开启：这一拨号必须被 netguard 的钩子拦下。
	guarded := i.newACMETransport(srv.URL, true)
	defer guarded.CloseIdleConnections()
	resp, err := (&http.Client{Transport: guarded}).Get(srv.URL)
	if err == nil {
		resp.Body.Close()
		t.Fatalf("防护开启时连到本机 %s 竟然成功了", srv.URL)
	}
	if !errors.Is(err, netguard.ErrBlocked) {
		t.Fatalf("应被 netguard 拦下（errors.Is ErrBlocked），实际 %v", err)
	}

	// 防护关闭：同一地址必须连得通，否则这道修复把私有 CA 的自建场景一起打死了。
	plain := i.newACMETransport(srv.URL, false)
	defer plain.CloseIdleConnections()
	resp2, err := (&http.Client{Transport: plain}).Get(srv.URL)
	if err != nil {
		t.Fatalf("防护关闭时应能连到本机 %s，实际 %v", srv.URL, err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("状态码应为 200，实际 %d", resp2.StatusCode)
	}
}

// TestACMETransportKeepsTunedParams 那组超时/HTTP2 参数不能在这次改动里丢掉。
//
// 它们各自解决过一个真实故障：没有它们，「CA 不可达」会挂到整体 ctx（最长 30 分钟）
// 才失败、表现为证书永久卡在「正在签发」；ForceAttemptHTTP2=false 则是为了不复用被 CA
// 单方关闭的空闲 HTTP/2 连接。这也正是**不能**改用 netguard.HTTPClient 的原因——
// 那份共享 Transport 没有这几项。
func TestACMETransportKeepsTunedParams(t *testing.T) {
	i := &acmeIssuer{log: logx.New(logx.Options{})}
	for _, blockPrivate := range []bool{false, true} {
		tr := i.newACMETransport(letsEncryptDirectoryURL, blockPrivate)
		tr.CloseIdleConnections()
		if tr.ForceAttemptHTTP2 {
			t.Errorf("blockPrivate=%v：ForceAttemptHTTP2 应为 false", blockPrivate)
		}
		if tr.ResponseHeaderTimeout == 0 || tr.TLSHandshakeTimeout == 0 || tr.IdleConnTimeout == 0 {
			t.Errorf("blockPrivate=%v：超时参数不应为零值（%+v）", blockPrivate, tr)
		}
		if tr.DialContext == nil {
			t.Errorf("blockPrivate=%v：DialContext 未设置", blockPrivate)
		}
		// 代理支持必须保留：只有代理能出网的部署里，去掉它签发会直接失败。
		if tr.Proxy == nil {
			t.Errorf("blockPrivate=%v：Proxy 不应为 nil", blockPrivate)
		}
	}
}

// TestACMEDirectoryBlockedRejectsUnparsableURL 地址解析不了时报错而不是静默放行。
func TestACMEDirectoryBlockedRejectsUnparsableURL(t *testing.T) {
	if err := acmeDirectoryBlocked("https://[::1", true); err == nil {
		t.Fatal("无法解析的目录地址应当报错")
	}
	// 防护关闭时这条判定整个不生效，坏地址交给后面的 Transport 自己失败。
	if err := acmeDirectoryBlocked("https://[::1", false); err != nil {
		t.Fatalf("防护关闭时不应在这里报错，实际 %v", err)
	}
}

// TestACMEDirectoryBlockedMatchesNetguard 判定口径与 netguard 完全一致。
//
// 这条防的是"两份地址表各自演化"：acmeDirectoryBlocked 若哪天改成自己维护一份网段清单，
// 就会和 DDNS / 通知 / 计划任务那几条出站给出不同的答案。
func TestACMEDirectoryBlockedMatchesNetguard(t *testing.T) {
	for _, host := range []string{
		"127.0.0.1", "10.1.2.3", "172.16.0.1", "192.168.0.1", "169.254.169.254",
		"100.64.0.1", "192.0.0.1", "198.18.0.1", "240.0.0.1", "8.8.8.8", "1.1.1.1",
		"[::1]", "[fe80::1]", "[2001:db8::1]", "[64:ff9b::8.8.8.8]", "[2606:4700::1111]",
	} {
		t.Run(host, func(t *testing.T) {
			raw := "https://" + host + "/directory"
			u, err := url.Parse(raw)
			if err != nil {
				t.Fatal(err)
			}
			want := netguard.IsPrivateOrReserved(net.ParseIP(u.Hostname()))
			got := acmeDirectoryBlocked(raw, true) != nil
			if got != want {
				t.Fatalf("acmeDirectoryBlocked 判 %v，netguard.IsPrivateOrReserved 判 %v", got, want)
			}
		})
	}
}
