package cert

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"
	"unicode"

	"golang.org/x/crypto/acme"
	"golang.org/x/net/publicsuffix"

	"mantou/internal/config"
	"mantou/internal/dnsprovider"
	"mantou/internal/logx"
	"mantou/internal/netguard"
)

// acmeIssuer 基于 golang.org/x/crypto/acme 实现 ACME 证书自动签发。
// 仅支持 DNS-01 验证：通过内置的 DNS 服务商（见 internal/dnsprovider）写入
// _acme-challenge TXT 记录完成域名所有权证明，因此天然支持通配符证书。
type acmeIssuer struct {
	cfgMgr ConfigWriter
	log    *logx.Logger
}

// NewACMEIssuer 创建 ACME 签发器，可通过 Module.SetIssuer 注入。
func NewACMEIssuer(cfgMgr ConfigWriter, log *logx.Logger) Issuer {
	return &acmeIssuer{cfgMgr: cfgMgr, log: log}
}

const (
	acmePropagationDelay   = 5 * time.Second  // 首次查询前的传播等待
	acmePropagationTimeout = 3 * time.Minute  // TXT 传播等待上限
	acmeOrderReadyTimeout  = 60 * time.Second // 等待订单就绪上限
	acmeTXTTTL             = 120              // 验证 TXT 记录 TTL（秒）
	acmeStepTimeout        = 60 * time.Second // 单个 ACME 网络调用（注册/建订单/提交/签发）独立截止，避免某一步挂死
	acmeAuthzTimeout       = 2 * time.Minute  // 等待 CA 授权（DNS-01 验证）上限，允许较慢但合法的传播

	// 以下三项服务于「直查权威 NS 做传播预检」（见 waitTXT）。
	acmeNSQueryTimeout    = 8 * time.Second // 单次 NS / TXT 查询上限
	acmeNSDialTimeout     = 5 * time.Second // 连到权威 NS 的拨号上限
	acmeMaxZoneCandidates = 6               // 自下而上寻找区名时的最大尝试层数，防止超长域名放大查询次数
)

// letsEncryptDirectoryURL 默认 CA（Let's Encrypt 生产环境）目录地址。
const letsEncryptDirectoryURL = "https://acme-v02.api.letsencrypt.org/directory"

// caDirectoryURL 将账户 CA 标识映射为 ACME 目录地址；认不出来的一律返回空串，
// 由调用方给出明确错误（见 precheckIssue 与 setupACME）。
//
// 只接受 https:// 前缀是安全要求，不是洁癖：ACME 目录决定了「向谁申请证书、
// 把 DNS 验证凭据交给谁」，若允许 http://，任何能改写明文流量的中间人都可以把签发
// 引导到自己的 CA 并取得可用于该域名的证书。
//
// **认不出来时不回落到默认 CA**，包括漏写协议（acme.corp.internal/directory）和
// 内置名字打错（letsencryp）这两种。回落的后果不是"少了个提示"：用户以为在用自己的
// 私有 CA，实际上域名清单和账户密钥都发给了 Let's Encrypt，而且它还真能签出证书来
// ——整件事从头到尾没有一处看起来不对，直到有人去查签发记录。
// 面板的 CA 下拉框只给三个内置值，所以走到这里的自定义地址来自手改 config.json
// 或直接调接口，也就是最可能带着笔误的两条路。
func caDirectoryURL(ca string) string {
	ca = strings.TrimSpace(ca)
	switch ca {
	case "letsencrypt", "":
		return letsEncryptDirectoryURL
	case "letsencrypt-staging":
		return "https://acme-staging-v02.api.letsencrypt.org/directory"
	case "zerossl":
		return "https://acme.zerossl.com/v2/DV90"
	case "buypass":
		return "https://api.buypass.com/acme/directory"
	default:
		// 协议名按 RFC 3986 不区分大小写，url.Parse 也会把它归一化成小写，
		// 所以 HTTPS:// 照收——否则一个大写就把地址推进下面的拒绝分支。
		if len(ca) >= 8 && strings.EqualFold(ca[:8], "https://") {
			return ca
		}
		return "" // 明文目录、漏写协议、名字打错：全部拒绝
	}
}

// unsupportedCAMsg caDirectoryURL 返回空串时给用户看的那句话。
//
// 两个调用点共用一份文本：这句话要同时覆盖三种成因（漏写协议、写了 http://、
// 内置名字打错），各自编一句的话，用户在预检和签发两条路上会看到不一样的解释。
// 刻意把可选值列出来——报错时最有用的信息是"那我该填什么"。
func unsupportedCAMsg(ca string) string {
	return fmt.Sprintf("账户 CA %q 无法识别：内置可选 letsencrypt / letsencrypt-staging / zerossl / buypass，"+
		"自定义 ACME 目录必须以 https:// 开头（明文目录会让中间人把签发引导到自己的 CA）", ca)
}

// ACME 目录的出站也归「内网防护」管（审计 F-01）。
//
// # 为什么这条出站需要管
//
// 自定义 CA 目录是用户可填的任意 https 地址（见 caDirectoryURL），而它此前用的是裸
// net.Dialer——同一份配置里 DDNS 取址、计划任务 HTTP 动作、通知推送、更新清单拉取
// 全都经 netguard 约束，只有它不受约束。填一个内网地址进去，面板就会代为发起请求，
// 由响应差异（连得上 / 证书报错 / 超时）反推内网存活与端口开放，并把域名清单送出去。
//
// 影响面比通用 SSRF 小：只能 https（元数据端点那类明文地址够不着）、要有能通过校验的
// TLS 证书、只会讲 ACME 协议、且只有管理员能配。所以这里做的是**把这条出站并回既有开关**，
// 不是新加一道默认拦截——默认关闭时行为与从前完全一致（私有 CA 的自建场景照旧可用）。
//
// # 为什么不直接换成 netguard.HTTPClient
//
// 那条路在防护开启时刻意禁用代理（理由见 netguard.newTransport），换过去会让
// 「只有代理能出网」的部署里签发直接失败；而它共享的 Transport 也丢掉了这里为
// 「CA 不可达要快速失败」「不复用被 CA 单方关闭的 HTTP/2 连接」调出来的那组参数。
// 所以只借它的 Control 钩子（netguard.DialControl），Transport 仍是本地这一份。

// acmeDirectoryBlocked 在建连之前先看目录地址本身：主机是 IP 字面量且落在内网 / 保留段
// 时直接拒绝，并给出一句能照着改的错误。
//
// 与 Control 钩子不重复，它补的正是钩子够不到的那一格——经代理转发时钩子只看得到代理
// 地址（见 newACMETransport），而 IP 字面量恰好是唯一在拨号那一刻不会变样的写法
// （域名会：DNS 重绑定），因此在这里判是有效的。blockPrivate 为假时不判，保持开关语义。
func acmeDirectoryBlocked(directoryURL string, blockPrivate bool) error {
	if !blockPrivate {
		return nil
	}
	u, err := url.Parse(directoryURL)
	if err != nil {
		return fmt.Errorf("ACME 目录地址无法解析: %w", err)
	}
	ip := net.ParseIP(u.Hostname())
	if ip == nil {
		return nil // 域名交给拨号期的 Control 钩子
	}
	if netguard.IsPrivateOrReserved(ip) {
		return fmt.Errorf("%w：ACME 目录 %s 指向内网 / 保留地址 %s。"+
			"如确需向内网私有 CA 申请证书，请在「设置 → 安全」关闭内网防护",
			netguard.ErrBlocked, u.Host, ip.String())
	}
	return nil
}

// newACMETransport 构造本次签发专用的 Transport。
//
// 超时与 HTTP/2 那几项的由来：默认情况下 acme.Client 复用 http.DefaultClient，而它没有
// 连接/头部超时，一旦 ACME 目录或订单接口不可达（网络不通、被防火墙拦截、Docker 桌面
// 环境无出网等），请求会一直挂到整体 ctx（最长 30 分钟）才失败，表现为证书永久卡在
// 「正在签发」。这里把连接/TLS/响应头超时收敛到数十秒，让「CA 不可达」类故障快速以明确
// 错误返回。不强制 HTTP/2 则是为了规避实测中「Register 成功但 AuthorizeOrder 挂死」的
// 差分现象：极可能是复用了被 CA 单方关闭的空闲 HTTP/2 连接（服务端关闭后客户端仍在其上
// 发流，直到超时），改走 HTTP/1.1 后每请求的连接探测更可靠。
//
// 内网防护开启时二者只能取一个（原因见 netguard.DialControl）：
//
//   - 该地址没有代理 → 直连 + 挂 Control 钩子，拨号期逐个 IP 校验，重定向与
//     「域名解析到内网」同样拦得住；
//   - 该地址有代理 → 保留代理、不挂钩子。挂了反而两头空：钩子只能校验代理地址，
//     而代理常部署在 127.0.0.1:8080 这类地址上，于是这一拨号会被自己拦下、签发直接失败。
//     此时出网策略点是代理本身，面板记一条告警说明这次防护没生效在哪。
func (i *acmeIssuer) newACMETransport(directoryURL string, blockPrivate bool) *http.Transport {
	dialer := &net.Dialer{Timeout: 15 * time.Second, KeepAlive: 30 * time.Second}
	tr := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		ForceAttemptHTTP2:     false,
		MaxIdleConns:          100,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   15 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
	guard, viaProxy := acmeGuardDial(directoryURL, blockPrivate, http.ProxyFromEnvironment)
	if guard {
		dialer.Control = netguard.DialControl
	} else if viaProxy != nil && i.log != nil {
		i.log.Warn("内网防护对本次 ACME 签发不生效：该目录地址经代理出网，拨号目标是代理而非 CA",
			"directory", directoryURL, "proxy", viaProxy.Host)
	}
	tr.DialContext = dialer.DialContext
	return tr
}

// acmeGuardDial 决定本次 ACME 出站是否挂内网防护钩子。
//
// 返回 guard=false 时，第二个返回值给出"是因为要经这个代理出网"——调用方据此记告警；
// 为 nil 则表示防护本就没开，那是正常状态，不必吵。
//
// 单独拆出来是为了能把四种组合都测到：proxy 探测走的是 http.ProxyFromEnvironment，
// 它在进程内只读一次环境变量（sync.Once），测试里 t.Setenv 改不动它，所以把这个函数
// 依赖的探测器做成参数。
func acmeGuardDial(directoryURL string, blockPrivate bool, proxy func(*http.Request) (*url.URL, error)) (bool, *url.URL) {
	if !blockPrivate {
		return false, nil
	}
	if proxy == nil {
		return true, nil
	}
	u, err := url.Parse(directoryURL)
	if err != nil {
		return true, nil // 地址本身有问题，往严的那侧倒
	}
	proxyURL, err := proxy(&http.Request{URL: u, Host: u.Host})
	if err != nil || proxyURL == nil {
		// 解析失败一律当作"没有代理"：那种情况下 Transport 自己发请求时也会失败，
		// 而这里返回"直连"只会让防护往严的那侧倒。
		return true, nil
	}
	return false, proxyURL
}

// friendlyACMEError 把常见的 ACME 错误类型翻译为更友好的中文提示，便于面板直接展示原因
// （否则用户只能看到裸的 urn:ietf:params:acme:error:xxx 英文串）。仅做前缀补充，原始错误仍随 %w 保留。
func friendlyACMEError(err error, defaultMsg string) string {
	if err == nil {
		return defaultMsg
	}
	msg := err.Error()
	switch {
	case strings.Contains(msg, "rateLimited"):
		return defaultMsg + "（Let's Encrypt 限流：相同域名组合每周最多签发 5 张证书，请等待配额恢复后再试；说明见 letsencrypt.org/docs/rate-limits）"
	case strings.Contains(msg, "badCSR"):
		return defaultMsg + "（CSR 不被 CA 接受，请检查域名配置）"
	case strings.Contains(msg, "dns-01"):
		return defaultMsg + "（DNS-01 验证失败，请检查 TXT 记录与 DNS 服务商凭证）"
	case strings.Contains(msg, "badNonce"):
		return defaultMsg + "（ACME nonce 失效，请重试一次）"
	default:
		return defaultMsg
	}
}

// Issue 完成一次 ACME 签发/续期，返回证书链 PEM 与私钥 PEM。
// progress 可选，用于回报阶段进度（便于前端展示「正在签发」的具体步骤，而不是静止的 running）。
func (i *acmeIssuer) Issue(ctx context.Context, c config.Certificate, account *config.ACMEAccount, dnsProvider string, secrets map[string]string, progress func(string)) (certPEM, keyPEM []byte, err error) {
	report := func(msg string) {
		if progress != nil {
			progress(msg)
		}
	}
	// 规范化域名：拆分逗号/空格分隔的脏数据、去重、校验通配符位置。
	// 例如用户在单个输入框填写 "whicc.top,*.whicc.top"，会被正确拆分为两个独立 identifier。
	domains, err := normalizeDomains(c.Domains)
	if err != nil {
		return nil, nil, err
	}
	// 将规范化结果写回配置，避免逗号拼接等脏数据被反复保存。
	if i.cfgMgr != nil && !sameStrings(c.Domains, domains) {
		id := c.ID
		_ = i.cfgMgr.Update(func(cfg *config.Config) {
			for idx := range cfg.Certs {
				if cfg.Certs[idx].ID == id {
					cfg.Certs[idx].Domains = domains
					return
				}
			}
		})
	}
	prov, err := dnsprovider.Get(dnsProvider)
	if err != nil {
		return nil, nil, fmt.Errorf("获取 DNS 服务商失败: %w", err)
	}
	report(fmt.Sprintf("已加载 DNS 服务商 %q，准备注册 ACME 账户", dnsProvider))

	// 账户私钥：优先加载已有，否则生成并持久化到配置。
	accountKey, err := i.ensureAccountKey(account)
	if err != nil {
		return nil, nil, err
	}

	directoryURL := caDirectoryURL(account.CA)
	if directoryURL == "" {
		return nil, nil, fmt.Errorf("%s", unsupportedCAMsg(account.CA))
	}

	// 内网防护（Settings.Security.BlockPrivateNetwork）——自定义 ACME 目录也是一条
	// 「用户可配置的出站请求」，此前它是唯一绕过这道开关的那条（审计 F-01）。
	blockPrivate := false
	if i.cfgMgr != nil {
		if snap := i.cfgMgr.Snapshot(); snap != nil {
			blockPrivate = snap.Settings.Security.BlockPrivateNetwork
		}
	}
	if err := acmeDirectoryBlocked(directoryURL, blockPrivate); err != nil {
		return nil, nil, err
	}

	acmeTransport := i.newACMETransport(directoryURL, blockPrivate)
	// 这个连接池只服务本次签发。签发完就丢，而丢掉不等于关掉——不主动关，
	// 到 CA 的空闲连接还要挂 30 秒（IdleConnTimeout）。
	defer acmeTransport.CloseIdleConnections()

	client := &acme.Client{
		Key:          accountKey,
		DirectoryURL: directoryURL,
		UserAgent:    "mantou",
		HTTPClient:   &http.Client{Transport: acmeTransport},
	}

	// 注册（或复用已存在的）账户。
	acct := &acme.Account{}
	if account.Email != "" {
		acct.Contact = []string{"mailto:" + account.Email}
	}
	if account.EABKid != "" && account.EABHMAC != "" {
		hmacKey, derr := decodeEABKey(account.EABHMAC)
		if derr != nil {
			return nil, nil, fmt.Errorf("解析 EAB 密钥失败: %w", derr)
		}
		acct.ExternalAccountBinding = &acme.ExternalAccountBinding{KID: account.EABKid, Key: hmacKey}
	}
	report(fmt.Sprintf("正在注册/复用 ACME 账户（CA: %s）…", account.CA))
	regCtx, regCancel := context.WithTimeout(ctx, acmeStepTimeout)
	defer regCancel()
	if _, rerr := client.Register(regCtx, acct, acme.AcceptTOS); rerr != nil && !errors.Is(rerr, acme.ErrAccountAlreadyExists) {
		return nil, nil, fmt.Errorf("ACME 账户注册失败: %w", rerr)
	}
	report("ACME 账户就绪，正在创建证书订单…")

	// 创建订单。
	report(fmt.Sprintf("正在为域名 %v 创建 ACME 订单…", domains))
	ordCtx, ordCancel := context.WithTimeout(ctx, acmeStepTimeout)
	defer ordCancel()
	order, err := client.AuthorizeOrder(ordCtx, acme.DomainIDs(domains...))
	if err != nil {
		return nil, nil, fmt.Errorf("%s: %w", friendlyACMEError(err, "创建 ACME 订单失败"), err)
	}

	// 逐个满足授权（DNS-01），结束后清理 TXT 记录。
	var cleanups []func()
	defer func() {
		for _, fn := range cleanups {
			fn()
		}
	}()

	// solveAuthz 处理单个授权。之所以抽成一次函数调用而不是直接写在 for 里：
	// 函数体内有三处 context.WithTimeout 的 defer cancel()，写在循环里的 defer 要等
	// Issue 整个返回才执行——签发 20 个域名就会同时挂着 60 个未释放的 context 与其内部 timer，
	// 而它们本该在各自那一轮结束时就释放。每轮一次函数调用，defer 的作用域才与逻辑一致。
	solveAuthz := func(authzURL string) error {
		getCtx, getCancel := context.WithTimeout(ctx, acmeStepTimeout)
		authz, aerr := client.GetAuthorization(getCtx, authzURL)
		getCancel()
		if aerr != nil {
			return fmt.Errorf("获取授权失败: %w", aerr)
		}
		if authz.Status == acme.StatusValid {
			report(fmt.Sprintf("域名 %s 已验证（复用），跳过", authz.Identifier.Value))
			return nil // 已验证（复用）
		}
		report(fmt.Sprintf("正在验证域名 %s（DNS-01）", authz.Identifier.Value))

		var chal *acme.Challenge
		for _, ch := range authz.Challenges {
			if ch.Type == "dns-01" {
				chal = ch
				break
			}
		}
		if chal == nil {
			return fmt.Errorf("域名 %s 不支持 dns-01 验证", authz.Identifier.Value)
		}

		txtValue, terr := client.DNS01ChallengeRecord(chal.Token)
		if terr != nil {
			return fmt.Errorf("生成 TXT 记录值失败: %w", terr)
		}

		// 通配域 *.example.com 的授权标识为 example.com；统一去除前缀 "*."。
		name := strings.TrimPrefix(authz.Identifier.Value, "*.")
		fqdn := "_acme-challenge." + name
		txtReq := dnsprovider.TXTRequest{
			Zone:    registrableDomain(name),
			FQDN:    fqdn,
			Value:   txtValue,
			TTL:     acmeTXTTTL,
			Secrets: secrets,
		}
		if serr := prov.SetTXT(ctx, txtReq); serr != nil {
			return fmt.Errorf("写入 TXT 记录失败: %w", serr)
		}
		report(fmt.Sprintf("TXT 记录已写入 %s，等待 DNS 传播…", fqdn))
		reqCopy := txtReq
		cleanups = append(cleanups, func() {
			cctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			_ = prov.RemoveTXT(cctx, reqCopy)
		})

		// 等待 DNS 传播（尽力而为，超时后仍继续，由 CA 侧权威查询决定成败）。
		i.waitTXT(ctx, fqdn, txtValue)
		report(fmt.Sprintf("DNS 传播查询完成，正在向 CA 提交 %s 验证…", authz.Identifier.Value))

		accCtx, accCancel := context.WithTimeout(ctx, acmeStepTimeout)
		defer accCancel()
		if _, aerr := client.Accept(accCtx, chal); aerr != nil {
			return fmt.Errorf("提交验证失败: %w", aerr)
		}
		report(fmt.Sprintf("已提交 %s 验证，等待 CA 授权…", authz.Identifier.Value))
		authzCtx, authzCancel := context.WithTimeout(ctx, acmeAuthzTimeout)
		defer authzCancel()
		if _, aerr := client.WaitAuthorization(authzCtx, authz.URI); aerr != nil {
			return fmt.Errorf("域名 %s 验证未通过: %w", authz.Identifier.Value, aerr)
		}
		report(fmt.Sprintf("域名 %s 验证通过", authz.Identifier.Value))
		return nil
	}

	for _, authzURL := range order.AuthzURLs {
		if err := solveAuthz(authzURL); err != nil {
			return nil, nil, err
		}
	}

	// 等待订单进入 ready。
	report("所有域名已验证，等待订单进入 ready…")
	if err := i.waitOrderReady(ctx, client, order.URI); err != nil {
		return nil, nil, err
	}

	// 生成证书私钥与 CSR，向 CA 申请签发。
	report("订单就绪，正在生成 CSR 并向 CA 申请签发…")
	certKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: domains[0]},
		DNSNames: domains,
	}, certKey)
	if err != nil {
		return nil, nil, fmt.Errorf("生成 CSR 失败: %w", err)
	}

	finalCtx, finalCancel := context.WithTimeout(ctx, acmeStepTimeout)
	defer finalCancel()
	der, _, err := client.CreateOrderCert(finalCtx, order.FinalizeURL, csrDER, true)
	if err != nil {
		return nil, nil, fmt.Errorf("签发证书失败: %w", err)
	}
	report("证书已签发，正在编码为 PEM…")

	// 编码证书链与私钥为 PEM。
	var chain bytes.Buffer
	for _, b := range der {
		if err := pem.Encode(&chain, &pem.Block{Type: "CERTIFICATE", Bytes: b}); err != nil {
			return nil, nil, err
		}
	}
	keyDER, err := x509.MarshalECPrivateKey(certKey)
	if err != nil {
		return nil, nil, err
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return chain.Bytes(), keyPEM, nil
}

// ensureAccountKey 加载账户私钥；不存在时生成 ECDSA P-256 并持久化到配置。
func (i *acmeIssuer) ensureAccountKey(account *config.ACMEAccount) (crypto.Signer, error) {
	if strings.TrimSpace(account.PrivateKeyPEM) != "" {
		key, err := parsePrivateKeyPEM([]byte(account.PrivateKeyPEM))
		if err != nil {
			return nil, fmt.Errorf("解析账户私钥失败: %w", err)
		}
		return key, nil
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	pemStr := string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}))
	account.PrivateKeyPEM = pemStr

	if i.cfgMgr != nil && account.ID != "" {
		id := account.ID
		_ = i.cfgMgr.Update(func(c *config.Config) {
			for idx := range c.ACMEAccounts {
				if c.ACMEAccounts[idx].ID == id {
					c.ACMEAccounts[idx].PrivateKeyPEM = pemStr
					return
				}
			}
		})
	}
	return key, nil
}

// waitTXT 等待 _acme-challenge TXT 记录生效（best-effort：等不到也继续，最终成败由 CA 判定）。
//
// 预检**直查该域名的权威 NS**，而不是问本机解析器。本机解析器（容器里通常是 Docker 的
// 127.0.0.11，或宿主/运营商 DNS）有自己的正缓存与负缓存，会造成两类误判：
//
//   - 假阴性：此前查过、缓存了 NXDOMAIN/NODATA，即便权威侧已经生效，本地在负缓存 TTL
//     内仍然查不到 → 白等到超时；
//   - 假阳性：缓存里还是上一轮的旧 TXT 值，被误判成"已生效"就通知 CA 来验，而 CA 从权威 NS
//     读到的是旧值 → 验证失败，并实打实消耗 CA 的失败配额（Let's Encrypt 每小时有上限）。
//
// 取不到可用的权威 NS 时回落到本机解析器（即改造前的行为）：内网 / split-horizon 部署里
// 权威 NS 往往就是那台内网 DNS，此时"问本机"反而是唯一正确的做法。
func (i *acmeIssuer) waitTXT(ctx context.Context, fqdn, expected string) {
	select {
	case <-ctx.Done():
		return
	case <-time.After(acmePropagationDelay):
	}

	resolvers, hosts := i.authoritativeResolvers(ctx, fqdn)
	if len(resolvers) == 0 {
		resolvers = []*net.Resolver{net.DefaultResolver}
		if i.log != nil {
			i.log.Debug("未取到可直查的权威 NS，回落到本机解析器做传播预检", "fqdn", fqdn)
		}
	} else if i.log != nil {
		i.log.Debug("按权威 NS 预检 TXT 传播", "fqdn", fqdn, "ns", strings.Join(hosts, ","))
	}

	deadline := time.Now().Add(acmePropagationTimeout)
	for {
		if txtPropagated(ctx, resolvers, fqdn, expected) {
			return
		}
		if !time.Now().Before(deadline) {
			break
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(5 * time.Second):
		}
	}
	if i.log != nil {
		i.log.Warn("TXT 记录传播等待超时，仍尝试继续验证", "fqdn", fqdn)
	}
}

// txtPropagated 判断 TXT 是否已在**所有**给定解析器上生效。
//
// 要求"全部命中"而不是"任一命中"：CA 验证时会自己挑一台权威 NS 提问，
// 若这里任一命中就放行，等于把成败交给运气——多台 NS 之间的同步延迟正是 DNS-01
// 最常见的失败原因。查询出错（含尚不存在的 NODATA）一律视为未生效，继续等。
func txtPropagated(ctx context.Context, resolvers []*net.Resolver, fqdn, expected string) bool {
	if len(resolvers) == 0 {
		return false
	}
	name := absoluteName(fqdn)
	for _, r := range resolvers {
		qctx, cancel := context.WithTimeout(ctx, acmeNSQueryTimeout)
		vals, err := r.LookupTXT(qctx, name)
		cancel()
		if err != nil || !slices.Contains(vals, expected) {
			return false
		}
	}
	return true
}

// authoritativeResolvers 为域名所在区的每台权威 NS 构造一个"只问它"的解析器，
// 并返回对应的 NS 主机名（仅用于日志）。任何一步失败都返回空列表，由调用方回落。
func (i *acmeIssuer) authoritativeResolvers(ctx context.Context, fqdn string) ([]*net.Resolver, []string) {
	hosts := i.lookupZoneNS(ctx, fqdn)
	if len(hosts) == 0 {
		return nil, nil
	}
	probe := absoluteName(fqdn)
	var (
		resolvers []*net.Resolver
		used      []string
	)
	for _, host := range hosts {
		lctx, cancel := context.WithTimeout(ctx, acmeNSQueryTimeout)
		ips, err := net.DefaultResolver.LookupIPAddr(lctx, host)
		cancel()
		if err != nil {
			continue
		}
		for _, ip := range ips {
			// 跳过指向内网 / 保留地址的 NS：这类地址上的"权威视图"从本机看没有意义，
			// 而 NS 记录是域名所有者可任意指定的，照着它向内网主机发查询等于凭空多一条
			// SSRF 面。命中这一分支通常意味着 split-horizon 部署，回落到本机解析器才正确。
			if netguard.IsPrivateOrReserved(ip.IP) {
				continue
			}
			r := nsResolver(ip.IP)
			// 探一次：目的只是确认这台 NS 从本机可达且会应答。记录尚未生效时
			// 返回的是 NODATA/NXDOMAIN（net.DNSError.IsNotFound），那同样算"可用"。
			pctx, pcancel := context.WithTimeout(ctx, acmeNSQueryTimeout)
			_, perr := r.LookupTXT(pctx, probe)
			pcancel()
			var dnsErr *net.DNSError
			if perr != nil && !(errors.As(perr, &dnsErr) && dnsErr.IsNotFound) {
				continue // 超时 / 拒绝 / 不可达：换下一个地址
			}
			resolvers = append(resolvers, r)
			used = append(used, host)
			break // 每台 NS 只用一个地址
		}
	}
	return resolvers, used
}

// lookupZoneNS 自下而上找到最近的一个"有 NS 记录"的区，并返回它的 NS 主机名。
//
// 从 fqdn 的父域开始逐级向上、以注册域为上界：_acme-challenge 记录可能落在被单独委派的
// 子区里（例如 sub.example.com 交给了另一组 NS），只问注册域的 NS 会拿到 referral 而非记录。
// 这一步刻意用本机解析器：NS 记录长期稳定、TTL 很长，缓存它不会带来 TXT 那样的误判。
func (i *acmeIssuer) lookupZoneNS(ctx context.Context, fqdn string) []string {
	for _, zone := range zoneCandidates(fqdn) {
		qctx, cancel := context.WithTimeout(ctx, acmeNSQueryTimeout)
		nss, err := net.DefaultResolver.LookupNS(qctx, zone)
		cancel()
		if err != nil || len(nss) == 0 {
			continue
		}
		hosts := make([]string, 0, len(nss))
		for _, ns := range nss {
			if host := strings.TrimSuffix(strings.TrimSpace(ns.Host), "."); host != "" {
				hosts = append(hosts, host)
			}
		}
		if len(hosts) > 0 {
			return hosts
		}
	}
	return nil
}

// zoneCandidates 列出可能承载 fqdn 的区名，由最具体到最宽泛，止于注册域。
// 上界取注册域（publicsuffix）是必要的：再往上就是 TLD 甚至根，问它们的 NS 毫无意义。
func zoneCandidates(fqdn string) []string {
	name := strings.TrimSuffix(strings.TrimSpace(fqdn), ".")
	reg := registrableDomain(name)
	if name == "" || reg == "" {
		return nil
	}
	labels := strings.Split(name, ".")
	out := make([]string, 0, len(labels))
	// 从 i=1 起，即跳过 _acme-challenge 这一层，第一个候选就是域名本身。
	for i := 1; i < len(labels) && len(out) < acmeMaxZoneCandidates; i++ {
		cand := strings.Join(labels[i:], ".")
		if len(cand) < len(reg) {
			break // 已越过注册域
		}
		out = append(out, cand)
		if cand == reg {
			break
		}
	}
	return out
}

// nsResolver 构造一个只向指定权威 NS（ip:53）提问的解析器。
//
// PreferGo 是关键：不设它，部分平台会把查询交给系统解析器，自定义 Dial 直接失效，
// 于是又绕回"问本机缓存"的老问题。Dial 忽略上层传入的服务器地址，一律连到这台 NS。
func nsResolver(ip net.IP) *net.Resolver {
	addr := net.JoinHostPort(ip.String(), "53")
	return &net.Resolver{
		PreferGo:     true,
		StrictErrors: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			d := net.Dialer{Timeout: acmeNSDialTimeout}
			return d.DialContext(ctx, network, addr)
		},
	}
}

// absoluteName 返回带根点的绝对域名，避免解析器按 search 域后缀展开查询。
func absoluteName(fqdn string) string {
	name := strings.TrimSpace(fqdn)
	if strings.HasSuffix(name, ".") {
		return name
	}
	return name + "."
}

// errOrderReadyTimeout 「等到超时订单还没就绪」。三处返回它：整体预算用光、
// 睡醒发现预算已经用光、以及单次查询自己超时（见 waitOrderReady 里的说明）。
var errOrderReadyTimeout = errors.New("等待订单就绪超时")

// waitOrderReady 轮询订单直到 ready/valid。
//
// 每次查询都单独设截止，与注册 / 建订单 / 提交验证 / 签发那几步同一口径（见 acmeStepTimeout）。
// 原先这里直接用外层 ctx：整体预算（acmeOrderReadyTimeout）只在**查询返回之后**才检查一次，
// 于是一次挂住的查询能把这个函数拖到远超预算——x/crypto/acme 的客户端在 5xx / badNonce 上
// 会带退避自己重试，那些重试全都算在同一次 GetOrder 里，只受 ctx 约束。
// 表现是证书长时间卡在「正在签发」，最后抛出来的还是外层 ctx 的错（整轮签发最长 30 分钟），
// 而不是「等待订单就绪超时」这句能看懂的话。
func (i *acmeIssuer) waitOrderReady(ctx context.Context, client *acme.Client, orderURL string) error {
	deadline := time.Now().Add(acmeOrderReadyTimeout)
	for {
		// 单次上限再夹一道「到整体截止还剩多久」：这样最后一次查询也不会跑过预算，
		// 超时那一刻报的就是本函数自己的话。
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return errOrderReadyTimeout
		}
		getCtx, getCancel := context.WithTimeout(ctx, min(remaining, acmeStepTimeout))
		order, err := client.GetOrder(getCtx, orderURL)
		getCancel()
		if err != nil {
			// 外层 ctx 结束（用户取消 / 整轮签发超时）按它本来的错返回，别改写成别的意思。
			if ctxErr := ctx.Err(); ctxErr != nil {
				return ctxErr
			}
			// 只是这一次查询自己超时：说成「等待订单就绪超时」，而不是抛一个裸的
			// context deadline exceeded——后者对着面板上的人什么也没说明。
			if errors.Is(err, context.DeadlineExceeded) {
				return errOrderReadyTimeout
			}
			return fmt.Errorf("查询订单状态失败: %w", err)
		}
		switch order.Status {
		case acme.StatusReady, acme.StatusValid:
			return nil
		case acme.StatusInvalid:
			return fmt.Errorf("ACME 订单无效")
		}
		// 这一次已经查到「还没就绪」且预算用光：立刻收摊，不必再睡 3 秒。
		if time.Now().After(deadline) {
			return errOrderReadyTimeout
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(3 * time.Second):
		}
	}
}

// parsePrivateKeyPEM 解析 EC/PKCS8/PKCS1 私钥 PEM。
func parsePrivateKeyPEM(data []byte) (crypto.Signer, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("无效的私钥 PEM")
	}
	switch block.Type {
	case "EC PRIVATE KEY":
		return x509.ParseECPrivateKey(block.Bytes)
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	case "PRIVATE KEY":
		k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		signer, ok := k.(crypto.Signer)
		if !ok {
			return nil, errors.New("不支持的私钥类型")
		}
		return signer, nil
	default:
		return nil, fmt.Errorf("不支持的私钥类型: %s", block.Type)
	}
}

// decodeEABKey 解析 EAB HMAC 密钥（依次尝试多种 base64 变体）。
func decodeEABKey(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	for _, enc := range []*base64.Encoding{
		base64.RawURLEncoding,
		base64.URLEncoding,
		base64.RawStdEncoding,
		base64.StdEncoding,
	} {
		if k, err := enc.DecodeString(s); err == nil {
			return k, nil
		}
	}
	return nil, errors.New("无法解析 base64 EAB 密钥")
}

// registrableDomain 返回 FQDN 的可注册域（Zone），基于公共后缀列表；失败时退回末两段。
func registrableDomain(fqdn string) string {
	fqdn = strings.TrimSuffix(strings.TrimSpace(fqdn), ".")
	if d, err := publicsuffix.EffectiveTLDPlusOne(fqdn); err == nil && d != "" {
		return d
	}
	parts := strings.Split(fqdn, ".")
	if len(parts) <= 2 {
		return fqdn
	}
	return strings.Join(parts[len(parts)-2:], ".")
}

// normalizeDomains 将用户可能以逗号/空格分隔填写的域名规范化为一组独立、去重、合法的 ACME 标识符。
// 这是修复 "invalid wildcard" 报错的关键：形如 "a.com,*.a.com" 的逗号拼接字符串若直接作为单个
// identifier 提交给 CA，会因其内部 "*" 不在首个点之前而被拒绝。
func normalizeDomains(raw []string) ([]string, error) {
	seen := make(map[string]struct{})
	var out []string
	for _, item := range raw {
		// 允许用户在单个输入框中以逗号或空白分隔填写多个域名。
		parts := strings.FieldsFunc(item, func(r rune) bool {
			return r == ',' || unicode.IsSpace(r)
		})
		for _, p := range parts {
			d := strings.ToLower(strings.TrimSpace(p))
			if d == "" {
				continue
			}
			if err := validateACMEDomain(d); err != nil {
				return nil, err
			}
			if _, ok := seen[d]; ok {
				continue
			}
			seen[d] = struct{}{}
			out = append(out, d)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("证书未配置有效域名")
	}
	return out, nil
}

// validateACMEDomain 校验单个 ACME 标识符是否合法：普通域名，或以 "*. " 开头的通配符
// （星号必须位于首个点之前，即整个最左标签只能是 "*"）。
func validateACMEDomain(d string) error {
	if strings.ContainsRune(d, ' ') {
		return fmt.Errorf("域名含非法字符（空格）: %q", d)
	}
	if !strings.Contains(d, "*") {
		if !isValidHostname(d) {
			return fmt.Errorf("域名格式非法: %q", d)
		}
		return nil
	}
	// 通配符：必须恰好为 "*. " 前缀，其后为合法域名（含至少一个点），
	// 不允许 a*.b / a.*.b / *a.b / *.com(裸 TLD) 等非法形式。
	if !strings.HasPrefix(d, "*.") {
		return fmt.Errorf("通配符必须位于域名最左侧（形如 *.example.com）: %q", d)
	}
	base := d[2:]
	if !strings.Contains(base, ".") {
		return fmt.Errorf("通配符域名缺少可注册域: %q", d)
	}
	if strings.Contains(base, "*") {
		return fmt.Errorf("域名中只能有一个通配符且须位于最左侧: %q", d)
	}
	if !isValidHostname(base) {
		return fmt.Errorf("通配符基础域名非法: %q", d)
	}
	return nil
}

// isValidHostname 做轻量主机名校验：仅含小写字母、数字、点与连字符，以字母/数字开头和结尾，且至少含一个点。
func isValidHostname(d string) bool {
	if d == "" || !strings.Contains(d, ".") {
		return false
	}
	if strings.HasPrefix(d, "-") || strings.HasSuffix(d, "-") ||
		strings.HasPrefix(d, ".") || strings.HasSuffix(d, ".") {
		return false
	}
	for _, r := range d {
		if !(r >= 'a' && r <= 'z') && !(r >= '0' && r <= '9') && r != '.' && r != '-' {
			return false
		}
	}
	return true
}

// sameStrings 判断两个字符串切片（忽略顺序）是否包含相同元素。
func sameStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	seen := make(map[string]int, len(a))
	for _, s := range a {
		seen[s]++
	}
	for _, s := range b {
		if seen[s] == 0 {
			return false
		}
		seen[s]--
	}
	return true
}
