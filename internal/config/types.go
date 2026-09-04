package config

import (
	"unicode"

	"mantou/internal/strutil"
)

// 本文件定义 mantou 的全部配置数据模型（持久化到 data/config.json）。
// 设计原则：
//   1. 所有模块规则都是可独立启停的条目（含 ID、Name、Enabled）。
//   2. 服务商凭证集中存放于 Credentials，其他模块通过 CredentialRef 引用，便于脱敏与复用。
//   3. 结构体尽量使用明确的 JSON tag，字段可平滑扩展。

// MaxStatusMessageLen 回写进配置的运行状态文本（LastStatus / LastResult /
// IssueStatus.Message 等）允许的最大字节数。
//
// 这些字段的内容来自外部：DNS 服务商的 HTTP 响应体、ACME 服务器的问题详情、
// 计划任务里被请求 URL 的返回内容……长度完全不受本程序控制。它们又都是**持久化**字段，
// 于是一条异常响应（例如某服务商在故障时返回整页 HTML 错误页）会被原样写进 config.json 并
// 常驻内存：config.Manager 的每次 Get() 都是一次深拷贝（JSON 往返），而 TLS 握手与
// 面板轮询都会调 Get()，于是这段垃圾文本在每次拷贝时都被重新分配一遍。
// 300 字节足以容纳一句完整的中文错误描述（约 100 个汉字），超出部分对排障没有增量价值——
// 完整错误始终会原样进日志，那里有轮转上限兜底。
const MaxStatusMessageLen = 300

// TruncateStatus 将待持久化的状态文本裁剪到 MaxStatusMessageLen 字节以内。
// 按 rune 边界回退的实现在 strutil.Truncate（原先本仓库有三份各自演化的截断实现，
// 其中两份按字节切、会切断多字节字符，见 strutil 包注释）。
func TruncateStatus(s string) string {
	return strutil.Truncate(s, MaxStatusMessageLen, "…（已截断）")
}

// Config 是配置的根对象。
type Config struct {
	Version      int           `json:"version"`
	Panel        Panel         `json:"panel"`
	Auth         Auth          `json:"auth"`
	Settings     Settings      `json:"settings"`
	Update       UpdateConfig  `json:"update"`
	Credentials  []Credential  `json:"credentials"`
	DDNS         []DDNSRule    `json:"ddns"`
	WebServices  []WebService  `json:"webServices"`
	Forwards     []ForwardRule `json:"forwards"`
	WOLDevices   []WOLDevice   `json:"wolDevices"`
	CronTasks    []CronTask    `json:"cronTasks"`
	Certs        []Certificate `json:"certs"`
	ACMEAccounts []ACMEAccount `json:"acmeAccounts"`

	// ---- 消息路由（Webhook 接收 → 条件匹配 → 模板渲染 → 通知投递）----
	// 拆成四段而不是塞进一个大结构：接收器、通知目标、模板三者是**独立复用**的维度
	//（一个模板可被多个接收器引用，一个通知目标可被多条规则引用），
	// 各自走一套 registerCRUD，前端也是三张独立列表。
	Webhook          WebhookServer     `json:"webhook"`          // 模块级监听与 HTTPS
	WebhookReceivers []WebhookReceiver `json:"webhookReceivers"` // 入站接收器（含规则）
	NotifyTargets    []NotifyTarget    `json:"notifyTargets"`    // 出站通知目标
	MessageTemplates []MessageTemplate `json:"messageTemplates"` // 消息模板库

	// GlobalFirewall 服务防护（连接层）：保护 Web 服务与消息路由的入站连接，
	// 与面板入站防护是两套独立机制（后者只管面板端口，见 PanelFirewall 的说明）。
	// 它是顶层配置而非挂在 Settings 下：它管的是面板之外的业务端口，与「面板设置」语义不同。
	GlobalFirewall GlobalFirewall `json:"globalFirewall"`
}

// UpdateConfig 版本更新相关配置。
//   - ManifestURL：自托管清单地址（返回 JSON，字段 version/url/description）。配置后优先于 GitHub 检测，
//     用于不依赖 GitHub 的私有部署；留空则回退到 GitHub 仓库检测。
//   - ReleaseURL：有新版本时「更新」按钮跳转的下载页地址；为空时回退到清单/GitHub 返回的下载页。
//   - GitHubRepo：用于「关于」页版本检测的 GitHub 仓库（owner/name）。留空默认 ovoene/Mantou；
//     仅在未配置 ManifestURL 时用于检测更新，且可被任意值覆盖（满足「更新源可配置」约束，不写死）。
//   - SignKey：自更新包 Ed25519 公钥（base64 编码的 32 字节）。配置后，上传更新包必须附带
//     同名 .sig 签名文件且验签通过才允许覆盖二进制。
//   - AllowUnsignedUpdate：未配置公钥时是否仍接收更新包。默认 false，即不接收。
//   - About/Description：关于页展示的自定义说明文本 / 从在线清单拉取的程序说明。
type UpdateConfig struct {
	ManifestURL string `json:"manifestUrl"`
	ReleaseURL  string `json:"releaseUrl"`
	GitHubRepo  string `json:"githubRepo"`
	// SignKey 可选：自更新包 Ed25519 公钥（base64 编码的 32 字节）。配置后，上传更新包必须附带
	// 同名 .sig 签名文件且验签通过才允许覆盖二进制。
	SignKey string `json:"signKey"`
	// AllowUnsignedUpdate 公钥留空时是否仍接收更新包。
	//
	// 默认 false（零值），也就是说不填公钥就传不上更新包。这一项的存在是因为
	// 上传更新包等于让面板执行一个新二进制：公钥留空又照收的话，一个被盗的会话
	// 就能把机器上的程序换掉，而这条路径不需要用户有 shell。
	//
	// 又不能直接把没公钥的情况一禁了之：自己签一份 tar.gz 不是这个项目对用户的要求，
	// 于是留这个开关——想跳过验签，先自己在设置里打开，别人替你打不开。
	AllowUnsignedUpdate bool `json:"allowUnsignedUpdate"`

	About       string `json:"about"`
	Description string `json:"description"`
}

// Panel 面板服务自身的监听与 HTTPS 配置。
type Panel struct {
	Listen   string     `json:"listen"`   // 监听地址；固定 0.0.0.0（不在设置 UI 暴露）
	Port     int        `json:"port"`     // 监听端口（设置中可改，重启生效）
	BasePath string     `json:"basePath"` // 访问路径前缀，如 /mantou（设置中可改，重启生效）
	HTTPS    PanelHTTPS `json:"https"`    // 面板 HTTPS
}

// PanelHTTPS 面板 HTTPS 设置。
type PanelHTTPS struct {
	Enabled      bool     `json:"enabled"`
	CertID       string   `json:"certId"`
	Domain       string   `json:"domain"`
	AllowedHosts []string `json:"allowedHosts,omitempty"`
}

// DefaultSessionIdleMinutes 是「闲置超时」的默认值（分钟）。
//
// 这个值决定的是：浏览器崩溃/强杀/断电时，关闭信标根本没能发出去，那条会话要挂多久才作废。
//
// 取 30 而不是更短，是因为面板并非每个页面都有后台轮询（总览、证书、Web 服务、
// 消息路由、网络唤醒有，设置页与日志页没有），而有轮询的页面在标签切到后台时会
// 主动停掉它（省上行带宽）。也就是说「窗口开着但这段时间一个请求都没发出去」是
// 真会发生的：停在设置页慢慢填参数、或把面板切到后台去干别的。阈值压得太短，
// 这两种情况回来就得重新登录，设置页里没保存的内容也一起丢了。
// 想更严就到设置页把它调小；填 0 则完全不启用。
const DefaultSessionIdleMinutes = 30

// Auth 登录鉴权配置。
type Auth struct {
	Username     string `json:"username"`
	PasswordHash string `json:"passwordHash"` // bcrypt
	// SessionHours 是令牌有效时长（小时），从登录那一刻起算的**绝对**上限，
	// 中途再怎么活跃都不会延长；到点必须重新登录。
	SessionHours int `json:"sessionHours"`
	// SessionIdleMinutes 是闲置超时（分钟）：从**最后一次收到该会话的请求**起算，
	// 每来一个请求就归零重算。0 表示不启用。
	//
	// 它与 SessionHours 不重复，两者约束的不是同一件事：前者管「一个会话最长能活多久」，
	// 后者管「面板多久联系不上你，就认定你已经不在了」。因为闲置超时会被活跃请求
	// 不断推后，把它压短对正常使用零打扰；而把 SessionHours 压短等于按固定钟点
	// 反复把正在操作的人踢下线。
	//
	// 用途是给「关闭最后一个面板窗口即注销」兜底：正常关窗口走的是前端信标
	// + 服务端宽限那条路（见 server 包的 sessionGrace），几秒内即失效；只有信标
	// 根本发不出去的情况（崩溃、强杀、断电、拔网线）才轮到这个闲置超时收尾。
	SessionIdleMinutes int    `json:"sessionIdleMinutes"`
	JWTSecret          string `json:"jwtSecret"`        // 会话签名密钥（首次启动随机生成）
	TwoFA              TwoFA  `json:"twoFA"`            // 预留 TOTP 二次验证
	Initialized        bool   `json:"initialized"`      // 是否已完成初始化向导
	LoginMaxFails      int    `json:"loginMaxFails"`    // 登录失败次数上限；达到后锁定账户（≤0 表示不限制）
	LoginLockMinutes   int    `json:"loginLockMinutes"` // 锁定持续时间（分钟），到期自动解锁
}

// TwoFA 预留的 TOTP 配置（本期不实现界面）。
type TwoFA struct {
	Enabled bool   `json:"enabled"`
	Secret  string `json:"secret,omitempty"`
}

// Settings 全局设置。
type Settings struct {
	Language   string        `json:"language"` // zh-CN / en-US
	Log        LogConfig     `json:"log"`
	Appearance Appearance    `json:"appearance"`
	Notify     Notify        `json:"notify"`
	Security   Security      `json:"security"`
	Restart    RestartPolicy `json:"restart"` // 定时重启
}

// RestartPolicy 定时重启：到点让整个进程重启一次。
//
// 三种模式对应界面上的三个选项，每种只用自己那一组字段，互不干扰：
//   - weekly：每周固定的星期几（Weekdays，0=周日）
//   - dates：在日历上挑出具体日期（Dates，YYYY-MM-DD；过去的日期不再触发）
//   - interval：自 StartDate 起每隔 EveryDays 天
//
// 三种都只精确到 Hour:Minute（不设秒）——重启是分钟级的事件，秒只会带来"到底算不算同一次"
// 的歧义。真正的触发允许比设定时刻晚几十秒（见 restart.Scheduler 的检查间隔）。
type RestartPolicy struct {
	Enabled   bool     `json:"enabled"`
	Mode      string   `json:"mode"`      // weekly / dates / interval
	Weekdays  []int    `json:"weekdays"`  // mode=weekly：0-6（0=周日）
	Dates     []string `json:"dates"`     // mode=dates：YYYY-MM-DD（本地时区）
	EveryDays int      `json:"everyDays"` // mode=interval：间隔天数
	StartDate string   `json:"startDate"` // mode=interval：起算日 YYYY-MM-DD（本地时区）
	Hour      int      `json:"hour"`      // 0-23
	Minute    int      `json:"minute"`    // 0-59

	// LastRunAt 上一次由定时重启触发的时间（Unix 秒）。
	//
	// 它是**配置字段而不是运行态**，这一点是刻意的：运行态走 5 秒合并窗口落盘，
	// 而定时重启会在写完之后立刻结束进程——赶不上那个窗口就等于没写。
	// 一旦没写，新进程起来后看到的仍然是"这一次还没跑过"，于是再重启一次，成为重启循环。
	// 因此它必须走 Update 同步落盘。写放大不必担心：每触发一次才写一次。
	LastRunAt int64 `json:"lastRunAt,omitempty"`
}

// Security 安全相关设置。
type Security struct {
	// BlockPrivateNetwork 内网防护开关。开启后，由用户自定义目标的出站请求在目标解析到
	// 内网 / 保留地址时会被拒绝，用于降低服务端被诱导访问内部网络的风险。
	//
	// 适用范围（四项，这份清单是唯一的出处，前端提示文案与实现都照它写，加一条出站路径就要同步这里）：
	//   - 动态域名「从 URL 取址」
	//   - 计划任务「HTTP 请求」动作
	//   - 消息目标发送（webhook / 钉钉 / 企业微信 / Bark…）
	//   - 在线更新的清单地址拉取
	//
	// 不在范围内的出站各有理由，不是漏项：DNS 服务商 API 与 ACME 目录的地址不由用户自由指定，
	// 反向代理转发到内网上游本身就是那个功能要做的事。
	//
	// 默认关闭，以兼容目标本就位于内网的自建取址 / 回调场景。
	BlockPrivateNetwork bool `json:"blockPrivateNetwork"`

	// Firewall 面板入站防护。与 BlockPrivateNetwork 正好是相反的两个方向：
	// 那个管「本机能往哪儿发」，这个管「谁能连进面板」。
	Firewall PanelFirewall `json:"firewall"`
}

// 面板入站防护的取值边界。数字都写成常量，是因为它们要在三处保持一致：
// normalizePanelFirewall 的夹取、API 层的入参校验、前端输入框的 min/max。
const (
	// MaxFirewallIPs 单张名单（允许 / 拒绝各一张）最多多少条。
	// 这是一条内存与解析成本的护栏：名单在每次配置变更时全量重建，匹配又在请求路径上。
	// 一条「a-b」范围经 ipx.ParseCIDRs 会分解成覆盖整段的 CIDR 块（IPv4 最多 62 块、
	// IPv6 最多 254 块），因此 256 条全写成范围的最坏情况也只有万级条目。
	MaxFirewallIPs = 256
	// DefaultFirewallRateLimit 每个来源 IP 每秒允许的请求数。
	//
	// 60 是照着「面板正常使用」定的：首屏会并发拉十来个接口，仪表盘还有若干秒级轮询，
	// 突发几十次很常见；令牌桶按秒补充，持续 60 QPS 的正常人类操作不存在。
	DefaultFirewallRateLimit = 60
	// MaxFirewallRateLimit 每秒请求数上限。10000 远超任何面板的真实用量，
	// 设上限只是为了让「限速」不会被填成一个溢出后变负数的值。
	MaxFirewallRateLimit = 10000
	// DefaultFirewallAutoBanThreshold 触发自动封禁所需的「超限次数」。
	//
	// 计的是被限速拦下的次数，不是请求总数：正常客户端偶尔撞一两次上限很常见
	// （刷新过猛、浏览器并发预取），20 次意味着对方在持续超速而不是抖了一下。
	DefaultFirewallAutoBanThreshold = 20
	// MaxFirewallAutoBanThreshold 超限次数阈值上限。
	MaxFirewallAutoBanThreshold = 100000
	// DefaultFirewallAutoBanMinutes 自动封禁时长（分钟）。
	DefaultFirewallAutoBanMinutes = 60
	// MaxFirewallAutoBanMinutes 自动封禁时长上限，30 天。
	//
	// 不提供「永久」：自动封禁是靠机器判断下的手，判错的代价是把人关在门外，
	// 而这道门后面没有别的入口。有限期意味着任何误判都会自己愈合。
	// 真要永久封，请写进拒绝名单——那是人做的决定。
	MaxFirewallAutoBanMinutes = 43200
)

// 服务防护（连接层）的取值边界。与面板入站防护同口径：边界必须在三处保持一致——
// normalizeGlobalFirewall 的夹取、API 层的入参校验、前端输入框的 min/max 共用同一份数。
const (
	// GlobalFirewallMaxIPs 单张名单（允许 / 拒绝各一张）最多多少条。
	// 与面板入站防护同一护栏（见 MaxFirewallIPs 的说明）：名单每次配置变更全量重建，
	// 一条「a-b」范围在 ipx.ParseCIDRs 里会分解成覆盖整段的一组 CIDR 块。
	//
	// 直接**取自** MaxFirewallIPs 而不是另写一个 256：两张名单都由同一个 normalizeIPList
	// 整理，而它按 MaxFirewallIPs 截断。各写一份字面量的话，改动其中一个就会出现
	// 「校验说 256 条以内合法、整理时截到 200 条」这种静默丢数据。
	GlobalFirewallMaxIPs = MaxFirewallIPs

	// 检测档位。前三个是预设档位：选中哪个，下面那组数值就**由档位决定**，
	// 用户提交的数值一概不作数（规范化会照预设重写，见 normalizeGlobalFirewall）。
	// custom 是唯一让手填数值生效的档位——把"用预设"与"我要自己填"分成两个明确的选择，
	// 而不是靠猜「这组数是不是被人改过」。
	GlobalFirewallLevelLoose    = "loose"    // 宽松
	GlobalFirewallLevelBalanced = "balanced" // 均衡
	GlobalFirewallLevelStrict   = "strict"   // 严格
	GlobalFirewallLevelCustom   = "custom"   // 自定义：数值以用户填的为准

	// 各档位对应的窗口 / 阈值 / 封禁时长（秒、次、分钟）。
	// 三档必须**两两不同**，否则界面上换档位却什么都不变（见 TestGlobalFirewallPresetsDiffer）。
	// 宽松给家用慢速探测留余地，严格压到贴近扫描特征。
	gfwLooseWindowSeconds = 120
	gfwLooseWindowLimit   = 20
	gfwLooseBurstSeconds  = 5
	gfwLooseBurstLimit    = 8
	gfwLooseBanMinutes    = 60

	gfwBalancedWindowSeconds = 60
	gfwBalancedWindowLimit   = 12
	gfwBalancedBurstSeconds  = 3
	gfwBalancedBurstLimit    = 4
	gfwBalancedBanMinutes    = 120

	gfwStrictWindowSeconds = 30
	gfwStrictWindowLimit   = 8
	gfwStrictBurstSeconds  = 2
	gfwStrictBurstLimit    = 3
	gfwStrictBanMinutes    = 360

	// DefaultGlobalFirewallMemoryMB 自动封禁表内存上限（MB）。
	//
	// 默认 5 MB、最大 15 MB：封禁表的键是**攻击者选的**地址，一个 IPv6 /64 就能提供
	// 1.8e19 个来源，无上限等于把内存分配权交给对方（同面板入站防护封禁表的理由，见 config.BanEntriesForMemoryMB）。
	// 它是**每张表**的上限：面板入站防护与服务防护各有一张封禁表，两张都按这一个数换算容量
	// （折算函数见 config.BanEntriesForMemoryMB），最坏情况总占用是它的两倍。只能在此模块设置（见界面说明）。
	DefaultGlobalFirewallMemoryMB = 5
	MaxGlobalFirewallMemoryMB     = 15

	// MaxGlobalFirewallBanMinutes 自动封禁时长上限：7 天（7×24×60）。
	// 与面板同理——不提供「永久」：自动封禁是机器判断，判错代价是把人关在门外，
	// 有限期意味着误判会自己愈合。要永久封就写进拒绝名单（自动封禁页有一键加入的入口）。
	//
	// 从 24 小时放宽到 7 天：一天封顶对"每天换一批地址、一轮扫几个小时"的持续扫描起不到
	// 抑制作用——次日同一批地址又是干净的。7 天仍是有限期，误判照样会自己愈合，
	// 只是愈合周期长了；真要更久就该是一条明确的人工决定（拒绝名单），而不是机器判断。
	MaxGlobalFirewallBanMinutes = 7 * 24 * 60

	// 自定义档位的数值边界。四处必须一致：normalizeGlobalFirewall 的夹取、Valid 的校验、
	// 接口下发给前端的 limits、前端输入框的 min/max。任一处对不上，都会出现
	// 「界面上存得下、存进去被悄悄改成另一个数」。
	MinGlobalFirewallWindowSeconds = 1
	MaxGlobalFirewallWindowSeconds = 3600
	MinGlobalFirewallLimit         = 1
	MaxGlobalFirewallLimit         = 100000
)

// GlobalFirewall 服务防护（连接层）：保护 Web 服务与消息路由的入站连接，
// 与面板入站防护是两套独立机制（后者只管面板端口，见 PanelFirewall 的说明）。
//
// 它在 TCP 建立、TLS 握手之前按来源 IP 行为自动拦截，属于 fail2ban 家族：
// 判定顺序为 拒绝名单 → 局域网/回环豁免 → 允许名单 → 自动封禁 → 放行。
//
// 自动封禁的行为信号来自 TLS 握手失败（"TLS handshake error from <ip>"）：
// 那条日志由 crypto/tls 在握手失败时产出，发生在 HTTP 层之前，任何中间件都看不到，
// 只能从 http.Server.ErrorLog（一个 io.Writer）的写入链上 hook——详见 internal/inboundfw。
//
// 它不是 DDoS 防护：判据是 per-IP，分布式僵尸网络（上万来源、每个发一点点）
// 永远触发不了任何阈值。它也不是包过滤防火墙：不做状态检测、NAT、端口/协议规则。
type GlobalFirewall struct {
	// Enabled 总开关。默认**关闭**（见 defaultGlobalFirewall 的说明）。
	Enabled bool `json:"enabled"`

	// Level 检测档位，是窗口 / 阈值 / 封禁时长的**权威来源**：
	// loose / balanced / strict 三个预设档位下，下面那组数值一律由档位重写；
	// 只有 custom 档位才以用户填的数值为准。空值与认不出的值按 balanced 处理。
	Level string `json:"level"`

	AllowIPs []string `json:"allowIps"` // 允许名单：命中即放行，并跳过自动封禁计数。
	DenyIPs  []string `json:"denyIps"`  // 拒绝名单：命中即拒绝，优先于其他一切规则。

	// AutoBan 是否在来源持续触发握手异常时自动拉黑（带 TTL）。
	AutoBan bool `json:"autoBan"`

	// 下面五个数值在预设档位（loose/balanced/strict）下由 Level 决定，手填不作数；
	// Level=custom 时才以这里的值为准。落库的永远是**已经解析好的数值**，
	// 于是运行态（internal/inboundfw）只读这几个字段，不必认识"档位"这个概念。
	//
	// WindowSeconds / WindowLimit 常规窗口：WindowSeconds 秒内累计 WindowLimit 次握手异常即封禁。
	WindowSeconds int `json:"windowSeconds"`
	WindowLimit   int `json:"windowLimit"`
	// BurstSeconds / BurstLimit 突发窗口：更短窗口内 BurstLimit 次即封禁，专抓高速扫描。
	BurstSeconds int `json:"burstSeconds"`
	BurstLimit   int `json:"burstLimit"`
	// BanMinutes 自动封禁维持多少分钟。
	BanMinutes int `json:"banMinutes"`

	// MemoryMB **每张**自动封禁表的内存上限（MB），只在此模块设置。
	//
	// 面板入站防护与服务防护各有一张封禁表，两张都按这一个数换算容量
	//（见 BanEntriesForMemoryMB），因此最坏情况下的总占用是它的两倍——
	// 写成"共用一个额度"曾是这里的说法，但那与代码不符：一个数、两张表、各自封顶。
	MemoryMB int `json:"memoryMB"`
}

// PanelFirewall 面板入站防护：只管「谁能连到面板」，不涉及本机其他端口，
// 也不改动系统防火墙——它是本进程自己在监听器与请求入口上的判断。
//
// 决策顺序是这份设计的核心，实现见 server.panelFirewall.decide，顺序为：
//
//	回环放行（仅豁免 Mode 与自动封禁）→ 拒绝名单 → 自动封禁表 → 允许名单 → Mode → 限速
//
// 三处细节值得在类型上就写明：
//
//   - **拒绝优先于允许**，与 WebAccess 的 withIPFilter 同向：名单相互矛盾时，
//     「拦下」是那个可以事后放开的选择。
//   - **允许名单先于 Mode 生效**，因此 Mode=lan 且允许名单里写着办公室出口 IP，
//     等于「局域网 + 这个外网地址」。没有这一条，「只允许局域网」就无法表达
//     「再加一个我信任的外网地址」，用户只能整个改成 all。
//   - **回环永远进得来**（除非被显式写进拒绝名单），这是最后的自救通道：
//     配置写错时还能从本机 SSH 隧道进面板改回来。
type PanelFirewall struct {
	// Enabled 防火墙总开关。关闭时整道逻辑完全不参与，连监听器包装都不做。
	//
	// 全新安装默认开启且 Mode=lan；**升级**上来的旧配置默认关闭（见 store.go 的 v10 迁移块）——
	// 一个本来从外网管理面板的用户，不该因为升了个版本就把自己关在门外。
	Enabled bool `json:"enabled"`

	// Mode 允许的来源范围：
	//   - "lan"：只允许局域网（回环 / 私有网段 / 链路本地，判定见 ipx.IsLAN）
	//   - "all"：不限来源（仍然受名单、限速、自动封禁约束）
	// 空值按 "lan" 处理，即未知取值一律往严的方向落。
	Mode string `json:"mode"`

	// AllowIPs 允许名单。命中即放行，并**跳过 Mode 判定**（见类型注释）。
	// 写法同 ipx.ParseCIDRs：单 IP / CIDR / a-b 范围。
	AllowIPs []string `json:"allowIps"`
	// DenyIPs 拒绝名单。命中即拒绝，优先于其他一切规则（包括回环与允许名单）。
	DenyIPs []string `json:"denyIps"`

	// RateLimit 每个来源 IP 每秒允许的请求数，0 表示不限速。
	//
	// 注意它约束的是**已建立连接上的 HTTP 请求**，不是 TCP 连接数：
	// 连接层的拦截发生在更早的监听器上，那一层只看名单不看速率（见 server.firewallListener）。
	RateLimit int `json:"rateLimit"`

	// AutoBan 是否在来源持续超限时自动把它加入临时封禁。
	AutoBan bool `json:"autoBan"`
	// AutoBanThreshold 多少次「被限速拦下」触发封禁。计数窗口固定 10 分钟，
	// 窗口内不再超限则计数清零——见 server.panelFirewall。
	AutoBanThreshold int `json:"autoBanThreshold"`
	// AutoBanMinutes 自动封禁维持多少分钟。
	//
	// 自动封禁只存在于内存，进程重启即清空，**不写进 config.json**。
	// 这是刻意的：把每次攻击都落盘等于让攻击者控制本机的写入量（见 store.go 中
	// 关于统计数据搬去 runstats 的那段说明），且封禁本就是短期止血手段。
	AutoBanMinutes int `json:"autoBanMinutes"`
}

// LogConfig 日志设置。
type LogConfig struct {
	Levels []string `json:"levels"` // 允许记录的级别（debug/info/warn/error）；为空表示记录所有级别
	// MaxEntries 是「日志最大条数」——本程序日志数据量的**唯一总开关**，
	// 区间与默认值见 logx.MinLogEntries / MaxLogEntries / DefaultLogEntries（[100,5000]，默认 1000）。
	//
	// 它同时约束三处存储，三者各自独立地不超过该条数：
	//  1. 程序运行日志内存环（logx.Logger.SetMaxEntries）；
	//  2. Web 服务访问事件内存环（webservice.Module.SetAccessCap）；
	//  3. 磁盘日志文件 mantou.log（logx.RotatingFile.SetMaxEntries，按行数轮转）。
	//
	// 磁盘另有固定 5 MB 的体积上限（logx.LogMaxSizeMB）与之并行，先到先轮转——
	// 单条日志长度差异极大，只按条数无法保证日志目录占用有上界。
	//
	// JSON 名保留 maxEntries：老配置文件里它原本只管访问事件环，语义扩大后仍能原样读入，
	// 无需存储版本迁移。
	MaxEntries int  `json:"maxEntries"`
	Console    bool `json:"console"`    // 是否同时输出到控制台
	ShowOnHome bool `json:"showOnHome"` // 是否在总览页显示日志（默认开）
	// HomeLimit 总览页「程序日志」面板一次渲染的条数（≤0 表示默认 50，上限 200）。
	// 它是**展示**层的量，且必然 ≤ MaxEntries——环里没有的条数展示不出来。
	// 上限刻意远低于 MaxEntries：面板每 3 秒整体重渲染一次，条数越多每轮开销越大（见 Overview.vue）。
	HomeLimit int `json:"homeLimit"`
}

// 总览页「程序日志」面板一次渲染的条数区间。
//
// 上限 200 而不是跟着 MaxEntries 走到 5000：该面板每 3 秒整体重建一次列表，
// 每行都要跑一遍分词着色（Overview.vue 的 fmtProgramLogLine）与字段拼接，
// 且没有虚拟滚动——条数直接等于每轮的渲染量。面板可视区约 13 行，
// 200 条已是"往回翻十几屏"，再多只是给看不见的行付渲染与传输成本。
// 默认 50：约四屏，够看清一次启动或一次故障的前后文，单轮开销仍在几毫秒量级。
const (
	DefaultLogHomeLimit = 50
	MaxLogHomeLimit     = 200
)

// NormalizeLogHomeLimit 规范化总览页展示条数：≤0 视为「用默认值」，其余夹进 [1, MaxLogHomeLimit]，
// 并再夹到 maxEntries —— 环里只有 N 条，展示条数写得比 N 大没有意义，
// 只会让设置页显示一个永远达不到的数字。
func NormalizeLogHomeLimit(n, maxEntries int) int {
	if n <= 0 {
		n = DefaultLogHomeLimit
	}
	n = min(max(n, 1), MaxLogHomeLimit)
	if maxEntries > 0 {
		n = min(n, maxEntries)
	}
	return n
}

// Appearance 界面外观自定义。
type Appearance struct {
	ThemeMode  string               `json:"themeMode"` // light/dark/auto
	Colors     AppearanceColors     `json:"colors"`
	Background AppearanceBackground `json:"background"`
	Card       AppearanceCard       `json:"card"`
	Font       AppearanceFont       `json:"font"`
	Layout     AppearanceLayout     `json:"layout"`
}

// AppearanceColors 主题色。
type AppearanceColors struct {
	Primary string `json:"primary"`
	Accent  string `json:"accent"`
	Success string `json:"success"`
	Warning string `json:"warning"`
	Danger  string `json:"danger"`
}

// AppearanceBackground 背景（图片/纯色/渐变）。
type AppearanceBackground struct {
	Type           string  `json:"type"`           // image/color/gradient
	Value          string  `json:"value"`          // 图片路径/URL、颜色值或渐变定义
	Blur           int     `json:"blur"`           // 模糊强度（px）
	OverlayOpacity float64 `json:"overlayOpacity"` // 遮罩不透明度 0~1
	Fit            string  `json:"fit"`            // cover/contain/tile
	Position       string  `json:"position"`       // center 等
}

// AppearanceCard 卡片/面板玻璃拟态。
type AppearanceCard struct {
	Opacity float64 `json:"opacity"` // 0~1
	Blur    int     `json:"blur"`    // px
	Radius  int     `json:"radius"`  // 圆角 px
	Shadow  string  `json:"shadow"`  // none/sm/md/lg
}

// AppearanceFont 字体与字号。
type AppearanceFont struct {
	Family string  `json:"family"` // system 或指定字体族
	Scale  float64 `json:"scale"`  // 全局字号缩放，1.0 为标准
	Weight int     `json:"weight"` // 字重
}

// AppearanceLayout 布局。
type AppearanceLayout struct {
	Sidebar string `json:"sidebar"` // expanded/collapsed
	Density string `json:"density"` // comfortable/compact
}

// Notify 统一通知渠道（可选，供各模块告警复用）。
//
// 注：这里原本还有一个 WebhookURL，它只被「设置」页的保存接口写入、没有任何一处读取，
// 前端也从不引用，属于早期留下的空壳，已删除。旧配置文件里残留的 webhookUrl 键
// 在读取时被忽略，不需要迁移。
type Notify struct {
	Enabled bool `json:"enabled"`
}

// Credential 服务商凭证（DNS / ACME 等复用）。
// Provider 取值见 internal/dnsprovider：cloudflare/godaddy/aliyun/tencent/baidu。
type Credential struct {
	ID       string            `json:"id"`
	Name     string            `json:"name"`
	Provider string            `json:"provider"`
	Secrets  map[string]string `json:"secrets"` // 各家字段不同，如 apiToken、accessKeyId/accessKeySecret 等
}

// ---------- DDNS ----------

// DDNSRule 一条动态域名规则。
type DDNSRule struct {
	ID           string       `json:"id"`
	Name         string       `json:"name"`
	Enabled      bool         `json:"enabled"`
	Stack        string       `json:"stack"`       // ipv4/ipv6
	Source       DDNSSource   `json:"source"`      // 取址方式
	IntervalSec  int          `json:"intervalSec"` // 探测间隔（秒）
	Targets      []DDNSTarget `json:"targets"`     // 更新目标
	LastIP       string       `json:"lastIP"`
	LastUpdateAt int64        `json:"lastUpdateAt"` // Unix 秒
	LastStatus   string       `json:"lastStatus"`
}

// MaxDDNSRules 动态域名规则条数上限。
//
// 每条**启用中**的规则各占一条常驻协程与一个定时器，且每一拍都要向外发一次请求
// 取当前 IP（见 ddns.ruleRunner.start）。拍频由用户填的「探测间隔」决定，下限没有——
// 填 1 就是每秒一次。于是成本随规则数与拍频同时增长，而这里面出去的是**外部请求**：
// 取址接口与 DNS 服务商那边都可能按频率限流，撞上之后表现是"规则看着在跑、域名却不更新"。
//
// 100 相对真实用途留了很大余量：家用与小型办公通常是几条到十几条。
// 上限只拦新增（见 registerCRUD 的 maxCount），已存在的配置不会因为这个数字而失效。
const MaxDDNSRules = 100

// DDNSSource 取址来源。
type DDNSSource struct {
	Type  string `json:"type"`  // public/interface/url
	Iface string `json:"iface"` // 网卡名（type=interface）
	URL   string `json:"url"`   // 第三方获取 IP 接口（type=url）
	Regex string `json:"regex"` // 从返回文本提取的正则
}

// DDNSTarget 更新目标。
// 一个目标可同时更新同一主域名下的多个「主机记录（二级域名）」；
// 直接更新根域名（@）具有较高风险，需显式打开 AllowRoot 开关（默认关闭）。
type DDNSTarget struct {
	CredentialRef string   `json:"credentialRef"`
	Provider      string   `json:"provider"`
	Domain        string   `json:"domain"`
	Subdomains    []string `json:"subdomains"` // 主机记录（二级域名）列表，如 ["home","nas"]
	AllowRoot     bool     `json:"allowRoot"`  // 是否允许更新根域名(@)；默认 false
	RecordType    string   `json:"recordType"` // A/AAAA
	TTL           int      `json:"ttl"`
	Line          string   `json:"line"` // 解析线路（可选）

	// ---- 旧版单一主机记录字段，仅用于从旧配置迁移；迁移后清空 ----
	LegacySubdomain string `json:"subdomain,omitempty"`
}

// ---------- Web 服务 ----------

// MaxWebServices Web 服务（父项）条数上限。
//
// 一个父项就是一条监听：绑一个端口、装一份 TLS、套一道并发连接数上限
// （maxConnsPerListener = 2000，见 webservice 包）。所以父项数直接等于监听数，
// 而每次保存都要把涉及的监听重建一遍——与端口转发同一个毛病：条数一多，
// 保存一次就是几十次 bind/close，其中任何一个端口被别的进程占着都会留下一条启动错误，
// 而这些错误要逐条看才知道是哪一条没起来。
//
// 但真正花钱的不是父项数，是**子项数**——见下面的 MaxWebChildren。
// 一个父项可以挂很多子项，所以只拦这个数并不能拦住内存。两道闸都要有。
//
// 50 相对真实用途留了很大余量：父项按端口划分，一台机器上真正对外的端口
// 通常是 80/443 加几个自定义端口。上限只拦新增（见 registerCRUD 的 maxCount），
// 已存在的配置不会因为这个数字而失效。
const MaxWebServices = 50

// MaxWebChildren 单个 Web 服务下的子项条数上限。
//
// 这是 Web 服务这一块**真正的**成本所在：每个反代子项各自持有一个连接池
// （http.Transport，MaxIdleConnsPerHost = 128，见 webservice.proxyHandler），
// 于是空闲连接数是按「子项数 × 128」增长的，与父项数无关。
// 一个父项挂 500 个反代子项，光空闲连接的上限就是 6.4 万条——
// 而这些连接不是请求来了才建、请求完就关，是**留着复用**的，会一直占着文件描述符。
//
// 另一头：子项是按 Host 分流的（见 webservice.listener），每个请求进来都要在这张表里
// 找一次归属。表大了单次查找仍然很快，但配置本身会先变得没法看——
// 一个端口下几百条域名规则，出问题时根本分不清是哪一条接错了。
//
// 50 相对真实用途留了很大余量：一个端口下挂几个到十几个站点是常见规模。
// 与列表条数上限不同，这一道**只拦"变多"**（见 validateWebService 那段说明）。
const MaxWebChildren = 50

// WebService 是「父项」规则：由 监听端口 + IP 地址族 唯一确定一个监听，
// 其下可挂载多个「子项」（WebChild），各子项按前端地址（域名/IP）分流到不同后端。
// 约束：同一 (Port, IPFamily) 只能存在一个父项（前端校验，后端遇冲突时聚合并置错）。
// 父项关闭时其全部子项一并停用。
type WebService struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Enabled  bool   `json:"enabled"`
	Port     int    `json:"port"`     // 监听端口
	IPFamily string `json:"ipFamily"` // 监听地址族：v4=仅IPv4 / v6=仅IPv6 / both=双栈(默认)
	// ProbeInterval 主动探测间隔（秒）：作用于该父项下所有子项的后端可达性探测周期。
	// 默认 60；≤0 表示使用默认；过低（<5）会被夹到 5，避免探测过于频繁。
	ProbeInterval int        `json:"probeInterval"`
	Children      []WebChild `json:"children"` // 子项规则

	// ---- 以下为旧版扁平字段，仅用于从旧配置迁移；迁移后清空，omitempty 不再落盘 ----
	LegacyListens       []WebListen       `json:"listens,omitempty"`
	LegacyDomains       []string          `json:"domains,omitempty"`
	LegacyType          string            `json:"type,omitempty"`
	LegacyUpstreams     []WebUpstream     `json:"upstreams,omitempty"`
	LegacyLB            string            `json:"lb,omitempty"`
	LegacyStatic        *WebStatic        `json:"static,omitempty"`
	LegacyRedirect      *WebRedirect      `json:"redirect,omitempty"`
	LegacyProxy         *WebProxyOptions  `json:"proxy,omitempty"`
	LegacyHeaders       map[string]string `json:"headers,omitempty"`
	LegacyAccess        *WebAccess        `json:"access,omitempty"`
	LegacyRedirectHTTPS bool              `json:"redirectHttps,omitempty"`
	LegacyHSTS          bool              `json:"hsts,omitempty"`
	LegacyTLSMinVersion string            `json:"tlsMinVersion,omitempty"`
}

// WebChild 是「子项」规则：一个前端地址集合（域名/IP）到一类后端的映射，
// 归属于某个父项（共享父项的端口与地址族）。可单独启停并附带备注。
type WebChild struct {
	ID            string            `json:"id"`
	Enabled       bool              `json:"enabled"`
	Note          string            `json:"note"`    // 备注
	Domains       []string          `json:"domains"` // 前端地址（域名/IP）；留空=该端口的默认站点
	Type          string            `json:"type"`    // proxy/static/redirect
	Upstreams     []WebUpstream     `json:"upstreams"`
	LB            string            `json:"lb"` // roundrobin/iphash
	Static        WebStatic         `json:"static"`
	Redirect      WebRedirect       `json:"redirect"`
	Proxy         WebProxyOptions   `json:"proxy"`
	Headers       map[string]string `json:"headers"`
	Access        WebAccess         `json:"access"`
	TLS           bool              `json:"tls"`           // 该子项是否启用 HTTPS（端口只要有一个子项启用即以 TLS 监听）
	TLSMinVersion string            `json:"tlsMinVersion"` // TLS 最低版本：""(默认1.2)/1.0/1.1/1.2/1.3
	// RedirectHTTPS 把明文请求 307 跳到 https。TLS=true 时该开关被**强制置真**
	// （migrate 与 normalizeWebService 两条路径都会兜住，手改配置也绕不过）：
	// 既然这个子项已经提供 HTTPS，就没有理由再放任明文访问。
	// 需要"80 端口跳到 443"时，请在监听 80 的那个父项（其子项 TLS=false）下手动开启本开关。
	RedirectHTTPS bool `json:"redirectHttps"`
	HSTS          bool `json:"hsts"`
	// FrameDeny 禁止别的站点把本站页面套进 iframe（点击劫持防护），
	// 落地成 X-Frame-Options: SAMEORIGIN 与 CSP 的 frame-ancestors 'self'。
	//
	// 默认关闭、必须显式开启：把页面嵌进 iframe 是完全正当的用法（内嵌看板、
	// 第三方付款页、文档站里的示例框），无条件打开会把这类站点直接弄坏，
	// 而它们从配置里看不出任何异常。
	//
	// 取 SAMEORIGIN 而不是 DENY：本站自己嵌自己的页面很常见，而要防的是**第三方**
	// 站点拿本站页面做点击劫持——SAMEORIGIN 已经完整覆盖那件事。
	//
	// 反向代理的后端自己已经发了这两个头时不必再开这个开关：两份头会同时到达浏览器，
	// 而两者的处置规则并不一样——重复且取值冲突的 X-Frame-Options 被浏览器整条**忽略**
	// （不是"按更严的算"），重复的 CSP 则是逐条都要满足、等于取交集。也就是说这种情形下
	// 真正生效的是 frame-ancestors 那一半，结果仍然不会比任一方更宽松，只是 XFO 那道
	// 老浏览器兜底白发了。
	FrameDeny bool `json:"frameDeny"`
	// TrustProxyHeaders 决定是否采信上游代理声明的协议（X-Forwarded-Proto / CF-Visitor）。
	// 默认不采信：这两个头任何客户端都能自己填，采信它等于让请求方自己决定
	// "强制 HTTPS"与 HSTS 要不要生效。只有该子项确实挂在外层 TLS 终结代理
	// （Cloudflare、nginx 等）后面时才应打开。
	TrustProxyHeaders bool `json:"trustProxyHeaders"`
}

// WebListen 旧版监听结构，仅保留用于旧配置迁移。
type WebListen struct {
	Addr string `json:"addr"`
	Port int    `json:"port"`
	TLS  bool   `json:"tls"`
}

// WebUpstream 反代后端。
type WebUpstream struct {
	URL    string `json:"url"`
	Weight int    `json:"weight"`
}

// WebStatic 静态站点。
type WebStatic struct {
	Root        string `json:"root"`
	Index       string `json:"index"`
	SPAFallback bool   `json:"spaFallback"`
	// Gzip 开启后按响应 Content-Type 分流压缩（HTML/CSS/JS/JSON/SVG 等压，
	// 图片/视频/已压缩归档不压且仍走 sendfile）。新建站点默认开启，
	// 旧配置由 v4 迁移补真——见 store.go 的 migrate。
	Gzip bool `json:"gzip"`
	// DirList 决定目录里没有 Index 文件时是否列出文件清单。默认关闭：
	// 静态根目录常常就是一个项目目录，列表会把备份文件、子目录一并交给访客。
	DirList bool `json:"dirList"`
}

// WebRedirect 重定向 / URL 跳转。
type WebRedirect struct {
	Target    string `json:"target"`    // 目标 URL（如 https://example.com）
	Code      int    `json:"code"`      // 301/302/307/308，默认 302
	KeepPath  bool   `json:"keepPath"`  // 是否把原始路径拼到目标之后
	KeepQuery bool   `json:"keepQuery"` // 是否保留原始查询串
}

// WebProxyOptions 反向代理细项开关。
type WebProxyOptions struct {
	InsecureSkipVerify bool `json:"insecureSkipVerify"` // 忽略后端 TLS 证书校验
	PreserveHost       bool `json:"preserveHost"`       // 透传原始 Host（默认改写为上游 Host）
	AccessLog          bool `json:"accessLog"`          // 记录访问日志
	// AccessLogLimit 是**纯前端的展示偏好**：面板打开某个子项的访问日志时，用它作为
	// /api/actions/web/child-logs 的 limit 参数（见 WebServices.vue 的 openLogs）。
	// Go 侧刻意不读它——服务端的真实上限由访问日志环的容量决定，与用户想看几条无关。
	// 别因为"全仓库 Go 代码无引用"就把它当死配置删掉：删掉会让所有用户已保存的
	// 展示条数静默回落到默认值。
	AccessLogLimit int `json:"accessLogLimit"`
}

// WebAccess 访问控制。
type WebAccess struct {
	// BasicAuth 是 Basic 认证的独立开关（默认关闭）。
	// 引入它之前，"填了用户名就等于开启"，用户想临时关掉认证只能把账号口令整段删掉、
	// 想恢复又得重新输一遍；面板侧还需要一个能被 TLS 状态支配的显式开关（未启用 TLS 时
	// Basic 口令会以明文经网络传输，故面板仅在子项启用 TLS 后才展示该功能）。
	BasicAuth     bool   `json:"basicAuth"`
	BasicAuthUser string `json:"basicAuthUser"`
	// BasicAuthPass 存的是 **bcrypt 哈希**，不是明文：这是校验用口令，无需可逆。
	// 面板提交明文时由 normalizeWebService 就地哈希；历史配置里的明文由启动时的一次性
	// 迁移（app.MigrateWebBasicAuth）换成哈希，校验侧同时兼容两种形态，保证升级不锁门。
	// 也正因为它不可逆，它不属于 secret.go 的字段加密范围（加密一个哈希没有意义）。
	BasicAuthPass string   `json:"basicAuthPass"`
	AllowIPs      []string `json:"allowIps"`
	DenyIPs       []string `json:"denyIps"`
	RateLimit     int      `json:"rateLimit"`    // 每秒请求数，0 不限
	IPFilter      bool     `json:"ipFilter"`     // IP 过滤总开关（默认关闭）
	IPFilterMode  string   `json:"ipFilterMode"` // 过滤模式：allow=白名单 / deny=黑名单
}

// ---------- 端口转发 ----------

// ForwardRule 一条端口转发规则（极简：监听端口 → 目标地址:端口）。
// 支持端口范围：ListenPortEnd > ListenPort 时监听 [ListenPort, ListenPortEnd]，
// 目标端口有两种映射方式（见 SameTargetPort）：
//   - 递增对应（默认）：目标端口从 TargetPort 起按相同偏移递增（listen+i → target+i）；
//   - 多对一：监听段所有端口都转发到同一个 TargetPort。
type ForwardRule struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	Enabled       bool   `json:"enabled"`
	Protocol      string `json:"protocol"`      // tcp/udp/both
	ListenPort    int    `json:"listenPort"`    // 本机监听端口（范围起点）
	ListenPortEnd int    `json:"listenPortEnd"` // 监听端口范围终点；0 或等于起点表示单端口
	TargetHost    string `json:"targetHost"`    // 目标地址（IPv4/IPv6/域名）
	TargetPort    int    `json:"targetPort"`    // 目标端口（递增模式为范围起点，多对一模式为唯一目标）
	// SameTargetPort 端口范围下的映射方式：true=所有监听端口都转发到同一个 TargetPort（多对一）；
	// false（默认/零值）=按偏移递增。取零值即递增，历史配置无此字段时行为不变。
	SameTargetPort bool   `json:"sameTargetPort"`
	Family         string `json:"family"`    // 监听地址族：dual/v4/v6（用于 IPv6↔IPv4）
	Bind           string `json:"bind"`      // 监听绑定地址：留空=监听所有网卡(0.0.0.0/::)；可填 127.0.0.1/具体 IP，仅本地或指定网卡可访问
	LastError      string `json:"lastError"` // 最近一次启动错误（运行态）
}

// MaxForwardRules 端口转发规则条数上限。
//
// 一条规则不等于一个监听：填了端口范围时它会展开成逐端口的多个转发器
// （见 forward.expandRule，单条最多 maxRangePorts 个），每个转发器各占一个监听套接字
// 与一条接受连接的协程。所以"条数"这个数字本身并不直接等于资源量。
//
// 那这个上限管的是什么：**每次保存都要把全部规则重建一遍**（Reload 会停掉旧的、
// 按新配置重新监听）。规则一多，保存一次就是几百次 bind/close，其中任何一个端口被别的
// 进程占着都会留下一条启动错误——而这些错误要逐条看才知道是哪一条没起来。
// 把条数停在一个还能逐条排查的规模上，比让它长到"面板显示一片红、不知从哪查"更有用。
//
// 100 相对真实用途留了很大余量。上限只拦新增（见 registerCRUD 的 maxCount），
// 已存在的配置不会因为这个数字而失效。
const MaxForwardRules = 100

// MaxForwardRangePorts 单条规则的端口范围一次最多展开多少个监听端口。
//
// 两处共用同一个上限：forward.expandRule 把超出的部分夹掉（配置加载 / 导入这条不过保存
// 校验的路径上的兜底，防止一条误配置的巨大范围把进程的监听套接字与协程吃光），而保存接口
// （validateForward）按同一个数明确拦下——让「我配了一段、怎么只生效了一截」变成保存时
// 一句能照着改的报错，而不是运行之后才发现的静默截断。
const MaxForwardRangePorts = 1000

// ---------- 网络唤醒 ----------

// WOLDevice 一台可唤醒设备。
type WOLDevice struct {
	ID        string `json:"id"`
	Enabled   bool   `json:"enabled"` // 设备级启用开关（默认 true）；关闭后定时唤醒与列表快捷启用均不生效
	Name      string `json:"name"`
	MAC       string `json:"mac"`
	Broadcast string `json:"broadcast"` // 留空或 255.255.255.255 = 自动逐网卡定向广播；填具体地址则只发该地址
	Port      int    `json:"port"`      // 默认 9
	// Interface 指定从哪张网卡发出（网卡名，如 eth0）。留空 = 自动。
	//
	// 自动模式只会用「内网且非虚拟」的网卡：往容器网桥、虚拟机网卡、公网网卡广播既唤不醒
	// 任何设备（魔术包是二层广播，跨路由不转发），又会把目标设备的 MAC 泄露给容器对端
	// 或同机房邻居。显式指定则原样尊重，包括「就是要用这一张」的场景。
	// 详见 wol.selectTargets。
	Interface string      `json:"interface"`
	Note      string      `json:"note"`
	Schedule  WOLSchedule `json:"schedule"` // 定时唤醒

	// 列表上的「最近唤醒」与「唤醒次数」不在这里：它们只在内存里（见 internal/runstats）。
	// 「时间范围」模式最快 1 秒一拍，每拍都要推进这几个数——放在配置条目上就意味着
	// 每拍换一份配置、涨一次 rev、标一次脏等着落盘，而这三个数丢了不影响任何行为。
}

// MaxWOLDevices 设备条数上限。
//
// 定这个上限不是怕配置文件变大，而是因为每台启用了定时唤醒的设备各占一条常驻协程，
// 且范围模式下每台设备的每一拍都要走一遍「枚举网卡（有缓存）+ 发包 + 回写运行态」。
// 回写是全局串行的，于是总成本随设备数与拍频**同时**增长；200 台 × 1 秒间隔已是
// 每秒 200 次回写，再往上就不是「面板变慢」而是「面板不响应」。
//
// 200 相对真实用途留了很大余量：家用与小型办公的唤醒目标通常是个位数到几十台。
// 上限只拦新增（见 registerCRUD 的 maxCount），已存在的配置不会因为这个数字而失效——
// 从旧版本升级上来的超量配置照常加载，只是不能再往上加。
const MaxWOLDevices = 200

// MaxWOLWakeCount 单台设备「固定时间」模式下一秒内的发包次数上限。
// 魔术包是一次性 UDP 广播，正常场景 1~5 次已足够；设上限是为了避免配置中出现极端值
// （如 100000）时，调度器在一秒内持续广播（网络放大）。API 校验、配置迁移与调度器三处共用此常量。
const MaxWOLWakeCount = 100

// MaxWOLIntervalSec 「时间范围」模式下发送间隔的上限（24 小时）。
// 间隔本身不消耗资源，设上限只为拦住明显写错的巨大数值（那会让整个时间范围只发一个包）。
const MaxWOLIntervalSec = 86400

// WOLSchedule 定时唤醒设置。
//
// 两种触发方式各自只用到其中一组字段，互不干扰：
//   - fixed（固定时间）：用 Time + Count。每天在 Time 这一个时刻，于 1 秒内连发 Count 个魔术包。
//     不使用 IntervalSec——「一秒内发几个」已经把密度说完了。
//   - range（时间范围）：用 Start + End + IntervalSec。从 Start 到 End，每 IntervalSec 秒发 1 个包。
//     不使用 Count——发多少个包由时间跨度除以间隔决定。
type WOLSchedule struct {
	Enabled         bool   `json:"enabled"`
	CalendarEnabled bool   `json:"calendarEnabled"`
	Mode            string `json:"mode"` // fixed=每天固定时间 / range=时间范围内按间隔发送
	StartDate       string `json:"startDate"`
	EndDate         string `json:"endDate"`
	Time            string `json:"time"`        // fixed 模式：HH:MM
	Start           string `json:"start"`       // range 模式：起 HH:MM
	End             string `json:"end"`         // range 模式：止 HH:MM
	Count           int    `json:"count"`       // fixed 模式：1 秒内的发包次数；上限见 MaxWOLWakeCount
	IntervalSec     int    `json:"intervalSec"` // range 模式：每隔多少秒发一个包；上限见 MaxWOLIntervalSec
}

// ---------- 计划任务 ----------

// CronTask 一条计划任务。
type CronTask struct {
	ID         string       `json:"id"`
	Name       string       `json:"name"`
	Enabled    bool         `json:"enabled"`
	Cron       string       `json:"cron"`     // 最终 cron 表达式（由 Schedule 生成或自定义）
	Schedule   CronSchedule `json:"schedule"` // 结构化调度，供前端可视化编辑与回显
	Action     CronAction   `json:"action"`
	TimeoutSec int          `json:"timeoutSec"`
	LastRunAt  int64        `json:"lastRunAt"`
	NextRunAt  int64        `json:"nextRunAt"`
	LastStatus string       `json:"lastStatus"`
}

// MaxCronTasks 计划任务条数上限。
//
// 调度器只有一个（robfig），多一条任务只多一个表项——常驻成本很低。真正的成本在**触发那一刻**：
// 每次执行结束都要回写一次「最近执行时间 / 结果 / 下次执行时间」（见 cron.writeResult），
// 而这条回写是走配置管理器的，全局串行。若一批任务都配成每分钟一次，那就是同一分钟内
// N 次串行回写 + N 个并发的处理协程（其中可能包含向外发请求、跑续期这类慢活）。
//
// 100 相对真实用途留了很大余量：常见用法是几条到十几条。
// 上限只拦新增（见 registerCRUD 的 maxCount），已存在的配置不会因为这个数字而失效。
const MaxCronTasks = 100

// CronSchedule 结构化调度描述（前端据此生成 cron，无需用户手写）。
type CronSchedule struct {
	Type         string `json:"type"`         // minutely/hourly/daily/weekly/monthly/interval/custom
	Minute       int    `json:"minute"`       // 分钟 0-59
	Hour         int    `json:"hour"`         // 小时 0-23
	Weekdays     []int  `json:"weekdays"`     // weekly：星期 0-6（0=周日）
	Day          int    `json:"day"`          // monthly：日 1-31
	EveryMinutes int    `json:"everyMinutes"` // interval：间隔数值（配合 EveryUnit）
	EveryUnit    string `json:"everyUnit"`    // interval：间隔单位 minutes/hours（默认 minutes）
	Expr         string `json:"expr"`         // custom：自定义 cron 表达式
}

// CronAction 任务动作。
type CronAction struct {
	Type   string            `json:"type"`   // ddns.refresh / wol.wake / cert.renew / http
	Params map[string]string `json:"params"` // 动作参数，如 targetId、url
}

// ---------- 证书 ----------

type CertificateOperationStatus struct {
	State     string `json:"state"`
	Message   string `json:"message"`
	UpdatedAt int64  `json:"updatedAt"`
}

// Certificate 一张证书。
type Certificate struct {
	ID              string                     `json:"id"`
	Name            string                     `json:"name"`
	Enabled         bool                       `json:"enabled"` // 是否启用（用于 TLS 监听）；默认 true
	Domains         []string                   `json:"domains"`
	Method          string                     `json:"method"`        // file=粘贴PEM / path=磁盘路径 / acme=自动签发
	CertPath        string                     `json:"certPath"`      // method=path：证书文件路径
	KeyPath         string                     `json:"keyPath"`       // method=path：私钥文件路径
	ACMEChallenge   string                     `json:"acmeChallenge"` // method=acme：固定 dns01（HTTP-01 未实现且已移除，旧值会被迁移为 dns01）
	CredentialRef   string                     `json:"credentialRef"` // method=acme：DNS 服务商凭证（DNS-01 必需）
	ACMEAccountRef  string                     `json:"acmeAccountRef"`
	AutoRenew       bool                       `json:"autoRenew"`
	RenewBeforeDays int                        `json:"renewBeforeDays"`
	RenewTime       string                     `json:"renewTime"` // 每天自动续期检查时刻（HH:MM）；空则默认 03:00
	NotAfter        int64                      `json:"notAfter"`
	Issuer          string                     `json:"issuer"`
	Status          string                     `json:"status"`
	IssueStatus     CertificateOperationStatus `json:"issueStatus"`
	RenewStatus     CertificateOperationStatus `json:"renewStatus"`
	LastRenewAt     int64                      `json:"lastRenewAt"`
}

// MaxCerts 证书条数上限。
//
// 每张**启用中**的证书都会把解析好的证书链与私钥常驻在内存里（供面板与 Web 服务的 TLS
// 握手直接取用），且续期检查是每分钟醒一次、醒来遍历全部证书（见 cert 模块的 ticker）。
//
// 另一头的限制更硬：自动签发走的是 ACME，签发方本身就按域名、按账户限频
// （常见的是每周若干张、重复签发更少）。把证书条数堆到几百张，撞上的不是本机资源，
// 而是签发方的配额——那种失败要等一周才能重试。
//
// 50 相对真实用途留了很大余量：一份证书可以覆盖多个域名（含通配），
// 常见用法是一到几张。上限只拦新增（见 registerCRUD 的 maxCount），
// 已存在的配置不会因为这个数字而失效。
const MaxCerts = 50

// ACMEAccount 一个 ACME 账户。
type ACMEAccount struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	CA      string `json:"ca"` // letsencrypt/letsencrypt-staging/zerossl/buypass
	Email   string `json:"email"`
	EABKid  string `json:"eabKid,omitempty"`
	EABHMAC string `json:"eabHmac,omitempty"`
	// PrivateKeyPEM 账户私钥（首次注册后由后端生成并保存），前端不展示。
	PrivateKeyPEM string `json:"privateKeyPem,omitempty"`
}

// ---------- 消息路由（Webhook → 规则 → 模板 → 通知）----------
//
// 数据模型分四层，与界面的四张列表一一对应：
//
//	① WebhookServer    模块级监听：端口、HTTPS（选证书 + 填域名，与面板同口径）
//	② WebhookReceiver  一个第三方来源 = 一条入站路径 + 鉴权 + 限流 + IP 名单 + 字段映射 + 规则
//	③ MessageTemplate  消息模板（text/template 语法），可被任意接收器的任意规则引用
//	④ NotifyTarget     出站通知目标（钉钉 / 企业微信 / 自定义 HTTP），可被任意规则引用
//
// 为什么「发什么」（规则 → 模板）与「发给谁」（目标改写）是两张表而不是一棵树：
// 内容与去向是两个**正交**维度。把去向嵌进内容规则里，3 种业务 × 2 个群就要配 6 条，
// 加一个群要回头改 3 条；拆开之后是 3 条内容规则 + 1 条去向规则，加群只加 1 条。
// 目标改写整体可选——只有一个群的用户永远不需要看见它。

// WebhookServer 消息路由模块自身的监听与 HTTPS 配置。
//
// 独立监听（而不是挂在面板端口下）有两个理由：
// 其一，入站 Webhook 的调用方是第三方系统，把它和管理面板放同一端口意味着
// 任何能推消息的系统都能摸到登录接口；其二，HTTPS 要用的证书与域名往往与面板不同
// （面板用内网域名，Webhook 用公网域名）。
//
// 但 80 / 443 是三方（面板、Web 服务、消息路由）都想要的公共端口，而很多第三方系统
// 只允许回调标准端口。所以本模块的端口**允许**与某个已启用的 Web 服务重合：此时不自己
// 绑定，而是把 Domain 注册成那个监听上的一条 Host 路由（见 WebhookSharesWebServicePort）。
// 代价是 Domain 必须填、且不得与面板/Web 服务任何域名重复——共享监听靠域名区分归属，
// 域名撞车就没有任何办法判断一个请求该给谁。
type WebhookServer struct {
	// Created 模块是否已创建。它不是"启用"的同义词，而是"这一行存在不存在"：
	//
	// 消息路由的一切都挂在这个监听上——没有它，接收器既没有域名也没有可访问的地址，
	// 启用一个接收器只会得到一条永远收不到消息的配置。所以模块设置那一页做成了
	// 「未创建 → 空列表 + 新建」，创建之后才有那一行、才有开关、才能启用接收器
	//（见 server.handleUpdateWebhookServer / handleDeleteWebhookServer）。
	//
	// 为什么要一个显式字段、不靠"端口是默认值且域名为空"来推断：删除之后各字段回到默认值，
	// 与全新安装长得一模一样，而"升级上来的旧配置"同样可能是默认值——三种状态混在一起，
	// 只有一个显式布尔能把它们分开（旧配置在 migrate 的 v7 块里统一置真）。
	Created bool   `json:"created"`
	Enabled bool   `json:"enabled"` // 模块总开关；关闭后不监听、不接收
	Listen  string `json:"listen"`  // 监听地址；固定 0.0.0.0（不在 UI 暴露）
	Port    int    `json:"port"`    // 监听端口，默认 25667
	// Domain 访问域名。启用 HTTPS 时必填（校验 Host 并保证 SNI 取到正确证书）；
	// 端口为 80 / 443 时同样必填——那两个端口可能与 Web 服务共享，域名是唯一的分流依据。
	Domain string       `json:"domain"`
	Note   string       `json:"note"`  // 备注：这个入站监听是干什么的，只给人看
	HTTPS  WebhookHTTPS `json:"https"` // HTTPS 设置

	// SourceRetainMB 被拒收 / 被丢弃的入站原文，最多在内存里留多少 MB（0 表示不留存）。
	// 取值范围与理由见 DefaultSourceRetainMB / MaxSourceRetainMB；越界由 normalizeWebhook 收拢。
	//
	// 放在这个结构里是因为它是**模块级**设置，而这个结构就是界面上「模块设置」那一页
	// 保存的东西（见 server.handleUpdateWebhookServer）。它与监听无关，
	// 但模块只有这一处模块级设置，另立一个结构只会多出一层没人记得的嵌套。
	SourceRetainMB int `json:"sourceRetainMb"`
}

// WebhookHTTPS 消息路由模块的 HTTPS 设置，字段与用途和 PanelHTTPS 一致。
//
// **一旦启用 HTTPS，明文访问全部禁止**：本模块只有一个监听端口，启用后该端口直接以 TLS 起监听，
// 明文请求在 TLS 握手阶段即失败——这个"禁止"是结构上的，不依赖任何跳转开关，
// 因此也不存在"手改配置把跳转关掉就能明文进来"的绕过路径。
type WebhookHTTPS struct {
	Enabled bool   `json:"enabled"`
	CertID  string `json:"certId"`
	// Domain 已上移到 WebhookServer.Domain（端口 80 共享时没有 HTTPS 也要域名）。
	// 这里保留字段只为读得到旧配置，normalizeWebhook 会把它折上去并清空。
	Domain string `json:"domain,omitempty"`
}

// 消息路由各类条目的条数上限。
//
// 这些数字不是"怕配置文件变大"，而是各有其运行期成本：
//   - 接收器：每条在 Reload 时编译出一份运行态（预编译正则、预解析模板、独立限流桶），
//     且路径要建索引，数量直接等于 Reload 的编译量与常驻内存；
//   - 规则 / 映射：每条入站请求都要顺序过一遍（首个命中即停），是**每请求**成本；
//   - 模板 / 目标：只在被引用时才有成本，上限放宽一些。
//
// 与 MaxWOLDevices 同口径：上限只拦新增（见 registerCRUD 的 maxCount），
// 已存在的超量配置照常加载与编辑，只是不能再往上加。
const (
	MaxWebhookReceivers  = 50
	MaxWebhookRules      = 50 // 单个接收器内的消息规则条数
	MaxWebhookMappings   = 50 // 单个接收器内的字段映射条数
	MaxWebhookConditions = 20 // 单条规则内的条件条数（分支的附加条件各自单独计）
	MaxWebhookBranches   = 10 // 单条规则内的输出分支数
	MaxWebhookKeywords   = 20 // 单个接收器的关键词准入词条数
	MaxMessageTemplates  = 100
	MaxNotifyTargets     = 50
)

// MaxWebhookKeywordLen 单个关键词的长度上限。
// 关键词是逐条在请求体原文里做子串查找的，长度直接进每请求成本；
// 而"要求消息里带上某个词"这件事本身，几十个字符远够用。
const MaxWebhookKeywordLen = 64

// 入站请求体的体积上限（KB）。
//
// 必须有上限：请求体在解析前要整段读进内存（JSON 解析没有流式的路径可走），
// 而调用方是第三方系统，体积完全不受本程序控制。默认 256 KB 足以容纳
// 一份几百行的消息；上限 4 MB 留给极端场景，再大应该在来源侧分批推送。
const (
	DefaultWebhookBodyKB = 256
	MaxWebhookBodyKB     = 4096
)

// DefaultWebhookPort 消息路由模块的默认监听端口。
// 刻意紧邻面板默认端口（25666），便于用户记忆与在防火墙上成对放行。
const DefaultWebhookPort = 25667

// 入站原文留存的额度（MB）。被拒收 / 被丢弃的消息，把对方发来的原文留一份在内存里，
// 面板在执行历史那一行点「来源」就能看到（实现见 webhook 包的 source.go）。
//
// 做成可调而不是写死一个数：这份留存装的是第三方推来的整段正文，可能含姓名、
// 手机号、内部地址。"正在查为什么没收到"的人需要它，而不查问题的人希望这些内容
// 根本不进内存——两种诉求都合理，差别只是一个数字，所以把这个数交给用户。
//
// 0 表示不留存：此时连槽位数组都不分配，历史记录上也不会再出现「来源」链接。
// 上限 3 MB 不是技术限制，而是再往上没有意义——查问题翻的是最近几条，
// 而 2 MB 已经能留住几百条真实推送（详见 webhook 包 defaultSourceBudget 那段说明）。
const (
	DefaultSourceRetainMB = 2
	MaxSourceRetainMB     = 3
)

// WebhookPathLen 随机生成的入站路径长度（hex 字符数，即 16 字节熵）。
//
// 路径本身就是一层弱凭证：很多第三方系统的推送插件只允许配一个 URL、
// 不支持自定义请求头，此时"猜不到的路径"是唯一可用的保护。32 个 hex 字符 = 128 bit 熵，
// 与 UUID 同量级，不可枚举。
const WebhookPathLen = 32

// MaxWebhookPathLen 自定义入站路径的长度上限。
// 路径要进日志、进审计、进前端列表，太长会把这些地方挤爆；256 远超任何合理用途。
const MaxWebhookPathLen = 256

// WeakWebhookPathLen 路径短于这个长度时，"靠路径保护"这件事就不再成立。
//
// 只用于提示，不参与校验：改成自定义路径往往是第三方系统的硬性要求，
// 拦下来会让人无路可走。16 个字符是个宽松的门槛——即便全用小写字母和数字，
// 也还有 36^16 种组合；真正会中的是 hook、notify、test 这类顺手起的短名字，
// 它们出现在任何一份路径字典里。
//
// 由 /webhook/meta 的 limits 下发给界面（见 handleWebhookMeta），
// 前端据此在"不鉴权 + 短路径"时给一条黄色提示，不阻止保存。
const WeakWebhookPathLen = 16

// WebhookReceiver 一个入站 Webhook 接收器：对应一个第三方来源系统。
//
// 每个来源单独一条（而不是共用一个入口再靠字段区分）的原因：
// 不同来源的鉴权方式、限流阈值、IP 名单、数据结构（RootPath）都不一样，
// 且出问题时要能单独停掉某一个来源，而不影响其余。
type WebhookReceiver struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Enabled bool   `json:"enabled"`
	Note    string `json:"note"`

	// Path 入站路径（不含前导斜杠，不含 query）。新建时随机生成（见 WebhookPathLen），
	// 也允许用户改成自定义值——有些第三方系统的 URL 里要带上它自己认得的路径片段。
	// 全局唯一，大小写敏感（HTTP 路径本身就区分大小写）。
	Path string `json:"path"`

	// AuthType 入站鉴权方式：
	//   none   仅靠随机路径（第三方系统不支持自定义请求头时的唯一选择）
	//   token  从请求头 / query 取 token 与 Token 比对（等长时间比较，不给计时预言机）
	//   header 要求某个请求头存在且等于 Token（供签名头、自定义鉴权头使用）
	AuthType string `json:"authType"`
	// AuthHeader authType=token/header 时读取的请求头名（大小写不敏感）。
	// authType=token 且留空时，依次尝试 X-Mantou-Token、Authorization（Bearer）、query 的 token。
	AuthHeader string `json:"authHeader"`
	// Token 期望的令牌值。属于凭证：由 secret.go 加密落盘（见 aadWebhookToken）。
	Token string `json:"token,omitempty"`

	// RateLimit 每秒允许的请求数，0 不限。与 WebAccess.RateLimit 同口径。
	RateLimit int `json:"rateLimit"`
	// MaxBodyKB 请求体上限（KB）；≤0 表示用 DefaultWebhookBodyKB。
	MaxBodyKB int `json:"maxBodyKb"`

	// ---- IP 黑白名单：字段与语义完全照搬 WebAccess，避免同一个功能在两处有两套写法 ----
	IPFilter     bool     `json:"ipFilter"`     // IP 过滤总开关（默认关闭）
	IPFilterMode string   `json:"ipFilterMode"` // 过滤模式：allow=白名单 / deny=黑名单
	AllowIPs     []string `json:"allowIps"`     // 支持单 IP 与 CIDR
	DenyIPs      []string `json:"denyIps"`

	// ---- 关键词准入 ----
	//
	// 与钉钉、企业微信机器人的「自定义关键词」同一个思路，只是方向相反：那边是出站
	// 平台要求消息里带上约定的词，这边是本程序要求**收到的**消息里带上约定的词，
	// 带了才往下走，没带就拒收。用途是把"路径对了但内容明显不是给这个接收器的"这类
	// 请求挡在流水线之外——路径与令牌只能证明来源，证明不了内容。
	//
	// 判据刻意放在原始文本上（请求体原文 + 查询串的值），不解析、不看结构：
	// 第三方推来的可能是 JSON，也可能是一段自己拼的文本，甚至是个 txt。
	// 任何"先按某种结构取某个字段再比对"的写法都会在下一个来源上失效。
	// 请求头不参与比对：那是传输元数据，User-Agent 里凑巧出现一个词就放行不是用户的本意。
	KeywordFilter bool     `json:"keywordFilter"` // 关键词准入总开关（默认关闭）
	Keywords      []string `json:"keywords"`      // 要求出现的词，大小写不敏感
	KeywordMode   string   `json:"keywordMode"`   // any=任一命中即可（默认）/ all=必须全部出现

	// SourceType 来源消息类型：auto=自动识别（默认，留空同义）/ json=标准 JSON /
	// kv=键值文本 / txt=纯文本。
	//
	// 这几种覆盖了真实来源的全部形态：能配 Webhook 的系统要么发 JSON，要么发一段
	// 自己拼的文本（告警短信、日志行），而后者里最常见的一类是 name=x&type=y
	// 这种按符号拼起来的键值串——它有结构，只是不是 JSON。
	//
	// 默认 auto 是**逐条**判定，不是"存的时候猜一次"：同一个来源本来就会发不同格式的
	// 东西（旧接口拼的键值串、新接口的 JSON），而这两种形态里字段名往往是同一套。
	// 选死一种的代价实测过一次——接收器上写着 kv、对方推来 JSON，整份载荷被按逗号+冒号
	// 拆成一堆名叫 `{"biz"` 的假字段，body.biz 取不到值、规则全部落空，
	// 而用户能看到的只有"规则不命中"。auto 之下两种格式都能命中同一条规则。
	//
	// 另外三个值是"我知道这个来源长什么样，别自动"的显式模式，各自的用途很窄：
	// txt 挡掉一切拆分（对方发的正文里凑巧有 a=b 也不要拆），
	// kv 配合手填分隔符处理值里也带分隔符的刁钻载荷，
	// json 用来确认"这个来源只该发 JSON"（发来别的就整段进 body，不拆字段）。
	//
	// 填 txt 时请求体原样进 body（一个字符串），模板里写 {{.body}}；
	// 填 kv 或自动识别为 kv 时拆成字段，与 JSON 一样写 {{.body.name}}。
	SourceType string `json:"sourceType"`

	// PairSep / KVSep 仅在 SourceType=kv 时有意义：字段之间用什么符号隔开、
	// 字段名与值之间用什么符号连接（上面那个例子里分别是 & 和 =）。
	//
	// 两个都留空表示自动识别（默认）：候选符号里挑拆出字段最多的那一组，见 webhook.sniffKV。
	// 之所以还留着手填，是因为自动识别只能按"哪种拆得多"投票，而用户手上那个来源
	// 到底用什么符号，他自己是知道的——遇到值里也带分隔符的刁钻载荷时，说清楚比猜准。
	// 这也是 SourceType=kv 相对 auto 唯一多出来的能力（auto 下这两个字段被清空）。
	// 输入里的 \n \t 会在规范化时转成真字符（输入框里打不出换行）。
	PairSep string `json:"pairSep"`
	KVSep   string `json:"kvSep"`

	// RootPath 取值根路径：把取值起点下移到信封或载荷里的某个子对象。
	// 先按信封解（填 body 即"从请求体根开始"），解不出再按载荷解（填 heartbeat 指载荷内部的子对象）。
	//
	// 这个字段存在的全部意义是**不写死任何一家的结构**。有的系统把业务数据直接作为请求体发来，
	// Grafana 放在根一级（status + alerts[]），Uptime Kuma 放在 heartbeat 下，
	// GitLab 放在根的 object_kind。填 "body" 之后模板里写 {{.biz}} 而不是 {{.body.biz}}，
	// 留空则从内部事件根开始取值（body/headers/query 都在）。
	// 它只影响**默认取值起点**：显式写全路径（body.xxx、headers.xxx）永远有效。
	RootPath string `json:"rootPath"`

	// Mappings 字段映射：给深路径起一个能在模板里直接写的短名（消息类型 ← body.biz）。
	// 整体可选——映射结果与原始路径**并存**注入模板根，不用映射也能写 {{.body.biz}}。
	Mappings []FieldMapping `json:"mappings"`

	// Rules 消息规则：按 Priority 升序（相同则按列表顺序）逐条比对条件，
	// 命中即渲染其模板、发往其目标。**分流全部由这里决定**——
	// 模板只负责把字段拼成对方平台认得的文本，不再写任何条件。
	Rules []WebhookRule `json:"rules"`

	// DefaultTargets 规则未指定目标时使用的通知目标 ID 列表。
	DefaultTargets []string `json:"defaultTargets"`

	// 这里原先还有三个运行态字段（最近接收时刻 / 最近状态 / 累计条数）。
	// 已经搬到 internal/runstats：那三个数只有列表页在看，没有任何逻辑读它们，
	// 而入站频率由公网决定，让它们跟着配置条目走等于每条请求换一份配置。
	// 列表接口在返回前从 runstats 取出来拼上，JSON 字段名没变（见 receiverRow）。
}

// FieldMapping 一条字段映射：给一个取值路径起个短名。
//
// Name 的字符集受 text/template 的标识符规则限制（见 ValidMappingName）：
// 模板里写成 {{.消息类型}}，名字里有空格或点号会直接让模板解析失败，
// 因此在保存时就拦下来，而不是等到第一条消息进来才报错。
type FieldMapping struct {
	Name    string `json:"name"`    // 模板中的字段名，如 消息类型
	Path    string `json:"path"`    // 取值路径，如 body.biz
	Default string `json:"default"` // 取不到值时的替代文本（留空即空串）
	Note    string `json:"note"`
}

// Condition 一条匹配条件：取 Path 的值，用 Op 与 Value 比较。
//
// 比较刻意做成**松类型**：JSON 里的 200 可能是数字也可能是字符串，
// 而配规则的人不该需要先搞清楚对方发的是哪种。eq/ne 统一转字符串比，
// gt/lt 先按数字比、比不了再按字符串比（见 webhook 模块的 compare）。
//
// countGt / countGte / countLt / countLte / countEq 这一组比的是**取到几个值**，
// 而不是值本身：路径里带 [*] 时（body.列表[*].名称）一条载荷会取出多个值，
// "创建人多于 1 个就发汇总模板"这类分流只能靠数量表达。
type Condition struct {
	Path  string `json:"path"` // 取值路径，如 body.消息类型 / body.列表[*].名称
	Op    string `json:"op"`   // 见 webhook.Operators：eq/ne/contains/regex/gt/countGt/exists/…
	Value string `json:"value"`
	// Not 对整条条件取反。有它就不必为每个算子都配一个反向算子。
	Not bool `json:"not"`
}

// WebhookRule 一条消息规则：条件命中 → 用哪个模板渲染 → 发给哪些目标。
type WebhookRule struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Enabled bool   `json:"enabled"`
	// Priority 越小越先比对；相同优先级按列表顺序。
	Priority int `json:"priority"`
	// Match 条件组合方式：all=全部满足（默认） / any=任一满足。
	// 条件为空表示无条件命中，可作为兜底规则（放在最后）。
	Match      string      `json:"match"`
	Conditions []Condition `json:"conditions"`
	// TemplateRef 引用的模板 ID。Branches 非空时**不生效**（各分支各自选模板）。
	TemplateRef string `json:"templateRef"`
	// Targets 通知目标 ID 列表；留空则用接收器的 DefaultTargets。
	// 同样在 Branches 非空时不生效。
	Targets []string `json:"targets"`
	// Branches 输出分支。为空（默认，也是所有老配置的形态）时这条规则只有一个输出，
	// 就是上面的 TemplateRef + Targets。
	//
	// 加这一层是为了表达"同一批消息按细分条件发不同模板给不同的目标"。以前只能拆成
	// 两条规则，公共条件要在两处各维护一遍，改一处漏一处；想让两条都执行还得看懂
	// Continue（漏勾第二条就静默不发）。
	//
	// 分成两层判定：规则本体的 Conditions 当粗筛，分支的 Conditions 当细分。
	// 判定与取舍见 webhook 模块的 process。
	Branches []RuleBranch `json:"branches,omitempty"`
	// FirstBranchOnly 只发**第一个**命中的分支；默认（零值 false）是命中的分支全都发。
	//
	// 方向与 Continue 同一个考虑：布尔零值必须等于默认行为。默认取"全都发"是因为
	// 多分支最常见的用法是并列分流（几个分支各通知一批目标，互不相干）；
	// 需要 IF/ELSE 的人把无条件的那个分支放在最后，改成"命中即停"即可。
	FirstBranchOnly bool `json:"firstBranchOnly,omitempty"`
	// Continue 命中后是否继续比对后续规则。
	//
	// 默认（零值 false）是**首个命中即停**，与 IF / ELSE 的直觉一致。
	// 字段刻意取"继续"而不是"停止"这个方向：布尔的零值必须等于默认行为，
	// 否则手改 config.json 漏掉这一项、或旧备份里没有这一项，行为就会与界面上写的默认值相反。
	Continue bool `json:"continue"`
}

// RuleBranch 规则的一个输出分支：（可选的附加条件）→ 用哪个模板 → 发给哪些目标。
//
// 与"再建一条规则"的区别只在判定范围：分支的条件只在所属规则已经命中之后才比对，
// 因此公共条件只写一遍。分支之间**没有优先级**，按列表顺序比对，
// 命中的全都发（除非规则上打开了 FirstBranchOnly）。
//
// 刻意不给分支加 Continue / Priority / Enabled：
//   - Continue 属于"要不要接着比对后面的**规则**"，是规则级的事；分支级再来一个同名开关，
//     用户就得同时在脑子里维护两层跳出逻辑，而这正是多分支要消灭的那种复杂度。
//   - 顺序即优先级。分支是同一条规则内的几个并列出口，需要排序时上下挪一格就够了，
//     再引入一个数字列会让"为什么这个先发"变成两个字段的组合结果。
//   - 不需要单独停用：临时不发就把它删掉或整条规则停用；一个能停用的分支在界面上
//     是一行灰字，在排查时却要多问一句"它是不是被关了"。
type RuleBranch struct {
	// Name 分支名。执行历史与试运行里显示成「规则名 / 分支名」，
	// 出问题时要能一眼看出是哪个出口，所以它是必填的（见 server 的校验）。
	Name string `json:"name"`
	// Match / Conditions 分支的附加条件：all=全部满足（默认）/ any=任一满足。
	// 条件为空表示无附加条件——所属规则命中它就命中，可当兜底分支（放最后）。
	Match      string      `json:"match"`
	Conditions []Condition `json:"conditions"`
	// TemplateRef 这个分支用哪个模板渲染。
	TemplateRef string `json:"templateRef"`
	// Targets 这个分支发给谁；留空回落到接收器的 DefaultTargets（与规则级同口径）。
	Targets []string `json:"targets"`
}

// MessageTemplate 一个消息模板。
//
// 模板只管**把字段拼成对方平台认得的文本**，不承担任何分流判断——
// 该发不该发、发给谁，全部由消息规则决定（见 WebhookRule）。同一件事有两处能改，
// 用户就永远说不清"消息没发出去"是规则没命中还是模板里的条件没成立。
//
// 模板语法是 Go 标准库 text/template：{{.字段}} 取值、{{range}} 遍历数组。
// 选它而不是自造一套占位符替换，是因为聚合型载荷（一条消息带 N 条记录）必须能循环——
// 纯占位符替换表达不出"把 items 里每一条各渲染一行"，而这正是真实场景里最常见的一种消息。
//
// 刻意**不**引入 sprig 之类的模板函数库：模板正文可以在面板里编辑，
// 而 sprig 带 env / expandenv / getHostByName，等于给模板编辑者一条读取
// MANTOU_MASTER_KEY 与探测内网的通路。可用函数是手工挑选的一小组纯函数
// （见 webhook 模块的 funcMap），只做取值与格式化，不碰环境、文件与网络。
type MessageTemplate struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Note   string `json:"note"`
	Format string `json:"format"` // text=纯文本 / markdown=Markdown（钉钉、企业微信均支持）
	Title  string `json:"title"`  // markdown 格式的标题（钉钉必需）；也支持模板语法
	Body   string `json:"body"`   // 模板正文

	// TitleStyle markdown 模式下标题以什么样式插进正文：h1/h2/h3/bold/none。
	//
	// 为什么需要这个字段：钉钉的 markdown.title **只用于会话列表里的那行预览**，
	// 消息气泡里根本不显示；企业微信的 markdown 连 title 字段都没有。也就是说
	// 光填「标题」的用户，发出去的消息里是看不到标题的——这是个纯粹的困惑来源。
	// 于是标题要真正出现在正文里，而"用几号标题、要不要只加粗"是审美问题，
	// 不该由代码替用户定死，所以做成一个选项。none = 只当推送预览标题（老行为）。
	TitleStyle string `json:"titleStyle"`

	Updated int64 `json:"updated"`
}

// MarkdownTitleStyles 标题样式的全部取值，顺序即面板下拉的顺序。
// DefaultMarkdownTitleStyle 是留空时的取值：多数人填标题就是想让它显眼，
// 三级标题在钉钉和企业微信里都是"比正文大一号且加粗"，不至于像 # 那样撑满一行。
var MarkdownTitleStyles = []string{"h1", "h2", "h3", "bold", "none"}

const DefaultMarkdownTitleStyle = "h3"

// ValidMarkdownTitleStyle 判断标题样式是否受支持。
func ValidMarkdownTitleStyle(s string) bool {
	for _, v := range MarkdownTitleStyles {
		if v == s {
			return true
		}
	}
	return false
}

// NotifyTarget 一个出站通知目标。
//
// 三种内置类型覆盖了自托管场景的绝大多数用法：
//   - dingtalk 钉钉自定义机器人（支持加签）
//   - wecom    企业微信群机器人
//   - http     自定义 HTTP 请求（请求体也是模板，可对接任意接收方）
//
// 飞书与 Telegram 的适配器留待后续：三者的差别只是 URL 与请求体结构，
// 适配层是一个函数，加一种类型不动其它任何代码。
type NotifyTarget struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Enabled bool   `json:"enabled"`
	Type    string `json:"type"` // dingtalk / wecom / http
	Note    string `json:"note"`

	// URL 机器人地址（钉钉、企业微信）或目标地址（自定义 HTTP）。
	//
	// **整段加密落盘**（见 aadNotifyURL）：钉钉与企业微信把 access_token 直接放在 query 里，
	// 这个 URL 本身就是凭证——拿到它的人可以往群里发任意消息。
	// 代价是 config.json 里看不到主机名了，故 Name/Type 保持明文，排障时靠它们定位条目。
	URL string `json:"url,omitempty"`
	// Secret 钉钉机器人「加签」密钥（以 SEC 开头）。留空表示该机器人未开启加签。加密落盘。
	Secret string `json:"secret,omitempty"`

	// ---- type=http 专用 ----
	Method      string            `json:"method"`      // POST（默认）/ PUT
	ContentType string            `json:"contentType"` // 默认 application/json
	Headers     map[string]string `json:"headers"`     // 附加请求头；值加密落盘（可能含 Authorization）
	// BodyTemplate 请求体模板；留空则发 {"text":"<渲染结果>"}。
	// 模板里可用 {{.message}} 取渲染结果，以及内部事件的全部字段。
	BodyTemplate string `json:"bodyTemplate"`

	// ---- 群机器人可选项 ----
	AtMobiles []string `json:"atMobiles"` // @ 指定手机号（钉钉、企业微信通用）
	AtAll     bool     `json:"atAll"`     // @ 全体成员

	// TimeoutSec 单次投递超时（秒）；≤0 用 DefaultNotifyTimeoutSec。
	TimeoutSec int `json:"timeoutSec"`
	// Retry 投递失败后的重试次数；≤0 表示不重试，上限 MaxNotifyRetry。
	// 重试队列在内存里，有界；重试仍失败则记一条执行日志（用户的存储决策）。
	Retry int `json:"retry"`

	// 列表上的「最近投递」与成功/失败计数不在这里：它们只在内存里（见 internal/runstats）。
	// 一条入站消息扇出到 N 个目标就是 N 次回写，频率由投递量决定；而这几个数只有列表页
	// 在看，全项目没有任何逻辑读它们。
}

// 出站投递的默认值与上限。
//
// 超时 10 秒：群机器人正常在百毫秒级返回，10 秒已足够覆盖一次网络抖动；
// 再长会让重试队列里的任务长时间占着 worker。上限 120 秒留给慢的自建接收端。
//
// 重试 2 次（合计 3 次投递）：能救回绝大多数瞬时失败（限流、连接重置），
// 又不至于在对方持续故障时把同一条消息放大成一串。上限 10。
const (
	DefaultNotifyTimeoutSec = 10
	MaxNotifyTimeoutSec     = 120
	DefaultNotifyRetry      = 2
	MaxNotifyRetry          = 10
)

// 单个通知目标内部的规模上限。
//
// 这几项以前是没有的：条数与长度都不限，于是一条目标可以带着任意多个请求头、
// 任意长的请求体模板存进 config.json，之后每次快照都照样复制一份。
// 面板入口的请求体上限（panelBodyLimit）只能挡住"单次保存不超过 1MB"，
// 挡不住"存 50 条这样的目标"——真正的界就是这里。
//
// 取值都留得比实际用量宽一档，宁可挡不住一个写得离谱的配置，也不要卡住一个正常的：
//   - 请求头 20 条：自建接收端常见是 1～3 条（Authorization、追踪 ID），20 条已经很宽。
//   - 头名 64 字节：HTTP 头名实际都在 40 字节以下。
//   - 头值 4096 字节：留给带一堆声明的 JWT，那种能到两三千字节。
//   - 请求体模板 16KB：写得最细的 JSON 模板也就几 KB；渲染结果另有 tmplx.MaxRenderBytes 管着。
//   - @手机号 100 个：群机器人本身就不适合 @ 这么多人，再多是填错了。
const (
	MaxNotifyHeaders         = 20
	MaxNotifyHeaderKeyLen    = 64
	MaxNotifyHeaderValueLen  = 4096
	MaxNotifyBodyTemplateLen = 16 << 10
	MaxNotifyAtMobiles       = 100
	MaxNotifyAtMobileLen     = 64
)

// ValidMappingName 判断字段映射名是否可以安全地出现在 {{.名字}} 里。
//
// text/template 的字段名只接受"字母 / 数字 / 下划线"，且不能以数字开头；
// 它对"字母"的判定走 unicode.IsLetter，所以汉字是合法的（{{.消息类型}} 能解析），
// 但空格、点号、连字符、括号都会让模板在解析期直接报错。
//
// 放在 config 包是为了让 API 校验与模块编译共用同一份判定：
// 若两边各写一套，就会出现"界面存得下、运行时渲染不出来"的缺口。
func ValidMappingName(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for i, r := range s {
		switch {
		case r == '_':
		case r >= '0' && r <= '9':
			if i == 0 {
				return false
			}
		case isTemplateLetter(r):
		default:
			return false
		}
	}
	return true
}

// isTemplateLetter 与 text/template 词法分析器对"字母"的判定保持一致（unicode.IsLetter）。
// 单独成函数只为把这个约定写在一处：改这里就等于改了模板里能用什么字段名。
func isTemplateLetter(r rune) bool { return unicode.IsLetter(r) }
