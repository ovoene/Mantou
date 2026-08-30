package server

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"mantou/internal/auth"
	"mantou/internal/config"
	"mantou/internal/modules/wol"
	"mantou/internal/runstats"
)

// childToggle 描述一个可单独启停的子项（仅 Web 服务子项使用），用于审计时区分父/子开关。
type childToggle struct {
	id      string
	name    string
	enabled bool
}

// resource 描述一类可增删改查的配置资源，通过闭包访问其在 Config 中的切片。
type resource[T any] struct {
	get   func(*config.Config) []T
	set   func(*config.Config, []T)
	id    func(*T) string
	setID func(*T, string)
	list  func([]T) []T
	// rows 可选：把列表整成与 T 不同的返回形状。
	//
	// 用于给列表补上「不在配置里」的字段——列表页显示的统计数字（最近一次、累计次数）
	// 存在内存里、不是配置的一部分（见 internal/runstats），所以它们没法作为 T 的字段
	// 直接被序列化出去。设了 rows 就用它的返回值应答，list 那一步照旧先跑
	//（凭证脱敏在那里做，顺序不能倒过来）。
	rows      func([]T) any
	normalize func(*T)
	validate  func(*config.Config, T) error
	// validateDelete 删除前的校验，留空表示删除无条件放行（多数资源如此）。
	//
	// 与 validate 分开是因为两者拦的不是同一件事：validate 看的是"这份配置本身合不合法"，
	// 而这里看的是"别人还在用它吗"。只给 validate 挂钩子的话，被"无法禁用"挡住的用户
	// 换成点删除就绕过去了——而删除比禁用更彻底，配置里连痕迹都不剩。
	validateDelete func(*config.Config, T) error
	// maxCount 条数上限，0 表示不限。只拦新增（POST），不拦编辑与删除：
	// 已经存在的超量配置（从旧版本升级、或手工编辑而来）仍要能被编辑和删掉，
	// 否则用户为了减少条目反而先被上限堵住，无路可走。
	maxCount int
	// afterCreate 资源创建成功后触发的副作用（如 DDNS 首次同步）。
	// 返回非致命告警 warning：即使 err 非 nil 也视为创建成功，仅把告警透传给前端提示，
	// 让用户在创建页即看到首次同步结果（成功或失败），而不必事后到列表里手动「立即运行」。
	afterCreate func(id string) (warning string, err error)
	// afterDelete 条目删除后触发的清理，参数是被删掉那条的 ID。
	//
	// 目前只有一个用途：把它在内存统计表里的那条记录删掉（见 runstats.Store.Forget）。
	// 不做这件事也不会出错——那张表有条数上限、满了会淘汰最久没动静的——但"反复新增
	// 又删除"会一直往表里堆再也不会有人看的键，白占额度。
	afterDelete func(id string)
	// 审计日志相关：设置了 modLabel 的模块输出「动作 模块 下 条目」格式的中文审计日志，
	// 否则沿用通用「新建/保存/删除资源」。detail 追加额外上下文（如域名列表）；childItems
	// 用于 Web 服务这类「父项含可单独启停子项」的模块，以区分父/子开关。
	modLabel   string
	itemName   func(*T) string
	detail     func(*T) string
	childItems func(*T) []childToggle
	// enabled 读取条目的启用开关，用于审计日志区分「启用/禁用」与普通「保存」。
	// 留空表示该资源没有启用开关（凭证、ACME 账户即如此），此时编辑一律记「保存」。
	//
	// 这里刻意用显式闭包而不是反射取 Enabled 字段：反射版本对「类型没有该字段」
	// 与「字段值为 false」返回同一种零值，靠额外的 ok 布尔区分，编译期完全不检查；
	// 给某个资源加上 Enabled 字段却忘了它会不会被审计到，是无声的行为变化。
	// 显式闭包把这件事变成一行可读的代码，且字段改名时编译器会直接报错。
	enabled func(*T) bool
	// setEnabled 写入条目的启用开关。设置了它的资源会多注册一个
	// POST <base>/:id/toggle 轻量端点，供列表里那个开关调用（见 registerCRUD 末尾）。
	// 留空则不注册，列表若有开关就只能走整行 PUT。
	setEnabled func(*T, bool)
}

// logOp 输出一条「动作 模块 下 条目」格式的 info 级审计日志。
// 程序日志页直接展示原始 slog 文案（不做 i18n 翻译），故此处用中文硬编码；
// 同时附带 module/id/name 结构化字段便于检索。
func (s *Server) logOp(verb, modLabel, id, itemName, extra string) {
	if s.deps.Log == nil {
		return
	}
	msg := verb + " " + modLabel + " 下 " + itemName
	if extra != "" {
		msg += extra
	}
	s.deps.Log.Info(msg, "module", modLabel, "id", id, "name", itemName)
}

// childMap 将子项列表按 ID 建索引，便于比对启用状态变化。
func childMap(items []childToggle) map[string]childToggle {
	m := make(map[string]childToggle, len(items))
	for _, c := range items {
		m[c.id] = c
	}
	return m
}

// detailOf 返回条目的额外审计上下文（如域名列表），无则空串。
func detailOf[T any](r resource[T], item *T) string {
	if r.detail != nil {
		return r.detail(item)
	}
	return ""
}

// enabledOf 读取条目的启用状态；第二个返回值为 false 表示该资源没有启用开关。
func enabledOf[T any](r resource[T], item *T) (bool, bool) {
	if r.enabled == nil || item == nil {
		return false, false
	}
	return r.enabled(item), true
}

// auditUpdate 输出编辑（PUT）的审计日志：优先记录父项启用/禁用，其次记录子项启用/禁用，
// 若启用状态均未变化则记录普通「保存」。
func auditUpdate[T any](s *Server, r resource[T], id string, old, item *T) {
	name := r.itemName(item)
	extra := ""
	if r.detail != nil {
		extra = r.detail(item)
	}
	oldEn, oldOK := enabledOf(r, old)
	newEn, newOK := enabledOf(r, item)
	parentEnChanged := oldOK && newOK && oldEn != newEn

	if r.childItems != nil {
		oldMap := childMap(r.childItems(old))
		for _, c := range r.childItems(item) {
			oc, ok := oldMap[c.id]
			if ok && oc.enabled != c.enabled {
				verb := "启用"
				if !c.enabled {
					verb = "禁用"
				}
				s.logOp(verb, r.modLabel, id, name+" 的子项 "+c.name, "")
			}
		}
	}

	if parentEnChanged {
		verb := "启用"
		if !newEn {
			verb = "禁用"
		}
		s.logOp(verb, r.modLabel, id, name, extra)
		return
	}
	// 未改动启用状态：记录普通保存（附模块名与条目名，便于审计）。
	s.logOp("保存", r.modLabel, id, name, extra)
}

// normalizeBackendURL 若地址缺少协议前缀（未以 http:// 或 https:// 开头），
// 自动补全为 http://：避免「只填域名 / IP+端口」时拼出的链接跳转到当前页、
// 以及反代 / 重定向目标无法被解析。已带协议的地址原样返回。
func normalizeBackendURL(u string) string {
	u = strings.TrimSpace(u)
	if u == "" {
		return u
	}
	if strings.Contains(u, "://") {
		return u
	}
	return "http://" + u
}

func normalizeWebService(ws *config.WebService) {
	for i := range ws.Children {
		ch := &ws.Children[i]
		if ch.TLSMinVersion == "" {
			ch.TLSMinVersion = "1.2"
		}
		// 启用 TLS 即强制开启 HTTPS 跳转（面板把该开关锁成开启状态，此处兜住直接调 API 的情况）。
		if ch.TLS {
			ch.RedirectHTTPS = true
		}
		// Basic 认证口令只存 bcrypt 哈希：面板提交的是明文（用户新设或改口令），
		// 而"没改口令"时提交回来的就是已存的哈希，故按是否已是哈希决定要不要再哈希一次。
		// 哈希失败（bcrypt 上限 72 字节）时刻意保留明文原样——由 validateWebService 据此
		// 给出"口令过长"的明确报错，而不是在这里默默清空或落一个假哈希。
		if ch.Access.BasicAuthPass != "" && !auth.IsHash(ch.Access.BasicAuthPass) {
			if hash, err := auth.HashPassword(ch.Access.BasicAuthPass); err == nil {
				ch.Access.BasicAuthPass = hash
			}
		}
		// 后端地址（反代上游 / 重定向目标）自动补全 http:// 前缀：
		// 只填域名或 IP+端口 时也能正确跳转与解析。
		for j := range ch.Upstreams {
			ch.Upstreams[j].URL = normalizeBackendURL(ch.Upstreams[j].URL)
		}
		if ch.Type == "redirect" {
			ch.Redirect.Target = normalizeBackendURL(ch.Redirect.Target)
		}
	}
}

// webChildCount 配置里那个 Web 服务当前有几个子项；新建（ID 尚不存在）时为 0。
// 供 validateWebService 判断这一次保存是不是在往上加。
func webChildCount(cfg *config.Config, id string) int {
	if id == "" {
		return 0
	}
	for i := range cfg.WebServices {
		if cfg.WebServices[i].ID == id {
			return len(cfg.WebServices[i].Children)
		}
	}
	return 0
}

func validateWebService(cfg *config.Config, ws config.WebService, dataDir string) error {
	// 子项数上限。Web 服务这一块真正花钱的是子项而不是父项：每个反代子项各自持有一个
	// 连接池（MaxIdleConnsPerHost = 128），空闲连接数按子项数增长（原因见 config.MaxWebChildren）。
	//
	// 只拦"变多"，不拦"已经超了"：这个校验同时管着保存与启停子项两条路径
	//（见 registerCRUD 的 toggle 与 childItems）。若一律拒绝，一份手改过、一上来就超限的配置
	// 会连开关都动不了——而界面上唯一能减子项的地方就是编辑弹窗，保存又被这里拒掉，
	// 于是成了一个绕不出去的死结。与列表条数上限只拦 POST 是同一个道理。
	if n := len(ws.Children); n > config.MaxWebChildren && n > webChildCount(cfg, ws.ID) {
		return fmt.Errorf("子项数量超过上限 %d 条（当前 %d 条）", config.MaxWebChildren, n)
	}

	if ws.Enabled && ws.Port == cfg.Panel.Port {
		return fmt.Errorf("Web 服务端口 %d 与面板管理端口冲突，请改用其他端口", ws.Port)
	}

	// 同一（地址族, 端口）仅允许一个启用父项：
	// 前端保证唯一，但 API 可直接构造两个同端口父项；后端 Reload 会将其子项静默聚合进同一监听，
	// 可能使一个父项的 TLS 配置被另一父项覆盖，且 toggle 轻量路径会绕过跨父项一致性校验。
	// 故在保存与 toggle 两条路径共用的 validateWebService 内直接拒绝重复父项。
	if ws.Enabled && ws.Port > 0 {
		fam := normalizeWebFamily(ws.IPFamily)
		for _, other := range cfg.WebServices {
			if other.ID == ws.ID || !other.Enabled || other.Port != ws.Port {
				continue
			}
			if normalizeWebFamily(other.IPFamily) == fam {
				return fmt.Errorf("Web 服务端口 %d（地址族 %s）已被另一个启用的服务占用，同一（地址族, 端口）仅允许存在一个父项", ws.Port, fam)
			}
		}
	}

	var enabledTLS *bool
	for _, child := range ws.Children {
		// 域名写法在这里查（而不是在下面的"域名归属"块里）：那一块只看启用子项，
		// 而写错的域名不该因为子项当时是停用的就存进配置——它一旦被启用就是个死键。
		for _, d := range child.Domains {
			if err := checkRouteDomainSyntax(d); err != nil {
				return err
			}
		}
		switch child.TLSMinVersion {
		case "1.2", "1.3":
		default:
			return fmt.Errorf("TLS 最低版本 %q 无效，只允许 1.2 或 1.3（弱加密版本已禁用）", child.TLSMinVersion)
		}
		// Basic 认证：开关开着就必须有账号和口令，否则要么弹框却对空口令放行（假保护），
		// 要么谁都进不去。normalizeWebService 已把明文换成哈希，此时仍是明文只有一种可能：
		// 口令超过了 bcrypt 的 72 字节上限。
		if child.Access.BasicAuth {
			if child.Access.BasicAuthUser == "" || child.Access.BasicAuthPass == "" {
				return fmt.Errorf("已开启 Basic 认证的子项必须填写访问账号与访问口令")
			}
			if !auth.IsHash(child.Access.BasicAuthPass) {
				return fmt.Errorf("Basic 认证的访问口令过长（bcrypt 上限 72 字节），请改用更短的口令")
			}
		}
		if !child.Enabled {
			continue
		}
		if enabledTLS == nil {
			tlsEnabled := child.TLS
			enabledTLS = &tlsEnabled
			continue
		}
		if *enabledTLS != child.TLS {
			return fmt.Errorf("同一父项下启用的子项不得混用 HTTP 和 HTTPS")
		}
	}

	// 静态站点根目录安全校验：禁止空路径、系统根目录、数据目录（含 config.json 与证书私钥）。
	for _, child := range ws.Children {
		if !child.Enabled || child.Type != "static" {
			continue
		}
		if err := validateStaticRoot(child.Static.Root, dataDir); err != nil {
			return err
		}
	}

	// 跨父项校验：若其它启用的 Web 服务父项使用了相同端口，其启用子项的 TLS 设置必须与本父项一致，
	// 否则在 Reload 聚合到同一监听器时，非 TLS 子项的明文请求会在 TLS 监听器上握手失败、被静默打不开。
	if ws.Enabled && ws.Port > 0 {
		var refTLS *bool
		for _, ch := range ws.Children {
			if !ch.Enabled {
				continue
			}
			t := ch.TLS
			refTLS = &t
			break
		}
		for _, other := range cfg.WebServices {
			if other.ID == ws.ID || !other.Enabled || other.Port != ws.Port {
				continue
			}
			for _, ch := range other.Children {
				if !ch.Enabled {
					continue
				}
				if refTLS == nil || *refTLS != ch.TLS {
					return fmt.Errorf("Web 服务端口 %d 已被其它服务占用且 TLS 设置不一致，不得跨服务混用 HTTP 与 HTTPS", ws.Port)
				}
			}
		}
	}

	// 域名归属：同一端口上一个域名只能属于一件东西，面板域名在任何端口上都不让别人用。
	// 刻意**不**查"同域名跨端口重复"：端口 80 上一条跳 HTTPS 的重定向 + 端口 443 上真正的
	// 站点，用的本来就是同一个域名，全局唯一会把这种最常见的配置直接判死（见 domains.go）。
	if ws.Enabled && ws.Port > 0 {
		seen := make(map[string]bool)
		for _, ch := range ws.Children {
			if !ch.Enabled {
				continue
			}
			for _, d := range ch.Domains {
				key := strings.ToLower(strings.TrimSpace(d))
				if key == "" {
					continue
				}
				if seen[key] {
					return fmt.Errorf("域名 %s 在本服务的多个子项里重复了；同一端口上一个域名只能指向一处", key)
				}
				seen[key] = true
				if err := checkPanelDomainReserved(cfg, key, "Web 服务"); err != nil {
					return err
				}
				if err := checkPortDomainFree(cfg, ws.Port, key, ws.ID, false); err != nil {
					return err
				}
			}
		}
	}

	// 「默认站点」只能有一个：没填访问域名的子项接管这个监听上所有对不上域名的请求
	// （见 webservice/listener.go 的 setDefault）。同一个父项下有两个这样的启用子项时，
	// 只有最后装载的那个能被访问到，另一个像不存在——而两边的配置页上都是绿的、
	// 状态与链接检测也都正常，界面上没有任何地方看得出被顶掉了。
	//
	// 只查本父项内部：同一（地址族, 端口）只允许一个启用父项（上面已拦），
	// 地址族不同的父项各起一个监听，各有一个默认站点是对的。
	if ws.Enabled && ws.Port > 0 {
		fallback := ""
		for _, ch := range ws.Children {
			if !ch.Enabled || !claimsDefaultSite(ch) {
				continue
			}
			if fallback != "" {
				return fmt.Errorf("本服务下有两个没填访问域名的启用子项（%s 与 %s）；没填域名表示接管这个端口上所有对不上域名的请求，只能有一个，请给其中一个填上访问域名",
					fallback, childLabel(ch))
			}
			fallback = childLabel(ch)
		}
	}

	// 消息路由可能与本服务共用端口（80 / 443 是面板、Web 服务、消息路由都想要的公共端口）。
	if ws.Enabled {
		if err := checkWebhookPortShare(cfg, ws); err != nil {
			return err
		}
	}

	// 禁用证书不可被引用：启用且开启 TLS 的子项，其域名必须至少被一张「已启用」证书覆盖；
	// 若仅被禁用证书覆盖（无启用证书覆盖），运行期将因拿不到证书而握手失败，故在此提前拒绝。
	if err := validateNoDisabledCertOnlyCoverage(cfg, ws); err != nil {
		return err
	}
	return nil
}

// validateNoDisabledCertOnlyCoverage 校验任一启用且开启 TLS 的子项：
// 其每个域名若被证书覆盖，则必须存在至少一张「已启用」证书覆盖它；
// 若某域名仅被禁用证书覆盖（无任何启用证书覆盖），则拒绝保存——满足「禁用证书不可被引用」。
func validateNoDisabledCertOnlyCoverage(cfg *config.Config, ws config.WebService) error {
	for _, ch := range ws.Children {
		if !ch.Enabled || !ch.TLS {
			continue
		}
		for _, d := range ch.Domains {
			domain := strings.TrimSpace(d)
			if domain == "" {
				continue
			}
			enabledCovers := false
			disabledCovers := false
			for i := range cfg.Certs {
				c := &cfg.Certs[i]
				if !certCoversDomain(domain, c.Domains) {
					continue
				}
				if c.Enabled {
					enabledCovers = true
				} else {
					disabledCovers = true
				}
			}
			if disabledCovers && !enabledCovers {
				return fmt.Errorf("子项域名 %q 仅被已禁用的证书覆盖，无法启用 TLS；请先启用对应证书，或改用覆盖该域名的已启用证书", domain)
			}
		}
	}
	return nil
}

// validateStaticRoot 校验静态站点根目录，防止通过静态服务暴露系统敏感目录
// （尤其是 data/ 下的 config.json 与证书私钥，以及系统根目录）。
//
// dataDir 是本进程实际使用的数据目录。必须按它比一次而不是只比 "/data"：
// 后者只在容器镜像里成立，原生部署的数据目录可以在任何地方（--data ./data、
// D:\mantou\data），那道闸于是等于只在容器里生效。
func validateStaticRoot(root, dataDir string) error {
	if strings.TrimSpace(root) == "" {
		return fmt.Errorf("静态站点根目录不能为空")
	}
	clean := filepath.Clean(root)
	// 比较前统一成正斜杠：Windows 上 filepath.Clean("/") 得到的是 `\`，
	// 直接和 "/" 比等于这几条在 Windows 上一条都不生效。
	slash := filepath.ToSlash(clean)
	switch slash {
	case "/", ".", "..":
		return fmt.Errorf("静态站点根目录不能是系统根目录")
	}
	// 盘符根同样是系统根：C:\ 与 C:（Clean 后成 "C:."，即"C 盘的当前目录"）都算。
	//
	// 去掉盘符后先统一成正斜杠再比，别把 filepath.Separator 写进 case 列表：
	// 那个常量在 Linux 上就等于 "/"，与后面那个字面量是同一个值，编译期直接报
	// duplicate case——本机（Windows，分隔符是 \）编得过，交叉编 linux/amd64 才炸。
	if vol := filepath.VolumeName(clean); vol != "" {
		switch filepath.ToSlash(strings.TrimPrefix(clean, vol)) {
		case "", ".", "/":
			return fmt.Errorf("静态站点根目录不能是系统根目录")
		}
	}
	const dataDirErr = "静态站点根目录不能是数据目录、也不能包含数据目录（那里有配置与证书私钥）"
	// 容器镜像里数据目录固定挂在 /data，这一条对任何平台都先拦一道。
	if slash == "/data" || strings.HasPrefix(slash, "/data/") {
		return fmt.Errorf("%s", dataDirErr)
	}
	if dataDir != "" {
		// 两个方向都拦：根目录落在数据目录里面（直接暴露），
		// 以及数据目录落在根目录里面（把整个项目目录当站点根，data/ 成了它的子路径）。
		if pathContains(dataDir, clean) || pathContains(clean, dataDir) {
			return fmt.Errorf("%s", dataDirErr)
		}
	}
	return nil
}

// pathContains 判断 target 是不是 base 本身或它下面的东西。两边都取绝对路径再比，
// Windows 上按不区分大小写处理。
func pathContains(base, target string) bool {
	abs := func(p string) string {
		if a, err := filepath.Abs(p); err == nil {
			return a
		}
		return filepath.Clean(p)
	}
	b, t := abs(base), abs(target)
	if runtime.GOOS == "windows" {
		b, t = strings.ToLower(b), strings.ToLower(t)
	}
	return b == t || strings.HasPrefix(t, b+string(filepath.Separator))
}

// normalizeWebFamily 将 Web 服务地址族归一化为聚合键（与 webservice 模块 Reload 的聚合口径一致）：
// v4/v6 原样返回，其余（含空、both、未知）归为 both。用于「同一（地址族, 端口）仅允许一个父项」校验。
func normalizeWebFamily(f string) string { return config.NormalizeIPFamily(f) }

// claimsDefaultSite 这个子项会不会接管「对不上域名的请求」。
// 判据与运行期完全一致（见 webservice/listener.go）：一个域名都没填，或者填的域名
// 去掉空白后是空串——后者是手改配置或复制粘贴留下的空行，看起来填了，实际就是没填。
func claimsDefaultSite(ch config.WebChild) bool {
	if len(ch.Domains) == 0 {
		return true
	}
	for _, d := range ch.Domains {
		if strings.TrimSpace(d) == "" {
			return true
		}
	}
	return false
}

// childLabel 子项在报错文案里的称呼。备注是用户自己起的名字，最认得出来；
// 没填备注就退到 ID，总比一句"某个子项"有用。
func childLabel(ch config.WebChild) string {
	if note := strings.TrimSpace(ch.Note); note != "" {
		return "「" + note + "」"
	}
	return ch.ID
}

// validateForward 校验单条端口转发规则。重点检查 Bind：若指定监听绑定地址，
// 必须是合法 IP（如 127.0.0.1），避免误填主机名导致监听失败；留空仍表示监听所有网卡。
func validateForward(_ *config.Config, r config.ForwardRule) error {
	if r.ListenPort < 1 || r.ListenPort > 65535 {
		return fmt.Errorf("监听端口需在 1-65535 之间")
	}
	if r.TargetPort < 1 || r.TargetPort > 65535 {
		return fmt.Errorf("目标端口需在 1-65535 之间")
	}
	// 端口范围校验（ListenPortEnd 为 0 表示单端口，不参与范围判定）。
	// 这些都是 expandRule 会「静默兜底」的情形——终点越界被夹、终点小于起点被当单端口、
	// 递增目标越过 65535 的尾部端口被直接跳过；兜底能防崩，却让用户配了一整段、实际只生效
	// 一截而毫无提示。保存这一关按同样的规则明确拦下，把静默截断换成一句能照着改的报错。
	if r.ListenPortEnd != 0 {
		if r.ListenPortEnd < 1 || r.ListenPortEnd > 65535 {
			return fmt.Errorf("监听结束端口需在 1-65535 之间")
		}
		if r.ListenPortEnd < r.ListenPort {
			return fmt.Errorf("监听结束端口不能小于起始端口")
		}
		span := r.ListenPortEnd - r.ListenPort
		if span+1 > config.MaxForwardRangePorts {
			return fmt.Errorf("监听端口范围一次最多 %d 个", config.MaxForwardRangePorts)
		}
		// 递增映射：目标端口 = 目标起点 + 偏移，尾部越过 65535 会被静默丢弃；多对一恒等于目标端口，不受影响。
		if !r.SameTargetPort && r.TargetPort+span > 65535 {
			return fmt.Errorf("递增映射的目标端口段会越过 65535（起点 %d + 跨度 %d），请改用多对一或缩小范围", r.TargetPort, span)
		}
	}
	if strings.TrimSpace(r.TargetHost) == "" {
		return fmt.Errorf("目标地址不能为空")
	}
	if strings.TrimSpace(r.Protocol) != "" {
		switch strings.TrimSpace(r.Protocol) {
		case "tcp", "udp", "both":
		default:
			return fmt.Errorf("协议仅支持 tcp/udp/both")
		}
	}
	if b := strings.TrimSpace(r.Bind); b != "" {
		if net.ParseIP(b) == nil {
			return fmt.Errorf("绑定地址（bind）需为合法 IP，如 127.0.0.1；留空表示监听所有网卡")
		}
	}
	return nil
}

// normalizeWOL 规范化网络唤醒设备的保存请求。
//
//   - MAC 统一规整为大写冒号写法（AA:BB:CC:DD:EE:FF）。用户可以按 XX:XX 或 XX-XX 任意写法录入，
//     甚至带上中文输入法的全角分隔符（见 wol.NormalizeMAC），落盘只保留一种形式，
//     列表展示、日志与审计才不会同一台设备出现多种写法。解析不通过时原样保留，
//     由 validateWOL 报错，不静默改写用户输入。
//   - 「时间范围」模式把发包次数归零：该模式下发包密度只由发送间隔决定，次数不参与计算。
//     归零同时充当配置迁移的「已迁移」标记（见 config.migrateWOL）——若新写入的条目仍带着
//     次数，下次启动加载时会被误判为旧版配置而再换算一次间隔。
//     反向不清空发送间隔：用户在两种方式之间来回切换时，间隔仍是原来那个，不至于被抹成 0。
//   - 「固定时间」模式保证次数至少为 1：一秒内发 0 个包等于没开，是无意义状态。
func normalizeWOL(d *config.WOLDevice) {
	d.MAC = wol.NormalizeMAC(d.MAC)
	// 网卡名首尾空白必须去掉：它要和 net.Interface.Name 精确比对，
	// 一个尾随空格就会让「指定网卡」变成「网卡不存在」，而界面上看不出区别。
	d.Interface = strings.TrimSpace(d.Interface)
	if d.Schedule.Mode == "range" {
		d.Schedule.Count = 0
	} else if d.Schedule.Count < 1 {
		d.Schedule.Count = 1
	}
}

// validateWOL 校验网络唤醒设备：MAC 可解析、端口范围、广播地址合法性，以及定时唤醒参数。
//
// 「往哪发」那三项（MAC / 广播地址 / 端口，外加网卡名长度）委托给 wol.ValidateTarget：
// 同一套口径还要用在「配置加载与整份导入之后重新校验」上（见 app.SanitizeWOLDevices），
// 两处若各写一份，就会出现「接口拦得住、导入拦不住」的缺口。
//
// MAC 在保存时就拦下来：否则一个写错的 MAC 要等到真正唤醒（或第一次定时触发）才浮现，
// 表现为列表里一条「失败: MAC 地址格式无效」，而用户在编辑页看不到任何异常。
// 代价是历史配置里若存着空/坏 MAC 的设备，在改好 MAC 之前无法再保存该条（含列表里的启停开关）——
// 这比留着一台注定唤不醒的设备要好。
//
// 定时唤醒的字段只在其启用时校验：关掉调度后，表单里残留的默认值不该阻塞保存。
// 两种触发方式各自只校验自己用得到的字段（见 config.WOLSchedule）：
// 固定时间用「时间 + 一秒内发包次数」，时间范围用「起止时间 + 发送间隔」。
func validateWOL(_ *config.Config, d config.WOLDevice) error {
	if err := wol.ValidateTarget(d); err != nil {
		return err
	}
	if !d.Schedule.Enabled {
		return nil
	}
	if d.Schedule.CalendarEnabled {
		if d.Schedule.StartDate == "" || d.Schedule.EndDate == "" {
			return fmt.Errorf("启用日历后请选择执行日期或日期范围")
		}
		if _, err := time.Parse("2006-01-02", d.Schedule.StartDate); err != nil {
			return fmt.Errorf("定时开始日期需为 YYYY-MM-DD 格式")
		}
		if _, err := time.Parse("2006-01-02", d.Schedule.EndDate); err != nil {
			return fmt.Errorf("定时结束日期需为 YYYY-MM-DD 格式")
		}
		if d.Schedule.EndDate < d.Schedule.StartDate {
			return fmt.Errorf("定时结束日期不能早于开始日期")
		}
	}
	if d.Schedule.Mode == "range" {
		if !wol.ValidClockHM(d.Schedule.Start) || !wol.ValidClockHM(d.Schedule.End) {
			return fmt.Errorf("时间范围的开始时间与结束时间需为 HH:MM 格式")
		}
		if d.Schedule.IntervalSec < 1 {
			return fmt.Errorf("时间范围模式的发送间隔至少为 1 秒")
		}
		if d.Schedule.IntervalSec > config.MaxWOLIntervalSec {
			return fmt.Errorf("发送间隔不能超过 %d 秒（24 小时）", config.MaxWOLIntervalSec)
		}
		return nil
	}
	if !wol.ValidClockHM(d.Schedule.Time) {
		return fmt.Errorf("固定时间需为 HH:MM 格式")
	}
	if d.Schedule.Count < 1 || d.Schedule.Count > config.MaxWOLWakeCount {
		return fmt.Errorf("固定时间模式下「一秒内发包次数」需在 1-%d 之间", config.MaxWOLWakeCount)
	}
	return nil
}

// deviceRow 是网络唤醒列表返回的形状：配置里的字段，加上内存里的统计。
//
// 与消息路由那两处同一套做法（见 receiverRow / targetRow）：统计不在配置里
// （见 internal/runstats），只能在这一层拼上去。JSON 字段名与搬走之前完全一致。
type deviceRow struct {
	config.WOLDevice
	LastWakeAt int64  `json:"lastWakeAt"`
	LastResult string `json:"lastResult"`
	WakeCount  int64  `json:"wakeCount"`
}

// wolResource 网络唤醒的 CRUD 定义。单独成函数是为了让测试能拿到与线上**同一份**定义：
// 若在测试里照抄一遍字段，日后改了线上却忘了改测试，测试照样全绿。
//
// stats 可以是 nil：runstats.Store 的方法对 nil 接收者是安全的（写入空操作、读出零值），
// 于是不带统计库的测试也能用这份定义，列表里那三个数一律是 0。
func wolResource(stats *runstats.Store) resource[config.WOLDevice] {
	return resource[config.WOLDevice]{
		get:      func(c *config.Config) []config.WOLDevice { return c.WOLDevices },
		set:      func(c *config.Config, v []config.WOLDevice) { c.WOLDevices = v },
		id:       func(t *config.WOLDevice) string { return t.ID },
		setID:    func(t *config.WOLDevice, id string) { t.ID = id },
		modLabel: "网络唤醒",
		enabled:  func(t *config.WOLDevice) bool { return t.Enabled },
		// 列表开关与消息路由共用同一个前端实现，故这里也走轻量 toggle 端点。
		setEnabled: func(t *config.WOLDevice, v bool) { t.Enabled = v },
		itemName:   func(t *config.WOLDevice) string { return t.Name },
		validate:   validateWOL,
		rows: func(source []config.WOLDevice) any {
			out := make([]deviceRow, len(source))
			for i := range source {
				st := stats.Wake(source[i].ID)
				out[i] = deviceRow{
					WOLDevice:  source[i],
					LastWakeAt: st.LastAt,
					LastResult: st.LastText,
					WakeCount:  st.Count,
				}
			}
			return out
		},
		afterDelete: func(id string) { stats.Forget(id) },
		// 条数上限：每台启用定时唤醒的设备各占一条常驻协程（原因见 config.MaxWOLDevices）。
		maxCount: config.MaxWOLDevices,
		// MAC 规整与「按触发方式清理无关字段」都放在 normalize，故新建与保存两条路径共用
		// （registerCRUD 的 POST / PUT 均先 normalize 再 validate）。
		normalize: normalizeWOL,
	}
}

// normalizeCert 规范化证书保存请求。
// ACME 证书的验证方式固定为 dns01：HTTP-01 从未实现且已从代码中移除，
// 这里在入口处统一改写，避免旧前端或直接调 API 写入一个永远走不通的死值
// （配置迁移只在加载时生效，无法覆盖运行期新写入的条目）。
func normalizeCert(c *config.Certificate) {
	if c.Method == "acme" {
		c.ACMEChallenge = "dns01"
	}
}

// validateCert 校验证书保存请求：禁用中的证书若正被面板或 Web 服务使用，
// 则拒绝保存，避免面板/反代因证书失效而启动失败；也避免「界面能禁用却在运行时被忽略」的割裂。
func validateCert(cfg *config.Config, cert config.Certificate) error {
	if !cert.Enabled {
		if used, mods := certInUse(cfg, cert.ID); used {
			return fmt.Errorf("该证书正被以下模块使用：%s，无法禁用", strings.Join(mods, "、"))
		}
	}
	return nil
}

// validateCertDelete 校验证书删除请求：正被使用的证书不许删。
//
// 这是 validateCert 那条「无法禁用」的另一半：只拦禁用的话，用户被挡住之后
// 点删除就绕过去了，而删除的后果更重——禁用至少还留着一条能改回来的记录，
// 删除之后面板/反代/消息路由下次启动直接找不到证书，且启用 HTTPS 后没有明文回落。
// 判定口径与禁用完全一致（同一个 certInUse），否则两条路径会给出互相矛盾的答案。
func validateCertDelete(cfg *config.Config, cert config.Certificate) error {
	if used, mods := certInUse(cfg, cert.ID); used {
		return fmt.Errorf("该证书正被以下模块使用：%s，无法删除。请先在对应模块里改用其它证书或关闭 HTTPS", strings.Join(mods, "、"))
	}
	return nil
}

// certCoversDomain 判断证书域名集合是否覆盖给定前端域名（支持 *.example.com 通配）。
// 与 cert 模块的 SNI 解析（Store.Resolve）保持一致：精确匹配，或一级通配匹配
// （前端域名 a.example.com 命中证书通配 *.example.com）。
func certCoversDomain(domain string, certDomains []string) bool {
	domain = strings.TrimSpace(domain)
	if domain == "" {
		return false
	}
	for _, cd := range certDomains {
		cd = strings.TrimSpace(cd)
		if cd == "" {
			continue
		}
		if cd == domain {
			return true
		}
		if strings.HasPrefix(cd, "*.") && wildcardOf(domain) == cd {
			return true
		}
	}
	return false
}

// certInUse 返回证书是否被面板、Web 服务或消息路由使用，以及使用它的模块名列表（用于提示用户）。
//   - 面板服务：Panel.HTTPS 启用且 CertID 指向该证书。
//   - Web 服务：任一启用父项下、启用且开启 TLS 的子项，其前端域名被该证书域名集合覆盖。
//   - 消息路由：Webhook.HTTPS 启用且 CertID 指向该证书。这一项必须在：
//     该模块启用 HTTPS 后没有明文回落，证书一被停用，所有第三方来源会同时静默失联。
func certInUse(cfg *config.Config, id string) (bool, []string) {
	var mods []string
	if cfg.Panel.HTTPS.Enabled && cfg.Panel.HTTPS.CertID == id {
		mods = append(mods, "面板服务")
	}
	if cfg.Webhook.HTTPS.Enabled && cfg.Webhook.HTTPS.CertID == id {
		mods = append(mods, "消息路由")
	}
	var certDomains []string
	for i := range cfg.Certs {
		if cfg.Certs[i].ID == id {
			certDomains = cfg.Certs[i].Domains
			break
		}
	}
	for _, ws := range cfg.WebServices {
		if !ws.Enabled {
			continue
		}
		for _, ch := range ws.Children {
			if !ch.Enabled || !ch.TLS {
				continue
			}
			covered := false
			for _, d := range ch.Domains {
				if certCoversDomain(d, certDomains) {
					covered = true
					break
				}
			}
			if covered {
				name := ws.Name
				if name == "" {
					name = ws.ID
				}
				mods = append(mods, fmt.Sprintf("Web 服务「%s」", name))
				break
			}
		}
	}
	return len(mods) > 0, mods
}

// wildcardOf 返回域名对应的一级通配形式（a.example.com → *.example.com），非域名返回空。
func wildcardOf(name string) string {
	name = strings.TrimSpace(name)
	for i := 0; i < len(name); i++ {
		if name[i] == '.' {
			return "*" + name[i:]
		}
	}
	return ""
}

func (s *Server) registerResourceRoutes(g *gin.RouterGroup) {
	registerCRUD(s, g, "credentials", resource[config.Credential]{
		get:      func(c *config.Config) []config.Credential { return c.Credentials },
		set:      func(c *config.Config, v []config.Credential) { c.Credentials = v },
		id:       func(t *config.Credential) string { return t.ID },
		setID:    func(t *config.Credential, id string) { t.ID = id },
		modLabel: "域名服务商凭证",
		itemName: func(t *config.Credential) string { return t.Name },
		// 凭证密钥属于敏感信息：列表接口返回脱敏占位，明文仅由编辑表单按 ID 取回；
		// 编辑保存时若某字段值仍是脱敏占位（前端未改动），由 normalize 还原为已存储的真实值，避免误覆盖。
		list: func(source []config.Credential) []config.Credential {
			out := append([]config.Credential(nil), source...)
			for i := range out {
				if len(out[i].Secrets) > 0 {
					masked := make(map[string]string, len(out[i].Secrets))
					for k := range out[i].Secrets {
						masked[k] = "******"
					}
					out[i].Secrets = masked
				}
			}
			return out
		},
		normalize: func(c *config.Credential) {
			if c.ID == "" || len(c.Secrets) == 0 {
				return
			}
			cfg := s.deps.Config.Snapshot()
			for _, existing := range cfg.Credentials {
				if existing.ID != c.ID {
					continue
				}
				for k, v := range c.Secrets {
					if v == "******" {
						if old, ok := existing.Secrets[k]; ok {
							c.Secrets[k] = old
						}
					}
				}
				return
			}
		},
	})
	registerCRUD(s, g, "ddns", resource[config.DDNSRule]{
		get:      func(c *config.Config) []config.DDNSRule { return c.DDNS },
		set:      func(c *config.Config, v []config.DDNSRule) { c.DDNS = v },
		id:       func(t *config.DDNSRule) string { return t.ID },
		setID:    func(t *config.DDNSRule, id string) { t.ID = id },
		modLabel: "动态域名DDNS",
		enabled:  func(t *config.DDNSRule) bool { return t.Enabled },
		itemName: func(t *config.DDNSRule) string { return t.Name },
		// 条数上限：每条启用中的规则各占一条常驻协程，且每一拍都向外发请求（原因见 config.MaxDDNSRules）。
		maxCount: config.MaxDDNSRules,
		// 启用/禁用时一并记录所管理的域名，便于审计「启用 动态域名 下 规则（域名：…）」。
		detail: func(t *config.DDNSRule) string {
			var ds []string
			for _, tg := range t.Targets {
				if tg.Domain != "" {
					ds = append(ds, tg.Domain)
				}
			}
			if len(ds) == 0 {
				return ""
			}
			return "（域名：" + strings.Join(ds, "、") + "）"
		},
		// 创建成功后立即执行首次同步：把首次同步结果（成功或失败）以 warning 透传给前端提示。
		afterCreate: func(id string) (string, error) {
			if s.deps.DDNS == nil {
				return "", nil
			}
			msg, err := s.deps.DDNS.RunOnce(id)
			if err != nil {
				// 首次同步失败：非致命，规则已保存；仅告警，提示用户检查凭证/网络。
				return "首次同步失败：" + err.Error(), err
			}
			// 启用中的规则其运行循环也会立即执行一次首同步，故此处 RunOnce 多半命中
			// 「IP 未变化」——这不代表首同步没做，统一归一化为清晰的「已完成」提示，
			// 避免用户误以为同步没发生。
			if strings.HasPrefix(msg, "IP 未变化") {
				ip := strings.TrimPrefix(msg, "IP 未变化: ")
				return "首次同步已完成（当前 IP 已生效：" + ip + "）", nil
			}
			if msg != "" {
				return "首次同步完成：" + msg, nil
			}
			return "首次同步已完成", nil
		},
	})
	registerCRUD(s, g, "webservices", resource[config.WebService]{
		get:       func(c *config.Config) []config.WebService { return c.WebServices },
		set:       func(c *config.Config, v []config.WebService) { c.WebServices = v },
		id:        func(t *config.WebService) string { return t.ID },
		setID:     func(t *config.WebService, id string) { t.ID = id },
		modLabel:  "Web 服务",
		enabled:   func(t *config.WebService) bool { return t.Enabled },
		itemName:  func(t *config.WebService) string { return t.Name },
		normalize: normalizeWebService,
		// 静态站点根目录要和本进程实际的数据目录比，所以这里得把它带进去。
		validate: func(cfg *config.Config, ws config.WebService) error {
			return validateWebService(cfg, ws, s.deps.DataDir)
		},
		// 条数上限：一个父项就是一条监听，且每次保存都要把涉及的监听重建一遍
		//（原因见 config.MaxWebServices）。子项数另有一道闸，见 validateWebService。
		maxCount: config.MaxWebServices,
		// 父项含可单独启停的子项：列出子项以便审计区分「启用 Web 服务 下 父项」与
		// 「启用 Web 服务 下 父项 的子项 子项名」。
		childItems: func(ws *config.WebService) []childToggle {
			out := make([]childToggle, 0, len(ws.Children))
			for _, ch := range ws.Children {
				nm := ch.Note
				if nm == "" {
					if len(ch.Domains) > 0 {
						nm = strings.Join(ch.Domains, "、")
					} else {
						nm = "子项"
					}
				}
				out = append(out, childToggle{id: ch.ID, name: nm, enabled: ch.Enabled})
			}
			return out
		},
	})
	// 子项数的上限不是"列表条数"，registerCRUD 的 maxCount 管不到它，但界面同样要把这个数
	// 说出来（写在「添加子项」按钮旁边，与消息路由的请求头按钮同一种做法），所以单独下发一条。
	s.setResourceCap("webservices/children", config.MaxWebChildren)
	registerCRUD(s, g, "forwards", resource[config.ForwardRule]{
		get:      func(c *config.Config) []config.ForwardRule { return c.Forwards },
		set:      func(c *config.Config, v []config.ForwardRule) { c.Forwards = v },
		id:       func(t *config.ForwardRule) string { return t.ID },
		setID:    func(t *config.ForwardRule, id string) { t.ID = id },
		modLabel: "端口转发",
		enabled:  func(t *config.ForwardRule) bool { return t.Enabled },
		itemName: func(t *config.ForwardRule) string { return t.Name },
		// 条数上限：每次保存都要把全部规则重建一遍（原因见 config.MaxForwardRules）。
		maxCount: config.MaxForwardRules,
		validate: validateForward,
	})
	registerCRUD(s, g, "wol", wolResource(s.deps.Stats))
	registerCRUD(s, g, "crontasks", resource[config.CronTask]{
		get:      func(c *config.Config) []config.CronTask { return c.CronTasks },
		set:      func(c *config.Config, v []config.CronTask) { c.CronTasks = v },
		id:       func(t *config.CronTask) string { return t.ID },
		setID:    func(t *config.CronTask, id string) { t.ID = id },
		modLabel: "计划任务",
		enabled:  func(t *config.CronTask) bool { return t.Enabled },
		itemName: func(t *config.CronTask) string { return t.Name },
		// 条数上限：成本在触发那一刻——每次执行结束都要串行回写一次运行态（原因见 config.MaxCronTasks）。
		maxCount: config.MaxCronTasks,
	})
	registerCRUD(s, g, "certs", resource[config.Certificate]{
		get:      func(c *config.Config) []config.Certificate { return c.Certs },
		set:      func(c *config.Config, v []config.Certificate) { c.Certs = v },
		id:       func(t *config.Certificate) string { return t.ID },
		setID:    func(t *config.Certificate, id string) { t.ID = id },
		modLabel: "SSL/TLS 证书",
		enabled:  func(t *config.Certificate) bool { return t.Enabled },
		itemName: func(t *config.Certificate) string { return t.Name },
		// 条数上限：每张启用中的证书常驻一份解析后的链与私钥，且另一头还有签发方的配额（原因见 config.MaxCerts）。
		maxCount: config.MaxCerts,
		// 启用/禁用时一并记录域名，便于审计「启用 证书 下 名称（域名：…）」。
		detail: func(t *config.Certificate) string {
			if len(t.Domains) == 0 {
				return ""
			}
			return "（域名：" + strings.Join(t.Domains, "、") + "）"
		},
		// 保存（新建/编辑）时校验：禁用中的证书若正被面板 HTTPS 引用则拒绝，
		// 避免面板自身因证书失效而启动失败。删除同理，且后果更重（见 validateCertDelete）。
		validate:       validateCert,
		validateDelete: validateCertDelete,
		normalize:      normalizeCert,
		list: func(source []config.Certificate) []config.Certificate {
			list := append([]config.Certificate(nil), source...)
			if s.deps.Cert == nil {
				return list
			}
			now := time.Now()
			for i := range list {
				certPath, keyPath, err := s.deps.Cert.Paths(list[i])
				if err == nil {
					list[i].CertPath = certPath
					list[i].KeyPath = keyPath
				}
				domains, notAfter, ok := s.deps.Cert.Info(list[i].ID)
				if !ok {
					list[i].Status = "missing"
					continue
				}
				list[i].Domains = domains
				list[i].NotAfter = notAfter.Unix()
				if now.After(notAfter) {
					list[i].Status = "expired"
				} else {
					list[i].Status = "valid"
				}
			}
			return list
		},
	})
	registerCRUD(s, g, "acme-accounts", resource[config.ACMEAccount]{
		get:      func(c *config.Config) []config.ACMEAccount { return c.ACMEAccounts },
		set:      func(c *config.Config, v []config.ACMEAccount) { c.ACMEAccounts = v },
		id:       func(t *config.ACMEAccount) string { return t.ID },
		setID:    func(t *config.ACMEAccount, id string) { t.ID = id },
		modLabel: "ACME 账户",
		itemName: func(t *config.ACMEAccount) string { return t.Name },
	})

	s.registerWebhookRoutes(g)
	s.registerActions(g)
}

// handleResourceLimits 下发各资源的条数上限，供页面在标题下方那句说明里写出确切数字。
//
// 只读注册时填好的那张表（见 registerCRUD），不带任何配置内容，因此也不泄露"现在有几条"。
func (s *Server) handleResourceLimits(c *gin.Context) {
	out := make(map[string]int, len(s.resourceCaps))
	for k, v := range s.resourceCaps {
		out[k] = v
	}
	respondOK(c, out)
}

// setResourceCap 往下发给界面的那张上限表里补一条。
//
// 多数上限由 registerCRUD 自己填（那里就是"列表最多几条"）。这个方法给的是**不是列表条数**
// 的上限——目前只有 Web 服务的子项数：它是父项内部的一道闸，registerCRUD 看不见它，
// 但界面同样要把这个数说出来，而"界面上写的数就是拦人的那个数"这条性质不该因为
// 上限的位置不同就走两套路子。
//
// 就地建表而不是只依赖 New()：本包里有若干测试直接用 &Server{deps: …} 拼壳子挂路由，
// 那条路径上这张表是 nil，而往 nil map 写会 panic——挂路由这一步 panic 掉的是整个测试进程。
func (s *Server) setResourceCap(name string, n int) {
	if n <= 0 {
		return
	}
	if s.resourceCaps == nil {
		s.resourceCaps = make(map[string]int, 8)
	}
	s.resourceCaps[name] = n
}

func registerCRUD[T any](s *Server, g *gin.RouterGroup, name string, r resource[T]) {
	base := "/" + name

	// 记一份给界面用（GET /api/meta/limits）：显示的数与下面新增时拦人的数是同一个，
	// 前端不另存常量。没有上限的资源不进这张表，界面上也就不会多出一句"最多 0 条"
	//（setResourceCap 里那个 n <= 0 就是这条）。
	s.setResourceCap(name, r.maxCount)

	g.GET(base, func(c *gin.Context) {
		// 只读快照：r.get 返回的切片直接指向共享配置，因此 r.list 的实现**必须**先复制
		// （现有两处都是 append([]T(nil), source...)），不得就地改写元素——否则会污染
		// 所有并发读者看到的配置。凭证脱敏正是这样：整体换一个新 map，而不是往原 map 里写。
		cfg := s.deps.Config.Snapshot()
		list := r.get(cfg)
		if r.list != nil {
			list = r.list(list)
		}
		if list == nil {
			list = []T{}
		}
		if r.rows != nil {
			respondOK(c, r.rows(list))
			return
		}
		respondOK(c, list)
	})

	g.POST(base, func(c *gin.Context) {
		var item T
		if err := c.ShouldBindJSON(&item); err != nil {
			respondError(c, http.StatusBadRequest, "请求参数无效")
			return
		}
		// 条数上限先拦：与其让一份注定拖垮面板的配置落盘、再靠用户自己发现，
		// 不如在新增这一步就说清上限是多少、现在有多少条。
		if r.maxCount > 0 {
			if n := len(r.get(s.deps.Config.Snapshot())); n >= r.maxCount {
				respondError(c, http.StatusBadRequest,
					fmt.Sprintf("数量已达上限 %d 条（当前 %d 条），请先删除不再使用的条目", r.maxCount, n))
				return
			}
		}
		if r.normalize != nil {
			r.normalize(&item)
		}
		if r.validate != nil {
			if err := r.validate(s.deps.Config.Snapshot(), item); err != nil {
				respondError(c, http.StatusBadRequest, err.Error())
				return
			}
		}
		newID, err := genID()
		if err != nil {
			respondError(c, http.StatusInternalServerError, "生成资源 ID 失败")
			return
		}
		r.setID(&item, newID)
		if err := s.deps.Config.Update(func(cfg *config.Config) {
			r.set(cfg, append(r.get(cfg), item))
		}); err != nil {
			respondError(c, http.StatusInternalServerError, "保存失败")
			return
		}
		s.afterChange()
		// 敏感操作审计：新建资源。设置了 modLabel 的模块输出「新增 模块 下 条目」，否则沿用通用「新建资源」。
		if s.deps.Log != nil {
			if r.modLabel != "" && r.itemName != nil {
				s.logOp("新增", r.modLabel, newID, r.itemName(&item), detailOf(r, &item))
			} else {
				s.deps.Log.Info("新建资源", "module", name, "id", newID)
			}
		}
		// 可选钩子：创建后执行首次同步等副作用。失败不回滚创建，仅以 warning 提示前端。
		if r.afterCreate != nil {
			if warn, herr := r.afterCreate(newID); herr != nil || warn != "" {
				respondOK(c, gin.H{"item": item, "warning": warn})
				return
			}
		}
		respondOK(c, item)
	})

	g.PUT(base+"/:id", func(c *gin.Context) {
		id := c.Param("id")
		var item T
		if err := c.ShouldBindJSON(&item); err != nil {
			respondError(c, http.StatusBadRequest, "请求参数无效")
			return
		}
		// ID 以地址里的那个为准，且要在校验之前就填好。
		// 校验普遍要靠 ID 把自己排除掉（端口占用、入站路径重复都是这种：与自己重名不算冲突），
		// 另有一些要靠 ID 去配置里找出这条现在长什么样（见 webChildCount）。ID 此时若还是空的，
		// 这些判断拿到的就是"这是一条新记录"——于是改一条服务却报它与自己端口冲突，
		// 或者一份已超限的配置怎么改都存不回去。请求体里通常也带着 id，但那是客户端给的，
		// 本就不该作为判断依据。
		r.setID(&item, id)
		if r.normalize != nil {
			r.normalize(&item)
		}
		if r.validate != nil {
			if err := r.validate(s.deps.Config.Snapshot(), item); err != nil {
				respondError(c, http.StatusBadRequest, err.Error())
				return
			}
		}
		var old T
		found := false
		if err := s.deps.Config.Update(func(cfg *config.Config) {
			list := r.get(cfg)
			for i := range list {
				if r.id(&list[i]) == id {
					old = list[i]
					list[i] = item
					found = true
					break
				}
			}
			r.set(cfg, list)
		}); err != nil {
			respondError(c, http.StatusInternalServerError, "保存失败")
			return
		}
		if !found {
			respondError(c, http.StatusNotFound, "资源不存在")
			return
		}
		s.afterChange()
		// 敏感操作审计：编辑/保存资源记入 info 级日志。
		// 设置了 modLabel 的模块输出「启用/禁用 模块 下 条目」或「保存 模块 下 条目」，
		// 并区分父项与子项开关（Web 服务）；否则沿用通用「保存资源」。
		if s.deps.Log != nil {
			if r.modLabel != "" && r.itemName != nil {
				auditUpdate(s, r, id, &old, &item)
			} else {
				s.deps.Log.Info("保存资源", "module", name, "id", id)
			}
		}
		respondOK(c, item)
	})

	// 列表里那个启用开关走这条轻量端点，而不是整行 PUT——与证书、Web 服务的开关同一个思路
	// （见 handleToggleCert）。只有声明了 setEnabled 的资源才注册。
	//
	// 为什么不让前端把整行原样回传：那份"整行"是页面当初加载到的，这中间这条配置可能
	// 已经在别处（另一个标签页、或直接调 API）被改过，回传就把那些改动一起覆盖回去了；
	// 而且列表接口里的凭证是脱敏的，整行回传还得靠占位符往返才不会把令牌写成 ******。
	// 只发一个 enabled，这两件事都不存在。
	if r.setEnabled != nil {
		g.POST(base+"/:id/toggle", func(c *gin.Context) {
			id := c.Param("id")
			var req struct {
				Enabled bool `json:"enabled"`
			}
			if err := c.ShouldBindJSON(&req); err != nil {
				respondError(c, http.StatusBadRequest, "请求参数无效")
				return
			}
			var item T
			var validErr error
			found := false
			// 先改再校验、不过就地回滚，保证落盘的状态始终合法（同 handleToggleWebServiceChild）。
			// 只在启用这一侧校验：禁用必须永远走得通，否则一份存得下却跑不起来的配置
			// 会把用户锁在"开着且报错"里，连关掉都做不到。
			if err := s.deps.Config.Update(func(cfg *config.Config) {
				list := r.get(cfg)
				for i := range list {
					if r.id(&list[i]) != id {
						continue
					}
					found = true
					was := !req.Enabled
					if r.enabled != nil {
						was = r.enabled(&list[i])
					}
					r.setEnabled(&list[i], req.Enabled)
					if req.Enabled && r.validate != nil {
						if err := r.validate(cfg, list[i]); err != nil {
							r.setEnabled(&list[i], was)
							validErr = err
						}
					}
					item = list[i]
					break
				}
				r.set(cfg, list)
			}); err != nil {
				respondError(c, http.StatusInternalServerError, "保存失败")
				return
			}
			if !found {
				respondError(c, http.StatusNotFound, "资源不存在")
				return
			}
			if validErr != nil {
				respondError(c, http.StatusBadRequest, validErr.Error())
				return
			}
			s.afterChange()
			// 审计动词是「启用/禁用」而非「保存」：列表上的操作不写保存日志，
			// 只有编辑弹窗里点保存才算一次保存（与证书、Web 服务的开关一致）。
			if s.deps.Log != nil {
				verb := "禁用"
				if req.Enabled {
					verb = "启用"
				}
				if r.modLabel != "" && r.itemName != nil {
					s.logOp(verb, r.modLabel, id, r.itemName(&item), detailOf(r, &item))
				} else {
					s.deps.Log.Info(verb+"资源", "module", name, "id", id)
				}
			}
			respondOK(c, gin.H{"id": id, "enabled": req.Enabled})
		})
	}

	g.DELETE(base+"/:id", func(c *gin.Context) {
		id := c.Param("id")
		// 删除前校验必须在 Update 之前：Update 一旦返回就已经落盘了，没有回滚。
		if r.validateDelete != nil {
			cfg := s.deps.Config.Snapshot()
			item, ok := findByID(r, cfg, id)
			if !ok {
				respondError(c, http.StatusNotFound, "资源不存在")
				return
			}
			if err := r.validateDelete(cfg, item); err != nil {
				respondError(c, http.StatusBadRequest, err.Error())
				return
			}
		}
		found := false
		var delName string
		if err := s.deps.Config.Update(func(cfg *config.Config) {
			list := r.get(cfg)
			out := make([]T, 0, len(list))
			for i := range list {
				if r.id(&list[i]) == id {
					found = true
					if r.itemName != nil {
						delName = r.itemName(&list[i])
					}
					continue
				}
				out = append(out, list[i])
			}
			r.set(cfg, out)
		}); err != nil {
			respondError(c, http.StatusInternalServerError, "删除失败")
			return
		}
		if !found {
			respondError(c, http.StatusNotFound, "资源不存在")
			return
		}
		if r.afterDelete != nil {
			r.afterDelete(id)
		}
		s.afterChange()
		// 敏感操作审计：删除资源记入 info 级日志。
		if s.deps.Log != nil {
			if r.modLabel != "" {
				s.logOp("删除", r.modLabel, id, delName, "")
			} else {
				s.deps.Log.Info("删除资源", "module", name, "id", id)
			}
		}
		respondOK(c, gin.H{"ok": true})
	})
}

// findByID 在配置快照里按 ID 找条目。返回的是结构体副本，只读用。
func findByID[T any](r resource[T], cfg *config.Config, id string) (T, bool) {
	list := r.get(cfg)
	for i := range list {
		if r.id(&list[i]) == id {
			return list[i], true
		}
	}
	var zero T
	return zero, false
}

func (s *Server) afterChange() {
	if s.deps.OnConfigChanged != nil {
		s.deps.OnConfigChanged()
	}
}

// genID 生成随机资源 ID；随机源不可用时返回错误，交由调用方按 500 处理，
// 避免退回到固定字符串使多条资源共用同一 ID。
func genID() (string, error) {
	b := make([]byte, 6)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
