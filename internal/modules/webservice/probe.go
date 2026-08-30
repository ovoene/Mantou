package webservice

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// 本文件是 webservice 的主动探测层：不依赖真实流量，按各父项的探测间隔周期性地
// 访问一次后端，把结果写进 linkStatus 供面板显示「前端 → 后端」是否通。
// linkStatus 的唯一写入方就在这里；真实请求路径刻意不回写它，避免高频写锁竞争。

// linkState 记录某子项最近的成功与失败访问，用于判定链接状态。
// LastOK / LastErr 为 Unix 毫秒；LastStatus 为最近一次失败时的 HTTP 状态码（无失败为 0）。
// 该状态现在由「周期主动探测」(runProbe) 写入，与真实流量、10/s 日志限速完全解耦。
type linkState struct {
	LastOK     int64 `json:"lastOK"`
	LastErr    int64 `json:"lastErr"`
	LastStatus int   `json:"lastStatus"`
}

// 探测间隔相关常量：间隔下放到「父项」级别（作用于该父项下所有子项），用户可在 UI 调整，默认 60 秒。
const (
	defaultProbeInterval = 60 * time.Second // 父项未设置（≤0）时使用的默认探测间隔
	minProbeInterval     = 5 * time.Second  // 下限，避免过短间隔打爆后端
	probeSweepInterval   = 2 * time.Second  // 调度心跳：周期性检查各子项是否到期，按各自父项间隔触发
)

// normalizeProbeInterval 将父项配置的秒数规范为合法 time.Duration：≤0→默认；过低→下限。
func normalizeProbeInterval(sec int) time.Duration {
	d := time.Duration(sec) * time.Second
	if d <= 0 {
		return defaultProbeInterval
	}
	if d < minProbeInterval {
		return minProbeInterval
	}
	return d
}

// probeTimeout 单次探测的上下文/客户端超时，防止后端无响应时探测goroutine 长时间挂起。
const probeTimeout = 3 * time.Second

// probeTarget 描述一个待主动探测的子项后端，字段按模式取用其一。
type probeTarget struct {
	childID   string
	typ       string        // proxy / static / redirect
	upstreams []string      // 反代：上游 URL 列表（任一可达即视为正常）
	insecure  bool          // 反代：忽略后端 TLS 证书校验
	root      string        // 静态：本地根目录
	target    string        // 重定向：目标 URL
	interval  time.Duration // 该子项所属父项的探测间隔（作用于其下全部子项）
	// service 子项展示名（"父项 / 子项" 格式），用于探测日志的「后端 X 连接正常/访问错误」文案。
	service string
}

// refreshProbeTargets 依据当前启用子项重建主动探测目标清单（反代/静态/重定向 三种模式）。
// 每个目标的探测间隔取「其所属父项」的 probeInterval（作用于该父项下全部子项）；
// 同时重置探测调度表（probeNext），使父项间隔的变更在下次 sweep 立即生效。
// 仅纳入「已配置后端链接」的子项，避免对未配置上游/根目录/目标的子项误报「访问错误」。
// 同时清理 linkLogState 中已删除子项的条目，保证内存随子项数有界。
func (m *Module) refreshProbeTargets(groups map[string]*wsGroup) {
	targets := make([]probeTarget, 0, 8)
	present := make(map[string]bool, 8)
	for _, g := range groups {
		for _, b := range g.bindings {
			ch := b.child
			present[ch.ID] = true
			pt := probeTarget{childID: ch.ID, typ: ch.Type, interval: b.probeInterval, service: b.service}
			switch ch.Type {
			case "proxy":
				for _, up := range ch.Upstreams {
					if strings.TrimSpace(up.URL) != "" {
						pt.upstreams = append(pt.upstreams, up.URL)
					}
				}
				if len(pt.upstreams) == 0 {
					continue // 无可用上游，不探测
				}
				pt.insecure = ch.Proxy.InsecureSkipVerify
			case "static":
				if strings.TrimSpace(ch.Static.Root) == "" {
					continue // 未配置根目录，不探测
				}
				pt.root = ch.Static.Root
			case "redirect":
				if strings.TrimSpace(ch.Redirect.Target) == "" {
					continue // 未配置目标，不探测
				}
				pt.target = ch.Redirect.Target
			default:
				continue
			}
			targets = append(targets, pt)
		}
	}
	m.probeTargets = targets
	// 重置调度表：父项间隔变更后，下次 sweep 会以新间隔重新排期（已删除子项的调度项也随之清除，内存有界）。
	m.probeMu.Lock()
	m.probeNext = make(map[string]time.Time, len(targets))
	m.probeMu.Unlock()
	// 清理 linkLogState 中已删除子项的条目（与 linkStatus 的 pruneLinkStatus 同样的内存有界保证）。
	m.statMu.Lock()
	for id := range m.linkLogState {
		if !present[id] {
			delete(m.linkLogState, id)
		}
	}
	m.statMu.Unlock()
}

// pruneLinkStatus 删除不再存在的子项的链接状态，避免长期增删/启停子项后
// linkStatus 映射无限累计陈旧条目（探测内存随子项数有界的关键一环）。
func (m *Module) pruneLinkStatus(present map[string]bool) {
	m.statMu.Lock()
	defer m.statMu.Unlock()
	for id := range m.linkStatus {
		if !present[id] {
			delete(m.linkStatus, id)
		}
	}
}

// runProbe 调度各子项的主动探测：启动即全量探测一次，之后由 probeSweep 按各子项所属父项的
// 探测间隔分别排期触发；收到 probeKick 时额外立即全量探测（如 Reload 刷新目标后）。
// 与真实流量、日志限速完全解耦，即便站点零访问也能反映「前端到后端是否正常访问」这一健康信号。
func (m *Module) runProbe() {
	defer m.probeWG.Done()
	m.probeSweep(time.Now())
	ticker := time.NewTicker(probeSweepInterval)
	defer ticker.Stop()
	for {
		select {
		case <-m.probeStop:
			return
		case <-m.probeKick:
			m.probeSweep(time.Now())
		case <-ticker.C:
			m.probeSweep(time.Now())
		}
	}
}

// probeReasonClass 将探测失败的具体原因归类为可读的「结果类别」，返回形如 "类别：具体原因" 的字符串，
// 供总览程序日志与子项「后端状态」列共用。
//
// 分类不是笼统兜底，而是结合本项目 webservice 探测子系统（proxy/static/redirect 三种模式）真实会抛出的错误逐一分析得出：
//   - HTTP 错误：后端可达但返回 ≥400（proxy 模式下全部上游均 ≥400）。此时 status>0，errMsg 是较早连接的陈旧错误，故以状态码为准。
//   - 超时：3s 探测窗口内未完成 → errMsg 含 timeout / deadline exceeded / i/o timeout（含 TLS 握手超时 "TLS handshake timeout"）。
//   - 证书错误：TLS 握手/校验失败（未开启「忽略证书错误」时）→ errMsg 含 x509 / certificate / tls:。
//   - 不可访问：网络层不可达 → errMsg 含 refused / no such host / no route / network unreachable / connectex / connection failed / connection reset / host is down。
//   - 目录不存在：静态站点根目录缺失 → os.Stat 报 no such file or directory（含 Windows 中文路径报错）。
//   - 配置错误：用户配置缺失或非法 → 未配置上游 / 未配置根目录 / 无可用上游 / 目标 URL 解析失败 / 目标 URL 不合法 / URL 解析异常。
//   - 未知错误（兜底）：极个别未预料的错误串，原样返回，不臆造类别。
//
// 任何分支都不输出「其他情况」这类无信息量的标签。
func probeReasonClass(errMsg string, status int) string {
	// HTTP ≥400 是确定的「后端返回错误」，优先于 errMsg 关键字判定。
	if status > 0 {
		return "HTTP 错误：" + fmt.Sprintf("%d %s", status, http.StatusText(status))
	}
	detail := errMsg
	if detail == "" {
		detail = "无法连接"
	}
	low := strings.ToLower(detail)
	switch {
	case strings.Contains(low, "timeout"), strings.Contains(low, "deadline exceeded"), strings.Contains(low, "i/o timeout"):
		return "超时：" + detail
	case strings.Contains(low, "x509"), strings.Contains(low, "certificate"), strings.Contains(low, "tls:"):
		return "证书错误：" + detail
	case strings.Contains(low, "refused"), strings.Contains(low, "no such host"),
		strings.Contains(low, "no route"), strings.Contains(low, "network unreachable"),
		strings.Contains(low, "network is unreachable"), strings.Contains(low, "connectex"),
		strings.Contains(low, "connection failed"), strings.Contains(low, "connection reset"),
		strings.Contains(low, "host is down"):
		return "不可访问：" + detail
	case strings.Contains(low, "no such file or directory"), strings.Contains(low, "cannot find the path"),
		strings.Contains(low, "系统找不到指定的路径"), strings.Contains(low, "系统找不到指定的文件"):
		return "目录不存在：" + detail
	case strings.Contains(low, "未配置"), strings.Contains(low, "无可用"),
		strings.Contains(low, "目标 url"), strings.Contains(low, "parse "),
		strings.Contains(low, "invalid"), strings.Contains(low, "malformed"):
		return "配置错误：" + detail
	default:
		// 兜底：原样返回，避免臆造类别误导用户。
		return detail
	}
}

// probeSweep 按各子项所属父项的探测间隔，仅对「已到期」的子项执行一次可达性探测并写 linkStatus。
// 调度状态（下次探测时间）存于 probeNext，按 childID 维护；与真实流量、10/s 日志限速完全解耦。
// 在持 m.mu 拷贝目标快照后释放锁再探测/写状态，避免探测（含网络等待）长时间占用模块锁。
// 每次探测完成后，仅在「链接状态变化」（或首次探测）时：
//  1. 写一条程序日志（Info/正常；Warn/错误+原因）→ 总览页「程序日志」面板；
//  2. 追加一条 AccessEntry（event=probe）到环形缓冲 → 子项日志对话框「后端状态」列。
//
// 两处共用同一 needLog 判定，避免每 60s 重复刷屏；启动 / 新增子项的首次探测会各记一条「初始状态」。
func (m *Module) probeSweep(now time.Time) {
	m.mu.Lock()
	targets := make([]probeTarget, len(m.probeTargets))
	copy(targets, m.probeTargets)
	m.mu.Unlock()
	for _, t := range targets {
		m.probeMu.Lock()
		if nt, ok := m.probeNext[t.childID]; ok && !now.After(nt) {
			m.probeMu.Unlock()
			continue // 该子项所属父项的探测间隔未到，跳过
		}
		m.probeNext[t.childID] = now.Add(t.interval)
		m.probeMu.Unlock()
		ok, status, errMsg := m.probeOne(t)
		ts := now.UnixMilli()
		m.statMu.Lock()
		st := m.linkStatus[t.childID]
		if ok {
			st.LastOK = ts // 成功：仅刷新 LastOK；即便曾有失败记录，LastOK 更新后 UI 判定为「正常」
		} else {
			st.LastErr = ts
			st.LastStatus = status // 失败状态码（连接失败为 0）
		}
		m.linkStatus[t.childID] = st
		// 链接状态日志去重：仅在状态变化或首次探测时记录一条，避免每 60s 重复刷屏。
		// 启动 / 新增子项的首次探测会进入 if 分支（prev 不存在）。
		prev, logged := m.linkLogState[t.childID]
		needLog := !logged || prev != ok
		if needLog {
			m.linkLogState[t.childID] = ok
		}
		m.statMu.Unlock()
		if needLog {
			svc := t.service
			if svc == "" {
				svc = t.childID
			}
			// 统一构造 reason：成功时为空；失败时按「结果类别：具体原因」组织
			// （类别取 不可访问 / 超时 / 其他情况），供总览程序日志与子项「后端状态」列共用。
			reason := ""
			if !ok {
				reason = probeReasonClass(errMsg, status)
			}
			// 1) 程序日志：与总览页「程序日志」面板共享的边缘触发记录。
			//    失败行形如「后端 X 不可访问：dial tcp …」，类别即「后端的结果」，冒号后跟具体原因。
			if ok {
				m.log.Info("后端 "+svc+" 连接正常", "childId", t.childID)
			} else {
				m.log.Warn("后端 "+svc+" "+reason, "childId", t.childID, "status", status)
			}
			// 2) 子项日志环形缓冲：同样边缘触发，事件类型 event=probe，
			//    前端「后端状态」列直接渲染 Reason。耗时/来源 IP 对探测无意义，置 0/空。
			m.recordAccess(AccessEntry{
				Time:    ts,
				ChildID: t.childID,
				Service: svc,
				Method:  eventLabel(eventProbe),
				Status:  status,
				DurMS:   0,
				Remote:  "",
				Event:   eventProbe,
				Reason:  reason,
			})
		}
	}
}

// probeOne 按子项模式分发到对应的可达性探测。
// 返回 (ok, status, errMsg)：ok 为探测是否通过；status 为失败时的 HTTP 状态码（连接失败为 0）；
// errMsg 为失败时的可读原因（用于程序日志的「后端 X 访问错误：原因」）。
func (m *Module) probeOne(t probeTarget) (ok bool, status int, errMsg string) {
	switch t.typ {
	case "static":
		ok, errMsg = m.probeStatic(t.root)
		return ok, 0, errMsg
	case "redirect":
		return m.probeRedirect(t.target)
	default: // proxy
		return m.probeProxy(t.upstreams, t.insecure)
	}
}

// probeProxy 对反代上游逐个发起轻量 HTTP GET（3s 超时）：任一上游返回 <400 即视为可达；
// 全部上游均连接失败 → 不可达（status=0，记录最后一个 err.Error()）；
// 全部返回 ≥400 → 不可达（记录首个失败码）；errMsg 始终反映最后一次失败的具体原因。
func (m *Module) probeProxy(upstreams []string, insecure bool) (ok bool, status int, errMsg string) {
	if len(upstreams) == 0 {
		return false, 0, "未配置上游"
	}
	client := m.probeClient(insecure)
	ctx, cancel := context.WithTimeout(context.Background(), probeTimeout)
	defer cancel()
	for _, u := range upstreams {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			errMsg = err.Error() // URL 解析/构造错误，记录后继续
			continue
		}
		req.Header.Set("User-Agent", "mantou-health-probe")
		resp, err := client.Do(req)
		if err != nil {
			errMsg = err.Error() // 连接错误（拒绝/超时/DNS），记录最后一个
			continue
		}
		resp.Body.Close()
		if resp.StatusCode < 400 {
			return true, resp.StatusCode, ""
		}
		if status == 0 {
			status = resp.StatusCode // 记录首个失败码，继续尝试其余上游
		}
	}
	if status == 0 && errMsg == "" {
		errMsg = "无可用上游"
	}
	return false, status, errMsg
}

// probeStatic 静态站点：本地根目录可 stat 即视为可达；失败时返回 os.Stat 的错误信息。
func (m *Module) probeStatic(root string) (ok bool, errMsg string) {
	if strings.TrimSpace(root) == "" {
		return false, "未配置根目录"
	}
	_, err := os.Stat(root)
	if err != nil {
		return false, err.Error()
	}
	return true, ""
}

// probeRedirect 重定向：校验目标为 http/https URL，并对目标主机:端口做轻量 TCP 拨号
// （不实际抓取目标内容，避免对外部站点造成压力），能建立连接即视为可达。
func (m *Module) probeRedirect(target string) (ok bool, status int, errMsg string) {
	u, err := url.Parse(strings.TrimSpace(target))
	if err != nil {
		return false, 0, "目标 URL 解析失败：" + err.Error()
	}
	if (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return false, 0, "目标 URL 不合法（需 http/https）"
	}
	host := u.Host
	if u.Port() == "" {
		if u.Scheme == "https" {
			host = net.JoinHostPort(u.Hostname(), "443")
		} else {
			host = net.JoinHostPort(u.Hostname(), "80")
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), probeTimeout)
	defer cancel()
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", host)
	if err != nil {
		return false, 0, err.Error()
	}
	conn.Close()
	return true, 0, ""
}

// probeClient 返回（并惰性创建）探测用 HTTP 客户端；忽略证书校验与否走不同实例，
// 两者均设 probeTimeout，跨探测复用、只读不写，无并发写冲突。
func (m *Module) probeClient(insecure bool) *http.Client {
	if insecure {
		return m.probeClientInsecure
	}
	return m.probeClientSecure
}

// ChildStatus 返回各子项最近一次的链接状态（childID -> {最近成功时间, 最近失败时间, 失败状态码}）。
// 跨 Reload 保留，便于在「未访问子项」与「活跃但失败」之间区分。
func (m *Module) ChildStatus() map[string]linkState {
	m.statMu.Lock()
	defer m.statMu.Unlock()
	out := make(map[string]linkState, len(m.linkStatus))
	for id, st := range m.linkStatus {
		out[id] = st
	}
	return out
}
