package webhook

import (
	"bytes"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"mantou/internal/errpage"
	"mantou/internal/ipx"
	"mantou/internal/modules/notify"
	"mantou/internal/strutil"
)

// 本文件是入站 HTTP 的全部逻辑。
//
// 检查顺序是刻意的：方法 → IP 名单 → 限流 → 鉴权 → 并发 → 体积 → 关键词。
// 从最便宜、最不需要读请求体的检查往后排，保证被拒的请求消耗最少资源——
// 尤其是"先限流再鉴权"：反过来的话，海量错令牌的请求每一条都要走完鉴权流程。
// 并发闸紧挨在读请求体之前：它守的正是从那一行开始花的内存（见 inflight.go）。
// 关键词准入只能排在最后：它是唯一一个非看正文不可的检查。
//
// 派发一律是**异步入队后立刻返回 200**。第三方推送方普遍有很短的超时
//（有些推送插件只等几秒），等钉钉返回再回 200 会让对方判定推送失败并重推，
// 于是同一条消息进来两遍。

// bodyReadLimit 读取请求体时额外允许的余量。
// MaxBytesReader 在超限时才报错，多留 1 字节让"刚好等于上限"的请求正常通过。
const bodyReadLimit = 1

// errNoReceiver 试运行时指定的接收器不存在或已停用。
var errNoReceiver = errors.New("接收器不存在或未启用")

// handler 返回入站处理器。
//
// 刻意不用 http.ServeMux：入站路径是配置驱动的、可以带斜杠、可以随时增删，
// 而 ServeMux 的模式在注册后不可变，每次 Reload 都要重建整个 mux。
// 一次 map 查表比那简单得多，也不会有"改了配置但旧 mux 还在服务"的窗口。
func (m *Module) handler() http.Handler {
	return http.HandlerFunc(m.serve)
}

func (m *Module) serve(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	remote := ipx.RemoteHost(r.RemoteAddr)

	// 启用 HTTPS 后强制校验 Host：既挡住拿 IP 直连绕过域名的探测，
	// 也保证证书与访问域名始终对得上（见 config.WebhookServer 的说明）。
	// 共享端口时同样校验：那条监听上还挂着别人的站点，只有域名能证明这个请求是找本模块的。
	m.mu.Lock()
	spec := m.spec
	m.mu.Unlock()
	if (spec.tls || spec.shared) && !hostMatches(r.Host, spec.domain) {
		m.reject(w, r, nil, nil, remote, http.StatusMisdirectedRequest, "访问域名不匹配", start, false)
		return
	}

	path := strings.Trim(r.URL.Path, "/")
	table := m.routes.Load()
	rc := table.byPath[path]
	// 停用的接收器只在它自己的试运行开着时才开门（见 testrun.go）。
	// 这是"先调通再上线"的唯一走法：把一个还没配好的接收器挂到公网上去试，
	// 意味着调试期间的每一条消息都会真的发进群里。
	testing := false
	if rc == nil {
		if cand := table.byPathAll[path]; cand != nil && m.tests.active(cand.cfg.ID, start) {
			rc, testing = cand, true
		}
	} else {
		testing = m.tests.active(rc.cfg.ID, start)
	}
	if rc == nil {
		// 刻意不区分"路径不存在"与"接收器已停用"：路径本身是一层凭证
		//（很多第三方系统只能配一个 URL，猜不到的路径是唯一的保护），
		// 用不同的响应区分两者等于给枚举者一个信号。
		//
		// Plain 保持成原来那句 "not found"：入站端口对面是第三方系统，
		// 它们的日志里已经在记这一行，没必要为了页面好看去改（见 errpage 的内容协商）。
		errpage.Write(w, r, errpage.Page{
			Status: http.StatusNotFound,
			Title:  "这个推送地址不存在",
			Detail: "地址对上了主机，但后面这段路径没有对应的接收器。",
			Hint:   "请核对第三方系统里填的推送地址。",
			Where:  strutil.Truncate(r.Host+"/"+path, 160, "…"),
			Plain:  "not found",
		})
		// 记录要配额，计数不要：计数是纯 atomic，不吃内存也不写盘，
		// 而扫描期间它是面板上唯一还在动的信号（总览的"拒收"取自 Metrics）。
		if ok, merged := m.anon.take(start); ok {
			reason := "入站路径不存在：" + strutil.Truncate(path, 128, "…") + mergedNote(merged)
			// 这一条的原文只有方法、路径与请求头——正文在这里还没读（检查顺序见本文件顶部）。
			// 留存它仍然值得：第三方系统把地址填错（多了一层前缀、少了一段路径）时，
			// 面板上能看到对方实际请求的是哪个路径，这是最常见的一类"配好了却收不到"。
			m.hist.add(HistoryEntry{Event: EventRejected, Remote: remote, Status: 404,
				Reason:   reason,
				DurMS:    sinceMS(start),
				SourceID: m.captureSource(r, nil, remote, EventRejected, 404, reason, "", nil)})
		}
		m.rejected.Add(1)
		return
	}

	if !allowedMethod(r.Method) {
		m.reject(w, r, rc, nil, remote, http.StatusMethodNotAllowed, "不支持的请求方法 "+r.Method, start, testing)
		return
	}
	if ok, why := rc.allowIP(ipx.ClientIP(r)); !ok {
		m.reject(w, r, rc, nil, remote, http.StatusForbidden, why, start, testing)
		return
	}
	if rc.rate > 0 && !m.limiter.Allow(rc.cfg.ID, ipx.LimitKey(r), rc.rate) {
		m.reject(w, r, rc, nil, remote, http.StatusTooManyRequests, "超出每秒请求数限制", start, testing)
		return
	}
	if why := checkAuth(rc, r); why != "" {
		m.reject(w, r, rc, nil, remote, http.StatusUnauthorized, why, start, testing)
		return
	}

	// 并发闸：从这一行往下才开始花内存（读体、解析、渲染），所以名额占在这里。
	// 装得更前会让一串猜错路径的请求占满名额，把真消息挡在外面；装得更后就没有意义了。
	// 见 inflight.go 对"为什么计条数、为什么不排队"的说明。
	if !m.gate.enter() {
		m.reject(w, r, rc, nil, remote, http.StatusServiceUnavailable, "同时处理的入站请求已达上限，请稍后重试", start, testing)
		return
	}
	defer m.gate.leave()

	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, rc.maxBody+bodyReadLimit))
	if err != nil {
		// MaxBytesReader 超限与网络中断都落在这里。两者对用户的下一步动作不同，
		// 所以按已读长度区分：读到上限说明是体积问题，提示去调 MaxBodyKB。
		reason := "读取请求体失败：" + err.Error()
		status := http.StatusBadRequest
		if int64(len(raw)) >= rc.maxBody {
			reason = "请求体超过上限 " + strutil.Truncate(byteSize(rc.maxBody), 32, "") + "，可在接收器里调大"
			status = http.StatusRequestEntityTooLarge
		}
		m.reject(w, r, rc, nil, remote, status, reason, start, testing)
		return
	}

	// 人拿浏览器直接打开了这个地址：什么内容都没带。这不是一条消息，别收下。
	//
	// 为什么必须挡在这里：GET 是放行的（有些系统只能在 URL 上带参数推送），所以在浏览器
	// 地址栏里敲一下这个 URL 会一路走到底，被当成一条空消息记进历史、计进接收数，
	// 面板上凭空多出一条"没有规则命中"。而用户敲这一下的本意只是"看看这个地址通不通"。
	//
	// 只对浏览器这么做（errpage.WantsHTML）：第三方系统发来的空请求仍照旧当消息处理，
	// 有人用一个空 POST 当连通性探测，回给它的还是原来那份 JSON。
	if blankVisit(r, raw) && errpage.WantsHTML(r) {
		errpage.Write(w, r, errpage.Page{
			Status: http.StatusOK,
			Title:  "这个推送地址工作正常",
			Detail: "它只接收第三方系统推送过来的消息，用浏览器直接打开不会产生任何消息。",
			Hint:   "把当前这段地址整个填进第三方系统的推送 / 回调地址里即可。",
			Where:  strutil.Truncate(r.Host+"/"+path, 160, "…"),
		})
		return
	}

	// 关键词准入：路径与令牌只能证明来源，证明不了内容。这一步必须等请求体读完，
	// 所以排在最后——它也是唯一一个需要看正文的准入检查。
	//
	// 传闭包而不是传值：keywordText 会把整份载荷（上限 4MB）拷一遍，
	// 而没配关键词的接收器一进 allowKeywords 就返回。见那个函数上的说明。
	if ok, why := rc.allowKeywords(func() string { return keywordText(r, raw) }); !ok {
		m.reject(w, r, rc, raw, remote, http.StatusForbidden, why, start, testing)
		return
	}

	ev := buildEvent(rc, r, raw, remote)
	res := rc.process(ev)

	// 试运行中：消息到这里就结束——不投递、不计数、不写历史，只留在试运行面板里。
	// 只有停止试运行之后，后续的新消息才会真的转发出去。
	if testing && m.captureTestRun(rc, r, raw, remote, ev, res, nil) {
		writeAccepted(w, ev.ID, res.MatchedRules)
		return
	}

	m.received.Add(1)
	m.dispatch(rc, r, ev, res, remote, start)
	writeAccepted(w, ev.ID, res.MatchedRules)
}

// blankVisit 判断这次请求"什么内容都没带"：请求体是空的（或只有空白），
// 查询串里也没有除令牌之外的参数。
//
// token 不算内容：它是凭证，而不是被推送的数据；带令牌的地址被人从聊天记录里
// 复制到浏览器里打开，是这一整段代码要处理的典型情形。
func blankVisit(r *http.Request, raw []byte) bool {
	if len(bytes.TrimSpace(raw)) > 0 {
		return false
	}
	if r.URL == nil {
		return true
	}
	for k := range r.URL.Query() {
		if k != "token" {
			return false
		}
	}
	return true
}

// writeAccepted 回一条"已收到"。响应体刻意简短且固定：
// 对面是第三方系统，它只需要一个 2xx；eventId 留给用户对着历史列表查同一条消息。
func writeAccepted(w http.ResponseWriter, eventID string, matched int) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"ok":      true,
		"eventId": eventID,
		"matched": matched,
	})
}

// captureTestRun 把一次请求记进试运行缓冲。
//
// 返回 false 表示试运行刚好在这一瞬被停掉了（用户点了"停止"，而请求已经进到这里）。
// 此时调用方必须**按真实请求继续处理**：宁可多转发一条，也不能把一条已经接下来的
// 消息静默丢掉——用户点停止的本意是"从现在起恢复转发"，不是"丢掉手上这条"。
//
// rej 非空表示这条请求是被拒收的，此时不带处理结果（流水线根本没跑）。
//
// 三处裁剪都在这里做，且都复用入站原文留存那边的实现（clampBody / clampHeaders /
// redactQueryKeepingRaw）：一份抓包能留三小时，内容全由对端决定，不设闸就是
// "外部决定本程序占多少内存"；打码规则也只该有一份，另写一遍迟早出现
// "入站原文留存里打了码、试运行页上没打"。
func (m *Module) captureTestRun(rc *receiverRT, r *http.Request, raw []byte, remote string,
	ev *event, res result, rej *rejection) bool {

	c := TestRunCapture{
		Time:    time.Now().UnixMilli(),
		Remote:  remote,
		Method:  r.Method,
		Query:   redactQueryKeepingRaw(r.URL.RawQuery, captureQueryMax),
		Headers: clampHeaders(headerMap(r.Header, rc.cfg.AuthHeader)),
		Sniffed: SniffSourceType(raw),
	}
	// 类型判定用整段正文，留存用截断后的：两者不一致会让界面上的"按什么解的"
	// 和用户手里那段样本对不上。
	c.Body, c.BodySize, c.BodyTruncated = clampBody(raw, captureBodyMax)
	if c.Headers == nil {
		// 界面按对象遍历它，nil 会渲染成空白而不是"没有请求头"。
		c.Headers = map[string]string{}
	}
	if rej != nil {
		c.Rejected, c.Status, c.Reason = true, rej.status, rej.reason
	} else {
		c.Result = dryRunOf(ev, res, m.targetNames())
		if c.BodyTruncated {
			// 正文都截了，字段树却是按整段正文解出来的——留着它这道闸就等于没设。
			// 渲染结果与命中判定照常保留：那是用户此刻真正要看的东西，
			// 而它们各自都有长度闸（tmplx.MaxRenderBytes）。
			c.Result.Root = nil
			c.RootDropped = true
		}
	}
	return m.tests.add(rc.cfg.ID, c)
}

// rejection 一次拒收的结果，供试运行抓包记录。
type rejection struct {
	status int
	reason string
}

// targetNames 出站目标的 ID → 名称，供试运行面板显示"会发给谁"。
func (m *Module) targetNames() map[string]string {
	if n := m.notifier.Load(); n != nil && *n != nil {
		return (*n).Targets()
	}
	return map[string]string{}
}

// dispatch 把渲染结果交给出站模块，并记账。
//
// 带着 *http.Request 进来只为一件事：消息被丢弃时要留一份原文（见 captureSource）。
// "没有规则命中"这句结论本身说明不了该去改什么，得看见对方发的字段长什么样。
func (m *Module) dispatch(rc *receiverRT, r *http.Request, ev *event, res result, remote string, start time.Time) {
	base := HistoryEntry{
		EventID: ev.ID, ReceiverID: rc.cfg.ID, Receiver: rc.cfg.Name,
		Remote: remote, DurMS: sinceMS(start),
	}

	if res.MatchedRules == 0 {
		m.dropped.Add(1)
		e := base
		e.Event = EventDropped
		e.Status = http.StatusOK
		e.Reason = "没有规则命中，消息未发送"
		e.SourceID = m.captureSource(r, rc, remote, EventDropped, e.Status, e.Reason, ev.ID, ev.Raw)
		m.hist.add(e)
		m.writeState(rc, "已接收，无规则命中")
		return
	}
	// 命中了规则、却没有任何输出分支的条件成立。消息一样没发出去，但原因与上面那条
	// 完全不同（规则条件过了、分支条件没过），必须分开说——混成同一句话会让用户
	// 回头去改已经对了的那一层条件。
	if len(res.Messages) == 0 {
		m.dropped.Add(1)
		e := base
		e.Event = EventDropped
		e.Status = http.StatusOK
		e.Rule = strings.Join(res.NoBranch, "、")
		e.Reason = "命中了规则，但没有任何输出分支的条件成立，消息未发送"
		e.SourceID = m.captureSource(r, rc, remote, EventDropped, e.Status, e.Reason, ev.ID, ev.Raw)
		m.hist.add(e)
		m.writeState(rc, "已接收，无分支命中")
		return
	}

	notifier := m.notifier.Load()
	sent := 0
	for _, msg := range res.Messages {
		e := base
		e.Rule = msg.Label()
		e.Status = http.StatusOK

		switch {
		case msg.Err != nil && msg.Body == "":
			e.Event = EventError
			e.Reason = msg.Err.Error()
			m.hist.add(e)
			continue
		case len(msg.Targets) == 0:
			e.Event = EventError
			e.Reason = "规则命中但没有通知目标（规则与接收器都没配）"
			m.hist.add(e)
			continue
		case notifier == nil || *notifier == nil:
			e.Event = EventError
			e.Reason = "出站模块不可用"
			m.hist.add(e)
			continue
		}

		req := notify.Request{
			TargetIDs: msg.Targets,
			Title:     msg.Title,
			Message:   msg.Body,
			Format:    msg.Format,
			Data:      ev.Root,
			Source:    rc.cfg.Name,
			RuleName:  msg.Label(),
			EventID:   ev.ID,
		}
		if err := (*notifier).Enqueue(req); err != nil {
			e.Event = EventError
			e.Reason = "入队失败：" + err.Error()
			m.hist.add(e)
			continue
		}

		e.Event = EventReceived
		e.Reason = renderNote(msg, res.Truncated)
		m.hist.add(e)
		sent++
	}

	status := "已接收并派发"
	if sent == 0 {
		status = "已接收，但没有消息派发成功"
	}
	m.writeState(rc, status)
}

// renderNote 把"这条消息渲染时有什么值得知道的事"压成一句话。
// 空字符串表示一切正常——历史列表里绝大多数记录应该是空的，有内容才值得看。
func renderNote(msg message, truncated bool) string {
	var parts []string
	if msg.Missing > 0 {
		parts = append(parts, "有 "+itoa(msg.Missing)+" 处字段取不到值")
	}
	if truncated {
		parts = append(parts, "内容过长已截断")
	}
	if msg.Err != nil {
		parts = append(parts, msg.Err.Error())
	}
	return strings.Join(parts, "；")
}

// reject 统一的拒收路径：回响应、记历史、记账、回写运行态。
//
// 只有 400 与 405 把原因写进响应体。403 / 401 一律只回一句通用文本：
// 那两条路上的"对方"可能是探测者，告诉它"你不在白名单里"或"令牌错了"
// 等于确认这个路径确实存在、并提示它换个方向继续试。原因照常进历史与日志，
// 用户在面板上看得到。
//
// testing 为真时**改记进试运行缓冲**，不进历史也不计数：试运行期间该接收器的
// 全部流量只属于试运行面板。响应码照旧原样回给对方——那是真实发生的事，
// 不能因为面板开着调试就骗第三方系统说收下了。被拒的请求尤其要让用户看见：
// 否则他面对一个"开着试运行却什么都收不到"的界面，猜不到是 IP 名单或令牌挡了。
//
// raw 是已读到的请求体，只有关键词准入那条路给得出（其余检查都在读体之前）。
// 它专门为那一条存在：拒收原因说的是"正文里没有那个词"，而试运行面板上看不到正文，
// 用户就没法判断是第三方改了措辞还是自己的词填错了。
//
// raw 同时是「入站原文留存」区分"正文没读过"与"正文是空的"的依据（见 captureSource）：
// nil 表示这次拒收发生在读正文之前，因此确实没有正文可留。
func (m *Module) reject(w http.ResponseWriter, r *http.Request, rc *receiverRT, raw []byte, remote string,
	status int, reason string, start time.Time, testing bool) {

	body := "rejected"
	switch status {
	case http.StatusMethodNotAllowed, http.StatusRequestEntityTooLarge:
		body = reason
	case http.StatusBadRequest:
		// 唯一不能原样回的一条，原因见 badRequestPlain 上方。
		body = badRequestPlain
	case http.StatusMisdirectedRequest:
		body = "misdirected request"
	}
	// 浏览器拿到卡片页，第三方系统拿到的还是上面那句纯文本，一字不改——
	// 它们的日志里已经在记这几句，为了页面好看去动它没有道理（见 errpage 的内容协商）。
	errpage.Write(w, r, rejectPage(status, reason, body))

	if testing && rc != nil {
		if m.captureTestRun(rc, r, raw, remote, nil, result{}, &rejection{status: status, reason: reason}) {
			m.log.Warn("消息路由拒收请求（试运行中）",
				"remote", remote, "path", r.URL.Path, "status", status, "reason", reason)
			return
		}
	}

	// 记不记这一条，走配额（见 anonlimit.go）。两侧都要有：拒收会记一条执行历史、
	// 再同步写一行程序日志，而"每个请求都被拒"这件事完全由对端的发送速率决定。
	//
	//   rc == nil ——"访问域名不匹配"那一条：路径都还没查，对端没出示任何凭证，
	//     与路径未命中同理，只能按全局配额算。
	//   rc != nil —— 已经猜对了路径，但仍不能照单全记：401/403/413/关键词未命中
	//     这些都能被无限重复。按接收器各发一份配额，刷一个接收器不影响别的接收器留痕。
	record, merged := true, int64(0)
	if rc == nil {
		record, merged = m.anon.take(start)
	} else {
		record, merged = m.rejQuota.take(rc.cfg.ID, start)
	}
	m.rejected.Add(1)
	// 归属到具体接收器的拒收计数（界面上「累计 N 次（含拒收 M）」的后一个数）。
	//
	// 必须排在 record 判断之前：那个配额管的是「这条要不要进执行历史」，与「列表上的
	// 计数」是两件事。配额现在两侧都生效了，顺序错一次就会静悄悄地把计数一起吞掉——
	// 界面上会变成"被刷了几万次，计数只涨了 20"。
	m.markRejected(rc)
	if !record {
		return
	}

	e := HistoryEntry{Event: EventRejected, Remote: remote, Status: status,
		Reason: reason + mergedNote(merged), DurMS: sinceMS(start)}
	if rc != nil {
		e.ReceiverID = rc.cfg.ID
		e.Receiver = rc.cfg.Name
	}
	e.SourceID = m.captureSource(r, rc, remote, EventRejected, status, e.Reason, "", raw)
	m.hist.add(e)

	m.log.Warn("消息路由拒收请求", "remote", remote, "path", r.URL.Path, "status", status, "reason", reason)
}

// captureSource 留存一次"没有转发出去"的入站请求原文，返回留存 ID（挂到那条历史记录上）。
//
// 只有被拒收与被丢弃才走这里。收到并派发成功的消息不留存：它的内容已经作为消息发出去了，
// 而留存的用途是"结论只有一句话、不看原文查不下去"，这两类才有这个问题。
//
// rc 为 nil 是正常情形——路径未命中与域名不匹配这两条路上还没查到接收器。
// 此时打码用的自定义头名取不到，只能按通用名单打码（见 headerMap）；能走到这里的请求
// 本来也没出示过任何凭证。
//
// raw 为 nil 表示这次请求的正文没有被读过，而不是"正文是空的"。入站检查刻意把不需要
// 读正文的闸排在前面（见本文件顶部），被它们拦下的请求确实没有正文可留——这件事必须
// 如实标出来，否则用户会以为对方发了个空包。
func (m *Module) captureSource(r *http.Request, rc *receiverRT, remote, event string,
	status int, reason, eventID string, raw []byte) string {

	if !worthCapturing(status) {
		return ""
	}
	rec := SourceRecord{
		Event: event, EventID: eventID, Remote: remote, Status: status,
		Reason:   strutil.Truncate(strings.TrimSpace(reason), maxReasonBytes, "…"),
		Method:   r.Method,
		BodyRead: raw != nil,
	}
	authHeader := ""
	if rc != nil {
		rec.ReceiverID, rec.Receiver = rc.cfg.ID, rc.cfg.Name
		authHeader = rc.cfg.AuthHeader
	}
	rec.Headers = clampHeaders(headerMap(r.Header, authHeader))
	if r.URL != nil {
		rec.Path = strutil.Truncate(r.URL.Path, sourcePathMax, "…")
		rec.Query = redactQuery(r.URL.RawQuery)
	}
	if raw != nil {
		rec.Body, rec.BodySize, rec.BodyTruncated = clampBody(raw, sourceBodyMax)
		// 按**原文**判类型，不按截断后的那一截：一段被切断的 JSON 是解不出来的，
		// 那会在面板上标成 txt，看着像"对方发的不是 JSON"。
		rec.Sniffed = SniffSourceType(raw)
	}
	return m.sources.add(rec)
}

// worthCapturing 判断这个拒收状态值不值得占一个留存槽位。
//
// 留存区只有 sourceMaxEntries 个槽位（500），而它是一个环——**存一条没用的就顶掉一条有用的**。
// 所以问题不是"这条有没有一点信息量"，是"它值不值得挤掉别的"。
//
// 429 不值得，理由三条叠在一起，缺一条都不至于单独排除它：
//
//   - 原因是个常量。永远是「超出每秒请求数限制」那一句，500 条一模一样的记录
//     不比 1 条多说任何事，而执行历史里已经有这一句（连同来源 IP 与时刻）。
//   - 没有正文。限流闸排在读正文之前（见本文件顶部的检查顺序），留下的只有
//     方法、路径、请求头——而这三样在同一个接收器上每条都长得差不多。
//   - 它是配好了之后的**稳态**产物，不是故障。第三方系统按 5 次/秒推、限流配的是
//     1 次/秒，那就永远是每秒 4 条 429。没有人需要翻原文来"查"这件事，
//     该看的是那个数字对不对。
//
// 而 429 恰好是最容易刷满槽位的一条路：记录配额（见 anonlimit.go）按接收器每分钟
// 还是放得过几十条，而 429 的触发频率完全由对方的推送速率决定，几分钟稳态限流攒下来
// 就足以把 400（正文格式不对）、关键词未命中、被丢弃这些**必须看原文才查得下去**的
// 记录挤出留存区。留存区在最需要它的时候恰好是空的。
//
// 403 / 401 留着不动：那两条的频率由"有人在拿错凭证敲门"决定，本身就是要看的信号，
// 而且 remote 与请求头逐条都可能不同（配额那道闸已经把总量按接收器封住了）。
func worthCapturing(status int) bool {
	return status != http.StatusTooManyRequests
}

// badRequestPlain / badRequestDetail 400 回给对方的那句话。
//
// 这一条不能像 405、413 那样把拒收原因原样回过去：400 的原因里带着底层读取错误
// （net.OpError 那一类），它的文本形如 "read tcp 10.0.0.5:9000->203.0.113.9:44321:
// read: connection reset by peer"——前一个地址是本机的监听地址。入站端口是对公网
// 开着的，本机地址不该由一次故障回给对方。
//
// 真实原因照旧进执行历史与服务端日志（见 reject 末尾），管理员在面板上看得到。
const (
	badRequestPlain  = "bad request"
	badRequestDetail = "这次推送的请求体没有被完整接收。"
)

// rejectPage 把一次拒收整成给浏览器看的卡片页。
//
// 401 / 403 只给标题不给原因，和响应体里那句通用文本一个道理：那两条路上的"对方"
// 可能是探测者，"你不在白名单里"或"令牌错了"等于确认这个路径确实存在。
//
// 提示语一律不提"去哪个页面改哪个设置"：入站端口是对公网开着的，页面上写出管理面的
// 名字或位置，等于向任何拿到这个地址的人确认这台机器上还有一个可登录的后台。
// 真实原因照旧进执行历史与服务端日志（见 reject 末尾的 m.log.Warn），管理员不缺渠道。
func rejectPage(status int, reason, plain string) errpage.Page {
	const adminHint = "如果你是这个接收器的管理员，具体原因已记入服务端的执行记录。"
	p := errpage.Page{Status: status, Plain: plain}
	switch status {
	case http.StatusMethodNotAllowed:
		p.Title = "这个地址只接收推送请求"
		p.Detail = reason
		p.Hint = "第三方系统里请改用 POST 推送；用浏览器直接打开这个地址不会产生消息。"
	case http.StatusRequestEntityTooLarge:
		p.Title = "推送的内容太大了"
		p.Detail = reason
		p.Hint = "请让推送方精简内容，或调大这个接收器的请求体上限。"
	case http.StatusBadRequest:
		p.Title = "请求内容读不出来"
		p.Detail = badRequestDetail
		p.Hint = "确认推送方把请求体完整发完了，然后重试一次。"
	case http.StatusMisdirectedRequest:
		p.Title = "访问的域名不对"
		p.Detail = "这个端口要求用配置好的域名访问。"
		p.Hint = "请改用配置好的域名访问，不要用 IP 直连。"
	case http.StatusTooManyRequests:
		p.Title = "推送太频繁了"
		p.Detail = "超出了这个接收器设置的每秒请求数上限。"
		p.Hint = "请降低推送频率，或调大这个接收器的每秒请求数上限。"
	case http.StatusServiceUnavailable:
		// 与 429 同一个口径：卡片上说清楚，纯文本响应体照旧只回一句通用文本。
		// 第三方系统看的是状态码而不是响应体，而 503 本身就是"稍后再来"的意思。
		p.Title = "服务器正忙"
		p.Detail = "同时在处理的推送请求已达上限，这一条没有被接收。"
		p.Hint = "请让推送方稍后重试。"
	case http.StatusUnauthorized:
		p.Title = "认证未通过"
		p.Hint = adminHint
	default: // 403 及其它
		p.Title = "访问被拒绝"
		p.Hint = adminHint
	}
	return p
}

// writeState 记一条「收下了」：刷新最近接收时刻与结果文本，收下计数加一。
//
// 只在正文已经进了流水线之后调用。被挡在流水线之外的请求走 markRejected，
// 那条路不碰时刻与结果文本——「最近收到」这一列说的是上一次真有数据进来。
//
// 截断状态文本、找不到 ID 就跳过都在 runstats 里做，这几件事只有一种正确写法，
// 放在唯一的写入口比放在调用方可靠。
func (m *Module) writeState(rc *receiverRT, status string) {
	if m.stats == nil {
		return
	}
	m.stats.Received(rc.cfg.ID, time.Now().Unix(), status)
}

// markRejected 记一条「被挡掉了」。
//
// 与 writeState 分开的两点理由：
//   - 这条路不该刷新「最近收到」（见 runstats.Store.Rejected）；
//   - 这条路的频率由公网决定，猜路径、猜令牌的流量一比一换成这里的调用。
//     它现在只是一次加锁 + 一次 map 写，不换配置、不落盘。
func (m *Module) markRejected(rc *receiverRT) {
	if m.stats == nil || rc == nil {
		return
	}
	m.stats.Rejected(rc.cfg.ID)
}

// keywordText 拼出关键词准入要比对的文本：请求体原文 + 查询串里的**值**。
//
// 为什么带上查询串：有些系统只能在 URL 上带参数推送（见 event.go 的 query 说明），
// 那种请求根本没有请求体，只看正文会把它们全部拒掉。取解码后的值而不是原始
// RawQuery，是因为中文关键词在 RawQuery 里是一串 %E4%B8...，永远匹配不上。
// 参数名不参与：那是第三方定的结构，不是消息内容。
//
// 请求体不按 JSON 解析，整段当文本查。这是刻意的：来源可能发 JSON，也可能发一段
// 自己拼的文本或一个 txt，任何"先解析再取字段"的写法都会在下一个来源上失效。
//
// 这个函数一定会拷一份完整载荷（`string(raw)` 也是拷贝，不是转引用），所以两个调用点
// 都把它包成闭包传给 allowKeywords，只在真的配了关键词时才执行。
func keywordText(r *http.Request, raw []byte) string {
	if r.URL == nil || r.URL.RawQuery == "" {
		return string(raw)
	}
	var b strings.Builder
	b.Write(raw)
	for _, vs := range r.URL.Query() {
		for _, v := range vs {
			b.WriteByte('\n')
			b.WriteString(v)
		}
	}
	return b.String()
}

// ---- 鉴权 ----

// checkAuth 返回空串表示通过，否则是拒绝原因。
func checkAuth(rc *receiverRT, r *http.Request) string {
	switch rc.cfg.AuthType {
	case "", "none":
		return ""
	case "token", "header":
	default:
		return "鉴权方式配置无效"
	}
	// 选了鉴权却没填令牌：拒收（失败关闭）。放行会让一个以为自己开了鉴权的用户
	// 把入口对全网敞开，而这个错误在界面上完全看不出来。
	if rc.cfg.Token == "" {
		return "已选择鉴权方式但未设置令牌"
	}

	if rc.cfg.AuthType == "header" {
		if rc.cfg.AuthHeader == "" {
			return "已选择请求头鉴权但未指定请求头名"
		}
		if !sameSecret(r.Header.Get(rc.cfg.AuthHeader), rc.cfg.Token) {
			return "请求头 " + rc.cfg.AuthHeader + " 校验失败"
		}
		return ""
	}

	// authType=token：指定了头就只认那个头，否则依次尝试常见位置。
	if rc.cfg.AuthHeader != "" {
		if !sameSecret(r.Header.Get(rc.cfg.AuthHeader), rc.cfg.Token) {
			return "请求头 " + rc.cfg.AuthHeader + " 校验失败"
		}
		return ""
	}
	for _, got := range []string{
		r.Header.Get("X-Mantou-Token"),
		strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")),
		r.URL.Query().Get("token"),
	} {
		if got != "" && sameSecret(got, rc.cfg.Token) {
			return ""
		}
	}
	return "令牌校验失败"
}

// sameSecret 等长时间比较。
//
// ConstantTimeCompare 在长度不等时直接返回 0（长度本身会泄露，这无法避免也无关紧要），
// 但内容比较必须是恒定时间的：入站端点对公网开放，长度已知时逐字节计时差足以把令牌试出来。
func sameSecret(got, want string) bool {
	return subtle.ConstantTimeCompare([]byte(strings.TrimSpace(got)), []byte(want)) == 1
}

// ---- 小工具 ----

// allowedMethod 允许的请求方法。
// GET 也放行：有些系统只能在 URL 上带参数推送（见 event.go 的 query 说明）。
// HEAD / OPTIONS 不放行——它们不携带业务数据，放行只会让健康探测被记成一条消息。
func allowedMethod(m string) bool {
	switch m {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodGet:
		return true
	}
	return false
}

// hostMatches 比较请求 Host 与配置域名（忽略端口与大小写）。
// 两侧都去掉 IPv6 的方括号：Host 头里 IPv6 字面量必须带括号，而域名栏里用户
// 两种写法都可能填，只在一侧去括号会让这类地址永远匹配不上。
func hostMatches(host, domain string) bool {
	if domain == "" {
		return true
	}
	h := strings.ToLower(strings.TrimSpace(host))
	if i := strings.LastIndexByte(h, ':'); i > 0 && !strings.Contains(h[i:], "]") {
		h = h[:i]
	}
	return strings.Trim(h, "[]") == strings.Trim(strings.ToLower(domain), "[]")
}

func tostr(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

func sinceMS(start time.Time) int64 { return time.Since(start).Milliseconds() }

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

// byteSize 把字节数写成人看得懂的形式，只用于错误文案。
func byteSize(n int64) string {
	if n >= 1<<20 {
		return itoa(int(n>>20)) + " MB"
	}
	return itoa(int(n>>10)) + " KB"
}

// ---- 试运行 ----

// DryRunResult 试运行的结果。刻意包含中间产物（信封、未解析的映射、渲染文本），
// 界面据此告诉用户"路径写对了没有、模板渲染出来长什么样、会发给谁"——
// 这是替代"回去写代码调试"的关键：不写代码的前提是能看见每一步的结果。
type DryRunResult struct {
	EventID    string         `json:"eventId"`
	Root       map[string]any `json:"root"`
	Unresolved []string       `json:"unresolved"`
	Matched    int            `json:"matched"`
	// NoBranch 命中了规则、但没有任何输出分支的条件成立的规则名。
	// 这是多分支专属的一种"配好了却收不到"，界面必须把它与"没有规则命中"分开说，
	// 否则用户会回头去改已经对了的那一层条件（见 process 的 result.NoBranch）。
	NoBranch   []string          `json:"noBranch,omitempty"`
	Truncated  bool              `json:"truncated"`
	Messages   []DryRunMessage   `json:"messages"`
	TargetName map[string]string `json:"targetNames"`
	// Blocked 这条样本会被关键词准入拒收。刻意仍然把下面的渲染结果算完并返回：
	// 用户此刻正在调词表，既要知道"这条会被拦"，也要看到"不拦的话会发出什么"。
	Blocked       bool   `json:"blocked,omitempty"`
	BlockedReason string `json:"blockedReason,omitempty"`
}

// DryRunMessage 试运行里一条渲染结果。
type DryRunMessage struct {
	RuleID   string `json:"ruleId"`
	RuleName string `json:"ruleName"`
	// Branch 产出这条消息的输出分支名；没配分支的规则为空。
	// 界面上显示成「规则名 / 分支名」，与执行历史里的写法一致。
	Branch string `json:"branch,omitempty"`
	// Template 渲染用的模板名。多分支下这一项才真正有用：两个分支的正文常常长得很像，
	// 只看渲染结果分不出是分支条件筛错了还是模板选错了。
	Template string   `json:"template,omitempty"`
	Title    string   `json:"title"`
	Body     string   `json:"body"`
	Format   string   `json:"format"`
	Targets  []string `json:"targets"`
	Missing  int      `json:"missing"`
	Error    string   `json:"error,omitempty"`
}

// dryRunOf 把一次处理结果整成界面要的形态。
// 实时试运行（testrun.go）与样本载荷试运行共用这一份，两者的右栏因此永远一致。
func dryRunOf(ev *event, res result, targetNames map[string]string) *DryRunResult {
	out := &DryRunResult{
		EventID:    ev.ID,
		Root:       ev.Root,
		Unresolved: ev.Unresolved,
		Matched:    res.MatchedRules,
		NoBranch:   res.NoBranch,
		Truncated:  res.Truncated,
		TargetName: targetNames,
	}
	for _, msg := range res.Messages {
		dm := DryRunMessage{
			RuleID: msg.RuleID, RuleName: msg.RuleName, Branch: msg.Branch,
			Template: msg.Template,
			Title:    msg.Title, Body: msg.Body, Format: msg.Format,
			Targets: msg.Targets, Missing: msg.Missing,
		}
		if msg.Err != nil {
			dm.Error = msg.Err.Error()
		}
		out.Messages = append(out.Messages, dm)
	}
	return out
}

// DryRun 用一段样本载荷跑完整条流水线，但**不投递**。
//
// 与真实请求走的是同一个 buildEvent + process：若这里另写一遍，
// 试运行页说"会发给 A 群"而实际发到 B 群，这个功能就没有意义了。
//
// 停用的接收器也允许试运行（查的是 list，含停用），与实时试运行同口径：
// "先调通再启用"是用户唯一合理的顺序。
func (m *Module) DryRun(receiverID string, body []byte, headers map[string]string, rawQuery string) (*DryRunResult, error) {
	var rc *receiverRT
	for _, cand := range m.routes.Load().list {
		if cand.cfg.ID == receiverID {
			rc = cand
			break
		}
	}
	if rc == nil {
		return nil, errNoReceiver
	}

	req := &http.Request{
		Method: http.MethodPost,
		Header: http.Header{},
		URL:    &url.URL{Path: "/" + rc.cfg.Path, RawQuery: rawQuery},
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	ev := buildEvent(rc, req, body, "试运行")
	out := dryRunOf(ev, rc.process(ev), m.targetNames())
	// 关键词准入在真实请求里排在渲染之前，这里反过来：拦不拦要说，会发什么也要看得见。
	// 不在这里体现的话，用户配好词表、试运行一切正常，上线后却一条也进不来。
	if ok, why := rc.allowKeywords(func() string { return keywordText(req, body) }); !ok {
		out.Blocked, out.BlockedReason = true, why
	}
	return out, nil
}

// TestRunStart 开启某接收器的实时试运行。接收器不存在时报错——
// 界面上按钮就挂在那一行，报错等于告诉用户"配置刚被别人删了"。
func (m *Module) TestRunStart(receiverID string) error {
	if !m.hasReceiver(receiverID) {
		return errNoReceiver
	}
	m.tests.start(receiverID, time.Now())
	return nil
}

// TestRunStop 停止实时试运行；停止后进来的新消息立刻恢复真实转发。
func (m *Module) TestRunStop(receiverID string) {
	m.tests.stop(receiverID, "")
}

// TestRunState 读取试运行状态与已抓到的消息，供界面轮询。
func (m *Module) TestRunState(receiverID string) TestRunState {
	return m.tests.state(receiverID, time.Now())
}

func (m *Module) hasReceiver(id string) bool {
	for _, cand := range m.routes.Load().list {
		if cand.cfg.ID == id {
			return true
		}
	}
	return false
}
