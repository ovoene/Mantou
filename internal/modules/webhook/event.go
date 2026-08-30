package webhook

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"time"

	"mantou/internal/tmplx"
)

// 本文件把一次 HTTP 请求整成"内部事件信封"——模板与条件唯一面对的数据形态。
//
// 为什么要有信封，而不是直接把解码后的 body 交给模板：
// 条件与模板需要的不只是载荷，还有请求头（有些系统把消息类型放在头里）、
// query（有些系统只能在 URL 上带参数）、以及来源标识。把它们摊成同一个根，
// 用户在界面上只需要记一套路径写法：body.xxx / headers.xxx / query.xxx。

// ReservedFieldNames 信封占用的键名。导出给 API 校验与前端提示用：
// 字段映射起了同名短名时会被信封覆盖，应在保存时就告诉用户，而不是等消息进来才发现取错了值。
// 载荷里若真有同名字段，用 {{.body.headers}} 这类全路径仍然取得到原值。
var ReservedFieldNames = []string{
	"body", "headers", "query", "method", "path", "ip",
	"source", "receiverId", "eventId", "receivedAt",
}

// redactedHeaders 不进模板的请求头。
//
// 入站凭证不该出现在渲染结果里：模板正文是面板可编辑的，出站目标又是任意 HTTP 地址，
// 两者相加意味着一个模板就能把本接收器的令牌转发出去。签名类的自定义头同理——
// 它对渲染消息没有用处，泄露却是实打实的。
var redactedHeaders = map[string]bool{
	"authorization":       true,
	"cookie":              true,
	"x-mantou-token":      true,
	"proxy-authorization": true,
}

// event 一次入站请求的内部表示。
type event struct {
	ID         string
	ReceiverID string
	Source     string
	ReceivedAt time.Time

	// Root 是模板渲染与条件匹配的取值根（已应用 RootPath 与字段映射）。
	Root map[string]any
	// Raw 原始请求体，只给调试留存用；不进模板。
	Raw []byte
	// Unresolved 取不到值、落到默认值的映射名，供试运行页提示。
	Unresolved []string
}

// newEventID 生成事件 ID，用于把"收到 → 命中规则 → 各目标投递结果"这几条日志串起来。
// 随机源失败时退回时间戳：ID 只用于串联日志，重复的代价远小于空 ID。
func newEventID() string {
	var b [6]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "e" + time.Now().Format("150405.000")
	}
	return hex.EncodeToString(b[:])
}

// buildEvent 组装信封。不会失败：解析不了的请求体以原始字符串形态进 body，
// 让用户在试运行页上直接看到"对方发的其实不是 JSON"，而不是收到一个笼统的 400。
func buildEvent(r *receiverRT, req *http.Request, raw []byte, clientIP string) *event {
	ev := &event{
		ID:         newEventID(),
		ReceiverID: r.cfg.ID,
		Source:     r.cfg.Name,
		ReceivedAt: time.Now(),
		Raw:        raw,
	}

	body := decodeBody(raw, r.cfg.SourceType, r.cfg.PairSep, r.cfg.KVSep)
	envelope := map[string]any{
		"body":       body,
		"headers":    headerMap(req.Header, r.cfg.AuthHeader),
		"query":      queryMap(req.URL.Query()),
		"method":     req.Method,
		"path":       r.cfg.Path,
		"ip":         clientIP,
		"source":     r.cfg.Name,
		"receiverId": r.cfg.ID,
		"eventId":    ev.ID,
		"receivedAt": tmplx.Normalize(ev.ReceivedAt.Unix()),
	}

	root := make(map[string]any, len(envelope)+len(r.mappings)+8)
	// RootPath 指向的子对象先摊开，信封键再覆盖上去（见 ReservedFieldNames 的说明）。
	//
	// 先按信封解一次、解不出再按载荷解一次：界面上这一栏的默认值是 body，
	// 含义是"从请求体根开始取值"（有的来源把业务对象直接作为请求体发来）；
	// 而 Uptime Kuma 要填的 heartbeat 是载荷**内部**的子对象。两种写法都得认，
	// 否则用户得先搞清楚"这一栏是相对信封还是相对载荷"——与字段映射的两步取值同一个理由。
	if len(r.rootSegs) > 0 {
		sub, ok := lookupObject(envelope, r.rootSegs)
		if !ok {
			sub, ok = lookupObject(body, r.rootSegs)
		}
		if ok {
			for k, v := range sub {
				root[k] = v
			}
		}
	}
	for k, v := range envelope {
		root[k] = v
	}

	// 字段映射最后注入：短名是用户显式起的，理应压过一切默认键。
	for _, m := range r.mappings {
		v, ok := lookupOne(root, m.segs)
		if !ok || v == nil {
			// 原始路径也在 body 下试一次：用户填 "biz" 而不是 "body.biz" 是很常见的写法。
			if v2, ok2 := lookupOne(body, m.segs); ok2 && v2 != nil {
				v, ok = v2, true
			}
		}
		if !ok || v == nil {
			ev.Unresolved = append(ev.Unresolved, m.name)
			root[m.name] = m.def
			continue
		}
		root[m.name] = v
	}

	ev.Root = root
	return ev
}

// lookupObject 取路径上的第一个值，且要求它是对象。
// 取不到、或取到的不是对象（数组、字符串）时返回 false，由调用方决定回退。
func lookupObject(src any, segs []segment) (map[string]any, bool) {
	v, ok := lookupOne(src, segs)
	if !ok {
		return nil, false
	}
	m, ok := v.(map[string]any)
	return m, ok
}

// decodeBody 把原始请求体变成模板数据。
//
// sourceType 是用户在界面上选的「来源消息类型」，四种：
//
//	auto  逐条判定（默认，留空同义）：这一条是 JSON 就按 JSON，是键值文本就拆字段，都不是就整段进 body
//	json  按 JSON 解析；解不出时**退回字符串**而不是报错
//	kv    按分隔符拆成字段（name=x&type=y），与 JSON 一样写 {{.body.name}}
//	txt   请求体原样作为一个字符串进 body，模板里写 {{.body}}
//
// 为什么默认逐条判定，而不是让用户选死一种：同一个来源本来就会发不同格式的东西
// （旧接口拼的 name=x&type=y、新接口的 JSON、临时脚本发的一行纯文本），
// 而这几种形态里字段名往往是同一套。选死一种的代价实测过一次——接收器上写着键值文本、
// 对方推来 JSON，整份载荷被按逗号+冒号拆成一堆名叫 `{"biz"` 的假字段，
// 于是 body.biz 取不到值、所有规则条件全部落空，用户能看到的只有"规则不命中"。
// 逐条判定之后，两种格式进来都能命中同一条规则、套同一个模板。
//
// pairSep / kvSep 只对 kv 有意义，留空即自动识别（见 decodeKV）。
//
// 刻意不看 Content-Type：真实的推送方经常把 JSON 标成 text/plain 或干脆不带，
// 按声明的类型走会把一份完好的 JSON 当纯文本处理，用户随后配的所有路径都取不到值。
//
// 解不出时退回字符串（而不是 400）：这样用户在试运行页上直接看到
// "对方发的其实不是 JSON / 不是键值文本"，比收到一个笼统的错误有用得多。
func decodeBody(raw []byte, sourceType, pairSep, kvSep string) any {
	trimmed := trimBody(raw)
	switch sourceType {
	case "txt":
		return trimmed
	case "kv":
		return decodeKV(trimmed, pairSep, kvSep)
	case "json":
		return decodeJSONBody(trimmed)
	}
	// auto 与留空：按这一条的实际形态走。判不出来就整段交出去，
	// 与 json/kv 解不动时的兜底一致——模板里 {{.body}} 至少能把原文发出来。
	switch detectSourceType(trimmed, pairSep, kvSep) {
	case "":
		return map[string]any{}
	case "json":
		return decodeJSONBody(trimmed)
	case "kv":
		return decodeKV(trimmed, pairSep, kvSep)
	}
	return trimmed
}

// decodeJSONBody 按 JSON 解；空体给空对象（模板对 nil 取值会 panic），解不动给原文。
func decodeJSONBody(trimmed string) any {
	if trimmed == "" {
		return map[string]any{}
	}
	if v, err := tmplx.DecodeJSON([]byte(trimmed)); err == nil {
		return v
	}
	return trimmed
}

// bodyPrefixJunk 请求体开头可能出现的不可见字符：UTF-8 BOM 与零宽空格。
//
// 必须单独去掉，因为 strings.TrimSpace 不认它们（unicode.IsSpace('\ufeff') 是 false）。
// 而它们在真实推送里并不少见：.NET / Java 以带 BOM 的 UTF-8 写出请求体、
// 从网页或文档里复制配置时带进零宽空格。
//
// 留着它们的后果极难查：json.Valid 直接判假，一份完好的 JSON 被当成纯文本，
// 用户配的每条取值路径与每条规则条件全部落空；而请求体在界面上、在抓包里
// 看起来**完全正常**——那个字节不显示。更糟的是 SniffSourceType 会因此判成键值文本，
// 试运行再把这个判定回写进「来源消息类型」，从那一刻起连没有 BOM 的正常 JSON
// 也会被按逗号+冒号拆成一堆假字段。
const bodyPrefixJunk = "\ufeff\u200b"

// trimBody 请求体去掉首尾空白与开头的不可见字符，得到可以直接判类型 / 解码的文本。
func trimBody(raw []byte) string {
	s := strings.TrimSpace(string(raw))
	return strings.TrimSpace(strings.TrimLeft(s, bodyPrefixJunk))
}

// looksLikeJSON 这段文本是不是一份**完整合法**的 JSON 对象 / 数组。
//
// 用 json.Valid 而不是 tmplx.DecodeJSON：后者只读第一个值，
// `{"a":1}{"b":2}` 这种拼接载荷它解得出第一个对象，后面的会被静默丢掉，
// 用户对着字段树永远看不出少了东西。
func looksLikeJSON(trimmed string) bool {
	if trimmed == "" || (trimmed[0] != '{' && trimmed[0] != '[') {
		return false
	}
	return json.Valid([]byte(trimmed))
}

// minKVPairs 至少拆得出这么多字段才敢说一段文本是键值文本。
//
// 阈值是 2 而不是 1：一个冒号的句子（"告警: 磁盘满了"）也能拆出一对，
// 把它当字段是帮倒忙——用户会看到一个叫"告警"的字段，以为配对了。
const minKVPairs = 2

// detectSourceType 判断一段**已去噪**的正文更像 json、kv 还是 txt；空文本返回空串（不表态）。
//
// auto 解码与 SniffSourceType 共用这一个判据，两边不能各写一套：
// 否则会出现"试运行说是键值文本、运行时却按纯文本解"这种查不出原因的分歧。
//
// 判据的强弱是刻意不对称的：JSON 由 json.Valid 说了算，没有猜的成分；
// kv 那一侧（一个分隔符就算一对）是猜的，所以卡了字段数下限与字段名形态（见 kvKeyBadChars）。
func detectSourceType(trimmed, pairSep, kvSep string) string {
	if trimmed == "" {
		return ""
	}
	if looksLikeJSON(trimmed) {
		return "json"
	}
	if trimmed[0] == '{' || trimmed[0] == '[' {
		// 看着像 JSON 却解不出：判 txt，至少原文看得见。刻意不再往 kv 上试——
		// 一段被截断的 JSON 也能按逗号+冒号拆出几个"字段"，那只会把用户带偏。
		return "txt"
	}
	if _, _, pairs := sniffKV(trimmed, pairSep, kvSep); pairs >= minKVPairs {
		return "kv"
	}
	return "txt"
}

// SniffSourceType 判断一段请求体更像 json、kv 还是 txt，供试运行在收到真实消息后
// 在界面上标出"这一条按什么解的"。类型本身不需要用户来选——默认的自动识别就是
// 每条消息各判一次（见 decodeBody），这里只是把结论说给用户听。
func SniffSourceType(raw []byte) string {
	return detectSourceType(trimBody(raw), "", "")
}

// headerMap 请求头转小写键的映射。
//
// 键统一小写是因为 HTTP 头名大小写不敏感，而模板取值是敏感的：
// 若保留原样，同一个来源换个客户端库就可能从 X-Event-Type 变成 X-EVENT-TYPE，
// 于是规则突然不命中。多值头用 ", " 连接（与 HTTP 自身的多值表示一致）。
func headerMap(h http.Header, authHeader string) map[string]any {
	out := make(map[string]any, len(h))
	extra := strings.ToLower(strings.TrimSpace(authHeader))
	for k, v := range h {
		lk := strings.ToLower(k)
		if redactedHeaders[lk] || (extra != "" && lk == extra) {
			out[lk] = "***"
			continue
		}
		out[lk] = strings.Join(v, ", ")
	}
	return out
}

// queryMap 查询参数转映射：单值直接给字符串，多值用 ", " 连接。
//
// 凭证参数打码，理由与 headerMap 完全相同（见上面那段）：入站令牌**可以写在查询串里**
// （checkAuth 的回退链里就有 ?token=），而模板正文是面板可编辑的、出站目标又是任意
// HTTP 地址——不打码，一个模板就能把本接收器的令牌转发出去。请求头那侧防住了、
// 查询串这侧漏着，等于没防。
//
// 用的是「入站原文留存」那张表（secretQueryKeys，见 source.go）：规则只该有一份。
func queryMap(q url.Values) map[string]any {
	out := make(map[string]any, len(q))
	for k, v := range q {
		// 键按小写比较（查询参数名本身大小写敏感，故键仍用原文）。
		if secretQueryKeys[strings.ToLower(k)] {
			out[k] = "***"
			continue
		}
		out[k] = strings.Join(v, ", ")
	}
	return out
}
