package notify

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"mantou/internal/netguard"
	"mantou/internal/strutil"
	"mantou/internal/tmplx"
)

// 各家对单条消息长度的硬限制。超出会被对方直接拒收，因此在发出去之前先截断——
// 一条被截短的告警仍然有用，一个 40058 错误码没有。
//
// 钉钉：text 与 markdown 均为 20000 字节。
// 企业微信：text 2048 字节、markdown 4096 字节。
const (
	dingMaxBytes         = 20000
	wecomTextMaxBytes    = 2048
	wecomMarkdownMaxByte = 4096
)

// maxResponseBytes 读取对端响应体的上限。
//
// 必须有上限：URL 由用户填写，对端可能是任何东西——一个返回无限流的接口
// 会让这次投递把内存吃光。8 KB 足够容纳任何 {"errcode":…,"errmsg":…}，
// 也足够在出错时给用户一段有意义的响应摘要。
const maxResponseBytes = 8 << 10

// deliver 执行一次投递（不含重试逻辑），返回一条完整结果。
func (m *Module) deliver(ctx context.Context, t *task) Result {
	started := time.Now()
	cfg := t.target.cfg
	res := Result{
		TargetID: cfg.ID, TargetName: cfg.Name, TargetType: cfg.Type,
		Attempt: t.attempt,
		Source:  t.req.Source, RuleName: t.req.RuleName, EventID: t.req.EventID,
	}

	detail, err := m.dispatch(ctx, t)
	res.OK = err == nil
	res.Status = statusText(err, detail)
	res.CostMS = time.Since(started).Milliseconds()
	res.At = time.Now().Unix()
	return res
}

// dispatch 按目标类型选适配器。
//
// 加一种渠道（飞书、Telegram）只需在这里多一个 case 加一个 build 函数：
// 队列、重试、超时、结果回报、内网防护全都不用动。
func (m *Module) dispatch(ctx context.Context, t *task) (string, error) {
	cfg := t.target.cfg
	if strings.TrimSpace(cfg.URL) == "" {
		return "", fmt.Errorf("目标地址为空")
	}
	switch cfg.Type {
	case "dingtalk":
		return m.sendDingTalk(ctx, t)
	case "wecom":
		return m.sendWeCom(ctx, t)
	case "http":
		return m.sendHTTP(ctx, t)
	default:
		return "", fmt.Errorf("不支持的目标类型 %q", cfg.Type)
	}
}

// ---------- 钉钉 ----------

// sendDingTalk 投递到钉钉自定义机器人。
func (m *Module) sendDingTalk(ctx context.Context, t *task) (string, error) {
	cfg := t.target.cfg
	endpoint, err := dingSignedURL(cfg.URL, cfg.Secret)
	if err != nil {
		return "", err
	}

	content := strutil.Truncate(t.req.Message, dingMaxBytes, "…（已截断）")
	// 钉钉的 @ 只有在正文里出现 @手机号 时才会真正生效（text 与 markdown 都是如此），
	// 光填 at.atMobiles 是不会亮起来的。所以这里把手机号补进正文——
	// 否则界面上那个勾选框看起来生效了，实际什么都没发生，这是最坏的一种表现。
	if len(cfg.AtMobiles) > 0 {
		var sb strings.Builder
		for _, mobile := range cfg.AtMobiles {
			sb.WriteString(" @")
			sb.WriteString(mobile)
		}
		content += sb.String()
	}

	at := map[string]any{"isAtAll": cfg.AtAll}
	if len(cfg.AtMobiles) > 0 {
		at["atMobiles"] = cfg.AtMobiles
	}

	var payload map[string]any
	if t.req.Format == "markdown" {
		title := strings.TrimSpace(t.req.Title)
		if title == "" {
			// 钉钉要求 markdown 必须带 title（它是会话列表里显示的那一行）。
			// 缺了就用正文首行兜住，而不是让整条消息发不出去。
			title = firstLine(t.req.Message)
		}
		payload = map[string]any{
			"msgtype":  "markdown",
			"markdown": map[string]any{"title": title, "text": content},
			"at":       at,
		}
	} else {
		payload = map[string]any{
			"msgtype": "text",
			"text":    map[string]any{"content": content},
			"at":      at,
		}
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("组装请求体失败: %w", err)
	}
	return m.post(ctx, t, endpoint, "application/json", nil, body)
}

// dingSignedURL 给钉钉地址补上加签参数。
//
// 加签算法：sign = base64(HMAC-SHA256(secret, "<毫秒时间戳>\n<secret>"))，
// 与 timestamp 一并作为 query 参数。secret 为空表示该机器人没开加签，原样返回。
//
// 时间戳必须是毫秒且与服务端相差在 1 小时内——机器时钟跑偏会让全部投递失败并报
// "sign not match"，这是最常见的一类"配置全对但发不出去"，排障时先看本机时间。
func dingSignedURL(raw, secret string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", fmt.Errorf("地址无法解析: %w", err)
	}
	if strings.TrimSpace(secret) == "" {
		return u.String(), nil
	}
	ts := strconv.FormatInt(time.Now().UnixMilli(), 10)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(ts + "\n" + secret))
	sign := base64.StdEncoding.EncodeToString(mac.Sum(nil))

	q := u.Query()
	q.Set("timestamp", ts)
	q.Set("sign", sign)
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// ---------- 企业微信 ----------

// sendWeCom 投递到企业微信群机器人。
func (m *Module) sendWeCom(ctx context.Context, t *task) (string, error) {
	cfg := t.target.cfg
	var payload map[string]any
	if t.req.Format == "markdown" {
		// 企业微信的 markdown 消息**不支持** mentioned_mobile_list：
		// 它只认 <@userid> 这种企业内部 ID，而面板里填的是手机号。
		// 因此这里如实地不发 @，而不是伪造一段看起来像 @ 的文本；
		// 界面上会就此给出提示（需要 @ 就用纯文本格式）。
		payload = map[string]any{
			"msgtype":  "markdown",
			"markdown": map[string]any{"content": strutil.Truncate(t.req.Message, wecomMarkdownMaxByte, "…（已截断）")},
		}
	} else {
		text := map[string]any{"content": strutil.Truncate(t.req.Message, wecomTextMaxBytes, "…（已截断）")}
		mentions := append([]string(nil), cfg.AtMobiles...)
		if cfg.AtAll {
			// 企业微信用 mentioned_mobile_list 里的 "@all" 表示 @全体成员。
			mentions = append(mentions, "@all")
		}
		if len(mentions) > 0 {
			text["mentioned_mobile_list"] = mentions
		}
		payload = map[string]any{"msgtype": "text", "text": text}
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("组装请求体失败: %w", err)
	}
	return m.post(ctx, t, strings.TrimSpace(cfg.URL), "application/json", nil, body)
}

// ---------- 自定义 HTTP ----------

// 请求体模板里的保留字段名。用户的事件字段若与它们同名会被覆盖，
// 这一点在界面上会写明。
const (
	fieldMessage     = "message"
	fieldMessageJSON = "messageJSON"
	fieldMessageURL  = "messageURL"
	fieldTitle       = "title"
	fieldFormat      = "format"
	fieldEvent       = "event"
)

// sendHTTP 投递到自定义 HTTP 接收端。
func (m *Module) sendHTTP(ctx context.Context, t *task) (string, error) {
	cfg := t.target.cfg
	if t.target.bodyErr != nil {
		return "", fmt.Errorf("请求体模板有错: %w", t.target.bodyErr)
	}

	contentType := cfg.ContentType
	if contentType == "" {
		contentType = "application/json"
	}

	var body []byte
	switch {
	case t.body != nil:
		// 排队投递的请求体在入队那一刻就渲染好了（见 prepareQueued）：
		// 队列里的任务不再持有整份事件数据，重试也不必重复渲染。
		body = t.body
	case t.target.body == nil:
		// 没填模板时的默认体：用 json.Marshal 生成而不是拼字符串，
		// 消息里必然出现的换行与引号才不会把请求体拼成坏 JSON。
		b, err := json.Marshal(map[string]string{"text": t.req.Message})
		if err != nil {
			return "", fmt.Errorf("组装请求体失败: %w", err)
		}
		body = b
	default:
		rendered, missing, err := tmplx.Render(t.target.body, m.bodyData(t.req))
		if err != nil {
			return "", fmt.Errorf("渲染请求体失败: %w", err)
		}
		if missing > 0 {
			// 不是错误：请求体模板引用了本次事件没带的字段是常见情形（多来源共用一个目标）。
			// 但它是"对方收到的内容不完整"的第一嫌疑，所以留一条痕迹。
			m.log.Debug("请求体模板有取不到值的字段", "target", cfg.Name, "count", missing)
		}
		body = []byte(rendered)
	}

	// 声称发 JSON 就必须真的是 JSON：坏 JSON 的典型症状是对端回 400，
	// 而用户看到的只是"投递失败"，根本想不到是自己模板里少了一处引号转义。
	// 在发出去之前就报错，并明确指路 {{.messageJSON}}。
	if isJSONContentType(contentType) && !json.Valid(body) {
		return "", fmt.Errorf("请求体不是合法 JSON（把消息插进 JSON 时请用 {{.messageJSON}} 或 {{toJSON .message}}，它们会自动加引号并转义）")
	}

	// 表单体（application/x-www-form-urlencoded）只告警、照发。
	//
	// 病根与 JSON 那侧是同一个——模板里把消息原样插进去（text={{.message}}），
	// 而消息里带着换行、& 和 %。区别在后果的确定性：坏 JSON 必然被对端拒收，
	// 所以拦下来是帮忙；坏表单体多半只是某个字段的值被截断、或多冒出一个参数，
	// 对端照样回 200。此时硬拦会把一条一直在发的通知突然停掉，而用户看到的只是
	// "投递失败"——那比一个被截断的字段更糟。所以这里只把话说清楚，然后照发。
	if isFormContentType(contentType) {
		if problem := formBodyProblem(body); problem != "" {
			m.log.Warn("表单请求体里有没转义的字符，对端可能收到被截断或多出来的字段",
				"target", cfg.Name, "problem", problem, "hint", "把 {{.message}} 换成 {{.messageURL}}")
		}
	}

	method := cfg.Method
	if method == "" {
		method = http.MethodPost
	}
	return m.request(ctx, t, method, strings.TrimSpace(cfg.URL), contentType, cfg.Headers, body)
}

// bodyData 组装请求体模板可见的数据。
//
// 事件的全部字段平铺在顶层（于是 {{.body.消息编号}} 这类写法与消息模板完全一致），
// 外加几个渲染结果的字段。event 保留一份完整事件，供用户在字段名冲突时改用 {{.event.xxx}}。
func (m *Module) bodyData(req Request) map[string]any {
	out := make(map[string]any, 8)
	if ev, ok := req.Data.(map[string]any); ok {
		for k, v := range ev {
			out[k] = v
		}
	}
	out[fieldEvent] = req.Data
	out[fieldMessage] = req.Message
	out[fieldTitle] = req.Title
	out[fieldFormat] = req.Format
	// messageJSON 是**带引号的 JSON 字符串字面量**，可直接嵌进 JSON 请求体：
	//   {"content": {{.messageJSON}}}
	// 这是把含换行 / 引号的消息塞进 JSON 的唯一安全写法。
	if b, err := json.Marshal(req.Message); err == nil {
		out[fieldMessageJSON] = string(b)
	} else {
		out[fieldMessageJSON] = `""`
	}
	// messageURL 是同一件事的表单版：百分号转义后的消息，可直接嵌进
	// application/x-www-form-urlencoded 的请求体：
	//   text={{.messageURL}}
	// 少了它，消息里的换行、& 与 % 会把后面的字段整个带偏（见 formBodyProblem）。
	out[fieldMessageURL] = url.QueryEscape(req.Message)
	return out
}

func isJSONContentType(ct string) bool {
	base := strings.TrimSpace(strings.ToLower(strings.SplitN(ct, ";", 2)[0]))
	return base == "application/json" || strings.HasSuffix(base, "+json")
}

// isFormContentType 是不是表单编码（application/x-www-form-urlencoded）。
func isFormContentType(ct string) bool {
	base := strings.TrimSpace(strings.ToLower(strings.SplitN(ct, ";", 2)[0]))
	return base == "application/x-www-form-urlencoded"
}

// formBodyProblem 表单体里第一处不该出现的字符，没有则返回空串。
//
// 刻意不做整体解析：url.ParseQuery 会把值里的分号也判成错（Go 1.17 起 ; 不再是
// 合法分隔符），而分号在告警文本里太常见，拿它当判据只会天天误报。这里只挑两类
// **必然是错**的字符：
//
//   - 控制字符（含换行、回车、制表）：表单编码里它们必须写成 %0A 这类转义，
//     出现原字符只能是模板把多行消息原样插进来了。
//   - 落单的 %：后面没跟两位十六进制数，对端解码时会报错、或把它连同后两个字符
//     一起吃掉——"CPU 95%" 这种再普通不过的消息就会踩到。
//
// 高位字节（原样的 UTF-8 中文）刻意不算错：严格说该转义，但常见服务端都收，
// 判它等于把每条中文消息都报一遍。
func formBodyProblem(body []byte) string {
	for i := 0; i < len(body); i++ {
		c := body[i]
		if c < 0x20 || c == 0x7f {
			return fmt.Sprintf("第 %d 字节是控制字符 0x%02x（换行一类的字符要写成 %%0A）", i+1, c)
		}
		if c == '%' {
			if i+2 >= len(body) || !isHexDigit(body[i+1]) || !isHexDigit(body[i+2]) {
				return fmt.Sprintf("第 %d 字节的 %% 后面不是两位十六进制数（百分号本身要写成 %%25）", i+1)
			}
			i += 2
		}
	}
	return ""
}

func isHexDigit(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

// firstLine 取首行并裁到一个适合当标题的长度。
func firstLine(s string) string {
	line := s
	if i := strings.IndexAny(s, "\r\n"); i >= 0 {
		line = s[:i]
	}
	line = strings.TrimSpace(strings.TrimLeft(line, "#* 　"))
	if line == "" {
		return "通知"
	}
	return strutil.Truncate(line, 60, "…")
}

// ---------- 公共请求路径 ----------

// post 是 request 的 POST 简写。
func (m *Module) post(ctx context.Context, t *task, endpoint, contentType string, headers map[string]string, body []byte) (string, error) {
	return m.request(ctx, t, http.MethodPost, endpoint, contentType, headers, body)
}

// request 发出请求并判定成败。
func (m *Module) request(ctx context.Context, t *task, method, endpoint, contentType string, headers map[string]string, body []byte) (string, error) {
	req, err := http.NewRequestWithContext(ctx, method, endpoint, bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("构造请求失败: %w", err)
	}
	req.Header.Set("Content-Type", contentType)
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	// 超时统一由 ctx 控制，故客户端级超时传 0，避免两处超时互相干扰。
	// blockPrivate 打开时目标解析到内网 / 保留地址会被拒绝（钉钉、企业微信都在公网，
	// 而自定义 HTTP 目标常常就在内网——所以这是个全局开关而非本模块的硬策略）。
	resp, err := netguard.HTTPClient(t.blockPrivate, 0).Do(req)
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return "", fmt.Errorf("投递超时（%s）", timeoutOf(t.target.cfg))
		}
		return "", err
	}
	defer resp.Body.Close()

	raw, _ := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	return interpret(resp.StatusCode, raw)
}

// robotReply 是钉钉与企业微信共用的响应形态。
type robotReply struct {
	ErrCode int    `json:"errcode"`
	ErrMsg  string `json:"errmsg"`
}

// interpret 判定一次投递是否真的成功。
//
// 这里有个必须处理的坑：钉钉与企业微信在**业务失败时也返回 HTTP 200**，
// 真正的结果在响应体的 errcode 里（sign not match、群机器人已停用、内容含敏感词、
// 触发频率限制，全是 200 + 非 0 errcode）。只看状态码的实现会把这些一律记成"发送成功"，
// 而用户在群里什么都没收到——这是最难排查的一类故障，所以状态码与 errcode 都要看。
func interpret(status int, raw []byte) (string, error) {
	excerpt := strings.TrimSpace(string(raw))
	if len(excerpt) > 0 {
		excerpt = strutil.Truncate(excerpt, 200, "…")
	}

	var reply robotReply
	// 只有响应确实是个带 errcode 的 JSON 对象时才据此判定；
	// 自定义 HTTP 目标返回的可能是 "ok"、一段 HTML 或空体，那就只看状态码。
	hasCode := json.Unmarshal(raw, &reply) == nil && bytes.Contains(raw, []byte(`"errcode"`))

	if status >= 400 {
		if hasCode && reply.ErrMsg != "" {
			return "", fmt.Errorf("HTTP %d: %s", status, reply.ErrMsg)
		}
		if excerpt != "" {
			return "", fmt.Errorf("HTTP %d: %s", status, excerpt)
		}
		return "", fmt.Errorf("HTTP %d", status)
	}
	if hasCode && reply.ErrCode != 0 {
		return "", fmt.Errorf("对方拒收（errcode=%d）: %s", reply.ErrCode, reply.ErrMsg)
	}
	return fmt.Sprintf("HTTP %d", status), nil
}

// 内置的目标类型清单，与 dispatch 的 case 一一对应。
// 新增渠道时两处一起改：dispatch 加一个 case，这里加一个名字。
var supportedTypes = []string{"dingtalk", "wecom", "http"}

// SupportedTypes 返回内置的目标类型，供 API 校验与面板下拉共用一份清单。
func SupportedTypes() []string { return append([]string(nil), supportedTypes...) }

// SupportedType 判断类型是否被支持。
func SupportedType(t string) bool {
	for _, s := range supportedTypes {
		if s == t {
			return true
		}
	}
	return false
}
