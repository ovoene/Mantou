package notify

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"mantou/internal/config"
	"mantou/internal/logx"
	"mantou/internal/runstats"
)

// 统计用真库而不是替身。
//
// 面板上「这个目标现在行不行」只有这一个数据来源，因此回写本身也要测，而不只是测投递
// 结果。而替身要照抄 runstats 的规则（状态文本截断、重试中的失败不记、空 ID 忽略），
// 照抄就会漏——原先这里就是一个手写的 fakeStore，它复刻 config.UpdateNotifyState 的行为，
// 每次那边改规则都得记得同步改这边。真库本来就只在内存里，起一份的代价与替身相同。
//
// newModule 造一个已 Reload 好目标表、且结果全部灌进 channel 的模块。
func newModule(t *testing.T, targets ...config.NotifyTarget) (*Module, *runstats.Store, chan Result) {
	t.Helper()
	return newModuleWithSettings(t, config.Settings{}, targets...)
}

func newModuleWithSettings(t *testing.T, st config.Settings, targets ...config.NotifyTarget) (*Module, *runstats.Store, chan Result) {
	t.Helper()
	stats := runstats.New()

	m := New(logx.New(logx.Options{}), stats)
	t.Cleanup(func() { _ = m.Close() })
	if err := m.Reload(&config.Config{
		NotifyTargets: append([]config.NotifyTarget(nil), targets...),
		Settings:      st,
	}); err != nil {
		t.Fatalf("Reload: %v", err)
	}

	results := make(chan Result, 32)
	m.SetResultSink(func(r Result) { results <- r })
	return m, stats, results
}

// capture 记下对端实际收到的东西。各家渠道的正确性全在"发出去的请求体长什么样"，
// 只断言 OK 等于什么都没测。
type capture struct {
	mu      sync.Mutex
	method  string
	rawURL  string
	headers http.Header
	body    []byte
	hits    int
}

func (c *capture) snapshot() (method, rawURL string, headers http.Header, body []byte, hits int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.method, c.rawURL, c.headers, c.body, c.hits
}

func (c *capture) payload(t *testing.T) map[string]any {
	t.Helper()
	_, _, _, body, hits := c.snapshot()
	if hits == 0 {
		t.Fatal("对端没有收到任何请求")
	}
	var out map[string]any
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("请求体不是 JSON: %v\n%s", err, body)
	}
	return out
}

// newServer 起一个记录请求的对端。reply 为 nil 时回一个成功的机器人响应。
func newServer(t *testing.T, reply func(w http.ResponseWriter, hit int)) (*httptest.Server, *capture) {
	t.Helper()
	c := &capture{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		c.mu.Lock()
		c.hits++
		hit := c.hits
		c.method, c.rawURL, c.headers, c.body = r.Method, r.URL.String(), r.Header.Clone(), body
		c.mu.Unlock()

		if reply != nil {
			reply(w, hit)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"errcode":0,"errmsg":"ok"}`))
	}))
	t.Cleanup(srv.Close)
	return srv, c
}

func waitResult(t *testing.T, ch <-chan Result) Result {
	t.Helper()
	select {
	case r := <-ch:
		return r
	case <-time.After(5 * time.Second):
		t.Fatal("等待投递结果超时")
		return Result{}
	}
}

// shortRetry 把退避压到 1ms。真实退避 5 秒起步，一个"失败→重试→成功"的用例要跑十几秒，
// 那样的测试没人会跑（这也是 retryDelay 是变量的原因）。
func shortRetry(t *testing.T) {
	t.Helper()
	old := retryDelay
	retryDelay = func(int) time.Duration { return time.Millisecond }
	t.Cleanup(func() { retryDelay = old })
}

func sendOnce(t *testing.T, m *Module, req Request) Result {
	t.Helper()
	out, err := m.Send(context.Background(), req)
	if err != nil {
		t.Fatalf("Send: %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("期望 1 条结果，实际 %d", len(out))
	}
	return out[0]
}

// ---------- 钉钉加签 ----------

func TestDingSignedURLWithoutSecret(t *testing.T) {
	raw := "https://oapi.dingtalk.com/robot/send?access_token=abc"
	got, err := dingSignedURL(raw, "   ")
	if err != nil {
		t.Fatalf("dingSignedURL: %v", err)
	}
	if got != raw {
		t.Fatalf("未开加签时应原样返回，得到 %q", got)
	}
}

func TestDingSignedURLSignsWithSecret(t *testing.T) {
	const secret = "SECtest"
	got, err := dingSignedURL("https://oapi.dingtalk.com/robot/send?access_token=abc", secret)
	if err != nil {
		t.Fatalf("dingSignedURL: %v", err)
	}
	u, err := url.Parse(got)
	if err != nil {
		t.Fatalf("结果无法解析: %v", err)
	}
	q := u.Query()
	if q.Get("access_token") != "abc" {
		t.Fatalf("原有 query 被丢掉了: %q", got)
	}
	ts := q.Get("timestamp")
	if ts == "" {
		t.Fatal("缺少 timestamp")
	}

	// 签名算法必须与钉钉一致，否则全部投递都会以 sign not match 失败。
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(ts + "\n" + secret))
	want := base64.StdEncoding.EncodeToString(mac.Sum(nil))
	if q.Get("sign") != want {
		t.Fatalf("sign 不符\n want %q\n got  %q", want, q.Get("sign"))
	}
}

func TestDingSignedURLBadURL(t *testing.T) {
	if _, err := dingSignedURL("http://[::1", "SECx"); err == nil {
		t.Fatal("地址不合法时应报错")
	}
}

// ---------- 响应判定 ----------

// HTTP 200 + 非 0 errcode 是这个模块最要紧的一个坑：钉钉与企业微信业务失败时
// 状态码仍是 200，只看状态码会把"群里根本没收到"记成发送成功。
func TestInterpret(t *testing.T) {
	cases := []struct {
		name    string
		status  int
		body    string
		wantErr bool
		wantSub string
	}{
		{"成功", 200, `{"errcode":0,"errmsg":"ok"}`, false, "HTTP 200"},
		{"200但业务失败", 200, `{"errcode":310000,"errmsg":"keywords not in content"}`, true, "对方拒收（errcode=310000）"},
		{"200业务失败无errmsg", 200, `{"errcode":45009}`, true, "errcode=45009"},
		{"自定义端回纯文本", 200, "ok", false, "HTTP 200"},
		{"自定义端回空体", 204, "", false, "HTTP 204"},
		{"无errcode字段不参与判定", 200, `{"code":1,"msg":"bad"}`, false, "HTTP 200"},
		{"4xx取errmsg", 400, `{"errcode":40035,"errmsg":"invalid parameter"}`, true, "HTTP 400: invalid parameter"},
		{"4xx取响应摘要", 429, "too many requests", true, "HTTP 429: too many requests"},
		{"5xx空体", 502, "", true, "HTTP 502"},
		{"5xx非errcode的JSON", 500, `{"code":1}`, true, `HTTP 500: {"code":1}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			detail, err := interpret(tc.status, []byte(tc.body))
			if tc.wantErr {
				if err == nil {
					t.Fatalf("应判为失败，实际成功（detail=%q）", detail)
				}
				if !strings.Contains(err.Error(), tc.wantSub) {
					t.Fatalf("错误里应含 %q，实际 %q", tc.wantSub, err.Error())
				}
				return
			}
			if err != nil {
				t.Fatalf("应判为成功，实际 %v", err)
			}
			if detail != tc.wantSub {
				t.Fatalf("detail 期望 %q，实际 %q", tc.wantSub, detail)
			}
		})
	}
}

func TestInterpretTruncatesExcerpt(t *testing.T) {
	_, err := interpret(500, []byte(strings.Repeat("x", 500)))
	if err == nil {
		t.Fatal("应报错")
	}
	// 响应体长度不受本程序控制，摘要必须裁剪后才进结果与日志。
	if len(err.Error()) > 260 {
		t.Fatalf("响应摘要未裁剪，长度 %d", len(err.Error()))
	}
}

func TestIsJSONContentType(t *testing.T) {
	cases := map[string]bool{
		"application/json":                  true,
		"Application/JSON; charset=utf-8":   true,
		"application/vnd.api+json":          true,
		"  application/json  ":              true,
		"text/plain":                        false,
		"application/x-www-form-urlencoded": false,
		"":                                  false,
	}
	for ct, want := range cases {
		if got := isJSONContentType(ct); got != want {
			t.Errorf("isJSONContentType(%q) = %v，期望 %v", ct, got, want)
		}
	}
}

func TestFirstLine(t *testing.T) {
	cases := []struct{ in, want string }{
		{"## 每日通知已提交\n第二行", "每日通知已提交"},
		{"**加粗**", "加粗**"},
		{"", "通知"},
		{"   \n正文", "通知"},
		{"单行标题", "单行标题"},
		{"带回车\r\n下一行", "带回车"},
		{strings.Repeat("长", 80), strings.Repeat("长", 20) + "…"},
	}
	for _, tc := range cases {
		if got := firstLine(tc.in); got != tc.want {
			t.Errorf("firstLine(%q) = %q，期望 %q", tc.in, got, tc.want)
		}
	}
}

func TestBackoffCaps(t *testing.T) {
	cases := map[int]time.Duration{
		1:  5 * time.Second,
		2:  15 * time.Second,
		3:  45 * time.Second,
		4:  60 * time.Second,
		10: 60 * time.Second,
	}
	for attempt, want := range cases {
		if got := backoff(attempt); got != want {
			t.Errorf("backoff(%d) = %s，期望 %s", attempt, got, want)
		}
	}
}

func TestTimeoutOf(t *testing.T) {
	cases := map[int]time.Duration{
		0:    config.DefaultNotifyTimeoutSec * time.Second,
		-3:   config.DefaultNotifyTimeoutSec * time.Second,
		5:    5 * time.Second,
		9999: config.MaxNotifyTimeoutSec * time.Second,
	}
	for sec, want := range cases {
		if got := timeoutOf(config.NotifyTarget{TimeoutSec: sec}); got != want {
			t.Errorf("timeoutOf(%d) = %s，期望 %s", sec, got, want)
		}
	}
}

func TestStatusTextTruncates(t *testing.T) {
	long := strings.Repeat("e", 400)
	if got := statusText(errors.New(long), ""); len(got) > 310 {
		t.Fatalf("错误文本未裁剪，长度 %d", len(got))
	}
	if got := statusText(nil, strings.Repeat("d", 400)); len(got) > 310 {
		t.Fatalf("detail 未裁剪，长度 %d", len(got))
	}
	if got := statusText(nil, "HTTP 200"); got != "HTTP 200" {
		t.Fatalf("短文本应原样返回，得到 %q", got)
	}
}

// ---------- 钉钉投递 ----------

func TestSendDingTalkText(t *testing.T) {
	srv, c := newServer(t, nil)
	tgt := config.NotifyTarget{
		ID: "d1", Name: "钉钉群", Type: "dingtalk", Enabled: true, URL: srv.URL,
		AtMobiles: []string{"13800000000"}, AtAll: true,
	}
	m, _, _ := newModule(t, tgt)

	res := sendOnce(t, m, Request{TargetIDs: []string{"d1"}, Message: "通知已提交", Format: "text"})
	if !res.OK {
		t.Fatalf("应投递成功，实际 %q", res.Status)
	}

	p := c.payload(t)
	if p["msgtype"] != "text" {
		t.Fatalf("msgtype 期望 text，实际 %v", p["msgtype"])
	}
	content, _ := p["text"].(map[string]any)["content"].(string)
	// 钉钉只有正文里出现 @手机号 时 @ 才真的亮起来，光填 at.atMobiles 是无效的。
	if !strings.HasSuffix(content, " @13800000000") {
		t.Fatalf("正文里应补上 @手机号，实际 %q", content)
	}
	at, _ := p["at"].(map[string]any)
	if at["isAtAll"] != true {
		t.Fatalf("isAtAll 应为 true，实际 %v", at["isAtAll"])
	}
	if got, _ := at["atMobiles"].([]any); len(got) != 1 || got[0] != "13800000000" {
		t.Fatalf("atMobiles 不符：%v", at["atMobiles"])
	}
}

func TestSendDingTalkMarkdownTitleFallback(t *testing.T) {
	srv, c := newServer(t, nil)
	m, _, _ := newModule(t, config.NotifyTarget{
		ID: "d1", Name: "钉钉群", Type: "dingtalk", Enabled: true, URL: srv.URL,
	})

	sendOnce(t, m, Request{
		TargetIDs: []string{"d1"},
		Message:   "## 每日通知已提交\n编号：A-1",
		Format:    "markdown",
	})

	md, _ := c.payload(t)["markdown"].(map[string]any)
	// 钉钉的 markdown 必须带 title，缺了整条消息发不出去，所以用正文首行兜住。
	if md["title"] != "每日通知已提交" {
		t.Fatalf("title 应回落到正文首行，实际 %v", md["title"])
	}
}

func TestSendDingTalkTruncates(t *testing.T) {
	srv, c := newServer(t, nil)
	m, _, _ := newModule(t, config.NotifyTarget{
		ID: "d1", Name: "钉钉群", Type: "dingtalk", Enabled: true, URL: srv.URL,
	})

	sendOnce(t, m, Request{TargetIDs: []string{"d1"}, Message: strings.Repeat("a", dingMaxBytes+50), Format: "text"})

	content, _ := c.payload(t)["text"].(map[string]any)["content"].(string)
	if !strings.HasSuffix(content, "…（已截断）") {
		t.Fatalf("超长消息应被截断，尾部为 %q", content[len(content)-20:])
	}
	if len(content) != dingMaxBytes+len("…（已截断）") {
		t.Fatalf("截断长度不符：%d", len(content))
	}
}

// ---------- 企业微信投递 ----------

func TestSendWeComTextMentions(t *testing.T) {
	srv, c := newServer(t, nil)
	m, _, _ := newModule(t, config.NotifyTarget{
		ID: "w1", Name: "企微群", Type: "wecom", Enabled: true, URL: srv.URL,
		AtMobiles: []string{"13900000000"}, AtAll: true,
	})

	sendOnce(t, m, Request{TargetIDs: []string{"w1"}, Message: "库存告警", Format: "text"})

	text, _ := c.payload(t)["text"].(map[string]any)
	got, _ := text["mentioned_mobile_list"].([]any)
	// 企业微信用列表里的 "@all" 表示 @全体成员，没有单独的开关字段。
	if len(got) != 2 || got[0] != "13900000000" || got[1] != "@all" {
		t.Fatalf("mentioned_mobile_list 不符：%v", text["mentioned_mobile_list"])
	}
}

func TestSendWeComMarkdownDropsMentions(t *testing.T) {
	srv, c := newServer(t, nil)
	m, _, _ := newModule(t, config.NotifyTarget{
		ID: "w1", Name: "企微群", Type: "wecom", Enabled: true, URL: srv.URL,
		AtMobiles: []string{"13900000000"}, AtAll: true,
	})

	sendOnce(t, m, Request{TargetIDs: []string{"w1"}, Message: "## 库存告警", Format: "markdown"})

	_, _, _, body, _ := c.snapshot()
	// 企业微信的 markdown 不认手机号 @，如实不发比伪造一段假 @ 文本好。
	if strings.Contains(string(body), "mentioned_mobile_list") || strings.Contains(string(body), "13900000000") {
		t.Fatalf("markdown 不应带 @ 信息：%s", body)
	}
	if _, ok := c.payload(t)["markdown"].(map[string]any); !ok {
		t.Fatalf("应发 markdown 消息：%s", body)
	}
}

func TestSendWeComTruncates(t *testing.T) {
	cases := []struct {
		format string
		limit  int
		field  string
	}{
		{"text", wecomTextMaxBytes, "text"},
		{"markdown", wecomMarkdownMaxByte, "markdown"},
	}
	for _, tc := range cases {
		t.Run(tc.format, func(t *testing.T) {
			srv, c := newServer(t, nil)
			m, _, _ := newModule(t, config.NotifyTarget{
				ID: "w1", Name: "企微群", Type: "wecom", Enabled: true, URL: srv.URL,
			})

			sendOnce(t, m, Request{
				TargetIDs: []string{"w1"},
				Message:   strings.Repeat("b", tc.limit+100),
				Format:    tc.format,
			})

			content, _ := c.payload(t)[tc.field].(map[string]any)["content"].(string)
			if len(content) != tc.limit+len("…（已截断）") {
				t.Fatalf("截断长度不符：%d（上限 %d）", len(content), tc.limit)
			}
		})
	}
}

// ---------- 自定义 HTTP 投递 ----------

func TestSendHTTPDefaultBody(t *testing.T) {
	srv, c := newServer(t, func(w http.ResponseWriter, _ int) { _, _ = w.Write([]byte("ok")) })
	m, _, _ := newModule(t, config.NotifyTarget{
		ID: "h1", Name: "自建", Type: "http", Enabled: true, URL: srv.URL,
	})

	// 消息里带引号和换行：默认体若是拼字符串而不是 json.Marshal，这里就会拼出坏 JSON。
	msg := "第一行\n他说\"好\""
	sendOnce(t, m, Request{TargetIDs: []string{"h1"}, Message: msg, Format: "text"})

	p := c.payload(t)
	if p["text"] != msg {
		t.Fatalf("默认请求体不符：%v", p)
	}
	method, _, headers, _, _ := c.snapshot()
	if method != http.MethodPost {
		t.Fatalf("默认方法应为 POST，实际 %s", method)
	}
	if ct := headers.Get("Content-Type"); ct != "application/json" {
		t.Fatalf("默认 Content-Type 应为 application/json，实际 %q", ct)
	}
}

func TestSendHTTPBodyTemplate(t *testing.T) {
	srv, c := newServer(t, func(w http.ResponseWriter, _ int) { _, _ = w.Write([]byte("ok")) })
	m, _, _ := newModule(t, config.NotifyTarget{
		ID: "h1", Name: "自建", Type: "http", Enabled: true, URL: srv.URL,
		BodyTemplate: `{"content": {{.messageJSON}}, "no": "{{.body.code}}"}`,
	})

	msg := "每日通知\n编号：A-1"
	res := sendOnce(t, m, Request{
		TargetIDs: []string{"h1"}, Message: msg, Format: "text",
		Data: map[string]any{"body": map[string]any{"code": "A-1"}},
	})
	if !res.OK {
		t.Fatalf("应投递成功，实际 %q", res.Status)
	}

	p := c.payload(t)
	// messageJSON 是带引号的字面量：含换行的消息只有这样才能安全塞进 JSON。
	if p["content"] != msg {
		t.Fatalf("content 不符：%v", p["content"])
	}
	if p["no"] != "A-1" {
		t.Fatalf("事件字段应平铺在顶层，实际 %v", p["no"])
	}
}

func TestSendHTTPRejectsInvalidJSON(t *testing.T) {
	srv, c := newServer(t, nil)
	m, _, _ := newModule(t, config.NotifyTarget{
		ID: "h1", Name: "自建", Type: "http", Enabled: true, URL: srv.URL,
		BodyTemplate: `{"content": "{{.message}}"}`,
	})

	res := sendOnce(t, m, Request{TargetIDs: []string{"h1"}, Message: `他说"好"`, Format: "text"})
	if res.OK {
		t.Fatal("坏 JSON 应在发出前就被拦下")
	}
	// 报错要指路到正确写法，否则用户只看到"投递失败"，想不到是模板里少了转义。
	if !strings.Contains(res.Status, "messageJSON") {
		t.Fatalf("错误应指向 messageJSON，实际 %q", res.Status)
	}
	if _, _, _, _, hits := c.snapshot(); hits != 0 {
		t.Fatalf("坏 JSON 不该发出去，对端收到 %d 次", hits)
	}
}

func TestSendHTTPNonJSONSkipsPreflight(t *testing.T) {
	srv, c := newServer(t, func(w http.ResponseWriter, _ int) { _, _ = w.Write([]byte("ok")) })
	m, _, _ := newModule(t, config.NotifyTarget{
		ID: "h1", Name: "自建", Type: "http", Enabled: true, URL: srv.URL,
		Method: http.MethodPut, ContentType: "text/plain",
		Headers:      map[string]string{"Authorization": "Bearer token123"},
		BodyTemplate: `纯文本：{{.message}}`,
	})

	res := sendOnce(t, m, Request{TargetIDs: []string{"h1"}, Message: "告警", Format: "text"})
	if !res.OK {
		t.Fatalf("非 JSON 请求体应照发，实际 %q", res.Status)
	}

	method, _, headers, body, _ := c.snapshot()
	if method != http.MethodPut {
		t.Fatalf("方法应为 PUT，实际 %s", method)
	}
	if headers.Get("Authorization") != "Bearer token123" {
		t.Fatalf("附加请求头没送出去：%v", headers)
	}
	if string(body) != "纯文本：告警" {
		t.Fatalf("请求体不符：%q", body)
	}
}

func TestSendHTTPBrokenTemplate(t *testing.T) {
	srv, c := newServer(t, nil)
	m, _, _ := newModule(t, config.NotifyTarget{
		ID: "h1", Name: "自建", Type: "http", Enabled: true, URL: srv.URL,
		BodyTemplate: `{{if}}`,
	})

	res := sendOnce(t, m, Request{TargetIDs: []string{"h1"}, Message: "x", Format: "text"})
	if res.OK {
		t.Fatal("模板编译失败时不该投递成功")
	}
	// 保留目标而不是丢掉它，就是为了能给出"模板有错"这个准确原因。
	if !strings.Contains(res.Status, "请求体模板有错") {
		t.Fatalf("原因应说明模板有错，实际 %q", res.Status)
	}
	if _, _, _, _, hits := c.snapshot(); hits != 0 {
		t.Fatalf("不该发出请求，对端收到 %d 次", hits)
	}
}

func TestBodyDataReservedFields(t *testing.T) {
	m, _, _ := newModule(t)
	data := m.bodyData(Request{
		Message: "正文\n第二行",
		Title:   "标题",
		Format:  "markdown",
		// 与保留字段同名的事件字段会被覆盖，这一点界面上有写明。
		Data: map[string]any{"message": "用户自己的字段", "code": "MSG-9"},
	})

	if data[fieldMessage] != "正文\n第二行" {
		t.Fatalf("message 应为渲染结果，实际 %v", data[fieldMessage])
	}
	if data["code"] != "MSG-9" {
		t.Fatalf("事件字段应平铺，实际 %v", data["code"])
	}
	if data[fieldTitle] != "标题" || data[fieldFormat] != "markdown" {
		t.Fatalf("title/format 不符：%v %v", data[fieldTitle], data[fieldFormat])
	}
	if _, ok := data[fieldEvent]; !ok {
		t.Fatal("应保留一份完整事件供字段名冲突时取用")
	}
	// messageJSON 必须是带引号的 JSON 字符串字面量。
	js, _ := data[fieldMessageJSON].(string)
	if !strings.HasPrefix(js, `"`) || !strings.HasSuffix(js, `"`) || !strings.Contains(js, `\n`) {
		t.Fatalf("messageJSON 应是带引号且已转义的字面量，实际 %q", js)
	}
}

// ---------- 结果、计数与运行态 ----------

// 同步 Send 刻意不记账：它是诊断路径（测试发送），结果直接交回调用方由界面展示。
// 若它也走 report，一次点按钮就会让目标的成功计数上涨、并在执行历史里多出一条
// 没有入站事件的记录——两者都会让"这个目标发出去过多少条"不再可信。
func TestSendDoesNotTouchMetricsOrState(t *testing.T) {
	srv, _ := newServer(t, nil)
	m, store, _ := newModule(t, config.NotifyTarget{
		ID: "d1", Name: "钉钉群", Type: "dingtalk", Enabled: true, URL: srv.URL,
	})

	res := sendOnce(t, m, Request{TargetIDs: []string{"d1"}, Message: "ok", Format: "text"})
	if !res.OK || res.Status != "HTTP 200" || res.Attempt != 1 {
		t.Fatalf("结果不符：%+v", res)
	}
	if res.CostMS < 0 || res.At == 0 {
		t.Fatalf("耗时与时间戳应已填好：%+v", res)
	}
	if sent, failed, dropped, pending := m.Metrics(); sent != 0 || failed != 0 || dropped != 0 || pending != 0 {
		t.Fatalf("同步投递不应记账：sent=%d failed=%d dropped=%d pending=%d", sent, failed, dropped, pending)
	}
	if st := store.Send("d1"); st.Sent != 0 || st.LastStatus != "" {
		t.Fatalf("同步投递不应回写运行态：%+v", st)
	}
}

// 异步 Enqueue 才是真实推送的路径：计数与运行态都由它负责。
func TestEnqueueWritesStateOnSuccess(t *testing.T) {
	srv, _ := newServer(t, nil)
	m, store, results := newModule(t, config.NotifyTarget{
		ID: "d1", Name: "钉钉群", Type: "dingtalk", Enabled: true, URL: srv.URL,
	})

	if err := m.Enqueue(Request{TargetIDs: []string{"d1"}, Message: "ok", Format: "text"}); err != nil {
		t.Fatalf("Enqueue: %v", err)
	}
	res := waitResult(t, results)
	if !res.OK || res.Status != "HTTP 200" {
		t.Fatalf("结果不符：%+v", res)
	}
	if sent, failed, dropped, _ := m.Metrics(); sent != 1 || failed != 0 || dropped != 0 {
		t.Fatalf("计数不符：sent=%d failed=%d dropped=%d", sent, failed, dropped)
	}
	st := store.Send("d1")
	if st.Sent != 1 || st.Fail != 0 || st.LastStatus != "HTTP 200" || st.LastAt == 0 {
		t.Fatalf("运行态回写不符：%+v", st)
	}
}

// 业务失败（HTTP 200 + errcode）必须计入失败，否则面板会显示一切正常而群里什么都没有。
func TestBusinessFailureOnHTTP200CountsAsFailure(t *testing.T) {
	srv, _ := newServer(t, func(w http.ResponseWriter, _ int) {
		_, _ = w.Write([]byte(`{"errcode":310000,"errmsg":"keywords not in content"}`))
	})
	m, store, results := newModule(t, config.NotifyTarget{
		ID: "d1", Name: "钉钉群", Type: "dingtalk", Enabled: true, URL: srv.URL,
	})

	if err := m.Enqueue(Request{TargetIDs: []string{"d1"}, Message: "ok", Format: "text"}); err != nil {
		t.Fatalf("Enqueue: %v", err)
	}
	res := waitResult(t, results)
	if res.OK {
		t.Fatal("HTTP 200 + 非 0 errcode 必须判为失败")
	}
	if !strings.Contains(res.Status, "310000") {
		t.Fatalf("原因里应带上 errcode：%q", res.Status)
	}
	if sent, failed, _, _ := m.Metrics(); sent != 0 || failed != 1 {
		t.Fatalf("计数不符：sent=%d failed=%d", sent, failed)
	}
	if st := store.Send("d1"); st.Fail != 1 || !strings.Contains(st.LastStatus, "310000") {
		t.Fatalf("运行态回写不符：%+v", st)
	}
}

// 目标被删掉却忘了从规则里摘掉时，表现是"规则命中了但什么都没发生"——
// 最难排查的一类故障，所以这里必须留下结果记录。
func TestSendReportsMissingAndDisabledTargets(t *testing.T) {
	m, _, results := newModule(t, config.NotifyTarget{
		ID: "off", Name: "已停用", Type: "dingtalk", Enabled: false, URL: "https://example.com",
	})

	_, err := m.Send(context.Background(), Request{TargetIDs: []string{"gone", "off", "off", ""}})
	if !errors.Is(err, ErrNoTarget) {
		t.Fatalf("期望 ErrNoTarget，实际 %v", err)
	}

	statuses := map[string]string{}
	for i := 0; i < 2; i++ {
		r := waitResult(t, results)
		statuses[r.TargetID] = r.Status
	}
	if !strings.Contains(statuses["gone"], "目标不存在") {
		t.Fatalf("缺失目标的原因不符：%q", statuses["gone"])
	}
	if !strings.Contains(statuses["off"], "目标已禁用") {
		t.Fatalf("停用目标的原因不符：%q", statuses["off"])
	}
	if _, failed, _, _ := m.Metrics(); failed != 2 {
		t.Fatalf("失败数期望 2，实际 %d", failed)
	}
}

func TestSendNoTargetIDs(t *testing.T) {
	m, _, _ := newModule(t)
	if _, err := m.Send(context.Background(), Request{}); !errors.Is(err, ErrNoTarget) {
		t.Fatalf("期望 ErrNoTarget，实际 %v", err)
	}
}

func TestDispatchRejectsEmptyURLAndUnknownType(t *testing.T) {
	m, _, _ := newModule(t,
		config.NotifyTarget{ID: "empty", Name: "空地址", Type: "dingtalk", Enabled: true, URL: "  "},
		config.NotifyTarget{ID: "weird", Name: "未知类型", Type: "feishu", Enabled: true, URL: "https://example.com"},
	)

	if res := sendOnce(t, m, Request{TargetIDs: []string{"empty"}}); res.OK || !strings.Contains(res.Status, "目标地址为空") {
		t.Fatalf("空地址应报错，实际 %+v", res)
	}
	if res := sendOnce(t, m, Request{TargetIDs: []string{"weird"}}); res.OK || !strings.Contains(res.Status, "不支持的目标类型") {
		t.Fatalf("未知类型应报错，实际 %+v", res)
	}
}

// ---------- 重试 ----------

func TestEnqueueRetryThenSuccess(t *testing.T) {
	shortRetry(t)
	srv, _ := newServer(t, func(w http.ResponseWriter, hit int) {
		if hit == 1 {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		_, _ = w.Write([]byte(`{"errcode":0}`))
	})
	m, store, results := newModule(t, config.NotifyTarget{
		ID: "d1", Name: "钉钉群", Type: "dingtalk", Enabled: true, URL: srv.URL, Retry: 2,
	})

	if err := m.Enqueue(Request{TargetIDs: []string{"d1"}, Message: "ok", Format: "text"}); err != nil {
		t.Fatalf("Enqueue: %v", err)
	}

	first := waitResult(t, results)
	if first.OK || !first.Retrying || first.Attempt != 1 {
		t.Fatalf("首投应是失败但仍标记重试：%+v", first)
	}
	second := waitResult(t, results)
	if !second.OK || second.Attempt != 2 {
		t.Fatalf("重投应成功：%+v", second)
	}

	// 一次"重试后成功"不能既记 1 失败又记 1 成功。
	if sent, failed, _, _ := m.Metrics(); sent != 1 || failed != 0 {
		t.Fatalf("计数不符：sent=%d failed=%d", sent, failed)
	}
	// 重试中的失败不写运行态，否则面板状态会在几秒内来回跳。
	if st := store.Send("d1"); st.Sent != 1 || st.Fail != 0 {
		t.Fatalf("运行态不符：%+v", st)
	}
}

func TestEnqueueRetriesExhausted(t *testing.T) {
	shortRetry(t)
	srv, c := newServer(t, func(w http.ResponseWriter, _ int) { w.WriteHeader(http.StatusInternalServerError) })
	m, store, results := newModule(t, config.NotifyTarget{
		ID: "d1", Name: "钉钉群", Type: "dingtalk", Enabled: true, URL: srv.URL, Retry: 1,
	})

	if err := m.Enqueue(Request{TargetIDs: []string{"d1"}, Message: "ok", Format: "text"}); err != nil {
		t.Fatalf("Enqueue: %v", err)
	}

	if first := waitResult(t, results); first.OK || !first.Retrying {
		t.Fatalf("首投应标记为还会重试：%+v", first)
	}
	final := waitResult(t, results)
	if final.OK || final.Retrying || final.Attempt != 2 {
		t.Fatalf("重试用尽后应是最终失败：%+v", final)
	}

	if sent, failed, _, _ := m.Metrics(); sent != 0 || failed != 1 {
		t.Fatalf("只有最终失败才计入失败数：sent=%d failed=%d", sent, failed)
	}
	if st := store.Send("d1"); !strings.Contains(st.LastStatus, "第 2 次尝试后放弃") {
		t.Fatalf("运行态应说明放弃于第几次：%q", st.LastStatus)
	}
	if _, _, _, _, hits := c.snapshot(); hits != 2 {
		t.Fatalf("Retry=1 应共投 2 次，实际 %d", hits)
	}
}

// ---------- 队列、关闭与内网防护 ----------

// 队列满必须明确拒绝并记账：无界队列在对方持续故障时会把内存吃光，
// 而静默丢弃会让用户对着空日志猜。
func TestPushRejectsWhenQueueFull(t *testing.T) {
	tgt := config.NotifyTarget{ID: "d1", Name: "钉钉群", Type: "dingtalk", Enabled: true, URL: "https://example.com"}

	// 手工构造：不启 worker，队列才会真的填满。
	m := &Module{
		log:         logx.New(logx.Options{}),
		stats:       runstats.New(),
		targets:     map[string]*targetRT{"d1": {cfg: tgt}},
		retryTimers: map[*time.Timer]struct{}{},
		queue:       make(chan *task, 1),
		stop:        make(chan struct{}),
	}
	results := make(chan Result, 4)
	m.SetResultSink(func(r Result) { results <- r })

	job := func() *task {
		return &task{req: Request{TargetIDs: []string{"d1"}}, target: m.targets["d1"], attempt: 1}
	}
	if err := m.push(job()); err != nil {
		t.Fatalf("首个任务应入队成功：%v", err)
	}
	if err := m.push(job()); !errors.Is(err, ErrQueueFull) {
		t.Fatalf("队列满时应返回 ErrQueueFull，实际 %v", err)
	}

	if r := waitResult(t, results); r.OK || !strings.Contains(r.Status, "队列已满") {
		t.Fatalf("应记下一条被自己队列挡下的结果：%+v", r)
	}
	if _, _, dropped, _ := m.Metrics(); dropped != 1 {
		t.Fatalf("丢弃数期望 1，实际 %d", dropped)
	}
	st := m.Status()
	if st.Healthy || st.Code != "dropped" || st.Args["n"] != int64(1) {
		t.Fatalf("队列丢过消息时状态应不健康且报 dropped=1：%+v", st)
	}
}

func TestCloseIsRepeatableAndRejectsNewWork(t *testing.T) {
	m := New(logx.New(logx.Options{}), runstats.New())
	if err := m.Close(); err != nil {
		t.Fatalf("首次 Close: %v", err)
	}
	// 自更新路径会调用两次 CloseAll，重复 Close 不能 panic 也不能报错。
	if err := m.Close(); err != nil {
		t.Fatalf("重复 Close: %v", err)
	}
	if err := m.Enqueue(Request{TargetIDs: []string{"whatever"}}); !errors.Is(err, ErrClosed) {
		t.Fatalf("关闭后应返回 ErrClosed，实际 %v", err)
	}
}

func TestBlockPrivateNetworkBlocksLoopback(t *testing.T) {
	srv, c := newServer(t, nil)
	st := config.Settings{}
	st.Security.BlockPrivateNetwork = true
	m, _, _ := newModuleWithSettings(t, st, config.NotifyTarget{
		ID: "h1", Name: "内网自建", Type: "http", Enabled: true, URL: srv.URL,
	})

	res := sendOnce(t, m, Request{TargetIDs: []string{"h1"}, Message: "x", Format: "text"})
	if res.OK {
		t.Fatal("开了内网防护后不该连上 127.0.0.1")
	}
	if !strings.Contains(res.Status, "内网防护") {
		t.Fatalf("原因应说明被内网防护拦截，实际 %q", res.Status)
	}
	if _, _, _, _, hits := c.snapshot(); hits != 0 {
		t.Fatalf("请求应在拨号阶段就被拦下，对端收到 %d 次", hits)
	}
}

// ---------- 目标表与状态 ----------

func TestReloadReplacesTargetsWithoutTouchingWorkers(t *testing.T) {
	m, _, _ := newModule(t, config.NotifyTarget{ID: "a", Name: "旧", Type: "dingtalk", Enabled: true, URL: "https://example.com"})

	if err := m.Reload(&config.Config{NotifyTargets: []config.NotifyTarget{
		{ID: "b", Name: "新", Type: "wecom", Enabled: true, URL: "https://example.com"},
	}}); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	if _, err := m.Send(context.Background(), Request{TargetIDs: []string{"a"}}); !errors.Is(err, ErrNoTarget) {
		t.Fatalf("旧目标应已不存在，实际 %v", err)
	}
	if names := m.Targets(); len(names) != 1 || names["b"] != "新" {
		t.Fatalf("目标表未换成新的：%v", names)
	}
}

func TestTargetsOnlyEnabled(t *testing.T) {
	m, _, _ := newModule(t,
		config.NotifyTarget{ID: "on", Name: "启用", Type: "dingtalk", Enabled: true, URL: "https://example.com"},
		config.NotifyTarget{ID: "off", Name: "停用", Type: "dingtalk", Enabled: false, URL: "https://example.com"},
	)
	names := m.Targets()
	if len(names) != 1 || names["on"] != "启用" {
		t.Fatalf("下拉里只该出现启用的目标：%v", names)
	}
}

func TestStatusReportsBrokenBodyTemplate(t *testing.T) {
	m, _, _ := newModule(t,
		config.NotifyTarget{ID: "ok", Name: "好的", Type: "http", Enabled: true, URL: "https://example.com", BodyTemplate: `{"a":1}`},
		config.NotifyTarget{ID: "bad", Name: "模板坏", Type: "http", Enabled: true, URL: "https://example.com", BodyTemplate: `{{range}}`},
	)
	st := m.Status()
	if st.Total != 2 || st.Active != 2 {
		t.Fatalf("目标计数不符：%+v", st)
	}
	// 模板写错在"保存配置"这一刻就该可见，而不是等第一条真实消息进来才暴露。
	if st.Healthy || st.Code != "bodyErr" || st.Args["n"] != 1 {
		t.Fatalf("有坏模板时状态应不健康且报 bodyErr=1：%+v", st)
	}
}

func TestSupportedTypes(t *testing.T) {
	got := SupportedTypes()
	want := []string{"dingtalk", "wecom", "http"}
	if len(got) != len(want) {
		t.Fatalf("类型清单不符：%v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("类型清单不符：%v", got)
		}
	}
	// 返回的必须是副本，调用方改它不能影响内置清单。
	got[0] = "tampered"
	if !SupportedType("dingtalk") || SupportedType("tampered") {
		t.Fatal("SupportedTypes 返回了内部切片本身")
	}
	if SupportedType("feishu") {
		t.Fatal("飞书尚未内置，不应被判为支持")
	}
}

// ---------- 内存预算 ----------

// 队列的字节账只在"任务只持有字符串"这个前提下才是真的。Data 是第三方推来的
// 整份载荷，大小不由本程序决定；prepareQueued 必须把它摘掉，否则预算形同虚设。
func TestPrepareQueuedDropsEventDataAndPreRendersBody(t *testing.T) {
	m, _, _ := newModule(t, config.NotifyTarget{
		ID: "h1", Name: "自建", Type: "http", Enabled: true,
		URL: "https://example.com", BodyTemplate: `{"no":"{{.消息编号}}"}`,
	})
	tasks, err := m.buildTasks(Request{
		TargetIDs: []string{"h1"}, Message: "x", Format: "text",
		Data: map[string]any{"消息编号": "SO-1"},
	})
	if err != nil {
		t.Fatalf("buildTasks: %v", err)
	}
	if err := m.prepareQueued(tasks[0]); err != nil {
		t.Fatalf("prepareQueued: %v", err)
	}
	if tasks[0].req.Data != nil {
		t.Fatal("排队任务不该继续持有事件数据")
	}
	if string(tasks[0].body) != `{"no":"SO-1"}` {
		t.Fatalf("请求体应在入队时就渲染好，实际 %q", tasks[0].body)
	}
}

func TestReserveStopsAtBudget(t *testing.T) {
	m := &Module{}
	const chunk = 64 << 10
	var n int
	for m.reserve(chunk) {
		n++
		if n > queueMemBudget/chunk {
			t.Fatal("reserve 越过了预算上限")
		}
	}
	if got := m.bytes.Load(); got > queueMemBudget {
		t.Fatalf("已占 %d 字节，超过预算 %d", got, queueMemBudget)
	}
	if n != queueMemBudget/chunk {
		t.Fatalf("64 KB 的任务应能装 %d 个，实际 %d", queueMemBudget/chunk, n)
	}
}

// 字节闸满了要明确拒绝并记账，而不是截短用户的消息，也不是静默丢弃。
func TestPushRejectsWhenMemBudgetFull(t *testing.T) {
	tgt := config.NotifyTarget{ID: "d1", Name: "钉钉群", Type: "dingtalk", Enabled: true, URL: "https://example.com"}
	// 手工构造：不启 worker，任务才会一直占着预算。队列容量放大到条数闸不会先触发。
	m := &Module{
		log:         logx.New(logx.Options{}),
		stats:       runstats.New(),
		targets:     map[string]*targetRT{"d1": {cfg: tgt}},
		retryTimers: map[*time.Timer]struct{}{},
		queue:       make(chan *task, 4096),
		stop:        make(chan struct{}),
	}
	results := make(chan Result, 64)
	m.SetResultSink(func(r Result) { results <- r })

	fat := strings.Repeat("x", 64<<10)
	job := func() *task {
		return &task{req: Request{TargetIDs: []string{"d1"}, Message: fat}, target: m.targets["d1"], attempt: 1}
	}
	var pushed int
	var lastErr error
	for i := 0; i < 64; i++ {
		if err := m.push(job()); err != nil {
			lastErr = err
			break
		}
		pushed++
	}
	if !errors.Is(lastErr, ErrQueueMemFull) {
		t.Fatalf("预算用尽时应返回 ErrQueueMemFull，实际 %v", lastErr)
	}
	if pushed == 0 || m.bytes.Load() > queueMemBudget {
		t.Fatalf("入队 %d 条后占用 %d 字节，预算 %d", pushed, m.bytes.Load(), queueMemBudget)
	}
	if _, _, dropped, _ := m.Metrics(); dropped != 1 {
		t.Fatalf("丢弃数期望 1，实际 %d", dropped)
	}
	// 被挡下的那条必须在执行历史里留下原因，否则用户对着空日志猜。
	// 入队成功的任务不产生结果（worker 没起），所以 channel 里就只有这一条。
	if r := waitResult(t, results); r.OK || !strings.Contains(r.Status, "内存已满") {
		t.Fatalf("应记下一条内存满的结果：%+v", r)
	}
}

// 投递成功后预算必须归零。漏一处 release 的表现是"明明没积压却一直说内存满"。
func TestBudgetReleasedAfterSuccess(t *testing.T) {
	srv, _ := newServer(t, nil)
	m, _, results := newModule(t, config.NotifyTarget{
		ID: "d1", Name: "钉钉群", Type: "dingtalk", Enabled: true, URL: srv.URL,
	})
	if err := m.Enqueue(Request{TargetIDs: []string{"d1"}, Message: "ok", Format: "text"}); err != nil {
		t.Fatalf("Enqueue: %v", err)
	}
	if r := waitResult(t, results); !r.OK {
		t.Fatalf("应投递成功：%+v", r)
	}
	if got := m.bytes.Load(); got != 0 {
		t.Fatalf("投完后预算应归零，实际还占 %d 字节", got)
	}
}

// 一次"首投 + N 次重试"整条链只占一份预算，且链终结时正好还回去一份——
// 不能只减不增（会假报内存满），也不能重复归还（会让预算失效）。
func TestBudgetReleasedOnceAcrossRetryChain(t *testing.T) {
	shortRetry(t)
	srv, _ := newServer(t, func(w http.ResponseWriter, _ int) { w.WriteHeader(http.StatusInternalServerError) })
	m, _, results := newModule(t, config.NotifyTarget{
		ID: "d1", Name: "钉钉群", Type: "dingtalk", Enabled: true, URL: srv.URL, Retry: 2,
	})
	if err := m.Enqueue(Request{TargetIDs: []string{"d1"}, Message: "ok", Format: "text"}); err != nil {
		t.Fatalf("Enqueue: %v", err)
	}
	for i := 0; i < 3; i++ {
		waitResult(t, results)
	}
	if got := m.bytes.Load(); got != 0 {
		t.Fatalf("重试用尽后预算应归零，实际 %d 字节", got)
	}
}
