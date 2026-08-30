package webhook

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"mantou/internal/config"
)

// 本文件盯的是 serve 的**检查顺序与对外表现**：
// Host → 路径 → 方法 → IP → 限流 → 鉴权 → 体积 → 关键词。
// 顺序错了不会有编译错误，只会让被拒的请求白白走完鉴权与解析；
// 而"哪些失败原因可以写进响应体"是安全决定，同样只能靠测试钉住。

// okTpl 一个不依赖载荷结构的模板：信封键 source 永远存在。
func okTpl() config.MessageTemplate { return tpl("t1", "收到 {{.source}}") }

// hitCfg 一个必然命中的配置：无条件规则 + 默认目标。
func hitCfg(mut func(*config.WebhookReceiver)) config.Config {
	rc := recv(rule("a", 0, "t1"))
	if mut != nil {
		mut(&rc)
	}
	return hookCfg(rc, okTpl())
}

// ---------- 路径 ----------

func TestServeSuccess(t *testing.T) {
	h := newHarness(t, hitCfg(nil))
	code, body := h.post(t, "/hook", `{"消息编号":"A-1"}`)
	if code != http.StatusOK {
		t.Fatalf("状态码应为 200，实际 %d：%s", code, body)
	}
	id, matched := h.okBody(t, body)
	if id == "" || matched != 1 {
		t.Fatalf("响应应带事件 ID 与命中数：%s", body)
	}

	reqs := h.n.all()
	if len(reqs) != 1 {
		t.Fatalf("应入队 1 条消息，实际 %d", len(reqs))
	}
	got := reqs[0]
	if got.Message != "收到 第三方系统" || got.EventID != id || got.Source != "第三方系统" || got.RuleName != "规则a" {
		t.Fatalf("入队内容不符：%+v", got)
	}
	if len(got.TargetIDs) != 1 || got.TargetIDs[0] != "g1" {
		t.Fatalf("应回落到接收器默认目标：%v", got.TargetIDs)
	}
	// Data 必须是整个信封，不是渲染后的文本：自定义 HTTP 目标要靠它转发原始字段。
	data, _ := got.Data.(map[string]any)
	if data == nil || data["eventId"] != id {
		t.Fatalf("Data 应是事件信封：%v", got.Data)
	}

	if e := h.last(t); e.Event != EventReceived || e.Receiver != "第三方系统" || e.Status != http.StatusOK {
		t.Fatalf("历史记录不符：%+v", e)
	}
	if received, rejected, dropped := h.m.Metrics(); received != 1 || rejected != 0 || dropped != 0 {
		t.Fatalf("计数不符：%d %d %d", received, rejected, dropped)
	}
	// 面板列表上的"最近收到"靠这几个数，它们只在内存里（internal/runstats），不落盘。
	st := h.stats.Recv("r1")
	if st.Received != 1 || st.LastStatus != "已接收并派发" || st.LastAt == 0 {
		t.Fatalf("统计不符：%+v", st)
	}
}

// 未知路径与已停用的接收器必须给出**完全一样**的响应：
// 路径本身是一层凭证（很多第三方系统只能配一个 URL），
// 用不同的响应区分两者等于给枚举者一个可用的信号。
func TestServeUnknownPathAndDisabledLookIdentical(t *testing.T) {
	known := newHarness(t, hitCfg(nil))
	codeA, bodyA := known.post(t, "/nope", "{}")

	off := newHarness(t, hitCfg(func(rc *config.WebhookReceiver) { rc.Enabled = false }))
	codeB, bodyB := off.post(t, "/hook", "{}")

	if codeA != http.StatusNotFound || codeB != http.StatusNotFound {
		t.Fatalf("两者都该是 404，实际 %d / %d", codeA, codeB)
	}
	if bodyA != bodyB || strings.TrimSpace(bodyA) != "not found" {
		t.Fatalf("响应体应一致且不含细节：%q / %q", bodyA, bodyB)
	}

	// 原因只进历史，用户在面板上看得到。
	e := known.last(t)
	if e.Event != EventRejected || !strings.Contains(e.Reason, "入站路径不存在") || e.ReceiverID != "" {
		t.Fatalf("404 的历史记录不符：%+v", e)
	}
	if _, rejected, _ := known.m.Metrics(); rejected != 1 {
		t.Fatalf("拒收计数应为 1，实际 %d", rejected)
	}
}

// 路径匹配忽略首尾斜杠：第三方系统填 URL 时加不加尾斜杠都有人。
func TestServePathTrimsSlashes(t *testing.T) {
	h := newHarness(t, hitCfg(nil))
	for _, target := range []string{"/hook", "/hook/", "//hook//"} {
		if code, body := h.post(t, target, "{}"); code != http.StatusOK {
			t.Errorf("路径 %q 应命中，实际 %d：%s", target, code, body)
		}
	}
}

// ---------- 方法 ----------

func TestServeMethods(t *testing.T) {
	h := newHarness(t, hitCfg(nil))

	// GET 也放行：有些系统只能在 URL 上带参数推送。
	for _, m := range []string{http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodGet} {
		if code, body := h.do(t, m, "/hook", "{}", nil); code != http.StatusOK {
			t.Errorf("%s 应放行，实际 %d：%s", m, code, body)
		}
	}
	// HEAD / OPTIONS 不放行：它们不携带业务数据，放行只会让健康探测被记成一条消息。
	for _, m := range []string{http.MethodHead, http.MethodOptions, http.MethodDelete} {
		code, body := h.do(t, m, "/hook", "", nil)
		if code != http.StatusMethodNotAllowed {
			t.Errorf("%s 应拒收，实际 %d：%s", m, code, body)
		}
	}
	// 405 的原因可以泄露：对方是用户自己接的系统，需要知道该换哪个方法。
	if _, body := h.do(t, http.MethodDelete, "/hook", "", nil); !strings.Contains(body, "DELETE") {
		t.Errorf("405 应说明是哪个方法：%q", body)
	}
}

// ---------- IP 名单 ----------

func TestServeIPFilter(t *testing.T) {
	// httptest 的对端固定是环回地址，正好用来分别验证放行与拒绝两侧。
	cases := []struct {
		name string
		mut  func(*config.WebhookReceiver)
		want int
	}{
		{"白名单命中", func(rc *config.WebhookReceiver) {
			rc.IPFilter, rc.IPFilterMode, rc.AllowIPs = true, "allow", []string{"127.0.0.0/8", "::1"}
		}, http.StatusOK},
		{"白名单未命中", func(rc *config.WebhookReceiver) {
			rc.IPFilter, rc.IPFilterMode, rc.AllowIPs = true, "allow", []string{"203.0.113.0/24"}
		}, http.StatusForbidden},
		{"黑名单命中", func(rc *config.WebhookReceiver) {
			rc.IPFilter, rc.IPFilterMode, rc.DenyIPs = true, "deny", []string{"127.0.0.0/8", "::1"}
		}, http.StatusForbidden},
		{"黑名单未命中", func(rc *config.WebhookReceiver) {
			rc.IPFilter, rc.IPFilterMode, rc.DenyIPs = true, "deny", []string{"203.0.113.0/24"}
		}, http.StatusOK},
		// 名单为空时过滤不生效（编译期已给出警告），不能变成"谁都进不来"。
		{"开关开着但名单为空", func(rc *config.WebhookReceiver) {
			rc.IPFilter, rc.IPFilterMode = true, "allow"
		}, http.StatusOK},
		{"开关关着名单无效", func(rc *config.WebhookReceiver) {
			rc.AllowIPs = []string{"203.0.113.0/24"}
		}, http.StatusOK},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := newHarness(t, hitCfg(c.mut))
			code, body := h.post(t, "/hook", "{}")
			if code != c.want {
				t.Fatalf("状态码应为 %d，实际 %d：%s", c.want, code, body)
			}
			if code != http.StatusForbidden {
				return
			}
			// 403 只回通用文本：告诉探测者"你不在白名单里"等于确认这个路径存在。
			if strings.TrimSpace(body) != "rejected" {
				t.Fatalf("403 不该泄露原因：%q", body)
			}
			if e := h.last(t); !strings.Contains(e.Reason, "IP") {
				t.Fatalf("原因应进历史：%+v", e)
			}
		})
	}
}

// X-Forwarded-For 不可信：入站端点直接对公网开放，采信这个头等于让任何人
// 一行请求头就绕过 IP 名单。ipx.ClientIP 只读 RemoteAddr。
func TestServeIPFilterIgnoresForwardedHeaders(t *testing.T) {
	h := newHarness(t, hitCfg(func(rc *config.WebhookReceiver) {
		rc.IPFilter, rc.IPFilterMode, rc.AllowIPs = true, "allow", []string{"203.0.113.7"}
	}))
	code, _ := h.do(t, http.MethodPost, "/hook", "{}", func(r *http.Request) {
		r.Header.Set("X-Forwarded-For", "203.0.113.7")
		r.Header.Set("X-Real-IP", "203.0.113.7")
	})
	if code != http.StatusForbidden {
		t.Fatalf("伪造的转发头不该让请求通过白名单，实际 %d", code)
	}
}

// ---------- 限流 ----------

func TestServeRateLimit(t *testing.T) {
	h := newHarness(t, hitCfg(func(rc *config.WebhookReceiver) { rc.RateLimit = 1 }))
	if code, body := h.post(t, "/hook", "{}"); code != http.StatusOK {
		t.Fatalf("首条应通过，实际 %d：%s", code, body)
	}
	code, body := h.post(t, "/hook", "{}")
	if code != http.StatusTooManyRequests {
		t.Fatalf("紧随其后的第二条应被限流，实际 %d：%s", code, body)
	}
	if strings.TrimSpace(body) != "rejected" {
		t.Fatalf("429 不该泄露原因：%q", body)
	}
	if e := h.last(t); e.Status != http.StatusTooManyRequests || !strings.Contains(e.Reason, "限制") {
		t.Fatalf("历史记录不符：%+v", e)
	}
	// 被限流的请求不该计入"已接收"。
	if received, rejected, _ := h.m.Metrics(); received != 1 || rejected != 1 {
		t.Fatalf("计数不符：received=%d rejected=%d", received, rejected)
	}
}

// 限流必须排在鉴权之前：反过来的话，海量错令牌的请求每一条都要走完鉴权。
func TestServeRateLimitBeforeAuth(t *testing.T) {
	h := newHarness(t, hitCfg(func(rc *config.WebhookReceiver) {
		rc.RateLimit, rc.AuthType, rc.Token = 1, "token", "秘密"
	}))
	auth := func(r *http.Request) { r.Header.Set("X-Mantou-Token", "秘密") }
	if code, _ := h.do(t, http.MethodPost, "/hook", "{}", auth); code != http.StatusOK {
		t.Fatal("首条带正确令牌应通过")
	}
	// 令牌是错的，但限流更早：这里必须是 429 而不是 401。
	if code, _ := h.post(t, "/hook", "{}"); code != http.StatusTooManyRequests {
		t.Fatalf("限流应先于鉴权生效，实际 %d", code)
	}
}

// 能归属到接收器的拒收要落到它自己的拒收计数上，且不动「最近收到」那两列（A5/A6）。
//
// 界面上这两个数是分开显示的（「累计 72 次（含拒收 5）」）。混成一个数之后，
// 用户看到的"收到 72 次"里可能有 70 次是被限流挡掉的——而这两件事要做的处置完全不同。
//
// 「最近收到」不受拒收影响是这条修复的另一半：那一列的语义是"上一次真有数据进来"，
// 被挡掉的请求没带来任何数据。让它跟着变，等于把一列信息交给对面单方面控制。
func TestServeRejectionsCountSeparately(t *testing.T) {
	h := newHarness(t, hitCfg(func(rc *config.WebhookReceiver) {
		rc.RateLimit, rc.AuthType, rc.Token = 1, "token", "秘密"
	}))
	auth := func(r *http.Request) { r.Header.Set("X-Mantou-Token", "秘密") }

	// 先正常收一条，把「最近收到」写上。
	if code, _ := h.do(t, http.MethodPost, "/hook", "{}", auth); code != http.StatusOK {
		t.Fatal("首条带正确令牌应通过")
	}
	okAt := h.stats.Recv("r1").LastAt
	if okAt == 0 {
		t.Fatal("正常收下的那条没有写上时刻，后面的断言就没有基准")
	}

	// 每秒 1 次的额度已经用掉，后面三条都被限流挡在鉴权之前（429）。
	for i := 0; i < 3; i++ {
		if code, _ := h.do(t, http.MethodPost, "/hook", "{}", auth); code != http.StatusTooManyRequests {
			t.Fatalf("第 %d 条应被限流挡下，实际 %d", i+2, code)
		}
	}

	got := h.stats.Recv("r1")
	if got.Rejected != 3 {
		t.Fatalf("三条被挡掉的请求应记进拒收计数，实际 %d", got.Rejected)
	}
	if got.Received != 1 {
		t.Fatalf("被挡掉的请求不该算进收下条数，实际 %d", got.Received)
	}
	if got.LastAt != okAt {
		t.Fatalf("被挡掉的请求改动了「最近收到」的时刻：%d → %d", okAt, got.LastAt)
	}
	if got.LastStatus != "已接收并派发" {
		t.Fatalf("被挡掉的请求改写了「最近收到」的结果：%q", got.LastStatus)
	}
}

// 限流状态要跨配置保存存活（见 Module.limiter）。
//
// 桶表原来挂在路由表上、跟着 Reload 一起重建，于是"保存一次配置"等于把所有来源的
// 令牌重新加满：正在被限流的那一方只要等用户在面板上按一次保存就能重新开跑，
// 而这两件事在界面上看不出任何关联。
func TestServeRateLimitSurvivesReload(t *testing.T) {
	cfg := hitCfg(func(rc *config.WebhookReceiver) { rc.RateLimit = 1 })
	h := newHarness(t, cfg)
	if code, body := h.post(t, "/hook", "{}"); code != http.StatusOK {
		t.Fatalf("首条应通过，实际 %d：%s", code, body)
	}
	if err := h.m.Reload(&cfg); err != nil {
		t.Fatalf("Reload 失败：%v", err)
	}
	if code, _ := h.post(t, "/hook", "{}"); code != http.StatusTooManyRequests {
		t.Fatalf("保存一次配置就把令牌重新加满了，实际 %d", code)
	}
}

// 共用的是表的容量，不是令牌：同一个来源打两个接收器，A 的额度用完不该连带堵住 B。
//
// 这是合表之后最容易出的错——桶键漏掉接收器 ID 的话，用户在界面上按接收器配的
// 那个"每秒几次"就变成了所有接收器合起来的总额度。
func TestServeRateLimitCountsPerReceiver(t *testing.T) {
	rcA := recv(rule("a", 0, "t1"))
	rcA.RateLimit = 1
	rcB := rcA
	rcB.ID, rcB.Name, rcB.Path = "r2", "另一个来源", "hook2"
	h := newHarness(t, config.Config{
		WebhookReceivers: []config.WebhookReceiver{rcA, rcB},
		MessageTemplates: []config.MessageTemplate{okTpl()},
	})
	if code, body := h.post(t, "/hook", "{}"); code != http.StatusOK {
		t.Fatalf("接收器 A 的首条应通过，实际 %d：%s", code, body)
	}
	if code, _ := h.post(t, "/hook", "{}"); code != http.StatusTooManyRequests {
		t.Fatal("测试前提不成立：接收器 A 的额度应已用完")
	}
	if code, body := h.post(t, "/hook2", "{}"); code != http.StatusOK {
		t.Fatalf("接收器 B 有自己的额度，实际 %d：%s", code, body)
	}
}

// ---------- 鉴权 ----------

func TestServeAuth(t *testing.T) {
	const token = "s3cr3t-令牌"
	cases := []struct {
		name string
		mut  func(*config.WebhookReceiver)
		req  func(*http.Request)
		want int
	}{
		{"未开启", nil, nil, http.StatusOK},
		{"显式none", func(rc *config.WebhookReceiver) { rc.AuthType = "none" }, nil, http.StatusOK},
		// 选了鉴权却没填令牌：拒收（失败关闭）。放行会让一个以为自己开了鉴权的
		// 用户把入口对全网敞开，而这个错误在界面上完全看不出来。
		{"选了鉴权但没填令牌", func(rc *config.WebhookReceiver) { rc.AuthType = "token" }, nil, http.StatusUnauthorized},
		{"鉴权方式非法", func(rc *config.WebhookReceiver) {
			rc.AuthType, rc.Token = "oauth2", token
		}, nil, http.StatusUnauthorized},

		{"X-Mantou-Token", func(rc *config.WebhookReceiver) { rc.AuthType, rc.Token = "token", token },
			func(r *http.Request) { r.Header.Set("X-Mantou-Token", token) }, http.StatusOK},
		{"Bearer", func(rc *config.WebhookReceiver) { rc.AuthType, rc.Token = "token", token },
			func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+token) }, http.StatusOK},
		// 有些系统只能在 URL 上带参数，令牌只能走 query。
		{"query", func(rc *config.WebhookReceiver) { rc.AuthType, rc.Token = "token", token }, nil, http.StatusOK},
		{"令牌错误", func(rc *config.WebhookReceiver) { rc.AuthType, rc.Token = "token", token },
			func(r *http.Request) { r.Header.Set("X-Mantou-Token", "wrong") }, http.StatusUnauthorized},
		{"什么都没带", func(rc *config.WebhookReceiver) { rc.AuthType, rc.Token = "token", token }, nil, http.StatusUnauthorized},

		// 指定了请求头之后就只认那个头：这类系统的头名是固定的，
		// 同时还认 Bearer 等于给了攻击者第二条通道。
		{"指定头_正确", func(rc *config.WebhookReceiver) {
			rc.AuthType, rc.AuthHeader, rc.Token = "token", "X-Sign", token
		}, func(r *http.Request) { r.Header.Set("X-Sign", token) }, http.StatusOK},
		{"指定头_改走Bearer无效", func(rc *config.WebhookReceiver) {
			rc.AuthType, rc.AuthHeader, rc.Token = "token", "X-Sign", token
		}, func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+token) }, http.StatusUnauthorized},

		{"header方式", func(rc *config.WebhookReceiver) {
			rc.AuthType, rc.AuthHeader, rc.Token = "header", "X-Sign", token
		}, func(r *http.Request) { r.Header.Set("X-Sign", token) }, http.StatusOK},
		{"header方式没填头名", func(rc *config.WebhookReceiver) {
			rc.AuthType, rc.Token = "header", token
		}, func(r *http.Request) { r.Header.Set("X-Sign", token) }, http.StatusUnauthorized},
		// 对方发来的值带首尾空白很常见（配置里多敲了个空格）。
		{"值带空白", func(rc *config.WebhookReceiver) { rc.AuthType, rc.Token = "token", token },
			func(r *http.Request) { r.Header.Set("X-Mantou-Token", " "+token+" ") }, http.StatusOK},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := newHarness(t, hitCfg(c.mut))
			target := "/hook"
			if c.name == "query" {
				target += "?token=" + token
			}
			code, body := h.do(t, http.MethodPost, target, "{}", c.req)
			if code != c.want {
				t.Fatalf("状态码应为 %d，实际 %d：%s", c.want, code, body)
			}
			if code != http.StatusUnauthorized {
				return
			}
			// 401 只回通用文本：区分"令牌错"与"没开鉴权"会告诉探测者下一步该试什么。
			if strings.TrimSpace(body) != "rejected" {
				t.Fatalf("401 不该泄露原因：%q", body)
			}
			if strings.Contains(body, token) {
				t.Fatal("响应体里绝不能出现令牌")
			}
			if e := h.last(t); e.Event != EventRejected || e.Reason == "" {
				t.Fatalf("原因应进历史：%+v", e)
			}
		})
	}
}

// ---------- 体积 ----------

func TestServeBodyLimit(t *testing.T) {
	h := newHarness(t, hitCfg(func(rc *config.WebhookReceiver) { rc.MaxBodyKB = 1 }))

	// 刚好等于上限必须通过：用户把 MaxBodyKB 调到刚好够用是常见做法，
	// 差一个字节就拒收会变成一个查不出原因的间歇性故障。
	exact := `{"x":"` + strings.Repeat("a", 1024-8) + `"}`
	if len(exact) != 1024 {
		t.Fatalf("测试样本长度应为 1024，实际 %d", len(exact))
	}
	if code, body := h.post(t, "/hook", exact); code != http.StatusOK {
		t.Fatalf("刚好等于上限应通过，实际 %d：%s", code, body)
	}

	code, body := h.post(t, "/hook", `{"x":"`+strings.Repeat("a", 4096)+`"}`)
	if code != http.StatusRequestEntityTooLarge {
		t.Fatalf("超限应给 413，实际 %d：%s", code, body)
	}
	// 413 的原因要泄露：对方是用户自己的系统，而"去哪里调大"只有这里说得清。
	if !strings.Contains(body, "请求体超过上限") || !strings.Contains(body, "1 KB") {
		t.Fatalf("413 应说明上限与去哪调整：%q", body)
	}
	if received, rejected, _ := h.m.Metrics(); received != 1 || rejected != 1 {
		t.Fatalf("计数不符：received=%d rejected=%d", received, rejected)
	}
}

// ---------- 关键词准入 ----------
//
// 与钉钉、企业微信的「自定义关键词」同一个思路，方向相反：要求**收到的**消息里带上
// 约定的词，带了才往下走。判据刻意落在原始文本上——第三方推来的可能是 JSON、
// 一段自己拼的文本、甚至一个 txt，任何"先按结构取字段再比对"的写法都会在下一个来源上失效。

// kwCfg 一份开着关键词准入的必然命中配置。
func kwCfg(mode string, words ...string) config.Config {
	return hitCfg(func(rc *config.WebhookReceiver) {
		rc.KeywordFilter, rc.KeywordMode, rc.Keywords = true, mode, words
	})
}

// urlEscape 中文进查询串要先转义，否则 http.NewRequest 直接报 URL 非法。
func urlEscape(s string) string { return url.QueryEscape(s) }

func TestServeKeywordFilter(t *testing.T) {
	cases := []struct {
		name string
		cfg  config.Config
		body string
		want int
	}{
		{"任一：命中", kwCfg("any", "每日汇总", "报警"), `{"标题":"每日汇总已处理"}`, http.StatusOK},
		{"任一：命中第二个", kwCfg("any", "每日汇总", "报警"), `{"msg":"磁盘报警"}`, http.StatusOK},
		{"任一：一个都没有", kwCfg("any", "每日汇总", "报警"), `{"msg":"每日心跳"}`, http.StatusForbidden},
		{"全部：都在", kwCfg("all", "每日", "已审核"), `{"msg":"每日汇总已审核"}`, http.StatusOK},
		{"全部：差一个", kwCfg("all", "每日", "已审核"), `{"msg":"每日汇总待审核"}`, http.StatusForbidden},
		// 大小写不敏感：用户填的是"要求带上的词"，不是一条精确取值路径。
		{"大小写不敏感", kwCfg("any", "Alert"), `{"level":"ALERT"}`, http.StatusOK},
		// 纯文本来源同样有效——这正是不解析结构的意义。
		{"txt 来源", kwCfg("any", "报警"), `磁盘 /data 使用率 95%，报警`, http.StatusOK},
		// 词在 JSON 的键名里也算：那也是消息的一部分，且不解析就无从区分键与值。
		{"键名里的词也算", kwCfg("any", "报警"), `{"报警级别":3}`, http.StatusOK},
		// 开关关着时词表不生效，否则用户"先填好词再决定要不要开"这一步就会误伤。
		{"开关关着", hitCfg(func(rc *config.WebhookReceiver) {
			rc.Keywords = []string{"每日汇总"}
		}), `{"msg":"每日心跳"}`, http.StatusOK},
		// 与 IP 名单同口径：开着但词表为空时失败开放（编译期已记警告）。
		// 反过来会让一份手改坏的配置把某个来源整体静默拒死。
		{"开关开着但词表为空", kwCfg("any"), `{"msg":"每日心跳"}`, http.StatusOK},
		{"词表只有空白", kwCfg("any", "   "), `{"msg":"每日心跳"}`, http.StatusOK},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := newHarness(t, c.cfg)
			code, body := h.post(t, "/hook", c.body)
			if code != c.want {
				t.Fatalf("状态码应为 %d，实际 %d：%s", c.want, code, body)
			}
			if code != http.StatusForbidden {
				return
			}
			// 403 只回通用文本：告诉对方"缺哪个词"等于把词表交给探测者去凑。
			if strings.TrimSpace(body) != "rejected" {
				t.Fatalf("403 不该泄露原因：%q", body)
			}
			// 原因照常进历史——用户在面板上要能判断是第三方改了措辞还是词填错了。
			if e := h.last(t); e.Event != EventRejected || !strings.Contains(e.Reason, "关键词") {
				t.Fatalf("原因应进历史：%+v", e)
			}
		})
	}
}

// 缺词的那一条要指名道姓：全部模式下词表可能有好几个，
// 只说"没通过"用户得自己一个个试。
func TestServeKeywordRejectionNamesTheMissingWord(t *testing.T) {
	h := newHarness(t, kwCfg("all", "每日", "已审核"))
	if code, _ := h.post(t, "/hook", `{"msg":"每日汇总待审核"}`); code != http.StatusForbidden {
		t.Fatalf("差一个词应被拒，实际 %d", code)
	}
	if e := h.last(t); !strings.Contains(e.Reason, "已审核") {
		t.Fatalf("原因应点出缺的那个词：%q", e.Reason)
	}
}

// 只能在 URL 上带参数推送的来源（见 event.go 的 query 说明）没有请求体，
// 只看正文会把它们全部拒掉。取的是解码后的值：中文关键词在 RawQuery 里是一串 %E4%B8...。
func TestServeKeywordFilterReadsQuery(t *testing.T) {
	h := newHarness(t, kwCfg("any", "报警"))
	if code, body := h.do(t, http.MethodGet, "/hook?msg="+urlEscape("磁盘报警"), "", nil); code != http.StatusOK {
		t.Fatalf("查询串里的词应算命中，实际 %d：%s", code, body)
	}
	if code, _ := h.do(t, http.MethodGet, "/hook?msg="+urlEscape("每日心跳"), "", nil); code != http.StatusForbidden {
		t.Fatalf("查询串里没有词应被拒，实际 %d", code)
	}
	// 参数名不参与比对：那是第三方定的结构，不是消息内容。
	if code, _ := h.do(t, http.MethodGet, "/hook?"+urlEscape("报警")+"=1", "", nil); code != http.StatusForbidden {
		t.Fatalf("参数名不该算命中，实际 %d", code)
	}
}

// 关键词准入必须排在鉴权之后：反过来的话，一个连令牌都不对的请求
// 会先被读完整个请求体、再逐词扫一遍。
func TestServeKeywordFilterAfterAuth(t *testing.T) {
	cfg := kwCfg("any", "每日汇总")
	cfg.WebhookReceivers[0].AuthType = "token"
	cfg.WebhookReceivers[0].Token = "正确令牌"
	h := newHarness(t, cfg)

	// 令牌错、词也不对：应该报的是令牌，不是关键词。
	if code, _ := h.post(t, "/hook", `{"msg":"每日心跳"}`); code != http.StatusUnauthorized {
		t.Fatalf("鉴权应先拦，实际 %d", code)
	}
	if e := h.last(t); !strings.Contains(e.Reason, "令牌") {
		t.Fatalf("原因应是令牌：%q", e.Reason)
	}
}

// 试运行中被关键词拦下的请求：抓包里要带上请求体。
// 拒收原因说的是"正文里没有那个词"，看不到正文就没法判断该改词表还是改来源。
func TestKeywordRejectionInTestRunKeepsBody(t *testing.T) {
	h := newHarness(t, kwCfg("any", "每日汇总"))
	if err := h.m.TestRunStart("r1"); err != nil {
		t.Fatal(err)
	}
	const body = `{"msg":"每日心跳"}`
	if code, _ := h.post(t, "/hook", body); code != http.StatusForbidden {
		t.Fatalf("试运行中也照样拒收，实际 %d", code)
	}
	st := h.m.TestRunState("r1")
	if st.Capture == nil {
		t.Fatalf("应抓到一条：%+v", st)
	}
	c := *st.Capture
	if !c.Rejected || c.Body != body {
		t.Fatalf("抓包应带上被拒的正文：%+v", c)
	}
	// 试运行期间的流量只属于试运行面板，不进历史。
	if got := h.history(t); len(got) != 0 {
		t.Fatalf("试运行不该写历史：%+v", got)
	}
}

// 样本试运行要把"这条会被关键词拦掉"说出来，同时照样给出渲染结果：
// 用户此刻正在调词表，两件事都得看得见。少了前者，他会配好词表、
// 试运行一切正常，上线后一条也进不来。
func TestDryRunReportsKeywordBlock(t *testing.T) {
	h := newHarness(t, kwCfg("any", "每日汇总"))

	got, err := h.m.DryRun("r1", []byte(`{"msg":"每日心跳"}`), nil, "")
	if err != nil {
		t.Fatal(err)
	}
	if !got.Blocked || !strings.Contains(got.BlockedReason, "关键词") {
		t.Fatalf("应报出被关键词拦下：%+v", got)
	}
	if got.Matched != 1 || len(got.Messages) != 1 {
		t.Fatalf("渲染结果照样要给出：%+v", got)
	}

	pass, err := h.m.DryRun("r1", []byte(`{"msg":"每日汇总"}`), nil, "")
	if err != nil {
		t.Fatal(err)
	}
	if pass.Blocked {
		t.Fatalf("命中关键词时不该报拦截：%+v", pass)
	}
}

// ---------- Host ----------

// 启用 HTTPS 后强制校验 Host：既挡住拿 IP 直连绕过域名的探测，
// 也保证证书与访问域名始终对得上。
func TestServeHostCheckWhenTLS(t *testing.T) {
	cfg := hitCfg(nil)
	cfg.Webhook.Enabled = true
	cfg.Webhook.HTTPS.Enabled = true
	cfg.Webhook.Domain = "hook.example.com"
	// 没注入证书解析器：startListen 在 net.Listen 之前就失败，
	// 于是 spec.tls 为真而端口没开——正好用来单测 Host 校验本身。
	h := newHarness(t, cfg)

	code, body := h.post(t, "/hook", "{}")
	if code != http.StatusMisdirectedRequest {
		t.Fatalf("Host 不匹配应给 421，实际 %d：%s", code, body)
	}
	if strings.TrimSpace(body) != "misdirected request" {
		t.Fatalf("421 不该泄露配置的域名：%q", body)
	}

	ok, _ := h.do(t, http.MethodPost, "/hook", "{}", func(r *http.Request) { r.Host = "hook.example.com" })
	if ok != http.StatusOK {
		t.Fatalf("Host 正确应通过，实际 %d", ok)
	}
	// 端口与大小写不参与比较：浏览器与推送方带不带端口都有。
	ok2, _ := h.do(t, http.MethodPost, "/hook", "{}", func(r *http.Request) { r.Host = "Hook.Example.com:25667" })
	if ok2 != http.StatusOK {
		t.Fatalf("忽略端口与大小写后应通过，实际 %d", ok2)
	}
}

// 未启用 HTTPS 时不校验 Host：内网直接用 IP 访问是主要用法。
func TestServeHostNotCheckedWithoutTLS(t *testing.T) {
	h := newHarness(t, hitCfg(nil))
	code, _ := h.do(t, http.MethodPost, "/hook", "{}", func(r *http.Request) { r.Host = "随便什么" })
	if code != http.StatusOK {
		t.Fatalf("明文模式不该校验 Host，实际 %d", code)
	}
}
