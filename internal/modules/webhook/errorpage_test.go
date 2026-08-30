package webhook

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"

	"mantou/internal/config"
)

// 本文件盯的是"人拿浏览器撞到入站端口"这一侧的表现。
//
// 这一层有两个必须同时成立的要求，它们互相拉扯，所以只能靠测试钉住：
//
//	对人  浏览器里看到的是一页说得清楚的卡片（这个地址干什么用的、下一步做什么），
//	      而不是一屏 "not found" / "rejected"
//	对机  第三方推送系统看到的响应体一字不改——它们的日志和判定已经在依赖那几句
//
// 顺带钉住一件更容易出事的事：浏览器地址栏里敲一下这个 URL **不算一条消息**。
// GET 是放行的（有些系统只能在 URL 上带参数推送），所以少了这层判断，
// 用户每验证一次地址通不通，面板上就凭空多出一条"没有规则命中"。

// browser 把请求装成浏览器导航：只有 Accept 里带 text/html 才会走卡片页。
func browser(r *http.Request) {
	r.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
}

func isCard(body string) bool {
	return strings.Contains(body, "<!doctype html>") && strings.Contains(body, `class="card"`)
}

// 浏览器直接打开入站地址：给一页"这个地址工作正常"，并且**不产生消息**。
func TestServeBlankBrowserVisitIsNotAMessage(t *testing.T) {
	h := newHarness(t, hitCfg(nil))
	code, body := h.do(t, http.MethodGet, "/hook", "", browser)
	if code != http.StatusOK {
		t.Fatalf("地址是通的，应回 200，实际 %d：%s", code, body)
	}
	if !isCard(body) {
		t.Fatalf("浏览器应看到卡片页：%q", body)
	}
	if !strings.Contains(body, "工作正常") {
		t.Fatalf("页面应说清这个地址是好的：%q", body)
	}

	// 这才是重点：没投递、没计数、没进历史。
	if reqs := h.n.all(); len(reqs) != 0 {
		t.Fatalf("空访问不该派发消息：%+v", reqs)
	}
	if received, rejected, dropped := h.m.Metrics(); received != 0 || rejected != 0 || dropped != 0 {
		t.Fatalf("空访问不该进任何计数：%d %d %d", received, rejected, dropped)
	}
	if all := h.history(t); len(all) != 0 {
		t.Fatalf("空访问不该写历史：%+v", all)
	}
}

// 令牌不算内容：带令牌的地址被人从聊天记录里复制到浏览器里打开，是最常见的一种。
func TestServeBlankBrowserVisitIgnoresToken(t *testing.T) {
	h := newHarness(t, hitCfg(func(rc *config.WebhookReceiver) {
		rc.AuthType, rc.Token = "token", "s3cr3t"
	}))
	code, body := h.do(t, http.MethodGet, "/hook?token=s3cr3t", "", browser)
	if code != http.StatusOK || !isCard(body) {
		t.Fatalf("应给「地址正常」卡片页，实际 %d：%s", code, body)
	}
	if received, _, dropped := h.m.Metrics(); received != 0 || dropped != 0 {
		t.Fatalf("仍不该算成一条消息：received=%d dropped=%d", received, dropped)
	}
}

// URL 上带了参数就是真的在推送（有些系统只能这么发），照旧当消息处理。
func TestServeBrowserVisitWithQueryStillIngests(t *testing.T) {
	h := newHarness(t, hitCfg(nil))
	code, body := h.do(t, http.MethodGet, "/hook?msg=x", "", browser)
	if code != http.StatusOK {
		t.Fatalf("状态码应为 200，实际 %d：%s", code, body)
	}
	if _, matched := h.okBody(t, body); matched != 1 {
		t.Fatalf("带参数的 GET 是一条真消息，应照旧命中：%s", body)
	}
}

// 非浏览器客户端的空请求完全按老样子走：有人用一个空 POST 当连通性探测，
// 回给它的还得是那份 JSON。
func TestServeBlankPushKeepsJSON(t *testing.T) {
	h := newHarness(t, hitCfg(nil))
	code, body := h.post(t, "/hook", "")
	if code != http.StatusOK {
		t.Fatalf("状态码应为 200，实际 %d：%s", code, body)
	}
	if _, _, found := strings.Cut(body, "eventId"); !found {
		t.Fatalf("非浏览器客户端应拿到原来那份 JSON：%q", body)
	}
	if received, _, _ := h.m.Metrics(); received != 1 {
		t.Fatalf("这条仍按消息处理：received=%d", received)
	}
}

// 拒收页：浏览器拿卡片，第三方拿原来那句纯文本。同一次拒绝，两种表述。
func TestRejectPageVsPlainBody(t *testing.T) {
	cases := []struct {
		name    string
		mut     func(*config.WebhookReceiver)
		method  string
		target  string
		status  int
		plain   string
		inCard  string // 卡片页上必须有的话
		notCard string // 卡片页上绝不能有的话（安全类）
	}{
		{"方法不允许", nil, http.MethodDelete, "/hook", http.StatusMethodNotAllowed,
			"不支持的请求方法 DELETE", "只接收推送请求", ""},
		{"IP 不在名单里", func(rc *config.WebhookReceiver) {
			rc.IPFilter, rc.IPFilterMode, rc.AllowIPs = true, "allow", []string{"203.0.113.0/24"}
		}, http.MethodPost, "/hook", http.StatusForbidden,
			"rejected", "访问被拒绝", "IP"},
		{"令牌错", func(rc *config.WebhookReceiver) {
			rc.AuthType, rc.Token = "token", "right"
		}, http.MethodPost, "/hook?token=wrong", http.StatusUnauthorized,
			"rejected", "认证未通过", "令牌"},
		{"路径不存在", nil, http.MethodPost, "/nope", http.StatusNotFound,
			"not found", "不存在", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := newHarness(t, hitCfg(c.mut))
			code, plain := h.do(t, c.method, c.target, "{}", nil)
			if code != c.status {
				t.Fatalf("状态码应为 %d，实际 %d：%s", c.status, code, plain)
			}
			if got := strings.TrimSpace(plain); got != c.plain {
				t.Fatalf("非浏览器客户端的响应体必须一字不改：%q，应为 %q", got, c.plain)
			}

			h2 := newHarness(t, hitCfg(c.mut))
			code, card := h2.do(t, c.method, c.target, "{}", browser)
			if code != c.status {
				t.Fatalf("卡片页的状态码也应为 %d，实际 %d", c.status, code)
			}
			if !isCard(card) {
				t.Fatalf("浏览器应看到卡片页：%q", card)
			}
			if !strings.Contains(card, c.inCard) {
				t.Fatalf("卡片页应含 %q：%s", c.inCard, card)
			}
			// 401 / 403 的真实原因只进执行历史：写在页面上等于向探测者确认
			// "这个路径存在、你差的只是名单或令牌"。
			if c.notCard != "" && strings.Contains(card, c.notCard) {
				t.Fatalf("卡片页不该出现 %q：%s", c.notCard, card)
			}
		})
	}
}

// HEAD 不能带正文。这一页天生是给人看的，但探测程序照样会 HEAD 它一下。
func TestRejectPageHeadHasNoBody(t *testing.T) {
	h := newHarness(t, hitCfg(nil))
	code, body := h.do(t, http.MethodHead, "/hook", "", browser)
	if code != http.StatusMethodNotAllowed {
		t.Fatalf("HEAD 仍应被拒，实际 %d", code)
	}
	if body != "" {
		t.Fatalf("HEAD 不该有正文：%q", body)
	}
}

// truncatedPush 声明 100 字节的请求体却只发几个字节就关掉写端，然后把响应读回来。
// 服务端读体时拿到 unexpected EOF——那正是"把底层读取错误当作拒收原因"的 400 分支。
// 用裸连接是因为 http.Client 不肯发一个与 Content-Length 不符的请求体。
func truncatedPush(t *testing.T, h *harness, accept string) (int, string) {
	t.Helper()
	c, err := net.Dial("tcp", h.srv.Listener.Addr().String())
	if err != nil {
		t.Fatalf("连不上测试服务: %v", err)
	}
	defer c.Close()
	head := fmt.Sprintf("POST /hook HTTP/1.1\r\nHost: %s\r\nContent-Type: application/json\r\n",
		h.srv.Listener.Addr().String())
	if accept != "" {
		head += "Accept: " + accept + "\r\n"
	}
	head += "Content-Length: 100\r\n\r\n{\"a\":"
	if _, err := c.Write([]byte(head)); err != nil {
		t.Fatalf("发请求失败: %v", err)
	}
	// 只关写端：服务端由此读到 EOF，同时这条连接还能把响应读回来。
	if err := c.(*net.TCPConn).CloseWrite(); err != nil {
		t.Fatalf("关写端失败: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		t.Fatalf("没读到响应: %v", err)
	}
	defer resp.Body.Close()
	var b strings.Builder
	if _, err := io.Copy(&b, resp.Body); err != nil {
		t.Fatalf("读响应体失败: %v", err)
	}
	return resp.StatusCode, b.String()
}

// 读请求体出错时，回给对方的话里一个字都不能带底层错误。
//
// 这条错误的文本形如 "read tcp 10.0.0.5:9000->203.0.113.9:44321: ..."，
// 前一个地址是本机的监听地址——入站端口对公网开着，一次读取故障不该把它送出去。
// 真实原因照旧进执行历史与服务端日志，管理员在面板上看得到。
func TestBadRequestNeverEchoesReadError(t *testing.T) {
	for _, tc := range []struct {
		name   string
		accept string
		want   string // 响应里必须有的话
	}{
		{"浏览器", "text/html,application/xhtml+xml", "请求内容读不出来"},
		{"第三方系统", "", "bad request"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, hitCfg(nil))
			code, body := truncatedPush(t, h, tc.accept)
			if code != http.StatusBadRequest {
				t.Fatalf("状态码应为 400，实际 %d：%s", code, body)
			}
			if !strings.Contains(body, tc.want) {
				t.Fatalf("响应里应有 %q：%s", tc.want, body)
			}
			// 本机监听地址：net.OpError 那一类错误的文本里就带着它。
			if addr := h.srv.Listener.Addr().String(); strings.Contains(body, addr) {
				t.Fatalf("响应里出现了本机监听地址 %s：%s", addr, body)
			}
			for _, leak := range []string{"unexpected EOF", "read tcp", "读取请求体失败"} {
				if strings.Contains(body, leak) {
					t.Fatalf("响应里出现了底层错误 %q：%s", leak, body)
				}
			}
		})
	}
}
