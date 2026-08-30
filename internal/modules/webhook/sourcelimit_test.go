package webhook

import (
	"net/http"
	"strings"
	"testing"
	"time"
)

// 本文件钉一件事：**留存区是个环，存一条没用的就顶掉一条有用的**（A8）。
//
// 留存区只有 sourceMaxEntries 个槽位。被限流挡掉的请求恰好是最容易把槽位刷满的一类
// （频率完全由对方的推送速率决定，且不受匿名配额约束），而它留下的东西信息量最低
// （原因是常量、没有正文）。判定写在 worthCapturing 里，理由见那里的注释。
//
// 分两条用例，因为要钉的是两件不同的事：
//   - 真实 HTTP 路径上 429 确实没占槽位（下面第一条）；
//   - 一波 429 顶不掉已经留下的有用记录（第二条）——这才是做这件事的原因，
//     而它是"槽位判定 + 环淘汰"合起来的性质，只钉第一条钉不住。

// 被限流挡掉的请求不占留存槽位。
//
// 三个断言分别对应三种坏法：历史记录上挂了 ID（面板会给出一个「来源」链接）、
// 槽位被占掉（哪怕历史上没挂 ID）、以及最容易被忽略的那种——顺手把该留的也一起关了。
func TestRateLimitedRequestKeepsNoSource(t *testing.T) {
	cfg := kwCfg("all", "每日汇总")
	cfg.WebhookReceivers[0].RateLimit = 1
	h := newHarness(t, cfg)

	if code, body := h.post(t, "/hook", `{"text":"每日汇总"}`); code != http.StatusOK {
		t.Fatalf("带关键词的首条应通过，实际 %d：%s", code, body)
	}
	before, _ := h.m.SourceStats()

	if code, _ := h.post(t, "/hook", `{"text":"每日汇总"}`); code != http.StatusTooManyRequests {
		t.Fatalf("紧随其后的第二条应被限流，实际 %d", code)
	}
	e := h.last(t)
	if e.Status != http.StatusTooManyRequests {
		t.Fatalf("最近一条历史不是限流拒收：%+v", e)
	}
	if e.SourceID != "" {
		t.Errorf("限流拒收挂上了留存 ID %q：面板会给这条记录一个「来源」链接，"+
			"而这一类的原文只有一句常量原因，点开什么都看不到", e.SourceID)
	}
	if after, _ := h.m.SourceStats(); after != before {
		t.Errorf("限流拒收占了留存槽位（%d → %d）：留存区是个环，"+
			"这一条会顶掉一条真正要看的记录", before, after)
	}

	// 反过来也要成立：不能为了挡住 429 而把该留的一起关了。
	// 关键词没命中是最需要看原文的一类——拒收原因只说"正文里没有那个词"，
	// 到底是对方改了措辞还是自己的词填错了，不看正文分不出来。
	//
	// 等限流的令牌桶回一格再发，否则这一条会先被 429 挡住，403 压根走不到。
	waitForRateToken(t, h, `{"text":"完全不相干"}`, http.StatusForbidden)
	miss := h.last(t)
	if miss.SourceID == "" {
		t.Fatalf("关键词未命中没有留存原文：这一类非看正文不可，改动挡得太宽了。记录：%+v", miss)
	}
	if rec, ok := h.m.Source(miss.SourceID); !ok || !strings.Contains(rec.Body, "完全不相干") {
		t.Fatalf("留存里没有那段正文：%+v", rec)
	}
}

// waitForRateToken 反复发同一条请求，直到限流放过它（拿到 want）。
// 令牌桶按秒补，最多等 3 秒——再等不到就是别的地方坏了，不该悄悄跑过去。
func waitForRateToken(t *testing.T, h *harness, body string, want int) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		code, respBody := h.post(t, "/hook", body)
		if code == want {
			return
		}
		if code != http.StatusTooManyRequests {
			t.Fatalf("期望 %d（或先被限流），实际 %d：%s", want, code, respBody)
		}
		if time.Now().After(deadline) {
			t.Fatalf("等了 3 秒仍一直被限流，等不到 %d", want)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// 一波限流顶不掉已经留下的有用记录。
//
// 这是 A8 真正要防的形态：第三方系统按 5 次/秒推、限流配的是 1 次/秒，那就是
// 每秒 4 条 429，几分钟就足以把 sourceMaxEntries 个槽位全部换成"超出每秒请求数限制"。
// 于此同时，用户真正要查的那条（关键词没命中、正文读不完、被丢弃）已经被冲走了——
// 留存区在最需要它的时候恰好是空的。
//
// 走 captureSource 而不是发 500 多次真实 HTTP：要钉的是"槽位判定 + 环淘汰"这一段，
// 而 captureSource 正是两者的交界；从那里往上（限流闸把 429 送到这里）由上一条用例钉。
// 发几百次真实请求只会让这条用例慢上百倍，钉住的东西一点不多。
func TestRateLimitFloodDoesNotEvictUsefulSource(t *testing.T) {
	h := newHarness(t, kwCfg("all", "每日汇总"))

	// 先留一条真正要看的：关键词没命中，原文是唯一查得下去的东西。
	if code, _ := h.post(t, "/hook", `{"text":"完全不相干"}`); code != http.StatusForbidden {
		t.Fatalf("关键词没命中应被 403 拒收")
	}
	keep := h.last(t).SourceID
	if keep == "" {
		t.Fatal("关键词未命中本该留存原文，前置条件都没成立")
	}

	// 灌满一整圈还多一条：任何一条 429 只要占了槽位，上面那条就会被顶掉。
	req, err := http.NewRequest(http.MethodPost, "http://example.com/hook", strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < sourceMaxEntries+1; i++ {
		h.m.captureSource(req, nil, "10.0.0.1:1234", EventRejected,
			http.StatusTooManyRequests, "超出每秒请求数限制", "", nil)
	}

	if _, ok := h.m.Source(keep); !ok {
		t.Fatalf("灌了 %d 条限流拒收之后，那条关键词未命中的原文没了（留存 ID %s）："+
			"限流记录占住了槽位，把真正要查的记录顶了出去", sourceMaxEntries+1, keep)
	}
}
