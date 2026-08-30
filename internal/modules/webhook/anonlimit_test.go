package webhook

import (
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"mantou/internal/config"
)

// 拒收也要留痕，而留痕本身就是放大器：每条被拒的请求都记一条执行历史（内存环 2000 条）、
// 再同步写一行程序日志（全进程一把锁）。于是"每个请求都被拒"这件事完全由对端的发送速率
// 决定——一次路径扫描既能把内存环顶空，又能把每个请求变成一次持锁写盘（见 5-C / 2.8-C）。
//
// 下面这组测试钉住那两道记录配额（见 anonlimit.go）：
//   - anonRecorder：全局一份，管"路径不存在"与"访问域名不匹配"——那两条路上还没有接收器；
//   - rejectQuota：每接收器一份，管路由到接收器之后的拒收（鉴权、超限、超体积、关键词）。
//
// 两道都只管"记不记"，不管"回不回"，也不管计数。

// ---------- 配额本身 ----------

// TestAnonRecorderBurstThenThrottles 先给够 burst 条，之后按窗口放行，
// 被挡下的次数由下一条记录带出去。
func TestAnonRecorderBurstThenThrottles(t *testing.T) {
	a := newAnonRecorder()
	t0 := time.Date(2026, 8, 27, 10, 0, 0, 0, time.UTC)

	for i := 0; i < anonRecordBurst; i++ {
		ok, merged := a.take(t0)
		if !ok {
			t.Fatalf("第 %d 条就被挡下了，头几条必须条条都记：burst=%d", i+1, anonRecordBurst)
		}
		if merged != 0 {
			t.Fatalf("第 %d 条不该带合并数，实际 %d", i+1, merged)
		}
	}
	// 配额用尽。
	for i := 0; i < 2; i++ {
		if ok, _ := a.take(t0); ok {
			t.Fatalf("配额已用尽，第 %d 次仍被放行", i+1)
		}
	}
	// 一个窗口后补一个配额，并把刚才挡下的 2 次交出来。
	ok, merged := a.take(t0.Add(anonRecordPer))
	if !ok {
		t.Fatalf("过了一个窗口（%s）仍不放行", anonRecordPer)
	}
	if merged != 2 {
		t.Fatalf("合并数应为 2，实际 %d——挡下的次数丢了，扫描会一点痕迹都不留", merged)
	}
	// 合并数交出去之后归零，不能被下一条重复带上。
	if ok, _ := a.take(t0.Add(anonRecordPer)); ok {
		t.Fatal("同一个窗口内放行了两条")
	}
	ok, merged = a.take(t0.Add(2 * anonRecordPer))
	if !ok || merged != 1 {
		t.Fatalf("下一个窗口应放行且只带 1 次合并，实际 ok=%v merged=%d", ok, merged)
	}
}

// TestAnonRecorderCapsBurst 闲置再久也只攒到 burst 条。
// 不封顶的话，静默一小时就能换来一次三百多条的连续记录，内存环照样被顶空。
func TestAnonRecorderCapsBurst(t *testing.T) {
	a := newAnonRecorder()
	t0 := time.Date(2026, 8, 27, 10, 0, 0, 0, time.UTC)
	if ok, _ := a.take(t0); !ok {
		t.Fatal("测试前提不成立：第一条就被挡下了")
	}

	idle := t0.Add(time.Hour)
	got := 0
	for i := 0; i < anonRecordBurst+50; i++ {
		if ok, _ := a.take(idle); ok {
			got++
		}
	}
	if got != anonRecordBurst {
		t.Fatalf("闲置一小时后放行了 %d 条，上限应为 %d", got, anonRecordBurst)
	}
}

// TestAnonRecorderIgnoresClockRewind 系统时钟被往回调之后：不补配额、不倒扣，
// 且窗口跟着挪到当下——把窗口留在"未来"等于时钟往回跳一小时就有一小时记不下任何东西。
func TestAnonRecorderIgnoresClockRewind(t *testing.T) {
	a := newAnonRecorder()
	t0 := time.Date(2026, 8, 27, 10, 0, 0, 0, time.UTC)
	for i := 0; i < anonRecordBurst; i++ {
		if ok, _ := a.take(t0); !ok {
			t.Fatalf("测试前提不成立：第 %d 条就被挡下了", i+1)
		}
	}

	rewound := t0.Add(-time.Hour)
	if ok, _ := a.take(rewound); ok {
		t.Fatal("时钟往回调了一小时却凭这一跳换来一个配额")
	}
	// 往回调之后再等一个窗口就该恢复，而不是等时钟重新走回原处。
	if ok, merged := a.take(rewound.Add(anonRecordPer)); !ok || merged != 1 {
		t.Fatalf("时钟回调后一个窗口应恢复，实际 ok=%v merged=%d", ok, merged)
	}
}

// TestMergedNoteEmptyWhenNothingDropped 没挡下任何东西时不往原因后面缀字。
func TestMergedNoteEmptyWhenNothingDropped(t *testing.T) {
	for _, n := range []int64{0, -1} {
		if got := mergedNote(n); got != "" {
			t.Fatalf("mergedNote(%d) = %q，应为空串", n, got)
		}
	}
	if got := mergedNote(7); !strings.Contains(got, "7") {
		t.Fatalf("mergedNote(7) = %q，里面得有次数", got)
	}
}

// ---------- 走真实请求路径 ----------

// rewindAnon 把配额桶的时间往回搬，等价于"过了 d"。
// 直接动内部字段：换成真等 10 秒会让这组测试没法跑。
func rewindAnon(m *Module, d time.Duration) {
	m.anon.mu.Lock()
	m.anon.last = m.anon.last.Add(-d)
	m.anon.mu.Unlock()
}

// anonMissFloodPaths 造一批各不相同的路径——扫描就是这个样子，
// 按路径去重挡不住它，只有全局配额能。
func anonMissFloodPaths(n int) []string {
	out := make([]string, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, "/miss-"+strconv.Itoa(i))
	}
	return out
}

// TestServeUnknownPathThrottlesHistory 路径扫描只能换来 burst 条历史，
// 但每一次都照旧得到 404，且拒收计数一次不漏。
func TestServeUnknownPathThrottlesHistory(t *testing.T) {
	h := newHarness(t, hitCfg(nil))
	const total = anonRecordBurst + 8

	for _, p := range anonMissFloodPaths(total) {
		code, body := h.post(t, p, "{}")
		// 配额只管记录，不管响应：对面可能是配错了地址的第三方系统。
		if code != http.StatusNotFound || strings.TrimSpace(body) != "not found" {
			t.Fatalf("%s 的响应变了：%d %q", p, code, body)
		}
	}

	if got := len(h.history(t)); got != anonRecordBurst {
		t.Fatalf("%d 次未命中记了 %d 条历史，上限应为 %d", total, got, anonRecordBurst)
	}
	if _, rejected, _ := h.m.Metrics(); rejected != total {
		t.Fatalf("拒收计数是 %d，应为 %d——计数不该被配额吞掉，它是扫描期间唯一还在动的信号",
			rejected, total)
	}
}

// TestServeUnknownPathKeepsRealHistory 配额存在的理由：扫描不能把真实记录顶掉。
// 内存环 2000 条，这里用一条已收下的消息代表"用户真正要看的那条"。
func TestServeUnknownPathKeepsRealHistory(t *testing.T) {
	h := newHarness(t, hitCfg(nil))
	if code, _ := h.post(t, "/hook", `{"消息编号":"MSG-1"}`); code != http.StatusOK {
		t.Fatalf("测试前提不成立：正常消息没收下，状态码 %d", code)
	}

	for _, p := range anonMissFloodPaths(200) {
		h.post(t, p, "{}")
	}

	h.findEvent(t, EventReceived) // 找不到就说明被顶掉了
	if got := len(h.history(t)); got > anonRecordBurst+1 {
		t.Fatalf("200 次扫描留下了 %d 条历史，应不超过 %d", got, anonRecordBurst+1)
	}
}

// TestServeUnknownPathRecordsMergedCount 被挡下的次数要写进下一条记录，
// 否则用户只看到"历史里突然只剩几条"，不知道发生过什么。
func TestServeUnknownPathRecordsMergedCount(t *testing.T) {
	h := newHarness(t, hitCfg(nil))
	for _, p := range anonMissFloodPaths(anonRecordBurst + 3) {
		h.post(t, p, "{}")
	}
	if got := len(h.history(t)); got != anonRecordBurst {
		t.Fatalf("测试前提不成立：应有 %d 条历史，实际 %d", anonRecordBurst, got)
	}

	rewindAnon(h.m, anonRecordPer)
	h.post(t, "/miss-after", "{}")

	e := h.last(t)
	if !strings.Contains(e.Reason, "入站路径不存在") {
		t.Fatalf("最后一条不是未命中记录：%+v", e)
	}
	if !strings.Contains(e.Reason, "3") || !strings.Contains(e.Reason, "未记入") {
		t.Fatalf("原因里没有被合并的 3 次：%q", e.Reason)
	}
}

// TestServeHostMismatchThrottlesHistory 访问域名不匹配走的是 reject，rc 同样是 nil，
// 配额必须一起管到——只管 404 的话，改个 Host 头就能绕开。
func TestServeHostMismatchThrottlesHistory(t *testing.T) {
	cfg := hitCfg(nil)
	cfg.Webhook.Enabled = true
	cfg.Webhook.HTTPS.Enabled = true
	cfg.Webhook.Domain = "hook.example.com"
	h := newHarness(t, cfg)
	const total = anonRecordBurst + 6

	for i := 0; i < total; i++ {
		code, _ := h.do(t, http.MethodPost, "/hook", "{}", nil)
		if code != http.StatusMisdirectedRequest {
			t.Fatalf("第 %d 次应给 421，实际 %d", i+1, code)
		}
	}

	if got := len(h.history(t)); got != anonRecordBurst {
		t.Fatalf("%d 次域名不匹配记了 %d 条历史，上限应为 %d", total, got, anonRecordBurst)
	}
	if _, rejected, _ := h.m.Metrics(); rejected != total {
		t.Fatalf("拒收计数是 %d，应为 %d", rejected, total)
	}
}

// rewindReject 把某个接收器那份配额桶的时间往回搬，等价于"过了 d"。
// 与 rewindAnon 同一个理由：真等 3 秒会让这组测试没法跑。
func rewindReject(m *Module, id string, d time.Duration) {
	m.rejQuota.mu.Lock()
	r := m.rejQuota.byID[id]
	m.rejQuota.mu.Unlock()
	if r == nil {
		return
	}
	r.mu.Lock()
	r.last = r.last.Add(-d)
	r.mu.Unlock()
}

// tokenRecv 一个必然命中、但开了令牌鉴权的接收器：不带令牌发过去必得 401。
func tokenRecv(id, path string) config.WebhookReceiver {
	rc := recv(rule("a", 0, "t1"))
	rc.ID, rc.Name, rc.Path = id, "系统"+id, path
	rc.AuthType, rc.Token = "token", "s3cret"
	return rc
}

// TestServeReceiverRejectionBurstThenThrottles 能归属到接收器的拒收：头 rejectRecordBurst 条
// 条条照记，之后按窗口放行，被挡下的次数由下一条带出去。
//
// 两头都要钉：
// 记得太少 → 用户排"我的令牌怎么不对"时，接收器自己的诊断信息不见了；
// 不封顶 → 猜对路径之后每个请求都换来一条历史 + 一行同步写盘，内存环与日志写入照旧被打爆
// （这一支的 rc 不为 nil，走不到匿名那道全局配额上）。
func TestServeReceiverRejectionBurstThenThrottles(t *testing.T) {
	h := newHarness(t, hitCfg(func(rc *config.WebhookReceiver) {
		rc.AuthType = "token"
		rc.Token = "s3cret"
	}))
	const extra = 6
	const total = rejectRecordBurst + extra

	for i := 0; i < total; i++ {
		code, _ := h.post(t, "/hook", "{}")
		// 配额只管记录，不管响应：对面可能是令牌配错了的第三方系统。
		if code != http.StatusUnauthorized {
			t.Fatalf("第 %d 次应给 401，实际 %d", i+1, code)
		}
	}

	all := h.history(t)
	if len(all) != rejectRecordBurst {
		t.Fatalf("%d 次令牌错误记了 %d 条历史，上限应为 %d", total, len(all), rejectRecordBurst)
	}
	if all[0].ReceiverID != "r1" || !strings.Contains(all[0].Reason, "令牌") {
		t.Fatalf("记录内容不符：%+v", all[0])
	}
	// 计数不受配额约束：它是纯 atomic，不吃内存也不写盘，而被刷期间面板上
	// 「累计 N 次（含拒收 M）」是唯一还在动的信号。
	if _, rejected, _ := h.m.Metrics(); rejected != total {
		t.Fatalf("模块拒收计数是 %d，应为 %d——计数不该被配额吞掉", rejected, total)
	}
	if got := h.stats.Recv("r1").Rejected; got != total {
		t.Fatalf("接收器拒收计数是 %d，应为 %d——列表上的计数与「这条要不要进历史」是两件事",
			got, total)
	}

	// 过一个窗口补一个配额，挡下的那几次要写进下一条记录，否则用户只看到
	// "历史里突然只剩这些"，不知道发生过什么。
	rewindReject(h.m, "r1", rejectRecordPer)
	if code, _ := h.post(t, "/hook", "{}"); code != http.StatusUnauthorized {
		t.Fatalf("窗口过后响应不该变，实际 %d", code)
	}
	e := h.last(t)
	if e.ReceiverID != "r1" || !strings.Contains(e.Reason, "令牌") {
		t.Fatalf("窗口过后应再记一条令牌错误，实际：%+v", e)
	}
	if !strings.Contains(e.Reason, strconv.Itoa(extra)) || !strings.Contains(e.Reason, "未记入") {
		t.Fatalf("原因里没有被合并的 %d 次：%q", extra, e.Reason)
	}
}

// TestServeReceiverRejectionQuotaPerReceiver 配额按接收器各发一份：一个接收器被刷，
// 不能把别的接收器的留痕额度一起吃掉。
//
// 共用一份的话，任何人只要猜对**其中一个**入站路径持续发，就能让其余接收器的拒收
// 记录整段消失——而那些记录正是别人排查时要看的东西。
func TestServeReceiverRejectionQuotaPerReceiver(t *testing.T) {
	h := newHarness(t, config.Config{
		WebhookReceivers: []config.WebhookReceiver{tokenRecv("r1", "hook"), tokenRecv("r2", "hook2")},
		MessageTemplates: []config.MessageTemplate{okTpl()},
	})

	// r1 先把自己那份配额刷穿。
	for i := 0; i < rejectRecordBurst+6; i++ {
		if code, _ := h.post(t, "/hook", "{}"); code != http.StatusUnauthorized {
			t.Fatalf("r1 第 %d 次应给 401，实际 %d", i+1, code)
		}
	}
	// r2 的配额应当是满的。
	for i := 0; i < rejectRecordBurst; i++ {
		if code, _ := h.post(t, "/hook2", "{}"); code != http.StatusUnauthorized {
			t.Fatalf("r2 第 %d 次应给 401，实际 %d", i+1, code)
		}
	}

	byRecv := map[string]int{}
	for _, e := range h.history(t) {
		byRecv[e.ReceiverID]++
	}
	if byRecv["r2"] != rejectRecordBurst {
		t.Fatalf("r2 只记了 %d 条，应为 %d——r1 被刷不该消耗 r2 的配额", byRecv["r2"], rejectRecordBurst)
	}
	if byRecv["r1"] != rejectRecordBurst {
		t.Fatalf("r1 记了 %d 条，上限应为 %d", byRecv["r1"], rejectRecordBurst)
	}
}
