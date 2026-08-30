package webhook

import (
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"mantou/internal/config"
)

// 本文件盯的是"试运行"（实时监听）：用户点一下按钮，接下来进来的真实消息
// 只进面板、不发进群里；点停止之后立刻恢复转发。
//
// 这个开关横跨 serve 的每一条分支，写错的表现都很安静：
// 要么调试期间的消息真的发出去了（一群人收到乱码），
// 要么忘了停止之后生产链路被无声掐断。所以两个方向都要钉住。

func mustStart(t *testing.T, h *harness, id string) {
	t.Helper()
	if err := h.m.TestRunStart(id); err != nil {
		t.Fatalf("开启试运行失败：%v", err)
	}
}

// ---------- 状态机 ----------

func TestTestRunStoreStartStop(t *testing.T) {
	s := newTestRunStore()
	now := time.Now()

	if s.active("r1", now) {
		t.Fatal("没开过的接收器不该处在试运行中")
	}
	s.start("r1", now)
	if !s.active("r1", now) {
		t.Fatal("开启后应处在试运行中")
	}
	if !s.add("r1", TestRunCapture{Body: "第一条", Sniffed: "txt"}) {
		t.Fatal("试运行中应能记下抓包")
	}

	st := s.state("r1", now)
	if !st.Running || st.Count != 1 || st.Capture == nil {
		t.Fatalf("状态不符：%+v", st)
	}
	if st.StartedAt != now.Unix() || st.ExpiresAt != now.Add(TestRunTTL).Unix() {
		t.Fatalf("界面要靠这两个时间做倒计时：%+v", st)
	}
	if st.Sniffed != "txt" {
		t.Fatalf("判定出的来源类型要回报给界面：%q", st.Sniffed)
	}

	// 停止**不清抓包**：那一条就是全局样本载荷，用户停下来正是为了照着它改配置。
	s.stop("r1", "")
	st = s.state("r1", now)
	if st.Running {
		t.Fatal("停止后不该再是运行中")
	}
	if st.Capture == nil || st.Capture.Body != "第一条" || st.Count != 1 {
		t.Fatalf("停止后抓包与总数都该留着（它是样本载荷）：%+v", st)
	}
	if st.StoppedReason != "" {
		t.Fatalf("用户主动停的不该带原因（那是「自动停止」的提示位）：%q", st.StoppedReason)
	}
	if s.add("r1", TestRunCapture{Body: "第二条"}) {
		t.Fatal("停止后不该再收抓包——调用方据此改走真实转发")
	}
	if got := s.state("r1", now); got.Capture.Body != "第一条" {
		t.Fatalf("停止后进来的请求不该顶掉样本：%q", got.Capture.Body)
	}
}

// 重复开启等于重新计时并清空：用户点"开始"时想看的是接下来发生的事。
func TestTestRunStoreRestartResets(t *testing.T) {
	s := newTestRunStore()
	now := time.Now()
	s.start("r1", now)
	s.add("r1", TestRunCapture{Body: "上一轮"})

	later := now.Add(time.Minute)
	s.start("r1", later)
	st := s.state("r1", later)
	if st.Count != 0 || st.Capture != nil {
		t.Fatalf("重开应清掉上一轮的抓包：%+v", st)
	}
	if st.ExpiresAt != later.Add(TestRunTTL).Unix() {
		t.Fatalf("重开应重新计时：%+v", st)
	}
}

// 忘记停止的试运行会静默吞掉所有真实推送，所以必须自己到期。
// 到期后还要留下一句话，否则用户只看到"怎么又开始转发了"。
func TestTestRunStoreExpires(t *testing.T) {
	s := newTestRunStore()
	now := time.Now()
	s.start("r1", now)
	s.add("r1", TestRunCapture{Body: "超时前收到的", Sniffed: "json"})

	after := now.Add(TestRunTTL + time.Second)
	if s.active("r1", after) {
		t.Fatal("超过存活上限应自动停止")
	}
	st := s.state("r1", after)
	if st.Running {
		t.Fatal("自动停止后不该还是运行中")
	}
	if !strings.Contains(st.StoppedReason, "自动停止") {
		t.Fatalf("应留下自动停止的原因供界面提示：%q", st.StoppedReason)
	}
	// 再开一次要把上一次的提示清掉，否则那句话会一直挂在界面上。
	s.start("r1", after)
	if got := s.state("r1", after).StoppedReason; got != "" {
		t.Fatalf("重开应清掉上一次的停止原因：%q", got)
	}
}

// active 没被调用过（这个接收器一直没有请求进来）时，state 自己也要认到期，
// 否则界面上的倒计时会走到 0 之后停在"运行中"。
func TestTestRunStateExpiresOnItsOwn(t *testing.T) {
	s := newTestRunStore()
	now := time.Now()
	s.start("r1", now)
	s.add("r1", TestRunCapture{Body: "超时前收到的"})

	st := s.state("r1", now.Add(TestRunTTL+time.Second))
	if st.Running || st.StoppedReason == "" {
		t.Fatalf("state 应自己认到期：%+v", st)
	}
	// 抓包照常返回：用户回到界面时要能看到超时之前收到的东西。
	if st.Count != 1 || st.Capture == nil {
		t.Fatalf("超时前收到的抓包不该跟着消失：%+v", st)
	}
}

// 只留最新那一条：调试模板、配映射、看预览，要的永远是刚刚推过来的那一条。
// 总数照实数，否则用户会以为对方只发了一条。
func TestTestRunStoreKeepsOnlyLatest(t *testing.T) {
	s := newTestRunStore()
	now := time.Now()
	s.start("r1", now)
	for i := 0; i < 5; i++ {
		s.add("r1", TestRunCapture{Body: itoa(i)})
	}

	st := s.state("r1", now)
	if st.Capture == nil || st.Capture.Body != itoa(4) {
		t.Fatalf("应留最新的那一条：%+v", st.Capture)
	}
	if st.Count != 5 {
		t.Fatalf("总数应含被顶掉的：%d", st.Count)
	}
}

// 抓包是副本：API 层拿去序列化时不该还持有 store 的内部指针。
func TestTestRunStateReturnsCopy(t *testing.T) {
	s := newTestRunStore()
	now := time.Now()
	s.start("r1", now)
	s.add("r1", TestRunCapture{Body: "原文"})

	st := s.state("r1", now)
	st.Capture.Body = "被改了"
	if again := s.state("r1", now); again.Capture.Body != "原文" {
		t.Fatalf("外部改动不该影响 store：%q", again.Capture.Body)
	}
}

// 删掉一个接收器后它的抓包必须立刻消失——里面有完整载荷与请求头。
func TestTestRunStoreKeepAndClear(t *testing.T) {
	s := newTestRunStore()
	now := time.Now()
	s.start("留下", now)
	s.start("删掉", now)
	s.stop("删掉过期的", "试运行已达最长时间")

	s.keep(map[string]struct{}{"留下": {}})
	if !s.active("留下", now) {
		t.Fatal("仍存在的接收器不该被清掉")
	}
	if s.active("删掉", now) {
		t.Fatal("已删除的接收器应连试运行一起清掉")
	}
	if got := s.state("删掉过期的", now).StoppedReason; got != "" {
		t.Fatalf("已删除的接收器不该留着停止提示：%q", got)
	}

	s.clear()
	if s.active("留下", now) {
		t.Fatal("clear 应停掉全部试运行")
	}
}

func TestLatestSniffed(t *testing.T) {
	// 来源类型跟着那一条抓包走，不另存一份：界面上显示的载荷与"这一条是按什么解的"
	// 必须是同一条记录，否则用户看着一段 JSON、下拉框却写着上一条空体的结论。
	s := newTestRunStore()
	now := time.Now()
	s.start("r1", now)
	s.add("r1", TestRunCapture{Body: `{"a":1}`, Sniffed: "json"})
	if got := s.state("r1", now).Sniffed; got != "json" {
		t.Fatalf("应回报当前抓包的判定：%q", got)
	}
	// 空体判不出类型（见 SniffSourceType），此时如实回空——样本本身已经换成这一条了。
	s.add("r1", TestRunCapture{Body: "", Sniffed: ""})
	if got := s.state("r1", now).Sniffed; got != "" {
		t.Fatalf("样本换了就该跟着换，不留上一条的结论：%q", got)
	}
}

// ---------- 样本载荷的存活上限 ----------

// 抓包同时是全局样本载荷，里面有完整请求头与业务字段（数值、联系人、手机号），
// 不能因为"用户还要照着它改配置"就一直躺在内存里。最后一次抓到之后到点销毁。
func TestCaptureDestroyedAfterTTL(t *testing.T) {
	s := newTestRunStore()
	now := time.Now()
	s.start("r1", now)
	if !s.add("r1", TestRunCapture{Body: `{"数值":100}`, Sniffed: "json"}) {
		t.Fatal("试运行中应能记下抓包")
	}
	// add 用的是真实时钟，只能改内部时间戳来把这一条挪到 3 小时前。
	run := s.runs["r1"]
	run.capturedAt = now.Add(-CaptureTTL - time.Minute)

	st := s.state("r1", now)
	if st.Capture != nil {
		t.Fatalf("超过 %v 的样本必须销毁：%+v", CaptureTTL, st.Capture)
	}
	if !st.CaptureExpired {
		t.Fatal("界面要能区分「从没抓到过」和「抓到过、已销毁」这两句话")
	}
	if st.Count != 1 {
		t.Fatalf("收到过几条只是个计数，不是载荷，可以留着：%d", st.Count)
	}
	if run.capture != nil {
		t.Fatal("store 内部也要真的把载荷交回 GC，不能只是读取时藏起来")
	}
}

// 口径是"最后一次收到样本之后 3 小时"：调试期间每来一条就重新计时，
// 否则一场跨过整点的调试会在用户正对着它改模板时把样本抽走。
func TestCaptureTTLCountsFromLatest(t *testing.T) {
	s := newTestRunStore()
	now := time.Now()
	s.start("r1", now)
	s.add("r1", TestRunCapture{Body: "旧的"})
	s.runs["r1"].capturedAt = now.Add(-CaptureTTL + time.Minute) // 还差 1 分钟到期

	s.add("r1", TestRunCapture{Body: "新的"})
	st := s.state("r1", now)
	if st.Capture == nil || st.Capture.Body != "新的" {
		t.Fatalf("新的一条应顶掉旧的：%+v", st.Capture)
	}
	if st.CaptureExpired {
		t.Fatal("刚收到新样本，不该报已销毁")
	}
	// 界面靠这个时刻显示"样本 X 后销毁"，必须跟着最新那一条重算。
	if want := now.Add(CaptureTTL).Unix(); st.CaptureExpiresAt < want-5 {
		t.Fatalf("新抓包应重新计时：captureExpiresAt=%d，约期望 %d", st.CaptureExpiresAt, want)
	}
}

// 销毁不能依赖界面来轮询：用户关掉浏览器就没人来问了，那份载荷会一直留着。
// 所以 store 自己拿一把定时器叫醒自己。
func TestCapturePurgedWithoutPolling(t *testing.T) {
	s := newTestRunStore()
	now := time.Now()
	s.start("r1", now)
	s.add("r1", TestRunCapture{Body: "载荷"})
	if s.purge == nil {
		t.Fatal("有抓包时就该有一把销毁定时器")
	}
	s.runs["r1"].capturedAt = now.Add(-CaptureTTL - time.Minute)

	s.purgeNow() // 模拟定时器到点，完全不经过读取路径
	if s.runs["r1"].capture != nil {
		t.Fatal("定时器到点应真的销毁抓包")
	}
	if s.purge != nil {
		t.Fatal("没有抓包了就不该留着一把定时器空转")
	}

	// Close 时也要停掉：定时器持有 store，不停掉能把它拖到 3 小时后才回收。
	s.add("r1", TestRunCapture{Body: "又一条"})
	s.clear()
	if s.purge != nil {
		t.Fatal("clear 应停掉销毁定时器")
	}
}

// ---------- 接在真实入站路径上 ----------

// 试运行期间消息**只进面板**：不投递、不计数、不写历史、不改运行态。
// 对方仍然收到 200——那是真实发生的事，不能因为面板开着调试就骗第三方系统。
func TestTestRunCapturesInsteadOfDispatching(t *testing.T) {
	h := newHarness(t, hitCfg(nil))
	mustStart(t, h, "r1")

	const raw = `{"消息编号":"MSG-1"}`
	code, body := h.post(t, "/hook", raw)
	if code != http.StatusOK {
		t.Fatalf("对方仍应收到 200，实际 %d：%s", code, body)
	}
	if _, matched := h.okBody(t, body); matched != 1 {
		t.Fatalf("命中数照实回：%s", body)
	}

	if len(h.n.all()) != 0 {
		t.Fatal("试运行期间不该真的入队")
	}
	if received, rejected, dropped := h.m.Metrics(); received != 0 || rejected != 0 || dropped != 0 {
		t.Fatalf("试运行是调试动作，不该混进业务计数：%d %d %d", received, rejected, dropped)
	}
	if len(h.history(t)) != 0 {
		t.Fatal("试运行不该写执行历史")
	}
	if st := h.stats.Recv("r1").LastStatus; st != "" {
		t.Fatalf("试运行不该改运行态：%q", st)
	}

	st := h.m.TestRunState("r1")
	if !st.Running || st.Capture == nil {
		t.Fatalf("应抓到 1 条：%+v", st)
	}
	c := *st.Capture
	// 左边那栏显示第三方原封不动发来的东西，用户据此判断路径怎么填。
	if c.Body != raw || c.Method != http.MethodPost || c.Rejected {
		t.Fatalf("抓包应留原始载荷：%+v", c)
	}
	// 判定结果回写「来源消息类型」下拉框，用户不必先搞清楚对方发的是什么格式。
	if c.Sniffed != "json" || st.Sniffed != "json" {
		t.Fatalf("应判定并回报来源类型：%q %q", c.Sniffed, st.Sniffed)
	}
	// 右边那栏是流水线跑出来的结果，与真实转发用的是同一条流水线。
	if c.Result == nil || c.Result.Matched != 1 || len(c.Result.Messages) != 1 {
		t.Fatalf("抓包应带处理结果：%+v", c.Result)
	}
	if c.Result.Messages[0].Body != "收到 第三方系统" {
		t.Fatalf("渲染结果不符：%+v", c.Result.Messages[0])
	}
	if c.Result.TargetName["g1"] != "运维群" {
		t.Fatalf("要显示「会发给谁」：%v", c.Result.TargetName)
	}
}

// 停止之后**后续的新消息**立刻恢复真实转发——这是这个开关的另一半。
func TestTestRunStopRestoresForwarding(t *testing.T) {
	h := newHarness(t, hitCfg(nil))
	mustStart(t, h, "r1")
	h.post(t, "/hook", `{"消息编号":"MSG-1"}`)
	h.m.TestRunStop("r1")

	if code, _ := h.post(t, "/hook", `{"消息编号":"MSG-2"}`); code != http.StatusOK {
		t.Fatalf("停止后仍应回 200，实际 %d", code)
	}
	if got := h.n.all(); len(got) != 1 {
		t.Fatalf("停止后的新消息应真的入队，实际 %d 条", len(got))
	}
	if received, _, _ := h.m.Metrics(); received != 1 {
		t.Fatalf("只该数试运行之外的那一条：%d", received)
	}
	if got := h.history(t); len(got) != 1 {
		t.Fatalf("只该给试运行之外的那一条写历史：%+v", got)
	}
	// 停止后再看状态：不该报"自动停止"，而那一条抓包要留着——它就是样本载荷。
	if st := h.m.TestRunState("r1"); st.Running || st.StoppedReason != "" {
		t.Fatalf("主动停止后的状态不符：%+v", st)
	}
	if st := h.m.TestRunState("r1"); st.Capture == nil || st.Capture.Body != `{"消息编号":"MSG-1"}` {
		t.Fatalf("停止后样本载荷应留着：%+v", st.Capture)
	}
}

// 停用的接收器也能开试运行——这正是"先调通再上线"的顺序。
// 它仍然不参与真实入站：没开试运行时那条路径依旧 404。
func TestTestRunOnDisabledReceiver(t *testing.T) {
	h := newHarness(t, hitCfg(func(rc *config.WebhookReceiver) { rc.Enabled = false }))

	if code, _ := h.post(t, "/hook", "{}"); code != http.StatusNotFound {
		t.Fatalf("停用且未开试运行时应 404，实际 %d", code)
	}

	mustStart(t, h, "r1")
	if code, body := h.post(t, "/hook", `{"消息编号":"MSG-1"}`); code != http.StatusOK {
		t.Fatalf("开了试运行的停用接收器应开门，实际 %d：%s", code, body)
	}
	if st := h.m.TestRunState("r1"); st.Capture == nil {
		t.Fatalf("应抓到那一条：%+v", st)
	}
	if len(h.n.all()) != 0 {
		t.Fatal("试运行期间不该投递")
	}

	// 停止之后重新关门：停用的接收器不该因为试运行过一次就一直开着。
	h.m.TestRunStop("r1")
	if code, _ := h.post(t, "/hook", "{}"); code != http.StatusNotFound {
		t.Fatalf("停止试运行后应回到 404，实际 %d", code)
	}
}

// 被拒的请求也要抓下来：否则用户面对一个"开着试运行却什么都收不到"的界面，
// 完全猜不到是被 IP 名单或令牌挡了。
func TestTestRunCapturesRejection(t *testing.T) {
	h := newHarness(t, hitCfg(func(rc *config.WebhookReceiver) {
		rc.AuthType, rc.Token = "token", "秘密"
	}))
	mustStart(t, h, "r1")

	code, _ := h.post(t, "/hook", "{}")
	if code != http.StatusUnauthorized {
		t.Fatalf("响应码照旧原样回给对方，实际 %d", code)
	}

	st := h.m.TestRunState("r1")
	if st.Capture == nil {
		t.Fatalf("被拒的请求也该留下：%+v", st)
	}
	c := *st.Capture
	if !c.Rejected || c.Status != http.StatusUnauthorized || c.Reason == "" {
		t.Fatalf("抓包应说明是被拒的以及原因：%+v", c)
	}
	// 拒收发生在读请求体之前，所以没有处理结果——界面据此只显示左边那栏。
	if c.Result != nil {
		t.Fatalf("被拒的请求跑不到流水线，不该带结果：%+v", c.Result)
	}
	if len(h.history(t)) != 0 {
		t.Fatal("试运行期间的拒收也不该写历史")
	}
	if _, rejected, _ := h.m.Metrics(); rejected != 0 {
		t.Fatalf("也不该计入拒收数：%d", rejected)
	}
}

// 抓包里绝不能出现令牌原文：这一栏是给用户看的，界面上只需要证明"头带上了"。
func TestTestRunCaptureRedactsSecrets(t *testing.T) {
	h := newHarness(t, hitCfg(func(rc *config.WebhookReceiver) {
		rc.AuthType, rc.Token, rc.AuthHeader = "header", "秘密", "X-Sign"
	}))
	mustStart(t, h, "r1")

	code, _ := h.do(t, http.MethodPost, "/hook", "{}", func(r *http.Request) {
		r.Header.Set("X-Sign", "秘密")
		r.Header.Set("Authorization", "Bearer 另一个秘密")
	})
	if code != http.StatusOK {
		t.Fatalf("鉴权应通过，实际 %d", code)
	}

	st := h.m.TestRunState("r1")
	if st.Capture == nil {
		t.Fatalf("应抓到 1 条：%+v", st)
	}
	for _, k := range []string{"authorization", "x-sign"} {
		if got := st.Capture.Headers[k]; got != "***" {
			t.Errorf("请求头 %q 应脱敏，实际 %q", k, got)
		}
	}
}

// ---------- 抓包的留存上限 ----------

// 这两道闸是"外部决定本程序占多少内存"的最后一层，所以数值本身也要钉住：
// 抓包最多 50 份（config.MaxWebhookReceivers 个接收器各一份），每份能留三小时，
// 而且只要试运行还开着，这些字节每 2 秒就被序列化一遍发给面板。
//
// 上面那些按行为写的用例都是"相对上限"的（输入按常量算出来），所以把常量本身
// 从 256 KB 抬到 256 MB 它们照样过。这条盯的正是那一手。
//
// 字段树（DryRunResult.Root）不在这笔账里：它只在正文没被截断时才留，
// 大小是正文解析后的形态，说不出一个精确倍数——只知道被正文上限压在同一个量级。
func TestCaptureLimitsStayModest(t *testing.T) {
	// 等于接收器请求体的默认上限，不该更大：再大就意味着"默认配置下的一条消息
	// 还装不满一份抓包"，那这道闸挡的就不是它该挡的东西了。
	if captureBodyMax > config.DefaultWebhookBodyKB*1024 {
		t.Errorf("captureBodyMax=%d 超过请求体的默认上限 %d 字节", captureBodyMax, config.DefaultWebhookBodyKB*1024)
	}
	if captureQueryMax > 64<<10 {
		t.Errorf("captureQueryMax=%d 太大：一条超过 64 KB 的请求行多数代理根本不转发", captureQueryMax)
	}
	// 最坏情况：每个接收器都各留着一份满额抓包。
	if worst, limit := config.MaxWebhookReceivers*(captureBodyMax+captureQueryMax), 16<<20; worst > limit {
		t.Errorf("%d 个接收器各一份满额抓包合计 %d MB，超过 %d MB",
			config.MaxWebhookReceivers, worst>>20, limit>>20)
	}
}

// 抓包内容全由对端决定，而它能在内存里留三小时、还每 2 秒被序列化一遍发给面板。
// 正文要有闸，而且不能只截正文：字段树是按整段正文解出来的，留着它这道闸等于没设。
func TestTestRunCaptureClampsOversizeBody(t *testing.T) {
	h := newHarness(t, hitCfg(func(rc *config.WebhookReceiver) {
		rc.MaxBodyKB = 1024 // 用户手动把上限抬到了 1 MB——只有这种接收器才会遇到截断
	}))
	mustStart(t, h, "r1")

	raw := `{"消息编号":"MSG-1","填充":"` + strings.Repeat("x", captureBodyMax) + `"}`
	if code, body := h.post(t, "/hook", raw); code != http.StatusOK {
		t.Fatalf("正文没超接收器自己的上限，应回 200，实际 %d：%s", code, body)
	}

	c := h.m.TestRunState("r1").Capture
	if c == nil {
		t.Fatal("应抓到 1 条")
	}
	if !c.BodyTruncated {
		t.Fatalf("%d 字节的正文应被截断", len(raw))
	}
	if len(c.Body) > captureBodyMax {
		t.Fatalf("留存 %d 字节，超过上限 %d", len(c.Body), captureBodyMax)
	}
	if c.BodySize != len(raw) {
		t.Fatalf("BodySize=%d，应报原始字节数 %d", c.BodySize, len(raw))
	}
	// 字段树跟着一起丢，并且标记出来——界面据此说明白，而不是显示一棵空树。
	if !c.RootDropped || c.Result == nil || c.Result.Root != nil {
		t.Fatalf("截断后不该留字段树：RootDropped=%v Root=%v", c.RootDropped, c.Result.Root != nil)
	}
	// 但"这条会发出什么"必须照常留着：那是用户此刻真正要看的东西。
	if c.Result.Matched != 1 || len(c.Result.Messages) != 1 {
		t.Fatalf("命中判定与渲染结果应照常保留：%+v", c.Result)
	}
}

// 常规大小的正文一个字节都不许动，字段树照留——截断只该发生在超限那一档。
func TestTestRunCaptureKeepsNormalBodyAndRoot(t *testing.T) {
	h := newHarness(t, hitCfg(nil))
	mustStart(t, h, "r1")

	const raw = `{"消息编号":"MSG-1"}`
	h.post(t, "/hook", raw)

	c := h.m.TestRunState("r1").Capture
	if c == nil {
		t.Fatal("应抓到 1 条")
	}
	if c.Body != raw || c.BodyTruncated || c.RootDropped {
		t.Fatalf("常规正文不该被动：%q truncated=%v rootDropped=%v", c.Body, c.BodyTruncated, c.RootDropped)
	}
	if c.BodySize != len(raw) {
		t.Fatalf("BodySize=%d，期望 %d", c.BodySize, len(raw))
	}
	if c.Result == nil || c.Result.Root == nil {
		t.Fatal("字段树应照常留着：模板与字段映射都靠它")
	}
}

// 查询串里的凭证要打码（本程序自己就支持 ?token=… 传令牌），但其余部分必须
// 一个字节都不改：这段字符串会被送回后端重建事件（见 useAsSample → 模板预览）。
func TestTestRunCaptureRedactsQueryByteExact(t *testing.T) {
	h := newHarness(t, hitCfg(nil))
	mustStart(t, h, "r1")

	// text 的值里转义过一个 &：解析→重建那一套会把它变成真的分隔符。
	h.post(t, "/hook?token=abc&text=a%26b&order=A001", `{"消息编号":"MSG-1"}`)

	c := h.m.TestRunState("r1").Capture
	if c == nil {
		t.Fatal("应抓到 1 条")
	}
	if want := "token=***&text=a%26b&order=A001"; c.Query != want {
		t.Fatalf("查询串应只打码凭证、其余原样：\n实际 %s\n期望 %s", c.Query, want)
	}
}

// 抓包的正文上限刻意等于接收器请求体的**默认**上限：照默认配置用的人永远看不到截断，
// 于是"用作样本载荷"那条路不会因为这道闸而失效。把 captureBodyMax 调小，这条就红。
func TestTestRunCaptureKeepsDefaultSizedBody(t *testing.T) {
	h := newHarness(t, hitCfg(nil)) // MaxBodyKB 留空 = DefaultWebhookBodyKB
	mustStart(t, h, "r1")

	// 贴着默认上限来一条，留出信封与引号的余量。
	raw := `{"消息编号":"MSG-1","填充":"` + strings.Repeat("x", config.DefaultWebhookBodyKB*1024-200) + `"}`
	if code, body := h.post(t, "/hook", raw); code != http.StatusOK {
		t.Fatalf("正文没超默认上限，应回 200，实际 %d：%s", code, body)
	}

	c := h.m.TestRunState("r1").Capture
	if c == nil {
		t.Fatal("应抓到 1 条")
	}
	if c.BodyTruncated || c.RootDropped {
		t.Fatalf("默认配置下的正文不该被截断：实际 %d 字节，抓包上限 %d", c.BodySize, captureBodyMax)
	}
}

// 查询串的长度同样由对端决定（Go 只在请求行总长上有闸，那是 1 MB 量级）。
func TestTestRunCaptureClampsQuery(t *testing.T) {
	h := newHarness(t, hitCfg(nil))
	mustStart(t, h, "r1")

	h.post(t, "/hook?a="+strings.Repeat("1", captureQueryMax+500), `{"消息编号":"MSG-1"}`)

	c := h.m.TestRunState("r1").Capture
	if c == nil {
		t.Fatal("应抓到 1 条")
	}
	if len(c.Query) > captureQueryMax+len("…") {
		t.Fatalf("留存 %d 字节，超过上限 %d", len(c.Query), captureQueryMax)
	}
}

// 请求头的条数与单值长度都由对端决定，两道闸都要有。
func TestTestRunCaptureClampsHeaders(t *testing.T) {
	h := newHarness(t, hitCfg(nil))
	mustStart(t, h, "r1")

	h.do(t, http.MethodPost, "/hook", `{"消息编号":"MSG-1"}`, func(r *http.Request) {
		for i := 0; i < sourceMaxHeaders*2; i++ {
			r.Header.Set("X-Pad-"+itoa(i), strings.Repeat("v", sourceHeaderValueMax+50))
		}
	})

	c := h.m.TestRunState("r1").Capture
	if c == nil {
		t.Fatal("应抓到 1 条")
	}
	if len(c.Headers) > sourceMaxHeaders {
		t.Fatalf("留了 %d 个请求头，超过上限 %d", len(c.Headers), sourceMaxHeaders)
	}
	for k, v := range c.Headers {
		if len(v) > sourceHeaderValueMax+len("…") {
			t.Fatalf("%s 的值 %d 字节，超过上限 %d", k, len(v), sourceHeaderValueMax)
		}
	}
}

func TestTestRunStartUnknownReceiver(t *testing.T) {
	h := newHarness(t, hitCfg(nil))
	// 界面上按钮就挂在那一行，报错等于告诉用户"这条配置刚被别人删了"。
	if err := h.m.TestRunStart("不存在"); !errors.Is(err, errNoReceiver) {
		t.Fatalf("应返回 errNoReceiver，实际 %v", err)
	}
	if st := h.m.TestRunState("不存在"); st.Running {
		t.Fatalf("开失败就不该有状态：%+v", st)
	}
}

// 试运行的正常用法是「收一条 → 照着抓包改配置 → 保存 → 再收一条」，
// 而保存会触发 Reload。清空等于用户每改一次就得回去重新点一次开始。
func TestTestRunSurvivesReload(t *testing.T) {
	cfg := hitCfg(nil)
	h := newHarness(t, cfg)
	mustStart(t, h, "r1")
	h.post(t, "/hook", `{"消息编号":"MSG-1"}`)

	if err := h.m.Reload(&cfg); err != nil {
		t.Fatalf("Reload 失败：%v", err)
	}
	st := h.m.TestRunState("r1")
	if !st.Running || st.Capture == nil {
		t.Fatalf("保存配置不该中断试运行：%+v", st)
	}

	// 接收器被删掉就另说了：抓包里有完整载荷与请求头，必须立刻消失。
	gone := config.Config{MessageTemplates: []config.MessageTemplate{okTpl()}}
	if err := h.m.Reload(&gone); err != nil {
		t.Fatalf("Reload 失败：%v", err)
	}
	if st := h.m.TestRunState("r1"); st.Running || st.Capture != nil {
		t.Fatalf("接收器已删除，试运行应一起清掉：%+v", st)
	}
}

// 退出时也要清：这些载荷只在内存里，不该留在可能被转储的进程内存中。
func TestTestRunClearedOnClose(t *testing.T) {
	h := newHarness(t, hitCfg(nil))
	mustStart(t, h, "r1")
	h.post(t, "/hook", `{"消息编号":"MSG-1"}`)

	if err := h.m.Close(); err != nil {
		t.Fatalf("Close 失败：%v", err)
	}
	if st := h.m.TestRunState("r1"); st.Running || st.Capture != nil {
		t.Fatalf("Close 后应清空：%+v", st)
	}
	if err := h.m.Close(); err != nil {
		t.Fatalf("Close 应可重复调用：%v", err)
	}
}
