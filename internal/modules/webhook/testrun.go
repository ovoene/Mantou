package webhook

import (
	"sync"
	"time"
)

// 本文件是"试运行"（实时监听）的状态机。
//
// 它要解决的问题：用户在第三方系统里配好了推送地址，但不知道对方到底会发什么。
// 在此之前唯一的办法是先让消息真的转发出去，看群里收到什么样子——一条配错的规则
// 就是一群人收到一条乱码消息。试运行把这一步搬到面板里：
//
//	开启 → 后续进来的真实请求跑完整条流水线，但**不投递**，原始载荷与渲染结果留在内存
//	停止 → 立刻恢复真实转发
//
// 三条刻意的设计：
//
//   - **停用的接收器也能开**：这正是"先调通再上线"的顺序（见 routeTable.byPathAll）。
//     停用 + 未开试运行时路径依旧 404，与之前完全一致。
//   - **试运行期间消息不再转发，且不计入 received / dropped，也不写执行历史**：
//     与 DryRun 同口径。它是调试动作，混进业务计数会让"今天收了多少条"不可信。
//   - **有存活上限**：忘记停止的试运行会静默吞掉所有真实推送。到期自动停止，
//     宁可让用户重新点一次，也不能让一个调试开关无声地掐断生产链路。

// TestRunTTL 一次试运行的最长存活时间。导出是给接口层下发到界面用的：
// 那个倒计时必须和这里的实际值一致，前端另写一份必然会漂。
// 够长到"去第三方系统里点一次推送再回来看"，短到忘了关也只影响一小段时间。
const TestRunTTL = 10 * time.Minute

// CaptureTTL 一份抓包（也就是全局样本载荷）留在内存里的最长时间，到点主动销毁。
//
// 试运行本身 10 分钟就自动停了，但抓包**刻意不随之清掉**：用户停下来正是为了照着
// 它改模板、配映射、调条件（见 stop 的说明）。于是这份含完整请求头与业务载荷
// （消息数值、联系人、手机号）的东西可能在内存里躺到进程重启为止——一次调试的
// 便利换来无限期的留存，不划算。
//
// 3 小时的取舍：一次"收一条 → 改配置 → 再收一条"的调试来回撑死也就半小时，
// 中间去开个会回来样本还在；而下班放到第二天早上再来看的那份，一定已经没了。
//
// 到期是**真的销毁**（time.AfterFunc 主动清，见 armPurgeLocked），不是等界面来轮询：
// 关掉浏览器就不再有人来问，若只在读取路径上判过期，那份载荷实际会一直留着。
const CaptureTTL = 3 * time.Hour

// ---- 抓包的留存上限 ----
//
// 抓包里装的是第三方原封不动发来的东西，大小由对端决定：接收器的请求体上限默认
// 256 KB、可调到 4 MB（config.MaxWebhookBodyKB），而抓包一份能留三小时、
// 每个接收器各一份（上限 50 个）。不设闸的话最坏情况是把几百兆压在内存里，
// 而这些字节还会每 2 秒被序列化一遍发给面板（界面轮询 testRunState）。
const (
	// captureBodyMax 抓包留存的正文上限，256 KiB。
	//
	// 这个数刻意等于接收器请求体的**默认**上限（config.DefaultWebhookBodyKB）：
	// 于是照默认配置用的人永远看不到截断，只有把上限手动调到 256 KB 以上的接收器
	// 才可能遇到——那也正是会把内存吃掉的那一类。
	//
	// 为什么不是更小的数：抓包同时是全局唯一的样本载荷，模板预览、字段映射、条件调试
	// 都直接拿它去解析（见 TestRunState.Capture）。截一半的 JSON 解析不出来，
	// 这几件事会一起失效。截断因此只该发生在"用户自己把上限抬上去了"的情形。
	captureBodyMax = 256 << 10

	// captureQueryMax 抓包留存的查询串上限，8 KiB。
	//
	// 有些系统只能在 URL 上带参数推送，那时查询串**就是**消息正文，所以给得比
	// 入站原文留存那边（sourceQueryMax，1 KB）宽：8 KB 已经超过多数代理愿意转发的
	// 请求行长度，正常推送碰不到，而它把 50 份抓包的这一项钉在 400 KB 以内。
	captureQueryMax = 8 << 10
)

// TestRunCapture 试运行抓到的一条消息。
//
// 同时带**原始载荷**与**处理结果**：左边那栏要显示第三方原封不动发来的东西
// （用户据此判断"来源消息类型"和取值路径该怎么填），右边那栏是流水线跑出来的结果。
// Rejected 为真时 Result 为空——被拒的请求也要留下来，否则用户面对一个
// "开着试运行却什么都收不到"的界面，完全猜不到是被 IP 名单或令牌挡了。
type TestRunCapture struct {
	Time    int64             `json:"time"`
	Remote  string            `json:"remote"`
	Method  string            `json:"method"`
	Query   string            `json:"query"`
	Headers map[string]string `json:"headers"`
	Body    string            `json:"body"`
	// Sniffed 由 SniffSourceType 判定的来源消息类型（json / kv / txt），供界面标出
	// "这一条是按什么解的"。刻意**不**回写「来源消息类型」下拉框：默认的自动识别本就
	// 每条各判一次，回写只会把一条消息的形态固化成接收器的类型——那条 BOM 开头的 JSON
	// 被判成 kv 之后，连后面正常的 JSON 也一起被拆坏了。
	Sniffed  string        `json:"sniffed"`
	Rejected bool          `json:"rejected"`
	Reason   string        `json:"reason"`
	Status   int           `json:"status"`
	Result   *DryRunResult `json:"result,omitempty"`

	// BodySize 正文的原始字节数（截断之前）。界面据此说"实际收到多大"。
	BodySize int `json:"bodySize,omitempty"`
	// BodyTruncated 正文超过 captureBodyMax，留存的是前一截。
	// 界面必须标出来：这一份当样本用会解析失败，而那不是模板的错。
	BodyTruncated bool `json:"bodyTruncated,omitempty"`
	// RootDropped 这一份没有留字段树。
	//
	// 只在正文被截断时发生：字段树是按**整段**正文解出来的，一份 4 MB 的载荷
	// 解成 map 之后比原文还大好几倍，把正文截了却留着它等于没截。
	// 界面据此在"字段"那一栏说明白，而不是显示一棵空树让人以为对方发了个空包。
	RootDropped bool `json:"rootDropped,omitempty"`
}

// TestRunState 一个接收器的试运行状态，供界面轮询。
type TestRunState struct {
	Running   bool  `json:"running"`
	StartedAt int64 `json:"startedAt"`
	ExpiresAt int64 `json:"expiresAt"`
	Count     int   `json:"count"`
	// Capture 最新抓到的那一条，**只留一条**。
	//
	// 曾经留 20 条并给界面配了个下拉框，想让人翻一翻"对方每次发的是不是同一个形状"。
	// 实际没人翻：调模板、配映射、看预览，要的永远是刚刚推过来的那一条，
	// 而一列历史抓包换来的是内存里躺着 20 份完整载荷（含请求头，可能带业务敏感信息）
	// 和界面上多一个"我现在看的是第几条"的问号。
	//
	// 留一条之后它同时就是全局唯一的**样本载荷**：模板预览、字段映射、条件调试
	// 都直接用它，用户不必再在几个弹窗之间搬运同一段 JSON。
	Capture *TestRunCapture `json:"capture,omitempty"`
	// CaptureExpiresAt 抓包被销毁的时刻（Unix 秒），供界面显示"样本 X 后销毁"。
	// Capture 为空时它也是 0。
	CaptureExpiresAt int64 `json:"captureExpiresAt,omitempty"`
	// CaptureExpired 为真表示抓到过样本、但已经到期销毁了。界面据此把"样本已失效、
	// 请重新试运行"说清楚——否则用户看到的是一个收到过 N 条却什么都没有的面板。
	CaptureExpired bool `json:"captureExpired,omitempty"`
	// Sniffed 最近一条抓包判定出的来源消息类型，界面据此回写下拉框。
	Sniffed string `json:"sniffed,omitempty"`
	// StoppedReason 非空表示上一次试运行是自动停的（超时），界面据此提示用户重开。
	StoppedReason string `json:"stoppedReason,omitempty"`
}

// testRun 单个接收器的试运行记录。
//
// 停止之后这条记录**不删**，只把 running 置假：那份抓包是全局样本载荷，
// 用户停下来正是为了照着它改配置（改完保存会触发 Reload，见 keep）。
type testRun struct {
	startedAt time.Time
	expiresAt time.Time
	running   bool
	capture   *TestRunCapture
	// capturedAt 抓到 capture 的时刻，用来算它什么时候该被销毁（CaptureTTL）。
	capturedAt time.Time
	// captureGone 抓包曾经存在、已被到期销毁。与"从没抓到过"要分开，界面上是两句不同的话。
	captureGone bool
	// total 抓到的总条数（含被后一条顶掉的），界面显示"共收到 N 条"。
	total int
}

// testRunStore 全部接收器的试运行状态。只在内存里：抓包含完整载荷与请求头，
// 里面可能有业务敏感信息（消息数值、联系人、手机号），不该落到磁盘上去。
// 也不该无限期留在内存里——purge 负责到点销毁（见 CaptureTTL）。
type testRunStore struct {
	mu      sync.Mutex
	runs    map[string]*testRun
	stopped map[string]string // 接收器 ID → 上次自动停止的原因
	// purge 对着"最早那份抓包的到期时刻"的一次性定时器；没有任何抓包时为 nil。
	// 只用一把：抓包最多和接收器数量同阶（上限 50），到期时间又都是 3 小时后，
	// 一把定时器每次醒来清掉所有已到期的、再对准下一个最早的即可。
	purge *time.Timer
}

func newTestRunStore() *testRunStore {
	return &testRunStore{runs: map[string]*testRun{}, stopped: map[string]string{}}
}

// start 开启（或重置）某接收器的试运行。重复开启等于重新计时并清空既有抓包——
// 用户点"开始"时想看的是接下来发生的事，不是上一轮的残留。
func (s *testRunStore) start(id string, now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.runs[id] = &testRun{startedAt: now, expiresAt: now.Add(TestRunTTL), running: true}
	delete(s.stopped, id)
	// 上一轮的抓包刚被覆盖掉，销毁定时器可能正对着它——重对一次。
	s.armPurgeLocked(now)
}

// stop 停止试运行。reason 非空表示不是用户主动停的（超时），留给界面提示。
// 抓包**不清**：用户停下来正是为了看刚收到的东西，而它也是样本载荷。
// 但也不会一直留着——最后一次抓到之后 3 小时销毁（见 CaptureTTL）。
func (s *testRunStore) stop(id, reason string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if run, ok := s.runs[id]; ok {
		run.running = false
	}
	if reason != "" {
		s.stopped[id] = reason
	}
}

// active 判断某接收器此刻是否处在试运行中，顺手处理超时。
//
// 到期检查放在这里（而不是起一个定时器）：这条路径每个请求都会走一次，
// 判断是否过期只是一次时间比较，而一个 goroutine 加一把定时器要维护生命周期、
// 还要和 Reload / Close 对齐——为一个调试开关不值得。
func (s *testRunStore) active(id string, now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.activeLocked(id, now)
}

// activeLocked 是 active 的内部版本，调用方须持锁。到期时就地停掉并记下原因。
func (s *testRunStore) activeLocked(id string, now time.Time) bool {
	run, ok := s.runs[id]
	if !ok || !run.running {
		return false
	}
	if now.After(run.expiresAt) {
		run.running = false
		s.stopped[id] = "试运行已达最长时间，已自动停止（消息恢复正常转发）"
		return false
	}
	return true
}

// add 记一条抓包，顶掉上一条。返回 false 表示这个接收器的试运行已经不在了（竞态：
// 请求进来的同时用户点了停止），此时调用方应当按真实请求继续处理。
func (s *testRunStore) add(id string, c TestRunCapture) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	run, ok := s.runs[id]
	if !ok || !run.running {
		return false
	}
	run.total++
	// 留最新的：调试时关心的永远是刚发生的那一条。
	run.capture = &c
	// 新的一条重新开始计 3 小时——"最后一次收到样本之后 3 小时"才是用户能理解的口径。
	run.capturedAt = time.Now()
	run.captureGone = false
	s.armPurgeLocked(run.capturedAt)
	return true
}

// dropExpiredLocked 销毁所有已过 CaptureTTL 的抓包，返回下一个到期时刻（没有则零值）。
// 调用方须持锁。
func (s *testRunStore) dropExpiredLocked(now time.Time) time.Time {
	var next time.Time
	for _, run := range s.runs {
		if run.capture == nil {
			continue
		}
		exp := run.capturedAt.Add(CaptureTTL)
		if !exp.After(now) {
			// 置 nil 就把那份载荷交回 GC；captureGone 留着，好让界面说清"曾经有、已销毁"。
			run.capture = nil
			run.captureGone = true
			continue
		}
		if next.IsZero() || exp.Before(next) {
			next = exp
		}
	}
	return next
}

// armPurgeLocked 先清掉已到期的抓包，再把销毁定时器对准剩下最早的那一个。
// 调用方须持锁。没有抓包时定时器被停掉——不留一个空转的 goroutine。
func (s *testRunStore) armPurgeLocked(now time.Time) {
	next := s.dropExpiredLocked(now)
	if s.purge != nil {
		s.purge.Stop()
		s.purge = nil
	}
	if next.IsZero() {
		return
	}
	// 多等 1 秒再醒：省掉"醒来时刚好差几纳秒没到期、于是又对准同一时刻"的空转一圈。
	s.purge = time.AfterFunc(next.Sub(now)+time.Second, s.purgeNow)
}

// purgeNow 定时器回调：到点真把抓包扔掉，不依赖界面来轮询。
func (s *testRunStore) purgeNow() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.armPurgeLocked(time.Now())
}

// state 读取某接收器的试运行状态（含到期处理）。
func (s *testRunStore) state(id string, now time.Time) TestRunState {
	s.mu.Lock()
	defer s.mu.Unlock()

	// 先跑一遍到期判定，好让"超时自停"这件事在界面只是轮询、没有请求进来时也能发生。
	running := s.activeLocked(id, now)
	// 抓包的到期同样在这里再判一次。定时器已经会主动销毁（armPurgeLocked），这一遍是
	// 为了读取路径自身自洽：不管定时器有没有恰好醒过，读到的绝不会是一份已过期的载荷。
	s.dropExpiredLocked(now)
	st := TestRunState{StoppedReason: s.stopped[id]}
	run, ok := s.runs[id]
	if !ok {
		return st
	}
	st.Running = running
	if running {
		st.StartedAt = run.startedAt.Unix()
		st.ExpiresAt = run.expiresAt.Unix()
	}
	// 抓包与总条数无论是否还在运行都照常返回：停下来之后它就是那份样本载荷。
	st.Count = run.total
	st.CaptureExpired = run.captureGone
	if run.capture != nil {
		c := *run.capture
		st.Capture = &c
		st.Sniffed = c.Sniffed
		st.CaptureExpiresAt = run.capturedAt.Add(CaptureTTL).Unix()
	}
	return st
}

// clear 停掉全部试运行。只在 Close 时调用：进程退出时这些完整载荷不该留在内存里。
//
// 刻意不在 Reload 里调用（Reload 只调 keep）：试运行的正常用法就是
// 「收一条 → 照着抓包改配置 → 保存 → 再收一条」，保存会触发 Reload，
// 清空等于用户每改一次就得回去重新点一次开始。
func (s *testRunStore) clear() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.runs = map[string]*testRun{}
	s.stopped = map[string]string{}
	// 定时器持有 s，不停掉的话它能把整个 store 拖到 3 小时后才回收。
	if s.purge != nil {
		s.purge.Stop()
		s.purge = nil
	}
}

// keep 只保留仍然存在的接收器。删掉一个接收器后它的抓包必须立刻消失。
func (s *testRunStore) keep(ids map[string]struct{}) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id := range s.runs {
		if _, ok := ids[id]; !ok {
			delete(s.runs, id)
		}
	}
	for id := range s.stopped {
		if _, ok := ids[id]; !ok {
			delete(s.stopped, id)
		}
	}
	// 刚删掉的可能正是定时器对着的那一份，重对一次（没抓包了就顺手停掉）。
	s.armPurgeLocked(time.Now())
}
