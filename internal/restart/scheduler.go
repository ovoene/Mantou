package restart

import (
	"fmt"
	"time"

	"mantou/internal/config"
	"mantou/internal/logx"
)

// 定时重启的调度器。职责只有一件：到点了就调一次 Fire。
//
// 「怎么重启」不在这里——它由 cmd/mantou 注入（走的是自更新那条已经验证过的
// 优雅关闭 → 替换进程 通道），调度器只管什么时候。
//
// 刻意不放进 internal/modules：那里的模块都有各自的启停开关与资源（监听、连接、任务队列），
// 而定时重启是「设置」的一部分，没有任何资源，且需要访问只有 cmd/mantou 才有的进程控制能力。

const (
	// tickInterval 检查间隔。设定只精确到分钟，30 秒足够保证每一分钟至少被看到一次
	// （用 60 秒会因为 ticker 漂移而可能整分钟跳过）。
	tickInterval = 30 * time.Second

	// catchUpWindow 迟到多久之内仍然执行。
	//
	// 需要这个窗口，是因为「到点」不等于「被看到」：检查有间隔，机器可能休眠、
	// 也可能被 NTP 往前校时。窗口内视为正常执行；超出则**跳过**而不是补做——
	// 用户把重启放在凌晨 4 点是为了避开使用高峰，机器上午 9 点醒来时补一次重启
	// 恰好落在最不该重启的时候，比不重启更糟。
	catchUpWindow = 10 * time.Minute

	// maxCatchUpSteps 单次检查最多往前推进多少个触发点。
	// 时钟被往前拨一年时，逐个推进会是几十次循环；有上限保证单次检查不会长时间占用，
	// 剩下的下一次检查继续推进（推进本身极快，只是不想在一个 tick 里全做完）。
	maxCatchUpSteps = 32
)

// Store 是调度器需要的配置能力，正好由 *config.Manager 满足。
// 收窄成接口是为了测试能塞一个假实现，尤其是「落盘失败」这条分支——
// 它决定要不要重启，靠真实文件系统很难稳定复现。
type Store interface {
	Snapshot() *config.Config
	Update(mutate func(c *config.Config)) error
}

// Options 构造参数。
type Options struct {
	Store Store
	Log   *logx.Logger
	// Fire 执行一次重启。返回 error 表示没能触发（此时进程继续运行）。
	// 正常情况下它不会返回——进程已经被新映像接管。
	Fire func() error
	// Now 取当前时间，留给测试注入。零值表示 time.Now。
	Now func() time.Time
	// Interval 检查间隔，零值表示 tickInterval。
	Interval time.Duration
}

// Scheduler 定时重启调度器。
type Scheduler struct {
	store    Store
	log      *logx.Logger
	fire     func() error
	now      func() time.Time
	interval time.Duration

	// anchor 是「已经处理过的时刻」，下一次触发点从它之后开始找。
	//
	// 只在调度 goroutine 里读写（测试里直接调 tick，同样是单线程），因此不加锁。
	anchor time.Time

	// fingerprint 是上一次检查时看到的那份设置（只含用户设的部分）。
	// 与 anchor 同样只在调度 goroutine 里读写。
	fingerprint string

	stop chan struct{}
	done chan struct{}
}

// New 创建调度器。锚点取 max(上次执行时间, 当前时间)：
//
//   - 取「当前时间」是因为进程刚起来本身就等于刚重启过——启动前错过的触发点没有补做的意义，
//     补了只会让人在开机后立刻再经历一次重启。
//   - 还要跟「上次执行时间」取大，是为了防时钟回拨：定时重启写完 LastRunAt 就结束进程，
//     若新进程启动时系统时间被校回到触发点之前（NTP 纠正、虚拟机恢复快照），
//     只看启动时间就会算出「同一个触发点还没到」，于是立刻再重启一次，循环下去。
func New(opts Options) *Scheduler {
	s := &Scheduler{
		store:    opts.Store,
		log:      opts.Log,
		fire:     opts.Fire,
		now:      opts.Now,
		interval: opts.Interval,
	}
	if s.now == nil {
		s.now = time.Now
	}
	if s.interval <= 0 {
		s.interval = tickInterval
	}
	if s.log == nil {
		s.log = logx.L()
	}
	p := s.policy()
	s.resetAnchor(s.now(), p)
	// 指纹在这里就要记下来：留空的话第一次检查会把它当成"设置刚被改过"，
	// 于是锚点被重置成 now，上面刚用 LastRunAt 建立起来的防时钟回拨保护当场失效。
	s.fingerprint = restartFingerprint(p)
	return s
}

// resetAnchor 把锚点定到「从现在开始」，但不早于已落盘的上次执行时间。
//
// 两处共用（构造时、以及设置被改动时），因为两处要的是同一件事：
// 既不补做过去的触发点，也不能因为系统时间被回拨而把已经做过的那一次再做一遍。
func (s *Scheduler) resetAnchor(now time.Time, p config.RestartPolicy) {
	s.anchor = now
	if p.LastRunAt > 0 {
		if last := time.Unix(p.LastRunAt, 0); last.After(s.anchor) {
			s.anchor = last
		}
	}
}

// restartFingerprint 是「用户设的那部分」的指纹，用来发现设置被改过。
//
// 刻意不含 LastRunAt：那是程序自己写的执行记录，每次触发都会变，
// 含进来会让每次触发之后的检查都以为"设置被改了"。
// 各列表字段的顺序由 normalizeRestart 统一排过，所以指纹是稳定的。
func restartFingerprint(p config.RestartPolicy) string {
	return fmt.Sprintf("%t|%s|%v|%v|%d|%s|%02d:%02d",
		p.Enabled, p.Mode, p.Weekdays, p.Dates, p.EveryDays, p.StartDate, p.Hour, p.Minute)
}

// Start 启动后台检查。可重复调用无害（已启动时直接返回）。
func (s *Scheduler) Start() {
	if s.stop != nil {
		return
	}
	s.stop = make(chan struct{})
	s.done = make(chan struct{})
	if p := s.policy(); p.Enabled {
		if next, ok := Next(p, s.anchor); ok {
			s.log.Info("定时重启已启用", "next", next.Format("2006-01-02 15:04"))
		}
	}
	go s.loop()
}

// Stop 停止后台检查并等待其退出。
func (s *Scheduler) Stop() {
	if s.stop == nil {
		return
	}
	close(s.stop)
	<-s.done
	s.stop = nil
	s.done = nil
}

func (s *Scheduler) loop() {
	defer close(s.done)
	t := time.NewTicker(s.interval)
	defer t.Stop()
	for {
		select {
		case <-s.stop:
			return
		case <-t.C:
			s.tick(s.now())
		}
	}
}

// policy 每次检查都重新读配置，这样界面上改完时刻立即生效，不需要重启程序。
func (s *Scheduler) policy() config.RestartPolicy {
	if s.store == nil {
		return config.RestartPolicy{}
	}
	cfg := s.store.Snapshot()
	if cfg == nil {
		return config.RestartPolicy{}
	}
	return cfg.Settings.Restart
}

// tick 是一次检查。拆出来是为了能在测试里直接喂时间，不必真的等 30 秒。
func (s *Scheduler) tick(now time.Time) {
	p := s.policy()

	// 设置刚被改过：把锚点挪到现在。
	//
	// 不这样做的话，界面上把时刻改成"最近十分钟内的某个点"会导致保存后半分钟内立刻重启一次——
	// 锚点还停在上一次触发点（或进程启动时刻），而新填的时刻正好落在它与现在之间，
	// 于是被当成"迟到但仍在补做窗口内"执行掉。改时刻的人并没有要求立刻重启，
	// 而设置页上显示的"下次执行"算的是 Next(p, 现在)，根本不会显示这一次。
	//
	// 同时也不追补"改之前那份设置的"触发点：那些触发点属于一份已经不存在的计划。
	if fp := restartFingerprint(p); fp != s.fingerprint {
		s.fingerprint = fp
		s.resetAnchor(now, p)
		if p.Enabled {
			if next, ok := Next(p, s.anchor); ok {
				s.log.Info("定时重启：设置已更新", "next", next.Format("2006-01-02 15:04"))
			}
		}
	}

	if !p.Enabled {
		// 关闭期间锚点跟着走。否则关掉开关几天后再打开，锚点还停在关掉那一刻，
		// 一打开就要处理一串早已过去的触发点（结果都是跳过，只是白刷一堆日志）。
		s.anchor = now
		return
	}
	skipped := 0
	var lastSkipped time.Time
	for i := 0; i < maxCatchUpSteps; i++ {
		next, ok := Next(p, s.anchor)
		if !ok || next.After(now) {
			break
		}
		s.anchor = next // 无论执行还是跳过都要推进，否则同一个触发点会被反复处理
		if now.Sub(next) <= catchUpWindow {
			if skipped > 0 {
				s.logSkipped(skipped, lastSkipped)
			}
			s.fireAt(next)
			return
		}
		skipped++
		lastSkipped = next
	}
	if skipped > 0 {
		s.logSkipped(skipped, lastSkipped)
	}
}

func (s *Scheduler) logSkipped(n int, last time.Time) {
	s.log.Warn("定时重启：错过的触发点已跳过（超出补做窗口）",
		"count", n, "last", last.Format("2006-01-02 15:04"), "window", catchUpWindow.String())
}

// fireAt 执行一次定时重启。
func (s *Scheduler) fireAt(at time.Time) {
	// 先把执行时间落盘，再触发重启。顺序不能反：反过来的话进程可能在写盘完成之前
	// 就被新映像接管，新进程读到的还是旧的 LastRunAt——一旦此时系统时间又落在触发点之前，
	// 它会认为这次还没做过，于是再重启一次。
	//
	// 写不进去就不重启：这条时间戳是防重启循环的唯一凭据，宁可这次不重启（错过一次，
	// 日志里有 Error），也不能在没有凭据的情况下动进程。
	if err := s.store.Update(func(c *config.Config) {
		c.Settings.Restart.LastRunAt = at.Unix()
	}); err != nil {
		s.log.Error("定时重启：执行时间写入失败，本次不重启", "error", err.Error())
		return
	}
	s.log.Info("定时重启：到达设定时刻，进程即将重启", "at", at.Format("2006-01-02 15:04"))
	if s.fire == nil {
		return
	}
	if err := s.fire(); err != nil {
		s.log.Error("定时重启：触发重启失败，进程继续运行", "error", err.Error())
	}
}
