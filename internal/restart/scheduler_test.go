package restart

import (
	"errors"
	"sync"
	"testing"
	"time"

	"mantou/internal/config"
	"mantou/internal/logx"
)

// 调度器只有一个真正危险的失败模式：**重启循环**（开机就重启，起来又重启）。
// 它一旦发生，面板将无法登录，用户只能停掉进程手改 config.json——所以下面的用例
// 大半是在钉住"什么情况下不许触发"。

type fakeStore struct {
	mu        sync.Mutex
	cfg       *config.Config
	updateErr error
	updates   int
}

func newFakeStore(p config.RestartPolicy) *fakeStore {
	cfg := &config.Config{}
	cfg.Settings.Restart = p
	return &fakeStore{cfg: cfg}
}

func (f *fakeStore) Snapshot() *config.Config {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.cfg
}

func (f *fakeStore) Update(mutate func(c *config.Config)) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.updateErr != nil {
		return f.updateErr
	}
	mutate(f.cfg)
	f.updates++
	return nil
}

func (f *fakeStore) lastRunAt() int64 {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.cfg.Settings.Restart.LastRunAt
}

// newTestScheduler 造一个不会自己转起来的调度器：测试直接调 tick 喂时间。
func newTestScheduler(t *testing.T, store *fakeStore, start time.Time, fired *int) *Scheduler {
	t.Helper()
	return New(Options{
		Store: store,
		Log:   logx.New(logx.Options{}),
		Now:   func() time.Time { return start },
		Fire: func() error {
			*fired++
			return nil
		},
	})
}

// 每周三 08:00：到点触发一次，之后同一个触发点不再触发。
func TestSchedulerFiresOnceAtTime(t *testing.T) {
	store := newFakeStore(config.RestartPolicy{
		Enabled: true, Mode: config.RestartModeWeekly,
		Weekdays: []int{3}, Hour: 8, // 2026-08-26 是周三
	})
	fired := 0
	s := newTestScheduler(t, store, lt(t, "2026-08-26 07:59"), &fired)

	s.tick(lt(t, "2026-08-26 07:59"))
	if fired != 0 {
		t.Fatalf("还没到点就触发了：fired=%d", fired)
	}
	s.tick(lt(t, "2026-08-26 08:00"))
	if fired != 1 {
		t.Fatalf("到点应触发一次，实际 fired=%d", fired)
	}
	if got, want := store.lastRunAt(), lt(t, "2026-08-26 08:00").Unix(); got != want {
		t.Fatalf("落盘的执行时间 = %d，期望 %d（触发点本身，不是当前时刻）", got, want)
	}
	// 后续检查不得再次触发：这正是重启循环的形状。
	s.tick(lt(t, "2026-08-26 08:00"))
	s.tick(lt(t, "2026-08-26 08:05"))
	if fired != 1 {
		t.Fatalf("同一个触发点被重复执行：fired=%d", fired)
	}
}

// 触发点在进程启动之前 → 不补做。进程刚起来本身就等于刚重启过。
func TestSchedulerIgnoresOccurrenceBeforeStart(t *testing.T) {
	store := newFakeStore(config.RestartPolicy{
		Enabled: true, Mode: config.RestartModeWeekly,
		Weekdays: []int{3}, Hour: 8,
	})
	fired := 0
	s := newTestScheduler(t, store, lt(t, "2026-08-26 09:00"), &fired) // 08:00 已过去
	s.tick(lt(t, "2026-08-26 09:01"))
	s.tick(lt(t, "2026-08-26 23:59"))
	if fired != 0 {
		t.Fatalf("启动前的触发点被补做了：fired=%d", fired)
	}
	// 下周三仍应正常触发。
	if next, ok := Next(store.cfg.Settings.Restart, s.anchor); !ok || !next.Equal(lt(t, "2026-09-02 08:00")) {
		t.Fatalf("下一次触发 = %v (ok=%v)，期望 2026-09-02 08:00", next, ok)
	}
}

// 迟到超过补做窗口 → 跳过。机器休眠一上午后醒来，不该在上班时间补一次重启。
func TestSchedulerSkipsWhenTooLate(t *testing.T) {
	store := newFakeStore(config.RestartPolicy{
		Enabled: true, Mode: config.RestartModeWeekly,
		Weekdays: []int{3}, Hour: 8,
	})
	fired := 0
	s := newTestScheduler(t, store, lt(t, "2026-08-26 06:00"), &fired)
	s.tick(lt(t, "2026-08-26 11:00")) // 迟到 3 小时
	if fired != 0 {
		t.Fatalf("超出补做窗口仍然触发了：fired=%d", fired)
	}
	if store.lastRunAt() != 0 {
		t.Fatal("跳过的触发点不该写执行时间")
	}
	// 跳过之后锚点必须已推进，下一次是一周后而不是卡在今天。
	if next, ok := Next(store.cfg.Settings.Restart, s.anchor); !ok || !next.Equal(lt(t, "2026-09-02 08:00")) {
		t.Fatalf("跳过后下一次触发 = %v (ok=%v)，期望 2026-09-02 08:00", next, ok)
	}
}

// 窗口之内（例如上一次检查到这一次之间跨过了触发点）照常执行。
func TestSchedulerFiresInsideCatchUpWindow(t *testing.T) {
	store := newFakeStore(config.RestartPolicy{
		Enabled: true, Mode: config.RestartModeWeekly,
		Weekdays: []int{3}, Hour: 8,
	})
	fired := 0
	s := newTestScheduler(t, store, lt(t, "2026-08-26 07:00"), &fired)
	s.tick(lt(t, "2026-08-26 08:09")) // 迟到 9 分钟，仍在 10 分钟窗口内
	if fired != 1 {
		t.Fatalf("补做窗口内应当执行，实际 fired=%d", fired)
	}
}

// 时钟被回拨到触发点之前：靠已落盘的 LastRunAt 认出"这次做过了"，否则就是重启循环。
func TestSchedulerHonorsLastRunAtAgainstClockRollback(t *testing.T) {
	store := newFakeStore(config.RestartPolicy{
		Enabled: true, Mode: config.RestartModeWeekly,
		Weekdays: []int{3}, Hour: 8,
		LastRunAt: lt(t, "2026-08-26 08:00").Unix(),
	})
	fired := 0
	// 重启完成后系统时间被校回到 07:30——只看启动时间会认为 08:00 还没到。
	s := newTestScheduler(t, store, lt(t, "2026-08-26 07:30"), &fired)
	s.tick(lt(t, "2026-08-26 07:31"))
	s.tick(lt(t, "2026-08-26 08:00"))
	s.tick(lt(t, "2026-08-26 08:01"))
	if fired != 0 {
		t.Fatalf("同一个触发点在时钟回拨后又执行了一次：fired=%d（这就是重启循环）", fired)
	}
}

// 关闭期间锚点跟着当前时间走：开关关了一周再打开，不该处理这一周里的历史触发点。
func TestSchedulerDisabledKeepsAnchorFresh(t *testing.T) {
	store := newFakeStore(config.RestartPolicy{
		Mode: config.RestartModeWeekly, Weekdays: []int{3}, Hour: 8,
	})
	fired := 0
	s := newTestScheduler(t, store, lt(t, "2026-08-26 07:00"), &fired)
	s.tick(lt(t, "2026-09-02 09:00")) // 关闭状态，且已越过 09-02 08:00
	if fired != 0 {
		t.Fatalf("关闭状态下触发了：fired=%d", fired)
	}
	store.mu.Lock()
	store.cfg.Settings.Restart.Enabled = true
	store.mu.Unlock()
	s.tick(lt(t, "2026-09-02 09:01"))
	if fired != 0 {
		t.Fatalf("刚打开开关就补做了历史触发点：fired=%d", fired)
	}
	if next, ok := Next(store.cfg.Settings.Restart, s.anchor); !ok || !next.Equal(lt(t, "2026-09-09 08:00")) {
		t.Fatalf("下一次触发 = %v (ok=%v)，期望 2026-09-09 08:00", next, ok)
	}
}

// 执行时间写不进去就不重启：这条时间戳是防重启循环的唯一凭据。
func TestSchedulerAbortsWhenTimestampWriteFails(t *testing.T) {
	store := newFakeStore(config.RestartPolicy{
		Enabled: true, Mode: config.RestartModeWeekly,
		Weekdays: []int{3}, Hour: 8,
	})
	store.updateErr = errors.New("磁盘满")
	fired := 0
	s := newTestScheduler(t, store, lt(t, "2026-08-26 07:59"), &fired)
	s.tick(lt(t, "2026-08-26 08:00"))
	if fired != 0 {
		t.Fatalf("执行时间没落盘却重启了：fired=%d", fired)
	}
}

// 触发失败（例如拉起新进程失败）不能让进程死掉，也不能反复重试同一个触发点。
func TestSchedulerSurvivesFireError(t *testing.T) {
	store := newFakeStore(config.RestartPolicy{
		Enabled: true, Mode: config.RestartModeWeekly,
		Weekdays: []int{3}, Hour: 8,
	})
	calls := 0
	s := New(Options{
		Store: store,
		Log:   logx.New(logx.Options{}),
		Now:   func() time.Time { return lt(t, "2026-08-26 07:59") },
		Fire:  func() error { calls++; return errors.New("拉起失败") },
	})
	s.tick(lt(t, "2026-08-26 08:00"))
	s.tick(lt(t, "2026-08-26 08:01"))
	if calls != 1 {
		t.Fatalf("触发失败后被重试：calls=%d", calls)
	}
}

// Start/Stop 的实际线路：main.go 只用这两个方法，必须确认后台真的会转、也真的停得下来。
func TestSchedulerStartStop(t *testing.T) {
	store := newFakeStore(config.RestartPolicy{
		Enabled: true, Mode: config.RestartModeWeekly,
		Weekdays: []int{3}, Hour: 8,
	})
	var mu sync.Mutex
	now := lt(t, "2026-08-26 07:59")
	fired := make(chan struct{}, 1)
	s := New(Options{
		Store:    store,
		Log:      logx.New(logx.Options{}),
		Interval: 2 * time.Millisecond,
		Now: func() time.Time {
			mu.Lock()
			defer mu.Unlock()
			return now
		},
		Fire: func() error {
			select {
			case fired <- struct{}{}:
			default:
			}
			return nil
		},
	})
	s.Start()
	defer s.Stop()

	mu.Lock()
	now = lt(t, "2026-08-26 08:00")
	mu.Unlock()

	select {
	case <-fired:
	case <-time.After(3 * time.Second):
		t.Fatal("后台检查没有在到点后触发重启")
	}
}

// ---- 设置被改动 ----
//
// 「改设置」与「机器休眠后醒来」在调度器眼里长得一样：都是锚点停在过去、
// 而现在已经越过了某个触发点。但要做的事完全相反——后者要补做，前者不能。

// 已开启的情况下把时刻改成"刚刚过去的那几分钟"，不该在保存后半分钟内重启一次。
func TestSchedulerDoesNotFireAfterPolicyChange(t *testing.T) {
	store := newFakeStore(config.RestartPolicy{
		Enabled: true, Mode: config.RestartModeWeekly,
		Weekdays: []int{3}, Hour: 8, // 2026-08-26 是周三
	})
	fired := 0
	s := newTestScheduler(t, store, lt(t, "2026-08-26 06:00"), &fired)
	// 上午 09:55：08:00 那次已经超出补做窗口被跳过，锚点停在 08:00。
	s.tick(lt(t, "2026-08-26 09:55"))
	if fired != 0 {
		t.Fatalf("超窗口的触发点不该执行：fired=%d", fired)
	}

	// 用户此刻把时刻改成 09:50——它落在锚点(08:00)与现在(09:56)之间，
	// 且只迟到 6 分钟，正好在补做窗口内。这是"保存完就重启"的成因。
	store.mu.Lock()
	store.cfg.Settings.Restart.Hour = 9
	store.cfg.Settings.Restart.Minute = 50
	store.mu.Unlock()

	s.tick(lt(t, "2026-08-26 09:56"))
	if fired != 0 {
		t.Fatalf("改完时刻就立刻重启了一次：fired=%d", fired)
	}
	// 新计划本身要生效：下一次是一周后的 09:50。
	if next, ok := Next(store.cfg.Settings.Restart, s.anchor); !ok || !next.Equal(lt(t, "2026-09-02 09:50")) {
		t.Fatalf("改完之后下一次触发 = %v (ok=%v)，期望 2026-09-02 09:50", next, ok)
	}
}

// 反面：改成一个还没到的时刻，到点照样要执行。别把"不立刻重启"做成"改完就不重启"。
func TestSchedulerStillFiresAtNewTimeSameDay(t *testing.T) {
	store := newFakeStore(config.RestartPolicy{
		Enabled: true, Mode: config.RestartModeWeekly,
		Weekdays: []int{3}, Hour: 8,
	})
	fired := 0
	s := newTestScheduler(t, store, lt(t, "2026-08-26 06:00"), &fired)
	s.tick(lt(t, "2026-08-26 09:55"))

	store.mu.Lock()
	store.cfg.Settings.Restart.Hour = 10
	store.cfg.Settings.Restart.Minute = 0
	store.mu.Unlock()

	s.tick(lt(t, "2026-08-26 09:56")) // 还没到 10:00
	if fired != 0 {
		t.Fatalf("还没到新时刻就触发了：fired=%d", fired)
	}
	s.tick(lt(t, "2026-08-26 10:00"))
	if fired != 1 {
		t.Fatalf("到达新时刻应触发一次，实际 fired=%d", fired)
	}
}

// 改设置时锚点重置，但防时钟回拨的那道保护不能跟着丢：
// 重置取的是 max(现在, 上次执行时间)，与构造时同一条规则。
func TestSchedulerPolicyChangeKeepsRollbackGuard(t *testing.T) {
	store := newFakeStore(config.RestartPolicy{
		Enabled: true, Mode: config.RestartModeWeekly,
		Weekdays: []int{3}, Hour: 8,
		LastRunAt: lt(t, "2026-08-26 08:00").Unix(),
	})
	fired := 0
	// 重启完系统时间被校回到 07:30。
	s := newTestScheduler(t, store, lt(t, "2026-08-26 07:30"), &fired)

	// 此时用户改了个无关字段（模式仍是每周，只多勾一天），指纹变化触发锚点重置。
	store.mu.Lock()
	store.cfg.Settings.Restart.Weekdays = []int{3, 5}
	store.mu.Unlock()

	s.tick(lt(t, "2026-08-26 07:31"))
	s.tick(lt(t, "2026-08-26 08:00"))
	s.tick(lt(t, "2026-08-26 08:01"))
	if fired != 0 {
		t.Fatalf("改设置后锚点重置把已执行过的触发点又做了一次：fired=%d（重启循环）", fired)
	}
	// 新勾上的周五仍要正常触发。
	if next, ok := Next(store.cfg.Settings.Restart, s.anchor); !ok || !next.Equal(lt(t, "2026-08-28 08:00")) {
		t.Fatalf("下一次触发 = %v (ok=%v)，期望 2026-08-28 08:00（周五）", next, ok)
	}
}

// 指纹只认"用户设的那部分"。LastRunAt 每次触发都会变，混进指纹会让每次触发之后
// 的检查都以为设置被改过——锚点被反复重置，跳过日志也会莫名消失。
func TestRestartFingerprintIgnoresLastRunAt(t *testing.T) {
	base := config.RestartPolicy{
		Enabled: true, Mode: config.RestartModeWeekly,
		Weekdays: []int{3}, Dates: []string{"2026-09-01"},
		EveryDays: 7, StartDate: "2026-08-01", Hour: 8, Minute: 30,
	}
	withRun := base
	withRun.LastRunAt = 1700000000
	if restartFingerprint(base) != restartFingerprint(withRun) {
		t.Fatal("LastRunAt 不该影响指纹")
	}

	// 反过来，用户能改的每一个字段都必须让指纹变化，否则改了等于没改。
	mutations := map[string]func(p *config.RestartPolicy){
		"开关":  func(p *config.RestartPolicy) { p.Enabled = false },
		"模式":  func(p *config.RestartPolicy) { p.Mode = config.RestartModeDates },
		"星期":  func(p *config.RestartPolicy) { p.Weekdays = []int{4} },
		"日期":  func(p *config.RestartPolicy) { p.Dates = []string{"2026-09-02"} },
		"间隔":  func(p *config.RestartPolicy) { p.EveryDays = 3 },
		"起算日": func(p *config.RestartPolicy) { p.StartDate = "2026-08-02" },
		"时":   func(p *config.RestartPolicy) { p.Hour = 9 },
		"分":   func(p *config.RestartPolicy) { p.Minute = 31 },
	}
	for name, mutate := range mutations {
		changed := base
		mutate(&changed)
		if restartFingerprint(base) == restartFingerprint(changed) {
			t.Fatalf("改了「%s」指纹却没变，调度器不会察觉这次改动", name)
		}
	}
}
