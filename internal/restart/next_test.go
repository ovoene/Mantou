package restart

import (
	"testing"
	"time"
	_ "time/tzdata" // 内嵌时区数据库：夏令时用例不能依赖宿主机装了什么

	"mantou/internal/config"
)

// Next 是定时重启唯一的时间计算入口，错一天用户不会立刻发现——他只会在某个早上
// 察觉"昨晚没重启"或者"今天怎么重启了两次"。所以三种模式的边界都用用例钉住，
// 特别是「正好等于触发时刻」这一条：它决定了刚重启完的进程会不会立刻再重启一次。

func lt(t *testing.T, s string) time.Time {
	t.Helper()
	v, err := time.ParseInLocation("2006-01-02 15:04", s, time.Local)
	if err != nil {
		t.Fatalf("解析时间 %q 失败: %v", s, err)
	}
	return v
}

func TestNextByWeekday(t *testing.T) {
	// 2026-08-24 是周一，08-27 周四，08-28 周五，08-31 周一。
	p := config.RestartPolicy{
		Mode:     config.RestartModeWeekly,
		Weekdays: []int{1, 4}, // 周一、周四
		Hour:     4,
		Minute:   30,
	}
	cases := []struct {
		name string
		from string
		want string
	}{
		{"当天还没到点", "2026-08-24 03:00", "2026-08-24 04:30"},
		{"正好等于触发时刻则顺延到下一次", "2026-08-24 04:30", "2026-08-27 04:30"},
		{"当天已过点", "2026-08-24 05:00", "2026-08-27 04:30"},
		{"跨周回到下周一", "2026-08-28 12:00", "2026-08-31 04:30"},
		{"非选中日", "2026-08-26 00:01", "2026-08-27 04:30"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := Next(p, lt(t, tc.from))
			if !ok {
				t.Fatalf("期望有下一次触发，实际 ok=false")
			}
			if want := lt(t, tc.want); !got.Equal(want) {
				t.Fatalf("下一次触发 = %v，期望 %v", got, want)
			}
		})
	}
}

func TestNextByWeekdayWithoutWeekdaysNeverFires(t *testing.T) {
	p := config.RestartPolicy{Mode: config.RestartModeWeekly, Hour: 4}
	if _, ok := Next(p, lt(t, "2026-08-24 03:00")); ok {
		t.Fatal("一天都没选却算出了触发时刻：这会变成每天都重启")
	}
}

func TestNextByDates(t *testing.T) {
	p := config.RestartPolicy{
		Mode:   config.RestartModeDates,
		Dates:  []string{"2026-09-01", "2026-08-27", "2026-08-24"},
		Hour:   2,
		Minute: 0,
	}
	cases := []struct {
		name string
		from string
		want string
	}{
		{"取最近的一个而不是列表第一个", "2026-08-20 00:00", "2026-08-24 02:00"},
		{"跳过已过去的日期", "2026-08-25 00:00", "2026-08-27 02:00"},
		{"正好等于触发时刻则顺延", "2026-08-27 02:00", "2026-09-01 02:00"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := Next(p, lt(t, tc.from))
			if !ok {
				t.Fatalf("期望有下一次触发，实际 ok=false")
			}
			if want := lt(t, tc.want); !got.Equal(want) {
				t.Fatalf("下一次触发 = %v，期望 %v", got, want)
			}
		})
	}
}

func TestNextByDatesExhausted(t *testing.T) {
	p := config.RestartPolicy{
		Mode:  config.RestartModeDates,
		Dates: []string{"2026-08-24"},
		Hour:  2,
	}
	// 日期全部过去之后必须报告"不会再触发"，界面据此显示"无"，
	// 而不是悄悄回到第一个日期去（那等于每年重来一遍）。
	if _, ok := Next(p, lt(t, "2026-08-25 00:00")); ok {
		t.Fatal("所有日期都已过去，却仍算出了触发时刻")
	}
}

func TestNextByDatesIgnoresUnparsable(t *testing.T) {
	p := config.RestartPolicy{
		Mode:  config.RestartModeDates,
		Dates: []string{"不是日期", "2026-09-01", ""},
		Hour:  3,
	}
	got, ok := Next(p, lt(t, "2026-08-26 00:00"))
	if !ok {
		t.Fatal("列表里有一个合法日期，应当能算出触发时刻")
	}
	if want := lt(t, "2026-09-01 03:00"); !got.Equal(want) {
		t.Fatalf("下一次触发 = %v，期望 %v", got, want)
	}
}

func TestNextByInterval(t *testing.T) {
	p := config.RestartPolicy{
		Mode:      config.RestartModeInterval,
		EveryDays: 7,
		StartDate: "2026-08-24",
		Hour:      4,
		Minute:    0,
	}
	cases := []struct {
		name string
		from string
		want string
	}{
		{"起算日之前", "2026-08-01 00:00", "2026-08-24 04:00"},
		{"起算日当天未到点", "2026-08-24 03:59", "2026-08-24 04:00"},
		{"正好等于触发时刻则跳到下一个周期", "2026-08-24 04:00", "2026-08-31 04:00"},
		{"周期内", "2026-08-27 12:00", "2026-08-31 04:00"},
		{"跨多个周期后仍落在 起算日+k×N 上", "2026-09-20 00:00", "2026-09-21 04:00"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := Next(p, lt(t, tc.from))
			if !ok {
				t.Fatalf("期望有下一次触发，实际 ok=false")
			}
			if want := lt(t, tc.want); !got.Equal(want) {
				t.Fatalf("下一次触发 = %v，期望 %v", got, want)
			}
		})
	}
}

// 间隔模式的锚点必须是起算日期，不是"上次重启时刻"——否则每次手动重启都会把计划推后，
// 用户过几周就说不出下一次是哪天。这里连算 5 个周期，确认它们严格是 起算日+k×N。
func TestNextByIntervalDoesNotDrift(t *testing.T) {
	p := config.RestartPolicy{
		Mode:      config.RestartModeInterval,
		EveryDays: 3,
		StartDate: "2026-08-24",
		Hour:      1,
		Minute:    15,
	}
	want := []string{
		"2026-08-24 01:15",
		"2026-08-27 01:15",
		"2026-08-30 01:15",
		"2026-09-02 01:15",
		"2026-09-05 01:15",
	}
	cur := lt(t, "2026-08-23 00:00")
	for i, w := range want {
		got, ok := Next(p, cur)
		if !ok {
			t.Fatalf("第 %d 次：期望有触发时刻", i+1)
		}
		if exp := lt(t, w); !got.Equal(exp) {
			t.Fatalf("第 %d 次触发 = %v，期望 %v", i+1, got, exp)
		}
		cur = got // 下一轮从刚算出的触发点开始，模拟"重启完再算下一次"
	}
}

func TestNextByIntervalWithoutStartDateFallsBackToToday(t *testing.T) {
	// 起算日是必填项（RestartPolicy.Valid 会拦），但配置文件可能被手工改坏。
	// 兜底行为：以"当天"为锚，至少还会触发，而不是永远不触发。
	p := config.RestartPolicy{Mode: config.RestartModeInterval, EveryDays: 2, Hour: 6}
	got, ok := Next(p, lt(t, "2026-08-26 07:00"))
	if !ok {
		t.Fatal("缺起算日时应当兜底算出触发时刻")
	}
	if want := lt(t, "2026-08-28 06:00"); !got.Equal(want) {
		t.Fatalf("下一次触发 = %v，期望 %v", got, want)
	}
}

func TestNextUnknownModeFallsBackToWeekly(t *testing.T) {
	// 规范化会把非法模式改成 weekly，但 Next 也要自己兜住：
	// 它会被界面拿去算"下一次"，那时的数据可能还没经过规范化。
	p := config.RestartPolicy{Mode: "每周吧", Weekdays: []int{3}, Hour: 8}
	got, ok := Next(p, lt(t, "2026-08-26 07:00"))
	if !ok {
		t.Fatal("未知模式应当按每周处理")
	}
	if want := lt(t, "2026-08-26 08:00"); !got.Equal(want) {
		t.Fatalf("下一次触发 = %v，期望 %v", got, want)
	}
}

// ---- 夏令时 ----
//
// 这些用例把 time.Local 临时换成一个真有夏令时的时区。本机测试环境不一定装了
// 时区数据库（CGO_ENABLED=0 的 Windows 构建尤其如此），所以在测试里内嵌一份
// （import _ "time/tzdata"，只影响测试二进制）。

// withDSTZone 把本机时区临时换成 America/New_York 并在用例结束后还原。
// 2026 年那里 3 月 8 日进入夏令时（当天只有 23 小时），11 月 1 日退出（25 小时）。
func withDSTZone(t *testing.T) {
	t.Helper()
	tz, err := time.LoadLocation("America/New_York")
	if err != nil {
		t.Fatalf("加载时区失败: %v", err)
	}
	saved := time.Local
	time.Local = tz
	t.Cleanup(func() { time.Local = saved })
}

// daysBetween 的名字与注释说的是"日历天数"，实现却是小时数除 24。
// 夏令时切换的那一天不是 24 小时，向下取整会让一整天凭空消失。
func TestDaysBetweenCountsCalendarDaysAcrossDST(t *testing.T) {
	withDSTZone(t)
	day := func(s string) time.Time { return lt(t, s+" 00:00") }
	cases := []struct {
		a, b string
		want int
	}{
		{"2026-03-08", "2026-03-09", 1},  // 进入夏令时：这一天只有 23 小时
		{"2026-11-01", "2026-11-02", 1},  // 退出夏令时：这一天有 25 小时
		{"2026-03-01", "2026-03-31", 30}, // 跨过一次切换的整月
		{"2026-03-08", "2026-03-08", 0},  // 同一天
		{"2026-03-09", "2026-03-08", -1}, // 反向：符号要对
		{"2026-06-01", "2026-06-08", 7},  // 不跨切换的普通一周
	}
	for _, c := range cases {
		if got := daysBetween(day(c.a), day(c.b)); got != c.want {
			t.Fatalf("daysBetween(%s, %s) = %d，期望 %d", c.a, c.b, got, c.want)
		}
	}
}

// 上面那个取整错误不会立刻显形——nextByInterval 后面"至多再往后挪两个周期"的循环
// 会把算小了的周期数补回来。这个用例钉住的是最终结果：无论取整对不对，
// 跨夏令时的间隔计划都必须落在 起算日 + k×N 上，且时刻仍是用户设的那个钟点。
func TestNextByIntervalAcrossDST(t *testing.T) {
	withDSTZone(t)
	p := config.RestartPolicy{
		Mode:      config.RestartModeInterval,
		EveryDays: 7,
		StartDate: "2026-03-01",
		Hour:      4,
		Minute:    30,
	}
	cases := []struct{ from, want string }{
		// 切换当天刚过点：下一次是再过 7 天，不是"今天再来一次"。
		{"2026-03-08 05:00", "2026-03-15 04:30"},
		// 切换当天还没到点：就是今天。
		{"2026-03-08 03:00", "2026-03-08 04:30"},
		// 跨过切换很久之后，锚点不漂：3 月 1 日起每 7 天，仍然落在周日 04:30。
		{"2026-06-10 12:00", "2026-06-14 04:30"},
	}
	for _, c := range cases {
		got, ok := Next(p, lt(t, c.from))
		if !ok {
			t.Fatalf("from=%s 应当算出触发时刻", c.from)
		}
		if want := lt(t, c.want); !got.Equal(want) {
			t.Fatalf("from=%s 下一次触发 = %v，期望 %v", c.from, got, want)
		}
	}
}
