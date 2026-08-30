package wol

import (
	"testing"
	"time"

	"mantou/internal/config"
)

// nyc 载入一个有夏令时的时区。中国大陆自 1991 年起不用夏令时，
// 默认时区下 W-8 观察不到；但容器的 TZ 是可配置的。
func nyc(t *testing.T) *time.Location {
	t.Helper()
	loc, err := time.LoadLocation("America/New_York")
	if err != nil {
		t.Skipf("本机缺少时区数据库，无法验证夏令时行为: %v", err)
	}
	return loc
}

// TestPlanForDayDSTSpringForward 锁定 W-8：春季夏令时切换日（这一天只有 23 小时），
// 用户设的 08:00 必须仍然是墙钟 08:00。
// 修复前用 day.Add(8h) 得到的是 09:00 EDT——晚一小时才发。
func TestPlanForDayDSTSpringForward(t *testing.T) {
	loc := nyc(t)
	// 2026-03-08 当天 02:00 直接跳到 03:00。
	day := time.Date(2026, 3, 8, 0, 0, 0, 0, loc)

	p, ok := planForDay(config.WOLSchedule{Enabled: true, Mode: "fixed", Time: "08:00", Count: 1}, day)
	if !ok {
		t.Fatal("planForDay 应成功")
	}
	if h, m, _ := p.start.Clock(); h != 8 || m != 0 {
		t.Fatalf("春季切换日的 08:00 被算成了 %02d:%02d（%v）", h, m, p.start)
	}
	if y, mo, d := p.start.Date(); y != 2026 || mo != time.March || d != 8 {
		t.Fatalf("触发时刻落到了别的日期: %v", p.start)
	}
}

// TestPlanForDayDSTFallBack 秋季夏令时切换日（这一天有 25 小时），
// 用户设的 08:00 必须仍然是墙钟 08:00。
// 修复前用 day.Add(8h) 得到的是 07:00 EST——早一小时发。
func TestPlanForDayDSTFallBack(t *testing.T) {
	loc := nyc(t)
	// 2026-11-01 当天 01:00 重复一次。
	day := time.Date(2026, 11, 1, 0, 0, 0, 0, loc)

	p, ok := planForDay(config.WOLSchedule{Enabled: true, Mode: "fixed", Time: "08:00", Count: 1}, day)
	if !ok {
		t.Fatal("planForDay 应成功")
	}
	if h, m, _ := p.start.Clock(); h != 8 || m != 0 {
		t.Fatalf("秋季切换日的 08:00 被算成了 %02d:%02d（%v）", h, m, p.start)
	}
}

// TestPlanForDayDSTRangeStaysInDay 时间范围模式的结束时刻不得越过当天边界。
//
// 修复前：春季切换日 00:00-23:59 的安排，end = day.Add(23h59m) 落在**次日** 00:59，
// 而 runSchedule 走完节拍后按 startOfDay(now).AddDate(0,0,1) 睡到「次日」——
// 此时 now 已经是次日，于是真正的次日被整个跳过，那一天完全不发包。
func TestPlanForDayDSTRangeStaysInDay(t *testing.T) {
	loc := nyc(t)
	for _, day := range []time.Time{
		time.Date(2026, 3, 8, 0, 0, 0, 0, loc),  // 23 小时的一天
		time.Date(2026, 11, 1, 0, 0, 0, 0, loc), // 25 小时的一天
		time.Date(2026, 6, 15, 0, 0, 0, 0, loc), // 普通的一天，作为对照
	} {
		p, ok := planForDay(config.WOLSchedule{
			Enabled: true, Mode: "range",
			Start: "00:00", End: "23:59", IntervalSec: 60,
		}, day)
		if !ok {
			t.Fatalf("%v: planForDay 应成功", day)
		}
		if _, _, d := p.end.Date(); d != day.Day() {
			t.Fatalf("%v: 结束时刻越到了次日（%v）——次日会被整个跳过", day.Format("2006-01-02"), p.end)
		}
		if h, m, _ := p.end.Clock(); h != 23 || m != 59 {
			t.Fatalf("%v: 结束时刻被算成 %02d:%02d", day.Format("2006-01-02"), h, m)
		}
		if h, m, _ := p.start.Clock(); h != 0 || m != 0 {
			t.Fatalf("%v: 开始时刻被算成 %02d:%02d", day.Format("2006-01-02"), h, m)
		}
	}
}

// TestAtClockPreservesWallClock atClock 在任意时区、任意日期都应给出请求的墙钟时刻。
// 落在夏令时空档里的时刻除外——那种时刻不存在，单独由 TestAtClockSkipsDSTGap 覆盖。
func TestAtClockPreservesWallClock(t *testing.T) {
	zones := []string{"UTC", "Asia/Shanghai", "America/New_York", "Australia/Lord_Howe"}
	for _, z := range zones {
		loc, err := time.LoadLocation(z)
		if err != nil {
			t.Skipf("本机缺少时区数据库: %v", err)
		}
		// Lord_Howe 的夏令时偏移是 30 分钟，能顺带覆盖非整小时偏移。
		for _, d := range []time.Time{
			time.Date(2026, 3, 8, 0, 0, 0, 0, loc),
			time.Date(2026, 4, 5, 0, 0, 0, 0, loc),
			time.Date(2026, 10, 4, 0, 0, 0, 0, loc),
			time.Date(2026, 11, 1, 0, 0, 0, 0, loc),
		} {
			// 只取切换点之外的时刻：0 点、上午晚些、下午、临近午夜。
			for _, hm := range [][2]int{{0, 0}, {8, 0}, {13, 45}, {23, 59}} {
				got := atClock(d, hm[0], hm[1])
				h, m, _ := got.Clock()
				if h != hm[0] || m != hm[1] {
					t.Errorf("%s %v %02d:%02d → %v（墙钟时刻不符）",
						z, d.Format("2006-01-02"), hm[0], hm[1], got)
				}
				if got.Day() != d.Day() {
					t.Errorf("%s %v %02d:%02d → %v（跨到了别的日期）",
						z, d.Format("2006-01-02"), hm[0], hm[1], got)
				}
			}
		}
	}
}

// TestAtClockSkipsDSTGap 请求的时刻落在春季被跳过的那一小时里时，
// 必须顺延到之后第一个真实存在的瞬时，而不是**提前**。
//
// 这是 time.Date 的未定义行为区：对不存在的本地时刻它只保证返回一个合理的瞬时，
// 实测 America/New_York 2026-03-08 02:30 会得到 01:30 EST——比用户设定早一小时触发。
// 早发比晚发更糟：设备可能还没到该被唤醒的时候。
func TestAtClockSkipsDSTGap(t *testing.T) {
	loc := nyc(t)
	day := time.Date(2026, 3, 8, 0, 0, 0, 0, loc)
	// 这一天 02:00-02:59 整段不存在。
	for _, m := range []int{0, 1, 30, 59} {
		got := atClock(day, 2, m)
		// 必须顺延到 03:00（跳变发生的那一刻），绝不能落在 02:00 之前。
		if !got.After(time.Date(2026, 3, 8, 1, 59, 59, 0, loc)) {
			t.Fatalf("02:%02d 被提前到了 %v——早于用户设定的时刻", m, got)
		}
		if h, mm, _ := got.Clock(); h != 3 || mm != 0 {
			t.Fatalf("02:%02d 应顺延到 03:00，实际 %02d:%02d（%v）", m, h, mm, got)
		}
		if got.Day() != 8 {
			t.Fatalf("02:%02d 顺延后跨到了别的日期: %v", m, got)
		}
	}

	// Lord_Howe 的空档只有 30 分钟（02:00 → 02:30），用来验证探测不假定空档是整小时。
	lh, err := time.LoadLocation("Australia/Lord_Howe")
	if err != nil {
		t.Skipf("本机缺少时区数据库: %v", err)
	}
	// 2026-10-04 02:00 → 02:30。
	lhDay := time.Date(2026, 10, 4, 0, 0, 0, 0, lh)
	got := atClock(lhDay, 2, 15)
	if h, m, _ := got.Clock(); h != 2 || m != 30 {
		t.Fatalf("Lord_Howe 02:15 应顺延到 02:30，实际 %02d:%02d（%v）", h, m, got)
	}
}

// TestAtClockAmbiguousFiresOnce 秋季重复的那一小时里的时刻只应产生一个触发时刻。
// 两个瞬时都是真实的该墙钟时刻，取哪个都对，但不能变成两拍。
func TestAtClockAmbiguousFiresOnce(t *testing.T) {
	loc := nyc(t)
	// 2026-11-01 的 01:00-01:59 出现两次。
	day := time.Date(2026, 11, 1, 0, 0, 0, 0, loc)
	got := atClock(day, 1, 30)
	if h, m, _ := got.Clock(); h != 1 || m != 30 {
		t.Fatalf("重复小时内的 01:30 被算成 %02d:%02d（%v）", h, m, got)
	}
	if got.Day() != 1 {
		t.Fatalf("跨到了别的日期: %v", got)
	}
	// 固定时间模式全天只有一拍（start == end），重复小时不会让它变成两拍。
	p, ok := planForDay(config.WOLSchedule{Enabled: true, Mode: "fixed", Time: "01:30", Count: 1}, day)
	if !ok {
		t.Fatal("planForDay 应成功")
	}
	if !p.start.Equal(p.end) {
		t.Fatalf("固定时间模式应只有一拍：start=%v end=%v", p.start, p.end)
	}
}
