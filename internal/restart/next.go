package restart

import (
	"math"
	"time"

	"mantou/internal/config"
)

// Next 返回严格晚于 from 的下一次触发时刻；第二个返回值为 false 表示不会再触发
// （典型情形：按日历模式，挑的日期全都过去了）。
//
// 全部按本机时区计算：用户设的"凌晨 4 点"指的是他自己的钟。
// 只精确到分钟，秒与纳秒一律取 0。
//
// 关闭状态也照算：面板要在开关还没打开时就把"下一次会是什么时候"显示出来，
// 让人先看清再决定要不要开。是否真的执行由调用方按 Enabled 判断。
func Next(p config.RestartPolicy, from time.Time) (time.Time, bool) {
	from = from.In(time.Local)
	switch p.Mode {
	case config.RestartModeDates:
		return nextByDates(p, from)
	case config.RestartModeInterval:
		return nextByInterval(p, from)
	default:
		return nextByWeekday(p, from)
	}
}

// at 返回 day 那一天的 H:M（本机时区）。day 的时刻部分被忽略。
func at(day time.Time, hour, minute int) time.Time {
	y, m, d := day.Date()
	return time.Date(y, m, d, hour, minute, 0, 0, time.Local)
}

// nextByWeekday 每周固定星期几。
func nextByWeekday(p config.RestartPolicy, from time.Time) (time.Time, bool) {
	if len(p.Weekdays) == 0 {
		return time.Time{}, false
	}
	want := make(map[int]bool, len(p.Weekdays))
	for _, d := range p.Weekdays {
		want[d] = true
	}
	// 最多看 8 天：今天可能已经过点了，而"下周同一天"最远也就 7 天后。
	for i := 0; i < 8; i++ {
		day := from.AddDate(0, 0, i)
		if !want[int(day.Weekday())] {
			continue
		}
		if t := at(day, p.Hour, p.Minute); t.After(from) {
			return t, true
		}
	}
	return time.Time{}, false
}

// nextByDates 按日历挑出的具体日期。
func nextByDates(p config.RestartPolicy, from time.Time) (time.Time, bool) {
	var best time.Time
	for _, raw := range p.Dates {
		day, err := config.ParseRestartDate(raw)
		if err != nil {
			continue // 解析不出来的日期在 normalizeRestart 里已被剔除，这里只是兜底
		}
		t := at(day, p.Hour, p.Minute)
		if !t.After(from) {
			continue // 已经过去的日期不再触发
		}
		if best.IsZero() || t.Before(best) {
			best = t
		}
	}
	if best.IsZero() {
		return time.Time{}, false
	}
	return best, true
}

// nextByInterval 自起算日起每隔 N 天。
//
// 锚点是**日期**而不是"上次重启的时刻"：后者会让计划随每次手动重启、每次断电漂移，
// 用户下周就说不出下一次是哪天了。以日期为锚，无论中间发生了什么，
// 触发日始终落在 起算日 + k×N 上。
func nextByInterval(p config.RestartPolicy, from time.Time) (time.Time, bool) {
	every := p.EveryDays
	if every < 1 {
		return time.Time{}, false
	}
	start, err := config.ParseRestartDate(p.StartDate)
	if err != nil {
		// 起算日是必填项（RestartPolicy.Valid 会拦住空值），这里只在配置被手工改坏时兜底：
		// 退化成以"今天"为锚，至少不会一直不触发。
		start = at(from, 0, 0)
	}
	first := at(start, p.Hour, p.Minute)
	if first.After(from) {
		return first, true
	}
	// 用日历天数差而不是时长差：跨夏令时的那一天只有 23 小时，按 24h 整除会算错一天。
	elapsed := daysBetween(first, from)
	k := elapsed / every
	for i := 0; i < 3; i++ { // 至多再往后挪两个周期（跨夏令时的边界情形）
		t := at(first.AddDate(0, 0, k*every), p.Hour, p.Minute)
		if t.After(from) {
			return t, true
		}
		k++
	}
	return time.Time{}, false
}

// daysBetween 返回从 a 到 b 之间跨过的**日历天数**（按本机时区的日界计算）。
//
// 两端都先归到当地零点，所以两者之差一定是"整数天 ± 一次夏令时偏移"——
// 春季那一天只有 23 小时，秋季那一天有 25 小时（个别时区偏移是 30 分钟）。
// 因此必须四舍五入而不能向下取整：`23h / 24 = 0.958`，截断后一整天会凭空消失。
//
// 取整方向错了不会立刻出错——nextByInterval 后面那个"至多再往后挪两个周期"的循环
// 会把算小了的周期数补回来。但那是兜底，不是依据：真正的天数差在这里就该是对的，
// 否则"下一次执行"在夏令时切换的那一周会先算出一个已经过去的时刻。
func daysBetween(a, b time.Time) int {
	ay, am, ad := a.Date()
	by, bm, bd := b.Date()
	da := time.Date(ay, am, ad, 0, 0, 0, 0, time.Local)
	db := time.Date(by, bm, bd, 0, 0, 0, 0, time.Local)
	return int(math.Round(db.Sub(da).Hours() / 24))
}
