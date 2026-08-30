package config

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// 本文件是「定时重启」这份设置的数据层规则：模式取值、边界、以及一份设置是否可用。
//
// 规则只写一遍、两处共用：加载 / 导入时由 normalizeRestart 兜底（手改过的 config.json、
// 来自别处的备份都会经过它），面板保存时由接口先 NormalizeRestart 再 Valid——
// 于是"界面上能存下的"与"程序实际会执行的"永远是同一套判断。
//
// 时刻按**本机时区**理解。跨时区的重启窗口没有意义：用户看着自己的钟设"凌晨 4 点"，
// 就该在自己的凌晨 4 点重启。

// 定时重启的三种模式。取值同时是接口契约（前端按这些字符串提交）。
const (
	RestartModeWeekly   = "weekly"   // 每周固定星期几
	RestartModeDates    = "dates"    // 按日历挑具体日期
	RestartModeInterval = "interval" // 自起算日起每隔 N 天
)

// restartDateLayout 日期字段（Dates / StartDate）的格式。
const restartDateLayout = "2006-01-02"

// MaxRestartDates「按日历」一次最多能挑多少个日期。
//
// 有上限不是为了省存储，而是因为这些日期要在每次调度检查时被逐个解析比较；
// 60 个已经远超"手工在日历上点几天"的实际用量，再多基本意味着填错了模式
// （想表达"每隔几天"应该用 interval，不该在日历上点两百天）。
const MaxRestartDates = 60

// MaxRestartEveryDays「每隔 N 天」的上限。365 天以上的间隔用日历表达更清楚。
const MaxRestartEveryDays = 365

// restartUnset 判断这一段设置是否**从未存在过**（旧配置里没有 settings.restart 时的零值）。
//
// 区分"从未配置"与"配过但清空了"是必要的：前者要补上一组完整初值，否则升级上来的用户
// 打开这一页看到的是「每周 / 00:00 / 一天没选」，与全新安装（每周日 04:00）不一致；
// 后者必须原样保留——用户主动取消了所有星期，程序不该替他填回去。
func restartUnset(p RestartPolicy) bool {
	return !p.Enabled && p.Mode == "" && len(p.Weekdays) == 0 && len(p.Dates) == 0 &&
		p.EveryDays == 0 && p.StartDate == "" && p.Hour == 0 && p.Minute == 0 && p.LastRunAt == 0
}

// normalizeRestart 就地规范化一份定时重启设置：夹住越界数值、统一模式取值、
// 整理星期与日期列表。**不判断这份设置是否可用**（那是 Valid 的事），
// 因为加载期不能因为一份不完整的设置就拒绝启动。
func normalizeRestart(p *RestartPolicy) {
	switch p.Mode {
	case RestartModeWeekly, RestartModeDates, RestartModeInterval:
	default:
		// 空值（旧配置里没有这一段）与认不出的值一律落到每周：它是三种里最容易看懂、
		// 也最不容易意外触发的一种（还要选了星期才会真的跑）。
		p.Mode = RestartModeWeekly
	}
	p.Hour = clampInt(p.Hour, 0, 23)
	p.Minute = clampInt(p.Minute, 0, 59)
	p.EveryDays = clampInt(p.EveryDays, 1, MaxRestartEveryDays)

	// 星期：去重、排序、丢掉越界值。排序是为了让界面与日志的顺序稳定。
	if len(p.Weekdays) > 0 {
		seen := make(map[int]bool, len(p.Weekdays))
		out := make([]int, 0, len(p.Weekdays))
		for _, d := range p.Weekdays {
			if d < 0 || d > 6 || seen[d] {
				continue
			}
			seen[d] = true
			out = append(out, d)
		}
		sort.Ints(out)
		p.Weekdays = out
	}

	// 日期：去重、排序、丢掉解析不出来的。解析不出来的日期在调度里本来就永远不会命中，
	// 留着只会让人以为它有效。**过去的日期不删**——那是用户在日历上亲手点的，
	// 悄悄抹掉比留着一个不会再触发的日期更让人困惑。
	//
	// 长度也要在这里截断，不能只靠 Valid：配置有三条写入路径（面板、整份导入、手改
	// config.json），Valid 只拦得住第一条。一份带着上万个日期且 enabled 的配置能被正常加载，
	// 之后调度器每 30 秒把这些日期逐个解析一遍——不会崩，只是白烧 CPU 且没有任何日志会说。
	// 加载期不能报错（不能因为一份不完整的设置就拒绝启动），但可以夹住。
	if len(p.Dates) > 0 {
		seen := make(map[string]bool, len(p.Dates))
		out := make([]string, 0, len(p.Dates))
		for _, raw := range p.Dates {
			d := strings.TrimSpace(raw)
			if d == "" || seen[d] {
				continue
			}
			if _, err := time.ParseInLocation(restartDateLayout, d, time.Local); err != nil {
				continue
			}
			seen[d] = true
			out = append(out, d)
		}
		sort.Strings(out) // YYYY-MM-DD 的字典序就是时间序
		if len(out) > MaxRestartDates {
			// 先排序再截断：留下的是最早的那些日期。反过来会留下一批已经过去的日期，
			// 等于把这份设置直接变成"不会再触发"。
			out = out[:MaxRestartDates]
		}
		p.Dates = out
	}
	p.StartDate = strings.TrimSpace(p.StartDate)
	if p.StartDate != "" {
		if _, err := time.ParseInLocation(restartDateLayout, p.StartDate, time.Local); err != nil {
			p.StartDate = ""
		}
	}
	if p.LastRunAt < 0 {
		p.LastRunAt = 0
	}
}

// Valid 判断这份设置是否"能真的跑起来"。关闭状态一律放过——关着的设置填成什么样都不影响行为，
// 拦下来只会让用户没法先关掉再慢慢改。
func (p RestartPolicy) Valid() error {
	if !p.Enabled {
		return nil
	}
	if p.Hour < 0 || p.Hour > 23 || p.Minute < 0 || p.Minute > 59 {
		return fmt.Errorf("重启时刻无效")
	}
	switch p.Mode {
	case RestartModeWeekly:
		if len(p.Weekdays) == 0 {
			return fmt.Errorf("按星期重启至少要选一天")
		}
		for _, d := range p.Weekdays {
			if d < 0 || d > 6 {
				return fmt.Errorf("星期取值无效")
			}
		}
	case RestartModeDates:
		if len(p.Dates) == 0 {
			return fmt.Errorf("按日历重启至少要选一个日期")
		}
		if len(p.Dates) > MaxRestartDates {
			return fmt.Errorf("按日历重启最多选 %d 个日期", MaxRestartDates)
		}
		for _, d := range p.Dates {
			if _, err := time.ParseInLocation(restartDateLayout, d, time.Local); err != nil {
				return fmt.Errorf("日期 %s 无效", d)
			}
		}
	case RestartModeInterval:
		if p.EveryDays < 1 || p.EveryDays > MaxRestartEveryDays {
			return fmt.Errorf("间隔天数需在 1-%d 之间", MaxRestartEveryDays)
		}
		// 起算日是必填的：没有它，"每隔 N 天"就只能拿"程序当前是哪一天"当锚点，
		// 于是每次重启锚点都可能变——用户看到的会是一个自己会漂移的计划。
		if p.StartDate == "" {
			return fmt.Errorf("每隔 N 天重启需要填起算日期")
		}
		if _, err := time.ParseInLocation(restartDateLayout, p.StartDate, time.Local); err != nil {
			return fmt.Errorf("起算日期无效")
		}
	default:
		return fmt.Errorf("重启方式无效")
	}
	return nil
}

// NormalizeRestart 对**外部提交**的定时重启设置执行与加载期完全相同的规范化。
// 面板保存前调用它，使"存进去的"与"加载后跑的"是同一份值——否则界面上会出现
// 保存成功、刷新后数字却变了的情况。
func NormalizeRestart(p *RestartPolicy) {
	if p == nil {
		return
	}
	normalizeRestart(p)
}

// ParseRestartDate 按本机时区把 YYYY-MM-DD 解析成当天的零点。
// 供计算下一次触发时刻使用（见 internal/restart）。
func ParseRestartDate(s string) (time.Time, error) {
	return time.ParseInLocation(restartDateLayout, strings.TrimSpace(s), time.Local)
}

// FormatRestartDate 把时刻格式化成 YYYY-MM-DD（本机时区）。
func FormatRestartDate(t time.Time) string {
	return t.Format(restartDateLayout)
}
