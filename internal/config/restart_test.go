package config

import (
	"fmt"
	"testing"
)

// 加载期的规范化不能报错（不能因为一份不完整的设置就拒绝启动），所以它是这份设置
// 唯一的兜底。配置有三条写入路径——面板、整份导入、手改 config.json——只有第一条
// 会经过接口层校验，因此"夹住"必须发生在这里。

func TestNormalizeRestartTruncatesDates(t *testing.T) {
	p := RestartPolicy{Enabled: true, Mode: RestartModeDates}
	// 造一份远超上限的日期列表（含一批已经过去的日期，用来验证截断的方向）。
	for i := 1; i <= 300; i++ {
		p.Dates = append(p.Dates, fmt.Sprintf("2020-%02d-%02d", (i%12)+1, (i%28)+1))
	}
	for i := 1; i <= 20; i++ {
		p.Dates = append(p.Dates, fmt.Sprintf("2099-01-%02d", i))
	}
	normalizeRestart(&p)

	if len(p.Dates) > MaxRestartDates {
		t.Fatalf("日期数量 = %d，应被夹到 %d 以内", len(p.Dates), MaxRestartDates)
	}
	// 先排序再截断：留下的必须是最早的那些。反过来会留下一批已经过去的日期，
	// 等于把这份设置悄悄变成"不会再触发"。
	for i := 1; i < len(p.Dates); i++ {
		if p.Dates[i-1] >= p.Dates[i] {
			t.Fatalf("日期未按时间序排好：%s 在 %s 之前", p.Dates[i-1], p.Dates[i])
		}
	}
}

func TestNormalizeRestartKeepsDatesUnderLimit(t *testing.T) {
	p := RestartPolicy{Enabled: true, Mode: RestartModeDates, Dates: []string{"2026-09-01", "2026-08-30", "2026-08-30"}}
	normalizeRestart(&p)
	// 去重 + 排序，但不截断。
	if len(p.Dates) != 2 || p.Dates[0] != "2026-08-30" || p.Dates[1] != "2026-09-01" {
		t.Fatalf("日期 = %v，期望 [2026-08-30 2026-09-01]", p.Dates)
	}
}

// 顺序上的坑：normalizeRestart 会把 EveryDays 夹成至少 1，一旦它先跑，
// restartUnset 就永远返回 false，升级上来的用户拿不到默认初值
// （打开这一页看到的是「一天没选、00:00」，与全新安装不一致）。
func TestMigrateFillsRestartDefaultsForOldConfig(t *testing.T) {
	c := Default()
	c.Settings.Restart = RestartPolicy{} // 旧配置里没有这一段，反序列化后就是零值
	Migrate(c)

	got := c.Settings.Restart
	want := defaultRestart()
	if got.Enabled || got.Mode != want.Mode || got.Hour != want.Hour || got.EveryDays != want.EveryDays {
		t.Fatalf("旧配置未补上默认初值：%+v", got)
	}
	if len(got.Weekdays) != 1 || got.Weekdays[0] != want.Weekdays[0] {
		t.Fatalf("默认星期 = %v，期望 %v", got.Weekdays, want.Weekdays)
	}
}

// 反过来：用户主动取消了所有星期，程序不该替他填回去。
func TestMigrateKeepsDeliberatelyClearedWeekdays(t *testing.T) {
	c := Default()
	c.Settings.Restart = RestartPolicy{Mode: RestartModeWeekly, Hour: 4, Weekdays: nil}
	Migrate(c)
	if len(c.Settings.Restart.Weekdays) != 0 {
		t.Fatalf("被清空的星期不该被填回：%v", c.Settings.Restart.Weekdays)
	}
}
