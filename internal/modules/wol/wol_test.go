package wol

import (
	"testing"
	"time"

	"mantou/internal/config"
)

func TestParseMAC(t *testing.T) {
	// 全部应解析为 aa:bb:cc:dd:ee:ff。除常规写法外，重点覆盖用户实际会输入 / 粘贴进来的形式：
	// 中文输入法的全角冒号与全角连字符、复制粘贴带入的不换行空格与零宽字符 / BOM、
	// Unicode 连字符，以及 Cisco 风格的点分写法。
	ok := []string{
		"aa:bb:cc:dd:ee:ff",
		"AA-BB-CC-DD-EE-FF",
		"aabbccddeeff",
		" aa bb cc dd ee ff ",
		"AA：BB：CC：DD：EE：FF",                          // 全角冒号（中文标点状态）
		"AA－BB－CC－DD－EE－FF",                          // 全角连字符
		"AA–BB–CC–DD–EE–FF",                          // en dash
		"aabb.ccdd.eeff",                             // Cisco 点分
		"\ufeffaa:bb:cc:dd:ee:ff",                    // 行首 BOM
		"aa:bb:cc\u200b:dd:ee:ff",                    // 零宽空格
		"aa\u00a0bb\u00a0cc\u00a0dd\u00a0ee\u00a0ff", // 不换行空格
		"aa\u3000bb\u3000cc\u3000dd\u3000ee\u3000ff", // 全角空格
	}
	for _, in := range ok {
		hw, err := parseMAC(in)
		if err != nil {
			t.Fatalf("parseMAC(%q) 失败: %v", in, err)
		}
		if len(hw) != 6 || hw[0] != 0xaa || hw[5] != 0xff {
			t.Fatalf("parseMAC(%q) 结果异常: %x", in, hw)
		}
	}
	for _, bad := range []string{"", "aa:bb:cc", "zz:bb:cc:dd:ee:ff", "aabbccddeeffaa", "aa:bb:cc:dd:ee:f", "网卡"} {
		if _, err := parseMAC(bad); err == nil {
			t.Fatalf("parseMAC(%q) 本应报错", bad)
		}
	}
}

func TestNormalizeMAC(t *testing.T) {
	for _, in := range []string{
		"aa:bb:cc:dd:ee:ff",
		"AA-BB-CC-DD-EE-FF",
		"aabbccddeeff",
		"AA：BB：CC：DD：EE：FF",
	} {
		if got := NormalizeMAC(in); got != "AA:BB:CC:DD:EE:FF" {
			t.Fatalf("NormalizeMAC(%q) = %q，应为 AA:BB:CC:DD:EE:FF", in, got)
		}
	}
	// 解析不通过时原样返回（仅去首尾空白），报错留给校验层，不静默丢弃用户输入。
	if got := NormalizeMAC("  aa:bb:cc  "); got != "aa:bb:cc" {
		t.Fatalf("非法 MAC 应原样返回，实际 %q", got)
	}
}

func TestValidClockHM(t *testing.T) {
	for _, s := range []string{"00:00", "8:00", "08:05", "23:59"} {
		if !ValidClockHM(s) {
			t.Fatalf("ValidClockHM(%q) 应为 true", s)
		}
	}
	for _, s := range []string{"", "24:00", "08:60", "8", "08:00:00", "ab:cd"} {
		if ValidClockHM(s) {
			t.Fatalf("ValidClockHM(%q) 应为 false", s)
		}
	}
}

func TestClampCount(t *testing.T) {
	if got := clampCount(0); got != 1 {
		t.Fatalf("clampCount(0) = %d，应为 1", got)
	}
	if got := clampCount(-5); got != 1 {
		t.Fatalf("clampCount(-5) = %d，应为 1", got)
	}
	if got := clampCount(1_000_000); got != config.MaxWOLWakeCount {
		t.Fatalf("clampCount 上限应为 %d，实际 %d", config.MaxWOLWakeCount, got)
	}
	if got := clampCount(7); got != 7 {
		t.Fatalf("clampCount(7) = %d，应原样返回", got)
	}
}

// TestClampInterval 验证间隔恒为正：interval 为 0 会让统一的节拍循环原地死转。
func TestClampInterval(t *testing.T) {
	if got := clampInterval(0); got != time.Second {
		t.Fatalf("clampInterval(0) = %s，应为 1s", got)
	}
	if got := clampInterval(-3); got != time.Second {
		t.Fatalf("clampInterval(-3) = %s，应为 1s", got)
	}
	if got := clampInterval(5); got != 5*time.Second {
		t.Fatalf("clampInterval(5) = %s，应为 5s", got)
	}
	want := time.Duration(config.MaxWOLIntervalSec) * time.Second
	if got := clampInterval(config.MaxWOLIntervalSec * 10); got != want {
		t.Fatalf("clampInterval 上限应为 %s，实际 %s", want, got)
	}
}

func TestBuildMagicPacket(t *testing.T) {
	hw, err := parseMAC("aa:bb:cc:dd:ee:ff")
	if err != nil {
		t.Fatal(err)
	}
	p := buildMagicPacket(hw)
	if len(p) != 102 {
		t.Fatalf("魔术包长度应为 102，实际 %d", len(p))
	}
	for i := 0; i < 6; i++ {
		if p[i] != 0xFF {
			t.Fatalf("魔术包前 6 字节应为 0xFF，第 %d 字节为 %#x", i, p[i])
		}
	}
	for i := 0; i < 16; i++ {
		off := 6 + i*6
		for j := 0; j < 6; j++ {
			if p[off+j] != hw[j] {
				t.Fatalf("第 %d 次 MAC 重复第 %d 字节不匹配", i, j)
			}
		}
	}
}

// TestPlanForDayFixed 验证「固定时间」：全天只有一拍（start == end），
// 一拍内连发 Count 个包，Count 被夹到 [1, MaxWOLWakeCount]，且不使用发送间隔。
func TestPlanForDayFixed(t *testing.T) {
	day := time.Date(2026, 1, 2, 0, 0, 0, 0, time.Local)

	p, ok := planForDay(config.WOLSchedule{Mode: "fixed", Time: "08:00", Count: 5, IntervalSec: 999}, day)
	if !ok {
		t.Fatal("合法的固定时间应返回 ok")
	}
	if !p.start.Equal(day.Add(8 * time.Hour)) {
		t.Fatalf("start 应为 08:00，实际 %s", p.start)
	}
	if !p.end.Equal(p.start) {
		t.Fatalf("固定时间应只有一拍（start == end），实际 end = %s", p.end)
	}
	if p.burst != 5 {
		t.Fatalf("burst 应等于 Count(5)，实际 %d", p.burst)
	}
	if p.interval <= 0 {
		t.Fatalf("interval 必须为正（否则节拍循环死转），实际 %s", p.interval)
	}
	if ticks := countTicks(p); ticks != 1 {
		t.Fatalf("固定时间当天应只触发 1 拍，实际 %d", ticks)
	}

	// Count 越界被夹住：既不会一秒内打出上限之外的包，也不会因 0 次而等于没开。
	if p, _ := planForDay(config.WOLSchedule{Mode: "fixed", Time: "08:00", Count: 1_000_000}, day); p.burst != config.MaxWOLWakeCount {
		t.Fatalf("burst 应被夹到 %d，实际 %d", config.MaxWOLWakeCount, p.burst)
	}
	if p, _ := planForDay(config.WOLSchedule{Mode: "fixed", Time: "07:30", Count: 0}, day); p.burst != 1 {
		t.Fatalf("Count=0 应按 1 次处理，实际 %d", p.burst)
	}

	// 空 Mode 按固定时间处理（旧配置与手写 JSON 都可能不带该字段）。
	if p, ok := planForDay(config.WOLSchedule{Time: "09:15", Count: 2}, day); !ok || !p.start.Equal(day.Add(9*time.Hour+15*time.Minute)) || p.burst != 2 {
		t.Fatalf("空 Mode 应按固定时间处理，实际 ok=%v start=%s burst=%d", ok, p.start, p.burst)
	}

	// 非法时间：当天不安排发送（调度器随即睡到次日）。
	if _, ok := planForDay(config.WOLSchedule{Mode: "fixed", Time: "25:00", Count: 1}, day); ok {
		t.Fatal("非法时间应返回 ok=false")
	}
}

// TestPlanForDayRange 验证「时间范围」：起止之间按发送间隔逐拍发送，每拍只发 1 个包，
// 发包次数（Count）完全不参与计算。
func TestPlanForDayRange(t *testing.T) {
	day := time.Date(2026, 1, 2, 0, 0, 0, 0, time.Local)

	p, ok := planForDay(config.WOLSchedule{Mode: "range", Start: "08:00", End: "18:00", IntervalSec: 3600, Count: 1_000_000}, day)
	if !ok {
		t.Fatal("合法的时间范围应返回 ok")
	}
	if !p.start.Equal(day.Add(8*time.Hour)) || !p.end.Equal(day.Add(18*time.Hour)) {
		t.Fatalf("起止应为 08:00 / 18:00，实际 %s / %s", p.start, p.end)
	}
	if p.interval != time.Hour {
		t.Fatalf("interval 应为 1h，实际 %s", p.interval)
	}
	if p.burst != 1 {
		t.Fatalf("时间范围模式每拍只发 1 个包，实际 burst=%d，Count 不应参与计算", p.burst)
	}
	// 08:00 到 18:00 每小时一拍，含两端共 11 拍。
	if ticks := countTicks(p); ticks != 11 {
		t.Fatalf("应触发 11 拍，实际 %d", ticks)
	}

	// 间隔为 0 / 负数时兜底为 1 秒，避免节拍循环死转。
	if p, _ := planForDay(config.WOLSchedule{Mode: "range", Start: "08:00", End: "18:00", IntervalSec: 0}, day); p.interval != time.Second {
		t.Fatalf("间隔为 0 应兜底为 1s，实际 %s", p.interval)
	}

	// 结束不晚于开始：退化为只在开始时刻发一次。
	single, ok := planForDay(config.WOLSchedule{Mode: "range", Start: "10:00", End: "09:00", IntervalSec: 60}, day)
	if !ok {
		t.Fatal("起止合法（仅顺序颠倒）应返回 ok")
	}
	if !single.end.Equal(single.start) {
		t.Fatalf("End 早于 Start 时应退化为 start == end，实际 %s / %s", single.start, single.end)
	}
	if ticks := countTicks(single); ticks != 1 {
		t.Fatalf("End 早于 Start 时应只有 1 拍，实际 %d", ticks)
	}

	// 非法时间字段：当天不安排发送。
	if _, ok := planForDay(config.WOLSchedule{Mode: "range", Start: "08:00", End: "bad", IntervalSec: 60}, day); ok {
		t.Fatal("非法结束时间应返回 ok=false")
	}
	if _, ok := planForDay(config.WOLSchedule{Mode: "range", Start: "", End: "18:00", IntervalSec: 60}, day); ok {
		t.Fatal("空开始时间应返回 ok=false")
	}
}

// TestFirstTickAfter 验证跳过已过时刻用的是整除而非逐拍推进
// （间隔 1 秒、跨度 24 小时若逐拍推进要空转 8 万多次）。
func TestFirstTickAfter(t *testing.T) {
	day := time.Date(2026, 1, 2, 0, 0, 0, 0, time.Local)
	p := wakePlan{start: day.Add(8 * time.Hour), end: day.Add(18 * time.Hour), interval: 5 * time.Second, burst: 1}

	cases := []struct {
		name string
		now  time.Time
		want time.Time
	}{
		{"早于开始", p.start.Add(-time.Hour), p.start},
		{"正好开始", p.start, p.start},
		{"落在两拍之间", p.start.Add(time.Second), p.start.Add(5 * time.Second)},
		{"正好命中某拍", p.start.Add(10 * time.Second), p.start.Add(10 * time.Second)},
		{"命中某拍后 1ns", p.start.Add(10*time.Second + time.Nanosecond), p.start.Add(15 * time.Second)},
		{"已过大半天", p.start.Add(9*time.Hour + 3*time.Second), p.start.Add(9*time.Hour + 5*time.Second)},
	}
	for _, c := range cases {
		if got := firstTickAfter(p, c.now); !got.Equal(c.want) {
			t.Fatalf("%s: firstTickAfter = %s，应为 %s", c.name, got, c.want)
		}
	}

	// 间隔 1 秒跨全天：整除应一步到位。
	dense := wakePlan{start: day, end: day.Add(24 * time.Hour), interval: time.Second, burst: 1}
	want := day.Add(23*time.Hour + 59*time.Minute + 59*time.Second)
	if got := firstTickAfter(dense, want.Add(-500*time.Millisecond)); !got.Equal(want) {
		t.Fatalf("密集节拍下 firstTickAfter = %s，应为 %s", got, want)
	}
}

func TestDateInSchedule(t *testing.T) {
	day := time.Date(2026, 8, 20, 0, 0, 0, 0, time.Local)
	if !dateInSchedule(config.WOLSchedule{}, day) {
		t.Fatal("日历关闭时应每天执行")
	}
	if dateInSchedule(config.WOLSchedule{CalendarEnabled: true}, day) {
		t.Fatal("日历开启但未选择日期时不应执行")
	}
	if !dateInSchedule(config.WOLSchedule{CalendarEnabled: true, StartDate: "2026-08-20", EndDate: "2026-08-20"}, day) {
		t.Fatal("单日范围当天应执行")
	}
	if !dateInSchedule(config.WOLSchedule{CalendarEnabled: true, StartDate: "2026-08-19", EndDate: "2026-08-21"}, day) {
		t.Fatal("日期范围内应执行")
	}
	if dateInSchedule(config.WOLSchedule{CalendarEnabled: true, StartDate: "2026-08-21", EndDate: "2026-08-22"}, day) {
		t.Fatal("日期范围外不应执行")
	}
}

// countTicks 数出一份发包安排在「从头开始执行」时会触发多少拍，
// 与 runPlanDay 的循环条件保持一致（这里不实际等待，只走时间轴）。
func countTicks(p wakePlan) int {
	n := 0
	for at := p.start; !at.After(p.end); at = at.Add(p.interval) {
		n++
		if n > 100_000 { // 防御：interval 若为 0 会死循环，测试里直接暴露
			return n
		}
	}
	return n
}
