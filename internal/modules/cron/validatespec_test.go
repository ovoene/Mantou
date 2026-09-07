package cron

import (
	"testing"

	"mantou/internal/config"
)

// 本文件盯住 ValidateSpec 与调度器的口径一致（审计 L-05）。
//
// 保存那一路拿 ValidateSpec 决定收不收（见 server.validateCronTask），运行期真正排班的是
// Reload 里的 c.AddFunc。这两者判断不一致就会各出一种坏结果：校验松了，还是"保存成功、
// 永不执行"；校验紧了，明明能跑的表达式被 400 挡在外面。所以下面不直接断言 ValidateSpec
// 的返回值，而是把它和**真的排进去了没有**逐条对照。

// specCases 覆盖真实会出现的写法：结构化调度生成的那几种、用户手写的描述符，
// 以及「自定义」那一档最常见的几种写错法。
var specCases = []struct {
	spec  string
	valid bool
}{
	{"0 3 * * *", true},       // 每天 03:00（前端 daily 生成的形状）
	{"* * * * *", true},       // minutely
	{"*/5 * * * *", true},     // interval 按分钟
	{"0 */2 * * *", true},     // interval 按小时
	{"0 3 1 * *", true},       // monthly
	{"0 3 * * 1,5", true},     // weekly 多选
	{"@every 1h", true},       // 描述符：robfig 的标准解析器收它，所以我们也得收
	{"@daily", true},          //
	{" 0 3 * * * ", true},     // 首尾空格无害（robfig 用 strings.Fields 切）
	{"", false},               // 空串：「自定义」那一档没填就是这个
	{"   ", false},            // 纯空白
	{"not a cron", false},     //
	{"*/5 * * *", false},      // 少一段
	{"0 3 * * * *", false},    // 多一段（标准解析器不带秒）
	{"99 99 * * *", false},    // 段数对但越界
	{"@bogus", false},         // 不存在的描述符
	{"0 3 * * MONDAY", false}, // 星期只认三字母缩写
	{"0 3 * * */0", false},    // 步进为 0
}

// TestValidateSpecMatchesScheduler ValidateSpec 放行的，Reload 必须真的排进去；它拒的，
// Reload 也一定排不进去。
//
// 这条断言防的是「解析器被换掉」：给 robfig.New() 加个 WithSeconds()、或换一套自己写的
// 字段检查，两边就会开始各说各话，而症状（保存成功却不执行）与本审计项一模一样。
func TestValidateSpecMatchesScheduler(t *testing.T) {
	for _, c := range specCases {
		t.Run(c.spec, func(t *testing.T) {
			if got := ValidateSpec(c.spec) == nil; got != c.valid {
				t.Fatalf("ValidateSpec(%q) 通过=%v，期望 %v", c.spec, got, c.valid)
			}
			// 同一条表达式交给真正的排班路径：Active 计的就是 AddFunc 成功的条数。
			m := newTestModule(t)
			task := testTask("t1")
			task.Cron = c.spec
			if err := m.Reload(&config.Config{CronTasks: []config.CronTask{task}}); err != nil {
				t.Fatal(err)
			}
			want := 0
			if c.valid {
				want = 1
			}
			if got := m.Status().Active; got != want {
				t.Fatalf("排进调度器的任务数 = %d，期望 %d（校验说 valid=%v）", got, want, c.valid)
			}
		})
	}
}
