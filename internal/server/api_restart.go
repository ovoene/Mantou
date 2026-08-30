package server

import (
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"

	"mantou/internal/config"
	"mantou/internal/restart"
)

// 设置 → 重启：立即重启一次，以及定时重启的读写。
//
// 这里只做「决定要不要重启」与「把设置存下来」。真正怎么重启由 cmd/mantou 注入的
// RestartExec 完成——它复用自更新那条已经验证过的通道（优雅关闭监听 → 落盘运行态 →
// 关闭各模块 → 用同一个二进制接管进程），所以重启后端口不会残留占用、运行态不会倒退。

// restartSettings 是设置页「重启」页签需要的全部字段。
//
// nextRunAt 由后端算：算法（周 / 日历 / 间隔三种模式，本机时区，只到分钟）只写一份在
// internal/restart 里，前端再实现一遍必然会在某个边界上与后端不一致，
// 而"界面显示的下一次"和"实际执行的下一次"不一样是最难被发现的一类问题。
func restartSettings(p config.RestartPolicy) gin.H {
	weekdays := p.Weekdays
	if weekdays == nil {
		weekdays = []int{}
	}
	dates := p.Dates
	if dates == nil {
		dates = []string{}
	}
	out := gin.H{
		"enabled":   p.Enabled,
		"mode":      p.Mode,
		"weekdays":  weekdays,
		"dates":     dates,
		"everyDays": p.EveryDays,
		"startDate": p.StartDate,
		"hour":      p.Hour,
		"minute":    p.Minute,
		"lastRunAt": p.LastRunAt,
		"nextRunAt": int64(0),
	}
	// 关着也算下一次：让人在打开开关之前就能确认"我设的是不是我想的那个时间"。
	if next, ok := restart.Next(p, time.Now()); ok {
		out["nextRunAt"] = next.Unix()
	}
	return out
}

// restartReq 是设置接口里 restart 这一段。整段提交（与 log / notify 同样的做法）：
// 三种模式各有自己的字段，逐字段可选会让"切到按星期后日历里那些日期还算不算"变得无法判断。
type restartReq struct {
	Enabled   bool     `json:"enabled"`
	Mode      string   `json:"mode"`
	Weekdays  []int    `json:"weekdays"`
	Dates     []string `json:"dates"`
	EveryDays int      `json:"everyDays"`
	StartDate string   `json:"startDate"`
	Hour      int      `json:"hour"`
	Minute    int      `json:"minute"`
}

// checkLimits 校验那些「规范化会替你夹住、但用户应当被告知」的量。
//
// 规范化在加载期必须能夹住超限的日期列表（配置有三条写入路径：面板、整份导入、
// 手改 config.json，加载期又不能因为一份不完整的设置就拒绝启动）。可它一夹住，
// RestartPolicy.Valid 就再也看不到超限——界面上选了 80 个日期会被静默留下 60 个。
// 所以这一条要在规范化之前拦，让用户当场知道多选了。
func (r restartReq) checkLimits() error {
	if len(r.Dates) > config.MaxRestartDates {
		return fmt.Errorf("按日历重启最多选 %d 个日期", config.MaxRestartDates)
	}
	return nil
}

// policy 把请求转成配置里的形态，并执行与加载期完全相同的规范化。
// LastRunAt 不从请求里取——它是程序自己写的执行记录，允许外部设置就等于允许
// 把它改到未来，从而让定时重启永远不触发（或反过来，改到过去造成重启循环）。
func (r restartReq) policy() config.RestartPolicy {
	p := config.RestartPolicy{
		Enabled:   r.Enabled,
		Mode:      r.Mode,
		Weekdays:  r.Weekdays,
		Dates:     r.Dates,
		EveryDays: r.EveryDays,
		StartDate: r.StartDate,
		Hour:      r.Hour,
		Minute:    r.Minute,
	}
	config.NormalizeRestart(&p)
	return p
}

// handleRestartNow 立即重启整个程序。
//
// 与「面板监听变更后的进程内重启」不是一回事：那一种只重建 HTTP 服务器，
// 各模块与进程本身照旧；这里是换掉整个进程，用于把内存彻底清一遍。
func (s *Server) handleRestartNow(c *gin.Context) {
	if s.deps.RestartExec == nil {
		// 只有 cmd/mantou 才注入这个回调。测试用的 server 实例、或将来别的宿主方式下没有它，
		// 此时明确报"不支持"，而不是回一个 ok 让用户以为重启了。
		respondError(c, http.StatusServiceUnavailable, "当前运行方式不支持重启")
		return
	}
	exe, err := os.Executable()
	if err != nil {
		respondError(c, http.StatusInternalServerError, "无法定位程序自身路径，重启已取消")
		return
	}
	// 在回 ok 之前先确认这个二进制真的还拉得起来（被删掉、改名、丢了执行位都在此拦下）。
	//
	// 换进程的失败点在最后一步，那时监听与各模块已经关掉、无法回退，进程只能退出——
	// 用户点一下"立即重启"却失去整个程序。所以这一眼必须在这里看：拦得住就是一条
	// 500 加一个仍然活着的面板；拦不住才轮到那条没有退路的路径。
	if err := restart.CheckExecutable(exe); err != nil {
		s.deps.Log.Error("立即重启已取消：程序文件不可执行", "path", exe, "error", err.Error())
		respondError(c, http.StatusInternalServerError, "程序文件不可用，重启已取消："+err.Error())
		return
	}

	// 同一时刻只允许一次：连点两下的第二下应当得到明确回复，
	// 而不是撞到底层"已有待执行的重启请求"那句内部错误上。
	s.restartMu.Lock()
	if s.restarting {
		s.restartMu.Unlock()
		respondError(c, http.StatusConflict, "重启已在进行中")
		return
	}
	s.restarting = true
	s.restartMu.Unlock()

	respondOK(c, gin.H{"ok": true, "restarting": true})

	// 延时是为了让上面这个响应先发出去——进程一换，连接就断了，
	// 没发出去的响应会让界面停在"请求失败"上，用户无从判断到底重启了没有。
	go func() {
		time.Sleep(1200 * time.Millisecond)
		s.deps.Log.Info("收到手动重启请求，进程即将重启")
		if err := s.deps.RestartExec(exe); err != nil {
			// 这里的失败都发生在"还没开始拆"之前（RestartExec 会先自检再入队），
			// 所以进程确实还是完好的，把开关放回去让用户能再点一次。
			// 入队之后的失败不会回到这里——那时已经没有回退路径，见 cmd/mantou。
			s.deps.Log.Error("手动重启失败，进程继续运行", "error", err.Error())
			s.restartMu.Lock()
			s.restarting = false
			s.restartMu.Unlock()
		}
	}()
}
