package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"mantou/internal/config"
	"mantou/internal/modules/notify"
	"mantou/internal/modules/wol"
	"mantou/internal/netguard"
	"mantou/internal/strutil"
)

// actionContext 依据任务超时秒数构造带取消的 context；timeoutSec<=0 时使用给定的默认上限，
// 避免长耗时动作无限阻塞（robfig 为每个任务单独起 goroutine，仍应有兜底上限）。
func actionContext(timeoutSec int, fallback time.Duration) (context.Context, context.CancelFunc) {
	d := fallback
	if timeoutSec > 0 {
		d = time.Duration(timeoutSec) * time.Second
	}
	return context.WithTimeout(context.Background(), d)
}

// wakeByID 依据设备 ID 查找并发送网络唤醒。
// 设备级开关（Enabled）关闭时拒绝执行：计划任务属于自动化路径，与定时唤醒一样受该开关约束，
// 否则「已禁用的设备仍被 cron 唤醒」会造成开关失灵的割裂感。面板上的手动「唤醒」按钮是用户
// 显式动作，不受此限制。
//
// ctx 用于给「发包」这一步设上限。wol.Wake 本身是同步的：它按网卡逐个解析广播地址并写 UDP，
// 若用户把广播地址填成了域名，DNS 解析可能长时间不返回。此处不把 ctx 往下透传，而是
// 让发送在后台跑完、超时即返回错误——魔术包是一次无连接的 UDP 写入，放任它自己结束
// 不会留下任何需要回收的状态，而调用方（计划任务）拿回控制权才是要紧的。
func wakeByID(ctx context.Context, cfgMgr *config.Manager, deviceID string) (string, error) {
	cfg := cfgMgr.Snapshot()
	for _, d := range cfg.WOLDevices {
		if d.ID == deviceID {
			if !d.Enabled {
				return "", fmt.Errorf("设备已禁用，跳过唤醒: %s", d.Name)
			}
			done := make(chan error, 1)
			go func() { done <- wol.WakeDevice(d) }()
			select {
			case err := <-done:
				if err != nil {
					return "", err
				}
				return "已唤醒 " + d.Name, nil
			case <-ctx.Done():
				return "", fmt.Errorf("发送网络唤醒超时已终止: %s", d.Name)
			}
		}
	}
	return "", fmt.Errorf("找不到设备: %s", deviceID)
}

// runHTTPAction 发起一次 HTTP 请求，超时后随 context 取消而被终止。
// 支持 params: url（必填）、method（默认 GET）。timeoutSec<=0 时使用 30 秒兜底。
// blockPrivate 为真时请求经内网防护客户端发起：目标解析到内网/保留地址将被拒绝。
func runHTTPAction(action config.CronAction, timeoutSec int, blockPrivate bool) (string, error) {
	url := strings.TrimSpace(action.Params["url"])
	if url == "" {
		return "", fmt.Errorf("URL 为空")
	}
	method := strings.ToUpper(strings.TrimSpace(action.Params["method"]))
	if method == "" {
		method = http.MethodGet
	}
	ctx, cancel := actionContext(timeoutSec, 30*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, method, url, nil)
	if err != nil {
		return "", err
	}
	// 整体超时交由上面的 context 统一控制，故客户端级超时传 0，避免重复设置。
	resp, err := netguard.HTTPClient(blockPrivate, 0).Do(req)
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return "", fmt.Errorf("HTTP 请求超时已终止")
		}
		return "", err
	}
	defer resp.Body.Close()
	// 读一小段响应体，而不是直接丢弃：机器人类接口（钉钉、企业微信及大量国产 API）
	// 业务失败时照样回 HTTP 200，真正的错误藏在响应体的 errcode/errmsg 里。
	// 全丢掉会让一次「消息没发出去」的执行在任务记录里显示成功。
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxActionRespBytes))
	drainForReuse(resp.Body, actionDrainLimit)

	if resp.StatusCode >= 400 {
		return "", fmt.Errorf("HTTP %d：%s", resp.StatusCode, strutil.Truncate(strings.TrimSpace(string(body)), 200, "…"))
	}
	if code, msg := apiErrCode(body); code != 0 {
		return "", fmt.Errorf("HTTP %d 但接口返回错误 errcode=%d：%s", resp.StatusCode, code, msg)
	}
	return fmt.Sprintf("HTTP %d", resp.StatusCode), nil
}

// maxActionRespBytes 读取响应体的上限。只为了看 errcode，不需要多。
const maxActionRespBytes = 4 << 10

// actionDrainLimit 排空剩余响应体的上限（在 maxActionRespBytes 之外另计，
// 因此单次请求最多下行 36 KiB）。
//
// 排空本身是有意义的：Go 的 Transport 要求响应体读到 EOF 才会把连接归还池里复用。
// 但排空干的事就是下载数据——不设上限就是"对端给多少就下多少"，唯一的约束是 context
// 超时与链路带宽，最坏情况是以线速下载整个超时时长。一个填错的 URL（比如填成了某个大
// 文件的直链）、或者被中间设备插了大页面的响应，会让这条任务每次触发都吃掉几十上百 MB
// 下行。内存不会爆（io.Copy 用 32 KiB 滚动缓冲，读完就丢），爆的是流量与时间——
// 在按量计费的线路上就是账单。
//
// 为了省一次 TCP + TLS 握手去下载几百 MB，方向是反的：超过这个数就放弃复用。
const actionDrainLimit = 32 << 10

// drainForReuse 有上限地读完剩余响应体，让这条连接能被池复用；超过上限则放弃复用。
// 返回 true 表示已读到结尾。
//
// 放弃复用不需要额外动作：调用方 defer 的 Close 在响应体没读完时会让 Transport
// 直接丢弃这条连接，而不是归还——那正是这里想要的结果。
func drainForReuse(body io.Reader, limit int64) bool {
	// CopyN 读满 limit 字节才返回 nil，说明后面还有，不值得再下载下去；
	// 提前读到头会返回 io.EOF，那才是真排空了。
	_, err := io.CopyN(io.Discard, body, limit)
	return errors.Is(err, io.EOF)
}

// apiErrCode 从响应体里找 errcode。返回 0 表示"没有错误码，或根本不是这种格式"。
//
// 只认 errcode 这一种拼法：钉钉、企业微信用的都是它。其他字段名（code/status/ret）
// 语义各家不同——有人用 0 表示成功，有人用 200，有人干脆用它装业务 ID，
// 猜错会把成功的执行报成失败，比漏报更糟。
func apiErrCode(body []byte) (int64, string) {
	if len(body) == 0 {
		return 0, ""
	}
	var r struct {
		ErrCode json.Number `json:"errcode"`
		ErrMsg  string      `json:"errmsg"`
	}
	if err := json.Unmarshal(body, &r); err != nil {
		return 0, ""
	}
	code, err := r.ErrCode.Int64()
	if err != nil || code == 0 {
		return 0, ""
	}
	msg := strings.TrimSpace(r.ErrMsg)
	if msg == "" {
		msg = strutil.Truncate(strings.TrimSpace(string(body)), 200, "…")
	}
	return code, msg
}

// sendNotifyAction 计划任务的通知动作。
// 支持 params: targets（目标 ID，逗号分隔）、title、message、format（text / markdown）。
func sendNotifyAction(ctx context.Context, mod *notify.Module, action config.CronAction) (string, error) {
	msg := strings.TrimSpace(action.Params["message"])
	if msg == "" {
		return "", fmt.Errorf("通知内容为空")
	}
	var ids []string
	for _, s := range strings.Split(action.Params["targets"], ",") {
		if s = strings.TrimSpace(s); s != "" {
			ids = append(ids, s)
		}
	}
	if len(ids) == 0 {
		return "", fmt.Errorf("未选择通知目标")
	}

	results, err := mod.Send(ctx, notify.Request{
		TargetIDs: ids,
		Title:     strings.TrimSpace(action.Params["title"]),
		Message:   msg,
		Format:    strings.TrimSpace(action.Params["format"]),
		Source:    "计划任务",
	})
	if err != nil {
		return "", err
	}

	// 逐目标汇总：一个群失败不影响其他群，但任务记录必须把失败的那个点出来，
	// 否则用户只会看到一句"部分失败"却不知道是哪一个。
	var okCount int
	var failed []string
	for _, r := range results {
		if r.OK {
			okCount++
			continue
		}
		failed = append(failed, r.TargetName+"("+r.Status+")")
	}
	if len(failed) > 0 {
		return "", fmt.Errorf("成功 %d 个，失败 %d 个：%s", okCount, len(failed), strings.Join(failed, "；"))
	}
	return fmt.Sprintf("已发送 %d 个目标", okCount), nil
}
