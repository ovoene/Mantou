package server

import (
	"context"
	"sync"
	"time"

	"github.com/gin-gonic/gin"

	"mantou/internal/modules/ddns"
	"mantou/internal/strutil"
)

// 总览页「外网 IP」卡片的数据来源。
//
// 取址复用 DDNS 的公网取址（ddns.DetectPublicIP）：同一组 HTTPS 回显端点、同一套公网校验，
// 卡片上显示的就是 DDNS 按「公网取址」会写进域名的那个地址，两处不会说出两个数。
//
// 只在有人看总览时才去取：检测由 /overview 的轮询顺带触发（见 handleOverview），
// 没人打开总览就一个外部请求都不发。那几个端点是第三方的，没理由在没人看的时候定期去问。
//
// 检测跑在后台协程里，轮询接口从不等它：一轮检测最坏要把每个端点的超时都等满
// （没有 IPv6 的机器上，IPv6 那一族常常就是这样），而 /overview 每 3 秒就来一次。
// 界面先显示「检测中」，结果出来之后的下一次轮询自然带上。

const (
	// publicIPTTL 取到之后多久再取一次。公网地址会变（拨号重连、运营商回收），
	// 但几分钟的滞后对"看一眼现在是多少"足够，而每一轮都是对第三方端点的请求。
	publicIPTTL = 5 * time.Minute
	// publicIPRetry 某一族没取到时隔多久再试。比 TTL 短：失败多半是端点抖动；
	// 又不能太短：没有公网 IPv6 的机器上，IPv6 那一族会一直失败下去。
	publicIPRetry = 2 * time.Minute
	// publicIPForceGap 两次手动刷新的最小间隔：连点刷新按钮不该换来成串的外部请求。
	publicIPForceGap = 10 * time.Second
	// publicIPRoundTimeout 一轮检测的总上限。单个端点各自限时 5 秒（ddns.publicProbeTimeout），
	// IPv4 一共 6 个端点，这里给到把它们都等完还有余量。
	publicIPRoundTimeout = 45 * time.Second
	// publicIPErrMax 失败原因的长度上限：它进接口响应、挂在卡片的提示上，
	// 而取址失败的原因里带着最后一个端点的完整错误串。
	publicIPErrMax = 300
)

// publicIPFamily 一个地址族的检测结果。
//
// 取不到时**保留上一次取到的地址**，Err 另外说明最近一次为什么失败：一次端点抖动
// 不该让卡片上的地址突然消失。界面据 OKAt 说明这个地址是什么时候取到的。
type publicIPFamily struct {
	IP      string `json:"ip,omitempty"`      // 最近一次成功取到的地址；从没取到过为空
	OKAt    int64  `json:"okAt,omitempty"`    // 那次成功的时刻（Unix 毫秒）
	Err     string `json:"error,omitempty"`   // 最近一次检测失败的原因；最近一次成功则为空
	TriedAt int64  `json:"triedAt,omitempty"` // 最近一次检测结束的时刻（Unix 毫秒）
}

// publicIPView 接口下发的形态。
type publicIPView struct {
	V4       publicIPFamily `json:"v4"`
	V6       publicIPFamily `json:"v6"`
	Checking bool           `json:"checking"`
}

// publicIPWatch 外网 IP 的缓存与检测调度。
//
// 零值可用：本包的测试常用 &Server{deps: …} 直接拼壳子（见 Server.reauthLimiter 的说明），
// 这里不要求任何构造步骤。
type publicIPWatch struct {
	mu       sync.Mutex
	v4, v6   publicIPFamily
	next4    time.Time // 这一族下一次自动检测的时刻；零值表示还没检测过
	next6    time.Time
	checking bool
	// lastForce 上一次手动刷新真的起了一轮检测的时刻（见 refresh）。
	lastForce time.Time

	// detect / now 只给测试注入；nil 时分别用 ddns.DetectPublicIP 与 time.Now。
	detect func(ctx context.Context, stack string) (string, error)
	now    func() time.Time
}

// view 返回当前结果；有哪一族到期了（或还没检测过），就顺带在后台起一轮检测它。
// 两族各算各的期：没有公网 IPv6 的机器上 IPv6 隔两分钟就要再试，IPv4 不必陪着一起重取。
func (w *publicIPWatch) view() publicIPView {
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.checking {
		now := w.clock()
		due4, due6 := !now.Before(w.next4), !now.Before(w.next6)
		if due4 || due6 {
			w.startLocked(due4, due6)
		}
	}
	return w.viewLocked()
}

// refresh 手动刷新：两族都重新检测，不等到期。
//
// 正在检测时不另起一轮（那一轮的结果马上就到）；两次手动刷新至少隔 publicIPForceGap。
// 没起新一轮时照常返回当前结果，不报错：对用户来说"刚刷过"与"正在刷"都不是错误。
func (w *publicIPWatch) refresh() publicIPView {
	w.mu.Lock()
	defer w.mu.Unlock()
	now := w.clock()
	if !w.checking && (w.lastForce.IsZero() || now.Sub(w.lastForce) >= publicIPForceGap) {
		w.lastForce = now
		w.startLocked(true, true)
	}
	return w.viewLocked()
}

func (w *publicIPWatch) viewLocked() publicIPView {
	return publicIPView{V4: w.v4, V6: w.v6, Checking: w.checking}
}

func (w *publicIPWatch) clock() time.Time {
	if w.now != nil {
		return w.now()
	}
	return time.Now()
}

// startLocked 在后台起一轮检测。调用方持有 w.mu 且确认此刻没有在检测。
func (w *publicIPWatch) startLocked(v4, v6 bool) {
	w.checking = true
	detect := w.detect
	if detect == nil {
		detect = ddns.DetectPublicIP
	}
	go w.run(detect, v4, v6)
}

// run 检测一轮：两族并行（互不拖累——IPv6 那一族把超时等满时，IPv4 早已取到），
// 全部结束后一次性写回，并解除 checking。
func (w *publicIPWatch) run(detect func(context.Context, string) (string, error), v4, v6 bool) {
	ctx, cancel := context.WithTimeout(context.Background(), publicIPRoundTimeout)
	defer cancel()

	var ip4, ip6 string
	var err4, err6 error
	var wg sync.WaitGroup
	if v4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ip4, err4 = detect(ctx, "ipv4")
		}()
	}
	if v6 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ip6, err6 = detect(ctx, "ipv6")
		}()
	}
	wg.Wait()

	w.mu.Lock()
	defer w.mu.Unlock()
	now := w.clock()
	if v4 {
		w.next4 = settlePublicIP(&w.v4, ip4, err4, now)
	}
	if v6 {
		w.next6 = settlePublicIP(&w.v6, ip6, err6, now)
	}
	w.checking = false
}

// settlePublicIP 记下一族的检测结果，返回它下一次自动检测的时刻。
func settlePublicIP(f *publicIPFamily, ip string, err error, now time.Time) time.Time {
	f.TriedAt = now.UnixMilli()
	if err != nil {
		f.Err = strutil.Truncate(err.Error(), publicIPErrMax, "…")
		return now.Add(publicIPRetry)
	}
	f.IP, f.OKAt, f.Err = ip, now.UnixMilli(), ""
	return now.Add(publicIPTTL)
}

// handlePublicIPRefresh 总览页外网 IP 卡片上的「刷新」：立即重新检测（后台进行），
// 返回当前结果。新结果随后由 /overview 的轮询带回。
func (s *Server) handlePublicIPRefresh(c *gin.Context) {
	respondOK(c, s.publicIP.refresh())
}
