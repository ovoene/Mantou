package webservice

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"mantou/internal/config"
	"mantou/internal/logx"
)

// scanReq 一个来自 ip 的请求。默认用 TEST-NET-3（203.0.113.0/24）这类文档地址：
// 它们不是局域网，因此不会被 scanBanKey 豁免掉。
func scanReq(ip string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "/admin", nil)
	req.RemoteAddr = ip + ":40000"
	return req
}

// TestScanBanTripsAtThreshold 记账到阈值那一次才封禁，之前一次都不封。
// 「刚刚促成封禁」只在那一次为真，之后对方继续撞门也不再重复登记——
// 日志量与对方的请求量无关，这是这道闸敢于无条件开启的前提。
func TestScanBanTripsAtThreshold(t *testing.T) {
	b := newScanBanner()
	now := time.Now()
	r := scanReq("203.0.113.9")

	for i := 1; i < scanBanStrikes; i++ {
		if _, newly := b.strike(r, now); newly {
			t.Fatalf("第 %d 次就封禁了，阈值是 %d", i, scanBanStrikes)
		}
		if _, banned := b.banned(r, now); banned {
			t.Fatalf("第 %d 次之后就被封禁了", i)
		}
	}
	until, newly := b.strike(r, now)
	if !newly {
		t.Fatalf("第 %d 次应触发封禁", scanBanStrikes)
	}
	if want := now.Add(scanBanDuration); !until.Equal(want) {
		t.Fatalf("封禁到期时间应为 %v，实际 %v", want, until)
	}
	retry, banned := b.banned(r, now)
	if !banned {
		t.Fatal("触发之后 banned 应为真")
	}
	if retry <= 0 || retry > scanBanDuration {
		t.Fatalf("剩余时长 %v 不在 (0, %v] 内", retry, scanBanDuration)
	}
	// 继续撞门：仍在封禁中，但不再重复登记（否则每个请求写一条日志）。
	if _, newly := b.strike(r, now); newly {
		t.Fatal("封禁期内不该重复登记")
	}
}

// TestScanBanWindowResets 窗口过完计数清零：一天里零星撞几个 404 永远攒不出封禁来。
func TestScanBanWindowResets(t *testing.T) {
	b := newScanBanner()
	base := time.Now()
	r := scanReq("203.0.113.10")

	// 第一个窗口：差一次到阈值。
	for i := 1; i < scanBanStrikes; i++ {
		b.strike(r, base)
	}
	// 隔了一整个窗口再来一次：应当重新从 1 开始数，而不是踩线触发。
	later := base.Add(scanBanWindow + time.Second)
	if _, newly := b.strike(r, later); newly {
		t.Fatal("跨窗口的零星请求不该累加成封禁")
	}
	if _, banned := b.banned(r, later); banned {
		t.Fatal("跨窗口不该被封禁")
	}
}

// TestScanBanReleasesAfterDuration 封禁到期自动解除，且解除后从零开始数，
// 而不是带着上一轮的余额一进门就再被封。
func TestScanBanReleasesAfterDuration(t *testing.T) {
	b := newScanBanner()
	base := time.Now()
	r := scanReq("203.0.113.11")
	for i := 0; i < scanBanStrikes; i++ {
		b.strike(r, base)
	}
	if _, banned := b.banned(r, base); !banned {
		t.Fatal("应处于封禁中")
	}
	after := base.Add(scanBanDuration + time.Second)
	if _, banned := b.banned(r, after); banned {
		t.Fatal("到期后应自动解除")
	}
	if _, newly := b.strike(r, after); newly {
		t.Fatal("解除后第一次记账就再封禁，说明计数没有清零")
	}
}

// TestScanBanExemptsLAN 局域网来源豁免：内网监控探针与 CI 撞 404 的花样最多，
// 而它们不在威胁模型里。判据与面板的「仅局域网」同一口径（ipx.IsLAN）。
func TestScanBanExemptsLAN(t *testing.T) {
	b := newScanBanner()
	now := time.Now()
	for _, ip := range []string{"127.0.0.1", "192.168.1.20", "10.1.2.3", "172.16.5.6", "[fe80::1]"} {
		r := httptest.NewRequest(http.MethodGet, "/admin", nil)
		r.RemoteAddr = ip + ":40000"
		for i := 0; i < scanBanStrikes*2; i++ {
			if _, newly := b.strike(r, now); newly {
				t.Fatalf("局域网来源 %s 被封禁了", ip)
			}
		}
		if _, banned := b.banned(r, now); banned {
			t.Fatalf("局域网来源 %s 被封禁了", ip)
		}
	}
	if b.Len() != 0 {
		t.Fatalf("豁免的来源不该在表里占位，实际 %d 条", b.Len())
	}
}

// TestScanBanPerSource 记账按来源分：一个 IP 在扫，不该把另一个 IP 一起封掉。
func TestScanBanPerSource(t *testing.T) {
	b := newScanBanner()
	now := time.Now()
	attacker := scanReq("203.0.113.12")
	visitor := scanReq("198.51.100.30")
	for i := 0; i < scanBanStrikes; i++ {
		b.strike(attacker, now)
	}
	if _, banned := b.banned(attacker, now); !banned {
		t.Fatal("扫描方应被封禁")
	}
	if _, banned := b.banned(visitor, now); banned {
		t.Fatal("另一个来源被连带封禁了")
	}
}

// TestScanBanFastPathBeforeAnyBan 无人被封禁时 banned 走的是无锁快路径：
// 表里已经有记账条目也不影响。这条钉的是"这道闸在常态下不花钱"。
func TestScanBanFastPathBeforeAnyBan(t *testing.T) {
	b := newScanBanner()
	now := time.Now()
	r := scanReq("203.0.113.13")
	for i := 0; i < 10; i++ {
		b.strike(r, now)
	}
	if b.hot.Load() != 0 {
		t.Fatalf("尚无封禁时 hot 应为零，实际 %d", b.hot.Load())
	}
	if _, banned := b.banned(r, now); banned {
		t.Fatal("尚无封禁时不该判为封禁")
	}
}

// TestScanBanTableBounded 海量来源涌入时表不会无上限增长。
func TestScanBanTableBounded(t *testing.T) {
	b := newScanBanner()
	now := time.Now()
	for i := 0; i < scanBanMaxEntries+2000; i++ {
		// 203.0.113.0/24 只有 256 个地址，用一段更大的空间造出足够多的不同来源。
		ip := "100.0." + strconv.Itoa(i/256%256) + "." + strconv.Itoa(i%256)
		b.strike(scanReq(ip), now)
	}
	if n := b.Len(); n > scanBanMaxEntries {
		t.Fatalf("表内 %d 条，超过上限 %d", n, scanBanMaxEntries)
	}
}

// TestScanBanEvictKeepsBanned 淘汰只动"没在封禁中"的条目。
//
// 反过来写就等于给对方开一条逃生通道：制造足够多的新来源把表顶满，自己就被挤出去解封了，
// 而在 IPv6 下"造一批新来源"几乎没有成本。
func TestScanBanEvictKeepsBanned(t *testing.T) {
	b := newScanBanner()
	now := time.Now()
	// 手工造一张满表：一条在封禁中，其余都是闲着的记账条目。
	b.entries["banned-one"] = &scanBanEntry{banUntil: now.Add(scanBanDuration), seen: now}
	for i := 1; i < scanBanMaxEntries; i++ {
		b.entries["idle-"+strconv.Itoa(i)] = &scanBanEntry{seen: now.Add(-time.Duration(i) * time.Millisecond)}
	}
	b.evictLocked(now)
	if _, ok := b.entries["banned-one"]; !ok {
		t.Fatal("正在封禁中的条目被淘汰了")
	}
	if n := len(b.entries); n >= scanBanMaxEntries {
		t.Fatalf("淘汰没有腾出空间，仍有 %d 条", n)
	}
}

// TestScanBanEvictAllBannedKeepsTableBounded 极端情况：表里全是正在封禁中的条目。
// 此时淘汰刻意什么都不做，strike 转为放弃给新来源建账——
// 这道闸退化成"不再新增封禁"，而不是让表继续长大。
func TestScanBanEvictAllBannedKeepsTableBounded(t *testing.T) {
	b := newScanBanner()
	now := time.Now()
	for i := 0; i < scanBanMaxEntries; i++ {
		b.entries["banned-"+strconv.Itoa(i)] = &scanBanEntry{banUntil: now.Add(scanBanDuration), seen: now}
	}
	if _, newly := b.strike(scanReq("203.0.113.14"), now); newly {
		t.Fatal("表满且全在封禁中时不该新增封禁")
	}
	if n := len(b.entries); n != scanBanMaxEntries {
		t.Fatalf("表长度应保持在上限 %d，实际 %d", scanBanMaxEntries, n)
	}
}

// TestScanBanGCReclaimsIdle 闲过一个窗口且没在封禁中的条目会被回收；
// 正在封禁中的必须留下，否则回收一次等于解封一批。
func TestScanBanGCReclaimsIdle(t *testing.T) {
	b := newScanBanner()
	base := time.Now()
	b.entries["idle"] = &scanBanEntry{seen: base}
	b.entries["banned"] = &scanBanEntry{seen: base, banUntil: base.Add(scanBanDuration)}
	// 让 GC 够条件跑一次：距上次 GC 已过一个窗口，且 idle 条目也闲过一个窗口。
	later := base.Add(scanBanWindow + time.Second)
	b.gcLocked(later)
	if _, ok := b.entries["idle"]; ok {
		t.Fatal("闲置条目应被回收")
	}
	if _, ok := b.entries["banned"]; !ok {
		t.Fatal("正在封禁中的条目被回收了")
	}
}

// TestScanBanNilSafe nil 表（测试里直接组装的 &Module{}）应表现为"没有这道闸"，
// 而不是在第一个请求上崩掉。
func TestScanBanNilSafe(t *testing.T) {
	var b *scanBanner
	r := scanReq("203.0.113.15")
	if _, banned := b.banned(r, time.Now()); banned {
		t.Fatal("nil 表不该判为封禁")
	}
	if _, newly := b.strike(r, time.Now()); newly {
		t.Fatal("nil 表不该产生封禁")
	}
	if b.Len() != 0 {
		t.Fatal("nil 表的长度应为 0")
	}
	if (*Module)(nil).scanBanner() != nil {
		t.Fatal("nil 模块的 scanBanner 应为 nil")
	}
}

// TestScanBanCountable 只有 401 / 403 / 404 记账。
//
// 5xx 排除是关键的一条：后端抖一下就自己封掉一批真实访客，比不封更糟。
// 429 排除同理——那是本机限流刚回绝的请求，算进来就成了"因为被限流所以被封禁"的自激。
func TestScanBanCountable(t *testing.T) {
	cases := map[int]bool{
		http.StatusOK:                  false,
		http.StatusMovedPermanently:    false,
		http.StatusUnauthorized:        true,
		http.StatusForbidden:           true,
		http.StatusNotFound:            true,
		http.StatusTooManyRequests:     false,
		http.StatusBadRequest:          false,
		http.StatusInternalServerError: false,
		http.StatusBadGateway:          false,
		http.StatusServiceUnavailable:  false,
	}
	for status, want := range cases {
		if got := scanBanCountable(&statusWriter{status: status}); got != want {
			t.Errorf("状态码 %d 应记账=%v，实际 %v", status, want, got)
		}
	}
	// 客户端主动挂断：状态码不代表服务端的判断，一律不记账。
	if scanBanCountable(&statusWriter{status: http.StatusNotFound, clientAborted: true}) {
		t.Error("客户端挂断不该记账")
	}
}

// TestWriteScanBannedResponse 封禁响应用 429 + Retry-After，且页面上不提"封禁"二字：
// 那会告诉对方这台机器有封禁机制、以及自己踩到了哪条线。
func TestWriteScanBannedResponse(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Accept", "text/html")
	writeScanBanned(w, r, 90*time.Second)
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("状态码应为 429，实际 %d", w.Code)
	}
	ra := w.Header().Get("Retry-After")
	if n, err := strconv.Atoi(ra); err != nil || n <= 0 {
		t.Fatalf("Retry-After 应为正整数秒，实际 %q", ra)
	}
	body := w.Body.String()
	for _, leak := range []string{"封禁", "ban", "扫描"} {
		if strings.Contains(strings.ToLower(body), strings.ToLower(leak)) {
			t.Errorf("响应体泄露了机制信息 %q：%s", leak, body)
		}
	}
}

// TestScanBanUnmatchedHostStrikes 「未匹配到站点」也要记账：拿 IP 直连、Host 是垃圾，
// 正是公网扫描最常见的形态，而这条路径压根不经过任何子项，因此必须在监听层记。
//
// 一并验证闸门装在监听层：踩线之后同一个来源拿到的是 429，而不是照旧走一遍路由。
func TestScanBanUnmatchedHostStrikes(t *testing.T) {
	m := New(logx.New(logx.Options{}))
	t.Cleanup(func() { _ = m.Close() })
	g := &wsGroup{family: "ipv4", port: 8080,
		bindings: []childBinding{{service: "官网", child: config.WebChild{
			ID: "ch1", Enabled: true, Type: "redirect", Domains: []string{"www.example.com"},
			Redirect: config.WebRedirect{Target: "https://example.com", Code: 301},
		}}},
	}
	h := newListenServer(g, nil, m, m.log).handler()

	serve := func(host string) int {
		req := httptest.NewRequest(http.MethodGet, "/wp-login.php", nil)
		req.RemoteAddr = "203.0.113.66:40000"
		req.Host = host
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		return w.Code
	}

	// 阈值之前一律 404（正常的"未匹配到站点"）。
	for i := 1; i < scanBanStrikes; i++ {
		if code := serve("nope-" + strconv.Itoa(i) + ".example.com"); code != http.StatusNotFound {
			t.Fatalf("第 %d 次应为 404，实际 %d", i, code)
		}
	}
	// 第 scanBanStrikes 次踩线：这一次仍然照常回 404（封禁在这次之后才生效）。
	if code := serve("nope.example.com"); code != http.StatusNotFound {
		t.Fatalf("踩线那一次应为 404，实际 %d", code)
	}
	// 之后的请求被闸门挡在路由之前：连合法域名都进不去了，这正是封禁的含义。
	if code := serve("nope.example.com"); code != http.StatusTooManyRequests {
		t.Fatalf("封禁后应为 429，实际 %d", code)
	}
	if code := serve("www.example.com"); code != http.StatusTooManyRequests {
		t.Fatalf("封禁是整机的，合法域名也应为 429，实际 %d", code)
	}
}

// TestScanBanChildErrorsStrike 子项内部的 4xx 同样记账（在 instrument 里），
// 与监听层共用同一张表：扫描器在某个站点上暴露了自己，没有理由让它接着去扫别的。
//
// 用 IP 规则拒绝（403）来造这批 4xx：它是扫描器最常撞上的一种，
// 而且它在 instrument 里有一条提前 return，记账必须排在那条之前。
func TestScanBanChildErrorsStrike(t *testing.T) {
	m := New(logx.New(logx.Options{}))
	t.Cleanup(func() { _ = m.Close() })
	var ch config.WebChild
	ch.ID = "ch1"
	ch.Access.IPFilter = true
	ch.Access.IPFilterMode = "deny"
	ch.Access.DenyIPs = []string{"203.0.113.77"}
	h := m.instrument("官网", ch, m.connCounter(ch.ID), applyMiddleware(m, "官网", ch, passthrough()))

	for i := 0; i < scanBanStrikes; i++ {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = "203.0.113.77:40000"
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != http.StatusForbidden {
			t.Fatalf("第 %d 次应为 403，实际 %d", i+1, w.Code)
		}
	}
	if _, banned := m.scanBan.banned(scanReq("203.0.113.77"), time.Now()); !banned {
		t.Fatal("子项内部的 403 没有累计成封禁")
	}
}
