package webhook

import (
	"net/http"
	"net/url"
	"runtime"
	"strings"
	"testing"

	"mantou/internal/config"
)

// 本文件盯的是关键词准入的**取文本时机**（3-J）。
//
// 关键词准入要比对的文本是"请求体原文 + 查询串的值"，也就是一整份载荷的拷贝
// （入站上限 4MB）。而这个功能是可选的，绝大多数接收器压根没开：
// 原先文本在调用点就拼好了，于是每条入站请求都白拷一份完整载荷，
// 只为喂给一个下一行就 return true 的判断。
//
// 修法是把参数改成 func() string，让拷贝发生在"确实配了词"之后。
// 下面两组测试分别钉住这件事的两半：
//   - 没配词时那个函数一次都不许调用；
//   - 配了词时只许调用一次（不是每个词调一次）。

// kwReceiver 编译一个只关心关键词那几项的接收器。
func kwReceiver(t *testing.T, mode string, words ...string) *receiverRT {
	t.Helper()
	rc := config.WebhookReceiver{
		ID:            "r1",
		Name:          "第三方系统",
		Path:          "hook",
		Enabled:       true,
		KeywordFilter: len(words) > 0,
		KeywordMode:   mode,
		Keywords:      words,
	}
	return compileReceiver(rc, nil)
}

// 没有生效的关键词时，取文本的那个函数一次都不该被调用。
//
// 三种"没有"都要覆盖：开关没开、开关开着但词表为空、词表只有空白。
// 后两种在编译期只留一条警告、行为上失败开放（见 compileReceiver），
// 但它们同样不该付出拷贝载荷的代价——手改坏一份配置不该顺带把每请求成本抬上去。
func TestAllowKeywordsSkipsTextWhenNoKeywords(t *testing.T) {
	cases := []struct {
		name string
		rc   *receiverRT
	}{
		{"开关没开", func() *receiverRT {
			rc := config.WebhookReceiver{ID: "r1", Path: "hook", Enabled: true, Keywords: []string{"报警"}}
			return compileReceiver(rc, nil)
		}()},
		{"开关开着但词表为空", kwReceiver(t, "any")},
		{"词表只有空白", func() *receiverRT {
			rc := config.WebhookReceiver{ID: "r1", Path: "hook", Enabled: true, KeywordFilter: true, Keywords: []string{"  ", "\t"}}
			return compileReceiver(rc, nil)
		}()},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			calls := 0
			ok, why := c.rc.allowKeywords(func() string { calls++; return "随便什么内容" })
			if !ok || why != "" {
				t.Fatalf("没有生效的关键词时应放行，实际 ok=%v why=%q", ok, why)
			}
			if calls != 0 {
				t.Fatalf("没配关键词却取了 %d 次文本——每条入站请求都在白拷一份载荷", calls)
			}
		})
	}
}

// 配了词时只取一次文本：词表可以有几十个词，一词一取就是把白拷从"每请求一份"
// 变成"每请求每词一份"，比修之前更糟。
func TestAllowKeywordsEvaluatesTextOnce(t *testing.T) {
	cases := []struct {
		name   string
		rc     *receiverRT
		text   string
		wantOK bool
	}{
		{"任一：命中第一个", kwReceiver(t, "any", "报警", "入库", "审核"), "磁盘报警", true},
		{"任一：全都不中", kwReceiver(t, "any", "报警", "入库", "审核"), "每日心跳", false},
		{"全部：都在", kwReceiver(t, "all", "每日", "已审核"), "每日汇总已审核", true},
		{"全部：差一个", kwReceiver(t, "all", "每日", "已审核"), "每日汇总待审核", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			calls := 0
			ok, _ := c.rc.allowKeywords(func() string { calls++; return c.text })
			if ok != c.wantOK {
				t.Fatalf("准入结论不对：ok=%v，期望 %v", ok, c.wantOK)
			}
			if calls != 1 {
				t.Fatalf("取了 %d 次文本，应当只取 1 次（词表有 %d 个词）", calls, len(c.rc.keywords))
			}
		})
	}
}

// 真实入站路径上也不许拼那份文本。
//
// 上面两组只钉住了 allowKeywords 自己：调用点仍然可以先把文本算好、再包成一个
// 常量闭包传进来——编译得过、行为也全对，而白拷原封不动地回来了。
// 这一条用分配量把调用点也钉住：同一个接收器，只有词表开关不同，
// 开着的那份必须比关着的那份多分配约一份载荷。差额来自 keywordText 的那次拷贝，
// 与握手、读体、渲染这些两边都要付的常量开销无关，所以不必给绝对阈值。
func TestServeDoesNotBuildKeywordTextWithoutKeywords(t *testing.T) {
	const bodyKB = 1024 // 1MiB：小到测试不至于跑很久，大到足以从噪声里分出来
	body := strings.Repeat("x", bodyKB<<10)

	measure := func(t *testing.T, cfg config.Config) uint64 {
		t.Helper()
		h := newHarness(t, cfg)
		// 先热一次：httptest 客户端、连接、日志缓冲这些首次分配不该算进来。
		if code, resp := h.post(t, "/hook", body); code != http.StatusOK {
			t.Fatalf("预热请求应成功，实际 %d：%s", code, resp)
		}
		const rounds = 6
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)
		for i := 0; i < rounds; i++ {
			if code, resp := h.post(t, "/hook", body); code != http.StatusOK {
				t.Fatalf("第 %d 轮应成功，实际 %d：%s", i+1, code, resp)
			}
		}
		runtime.ReadMemStats(&after)
		return (after.TotalAlloc - before.TotalAlloc) / rounds
	}

	big := func(rc *config.WebhookReceiver) { rc.MaxBodyKB = bodyKB * 2 }
	off := measure(t, hitCfg(big))
	on := measure(t, hitCfg(func(rc *config.WebhookReceiver) {
		big(rc)
		// 词就在正文里，命中之后照常往下走：两份配置除了这一项之外走的是同一条路径。
		rc.KeywordFilter, rc.KeywordMode, rc.Keywords = true, "any", []string{"x"}
	}))

	gap := int64(on) - int64(off)
	// 留一半余量：要抓的是"这份拷贝又回到了每一条请求上"，不是抠几百字节。
	want := int64(len(body)) / 2
	if gap < want {
		t.Fatalf("开关关着时每请求 %d 字节、开着时 %d 字节，差额只有 %d 字节（应超过 %d）——"+
			"说明没配关键词的请求也在拼那份文本", off, on, gap, want)
	}
}

// keywordText 自己的行为不变：正文 + 查询串的值，参数名不算。
// 上面把它推迟到了闭包里，这一条保证推迟的过程中没把它改坏。
func TestKeywordTextStillJoinsBodyAndQueryValues(t *testing.T) {
	req := &http.Request{Method: http.MethodPost, URL: &url.URL{Path: "/hook", RawQuery: "msg=" + url.QueryEscape("磁盘报警") + "&level=3"}}
	got := keywordText(req, []byte(`{"来源":"监控"}`))
	for _, want := range []string{"监控", "磁盘报警", "3"} {
		if !strings.Contains(got, want) {
			t.Fatalf("拼出的文本应含 %q：%q", want, got)
		}
	}
	if strings.Contains(got, "level") {
		t.Fatalf("参数名不该参与比对：%q", got)
	}

	// 没有查询串时走的是另一条分支，同样要给出正文。
	plain := &http.Request{Method: http.MethodPost, URL: &url.URL{Path: "/hook"}}
	if got := keywordText(plain, []byte("纯文本正文")); got != "纯文本正文" {
		t.Fatalf("没有查询串时应原样返回正文：%q", got)
	}
	// URL 为 nil 只会出现在非 HTTP 传输的构造里，但那条分支存在就得有人走过。
	if got := keywordText(&http.Request{}, []byte("abc")); got != "abc" {
		t.Fatalf("URL 为 nil 时应原样返回正文：%q", got)
	}
}
