package webhook

import (
	"net/http"
	"runtime"
	"strings"
	"testing"
	"unicode/utf8"
	"unsafe"
)

// sourceEntryBase 是内存记账的基数，必须真的盖住结构体本身的大小，
// 否则字节闸算出来的占用比实际小，那个额度上限就是个假承诺。
// SourceRecord 一加字段这条就会红。
func TestSourceEntryBaseCoversStruct(t *testing.T) {
	if got := int(unsafe.Sizeof(SourceRecord{})); got > sourceEntryBase {
		t.Fatalf("SourceRecord 已经 %d 字节，超过 sourceEntryBase=%d：请同时调大基数与预算注释里的估算", got, sourceEntryBase)
	}
}

// 满额条数下槽位数组不能把字节预算吃光，否则一条内容都留不住。
func TestSourceSlotsLeaveRoomForContent(t *testing.T) {
	s := newSourceStore()
	if got := s.contentBudget(); got < defaultSourceBudget/2 {
		t.Fatalf("槽位占掉太多，留给内容的只有 %d 字节（总预算 %d）", got, defaultSourceBudget)
	}
}

// ---------- 淘汰 ----------

// smallStore 一个只把环开小、字节预算照默认值的留存环。
//
// 不直接写 &sourceStore{buf: …}：那样 budget 是零值，而 0 表示「不留存」——
// 于是 contentBudget() 变成负数，第一条进来就把上一条顶掉，本文件几乎每条断言
// 都会以"因为根本没留住"的方式失败，而报出来的现象（条数是 1）指不到原因上。
func smallStore(n int) *sourceStore {
	return &sourceStore{buf: make([]SourceRecord, n), budget: defaultSourceBudget}
}

// 条数闸：环满之后顶掉最旧的。直接给 buf 定长而不走 newSourceStore，
// 否则要灌 501 条才看得到淘汰。
func TestSourceEvictsOldestByCount(t *testing.T) {
	s := smallStore(3)
	ids := make([]string, 0, 4)
	for _, body := range []string{"a", "b", "c", "d"} {
		ids = append(ids, s.add(SourceRecord{Body: body}))
	}
	if s.count != 3 {
		t.Fatalf("条数期望 3，实际 %d", s.count)
	}
	if _, ok := s.get(ids[0]); ok {
		t.Fatal("最旧那条应当已被顶掉")
	}
	for _, id := range ids[1:] {
		if _, ok := s.get(id); !ok {
			t.Fatalf("%s 应当还在", id)
		}
	}
}

// 字节闸：条数没满也要淘汰。0.75 MiB 一条，三条 2.25 MiB 超过 2 MiB 预算。
func TestSourceEvictsByByteBudget(t *testing.T) {
	s := smallStore(4)
	big := strings.Repeat("x", 768<<10)
	for i := 0; i < 3; i++ {
		s.add(SourceRecord{Body: big})
	}
	if s.count != 2 {
		t.Fatalf("条数期望 2（字节闸先到），实际 %d", s.count)
	}
	if s.bytes > s.contentBudget() {
		t.Fatalf("占用 %d 字节仍超预算 %d", s.bytes, s.contentBudget())
	}
}

// 淘汰之后账要对得上：槽位没清零、或字节数只加不减，都会让预算慢慢失效。
func TestSourceBytesMatchLiveEntries(t *testing.T) {
	s := smallStore(3)
	for _, body := range []string{"aaa", "bbbb", "ccccc", "dddddd", "e"} {
		s.add(SourceRecord{Body: body, Headers: map[string]string{"content-type": "text/plain"}})
	}
	want := 0
	for i := 0; i < s.count; i++ {
		want += sourceBytes(s.buf[(s.head+i)%len(s.buf)])
	}
	if s.bytes != want {
		t.Fatalf("记账 %d 字节，实际存活记录合计 %d 字节", s.bytes, want)
	}
}

// 最后一条哪怕自己就超预算也要留住：刚出问题的那条正是用户要点开看的。
func TestSourceKeepsLastEntryOverBudget(t *testing.T) {
	s := smallStore(2)
	s.add(SourceRecord{Body: "small"})
	id := s.add(SourceRecord{Body: strings.Repeat("x", defaultSourceBudget+1)})
	if s.count != 1 {
		t.Fatalf("条数期望 1，实际 %d", s.count)
	}
	if _, ok := s.get(id); !ok {
		t.Fatal("超预算的最后一条也必须留住")
	}
}

// ---------- 取用 ----------

func TestSourceGetMissing(t *testing.T) {
	s := newSourceStore()
	if _, ok := s.get(""); ok {
		t.Fatal("空 ID 不该命中")
	}
	if _, ok := s.get("s999"); ok {
		t.Fatal("不存在的 ID 不该命中")
	}
}

// ID 不能重复使用：重复了就是"点开看到的是别人那条"。
func TestSourceIDsUniqueAndMatch(t *testing.T) {
	s := smallStore(8)
	seen := map[string]string{}
	for _, body := range []string{"one", "two", "three", "four"} {
		id := s.add(SourceRecord{Body: body})
		if prev, dup := seen[id]; dup {
			t.Fatalf("ID %s 重复（先前是 %q）", id, prev)
		}
		seen[id] = body
	}
	for id, body := range seen {
		got, ok := s.get(id)
		if !ok || got.Body != body {
			t.Fatalf("%s 取到 %q/%v，期望 %q", id, got.Body, ok, body)
		}
	}
}

// 容量为 0 的环返回空 ID，调用方据此不给历史记录挂链接。
func TestSourceZeroCapacity(t *testing.T) {
	s := &sourceStore{}
	if id := s.add(SourceRecord{Body: "x"}); id != "" {
		t.Fatalf("期望空 ID，实际 %q", id)
	}
}

func TestSourceStats(t *testing.T) {
	s := smallStore(4)
	s.add(SourceRecord{Body: "hello"})
	count, bytes := s.stats()
	if count != 1 || bytes <= 0 {
		t.Fatalf("stats 返回 %d 条 / %d 字节", count, bytes)
	}
}

// ---------- 额度可调 ----------

// 额度调小要**当场**淘汰，不能等下一条消息进来才生效：
// 用户把它调小往往正是不想让这些内容继续留在内存里，而下一条消息可能几小时后才来。
func TestSourceSetBudgetEvictsImmediately(t *testing.T) {
	s := smallStore(8)
	big := strings.Repeat("x", 200<<10) // 200 KB 一条
	for i := 0; i < 5; i++ {
		s.add(SourceRecord{Body: big})
	}
	if s.count != 5 {
		t.Fatalf("前置条件不成立：默认额度下 5 条 200 KB 应当都留住，实际 %d 条", s.count)
	}

	// 只留得下两条内容的额度（槽位数组也要从这个数里扣）。
	s.setBudget(8*sourceEntryBase + 450<<10)
	if s.count != 2 {
		t.Fatalf("调小额度后期望剩 2 条，实际 %d 条", s.count)
	}
	if s.bytes > s.contentBudget() {
		t.Fatalf("占用 %d 字节仍超新预算 %d：额度调小了却没当场淘汰", s.bytes, s.contentBudget())
	}
	if got := s.currentBudget(); got != 8*sourceEntryBase+450<<10 {
		t.Fatalf("currentBudget 返回 %d，与刚下发的额度不一致", got)
	}
}

// 额度调到 0 就是「不留存」：已留的清空、槽位数组也还回去、之后不再留。
//
// 槽位数组必须一起还回去（130 KB 不是零头），而"之后不再留"是这个选项的全部意义——
// 只清空不拦新的，等于用户选了不留存、内存里却又慢慢长回来。
func TestSourceSetBudgetZeroStopsRetaining(t *testing.T) {
	s := smallStore(4)
	s.add(SourceRecord{Body: "hello"})

	s.setBudget(0)
	if s.count != 0 || s.bytes != 0 {
		t.Fatalf("额度 0 应当清空留存，实际 %d 条 / %d 字节", s.count, s.bytes)
	}
	if s.buf != nil {
		t.Fatal("额度 0 时槽位数组也该还回去：这份数组本身就有 130 KB")
	}
	if id := s.add(SourceRecord{Body: "x"}); id != "" {
		t.Fatalf("额度 0 之后还在留存，返回了 ID %q", id)
	}
	// 空 ID 之外还要保证取用侧不炸：面板上那些老链接还会点进来。
	if _, ok := s.get("s1"); ok {
		t.Fatal("额度 0 之后不该还能取到记录")
	}
	if c, b := s.stats(); c != 0 || b != 0 {
		t.Fatalf("stats 返回 %d 条 / %d 字节", c, b)
	}

	// 再调回来要能继续留：这个开关是双向的。
	s.setBudget(defaultSourceBudget)
	if id := s.add(SourceRecord{Body: "back"}); id == "" {
		t.Fatal("额度调回来之后应当恢复留存")
	}
}

// 负数按 0 处理（不留存），而不是当成"没填"去取默认值：
// 手改配置写出一个负数，意思显然是"别留"。
func TestSourceSetBudgetNegative(t *testing.T) {
	s := smallStore(4)
	s.add(SourceRecord{Body: "hello"})
	s.setBudget(-1)
	if s.count != 0 || s.currentBudget() != 0 {
		t.Fatalf("负数额度期望等同 0，实际 %d 条 / 额度 %d", s.count, s.currentBudget())
	}
}

// 清空：条数、字节数、槽位内容都要归零，而额度不动——下一条消息照常留存。
//
// 槽位必须真的清零：只把 count 归零的话，环仍持有那些正文与请求头，
// 账面清了、内存没还回去，而这个按钮的用意恰恰是"让这些内容立刻消失"。
func TestSourceClear(t *testing.T) {
	s := smallStore(4)
	// 记下清空之前发出的每一个 ID：后面要拿它们整体比对。
	// 只记最后一个不够——ID 是自增的，清空后若把计数器一起归零，下一个发出来的是
	// 头一条那个 ID，与"最后一个"根本不相等，断言会在真出问题时照样通过。
	var before []string
	for _, body := range []string{"aaa", "bbb", "ccc"} {
		before = append(before, s.add(SourceRecord{Body: body, Headers: map[string]string{"content-type": "text/plain"}}))
	}
	last := s.add(SourceRecord{Body: "ddd"})
	before = append(before, last)

	if got := s.clear(); got != 4 {
		t.Fatalf("clear 返回清掉 %d 条，期望 4", got)
	}
	if s.count != 0 || s.bytes != 0 {
		t.Fatalf("清空后仍有 %d 条 / %d 字节", s.count, s.bytes)
	}
	for i, r := range s.buf {
		if r.ID != "" || r.Body != "" || r.Headers != nil {
			t.Fatalf("第 %d 个槽位没清零：%+v——环还压着那条正文不放", i, r)
		}
	}
	if _, ok := s.get(last); ok {
		t.Fatal("清空后不该还能取到记录")
	}
	if got := s.currentBudget(); got != defaultSourceBudget {
		t.Fatalf("清空动了额度：现在是 %d，期望 %d", got, defaultSourceBudget)
	}
	// ID 不回头用：清空只是把内容删了，不是把这个环重置成新的。
	// 回头用会让面板上那些老链接指到新记录上——点开看到的是别人那条。
	// 与清空前一样多发几条，逐个比对，任何一个撞上都算回头用。
	used := map[string]bool{}
	for _, id := range before {
		used[id] = true
	}
	for i := range before {
		id := s.add(SourceRecord{Body: "after"})
		if id == "" {
			t.Fatalf("清空之后第 %d 条应当照常留存", i+1)
		}
		if used[id] {
			t.Fatalf("清空后 ID 又发到了 %s（清空前发过 %v）：面板上的老链接会指到新记录上", id, before)
		}
		used[id] = true
	}
}

// 额度为 0 的环上点清空不能炸（buf 是 nil）：这两个控件在界面上是并列的，
// 用户完全可能先把额度调到 0，再顺手点一下清空。
func TestSourceClearWhenNotRetaining(t *testing.T) {
	s := smallStore(4)
	s.add(SourceRecord{Body: "hello"})
	s.setBudget(0)
	if got := s.clear(); got != 0 {
		t.Fatalf("不留存时清空期望返回 0，实际 %d", got)
	}
}

// ---------- 入库前的裁剪 ----------

func TestClampBodyUnderLimit(t *testing.T) {
	body, size, truncated := clampBody([]byte("hello"), sourceBodyMax)
	if body != "hello" || size != 5 || truncated {
		t.Fatalf("clampBody 返回 %q/%d/%v", body, size, truncated)
	}
}

// 截断要标记出来，且 size 报的是**原始**字节数——面板要显示"实际收到多大"。
func TestClampBodyTruncates(t *testing.T) {
	raw := []byte(strings.Repeat("x", sourceBodyMax+100))
	body, size, truncated := clampBody(raw, sourceBodyMax)
	if !truncated {
		t.Fatal("超过上限必须标记截断")
	}
	if size != sourceBodyMax+100 {
		t.Fatalf("size=%d，期望原始字节数 %d", size, sourceBodyMax+100)
	}
	if len(body) > sourceBodyMax {
		t.Fatalf("留存 %d 字节，超过上限 %d", len(body), sourceBodyMax)
	}
}

// 截断后的正文不能还压着整段原始正文不放。
//
// 这是本文件里唯一一条"其他每条都过、内存照涨"的用例，所以单独说明：
// Go 的子串与原串共用底层数组，而 s[:n] + "" 会被运行时原样返回（不拷贝）。
// 于是"先 string(raw) 再截 32 KB"得到的那条记录，账上 32 KB、实际压着整段 4 MB。
// 字节闸照常记账、进程内存照常涨——那份留存额度变成一句空话。
// 判据是 GC 之后真正存活的堆字节数，不是记账值：这个错只有量内存才看得见。
func TestClampBodyDoesNotPinOriginal(t *testing.T) {
	const bodies = 16
	raw := make([]byte, 32*sourceBodyMax) // 一条远超上限的正文（1 MiB）
	for i := range raw {
		raw[i] = 'x'
	}

	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)

	kept := make([]string, 0, bodies)
	for i := 0; i < bodies; i++ {
		body, _, truncated := clampBody(raw, sourceBodyMax)
		if !truncated {
			t.Fatal("这么大的正文必须被截断")
		}
		kept = append(kept, body)
	}
	runtime.GC()
	runtime.ReadMemStats(&after)
	live := int64(after.HeapAlloc) - int64(before.HeapAlloc)
	runtime.KeepAlive(kept)

	// 留住 16 条各 32 KB = 512 KB。放宽到 4 倍容下切片增长与取整；
	// 而"压着原文"那种写法在这里是 16 MiB，与阈值差 32 倍，不会因噪声误判。
	if limit := int64(4 * bodies * sourceBodyMax); live > limit {
		t.Fatalf("留存 %d 条各 %d 字节，GC 后实际存活 %d KB，超过 %d KB——"+
			"截断后的字符串仍指向整段原始正文（别用 s[:n]+\"\"，直接 string(raw[:n])）",
			bodies, sourceBodyMax, live>>10, limit>>10)
	}
}

// 按字节切不能切开一个中文字符：切开会在面板上显示成方块，看着像"对方发来的是乱码"。
func TestClampBodyKeepsUTF8Intact(t *testing.T) {
	raw := []byte(strings.Repeat("中", sourceBodyMax/3+1))
	body, _, truncated := clampBody(raw, sourceBodyMax)
	if !truncated {
		t.Fatal("这段输入超过上限，应当截断")
	}
	if !utf8.ValidString(body) {
		t.Fatal("截断后不是合法 UTF-8")
	}
}

func TestClampHeadersEmpty(t *testing.T) {
	if got := clampHeaders(nil); got != nil {
		t.Fatalf("空输入期望 nil，实际 %v", got)
	}
}

// 条数与单值长度各设一道闸：两者都由对端决定。
func TestClampHeadersCaps(t *testing.T) {
	in := make(map[string]any, sourceMaxHeaders*2)
	for i := 0; i < sourceMaxHeaders*2; i++ {
		in["h"+itoa(i)] = strings.Repeat("v", sourceHeaderValueMax+50)
	}
	out := clampHeaders(in)
	if len(out) != sourceMaxHeaders {
		t.Fatalf("留了 %d 个请求头，期望 %d", len(out), sourceMaxHeaders)
	}
	for k, v := range out {
		if len(v) > sourceHeaderValueMax+len("…") {
			t.Fatalf("%s 的值 %d 字节，超过上限", k, len(v))
		}
	}
}

// 打码只在 headerMap 里做一次，留存这一层不能把它抹掉。
func TestClampHeadersKeepsRedaction(t *testing.T) {
	h := http.Header{}
	h.Set("Authorization", "Bearer secret-token")
	h.Set("X-Sign", "signature-value")
	h.Set("Content-Type", "application/json")
	out := clampHeaders(headerMap(h, "x-sign"))
	if out["authorization"] != "***" {
		t.Fatalf("authorization 期望 ***，实际 %q", out["authorization"])
	}
	if out["x-sign"] != "***" {
		t.Fatalf("接收器指定的鉴权头期望 ***，实际 %q", out["x-sign"])
	}
	if out["content-type"] != "application/json" {
		t.Fatalf("普通请求头不该被改动，实际 %q", out["content-type"])
	}
}

// ---------- 查询串 ----------

// 本程序自己支持 ?token=… 传令牌，照原样留存等于把入站令牌摆在页面上。
func TestRedactQuerySecrets(t *testing.T) {
	got := redactQuery("token=abc&order=SO001&access_token=xyz&secret=s3&name=%E4%B8%AD")
	for _, bad := range []string{"abc", "xyz", "s3"} {
		if strings.Contains(got, bad) {
			t.Fatalf("凭证 %q 没有被打码：%s", bad, got)
		}
	}
	// 其余参数一律照原样：有些系统只能在 URL 上带参数推送，那时查询串就是消息正文。
	if !strings.Contains(got, "order=SO001") || !strings.Contains(got, "name=中") {
		t.Fatalf("普通参数被弄丢了：%s", got)
	}
}

// 大小写不同的参数名也要挡住。
func TestRedactQueryCaseInsensitive(t *testing.T) {
	if got := redactQuery("Token=abc"); strings.Contains(got, "abc") {
		t.Fatalf("大写参数名没打码：%s", got)
	}
}

// 顺序必须固定：用户会前后两次点开同一条记录对照着看，顺序乱跳会被当成"对方改了请求"。
func TestRedactQueryStableOrder(t *testing.T) {
	raw := "z=1&a=2&m=3&b=4&y=5&c=6"
	first := redactQuery(raw)
	for i := 0; i < 20; i++ {
		if got := redactQuery(raw); got != first {
			t.Fatalf("第 %d 次返回 %s，与首次 %s 不同", i, got, first)
		}
	}
	if first != "a=2&b=4&c=6&m=3&y=5&z=1" {
		t.Fatalf("期望按参数名排序，实际 %s", first)
	}
}

// 解析不了就整段打码：说不清哪一截是凭证，不要赌。
func TestRedactQueryUnparseable(t *testing.T) {
	if got := redactQuery("%zz=1"); got != "***" {
		t.Fatalf("期望整段打码，实际 %q", got)
	}
	if got := redactQuery(""); got != "" {
		t.Fatalf("空查询串期望空，实际 %q", got)
	}
}

// 查询串本身也要有长度闸：它由对端决定。
func TestRedactQueryLengthCap(t *testing.T) {
	raw := "a=" + strings.Repeat("1", sourceQueryMax*2)
	if got := redactQuery(raw); len(got) > sourceQueryMax+len("…") {
		t.Fatalf("留存 %d 字节，超过上限 %d", len(got), sourceQueryMax)
	}
}

// ---------- 查询串：要能被再解析的那一版 ----------

// 打码之外一个字节都不许改。抓包的查询串会被送回后端重建事件（模板预览），
// 解析→重建那一套会把值里转义过的 & 变成真的分隔符，于是预览里的字段和真实收到的不是一回事。
func TestRedactQueryKeepingRawIsByteExact(t *testing.T) {
	raw := "z=1&text=a%26b%3Dc&token=abc&a=%E4%B8%AD"
	got := redactQueryKeepingRaw(raw, sourceQueryMax)
	if want := "z=1&text=a%26b%3Dc&token=***&a=%E4%B8%AD"; got != want {
		t.Fatalf("\n实际 %s\n期望 %s", got, want)
	}
}

// 键的大小写、以及转义过的键名都要挡住（url.ParseQuery 会解码键，这里也得解一次）。
func TestRedactQueryKeepingRawMasksEncodedKey(t *testing.T) {
	for _, raw := range []string{"Token=abc", "to%6Ben=abc", "ACCESS_TOKEN=abc", "secret=abc"} {
		if got := redactQueryKeepingRaw(raw, sourceQueryMax); strings.Contains(got, "abc") {
			t.Errorf("%q 没打码：%s", raw, got)
		}
	}
}

// 形如 ?debug 的裸参数没有值可打码，原样留着（丢掉它就是改了对方发来的请求）。
func TestRedactQueryKeepingRawBareParam(t *testing.T) {
	if got := redactQueryKeepingRaw("debug&token=abc&x", sourceQueryMax); got != "debug&token=***&x" {
		t.Fatalf("实际 %s", got)
	}
	if got := redactQueryKeepingRaw("", sourceQueryMax); got != "" {
		t.Fatalf("空查询串期望空，实际 %q", got)
	}
}

// 长度闸：截断处剩下的那半个参数不能把凭证漏出来。
func TestRedactQueryKeepingRawLengthCap(t *testing.T) {
	raw := "a=" + strings.Repeat("1", 100) + "&token=" + strings.Repeat("s", 100)
	got := redactQueryKeepingRaw(raw, 64)
	if len(got) > 64+len("…") {
		t.Fatalf("留存 %d 字节，超过上限 64", len(got))
	}
	if strings.Contains(got, "sss") {
		t.Fatalf("凭证漏出来了：%s", got)
	}
}
