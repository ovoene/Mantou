package logx

import (
	"encoding/json"
	"fmt"
	"runtime"
	"strings"
	"testing"
	"time"
	"unsafe"
)

// 本文件盯的是「日志字段表从 map 换成切片」这件事（3-I）：
//
//   - 接口形状不能变（前端 Overview.vue 用 Object.entries 渲染，变成数组就直接空掉）；
//   - 同名字段仍然只显示一个；
//   - 字段顺序现在是确定的，这是换切片顺带拿到的好处，值得钉住；
//   - 省下来的内存要能被测出来，否则这条修复没有任何可验证的收益。

// TestFieldsJSONShapeUnchanged 字段表在接口上必须仍是一个 JSON 对象。
//
// 这是本次改动唯一外部可见的约束：内存里是切片，线上仍要是 {"host":"…"}。
// 若哪天有人删掉 Fields.MarshalJSON，这条会立刻失败——而线上表现只是日志面板
// 悄悄不显示字段了，没人会立刻发现。
func TestFieldsJSONShapeUnchanged(t *testing.T) {
	log := New(Options{})
	log.Info("面板访问", "host", "panel.example.com", "status", 200, "ok", true)

	items := log.Recent(10)
	if len(items) != 1 {
		t.Fatalf("期望 1 条日志，得到 %d", len(items))
	}
	raw, err := json.Marshal(items[0])
	if err != nil {
		t.Fatalf("序列化失败：%v", err)
	}

	// 形状：fields 必须是对象而不是数组。
	var probe struct {
		Fields json.RawMessage `json:"fields"`
	}
	if err := json.Unmarshal(raw, &probe); err != nil {
		t.Fatalf("反序列化失败：%v\n%s", err, raw)
	}
	if len(probe.Fields) == 0 || probe.Fields[0] != '{' {
		t.Fatalf("fields 必须是 JSON 对象，实际是 %s", probe.Fields)
	}

	// 内容：键名与值都要与原来经 map 序列化时一致。
	var got map[string]any
	if err := json.Unmarshal(probe.Fields, &got); err != nil {
		t.Fatalf("fields 不是合法对象：%v", err)
	}
	for k, want := range map[string]any{
		"host":   "panel.example.com",
		"status": float64(200), // JSON 数字统一解回 float64
		"ok":     true,
	} {
		if got[k] != want {
			t.Errorf("fields[%q] = %#v，期望 %#v", k, got[k], want)
		}
	}
	if len(got) != 3 {
		t.Errorf("fields 应有 3 个键，实际 %d 个：%v", len(got), got)
	}
}

// TestFieldsEmptyIsOmitted 没有字段时 fields 这个键整个不出现。
//
// 原来是 map，omitempty 对空 map 生效；换切片后要靠「一个字段都没有就保持 nil」。
// 若写成 make(Fields, 0, 0)，omitempty 仍然生效（长度为 0），但白分配一次——
// 所以这里同时断言键不存在与切片为 nil。
func TestFieldsEmptyIsOmitted(t *testing.T) {
	log := New(Options{})
	log.Info("Web 服务已启动")

	items := log.Recent(10)
	if len(items) != 1 {
		t.Fatalf("期望 1 条日志，得到 %d", len(items))
	}
	if items[0].Fields != nil {
		t.Errorf("无字段日志不该分配字段表，实际 %#v", items[0].Fields)
	}
	raw, err := json.Marshal(items[0])
	if err != nil {
		t.Fatalf("序列化失败：%v", err)
	}
	if strings.Contains(string(raw), `"fields"`) {
		t.Errorf("无字段日志不该带 fields 键：%s", raw)
	}
}

// TestFieldsKeepsWriteOrder 字段顺序固定：先处理器固有字段，再本次调用的字段。
//
// map 的迭代顺序是随机的，同一条日志两次刷新在面板上字段会前后颠倒；切片没有这个问题。
// 顺序同时是长度预算的消耗顺序（见 clipLogText 的说明），所以「哪一段先被裁掉」也随之确定。
func TestFieldsKeepsWriteOrder(t *testing.T) {
	log := New(Options{})
	log.With("module", "webservice").WithGroup("req").Info("面板访问", "ip", "127.0.0.1", "status", 200)

	items := log.Recent(10)
	if len(items) != 1 {
		t.Fatalf("期望 1 条日志，得到 %d", len(items))
	}
	var keys []string
	for _, kv := range items[0].Fields {
		keys = append(keys, kv.Key)
	}
	want := []string{"module", "req.ip", "req.status"}
	if fmt.Sprint(keys) != fmt.Sprint(want) {
		t.Fatalf("字段顺序应为 %v，实际 %v", want, keys)
	}

	// JSON 里的键序也跟着走：手写的 MarshalJSON 按切片顺序输出。
	raw, err := json.Marshal(items[0].Fields)
	if err != nil {
		t.Fatalf("序列化失败：%v", err)
	}
	if want := `{"module":"webservice","req.ip":"127.0.0.1","req.status":200}`; string(raw) != want {
		t.Fatalf("序列化结果应为 %s，实际 %s", want, raw)
	}
}

// TestWithGroupDoesNotSwallowEarlierAttrs 分组只作用于它之后添加的字段。
//
// 这是写上面那条顺序测试时暴露出来的既有 bug：原先 Handle 对处理器固有字段统一套当前分组名，
// 于是 With("module", …) 之后再 WithGroup("req")，先加的 module 会被追认成 req.module。
// 现有代码一处 WithGroup 都没有，所以它在生产里从未显形——正因如此才需要一条测试盯着，
// 否则等到第一次真的用上分组时，面板上的字段名会莫名其妙多一截前缀。
func TestWithGroupDoesNotSwallowEarlierAttrs(t *testing.T) {
	log := New(Options{})

	// 先加字段再进分组：字段不属于该分组。
	log.With("module", "webservice").WithGroup("req").Info("面板访问", "ip", "127.0.0.1")
	// 先进分组再加字段：字段属于该分组。
	log.WithGroup("cert").With("id", "c1").Info("证书续期")
	// 分组套分组：前缀按进入顺序累积。
	log.WithGroup("a").WithGroup("b").With("k", "v").Info("嵌套分组")

	items := log.Recent(10)
	if len(items) != 3 {
		t.Fatalf("期望 3 条日志，得到 %d", len(items))
	}
	for i, want := range [][]string{
		{"module", "req.ip"},
		{"cert.id"},
		{"a.b.k"},
	} {
		var keys []string
		for _, kv := range items[i].Fields {
			keys = append(keys, kv.Key)
		}
		if fmt.Sprint(keys) != fmt.Sprint(want) {
			t.Errorf("第 %d 条日志的字段名应为 %v，实际 %v", i+1, want, keys)
		}
	}
}

// TestFieldsDuplicateKeyOverwrites 同名字段只留最后一个，与换掉 map 之前一致。
//
// 来源是 logger.With("k", …) 之后调用方又传了一个同名字段。map 是后写覆盖先写，
// 切片若直接 append 就会变成两条同名字段——JSON 对象里出现重复键，浏览器解析后
// 只留最后一个，看着"没坏"，但载荷白涨、面板与磁盘日志的字段数也对不上了。
func TestFieldsDuplicateKeyOverwrites(t *testing.T) {
	log := New(Options{})
	log.With("module", "webservice").Info("接管", "module", "webhook")

	items := log.Recent(10)
	if len(items) != 1 {
		t.Fatalf("期望 1 条日志，得到 %d", len(items))
	}
	if n := len(items[0].Fields); n != 1 {
		t.Fatalf("同名字段应只留一个，实际 %d 个：%#v", n, items[0].Fields)
	}
	if got := items[0].Fields.Get("module"); got != "webhook" {
		t.Fatalf("同名字段应后写覆盖先写，实际 %#v", got)
	}
}

// TestFieldsGetMissingKey 取不存在的字段返回 nil，不是 panic、也不是零值字符串。
func TestFieldsGetMissingKey(t *testing.T) {
	log := New(Options{})
	log.Info("面板访问", "host", "panel.example.com")
	items := log.Recent(10)
	if got := items[0].Fields.Get("没有这个字段"); got != nil {
		t.Fatalf("取不存在的字段应得 nil，实际 %#v", got)
	}
	var empty Fields
	if got := empty.Get("host"); got != nil {
		t.Fatalf("空字段表取值应得 nil，实际 %#v", got)
	}
}

// TestEntryLayoutMatchesComment 把占用注释里那几个数字钉成算术，而不是靠人记得去重测。
//
// 「n 个字段付 n×32 字节」这句话由三件事支撑：Field 就是 32 字节、Entry 就是 80 字节、
// 字段表的容量恰好等于字段个数（不预留、不翻倍）。任何一条被改掉，注释里的占用表就不成立了。
func TestEntryLayoutMatchesComment(t *testing.T) {
	if got := unsafe.Sizeof(Field{}); got != 32 {
		t.Errorf("Field 应为 32 字节（键 16 + 值 16），实际 %d——占用注释要跟着改", got)
	}
	if got := unsafe.Sizeof(Entry{}); got != 80 {
		t.Errorf("Entry 应为 80 字节（Time 24 + Level 16 + Message 16 + 切片头 24），实际 %d", got)
	}

	log := New(Options{})
	log.Info("面板访问", "module", "webservice", "ip", "127.0.0.1")
	f := log.Recent(1)[0].Fields
	if len(f) != 2 || cap(f) != 2 {
		t.Fatalf("2 个字段的字段表应当 len=cap=2（不预留空槽），实际 len=%d cap=%d", len(f), cap(f))
	}
}

// TestFieldsCostLessThanMap 把「换切片真的省了内存」测出来。
//
// 同一次运行里造两批 5000 条，一批用 map 一批用切片，字段名与值完全相同，只差数据结构。
// 实测（Go 1.26）2 字段时 map 441 B/条、切片 184 B/条，差 257 B；阈值取 100 B 是给
// GC 时机与不同 Go 版本留的余量——它要挡住的是「有人把字段表改回 map」这种整类回退，
// 不是去精确复现某个数字。
//
// 注意对照里已经把切片版每槽多出的 16 字节算进去了（mapEntry 64 B/槽，Entry 80 B/槽），
// 所以这个差值就是净收益，不需要再扣。
func TestFieldsCostLessThanMap(t *testing.T) {
	const n = 5000
	perMap := measureMapEntries(t, n)
	perSlice := measureSliceEntries(t, n)
	t.Logf("%d 条 × %d 字段：map %.0f B/条，切片 %.0f B/条，省 %.0f B/条（合计 %.2f MB）",
		n, len(sampleFields), perMap, perSlice, perMap-perSlice, (perMap-perSlice)*n/1024/1024)

	if perMap-perSlice < 100 {
		t.Fatalf("切片版应比 map 版每条至少省 100 B，实际 map %.0f B/条、切片 %.0f B/条", perMap, perSlice)
	}
}

// sampleFields 是对照用的字段，取项目里最常见的形态：模块名 + 一个地址。
var sampleFields = []struct{ key, val string }{
	{"module", "webservice"},
	{"ip", "127.0.0.1"},
}

// mapEntry 是换掉 map 之前的 Entry 形状，只在这份对照里出现。
type mapEntry struct {
	Time    time.Time
	Level   string
	Message string
	Fields  map[string]any
}

// memSink 让被测那批数据活到测量结束——被 GC 掉就什么都测不到了。
var memSink []any

func measureMapEntries(t *testing.T, n int) float64 {
	t.Helper()
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	buf := make([]mapEntry, n)
	for i := range buf {
		m := make(map[string]any, len(sampleFields))
		for _, f := range sampleFields {
			m[f.key] = f.val
		}
		buf[i] = mapEntry{Time: time.Now(), Level: "INFO", Message: "面板访问", Fields: m}
	}
	runtime.GC()
	runtime.ReadMemStats(&after)
	memSink = append(memSink, buf)
	return float64(after.HeapAlloc-before.HeapAlloc) / float64(n)
}

func measureSliceEntries(t *testing.T, n int) float64 {
	t.Helper()
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	buf := make([]Entry, n)
	for i := range buf {
		s := make(Fields, 0, len(sampleFields))
		for _, f := range sampleFields {
			s = s.set(f.key, f.val)
		}
		buf[i] = Entry{Time: time.Now(), Level: "INFO", Message: "面板访问", Fields: s}
	}
	runtime.GC()
	runtime.ReadMemStats(&after)
	memSink = append(memSink, buf)
	return float64(after.HeapAlloc-before.HeapAlloc) / float64(n)
}
