package webhook

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"mantou/internal/config"
)

// buildFor 用给定的请求头 / query 组一次入站请求并组装信封。
func buildFor(t *testing.T, r *receiverRT, raw, contentType, rawQuery string, header http.Header) *event {
	t.Helper()
	url := "/" + r.cfg.Path
	if rawQuery != "" {
		url += "?" + rawQuery
	}
	req := httptest.NewRequest(http.MethodPost, url, nil)
	for k, vs := range header {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	return buildEvent(r, req, []byte(raw), "203.0.113.9")
}

func str(t *testing.T, root map[string]any, key string) string {
	t.Helper()
	v, ok := root[key]
	if !ok {
		t.Fatalf("信封里缺少键 %q", key)
	}
	s, ok := v.(string)
	if !ok {
		t.Fatalf("键 %q 应是字符串，实际 %T", key, v)
	}
	return s
}

// ---------- 信封 ----------

func TestBuildEventEnvelope(t *testing.T) {
	r := newRT(t, config.WebhookReceiver{ID: "rid", Name: "第三方系统", Path: "hook"})
	ev := buildFor(t, r, sampleBody, "application/json", "env=prod", nil)

	// ReservedFieldNames 是给 API 校验与前端提示用的清单，必须与信封实际注入的键一致：
	// 少一个就会让用户用同名映射覆盖掉信封键而收不到任何提示。
	for _, k := range ReservedFieldNames {
		if _, ok := ev.Root[k]; !ok {
			t.Errorf("信封应包含保留键 %q", k)
		}
	}
	if len(ev.Root) != len(ReservedFieldNames) {
		t.Fatalf("无映射时信封键数应等于保留键数（%d），实际 %d", len(ReservedFieldNames), len(ev.Root))
	}

	if got := str(t, ev.Root, "method"); got != http.MethodPost {
		t.Errorf("method 不符：%q", got)
	}
	if got := str(t, ev.Root, "path"); got != "hook" {
		t.Errorf("path 应是接收器配置的路径：%q", got)
	}
	if got := str(t, ev.Root, "ip"); got != "203.0.113.9" {
		t.Errorf("ip 不符：%q", got)
	}
	if got := str(t, ev.Root, "source"); got != "第三方系统" {
		t.Errorf("source 应是接收器名：%q", got)
	}
	if got := str(t, ev.Root, "receiverId"); got != "rid" {
		t.Errorf("receiverId 不符：%q", got)
	}
	if got := str(t, ev.Root, "eventId"); got != ev.ID {
		t.Errorf("eventId 应与事件 ID 一致：%q vs %q", got, ev.ID)
	}
	if string(ev.Raw) != sampleBody {
		t.Error("Raw 应保留原始请求体")
	}

	// receivedAt 走 tmplx.Normalize：不这么做的话 {{formatTime}} 在
	// "真实推送"与"面板试运行"两条路径上会拿到不同类型的时间值。
	ts, ok := ev.Root["receivedAt"].(json.Number)
	if !ok {
		t.Fatalf("receivedAt 应是 json.Number，实际 %T", ev.Root["receivedAt"])
	}
	sec, err := ts.Int64()
	if err != nil || sec < time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC).Unix() {
		t.Fatalf("receivedAt 不像一个 Unix 秒：%v %v", ts, err)
	}
}

// RootPath 是"不写死任何一家结构"的落点：填了 body 之后模板里写 {{.消息类型}}，
// 不填则从信封根取值。两种写法都必须同时有效。
func TestBuildEventRootPathSpread(t *testing.T) {
	r := newRT(t, config.WebhookReceiver{Path: "hook", RootPath: "body"})
	ev := buildFor(t, r, sampleBody, "application/json", "", nil)

	if got := str(t, ev.Root, "消息类型"); got != "每日汇总" {
		t.Fatalf("RootPath 指向的子对象应摊到根上：%q", got)
	}
	// 摊开不代表原路径失效：显式写全路径永远有效。
	body, _ := ev.Root["body"].(map[string]any)
	if body == nil || body["消息类型"] != "每日汇总" {
		t.Fatalf("body.消息类型 也应仍然取得到：%v", ev.Root["body"])
	}
}

// 载荷里正好有个字段叫 path / source 时，信封键要压过它——否则
// {{.source}} 会时而是来源名、时而是对方载荷里的某个业务字段。
func TestBuildEventEnvelopeOverridesRootPathKeys(t *testing.T) {
	const raw = `{"body":{"path":"对方的路径","source":"对方的来源","编号":"X1"}}`
	r := newRT(t, config.WebhookReceiver{Path: "hook", Name: "第三方系统", RootPath: "body.body"})
	ev := buildFor(t, r, raw, "application/json", "", nil)

	if got := str(t, ev.Root, "path"); got != "hook" {
		t.Fatalf("信封的 path 应压过载荷同名字段：%q", got)
	}
	if got := str(t, ev.Root, "source"); got != "第三方系统" {
		t.Fatalf("信封的 source 应压过载荷同名字段：%q", got)
	}
	if got := str(t, ev.Root, "编号"); got != "X1" {
		t.Fatalf("非同名字段应正常摊开：%q", got)
	}
}

// 载荷内部的子对象也要认：Uptime Kuma 把数据放在 heartbeat 下，
// 用户不该需要先搞清楚"这一栏是相对信封还是相对载荷"。
func TestBuildEventRootPathFallsBackToPayload(t *testing.T) {
	r := newRT(t, config.WebhookReceiver{Path: "kuma", RootPath: "heartbeat"})
	ev := buildFor(t, r, `{"heartbeat":{"msg":"服务不可用","status":0},"monitor":{"name":"官网"}}`,
		"application/json", "", nil)

	if got := str(t, ev.Root, "msg"); got != "服务不可用" {
		t.Fatalf("载荷内部的子对象应摊到根上：%q", got)
	}
	if _, ok := ev.Root["monitor"]; ok {
		t.Fatal("只该摊开 RootPath 指向的那一层")
	}
}

// 信封与载荷都能解出同名子对象时，以信封为准：界面上默认填的 body
// 必须稳定地表示"请求体根"，不能因为对方载荷里恰好也有个 body 字段就换一层。
func TestBuildEventRootPathPrefersEnvelope(t *testing.T) {
	r := newRT(t, config.WebhookReceiver{Path: "hook", RootPath: "body"})
	ev := buildFor(t, r, `{"body":{"内层":1},"外层":2}`, "application/json", "", nil)

	if _, ok := ev.Root["外层"]; !ok {
		t.Fatalf("应摊开整个请求体：%v", ev.Root)
	}
	if _, ok := ev.Root["内层"]; ok {
		t.Fatal("不该改去摊开载荷内部的同名字段")
	}
}

// 请求体不是对象时不该 panic，也不该摊开任何东西。
func TestBuildEventRootPathOnNonObjectBody(t *testing.T) {
	r := newRT(t, config.WebhookReceiver{Path: "hook", RootPath: "body"})
	for _, raw := range []string{"消息已提交", `[1,2,3]`, ""} {
		ev := buildFor(t, r, raw, "application/json", "", nil)
		if len(ev.Root) != len(ReservedFieldNames) {
			t.Errorf("载荷 %q 不该摊出额外的键：%v", raw, ev.Root)
		}
	}
}

// 字段映射最后注入：短名是用户显式起的，理应压过一切默认键。
func TestBuildEventMappingWinsOverEnvelope(t *testing.T) {
	r := newRT(t, config.WebhookReceiver{Path: "hook", Name: "第三方系统", Mappings: []config.FieldMapping{
		{Name: "source", Path: "body.消息类型"},
	}})
	ev := buildFor(t, r, sampleBody, "application/json", "", nil)
	if got := str(t, ev.Root, "source"); got != "每日汇总" {
		t.Fatalf("显式映射应压过信封键：%q", got)
	}
}

func TestBuildEventMappingPaths(t *testing.T) {
	r := newRT(t, config.WebhookReceiver{Path: "hook", Mappings: []config.FieldMapping{
		{Name: "全路径", Path: "body.消息类型"},
		// 用户填 "消息类型" 而不是 "body.消息类型" 是很常见的写法，
		// 根上取不到时要再在 body 下试一次，否则这类配置全部静默落到默认值。
		{Name: "省略前缀", Path: "消息类型"},
		{Name: "取头", Path: "headers.x-source"},
		{Name: "取query", Path: "query.env"},
		{Name: "有默认值", Path: "body.没有这个字段", Default: "未填"},
		{Name: "无默认值", Path: "body.也没有"},
	}})
	ev := buildFor(t, r, sampleBody, "application/json", "env=prod",
		http.Header{"X-Source": []string{"sys-a"}})

	want := map[string]string{
		"全路径":    "每日汇总",
		"省略前缀":   "每日汇总",
		"取头":     "sys-a",
		"取query": "prod",
		"有默认值":   "未填",
		"无默认值":   "",
	}
	for k, v := range want {
		if got := str(t, ev.Root, k); got != v {
			t.Errorf("映射 %q 应取到 %q，实际 %q", k, v, got)
		}
	}
	// 取不到值的映射名要回报给试运行页，否则用户只看到一个空字段，
	// 分不清"对方没发"还是"路径写错了"。
	if len(ev.Unresolved) != 2 {
		t.Fatalf("应记下 2 个取不到值的映射：%v", ev.Unresolved)
	}
	for _, name := range ev.Unresolved {
		if name != "有默认值" && name != "无默认值" {
			t.Errorf("Unresolved 里出现了意外的名字：%q", name)
		}
	}
}

// 19 位消息号必须原样进模板：走 float64 会被改写成另一个数字。
func TestBuildEventKeepsBigNumbers(t *testing.T) {
	r := newRT(t, config.WebhookReceiver{Path: "hook", RootPath: "body"})
	ev := buildFor(t, r, `{"内部编号":1234567890123456789,"数值":1580.50}`,
		"application/json", "", nil)

	if n, ok := ev.Root["内部编号"].(json.Number); !ok || n.String() != "1234567890123456789" {
		t.Fatalf("19 位整数应原样保留：%v (%T)", ev.Root["内部编号"], ev.Root["内部编号"])
	}
	if n, ok := ev.Root["数值"].(json.Number); !ok || n.String() != "1580.50" {
		t.Fatalf("小数应保留源系统发来的原始文本：%v", ev.Root["数值"])
	}
}

// ---------- 请求头 ----------

func TestHeaderMapRedaction(t *testing.T) {
	h := http.Header{
		"Authorization":       []string{"Bearer 秘密"},
		"Cookie":              []string{"sid=abc"},
		"X-Mantou-Token":      []string{"面板令牌"},
		"Proxy-Authorization": []string{"Basic xxx"},
		"X-Sign":              []string{"签名值"},
		"X-Event-Type":        []string{"purchase"},
		"X-Multi":             []string{"a", "b"},
	}
	// 接收器自己那个鉴权头也要脱敏，且大小写不敏感。
	got := headerMap(h, "  x-SIGN  ")

	for _, k := range []string{"authorization", "cookie", "x-mantou-token", "proxy-authorization", "x-sign"} {
		if got[k] != "***" {
			t.Errorf("请求头 %q 应被脱敏，实际 %v", k, got[k])
		}
	}
	// 键统一小写：同一个来源换个客户端库就可能把 X-Event-Type 发成 X-EVENT-TYPE，
	// 保留原样会让规则突然不命中。
	if got["x-event-type"] != "purchase" {
		t.Errorf("键应转小写：%v", got)
	}
	if got["x-multi"] != "a, b" {
		t.Errorf("多值头应用 \", \" 连接：%v", got["x-multi"])
	}
	if _, ok := got["X-Event-Type"]; ok {
		t.Error("不该同时保留原始大小写的键")
	}

	// AuthHeader 留空时不该把某个头误当凭证。
	plain := headerMap(h, "")
	if plain["x-sign"] != "签名值" {
		t.Errorf("未配置鉴权头时 x-sign 应原样进模板：%v", plain["x-sign"])
	}
}

func TestQueryMap(t *testing.T) {
	got := queryMap(httptest.NewRequest(http.MethodGet, "/x?a=1&b=x&b=y&c=", nil).URL.Query())
	if got["a"] != "1" || got["b"] != "x, y" || got["c"] != "" {
		t.Fatalf("query 解析不符：%v", got)
	}
}

// ---------- 请求体解码 ----------

// decodeBody 的第二个参数是用户在界面上选的「来源消息类型」（json / kv / txt），
// **不是** Content-Type：真实的推送方经常把 JSON 标成 text/plain 或干脆不带，
// 按声明的类型走会把一份完好的 JSON 当纯文本处理，
// 用户随后配的所有路径都取不到值。
func TestDecodeBody(t *testing.T) {
	t.Run("JSON对象", func(t *testing.T) {
		v, ok := decodeBody([]byte(`{"a":1}`), "json", "", "").(map[string]any)
		if !ok || v["a"] != json.Number("1") {
			t.Fatalf("应解成对象：%#v", v)
		}
	})

	// 留空即自动识别（与 auto 同义）：老配置里没有这个字段，
	// 而自动识别下 JSON 的处理与选定 json 完全一致。
	t.Run("类型留空按自动识别", func(t *testing.T) {
		v, ok := decodeBody([]byte(`  {"a":1}  `), "", "", "").(map[string]any)
		if !ok || v["a"] != json.Number("1") {
			t.Fatalf("留空应按 JSON 解：%#v", v)
		}
	})

	t.Run("JSON数组", func(t *testing.T) {
		v, ok := decodeBody([]byte(`[{"a":1}]`), "json", "", "").([]any)
		if !ok || len(v) != 1 {
			t.Fatalf("应解成数组：%#v", v)
		}
	})

	// 选了 json 就按 json 解，表单串整段进 body（一个字符串），模板里写 {{.body}}。
	// 要把它拆成字段是「键值文本」（kv）的活，见 TestDecodeKV——两者的区别必须由
	// 用户在界面上选定，而不是由 decodeBody 看着内容猜。
	t.Run("表单整段进body", func(t *testing.T) {
		const form = "a=1&b=2"
		if v := decodeBody([]byte(form), "json", "", ""); v != form {
			t.Fatalf("表单应原样交出：%#v", v)
		}
	})

	// txt 选了就按 txt 处理，即便这段内容恰好是合法 JSON——
	// 用户明确选过的东西不该被"猜"覆盖掉。
	t.Run("txt原样", func(t *testing.T) {
		if v := decodeBody([]byte(`  {"a":1}  `), "txt", "", ""); v != `{"a":1}` {
			t.Fatalf("txt 应原样返回并去掉首尾空白：%#v", v)
		}
	})

	// 既不是 JSON 也不是 txt 就原样交出去：模板里 {{.body}} 至少能整段发出来，
	// 用户看一眼就知道该怎么配——比一个 400 有用得多。
	t.Run("纯文本原样", func(t *testing.T) {
		if v := decodeBody([]byte("  消息已提交  "), "json", "", ""); v != "消息已提交" {
			t.Fatalf("应原样返回并去掉首尾空白：%#v", v)
		}
	})

	t.Run("坏JSON退回纯文本", func(t *testing.T) {
		const bad = `{"a":`
		if v := decodeBody([]byte(bad), "json", "", ""); v != bad {
			t.Fatalf("解不动的 JSON 应原样交出：%#v", v)
		}
	})

	t.Run("空体", func(t *testing.T) {
		for _, raw := range []string{"", "   \n\t"} {
			v, ok := decodeBody([]byte(raw), "json", "", "").(map[string]any)
			if !ok || len(v) != 0 {
				t.Errorf("空体应给空对象而不是 nil，避免模板取值时 panic：%#v", v)
			}
		}
	})
}

// ---------- 来源消息类型 ----------

// txt 是"对方发的不是 JSON"这件事的唯一正确处理方式：整段原样进 body，
// 模板里写 {{.body}}。按 JSON 解会得到一个字符串，取值路径全部落空。
func TestDecodeBodyTxtKeepsRawText(t *testing.T) {
	r := newRT(t, config.WebhookReceiver{Path: "hook", SourceType: "txt"})
	ev := buildFor(t, r, `{"biz":"每日汇总"}`, "application/json", "", nil)
	// 选了 txt 就按 txt 处理，即便这段内容恰好是合法 JSON——
	// 用户明确选过的东西不该被"猜"覆盖掉。
	if got, ok := ev.Root["body"].(string); !ok || got != `{"biz":"每日汇总"}` {
		t.Fatalf("txt 应原样进 body：%#v", ev.Root["body"])
	}
}

// json 解不出时退回字符串而不是报错：用户在试运行页上直接看到对方发的到底是什么。
func TestDecodeBodyJSONFallsBackToString(t *testing.T) {
	r := newRT(t, config.WebhookReceiver{Path: "hook"})
	ev := buildFor(t, r, "消息已提交", "application/json", "", nil)
	if got, ok := ev.Root["body"].(string); !ok || got != "消息已提交" {
		t.Fatalf("解不出的 JSON 应退回字符串：%#v", ev.Root["body"])
	}
}

// 空体给空对象而不是空字符串：模板对 nil 取值会 panic。
func TestDecodeBodyEmptyGivesObject(t *testing.T) {
	if v, ok := decodeBody(nil, "json", "", "").(map[string]any); !ok || len(v) != 0 {
		t.Fatalf("空体应给空对象：%#v", decodeBody(nil, "json", "", ""))
	}
	if v := decodeBody([]byte("  "), "txt", "", ""); v != "" {
		t.Fatalf("txt 空体应给空字符串：%#v", v)
	}
}

// SniffSourceType 的结论会被试运行**回写**进「来源消息类型」下拉框，
// 所以它必须只在确定时表态：空体返回空串（不猜），其余三选一。
func TestSniffSourceType(t *testing.T) {
	cases := []struct{ raw, want string }{
		{"", ""},
		{"   ", ""},
		{`{"a":1}`, "json"},
		{"  [1,2]  ", "json"},
		{"消息已提交", "txt"},
		{"123", "txt"},    // 合法 JSON，但没人会为一个裸数字配取值路径
		{`{"a":1`, "txt"}, // 看着像 JSON 却解不出：按 txt 处理才能让用户看到原文
		{"{}extra", "txt"},
		// 键值文本：拆得出两个以上字段才敢表态。
		{"code=测试消息&biz=每日汇总&keyField=2026-08-24 11:44:25&creator=adm", "kv"},
		{"code=A1\nbiz=B1", "kv"},
		{"level: error\nmsg: disk full", "kv"},
		{"总数=100", "txt"},       // 只有一个字段：证据不足，不改用户的选择
		{"告警：磁盘满了", "txt"},      // 中文冒号本就不是候选分隔符
		{"告警: 磁盘满了", "txt"},     // 一个冒号的句子，同样是证据不足
		{`{"a":1,"b":2`, "txt"}, // 被截断的 JSON 能按逗号+冒号拆出两段，但不该判成 kv
		{"2026-08-24 11:00:00 ERROR: disk full\n2026-08-24 11:00:01 ERROR: retry", "txt"}, // 键里带空格 → 不是字段
		// 开头带 UTF-8 BOM / 零宽空格的 JSON。这两个字节看不见，但会让"第一个字符是不是 {"
		// 判错，从而落到 kv 那条判据上（JSON 按逗号+冒号能拆出一堆"字段"）。
		// 一旦判成 kv 并被试运行回写进下拉框，之后连正常 JSON 也会被拆坏。
		{"\ufeff" + `{"a":1,"b":2}`, "json"},
		{"\u200b" + `{"a":1,"b":2}`, "json"},
	}
	for _, c := range cases {
		if got := SniffSourceType([]byte(c.raw)); got != c.want {
			t.Errorf("SniffSourceType(%q) = %q，期望 %q", c.raw, got, c.want)
		}
	}
}

// 这份载荷是线上真实收到的那一条：一条消息 + 若干条记录。
const multiItemJSON = `{"biz":"每日汇总-超时未处理","code":"A26071442","keyField":"33","creator":"定时任务","items":[{"creator":"甲","keyField":"33","code":"A26071442"},{"creator":"乙","keyField":"32","code":"A26071444，A26071447"}]}`

// 「来源消息类型」选了键值文本、对方却推来一份 JSON——这两件事一定会同时发生：
// 同一个来源既有旧接口的 a=1&b=2 也有新接口的 JSON，或者用户拿 kv 试过一次没改回来，
// 或者 BOM 让试运行把类型判成了 kv 并回写进去（见上一个用例）。
//
// 这种组合曾经把载荷拆成一堆名叫 `{"biz"`、`"code"` 的假字段（同名的用 ", " 连起来），
// 字段树看着像解出来了，而所有取值路径与规则条件全部落空——用户能看到的只有
// "规则不命中"，从那里根本查不到原因。JSON 一律按 JSON 解。
func TestDecodeBodyKVNeverEatsJSON(t *testing.T) {
	// 手填了分隔符也一样：分隔符说的是"这段键值文本怎么拆"，不是"把 JSON 也拆开"。
	for _, seps := range [][2]string{{"", ""}, {"&", "="}, {",", ":"}} {
		got := decodeBody([]byte(multiItemJSON), "kv", seps[0], seps[1])
		m, ok := got.(map[string]any)
		if !ok {
			t.Fatalf("分隔符 %q/%q：合法 JSON 必须按 JSON 解，实际 %T", seps[0], seps[1], got)
		}
		if m["biz"] != "每日汇总-超时未处理" {
			t.Errorf("分隔符 %q/%q：biz 应是原值，实际 %#v", seps[0], seps[1], m["biz"])
		}
		if items, isArr := m["items"].([]any); !isArr || len(items) != 2 {
			t.Errorf("分隔符 %q/%q：items 应仍是两条记录的数组，实际 %#v", seps[0], seps[1], m["items"])
		}
		if _, bad := m[`{"biz"`]; bad {
			t.Errorf("分隔符 %q/%q：出现了按符号硬拆出来的假字段名，JSON 被键值解码器啃了", seps[0], seps[1])
		}
	}
}

// 反过来不成立：选了 json、收到的是键值文本时**不**替用户改主意（见 TestDecodeBody
// 的「表单整段进body」）。这条不对称是有意的——JSON 那一侧由 json.Valid 说了算，
// 没有猜的成分；而 kv 的判据（一个冒号就算一对）是猜的，猜错的表现是字段树里全是垃圾。

// 请求体开头的 UTF-8 BOM / 零宽空格必须当不存在。
//
// 它们在界面上、在抓包里都看不见，却会让 json.Valid 判假：一份完好的 JSON 变成一个
// 字符串进 body，用户配的每条路径与每条规则条件全部落空，而请求体看起来完全正常。
// .NET / Java 以带 BOM 的 UTF-8 写请求体是常见做法，这不是边角情况。
func TestDecodeBodyIgnoresInvisiblePrefix(t *testing.T) {
	for _, prefix := range []string{"\ufeff", "\u200b", "\ufeff\n  ", "  \ufeff"} {
		for _, st := range []string{"json", "kv", ""} {
			got := decodeBody([]byte(prefix+multiItemJSON), st, "", "")
			m, ok := got.(map[string]any)
			if !ok {
				t.Fatalf("前缀 %q + 类型 %q：应解成对象，实际 %T", prefix, st, got)
			}
			if m["code"] != "A26071442" {
				t.Errorf("前缀 %q + 类型 %q：code 取不到，实际 %#v", prefix, st, m["code"])
			}
		}
		// txt 仍然原样交出正文，只是不把那个看不见的字节也带进消息里。
		if got := decodeBody([]byte(prefix+"消息已提交"), "txt", "", ""); got != "消息已提交" {
			t.Errorf("前缀 %q：txt 应交出干净的正文，实际 %#v", prefix, got)
		}
	}
}

// 字段名里出现 JSON 的结构符号，说明拆的其实是结构化文本，不是键值文本。
// 拆出的字段数必须够不上 minKVPairs——界面上「按「,」分字段…拆出 N 个字段」这句提示
// 读的就是它，报一个虚高的数字比不报更糟：用户会以为配对了。
func TestSniffKVRejectsJSONShapedText(t *testing.T) {
	for _, raw := range []string{
		multiItemJSON,
		`{"a":1,"b":2`,       // 被截断的 JSON
		`[{"a":1},{"a":2}]`,  // JSON 数组
		`msg: {"a":1,"b":2}`, // 日志行里嵌了一段 JSON（能切出 msg 一个字段，但一个够不上门槛）
	} {
		if _, _, pairs := sniffKV(raw, "", ""); pairs >= minKVPairs {
			t.Errorf("sniffKV(%q) 拆出了 %d 个字段，结构化文本不该被当成键值文本", raw, pairs)
		}
	}
}

// ---------- 自动识别 ----------

// 这是「不写代码」在解析这一步的落点：用户不必先搞清楚对方发的是什么格式，
// 也不必为"这个来源偶尔发另一种格式"再开一个接收器。
//
// 同一个来源发 JSON 与发键值文本时，字段名往往是同一套（下面两条样本就是），
// 于是同一条规则、同一个模板对两种格式都成立——这正是自动识别要保住的东西。
func TestDecodeBodyAuto(t *testing.T) {
	const kvText = "code=A26071442&biz=每日汇总-超时未处理&keyField=33&creator=定时任务"

	t.Run("同一套字段名两种格式都取得到", func(t *testing.T) {
		for _, raw := range []string{multiItemJSON, kvText} {
			m, ok := decodeBody([]byte(raw), "auto", "", "").(map[string]any)
			if !ok {
				t.Fatalf("%.20s… 应解成字段表", raw)
			}
			if m["biz"] != "每日汇总-超时未处理" || m["code"] != "A26071442" {
				t.Errorf("%.20s… 的 biz / code 取不到：%#v / %#v", raw, m["biz"], m["code"])
			}
		}
	})

	// JSON 的数组必须还是数组：条目那一层被拆平就没法在模板里逐条列了。
	t.Run("JSON条目仍是数组", func(t *testing.T) {
		m, _ := decodeBody([]byte(multiItemJSON), "auto", "", "").(map[string]any)
		if items, ok := m["items"].([]any); !ok || len(items) != 2 {
			t.Fatalf("items 应是两条记录的数组：%#v", m["items"])
		}
	})

	// 判不出结构就整段交出去，而不是硬拆出一堆假字段：模板里 {{.body}} 至少能原样发。
	t.Run("判不出就整段交出", func(t *testing.T) {
		for _, raw := range []string{"消息已提交", "告警: 磁盘满了", `{"a":1`} {
			if got := decodeBody([]byte(raw), "auto", "", ""); got != raw {
				t.Errorf("%q 应原样交出，实际 %#v", raw, got)
			}
		}
	})

	t.Run("空体给空对象", func(t *testing.T) {
		v, ok := decodeBody([]byte("  \n"), "auto", "", "").(map[string]any)
		if !ok || len(v) != 0 {
			t.Fatalf("空体应给空对象，避免模板取值时 panic：%#v", v)
		}
	})

	// 带 BOM 的 JSON 一样要认（见 trimBody）：这两件事叠在一起才是线上那次事故的全貌。
	t.Run("带BOM的JSON", func(t *testing.T) {
		m, ok := decodeBody([]byte("\ufeff"+multiItemJSON), "auto", "", "").(map[string]any)
		if !ok || m["biz"] != "每日汇总-超时未处理" {
			t.Fatalf("BOM 不该影响自动识别：%#v", m)
		}
	})
}

// 显式选定的类型永远压过自动识别：这三个选项的意义就是"别猜，我说了算"。
func TestDecodeBodyExplicitTypeWins(t *testing.T) {
	const kvText = "a=1&b=2"

	// txt：正文里凑巧有 a=b 也不拆。
	if got := decodeBody([]byte(kvText), "txt", "", ""); got != kvText {
		t.Errorf("txt 应原样交出：%#v", got)
	}
	// json：不是 JSON 就整段进 body，不去拆字段。
	if got := decodeBody([]byte(kvText), "json", "", ""); got != kvText {
		t.Errorf("选定 json 时键值文本应整段进 body：%#v", got)
	}
	// kv：一个字段也算，不受自动识别那条"至少两个"的门槛限制。
	m, ok := decodeBody([]byte("总数=100"), "kv", "", "").(map[string]any)
	if !ok || m["总数"] != "100" {
		t.Fatalf("选定 kv 时单个字段也该拆出来：%#v", m)
	}
	// 而自动识别下同一段文本证据不足，整段交出。
	if got := decodeBody([]byte("总数=100"), "auto", "", ""); got != "总数=100" {
		t.Errorf("自动识别下单个字段证据不足，应整段交出：%#v", got)
	}
}

func TestNewEventID(t *testing.T) {
	seen := make(map[string]bool, 64)
	for i := 0; i < 64; i++ {
		id := newEventID()
		if id == "" {
			t.Fatal("事件 ID 不能为空")
		}
		if seen[id] {
			t.Fatalf("事件 ID 重复：%q", id)
		}
		seen[id] = true
	}
	if strings.ContainsAny(newEventID(), " \t\n") {
		t.Fatal("事件 ID 要能直接进日志一行，不能含空白")
	}
}
