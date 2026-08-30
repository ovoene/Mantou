package webhook

import (
	"strconv"
	"strings"
	"testing"

	"mantou/internal/config"
)

// 键值文本的样子（用户给的真实来源）：字段之间 &，字段名与值之间 =，
// 值里有中文、有空格，全都是原样发过来的，没有百分号编码。
const kvSample = "code=测试消息&biz=每日汇总&keyField=2026-08-24 11:44:25&creator=adm"

func TestDecodeKV(t *testing.T) {
	t.Run("自动识别", func(t *testing.T) {
		m, ok := decodeKV(kvSample, "", "").(map[string]any)
		if !ok {
			t.Fatalf("应拆成字段：%#v", decodeKV(kvSample, "", ""))
		}
		want := map[string]string{
			"code":     "测试消息",
			"biz":      "每日汇总",
			"keyField": "2026-08-24 11:44:25", // 值里的空格必须原样留着
			"creator":  "adm",
		}
		if len(m) != len(want) {
			t.Fatalf("字段数不符：%#v", m)
		}
		for k, v := range want {
			if m[k] != v {
				t.Errorf("%s = %#v，期望 %q", k, m[k], v)
			}
		}
	})

	// 一行一个字段是这类文本的另一种常见形态。按 & 拆只有一段，按换行拆有三段，
	// 自动识别靠的就是"哪种拆得多"。
	t.Run("换行分隔", func(t *testing.T) {
		m, ok := decodeKV("code=A1\nbiz=状态提醒\r\ncreator=adm", "", "").(map[string]any)
		if !ok || m["code"] != "A1" || m["biz"] != "状态提醒" || m["creator"] != "adm" {
			t.Fatalf("换行分隔应拆得出来：%#v", m)
		}
	})

	t.Run("冒号连接", func(t *testing.T) {
		m, ok := decodeKV("level: error\nmsg: disk full", "", "").(map[string]any)
		if !ok || m["level"] != "error" || m["msg"] != "disk full" {
			t.Fatalf("冒号形态应拆得出来：%#v", m)
		}
	})

	// 值里带冒号很常见（时间、URL），只在第一个分隔符处切开。
	t.Run("值里带分隔符", func(t *testing.T) {
		m, ok := decodeKV("time=12:30:00&url=http://a/b?c=1", "", "").(map[string]any)
		if !ok || m["time"] != "12:30:00" || m["url"] != "http://a/b?c=1" {
			t.Fatalf("值应完整保留：%#v", m)
		}
	})

	t.Run("手填分隔符压过自动识别", func(t *testing.T) {
		// 这段文本按 & 拆是两个字段，按 | 拆只有一个；用户说了用 |，就按 | 拆。
		m, ok := decodeKV("a=1&b=2", "|", "=").(map[string]any)
		if !ok || len(m) != 1 || m["a"] != "1&b=2" {
			t.Fatalf("应按用户指定的分隔符拆：%#v", m)
		}
	})

	t.Run("同名字段合并", func(t *testing.T) {
		m, ok := decodeKV("code=A1&code=A2", "", "").(map[string]any)
		if !ok || m["code"] != "A1, A2" {
			t.Fatalf("同名字段应与请求头、query 同口径合并：%#v", m)
		}
	})

	// 真按表单编码发来的载荷也要认，但 + 不能当空格：编号 A+B 改掉就是数据损坏。
	t.Run("百分号编码", func(t *testing.T) {
		m, ok := decodeKV("code=%E7%BC%96%E5%8F%B7&model=A%2BB&note=100%", "", "").(map[string]any)
		if !ok || m["code"] != "编号" || m["model"] != "A+B" || m["note"] != "100%" {
			t.Fatalf("百分号编码处理不符：%#v", m)
		}
	})

	t.Run("前导问号", func(t *testing.T) {
		m, ok := decodeKV("?a=1&b=2", "", "").(map[string]any)
		if !ok || m["a"] != "1" || m["b"] != "2" {
			t.Fatalf("粘进来的 query 串应照样拆：%#v", m)
		}
	})

	// 一个字段都拆不出来时给回原文，与 json 解不动时的处理一致：
	// 用户在试运行页上立刻看到"对方这次发的不是键值文本"。
	t.Run("拆不出就给原文", func(t *testing.T) {
		const raw = "消息已提交，请及时处理"
		if v := decodeKV(raw, "", ""); v != raw {
			t.Fatalf("应原样返回：%#v", v)
		}
	})

	t.Run("空体给空对象", func(t *testing.T) {
		if v, ok := decodeKV("", "", "").(map[string]any); !ok || len(v) != 0 {
			t.Fatalf("空体应给空对象而不是 nil：%#v", v)
		}
	})

	// 键的形态卡得比值严：日志行按冒号拆会得到"2026-08-24 11"这种键名，
	// 一旦当成字段，字段树里全是垃圾。
	t.Run("键带空格不算字段", func(t *testing.T) {
		const raw = "2026-08-24 11:00:00 ERROR: disk full"
		if v := decodeKV(raw, "", ""); v != raw {
			t.Fatalf("日志行不该被拆成字段：%#v", v)
		}
	})

	t.Run("字段数上限", func(t *testing.T) {
		parts := make([]string, 0, maxKVFields+50)
		for i := 0; i < maxKVFields+50; i++ {
			parts = append(parts, "k"+strconv.Itoa(i)+"=1")
		}
		m, ok := decodeKV(strings.Join(parts, "&"), "", "").(map[string]any)
		if !ok || len(m) != maxKVFields {
			t.Fatalf("应停在 %d 个字段，实际 %d", maxKVFields, len(m))
		}
	})

	// 2.8-A：同名键走合并分支，不增加字段数，所以 maxKVFields 挡不住它。
	// 每次合并都重新分配一个更长的字符串，不设闸就是二次复杂度：一份 256 KB 的
	// "a=1&" 累计复制约 6 GB，一条请求就能占住一个核心，而触发它只需要知道路径。
	t.Run("同名字段的合并次数有上限", func(t *testing.T) {
		const pairs = 65536 // 256 KB，正好是默认的请求体上限
		v := decodeKV(strings.Repeat("a=1&", pairs), "", "")
		m, ok := v.(map[string]any)
		if !ok {
			t.Fatalf("应拆成字段，实际 %T", v)
		}
		s, isStr := m["a"].(string)
		if !isStr {
			t.Fatalf("字段 a 应是字符串：%#v", m["a"])
		}
		if got := strings.Count(s, ", ") + 1; got > maxKVPairs {
			t.Fatalf("合并了 %d 段，超过对数上限 %d", got, maxKVPairs)
		}
		if len(s) > maxKVValueBytes {
			t.Fatalf("合并后的值 %d 字节，超过长度上限 %d", len(s), maxKVValueBytes)
		}
	})

	// 只限对数还不够：对数之内每个值都很大时，合并仍要复制上百 MB。
	t.Run("合并后的值有长度上限", func(t *testing.T) {
		const one = 1 << 10
		v := decodeKV(strings.Repeat("a="+strings.Repeat("x", one)+"&", 20), "", "")
		m, ok := v.(map[string]any)
		if !ok {
			t.Fatalf("应拆成字段，实际 %T", v)
		}
		s, _ := m["a"].(string)
		if len(s) > maxKVValueBytes {
			t.Fatalf("合并后的值 %d 字节，超过长度上限 %d", len(s), maxKVValueBytes)
		}
		if len(s) < one {
			t.Fatalf("第一个值应当留着，实际只剩 %d 字节", len(s))
		}
	})
}

// kv 与 JSON 走同一条路：字段直接进 body，模板里写 {{.body.code}}，
// 根路径填 body 时写 {{.code}}——这正是"和 json 一样区分出字段"的意思。
func TestKVGoesThroughSamePipeline(t *testing.T) {
	r := newRT(t, config.WebhookReceiver{Path: "hook", SourceType: "kv"})
	ev := buildFor(t, r, kvSample, "text/plain", "", nil)
	body, ok := ev.Root["body"].(map[string]any)
	if !ok {
		t.Fatalf("body 应是字段映射表：%#v", ev.Root["body"])
	}
	if body["creator"] != "adm" {
		t.Fatalf("creator 取不到：%#v", body)
	}
}

// 分隔符里的 \n 要在规范化时变成真换行：输入框里打不出换行，
// 用户能想到的写法就是反斜杠加 n。
func TestNormalizeReceiverSep(t *testing.T) {
	r := config.WebhookReceiver{Path: "hook", SourceType: "kv", PairSep: `\n`, KVSep: "="}
	config.NormalizeReceiver(&r)
	if r.PairSep != "\n" {
		t.Fatalf("\\n 应转成真换行：%q", r.PairSep)
	}
	// 换个类型就该清空：留着会让界面显示一组不起作用的设置。
	r.SourceType = "json"
	config.NormalizeReceiver(&r)
	if r.PairSep != "" || r.KVSep != "" {
		t.Fatalf("非 kv 类型应清空分隔符：%q / %q", r.PairSep, r.KVSep)
	}
}
