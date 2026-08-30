package webhook

import (
	"net/url"
	"strings"

	"mantou/internal/tmplx"
)

// 本文件解「键值文本」：一段不是 JSON、但用固定符号把字段拼起来的请求体。
//
//	name=测试消息&type=系统通知&keyField=2026-08-24 11:44:25&creator=adm
//
// 这类来源在现实里很常见（旧系统的 HTTP 回调、脚本里 curl 拼出来的串、
// 短信网关的通知），此前只能整段进 body 当一个字符串用，模板里写不出取值路径。
// 拆成字段之后，它与 JSON 走的是同一条路：字段树、字段映射、消息规则、模板全部照用。
//
// 为什么不复用 net/url.ParseQuery：那是严格的表单解析，值里必须是百分号编码。
// 真实来源里的中文、空格、逗号都是**原样**发过来的（上面这行就是），ParseQuery
// 遇到裸 % 会直接报错，遇到 + 会当成空格——编号 A+B 会被改坏。
// 所以这里自己拆：只按符号切，值原样保留，仅在确实是百分号编码时才解一次。

// kvPairSeps / kvKVSeps 自动识别时的候选分隔符，按优先级排列（拆出字段数相同时靠前者胜）。
//
// 顺序是有讲究的：先试 & 是因为它是这类文本最常见的写法；换行紧随其后（一行一个字段
// 的日志式文本）。逗号放最后——值里出现逗号的概率比它作为分隔符的概率高得多，
// 只有在别的符号都拆不出更多字段时才轮到它。
var (
	kvPairSeps = []string{"&", "\n", ";", "|", "\t", ","}
	kvKVSeps   = []string{"=", ":"}
)

// maxKVFields 单条消息最多拆出的字段数。
//
// 请求体本身已经有体积上限（MaxBodyKB），这里挡的是"上限之内塞满 a=1&"的情况：
// 那种内容拆出几千个字段对配模板毫无用处，只会让字段树没法看。超出的部分丢掉，
// 原文在调试抓包里仍然完整可见。
const maxKVFields = 200

// maxKVPairs 单条消息最多处理多少对键值——同名合并的每一次也算一对。
//
// maxKVFields 只挡得住**不同**的字段名，而同名合并那条路不增加字段数，于是挡不住
// "a=1&a=2&a=3…" 这种载荷：默认 256 KB 体积上限之内就有 6 万多对，每次合并都要重新
// 分配一个更长的字符串，累计复制约 6 GB；体积上限调到 4 MiB 则是 1.6 TB，等于这条请求
// 永不返回。而触发它只需要知道入站路径（默认不限流、鉴权可以是 none）。
// 这道闸按"处理过的对数"计，把解码成本压回与字段数上限同阶。
const maxKVPairs = 500

// maxKVValueBytes 同名字段合并后值的长度上限，超出后同名的后续值丢弃。
//
// 只限对数还不够：500 对里若每个值都有几十 KB，合并仍要复制上百 MB。两道闸相乘才是
// 这一步的真实上界（500 × 8 KiB ≈ 4 MB）。单个字段的值本身不截断——它是原文的切片，
// 不产生复制，截断反而会破坏取值与条件比对。
const maxKVValueBytes = 8 << 10

// maxKVKeyRunes 字段名的长度上限，用于把"一句话"与"一个字段名"区分开。
// 超过这个长度的更可能是正文里凑巧带了个冒号，不是字段。
const maxKVKeyRunes = 64

// kvKeyBadChars 字段名里不允许出现的字符。
//
// 前四个是空白：日志行 "2026-08-24 11:00:00 ERROR: disk full" 按冒号切会得到
// 一个带空格的"字段名"。后四个是 JSON 的结构符号：它们出现在字段名里只有一种可能——
// 正在拆的其实是一段结构化文本（完整 JSON、被截断的载荷、嵌了 JSON 的日志），
// 而不是键值文本。宁可一个字段都不拆（decodeKV 会退回原文，用户在试运行页上立刻看见），
// 也不要造出一堆名叫 `{"biz"` 的假字段——那种字段树看着像成功了，
// 而后面每一条取值路径都取不到值。
const kvKeyBadChars = " \t\r\n\"{}[]"

// decodeKV 把键值文本拆成字段。
//
// pairSep / kvSep 为空表示自动识别（界面上的默认值）。一个字段都拆不出来时返回**原文**，
// 与 json 解不动时的处理一致：用户在试运行页上立刻看到"对方这次发的不是键值文本"，
// 比拿到一个空对象、再去猜哪个路径写错了有用得多。
//
// 收到的是一份合法 JSON 时按 JSON 解，不按分隔符拆。这不是"猜"：json.Valid 说了算。
// 少了这一层的后果实测过一次——{"biz":"…","items":[…]} 被按逗号+冒号拆成了
// 名叫 `{"biz"`、`"name"` 的字段（同名的还用 ", " 连起来），字段树看着像解出来了，
// 而所有取值路径与规则条件全部落空，用户看到的只是"规则不命中"。
// 把 JSON 拆成键值文本从来不是任何人想要的结果，所以这里不问用户选了什么。
func decodeKV(text, pairSep, kvSep string) any {
	if text == "" {
		return map[string]any{}
	}
	if looksLikeJSON(text) {
		if v, err := tmplx.DecodeJSON([]byte(text)); err == nil {
			return v
		}
	}
	ps, ks, n := sniffKV(text, pairSep, kvSep)
	if n == 0 {
		return text
	}
	out := splitKV(text, ps, ks)
	if len(out) == 0 {
		return text
	}
	return out
}

// sniffKV 在候选分隔符里挑出能拆出最多字段的一组；force* 非空时只试指定的那个。
//
// 用"拆出的字段数"当判据，而不是问用户或看 Content-Type：a=1&b=2 按换行拆只有一段，
// 按 & 拆有两段，数字自己会说话。= 与 : 之间刻意不比数量而是**先认 =**：
// 值里带 : 的太多了（时间、URL），而 = 几乎只在键值场景里出现。
func sniffKV(text, forcePair, forceKV string) (pairSep, kvSep string, pairs int) {
	pairCands, kvCands := kvPairSeps, kvKVSeps
	if forcePair != "" {
		pairCands = []string{forcePair}
	}
	if forceKV != "" {
		kvCands = []string{forceKV}
	}
	for _, k := range kvCands {
		for _, p := range pairCands {
			if p == k {
				continue
			}
			if n := countKVPairs(text, p, k); n > pairs {
				pairSep, kvSep, pairs = p, k, n
			}
		}
		if pairs > 0 {
			break // 这一层的 kvSep 已经拆得出字段，不再往下试更弱的候选
		}
	}
	// pairs 为 0 时返回的两个分隔符是空串：一个字段都拆不出来，"用哪个符号拆"没有意义，
	// 调用方一律以 pairs 判断（见 decodeKV 的原文兜底）。
	return pairSep, kvSep, pairs
}

// countKVPairs 按给定分隔符能拆出多少个合法字段。
func countKVPairs(text, pairSep, kvSep string) int {
	n := 0
	for _, chunk := range strings.Split(text, pairSep) {
		if _, _, ok := cutKVPair(chunk, kvSep); ok {
			n++
		}
	}
	return n
}

// splitKV 按给定分隔符拆字段。同名字段用 ", " 连接，与请求头、query 的多值口径一致。
//
// 三道闸各管一件事，缺一不可：maxKVFields 管不同字段名的个数，maxKVPairs 管处理过的
// 对数（同名合并算在内），maxKVValueBytes 管合并结果的长度。理由见各自的注释。
// 超出的部分一律丢掉，不报错——原文在试运行的抓包里仍然完整可见。
func splitKV(text, pairSep, kvSep string) map[string]any {
	out := make(map[string]any, 8)
	pairs := 0
	for _, chunk := range strings.Split(text, pairSep) {
		k, v, ok := cutKVPair(chunk, kvSep)
		if !ok {
			continue
		}
		if pairs >= maxKVPairs {
			break
		}
		pairs++
		if prev, dup := out[k]; dup {
			if s, isStr := prev.(string); isStr {
				if len(s)+len(", ")+len(v) <= maxKVValueBytes {
					out[k] = s + ", " + v
				}
				continue
			}
		}
		if len(out) >= maxKVFields {
			break
		}
		out[k] = v
	}
	return out
}

// cutKVPair 从一段文本里切出一对键值。只在第一个 kvSep 处切开——
// 值里带分隔符是常态（url=http://a?b=1、time=12:30），切多了就把值截断了。
//
// 键的形态刻意卡得比值严：不能为空、不能过长、不能带空白或 JSON 的结构符号
// （见 kvKeyBadChars）。这是为了把"日志行"和"其实是 JSON 的载荷"挡在外面。
func cutKVPair(chunk, kvSep string) (key, val string, ok bool) {
	chunk = strings.TrimSpace(chunk)
	// 整段是 query 串时用户很可能把问号也粘进来了。
	chunk = strings.TrimPrefix(chunk, "?")
	i := strings.Index(chunk, kvSep)
	if i <= 0 {
		return "", "", false
	}
	key = strings.TrimSpace(chunk[:i])
	if key == "" || len([]rune(key)) > maxKVKeyRunes || strings.ContainsAny(key, kvKeyBadChars) {
		return "", "", false
	}
	val = strings.TrimSpace(chunk[i+len(kvSep):])
	return kvUnescape(key), kvUnescape(val), true
}

// kvUnescape 只在文本里确实出现 % 时解一次百分号编码，解不动就原样返回。
//
// 用 PathUnescape 而不是 QueryUnescape：后者会把 + 变成空格，而"+"在编号、
// 型号里是普通字符（A+B），改掉是实打实的数据损坏。真按表单编码发来的载荷里
// 空格通常也是 %20，照样解得出来。
func kvUnescape(s string) string {
	if !strings.Contains(s, "%") {
		return s
	}
	if d, err := url.PathUnescape(s); err == nil {
		return d
	}
	return s
}
