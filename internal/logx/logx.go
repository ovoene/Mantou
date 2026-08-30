package logx

import (
	"context"
	"encoding/json"
	"io"
	"log"
	"log/slog"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"mantou/internal/strutil"
)

// Entry 是供 UI 展示的一条日志记录。
// 它是 Logger.Recent 的元素类型，经 /api/logs 序列化给前端，
// 因此字段名（JSON tag）与总览页「程序日志」面板的渲染是一对一的契约。
type Entry struct {
	Time    time.Time `json:"time"`
	Level   string    `json:"level"`
	Message string    `json:"message"`
	Fields  Fields    `json:"fields,omitempty"`
}

// Field 是日志里的一个字段：一个名字加一个值。
type Field struct {
	Key string
	Val any
}

// Fields 是一条日志的字段表。
//
// 用切片而不是 map，这就是它存在的全部理由：每条日志的成本大头本来是这个 map——
// Go 的 swiss map 装 1 个字段也要分配一整组 8 槽位（约 300+ 字节），于是「2 字段」和
// 「6 字段」几乎一样贵，调字段数完全没用。切片是 n 个字段付 n 个槽位（每个 32 字节）。
//
// 顺带解决了一个显示问题：map 的迭代顺序是随机的，前端 Object.entries 拿到的顺序
// 每次都可能不同，同一条日志两次刷新字段会前后颠倒。切片保持写入顺序（先处理器
// 固有字段，再本次调用的字段），与长度预算的消耗顺序也一致。
//
// 代价是 Entry 从 64 字节涨到 80 字节（切片头 24 字节，map 指针只有 8 字节），
// 环在 New 里一次分配到位，5000 条即 400 KB 而不是 320 KB——这 80 KB 是启动就付的，
// 换回来的是填满之后少约 1.5 MB。
type Fields []Field

// Get 取一个字段的值，取不到返回 nil。
//
// 字段数由代码写死（现有最多 6 个），线性找一遍比建一个 map 还快。
// 提供它是因为换成切片之后 e.Fields["k"] 不再成立，而按名字取值是测试与排障的常用动作。
func (f Fields) Get(key string) any {
	for i := range f {
		if f[i].Key == key {
			return f[i].Val
		}
	}
	return nil
}

// set 写入一个字段：同名的覆盖，其余追加。
//
// 覆盖而不是追加两条，是为了与换掉 map 之前的行为一致——map 里同名键后写覆盖先写，
// 面板上只会看到一个。这种情形来自 logger.With("k", …) 之后调用方又传了一个同名字段。
func (f Fields) set(key string, val any) Fields {
	for i := range f {
		if f[i].Key == key {
			f[i].Val = val
			return f
		}
	}
	return append(f, Field{Key: key, Val: val})
}

// MarshalJSON 让字段表在接口上仍然是一个 JSON 对象（{"host":"…","status":200}）。
//
// 换数据结构不能连带改接口形状：前端 Overview.vue 用 Object.entries(fields) 渲染，
// 若这里变成数组，日志面板会直接空掉。所以内存里是切片、线上仍是对象——
// 这是本次改动**唯一**外部可见的约束，改动它等于改前端。
//
// 键与值都交给 json.Marshal 处理，转义规则与原来经 map 序列化时完全相同。
func (f Fields) MarshalJSON() ([]byte, error) {
	if len(f) == 0 {
		return []byte("{}"), nil
	}
	buf := make([]byte, 0, 32*len(f))
	buf = append(buf, '{')
	for i := range f {
		if i > 0 {
			buf = append(buf, ',')
		}
		key, err := json.Marshal(f[i].Key)
		if err != nil {
			return nil, err
		}
		buf = append(buf, key...)
		buf = append(buf, ':')
		val, err := json.Marshal(f[i].Val)
		if err != nil {
			return nil, err
		}
		buf = append(buf, val...)
	}
	return append(buf, '}'), nil
}

// ringHandler 是一个 slog.Handler，将日志写入内存环形缓冲，供总览页「程序日志」面板读取。
type ringHandler struct {
	state *ringState
	set   *levelSet
	attrs []slog.Attr
	group string
}

type ringState struct {
	mu     sync.Mutex
	buf    []Entry
	size   int
	next   int
	filled bool
}

// Logger 封装 slog.Logger，并暴露环形缓冲读取能力。
type Logger struct {
	*slog.Logger
	ring *ringHandler
	set  *levelSet
}

var (
	global   *Logger
	globalMu sync.RWMutex
)

// Options 日志初始化选项。
type Options struct {
	Levels     []string  // 允许记录的级别（debug/info/warn/error）；为空表示记录所有级别
	Console    bool      // 是否输出到 stdout
	MaxEntries int       // 内存环形缓冲容量（条），即全局「日志最大条数」
	FileWriter io.Writer // 可选的文件写入器（如轮转文件）
}

// 「日志最大条数」——全程序日志数据量的**唯一总开关**（设置 → 日志 → 日志最大条数）。
//
// 它同时约束三处，三者各自独立地不超过该条数：
//
//  1. 程序运行日志内存环（本文件的 ringState，总览页「程序日志」面板的数据源）；
//  2. Web 服务访问事件内存环（webservice.Module.access，见 SetAccessCap）；
//  3. 磁盘日志文件 mantou.log（见 RotatingFile，按行数轮转）。
//
// 之所以三处共用一个数字而不是各自一套：用户想控制的是「这个程序总共留多少日志」，
// 而不是去分别理解三个内部数据结构。三套独立限额只会让「我把条数调小了，占用怎么没降」
// 这类问题无法自查。
//
// 内存实测占用（Go 1.26，基线在 New 之前读，填满整环后强制 GC 读 HeapAlloc，
// 所以「每条」已包含环数组本身那 80 字节）：
//
//	无字段日志          80 B/条 →  1000 条  80 KB，5000 条 400 KB
//	模块日志（2 字段） 约 176 B/条 →  1000 条 177 KB，5000 条 0.86 MB
//	6 字段 × 43 字节串 约 672 B/条 →  1000 条 674 KB，5000 条 3.36 MB
//
// 实际部署以模块日志为主，故程序日志环默认 1000 条约 0.17 MB、拉满 5000 条约 0.86 MB；
// 访问事件环每条约 260 B，1000 条约 0.26 MB、5000 条约 1.3 MB。两者相加即内存总占用上界。
//
// 上面这些数字的前提是「字段值都是短串」，而这个前提由下面的 maxLogEntryBytes 保证：
// 单条日志的文本合计被裁到 8 KiB 以内，所以最坏情况有确定上界（5000 条 × 8 KiB = 40 MB），
// 不再取决于上游返回了多长的一段内容。
//
// 成本结构与直觉相反：大头从来不是 Entry 结构体（80 字节：Time 24 + Level/Message 各 16 +
// 字段表切片头 24），而是那张字段表。它**曾经**是个 map[string]any——Go 的 swiss map 装 1 个
// 字段也要分配一整组 8 槽位，实测每条要 356 字节，于是「1 字段」和「6 字段」几乎一样贵。
// 现在换成了切片（见 Fields），n 个字段付 n×32 字节。同一次运行里的对照（5000 条，只造 Entry）：
//
//	字段数        map      切片
//	  1        421 B/条  132 B/条
//	  2        441 B/条  184 B/条
//	  6        521 B/条  392 B/条
//
// 代价有两处，都不大：一是无字段日志反而多 15 字节（切片头 24 > map 指针 8），
// 而这个项目的日志基本都带字段；二是 buf 在 New 里一次分配到位（size×80 字节），
// 5000 条即 400 KB 启动就付，比原先的 320 KB 多 80 KB，换回填满之后少约 1.25 MB。
//
// 下限取 100：再小就看不到一次启动过程的完整日志，排障反而更费时间
// （这个下限原本只属于程序日志，合并后同样适用于访问日志——只留几条访问记录一样没有排障价值）。
const (
	MinLogEntries     = 100
	MaxLogEntries     = 5000
	DefaultLogEntries = 1000
)

// NormalizeLogEntries 把外部传入的条数夹进 [MinLogEntries, MaxLogEntries]；≤0 视为「用默认值」。
// 后端兜底，防止绕过面板直接调接口传入 1 或 10^9 这类值。
// 三处日志存储（程序环 / 访问环 / 磁盘文件）都必须经此函数规范化，保证同一个数字处处一致。
func NormalizeLogEntries(n int) int {
	if n <= 0 {
		return DefaultLogEntries
	}
	return min(max(n, MinLogEntries), MaxLogEntries)
}

// 单条日志的长度上限。上面那套「每条 114 / 434 / 678 字节」的实测数字有一个前提——
// 字段值都是短串——而这个前提原本没有任何代码保证：Entry.Message 与 Fields 的每个值
// 都是无上限的 string。
//
// 真正会踩到的路径是「把外部响应体拼进 error、再把 error 写进日志」：DNS 服务商适配层
// 允许读到 256 KB 的响应体，单条日志就能顶到实测最坏值的 380 倍，5000 条环乘上去
// 是 GB 级，而且这块内存要等到被后续日志挤出去才释放。
//
// 所以闸门必须设在这里，而不是几百个调用点上：最危险的调用点恰恰是那些「把上游返回的
// 内容塞进 error」的地方，靠 review 抓不干净，新增的调用点也不该需要知道这条规则。
// 做法与 config.TruncateStatus 在配置侧的做法一致。
const (
	// maxLogValueBytes 单个值（Message 或任一字段值）的上限。
	// 2 KiB 足够容纳一条完整的错误链与一段上游报错原文；再长的部分对排障已无增量信息。
	maxLogValueBytes = 2 << 10

	// maxLogEntryBytes 单条日志所有文本合计的上限。
	//
	// 只有每值上限是不够的：一条日志的字段**个数**虽然由代码决定（现有最多 6 个），
	// 但 6×2 KiB 已是实测最坏值的 20 倍，注释里那套占用数字仍然不成立。
	// 合计上限把单条钉在 8 KiB 以内，5000 条的上界因此是 40 MB 而不是无穷。
	maxLogEntryBytes = 8 << 10

	// logClipSuffix 裁剪标记。面板上看到它就知道"这里还有内容，只是没留"。
	logClipSuffix = "…（已截断）"

	// logValueClipped 是整条预算用尽之后，后续字段值的占位。
	// 用固定串而不是空串：空值与"真的是空"分不开，排障时会误导。
	// 它是字面量，因此不产生每条一份的分配。
	logValueClipped = "…（本条日志已达长度上限）"
)

// clipLogText 按剩余预算裁剪一段文本，返回裁剪结果与剩下的预算。
//
// 预算按「处理器固有字段 → 本次调用字段」的顺序消耗，这个顺序是确定的，
// 所以同一条日志每次被裁掉的都是同一部分（若按 map 迭代顺序裁，同一条日志两次显示
// 会不一样，那比截断本身更让人怀疑日志的可信度）。
func clipLogText(s string, budget int) (string, int) {
	if len(s) <= budget && len(s) <= maxLogValueBytes {
		return s, budget - len(s)
	}
	if budget <= 0 {
		return logValueClipped, 0
	}
	limit := min(budget, maxLogValueBytes)
	return strutil.Truncate(s, limit, logClipSuffix), budget - limit
}

// New 创建一个 Logger，同时输出到控制台/文件与内存环形缓冲。
// 级别采用「允许列表」：opts.Levels 为空表示记录所有级别；非空时仅记录列表中的级别。
func New(opts Options) *Logger {
	opts.MaxEntries = NormalizeLogEntries(opts.MaxEntries)
	set := newLevelSet(opts.Levels)

	ring := &ringHandler{
		state: &ringState{
			buf:  make([]Entry, opts.MaxEntries),
			size: opts.MaxEntries,
		},
		set: set,
	}

	// 内层 handler 用最低级别放行，真正的级别过滤交给 levelFilter / ringHandler。
	innerOpts := &slog.HandlerOptions{Level: slog.LevelDebug}
	handlers := []slog.Handler{ring}
	if opts.Console {
		handlers = append(handlers, &levelFilter{inner: slog.NewTextHandler(os.Stdout, innerOpts), set: set})
	}
	if opts.FileWriter != nil {
		handlers = append(handlers, &levelFilter{inner: slog.NewJSONHandler(opts.FileWriter, innerOpts), set: set})
	}

	l := &Logger{
		Logger: slog.New(&fanout{handlers: handlers}),
		ring:   ring,
		set:    set,
	}
	return l
}

// SetLevels 动态调整「允许记录的级别」；传入空切片表示记录所有级别。
func (l *Logger) SetLevels(levels []string) {
	l.set.set(levels)
}

// SetMaxEntries 动态调整内存环形缓冲容量，并保留最新的 min(现有条数, size) 条。
// size 会先经 NormalizeLogEntries 夹入合法区间；与当前容量相同时直接返回，不做任何分配。
// 由「设置 → 日志 → 日志最大条数」保存时调用（见 server.handleUpdateSettings），改完立即生效。
//
// 与 Clear 完全相同的约束：必须**就地改写** state 的字段，绝不能替换 l.ring.state 指针。
// WithAttrs/WithGroup 产生的 handler 克隆各自持有一份 state 指针副本（见 ringHandler.WithAttrs），
// 替换指针只会影响 l.ring 自己，那些克隆仍写向旧缓冲——表现为「调过一次条数之后，
// 由 With(...) 派生出来的日志（模块日志基本都是）再也不出现在面板上」。
// 这种 bug 只在改过设置的实例上出现，极难复现，故此处不做"看起来更干净"的整体替换。
func (l *Logger) SetMaxEntries(size int) {
	size = NormalizeLogEntries(size)
	st := l.ring.state
	st.mu.Lock()
	defer st.mu.Unlock()
	if size == st.size {
		return
	}

	// 先把现有条目按时间升序取出（与 snapshot 同一套环形读法）。
	var cur []Entry
	if st.filled {
		cur = append(cur, st.buf[st.next:]...)
		cur = append(cur, st.buf[:st.next]...)
	} else {
		cur = append(cur, st.buf[:st.next]...)
	}
	// 缩容时丢最旧的：用户调小条数是为了省内存，保留最新的才有排障价值。
	if len(cur) > size {
		cur = cur[len(cur)-size:]
	}

	buf := make([]Entry, size)
	copy(buf, cur)
	st.buf = buf
	st.size = size
	// len(cur) == size 时 next 归 0 且已满；否则下一个写入位就是 len(cur)。
	st.next = len(cur) % size
	st.filled = len(cur) == size
}

// Clear 清空内存环形缓冲（程序日志），用于「手动清空所有日志」时同步重置 UI 实时日志。
// 仅清空内存副本，不影响磁盘文件（文件由 RotatingFile.Reset 处理）。
//
// 实现要点：必须「就地重置」而不能替换 state 指针。
//  1. 替换指针会与并发 Handle 中对 h.state 的读构成数据竞争（写指针 / 读指针未同步）；
//  2. WithAttrs/WithGroup 产生的 handler 克隆各自持有一份 state 指针副本，替换只影响
//     l.ring 自己，克隆仍写向旧缓冲——表现为「清空后由 With(...) 派生的日志再也不显示」。
//
// 就地重置同时把 Entry 置零，让其字段表立即可被 GC 回收。
func (l *Logger) Clear() {
	st := l.ring.state
	st.mu.Lock()
	defer st.mu.Unlock()
	for i := range st.buf {
		st.buf[i] = Entry{}
	}
	st.next = 0
	st.filled = false
}

// Recent 返回环形缓冲中最近的日志（按时间升序）。
func (l *Logger) Recent(limit int) []Entry {
	return l.ring.snapshot(limit)
}

func (l *Logger) Standard(level slog.Level, message string) *log.Logger {
	return log.New(&standardWriter{logger: l, level: level, message: message}, "", 0)
}

type standardWriter struct {
	logger  *Logger
	level   slog.Level
	message string
}

func (w *standardWriter) Write(p []byte) (int, error) {
	text := strings.TrimSpace(string(p))
	if text != "" {
		w.logger.Log(context.Background(), w.level, w.message, "detail", text)
	}
	return len(p), nil
}

// NewTLSErrorLog 返回一个供 http.Server.ErrorLog 使用的 *log.Logger：把标准库报出的 TLS 握手错误
// 按「良性 / 严重」分级——端口扫描、连接复用探测、客户端中途取消等留下的
// "TLS handshake error ...: EOF / connection reset / i/o timeout" 属良性噪声，降级为 DEBUG；
// 真实证书 / 配置问题仍按传入 level（通常 WARN）输出。msg 为该错误日志的统一前缀。
func (l *Logger) NewTLSErrorLog(level slog.Level, msg string) *log.Logger {
	return log.New(&tlsErrorFilter{
		debug: l.Standard(slog.LevelDebug, msg),
		warn:  l.Standard(level, msg),
	}, "", 0)
}

// tlsErrorFilter 按行过滤：良性握手噪声降级到 debug，其余按 warn 输出。
type tlsErrorFilter struct {
	debug *log.Logger
	warn  *log.Logger
}

func (w *tlsErrorFilter) Write(p []byte) (int, error) {
	text := strings.TrimSpace(string(p))
	if text == "" {
		return len(p), nil
	}
	if isBenignTLSHandshakeErr(text) {
		w.debug.Println(text)
	} else {
		w.warn.Println(text)
	}
	return len(p), nil
}

// isBenignTLSHandshakeErr 判断是否为良性握手噪声：连接未完成握手即被关闭 / 重置 / 超时，
// 多由本地探测、连接复用探测、客户端中途取消等引起，并非服务故障。
func isBenignTLSHandshakeErr(text string) bool {
	if !strings.Contains(text, "TLS handshake error") {
		return false
	}
	for _, s := range []string{
		"EOF",
		"connection reset by peer",
		"i/o timeout",
		"TLS handshake timeout",
		"tls: first record does not look like a TLS handshake",
		"context canceled",
		// 「按 IP 直连面板 HTTPS」：RFC 6066 §3 禁止把 IP 字面量放进 SNI 扩展，
		// 所以浏览器输 https://192.168.x.x、公网扫描器扫端口，一律不带 SNI，
		// 被 panelTLSConfig 的 GetCertificate 拒掉（"主机名为空"）。
		// 这是**客户端用错了访问方式**，面板拒绝它正是预期行为，不是服务故障；
		// 若按 WARN 记，一台暴露在公网的面板会被扫描器刷满告警——比漏掉这条提示更糟。
		// 本机回环也走这一条：面板不再对回环开任何 TLS 放行（见 server.panelTLSConfig），
		// 所以本机进程用 https://127.0.0.1 连上来同样会被拒、同样降级到 DEBUG。
		"拒绝面板 TLS 连接: 主机名为空",
		"拒绝面板 TLS 连接: 不允许使用 IP 地址",
	} {
		if strings.Contains(text, s) {
			return true
		}
	}
	return false
}

// SetGlobal / L 提供包级默认 Logger，便于各处使用。
func SetGlobal(l *Logger) {
	globalMu.Lock()
	global = l
	globalMu.Unlock()
}

// L 返回全局 Logger；若未设置则返回一个仅控制台的兜底 Logger。
func L() *Logger {
	globalMu.RLock()
	l := global
	globalMu.RUnlock()
	if l == nil {
		l = New(Options{Levels: nil, Console: true})
		SetGlobal(l)
	}
	return l
}

// ---------- ringHandler 实现 slog.Handler ----------

func (h *ringHandler) Enabled(_ context.Context, level slog.Level) bool {
	return h.set.allowed(level)
}

func (h *ringHandler) Handle(_ context.Context, r slog.Record) error {
	// 长度预算在这一条日志内部按顺序消耗：先 Message，再处理器固有字段，最后本次调用的字段。
	budget := maxLogEntryBytes
	message, budget := clipLogText(r.Message, budget)
	// 一个字段都没有时保持 nil：不分配，JSON 里也照样被 omitempty 省掉。
	var fields Fields
	if n := len(h.attrs) + r.NumAttrs(); n > 0 {
		fields = make(Fields, 0, n)
	}
	for _, attr := range h.attrs {
		// 传 "" 而不是 h.group：这些属性的键在 WithAttrs 里就已经带好前缀了。
		fields, budget = addField(fields, "", attr, budget)
	}
	r.Attrs(func(attr slog.Attr) bool {
		fields, budget = addField(fields, h.group, attr, budget)
		return true
	})
	h.state.mu.Lock()
	defer h.state.mu.Unlock()
	h.state.buf[h.state.next] = Entry{
		Time:    r.Time,
		Level:   r.Level.String(),
		Message: message,
		Fields:  fields,
	}
	h.state.next = (h.state.next + 1) % h.state.size
	if h.state.next == 0 {
		h.state.filled = true
	}
	return nil
}

// WithAttrs 在这里就把分组前缀写进键名，而不是留到 Handle 里统一套 h.group。
//
// 一个属性归属于「它被添加时所在的那个分组」，之后再 WithGroup 不该追认它——这是 slog 的语义。
// 原先在 Handle 里对 h.attrs 统一套当前的 h.group，于是
// log.With("module", …).WithGroup("req") 会把先加的 module 也变成 req.module。
// 现有代码没有一处调用 WithGroup，所以这个 bug 在生产里从未显形；但改成切片之后
// 字段顺序被钉住了，写顺序测试时它就露了出来，顺手修掉。
//
// 顺带便宜一点：拼接从「每写一条日志一次」变成「每次 With 一次」。
func (h *ringHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	clone := *h
	qualified := make([]slog.Attr, 0, len(h.attrs)+len(attrs))
	qualified = append(qualified, h.attrs...) // 先前的已经带好各自的前缀
	for _, attr := range attrs {
		qualified = append(qualified, slog.Attr{Key: qualifyKey(h.group, attr.Key), Value: attr.Value})
	}
	clone.attrs = qualified
	return &clone
}

// qualifyKey 给字段名加上分组前缀；不在分组里就原样返回。
func qualifyKey(group, key string) string {
	if group == "" {
		return key
	}
	return group + "." + key
}

func (h *ringHandler) WithGroup(group string) slog.Handler {
	clone := *h
	if clone.group == "" {
		clone.group = group
	} else if group != "" {
		clone.group += "." + group
	}
	return &clone
}

// addField 把一个 attr 展开进 fields，返回追加后的字段表与消耗后的长度预算。
//
// 只裁字符串：其余类型（数字、布尔、时间）的占用由类型本身决定，长度不受外部输入影响。
// 字段名同理由代码写死，不参与预算。
//
// 返回 fields 而不是原地改：切片 append 可能换底层数组，调用方必须接住返回值。
func addField(fields Fields, group string, attr slog.Attr, budget int) (Fields, int) {
	attr.Value = attr.Value.Resolve()
	if attr.Equal(slog.Attr{}) {
		return fields, budget
	}
	key := qualifyKey(group, attr.Key)
	if attr.Value.Kind() == slog.KindGroup {
		for _, child := range attr.Value.Group() {
			fields, budget = addField(fields, key, child, budget)
		}
		return fields, budget
	}
	value := attr.Value.Any()
	if s, ok := value.(string); ok {
		clipped, left := clipLogText(s, budget)
		return fields.set(key, clipped), left
	}
	return fields.set(key, value), budget
}

// snapshot 返回环形缓冲内容（升序），最多 limit 条。
func (h *ringHandler) snapshot(limit int) []Entry {
	h.state.mu.Lock()
	defer h.state.mu.Unlock()

	var out []Entry
	if h.state.filled {
		out = append(out, h.state.buf[h.state.next:]...)
		out = append(out, h.state.buf[:h.state.next]...)
	} else {
		out = append(out, h.state.buf[:h.state.next]...)
	}
	if limit > 0 && len(out) > limit {
		out = out[len(out)-limit:]
	}
	return out
}

// ---------- fanout：把一条日志分发到多个 handler ----------

type fanout struct {
	handlers []slog.Handler
}

func (f *fanout) Enabled(ctx context.Context, level slog.Level) bool {
	for _, h := range f.handlers {
		if h.Enabled(ctx, level) {
			return true
		}
	}
	return false
}

func (f *fanout) Handle(ctx context.Context, r slog.Record) error {
	for _, h := range f.handlers {
		if h.Enabled(ctx, r.Level) {
			_ = h.Handle(ctx, r.Clone())
		}
	}
	return nil
}

func (f *fanout) WithAttrs(attrs []slog.Attr) slog.Handler {
	hs := make([]slog.Handler, len(f.handlers))
	for i, h := range f.handlers {
		hs[i] = h.WithAttrs(attrs)
	}
	return &fanout{handlers: hs}
}

func (f *fanout) WithGroup(name string) slog.Handler {
	hs := make([]slog.Handler, len(f.handlers))
	for i, h := range f.handlers {
		hs[i] = h.WithGroup(name)
	}
	return &fanout{handlers: hs}
}

// ---------- 级别允许列表（levelSet）----------
// levelSet 记录「允许输出的日志级别」；levels 为 nil 表示放行所有级别。
type levelSet struct {
	mu     sync.RWMutex
	levels map[slog.Level]bool
}

func newLevelSet(levels []string) *levelSet {
	s := &levelSet{}
	s.set(levels)
	return s
}

func (s *levelSet) set(levels []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(levels) == 0 {
		s.levels = nil
		return
	}
	m := make(map[slog.Level]bool, len(levels))
	for _, l := range levels {
		m[parseLevel(l)] = true
	}
	s.levels = m
}

func (s *levelSet) allowed(level slog.Level) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.levels == nil {
		return true
	}
	return s.levels[level]
}

// levelFilter 将一条日志按 levelSet 过滤后再交给内层 handler（用于控制台/文件输出）。
type levelFilter struct {
	inner slog.Handler
	set   *levelSet
}

func (f *levelFilter) Enabled(ctx context.Context, level slog.Level) bool {
	return f.set.allowed(level) && f.inner.Enabled(ctx, level)
}

func (f *levelFilter) Handle(ctx context.Context, r slog.Record) error {
	return f.inner.Handle(ctx, r.Clone())
}

func (f *levelFilter) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &levelFilter{inner: f.inner.WithAttrs(attrs), set: f.set}
}

func (f *levelFilter) WithGroup(group string) slog.Handler {
	return &levelFilter{inner: f.inner.WithGroup(group), set: f.set}
}

func parseLevel(s string) slog.Level {
	switch s {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

// Levels 是配置中允许出现的日志级别全集（顺序即由低到高）。
var Levels = []string{"debug", "info", "warn", "error"}

// NormalizeLevels 把外部传入的级别列表过滤为白名单内的值，顺序保持不变并去重。
// 输入为空、或过滤后为空时返回 nil——nil 的语义是「记录所有级别」（见 levelSet.allowed）。
//
// 为什么必须过滤而不能原样存下：parseLevel 对认不出的字符串一律回退成 info，
// 于是 levels=["verbose"] 会被静默解读成「只记 info」——用户以为开了更详细的日志，
// 实际上把 debug/warn/error 三档全关掉了，而且配置文件里看不出任何异常。
// 过滤后这种输入等价于「未选择任何级别」，即记录全部，至少不会静默丢日志。
func NormalizeLevels(levels []string) []string {
	if len(levels) == 0 {
		return nil
	}
	out := make([]string, 0, len(levels))
	seen := make(map[string]bool, len(levels))
	for _, raw := range levels {
		l := strings.ToLower(strings.TrimSpace(raw))
		if seen[l] || !slices.Contains(Levels, l) {
			continue
		}
		seen[l] = true
		out = append(out, l)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
