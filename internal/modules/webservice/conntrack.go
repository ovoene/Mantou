package webservice

import (
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// 本文件是监听层的三道收尾保护：连接台账（停机时能真正把连接关掉）、请求体停滞超时，
// 以及对称的响应体写入停滞超时。前两件只在 listenServer 内部用（见 listener.go 的
// start / close / handler），第三件由 statusWriter 驱动（见 handler.go）。

// bodyStallTimeout 请求体两次「读到了东西」之间允许的最长间隔。
//
// 这道闸补的是 http.Server 上刻意留的那个缺口：ReadTimeout 没设（设了会把大附件
// 上传中途掐断），ReadHeaderTimeout 只管到请求头读完为止，IdleTimeout 只管两次请求
// 之间。于是"请求头发完、正文发一半就不动了"这一段没有任何超时看着——连接、goroutine
// 与读缓冲一直留着，而这个监听的并发连接数是有上限的（maxConnsPerListener），
// 上限一满 Accept 就阻塞，正常访客连不进来。
//
// 取 60 秒、且是"有进展就续期"而不是总时长上限：上传一个几 GB 的附件、导出一份跑几
// 分钟的报表，都会持续有字节进来，不受影响；真正被切掉的是**一点动静都没有**的那种。
//
// 说清楚它挡不住什么：对端故意每 59 秒发一个字节，仍然能一直占着连接。那是速率问题，
// 该由子项上的「请求速率限制」与连接数上限管，不是这道闸的事。
const bodyStallTimeout = 60 * time.Second

// connTracker 记着本监听当下握着的连接，停机时用它兜底。
//
// 为什么 http.Server 自己那本账不够：Shutdown 超时返回后它不会去动任何连接，
// 而 Close 关得到的连接里**不包括被 Hijack 过的**——WebSocket 升级之后那条连接
// 就从 Server 的账本上摘掉了，只有拿着 net.Conn 的人能关它。反向代理是支持
// WebSocket 的，所以这类连接一定会出现：不自己记一份，改一次配置就漏一批连接，
// 端口迟迟不放、旧配置的处理器还在服务请求。
type connTracker struct {
	mu    sync.Mutex
	conns map[net.Conn]struct{}
}

func newConnTracker() *connTracker {
	return &connTracker{conns: make(map[net.Conn]struct{})}
}

// wrap 把监听器套上台账：Accept 出来的连接登记，连接关闭时销账。
// 台账为 nil（直接组装 listenServer 的测试）时原样返回，不改变行为。
func (t *connTracker) wrap(ln net.Listener) net.Listener {
	if t == nil {
		return ln
	}
	return &trackedListener{Listener: ln, tracker: t}
}

func (t *connTracker) add(c net.Conn) {
	t.mu.Lock()
	t.conns[c] = struct{}{}
	t.mu.Unlock()
}

func (t *connTracker) remove(c net.Conn) {
	t.mu.Lock()
	delete(t.conns, c)
	t.mu.Unlock()
}

// closeAll 关掉台账上剩下的全部连接。
// 只在停机收尾时调用：正常走完的连接早已自己销账，这里剩下的是"还赖着的"。
func (t *connTracker) closeAll() int {
	if t == nil {
		return 0
	}
	t.mu.Lock()
	left := make([]net.Conn, 0, len(t.conns))
	for c := range t.conns {
		left = append(left, c)
	}
	t.conns = make(map[net.Conn]struct{})
	t.mu.Unlock()
	for _, c := range left {
		_ = c.Close()
	}
	return len(left)
}

type trackedListener struct {
	net.Listener
	tracker *connTracker
}

func (l *trackedListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	l.tracker.add(c)
	return &trackedConn{Conn: c, tracker: l.tracker}, nil
}

// trackedConn 在关闭时销账。销账用的键是**内层的** net.Conn（登记时用的就是它），
// 因为 closeAll 关的也是内层那个对象。
type trackedConn struct {
	net.Conn
	tracker *connTracker
	once    sync.Once
}

func (c *trackedConn) Close() error {
	c.once.Do(func() { c.tracker.remove(c.Conn) })
	return c.Conn.Close()
}

// guardBodyRead 给这次请求的正文读取装上停滞超时（见 bodyStallTimeout）。
//
// 有意做成"只管正文"而不是给整条连接设一个读超时：后者会把 WebSocket 与 SSE
// 这类长连接按同一把尺子切掉，也会跟 http.Server 自己给 keep-alive 设的那个
// 空闲超时打架。
//
// w 必须是 Server 交给最外层处理器的那个原始 ResponseWriter：读超时要落到连接
// （HTTP/2 下是这条流）上，中间再包一层 statusWriter 之类的东西之后就取不到了。
func guardBodyRead(w http.ResponseWriter, r *http.Request) {
	if r.Body == nil || r.Body == http.NoBody {
		return
	}
	// 协议升级（WebSocket）的请求跳过：它握手成功之后连接会被 Hijack 走，
	// 而设在连接上的读超时会跟着留在那条连接上，把之后每一次空闲超过一分钟的
	// 长连接切掉。这类请求是 GET、本来也没有正文，绕开它一点代价都没有。
	if isUpgradeRequest(r) {
		return
	}
	rc := http.NewResponseController(w)
	if err := rc.SetReadDeadline(time.Now().Add(bodyStallTimeout)); err != nil {
		return // 这层 ResponseWriter 不支持（理论上 HTTP/1.1 与 HTTP/2 都支持），当这道闸不存在
	}
	r.Body = &progressBody{ReadCloser: r.Body, rc: rc}
}

// isUpgradeRequest 这次请求是不是在谈协议升级。
func isUpgradeRequest(r *http.Request) bool {
	if r.Header.Get("Upgrade") == "" {
		return false
	}
	for _, v := range r.Header.Values("Connection") {
		for _, tok := range strings.Split(v, ",") {
			if strings.EqualFold(strings.TrimSpace(tok), "upgrade") {
				return true
			}
		}
	}
	return false
}

// progressBody 每读到一点东西就把读超时往后推。
type progressBody struct {
	io.ReadCloser
	rc *http.ResponseController
}

func (b *progressBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	if n > 0 && err == nil {
		_ = b.rc.SetReadDeadline(time.Now().Add(bodyStallTimeout))
	}
	if err != nil {
		// 正文读完了（io.EOF）或读坏了：把超时撤掉。
		// 必须撤——它设在连接上，留着就会管到后面的事情上去：一次耗时几分钟的
		// 大文件下载期间，Server 在后台盯着连接的那次读会因为这个超时报错，
		// 而它报错的后果是**取消这次请求的 ctx**，下载正传到一半被掐断。
		b.clear()
	}
	return n, err
}

func (b *progressBody) Close() error {
	// 处理器返回后 Server 一定会关掉正文（也可能是处理器自己提前关），
	// 所以这里是"撤掉超时"最靠得住的一处。
	b.clear()
	return b.ReadCloser.Close()
}

func (b *progressBody) clear() { _ = b.rc.SetReadDeadline(time.Time{}) }

// writeStallTimeout 一次写操作允许卡住多久。
//
// 这道闸补的是 bodyStallTimeout 的对称缺口。请求体那侧已经看住了「发一半就不动」，
// 响应体这侧此前什么都没有：客户端发一个完全正常的请求要一个大文件，然后**不读**
// （或者每分钟读一个字节），服务端的写就卡在满掉的发送缓冲上，无限期地占着
// 一条连接、一个 goroutine 与它的读写缓冲。这条监听的并发连接数是有上限的
// （maxConnsPerListener = 2000），而 LimitListener 超限时是让 Accept **阻塞**——
// 于是两千条赖着不读的连接就能让正常访客一个都连不进来。这类手法有现成的名字
// （slow read / slowloris 的下行版本），成本对攻击方近乎为零：只要不调用 recv。
//
// 取值与 bodyStallTimeout 一致（60 秒），语义也一致：不是总时长上限，而是
// 「一段之内必须有进展」。整段逻辑见 statusWriter.Write 与 statusWriter.ReadFrom。
const writeStallTimeout = 60 * time.Second

// writeChunkBytes 委托给底层 ReaderFrom（sendfile 零拷贝）时，一次最多交出去多少字节。
//
// 为什么必须分段：写超时是**绝对时刻**，而 sendfile 一次调用可以把整个文件推完。
// 不分段就等于给整次下载设了 60 秒总时限，一个 2 GB 的备份包必然被掐断。
// 分段之后每段之前重设一次超时，于是"有进展就续期"这个语义在零拷贝路径上也成立。
//
// 段长的另一面是它给传输速率划了一条下限：一段必须在 writeStallTimeout 内走完，
// 因此持续速率低于 64 KiB / 60 s ≈ 1.1 KB/s（约 9 kbps）的连接会被切掉。
// 这条线刻意压得比任何还能用的网络都低——2G 都在它十倍以上——所以它切掉的
// 只会是"故意不读"的那一类。段长同时也就是 Write 那侧的天然粒度
// （io.CopyBuffer 与 ReverseProxy 的复制缓冲都是 32 KiB），两侧口径因此一致。
const writeChunkBytes = 64 << 10

// writeGuard 给一次响应的写入装上停滞超时。
//
// 用法是「每次写之前 arm、写完 disarm」，而不是一开始设一个总时限：
// 两次写**之间**的空闲不该被管——那是服务端自己的事（反代在等上游、SSE 在等下一个
// 事件），而这道闸要防的是"写不出去"。把空闲也算进来会把长轮询与 SSE 一并切掉。
//
// 零值不可用；nil 接收者表示"这次响应不设这道闸"，全部方法都对 nil 安全。
type writeGuard struct {
	rc *http.ResponseController
	// off 底层 ResponseWriter 不支持写超时（httptest.ResponseRecorder 就是），
	// 第一次失败之后就不再重试——否则每个写都要白跑一次穿透 Unwrap 链的查找。
	off atomic.Bool
}

// newWriteGuard 为这次响应造一道写停滞超时。
//
// w 必须是 Server 交给最外层处理器的那个原始 ResponseWriter：超时要落到连接
// （HTTP/2 下是这条流）上。返回 nil 表示这次请求不设这道闸。
func newWriteGuard(w http.ResponseWriter, r *http.Request) *writeGuard {
	// 协议升级（WebSocket）跳过，理由同 guardBodyRead：握手成功后连接被 Hijack 走，
	// 之后的收发不再经过 ResponseWriter，而设在连接上的超时会留在那条连接上，
	// 把之后每一次安静超过一分钟的长连接切掉。
	if isUpgradeRequest(r) {
		return nil
	}
	return &writeGuard{rc: http.NewResponseController(w)}
}

// arm 把写超时设到 now + writeStallTimeout。紧贴着一次会阻塞的写调用之前。
func (g *writeGuard) arm() {
	if g == nil || g.off.Load() {
		return
	}
	if err := g.rc.SetWriteDeadline(time.Now().Add(writeStallTimeout)); err != nil {
		g.off.Store(true)
	}
}

// disarm 撤掉写超时。写调用返回后立刻撤，让两次写之间的空闲不受管辖。
//
// 撤这一步不能省：超时设在连接上，留着就会管到后面的事情上去——最直接的后果是
// keep-alive 的下一个请求刚开始就带着一个已经过期的写超时。
func (g *writeGuard) disarm() {
	if g == nil || g.off.Load() {
		return
	}
	if err := g.rc.SetWriteDeadline(time.Time{}); err != nil {
		g.off.Store(true)
	}
}

// writeOnly 只暴露 Write，用来阻断 io.Copy 挑中 ReadFrom 造成的递归。
// （internal/errpage 里有一个同名的同款，两处都只在自己包内用，不值得为它再起一个包。）
type writeOnly struct{ w io.Writer }

func (o writeOnly) Write(b []byte) (int, error) { return o.w.Write(b) }
