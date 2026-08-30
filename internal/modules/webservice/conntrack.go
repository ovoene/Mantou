package webservice

import (
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// 本文件是监听层的两道收尾保护：连接台账（停机时能真正把连接关掉）与请求体停滞超时。
// 两件事都只在 listenServer 内部用（见 listener.go 的 start / close / handler）。

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
