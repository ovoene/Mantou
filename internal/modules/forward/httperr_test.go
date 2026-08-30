package forward

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

// 本文件盯的是「后端连不上时给浏览器回一页统一样式的错误页」（见 httperr.go）。
//
// 这件事的风险全在"认错了协议"上：端口转发跑的可能是网页，也可能是远程终端、
// 数据库连接，往一条非网页的连接里写 HTTP 响应就是在往人家的协议里插脏字节。
// 所以要钉住的除了"该出的时候出得来"，更要紧的是下面这几条**不该出**：
// 非 HTTP 的开头、非浏览器的客户端、非 GET/HEAD 的方法，以及——最要紧的——
// 后端正常时那条路一个字节都不许碰。

// deadForward 起一条"目标端口没人听"的 TCP 转发规则，返回一条已连上它监听端口的连接。
func deadForward(t *testing.T) net.Conn {
	t.Helper()
	var g connGate
	// 目标取一个刚释放的空闲端口：拨号会立刻被拒，正是"后端连不上"。
	_, listen := startRunner(t, &g, "tcp", freePort(t))
	c, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", listen))
	if err != nil {
		t.Fatalf("连不上转发端口: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	// 比 errPageWait 宽出许多：这个期限是给"卡住"兜底的，不参与被测行为。
	if err := c.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	return c
}

// 浏览器撞上一条后端已经宕掉的转发：该拿到 502 与本项目的卡片页，
// 而不是浏览器自己那句"无法访问此网站"。
func TestBackendDownServesCardPageToBrowser(t *testing.T) {
	c := deadForward(t)
	if _, err := c.Write([]byte("GET /a/b HTTP/1.1\r\nHost: example.test\r\nAccept: text/html\r\n\r\n")); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		t.Fatalf("没读到响应: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("状态码 = %d，要 502", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Fatalf("Content-Type = %q", ct)
	}
	// 写完就关：这条连接上的下一个请求同样连不上后端，留着它是骗客户端。
	if !resp.Close {
		t.Fatal("响应没有声明 Connection: close")
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("读正文失败: %v", err)
	}
	page := string(body)
	if !strings.Contains(page, "站点暂时不可用") {
		t.Fatalf("不是统一模板的卡片页: %q", page)
	}
	// 回显客户端自己发来的地址——它本来就知道，不构成泄露。
	if !strings.Contains(page, "example.test/a/b") {
		t.Fatal("卡片上没有回显访问地址")
	}
	// 转发目标是内网地址，页面是给任何能连上这个端口的人看的，一个字都不许写。
	if strings.Contains(page, "127.0.0.1") {
		t.Fatalf("页面泄露了转发目标: %q", page)
	}
}

// 非 HTTP 的开头（这里用远程终端的握手串）：一个字节都不许写回去。
// 这一条是整件事的底线——认错协议就是往人家的会话里插脏字节。
func TestBackendDownStaysSilentForNonHTTPClient(t *testing.T) {
	c := deadForward(t)
	if _, err := c.Write([]byte("SSH-2.0-OpenSSH_9.6\r\n")); err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(c)
	if err != nil {
		t.Fatalf("等连接关闭时出错: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("非 HTTP 的连接被写入了 %d 字节: %q", len(got), got)
	}
}

// 是 HTTP，但不是浏览器发的（Accept 里没有 text/html）：保持改动之前的行为，直接关闭。
// 命令行工具、探针、各类客户端库要的是能解析的响应，不是一页 HTML。
func TestBackendDownStaysSilentForNonBrowserClient(t *testing.T) {
	c := deadForward(t)
	if _, err := c.Write([]byte("GET / HTTP/1.1\r\nHost: example.test\r\nAccept: */*\r\n\r\n")); err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(c)
	if err != nil {
		t.Fatalf("等连接关闭时出错: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("非浏览器客户端收到了 %d 字节: %q", len(got), got)
	}
}

// 是浏览器，但方法不是 GET/HEAD：同样不写。表单提交的失败响应多半是给程序读的。
func TestBackendDownStaysSilentForPost(t *testing.T) {
	c := deadForward(t)
	req := "POST /submit HTTP/1.1\r\nHost: example.test\r\nAccept: text/html\r\nContent-Length: 2\r\n\r\nhi"
	if _, err := c.Write([]byte(req)); err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(c)
	if err != nil {
		t.Fatalf("等连接关闭时出错: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("POST 收到了 %d 字节: %q", len(got), got)
	}
}

// HEAD 只给头不给正文，但 Content-Length 照给——那正是 HEAD 要问的。
func TestBackendDownHeadHasNoBody(t *testing.T) {
	c := deadForward(t)
	if _, err := c.Write([]byte("HEAD / HTTP/1.1\r\nHost: example.test\r\nAccept: text/html\r\n\r\n")); err != nil {
		t.Fatal(err)
	}
	head, err := http.NewRequest(http.MethodHead, "http://example.test/", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(c), head)
	if err != nil {
		t.Fatalf("没读到响应: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("状态码 = %d，要 502", resp.StatusCode)
	}
	if resp.ContentLength <= 0 {
		t.Fatalf("HEAD 也要给出正文长度，得到 %d", resp.ContentLength)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("读正文失败: %v", err)
	}
	if len(body) != 0 {
		t.Fatalf("HEAD 不该有正文，收到 %d 字节", len(body))
	}
}

// 后端正常时，这条路一个字节都不许碰。
//
// 这是本文件最要紧的一条：错误页那段代码会从客户端连接上读请求，若不小心挪到了
// 拨号之前（或"先探一眼再决定"），被读走的那一串字节就再也送不到后端了——
// 表现是转发时不时丢掉请求的开头，而单看错误页的几条测试全都是绿的。
func TestHealthyForwardIsUntouched(t *testing.T) {
	var g connGate
	target, _ := echoTCP(t)
	_, listen := startRunner(t, &g, "tcp", target)
	c, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", listen))
	if err != nil {
		t.Fatalf("连不上转发端口: %v", err)
	}
	defer c.Close()
	if err := c.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	// 刻意发一串"最像网页请求"的字节：它必须原样到达后端。
	sent := "GET / HTTP/1.1\r\nHost: example.test\r\nAccept: text/html\r\n\r\n"
	if _, err := c.Write([]byte(sent)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len(sent))
	if _, err := io.ReadFull(c, buf); err != nil {
		t.Fatalf("后端没有原样回写: %v（读到 %q）", err, buf)
	}
	if string(buf) != sent {
		t.Fatalf("请求被改动了:\n发出 %q\n收回 %q", sent, buf)
	}
}

// 规则正在停的时候不再等那一秒。等待用的是连接期限而不是 ctx，所以停在等待中途的
// 连接仍会各自挂满 errPageWait；把已取消的挡在门外能少掉大部分——而这一条正是
// "停规则要立刻停"与"回一页体面的错误页"之间那个取舍的落点。
func TestBackendDownSkipsPageWhenRunnerStopping(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r := &runner{ctx: ctx}

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	// net.Pipe 是同步的：对面不读，这个写就一直阻塞。所以放到协程里，
	// 靠 defer client.Close() 收尾。
	go func() {
		_, _ = client.Write([]byte("GET /a HTTP/1.1\r\nHost: example.test\r\nAccept: text/html\r\n\r\n"))
	}()

	done := make(chan struct{})
	go func() {
		defer close(done)
		r.replyBackendDown(server)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("规则已取消，却还在等客户端把请求发过来")
	}

	if err := client.SetReadDeadline(time.Now().Add(200 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if n, _ := client.Read(make([]byte, 64)); n != 0 {
		t.Fatalf("规则已取消，不该回任何字节，实际回了 %d 字节", n)
	}
}
