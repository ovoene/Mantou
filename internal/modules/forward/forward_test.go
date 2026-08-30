package forward

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"testing"
	"time"
)

// dialPair 返回一对已建立的本地 TCP 连接（拨号侧, 接受侧）。
func dialPair(t *testing.T) (*net.TCPConn, *net.TCPConn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	type accepted struct {
		conn net.Conn
		err  error
	}
	ch := make(chan accepted, 1)
	go func() {
		conn, err := ln.Accept()
		ch <- accepted{conn: conn, err: err}
	}()

	dialed, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	got := <-ch
	if got.err != nil {
		dialed.Close()
		t.Fatal(got.err)
	}
	t.Cleanup(func() {
		dialed.Close()
		got.conn.Close()
	})
	return dialed.(*net.TCPConn), got.conn.(*net.TCPConn)
}

// 客户端发完请求后 shutdown(SHUT_WR) 是合法模式：转发必须把「写方向关闭」单独传递过去，
// 而不是一见 EOF 就把连接整个关掉——后者会把后端尚未发出的响应截断。
func TestPipeHalfCloseLetsUpstreamAnswerAfterClientEOF(t *testing.T) {
	client, forwardIn := dialPair(t)    // 客户端 ↔ 转发入口
	forwardOut, upstream := dialPair(t) // 转发出口 ↔ 后端

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	piped := make(chan struct{})
	go func() {
		pipe(ctx, forwardIn, forwardOut)
		close(piped)
	}()

	// 后端：读满整个请求（以 EOF 为界）之后才回响应。
	upDone := make(chan error, 1)
	go func() {
		req, err := io.ReadAll(upstream)
		if err != nil {
			upDone <- err
			return
		}
		if string(req) != "request" {
			upDone <- fmt.Errorf("后端收到的请求不完整: %q", req)
			return
		}
		_, err = upstream.Write([]byte("response"))
		upstream.Close()
		upDone <- err
	}()

	if _, err := client.Write([]byte("request")); err != nil {
		t.Fatal(err)
	}
	if err := client.CloseWrite(); err != nil {
		t.Fatal(err)
	}

	if err := client.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(client)
	if err != nil {
		t.Fatalf("读取响应失败: %v（读到 %q）", err, got)
	}
	if string(got) != "response" {
		t.Fatalf("客户端半关闭后响应被截断: %q", got)
	}
	if err := <-upDone; err != nil {
		t.Fatal(err)
	}
	select {
	case <-piped:
	case <-time.After(10 * time.Second):
		t.Fatal("两个方向均已结束，pipe 却未返回")
	}
}

// 模块重载 / 进程退出会取消 ctx：此时必须强制关闭两端，否则阻塞在读上的方向不会退出，
// runner.stop 的 wg.Wait 将一直等待。
func TestPipeClosesConnectionsOnContextCancel(t *testing.T) {
	_, forwardIn := dialPair(t)
	forwardOut, upstream := dialPair(t)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		pipe(ctx, forwardIn, forwardOut)
		close(done)
	}()

	cancel()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("ctx 取消后 pipe 未返回")
	}

	if err := upstream.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	_, err := upstream.Read(make([]byte, 1))
	if err == nil {
		t.Fatal("ctx 取消后后端连接应已关闭")
	}
	if errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatal("ctx 取消后后端连接仍处于打开状态")
	}
}
