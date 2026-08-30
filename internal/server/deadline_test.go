package server

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

// TestExtendRequestDeadlinesSupported 确认 gin 的 ResponseWriter 能被 http.ResponseController
// 一路 Unwrap 到底层连接，从而真的推得动读写截止时间。
//
// 这条断言看着琐碎，但它守的正是"修复变成空操作"这种最难发现的回归：
// 一旦 gin 某个版本不再实现 Unwrap()，SetReadDeadline 会安静地返回 ErrNotSupported，
// 上传接口便悄悄退回 30 秒全局超时，只在慢链路上以"传到一半失败"的形式暴露。
func TestExtendRequestDeadlinesSupported(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.POST("/x", func(c *gin.Context) {
		rc := http.NewResponseController(c.Writer)
		until := time.Now().Add(time.Minute)
		if err := rc.SetReadDeadline(until); err != nil {
			c.String(http.StatusInternalServerError, "read: "+err.Error())
			return
		}
		if err := rc.SetWriteDeadline(until); err != nil {
			c.String(http.StatusInternalServerError, "write: "+err.Error())
			return
		}
		// 读完请求体，确认放宽后的读路径仍然正常。
		body, err := io.ReadAll(c.Request.Body)
		if err != nil {
			c.String(http.StatusInternalServerError, "body: "+err.Error())
			return
		}
		c.String(http.StatusOK, "ok:"+string(body))
	})

	// 必须用真实连接：httptest.NewRecorder 的 ResponseWriter 不支持 deadline，
	// 只有走过 net/http 的 conn 才能验证 Unwrap 链是否完整。
	//
	// 起服务之前把超时配好（NewUnstartedServer + Start），不能起完再改 Config：
	// Serve 一开始就有 goroutine 在读这两个字段，之后写它们是数据竞争
	// （-race 下报在 net/http.(*Server).Serve 与本函数之间）。
	srv := httptest.NewUnstartedServer(r)
	// 服务端超时配置照搬 New() 里的取值，确保被测路径与生产一致。
	srv.Config.ReadTimeout = 30 * time.Second
	srv.Config.WriteTimeout = 60 * time.Second
	srv.Start()
	defer srv.Close()

	resp, err := http.Post(srv.URL+"/x", "text/plain", strings.NewReader("payload"))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	got, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("放宽截止时间失败: status=%d body=%s", resp.StatusCode, got)
	}
	if string(got) != "ok:payload" {
		t.Fatalf("响应异常: %s", got)
	}
}
