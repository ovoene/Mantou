package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"mantou/internal/config"
	"mantou/internal/logx"
)

// 更新清单地址（Update.ManifestURL）完全由用户填写，和「动态域名从 URL 取址」
// 「计划任务 HTTP 动作」「消息目标」是同一类出站，本该同受「内网防护」开关约束。
// 原来这一条走的是裸 http.Client，开关打开后其余三条被堵上、这一条照样能打内网。
// 下面这组测试钉住这条路确实接在开关上（见 5-K）。
//
// netguard 是在 Dialer.Control 里按解析出的 IP 拦的，所以拿一个跑在回环上的
// httptest 服务器就能真跑通这件事：开关打开时连不上，且服务端一次都没被访问到。

// newManifestServer 起一个返回固定清单的回环服务器，并给出它被访问过几次。
func newManifestServer(t *testing.T, version string) (*httptest.Server, *atomic.Int64) {
	t.Helper()
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"version":     version,
			"url":         "https://example.com/download",
			"description": "测试清单",
		})
	}))
	t.Cleanup(srv.Close)
	return srv, &hits
}

// TestFetchManifestHonorsBlockPrivateNetwork 开关关闭时拉得到，打开时拉不到。
//
// 两条腿都要：只验"打开时失败"的话，把 client 换成任何一个坏掉的客户端都能过；
// 加上"关闭时成功"才说明失败确实来自这个开关。
func TestFetchManifestHonorsBlockPrivateNetwork(t *testing.T) {
	srv, hits := newManifestServer(t, "9.9.9")

	ver, releaseURL, desc, err := fetchManifest(context.Background(), srv.URL, false)
	if err != nil {
		t.Fatalf("开关关闭时应能拉取清单：%v", err)
	}
	if !strings.Contains(ver, "9.9.9") {
		t.Fatalf("版本号解析结果是 %q", ver)
	}
	if releaseURL != "https://example.com/download" || desc != "测试清单" {
		t.Fatalf("清单字段没解析对：url=%q desc=%q", releaseURL, desc)
	}
	if got := hits.Load(); got != 1 {
		t.Fatalf("服务端被访问 %d 次，期望 1 次", got)
	}

	if _, _, _, err = fetchManifest(context.Background(), srv.URL, true); err == nil {
		t.Fatal("开关打开时清单地址指向回环地址，应被拒绝")
	}
	// 拦截必须发生在连接之前，而不是"连上了再丢掉响应"。
	if got := hits.Load(); got != 1 {
		t.Fatalf("开关打开后服务端仍被访问了 %d 次", got-1)
	}
}

// TestUpdateCheckWiresBlockPrivateNetwork 「检查更新」这个接口真的把开关值传了下去。
//
// 5-K 的实际毛病不是 netguard 不好用，而是这一处没接上去，
// 所以除了 fetchManifest 本身，还要从接口这一层量一次。
func TestUpdateCheckWiresBlockPrivateNetwork(t *testing.T) {
	gin.SetMode(gin.TestMode)
	srv, hits := newManifestServer(t, "9.9.9")

	cfg := config.NewManager(filepath.Join(t.TempDir(), "config.json"))
	if err := cfg.Load(); err != nil {
		t.Fatal(err)
	}
	if err := cfg.Update(func(c *config.Config) { c.Update.ManifestURL = srv.URL }); err != nil {
		t.Fatal(err)
	}
	s := &Server{deps: Deps{Config: cfg, Log: logx.New(logx.Options{})}}

	// updateCheckStore 是包级缓存，成功那一支会写进去；别把结果留给同包的其它测试。
	t.Cleanup(func() {
		updateCheckStore.mu.Lock()
		updateCheckStore.resp = nil
		updateCheckStore.expiresAt = time.Time{}
		updateCheckStore.mu.Unlock()
	})

	// force=1 跳过缓存，每次都真去拉一次。
	check := func() map[string]any {
		t.Helper()
		w := httptest.NewRecorder()
		ctx, _ := gin.CreateTestContext(w)
		ctx.Request = httptest.NewRequest(http.MethodGet, "/meta/update-check?force=1", nil)
		s.handleUpdateCheck(ctx)
		if w.Code != http.StatusOK {
			t.Fatalf("接口返回 %d：%s", w.Code, w.Body.String())
		}
		var resp struct {
			Data map[string]any `json:"data"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("响应解析失败：%v（%s）", err, w.Body.String())
		}
		return resp.Data
	}

	// 前提：开关关闭时这个清单地址是通的，否则下面那条断言说明不了任何事。
	data := check()
	if data["networkError"] == true {
		t.Fatalf("测试前提不成立：开关关闭时就拉不到清单（%v）", data)
	}
	if got, _ := data["latestVersion"].(string); !strings.Contains(got, "9.9.9") {
		t.Fatalf("测试前提不成立：没读到清单里的版本号（latestVersion=%q）", got)
	}
	before := hits.Load()

	if err := cfg.Update(func(c *config.Config) { c.Settings.Security.BlockPrivateNetwork = true }); err != nil {
		t.Fatal(err)
	}
	data = check()
	if data["networkError"] != true {
		t.Fatalf("开关打开后清单指向回环地址，应报网络不可用，实际 %v", data)
	}
	if got := hits.Load(); got != before {
		t.Fatalf("开关打开后清单服务端仍被访问了 %d 次", got-before)
	}
}
