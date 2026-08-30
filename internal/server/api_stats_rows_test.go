package server

import (
	"encoding/json"
	"net/http"
	"path/filepath"
	"testing"

	"github.com/gin-gonic/gin"

	"mantou/internal/config"
	"mantou/internal/runstats"
)

// decodeRows 取出列表应答里的那一层数组。
// 列表统一包在 {"data": …} 里（respondOK），照数组直接解会失败。
func decodeRows(body []byte) ([]map[string]any, error) {
	var envelope struct {
		Data []map[string]any `json:"data"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		return nil, err
	}
	return envelope.Data, nil
}

// 列表页上那几个统计数字必须真的从内存统计里取出来送到前端（A7）。
//
// 这一条补的是搬家之后新出现的缝：字段从配置结构体搬进 internal/runstats 之后，
// 「配置里存着 → 序列化时自动带上」变成了「在 API 这一层手工拼一次」（见 rows 钩子）。
// 手工拼的那一步没有任何编译期约束——把 st.Received 写成 st.Rejected、
// 或者干脆把 rows 钩子删掉，都能编译、能跑、返回 200，前端只会显示成一片 0，
// 而 config 包那两条用例（TestWebhookStatsNeverReachDisk 等）钉的是「不许落盘」，
// 对「读不出来」一无所知：统计压根没进磁盘，那两条反而更绿。
//
// 三个模块合在一个用例里，是因为要钉的性质完全相同，而三处实现各自独立
// （接收器与通知目标的钩子闭包在 s.deps.Stats 上，网络唤醒闭包在 wolResource 的入参上）——
// 只钉一处，另两处照样能悄悄坏掉。
func TestListRowsCarryMemoryStats(t *testing.T) {
	gin.SetMode(gin.TestMode)
	manager := config.NewManager(filepath.Join(t.TempDir(), "config.json"))
	if err := manager.Load(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = manager.Close() })
	if err := manager.Update(func(c *config.Config) {
		c.WebhookReceivers = []config.WebhookReceiver{{
			ID: "h1", Name: "接收器", Enabled: true, Path: "hook",
		}}
		c.NotifyTargets = []config.NotifyTarget{{
			ID: "t1", Name: "目标", Enabled: true, Type: "dingtalk",
			URL: "https://example.com/hook",
		}}
		c.WOLDevices = []config.WOLDevice{{
			ID: "w1", Name: "设备", Enabled: true,
			MAC: "AA:BB:CC:DD:EE:FF", Broadcast: "192.168.1.255", Port: 9,
		}}
	}); err != nil {
		t.Fatal(err)
	}

	// 每个数取一个互不相同的值：写串了（把收下的填进被挡掉的那一格之类）也能看出来。
	stats := runstats.New()
	for i := 0; i < 11; i++ {
		stats.Received("h1", 1_700_000_001, "已接收")
	}
	for i := 0; i < 3; i++ {
		stats.Rejected("h1")
	}
	for i := 0; i < 7; i++ {
		stats.Sent("t1", 1_700_000_002, "已发送", true)
	}
	for i := 0; i < 2; i++ {
		stats.Sent("t1", 1_700_000_002, "已发送", false)
	}
	for i := 0; i < 5; i++ {
		stats.Woke("w1", 1_700_000_003, "已发送")
	}

	s := &Server{deps: Deps{Config: manager, Stats: stats}}
	router := gin.New()
	g := router.Group("")
	s.registerWebhookReceivers(g)
	s.registerNotifyTargets(g)
	registerCRUD(s, g, "wol", wolResource(stats))

	cases := []struct {
		path string
		want map[string]float64
		// 状态文本那一格的键名各不相同：网络唤醒叫 lastResult，另两个叫 lastStatus。
		// 不统一是刻意的——搬家时 JSON 字段名一律照旧，好让前端一行都不用改。
		statusKey string
	}{
		{"/webhook/receivers", map[string]float64{
			"lastReceivedAt": 1_700_000_001, "receivedCount": 11, "rejectedCount": 3,
		}, "lastStatus"},
		{"/webhook/targets", map[string]float64{
			"lastSentAt": 1_700_000_002, "sentCount": 7, "failCount": 2,
		}, "lastStatus"},
		{"/wol", map[string]float64{
			"lastWakeAt": 1_700_000_003, "wakeCount": 5,
		}, "lastResult"},
	}
	for _, tc := range cases {
		w := performJSONRequest(router, http.MethodGet, tc.path, "")
		if w.Code != http.StatusOK {
			t.Fatalf("GET %s 返回 %d：%s", tc.path, w.Code, w.Body.String())
		}
		rows, err := decodeRows(w.Body.Bytes())
		if err != nil {
			t.Fatalf("GET %s 的应答解不开: %v（%s）", tc.path, err, w.Body.String())
		}
		if len(rows) != 1 {
			t.Fatalf("GET %s 返回 %d 行，应为 1 行", tc.path, len(rows))
		}
		for key, want := range tc.want {
			got, ok := rows[0][key].(float64)
			if !ok {
				t.Errorf("GET %s 的应答里没有 %q：统计没有拼进列表，面板上这个数会一直是 0。应答：%s",
					tc.path, key, w.Body.String())
				continue
			}
			if got != want {
				t.Errorf("GET %s 的 %q = %v，应为 %v：这一格接错了内存里的另一个数",
					tc.path, key, got, want)
			}
		}
		// 状态文本单独看：它与上面几个数走同一个钩子，但类型不同（字符串），
		// 拼漏了不会体现在任何一个数字上。
		if v, _ := rows[0][tc.statusKey].(string); v == "" {
			t.Errorf("GET %s 的 %s 是空的：上次结果没有拼进列表。应答：%s",
				tc.path, tc.statusKey, w.Body.String())
		}
	}
}

// 统计库缺省（nil）时列表仍要正常返回，那几个数一律为 0。
//
// 这不是假想的形态：wolResource 的注释明确许诺「stats 可以是 nil」，
// 好让不关心统计的用例复用线上那份定义（api_wol_limit_test.go 就靠这一点）。
// 许诺写在注释里而不钉住，等于没有——nil 接收器安全性由 runstats 自己的用例保证，
// 这里钉的是「本层没有绕开它自己解引用一次」。
func TestListRowsSurviveNilStats(t *testing.T) {
	gin.SetMode(gin.TestMode)
	manager := config.NewManager(filepath.Join(t.TempDir(), "config.json"))
	if err := manager.Load(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = manager.Close() })
	if err := manager.Update(func(c *config.Config) {
		c.WOLDevices = []config.WOLDevice{{
			ID: "w1", Name: "设备", Enabled: true,
			MAC: "AA:BB:CC:DD:EE:FF", Broadcast: "192.168.1.255", Port: 9,
		}}
	}); err != nil {
		t.Fatal(err)
	}
	s := &Server{deps: Deps{Config: manager}}
	router := gin.New()
	registerCRUD(s, router.Group(""), "wol", wolResource(nil))

	w := performJSONRequest(router, http.MethodGet, "/wol", "")
	if w.Code != http.StatusOK {
		t.Fatalf("不带统计库时列表返回 %d，应为 200：%s", w.Code, w.Body.String())
	}
	rows, err := decodeRows(w.Body.Bytes())
	if err != nil {
		t.Fatalf("应答解不开: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("返回 %d 行，应为 1 行", len(rows))
	}
	if got, _ := rows[0]["wakeCount"].(float64); got != 0 {
		t.Fatalf("不带统计库时 wakeCount = %v，应为 0", got)
	}
}
