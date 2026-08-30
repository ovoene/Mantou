package server

import (
	"fmt"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"mantou/internal/config"
	"mantou/internal/runstats"
)

// newWOLCRUDTest 用**线上那份** wolResource() 定义搭一套 CRUD 路由，
// 从而连 maxCount 是否真的接上去了一并验证（照抄字段的测试验不出这一点）。
func newWOLCRUDTest(t *testing.T) (*config.Manager, *gin.Engine) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	manager := config.NewManager(filepath.Join(t.TempDir(), "config.json"))
	if err := manager.Load(); err != nil {
		t.Fatal(err)
	}
	// 统计库照线上那样传进去（列表里的唤醒次数、删除时的 Forget 都走它）。
	// 它只在内存里，起一份的代价可以忽略。
	stats := runstats.New()
	s := &Server{deps: Deps{Config: manager, Stats: stats}}
	router := gin.New()
	registerCRUD(s, router.Group(""), "wol", wolResource(stats))
	return manager, router
}

// seedWOLDevices 直接往配置里塞 n 台设备，绕开 HTTP：模拟「从旧版本升级上来」
// 或「手工编辑 config.json」得到的存量配置，也让上限测试不必发几百个请求。
func seedWOLDevices(t *testing.T, manager *config.Manager, n int) {
	t.Helper()
	devices := make([]config.WOLDevice, 0, n)
	for i := 0; i < n; i++ {
		devices = append(devices, config.WOLDevice{
			ID:        "seed-" + strconv.Itoa(i),
			Enabled:   true,
			Name:      "存量设备 " + strconv.Itoa(i),
			MAC:       fmt.Sprintf("AA:BB:CC:00:%02X:%02X", i/256, i%256),
			Broadcast: "192.168.1.255",
			Port:      9,
		})
	}
	if err := manager.Update(func(cfg *config.Config) { cfg.WOLDevices = devices }); err != nil {
		t.Fatal(err)
	}
}

const newWOLDeviceBody = `{"name":"新设备","enabled":true,"mac":"AA:BB:CC:DD:EE:FF","broadcast":"192.168.1.255","port":9}`

// TestWOLCreateRejectedAtCap 锁定 W-13：设备条数必须有上限。
//
// 修复前 registerCRUD 对 wol 没有任何数量限制，而每台启用定时唤醒的设备各占一条常驻协程、
// 每一拍还要串行回写运行态（见 config.MaxWOLDevices），几百台就不是「变慢」而是「不响应」。
func TestWOLCreateRejectedAtCap(t *testing.T) {
	manager, router := newWOLCRUDTest(t)
	seedWOLDevices(t, manager, config.MaxWOLDevices)

	w := performJSONRequest(router, http.MethodPost, "/wol", newWOLDeviceBody)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("已有 %d 台（上限值）时新增返回 %d，应为 400：数量上限没有生效",
			config.MaxWOLDevices, w.Code)
	}
	// 报错要说清「上限多少」与「现在多少」，否则用户只知道被拒、不知道该删几条。
	body := w.Body.String()
	for _, want := range []string{"上限", strconv.Itoa(config.MaxWOLDevices)} {
		if !strings.Contains(body, want) {
			t.Errorf("错误提示里没有 %q：%s", want, body)
		}
	}
	if got := len(manager.Get().WOLDevices); got != config.MaxWOLDevices {
		t.Fatalf("被拒的新增仍改动了配置：%d 台，应仍为 %d 台", got, config.MaxWOLDevices)
	}
}

// TestWOLCreateAllowedJustBelowCap 差一条到上限时必须放行，
// 且放行后正好到上限——上限是「不超过」而不是「不到」。
func TestWOLCreateAllowedJustBelowCap(t *testing.T) {
	manager, router := newWOLCRUDTest(t)
	seedWOLDevices(t, manager, config.MaxWOLDevices-1)

	w := performJSONRequest(router, http.MethodPost, "/wol", newWOLDeviceBody)
	if w.Code != http.StatusOK {
		t.Fatalf("差一条到上限时新增返回 %d，应为 200：上限把合法操作也拦了。%s", w.Code, w.Body.String())
	}
	if got := len(manager.Get().WOLDevices); got != config.MaxWOLDevices {
		t.Fatalf("新增后 %d 台，应为 %d 台", got, config.MaxWOLDevices)
	}
	// 再来一条就该被拦：边界只允许通过一次。
	if w := performJSONRequest(router, http.MethodPost, "/wol", newWOLDeviceBody); w.Code != http.StatusBadRequest {
		t.Fatalf("到达上限后再新增返回 %d，应为 400", w.Code)
	}
}

// TestWOLEditAndDeleteWorkWhenOverCap 存量配置**超出**上限时（旧版本升级、手工编辑而来），
// 编辑与删除必须照常可用。
//
// 这是上限只放在 POST 的原因：若把它做成校验（validate）挡在保存路径上，
// 用户为了减少设备数而去删/改，反倒先被上限堵住，无路可走。
func TestWOLEditAndDeleteWorkWhenOverCap(t *testing.T) {
	over := config.MaxWOLDevices + 5
	manager, router := newWOLCRUDTest(t)
	seedWOLDevices(t, manager, over)

	// 编辑：改名要能存下去。
	renamed := `{"name":"改过名字","enabled":true,"mac":"AA:BB:CC:DD:EE:01","broadcast":"192.168.1.255","port":9}`
	if w := performJSONRequest(router, http.MethodPut, "/wol/seed-3", renamed); w.Code != http.StatusOK {
		t.Fatalf("超量配置下编辑返回 %d，应为 200：用户改不动自己的配置。%s", w.Code, w.Body.String())
	}
	devices := manager.Get().WOLDevices
	if len(devices) != over {
		t.Fatalf("编辑后设备数变成 %d，应仍为 %d", len(devices), over)
	}
	if devices[3].Name != "改过名字" {
		t.Fatalf("编辑没有生效：第 4 台仍叫 %q", devices[3].Name)
	}

	// 删除：这是用户降到上限以下的唯一出路，必须通。
	if w := performJSONRequest(router, http.MethodDelete, "/wol/seed-4", ""); w.Code != http.StatusOK {
		t.Fatalf("超量配置下删除返回 %d，应为 200：用户被上限锁死，连删都删不掉。%s", w.Code, w.Body.String())
	}
	if got := len(manager.Get().WOLDevices); got != over-1 {
		t.Fatalf("删除后 %d 台，应为 %d 台", got, over-1)
	}
}

// TestMaxCountUnsetMeansUnlimited 没设 maxCount 的资源不受影响。
// maxCount 是加在通用 CRUD 上的，一旦把「0」也当成上限，所有模块都只能建 0 条。
func TestMaxCountUnsetMeansUnlimited(t *testing.T) {
	_, router := newWebServiceCRUDTest(t)
	for i := 0; i < 3; i++ {
		// 端口逐条错开：Web 服务本身不允许同（地址族, 端口）重复，这与数量上限无关。
		body := fmt.Sprintf(`{"name":"site","enabled":true,"port":%d,"ipFamily":"both","children":[{"id":"a","enabled":true,"tls":true,"tlsMinVersion":"1.2"}]}`, 8443+i)
		if w := performJSONRequest(router, http.MethodPost, "/webservices", body); w.Code != http.StatusOK {
			t.Fatalf("未设上限的资源第 %d 次新增返回 %d，应为 200：%s", i+1, w.Code, w.Body.String())
		}
	}
}
