package server

import (
	"encoding/json"
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

// 本文件钉的是 A11 的那一条性质：**界面上写的那个数，就是新增时拦人的那个数**。
//
// 上限本身好办（POST 里一个 if）。会坏的是"说明里写 100、保存时报 50"这种不一致：
// 它只在用户快加满时才暴露，而那时候用户看到的是"界面骗我"，不是"上限该调"。
// 所以这里的用例一律**先从 /api/meta/limits 把数读出来，再拿这个数去撞上限**——
// 两处若不同源，用例就挂；照抄常量的写法验不出这一点。

// newAllResourcesTest 用**线上那份** registerResourceRoutes() 挂全部资源路由，
// 外加 /api/meta/limits。用线上那份是关键：单独 new 一个 resource[T]{maxCount: …} 的测试
// 只能证明 registerCRUD 会拦，证明不了「ddns/forwards/crontasks/certs 这四个真的接上去了」。
func newAllResourcesTest(t *testing.T) (*config.Manager, *gin.Engine) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	manager := config.NewManager(filepath.Join(t.TempDir(), "config.json"))
	if err := manager.Load(); err != nil {
		t.Fatal(err)
	}
	s := &Server{deps: Deps{Config: manager, Stats: runstats.New()}}
	router := gin.New()
	g := router.Group("")
	s.registerResourceRoutes(g)
	g.GET("/meta/limits", s.handleResourceLimits)
	return manager, router
}

// readCaps 从接口把上限表读回来——界面拿到的就是这一份。
func readCaps(t *testing.T, router *gin.Engine) map[string]int {
	t.Helper()
	w := performJSONRequest(router, http.MethodGet, "/meta/limits", "")
	if w.Code != http.StatusOK {
		t.Fatalf("GET /meta/limits 返回 %d：%s", w.Code, w.Body.String())
	}
	var resp struct {
		Data map[string]int `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("上限表解析失败：%v；原文 %s", err, w.Body.String())
	}
	return resp.Data
}

// capCase 一个受限资源：名字、往配置里塞 n 条的办法、以及一条能通过校验的新增请求体。
type capCase struct {
	name string
	want int // 期望的上限值（config 里的那个常量）
	seed func(cfg *config.Config, n int)
	body string
}

func capCases() []capCase {
	return []capCase{
		{
			name: "ddns",
			want: config.MaxDDNSRules,
			seed: func(cfg *config.Config, n int) {
				cfg.DDNS = make([]config.DDNSRule, 0, n)
				for i := 0; i < n; i++ {
					cfg.DDNS = append(cfg.DDNS, config.DDNSRule{
						ID: "seed-" + strconv.Itoa(i), Name: "存量规则 " + strconv.Itoa(i),
						Stack: "ipv4", IntervalSec: 600,
					})
				}
			},
			body: `{"name":"新规则","enabled":false,"stack":"ipv4","intervalSec":600,"targets":[]}`,
		},
		{
			name: "forwards",
			want: config.MaxForwardRules,
			seed: func(cfg *config.Config, n int) {
				cfg.Forwards = make([]config.ForwardRule, 0, n)
				for i := 0; i < n; i++ {
					cfg.Forwards = append(cfg.Forwards, config.ForwardRule{
						ID: "seed-" + strconv.Itoa(i), Name: "存量转发 " + strconv.Itoa(i),
						Protocol: "tcp", ListenPort: 20000 + i, TargetHost: "127.0.0.1", TargetPort: 80,
						Family: "dual",
					})
				}
			},
			body: `{"name":"新转发","enabled":false,"protocol":"tcp","listenPort":19999,"targetHost":"127.0.0.1","targetPort":80,"family":"dual"}`,
		},
		{
			name: "crontasks",
			want: config.MaxCronTasks,
			seed: func(cfg *config.Config, n int) {
				cfg.CronTasks = make([]config.CronTask, 0, n)
				for i := 0; i < n; i++ {
					cfg.CronTasks = append(cfg.CronTasks, config.CronTask{
						ID: "seed-" + strconv.Itoa(i), Name: "存量任务 " + strconv.Itoa(i),
						Cron: "0 3 * * *",
					})
				}
			},
			body: `{"name":"新任务","enabled":false,"cron":"0 4 * * *","action":{"type":"ddns.refresh","params":{}}}`,
		},
		{
			name: "certs",
			want: config.MaxCerts,
			seed: func(cfg *config.Config, n int) {
				cfg.Certs = make([]config.Certificate, 0, n)
				for i := 0; i < n; i++ {
					cfg.Certs = append(cfg.Certs, config.Certificate{
						ID: "seed-" + strconv.Itoa(i), Name: "存量证书 " + strconv.Itoa(i),
						Method: "path", CertPath: "/tmp/a.pem", KeyPath: "/tmp/a.key",
					})
				}
			},
			body: `{"name":"新证书","enabled":false,"method":"path","certPath":"/tmp/b.pem","keyPath":"/tmp/b.key"}`,
		},
		{
			// Web 服务的父项数。这一道拦的是"监听数"，而真正花钱的是子项数——
			// 那一道另有用例（见本文件末尾）。两道都要有，只拦一道等于没拦。
			name: "webservices",
			want: config.MaxWebServices,
			seed: func(cfg *config.Config, n int) {
				cfg.WebServices = make([]config.WebService, 0, n)
				for i := 0; i < n; i++ {
					cfg.WebServices = append(cfg.WebServices, config.WebService{
						ID: "seed-" + strconv.Itoa(i), Name: "存量服务 " + strconv.Itoa(i),
						Port: 30000 + i, IPFamily: "both",
					})
				}
			},
			body: `{"name":"新服务","enabled":false,"port":29999,"ipFamily":"both","children":[]}`,
		},
		{
			// 网络唤醒的上限早就有了（A11 之前）。放进来是因为 A11 改的是"把上限说出来"这件事：
			// 唯一一个一直有上限的模块，反倒成了唯一不写出来的那个，才是真的怪。
			name: "wol",
			want: config.MaxWOLDevices,
			seed: func(cfg *config.Config, n int) {
				cfg.WOLDevices = make([]config.WOLDevice, 0, n)
				for i := 0; i < n; i++ {
					cfg.WOLDevices = append(cfg.WOLDevices, config.WOLDevice{
						ID: "seed-" + strconv.Itoa(i), Enabled: true, Name: "存量设备 " + strconv.Itoa(i),
						MAC: fmt.Sprintf("AA:BB:CC:00:%02X:%02X", i/256, i%256), Port: 9,
					})
				}
			},
			body: `{"name":"新设备","enabled":true,"mac":"AA:BB:CC:DD:EE:FF","broadcast":"192.168.1.255","port":9}`,
		},
	}
}

// 四个新上限（外加早就有的网络唤醒）都必须出现在下发给界面的那张表里，且值与常量一致。
//
// 缺一项的后果不是报错，是**那一页的说明里那句话不见了**——页面照常能用，
// 于是没人会发现"这个模块的上限从来没写出来过"。
func TestResourceLimitsExposedToUI(t *testing.T) {
	_, router := newAllResourcesTest(t)
	caps := readCaps(t, router)

	for _, tc := range capCases() {
		got, ok := caps[tc.name]
		if !ok {
			t.Errorf("上限表里没有 %q：这一页标题下方那句「最多可添加 N 条」不会显示，"+
				"而页面照常能用，等于没人会发现漏了", tc.name)
			continue
		}
		if got != tc.want {
			t.Errorf("%q 下发的上限是 %d，config 里是 %d：界面写一个数、保存时报另一个数",
				tc.name, got, tc.want)
		}
	}

	// 子项数上限不是"列表条数"，但它同样要写在界面上（「添加子项」按钮旁边），
	// 所以走的是同一张表——漏了这一条，那个按钮就永远不会变灰。
	if n := caps["webservices/children"]; n != config.MaxWebChildren {
		t.Errorf("webservices/children 下发的上限是 %d，config 里是 %d："+
			"「添加子项」按钮旁边那句话会写错，或者干脆不显示", n, config.MaxWebChildren)
	}

	// 没设上限的资源不进这张表。进了就会在界面上冒出一句「最多可添加 0 条」，
	// 而那些资源其实是不限条数的。
	for _, name := range []string{"credentials", "acme-accounts"} {
		if n, ok := caps[name]; ok {
			t.Errorf("%q 不该有上限，却下发了 %d：界面会显示一句「最多可添加 %d 条」的假话", name, n, n)
		}
	}
}

// 拿界面上看到的那个数去撞上限：撞不上就说明两处不同源。
//
// 顺带把"到了上限确实拦得住"一起钉上——这四个资源此前完全不限条数，
// 而每一条的代价都是实打实的常驻开销（各自的理由见 config.Max* 那几处注释）。
func TestCreateRejectedAtExposedCap(t *testing.T) {
	for _, tc := range capCases() {
		t.Run(tc.name, func(t *testing.T) {
			manager, router := newAllResourcesTest(t)
			limit := readCaps(t, router)[tc.name]
			if limit <= 0 {
				t.Fatalf("接口没给出 %q 的上限，前置条件都不成立", tc.name)
			}

			// 用**接口给的那个数**塞满。若下发的数比实际拦人的数小，这里就塞不满，
			// 下面的新增会通过而不是被拒——用例挂在"界面报的数偏小"上。
			if err := manager.Update(func(cfg *config.Config) { tc.seed(cfg, limit) }); err != nil {
				t.Fatal(err)
			}

			w := performJSONRequest(router, http.MethodPost, "/"+tc.name, tc.body)
			if w.Code != http.StatusBadRequest {
				t.Fatalf("已有 %d 条（界面上写的上限）时新增返回 %d，应为 400："+
					"要么上限没生效，要么真正的上限比界面写的更大。%s", limit, w.Code, w.Body.String())
			}
			// 报错里要出现同一个数，否则用户看到的是两个互相矛盾的上限。
			if body := w.Body.String(); !strings.Contains(body, strconv.Itoa(limit)) {
				t.Errorf("被拒时报出的上限与界面上写的 %d 不一致：%s", limit, body)
			}
		})
	}
}

// 差一条到上限时必须放行：上限是「不超过」而不是「不到」。
// 少了这一条，把 >= 写成 > 或把上限当成"最多 N-1 条"都不会被发现。
func TestCreateAllowedJustBelowExposedCap(t *testing.T) {
	for _, tc := range capCases() {
		t.Run(tc.name, func(t *testing.T) {
			manager, router := newAllResourcesTest(t)
			limit := readCaps(t, router)[tc.name]
			if err := manager.Update(func(cfg *config.Config) { tc.seed(cfg, limit-1) }); err != nil {
				t.Fatal(err)
			}
			if w := performJSONRequest(router, http.MethodPost, "/"+tc.name, tc.body); w.Code != http.StatusOK {
				t.Fatalf("差一条到上限时新增返回 %d，应为 200：上限把合法操作也拦了。%s",
					w.Code, w.Body.String())
			}
		})
	}
}

// ---- Web 服务的子项数上限 ----
//
// 这一道与上面那些不同：它拦的不是"列表最多几条"，而是**一个父项内部**最多挂几个子项。
// 之所以要拦这个数，是因为 Web 服务这一块真正花钱的就是它——每个反代子项各自持有一个
// 连接池（MaxIdleConnsPerHost = 128），空闲连接数按子项数增长，与父项数无关。
// 只拦父项数的话，一个父项挂 500 个子项照样能把内存顶上去。

// webChildrenJSON 拼一个带 n 个子项的父项请求体。
// 子项一律停用：这样就不会撞上"同一父项下启用的子项不得混用 HTTP/HTTPS"之类
// 与本用例无关的校验——这里要验的只有条数那一道。
func webChildrenJSON(name string, n int) string {
	var b strings.Builder
	b.WriteString(`{"name":"` + name + `","enabled":false,"port":29000,"ipFamily":"both","children":[`)
	for i := 0; i < n; i++ {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(`{"id":"c` + strconv.Itoa(i) + `","enabled":false,"type":"proxy"}`)
	}
	b.WriteString(`]}`)
	return b.String()
}

// 界面上写的子项上限，就是保存时拦人的那个数。
// 与上面那些用例同一个办法：先从 /api/meta/limits 把数读出来，再拿它去撞。
func TestWebChildrenCapExposedAndEnforced(t *testing.T) {
	_, router := newAllResourcesTest(t)
	limit := readCaps(t, router)["webservices/children"]
	if limit <= 0 {
		t.Fatalf("接口没给出 webservices/children 的上限，前置条件都不成立")
	}

	// 正好到上限要能存下——上限是「不超过」而不是「不到」。
	w := performJSONRequest(router, http.MethodPost, "/webservices", webChildrenJSON("正好到上限", limit))
	if w.Code != http.StatusOK {
		t.Fatalf("%d 个子项（界面上写的上限）被拒，返回 %d：上限把合法配置也拦了。%s",
			limit, w.Code, w.Body.String())
	}

	// 多一个就该被拒，且报错里出现同一个数。
	w = performJSONRequest(router, http.MethodPost, "/webservices", webChildrenJSON("多一个", limit+1))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("%d 个子项（比界面上写的上限多一个）返回 %d，应为 400："+
			"要么上限没生效，要么真正的上限比界面写的更大。%s", limit+1, w.Code, w.Body.String())
	}
	if body := w.Body.String(); !strings.Contains(body, strconv.Itoa(limit)) {
		t.Errorf("被拒时报出的上限与界面上写的 %d 不一致：%s", limit, body)
	}
}

// 已经超限的配置（手改 config.json 或从旧版本升级而来）必须还能保存。
//
// 这一条钉的是那个死结：子项数校验同时管着"保存父项"与"启停子项"两条路径。若一律拒绝，
// 一份一上来就超限的配置连开关都动不了，而界面上唯一能减子项的地方就是编辑弹窗——
// 保存又被这里拒掉，用户没有任何出路。所以这道闸只拦"变多"。
func TestWebChildrenOverCapStillSavable(t *testing.T) {
	manager, router := newAllResourcesTest(t)
	limit := readCaps(t, router)["webservices/children"]

	// 直接往配置里塞一个超限的父项，绕过 API——手工编辑 config.json 就是这个效果。
	over := limit + 5
	children := make([]config.WebChild, 0, over)
	for i := 0; i < over; i++ {
		children = append(children, config.WebChild{ID: "c" + strconv.Itoa(i), Type: "proxy", TLSMinVersion: "1.2"})
	}
	if err := manager.Update(func(cfg *config.Config) {
		cfg.WebServices = []config.WebService{{
			ID: "legacy", Name: "手改来的服务", Port: 28080, IPFamily: "both", Children: children,
		}}
	}); err != nil {
		t.Fatal(err)
	}

	// 原样保存（子项数不变）：必须放行，否则这个父项在界面上成了只读的死配置。
	body := webChildrenJSON("手改来的服务", over)
	if w := performJSONRequest(router, http.MethodPut, "/webservices/legacy", body); w.Code != http.StatusOK {
		t.Fatalf("已超限的父项原样保存返回 %d，应为 200：界面上唯一能减子项的地方也被拦住了，"+
			"用户没有任何出路。%s", w.Code, w.Body.String())
	}

	// 往上加一个：这才该被拒。
	if w := performJSONRequest(router, http.MethodPut, "/webservices/legacy",
		webChildrenJSON("手改来的服务", over+1)); w.Code != http.StatusBadRequest {
		t.Fatalf("已超限的父项再加一个子项返回 %d，应为 400：只拦「变多」也得真的拦住变多。%s",
			w.Code, w.Body.String())
	}

	// 减到上限以内：当然要放行，且之后就回到普通规则了。
	if w := performJSONRequest(router, http.MethodPut, "/webservices/legacy",
		webChildrenJSON("手改来的服务", limit)); w.Code != http.StatusOK {
		t.Fatalf("已超限的父项减到 %d 个子项返回 %d，应为 200。%s", limit, w.Code, w.Body.String())
	}
}
