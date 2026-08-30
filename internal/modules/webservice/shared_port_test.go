package webservice

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"mantou/internal/config"
	"mantou/internal/logx"
)

// 本文件盯的是「80 / 443 与消息路由共用一条监听」这条路：
// 这两个端口是浏览器与第三方系统的默认端口，面板 / Web 服务 / 消息路由都想要，
// 而一个端口只能被一个进程绑定，所以由本模块持有监听、消息路由挂一条域名路由。
//
// 出错的表现全是静默的：域名键没折成小写 → 第三方按小写发来就落到站点上（或 404）；
// 绑定前没让消息路由松手 → 那一轮结束后这个端口上没有任何监听。都不会有人来报错。

// fakePeer 冒充消息路由模块，记下 ReleasePort 被问过哪个端口。
type fakePeer struct {
	released []int
	holding  int // 只有这个端口会答"我松手了"，与真模块一致
}

func (p *fakePeer) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("webhook-here"))
	})
}

func (p *fakePeer) ReleasePort(port int) bool {
	p.released = append(p.released, port)
	return port == p.holding
}

// serveHost 用给定 Host 走一遍监听的分流逻辑，返回响应。
func serveHost(ls *listenServer, host string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/anything", nil)
	req.Host = host
	w := httptest.NewRecorder()
	ls.handler().ServeHTTP(w, req)
	return w
}

// 域名路由必须大小写不敏感、且认带端口的 Host：
// 前者因为域名本就不区分大小写（RFC 4343）而 Host 头的大小写由客户端决定，
// 后者因为 https://hook.example.com:8443/... 发来的 Host 里带着端口。
func TestSharedListenerRoutesWebhookByDomain(t *testing.T) {
	m := New(logx.New(logx.Options{}))
	peer := &fakePeer{holding: 8443}
	m.SetWebhookPeer(peer)

	g := &wsGroup{family: "ipv4", port: 8443,
		bindings: []childBinding{{service: "官网", child: config.WebChild{
			ID: "ch1", Enabled: true, Type: "redirect", Domains: []string{"www.example.com"},
			Redirect: config.WebRedirect{Target: "https://example.com", Code: 301},
		}}},
		extRoutes: []extRoute{{owner: ownerWebhook, domain: "Hook.Example.COM"}},
	}
	ls := newListenServer(g, nil, m, m.log)

	for _, host := range []string{"hook.example.com", "Hook.Example.COM", "hook.example.com:8443"} {
		if got := serveHost(ls, host).Body.String(); got != "webhook-here" {
			t.Fatalf("Host %q 应转给消息路由，实际 %q", host, got)
		}
	}
	// 同一条监听上的站点不受影响。
	if code := serveHost(ls, "www.example.com").Code; code != 301 {
		t.Fatalf("站点域名应仍走子项（301），实际 %d", code)
	}
	// 谁都不认的域名仍是「未匹配到站点」，不该悄悄落到消息路由上——
	// 那会让任何一个指过来的域名都能往消息路由投递。
	if body := serveHost(ls, "other.example.com").Body.String(); body == "webhook-here" {
		t.Fatal("未配置的域名不该落到消息路由")
	}

	// 没注入 peer 时这条路由取不到处理器，必须干脆不挂，而不是挂一个 nil 进去
	//（那样第一个请求就是 panic，且只在共用端口这条路上才出现）。
	bare := New(logx.New(logx.Options{}))
	if h := newListenServer(g, nil, bare, bare.log).routes["hook.example.com"]; h != nil {
		t.Fatal("没有消息路由模块时不该留下这条路由")
	}
}

// 重载顺序：本模块的 Reload 排在消息路由之前，用户刚把两者改成共用时，
// 消息路由手里还攥着那个端口。绑定前必须先叫它松手，否则这一轮绑不上，
// 而它随后自己也松了手——端口上一个监听都没有，直到下次保存才恢复。
//
// 端口取自内核（:0），并在整个用例期间被本进程占着一份：既不去猜哪个端口空着，
// 也不会撞上机器上真在跑的服务。绑定成功与否不影响断言——Reload 里"先问 peer 再 start"
// 是同一条顺序代码，两种结果下监听都会被登记（失败的那份供 Status 反映不健康）。
func TestReloadAsksWebhookToReleaseSharedPort(t *testing.T) {
	held, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = held.Close() }()
	port := held.Addr().(*net.TCPAddr).Port

	m := New(logx.New(logx.Options{}))
	t.Cleanup(func() { _ = m.Close() })
	peer := &fakePeer{holding: port}
	m.SetWebhookPeer(peer)

	cfg := &config.Config{
		Panel: config.Panel{Port: 25666},
		Webhook: config.WebhookServer{Enabled: true, Port: port, Domain: "hook.example.com",
			HTTPS: config.WebhookHTTPS{Enabled: false}},
		WebServices: []config.WebService{{ID: "ws1", Name: "官网", Enabled: true, Port: port,
			IPFamily: "v4", Children: []config.WebChild{{
				ID: "ch1", Enabled: true, Type: "redirect", Domains: []string{"www.example.com"},
				Redirect: config.WebRedirect{Target: "https://example.com"},
			}}}},
	}
	if err := m.Reload(cfg); err != nil {
		t.Fatalf("Reload 不该整体失败（单个监听绑不上只记不健康）：%v", err)
	}
	if len(peer.released) != 1 || peer.released[0] != port {
		t.Fatalf("应在绑定前叫消息路由让出端口 %d，实际问过 %v", port, peer.released)
	}
	// 消息路由的域名必须真的挂进了这条监听的路由表：merge 那一步只看
	// config.WebhookSharesWebServicePort，漏了它就是"让了端口却没人接收"。
	ls := m.servers[fmt.Sprintf("v4|%d", port)]
	if ls == nil {
		t.Fatalf("这条监听应被登记，实际 %v", m.servers)
	}
	if ls.routes["hook.example.com"] == nil {
		t.Fatalf("消息路由的域名未挂进路由表：%v", ls.routes)
	}

	// 域名被手改配置删掉后就不再共用：此时端口归消息路由自己绑，
	// 本模块既不该问它要端口，也不该留下那条无处可去的路由。
	m2 := New(logx.New(logx.Options{}))
	t.Cleanup(func() { _ = m2.Close() })
	peer2 := &fakePeer{holding: port}
	m2.SetWebhookPeer(peer2)
	cfg.Webhook.Domain = ""
	if err := m2.Reload(cfg); err != nil {
		t.Fatalf("Reload 不该整体失败：%v", err)
	}
	if len(peer2.released) != 0 {
		t.Fatalf("没有域名时不该向消息路由索要端口，实际 %v", peer2.released)
	}
	if ls2 := m2.servers[fmt.Sprintf("v4|%d", port)]; ls2 == nil || len(ls2.routes) != 1 {
		t.Fatalf("路由表应只剩站点自己那一条：%+v", ls2)
	}
}
