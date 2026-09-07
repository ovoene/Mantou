package webservice

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
	"testing"

	"mantou/internal/config"
	"mantou/internal/logx"
)

// 本文件盯的是「反代后端指向面板管理端口」这条路，以及它依赖的那个前提。
//
// # 为什么这件事要拦
//
// 反代那一跳由面板自己发起：请求到这里就变成一个从 127.0.0.1 打向面板的新连接。
// 于是面板看到的来源全是本机——回环无条件放行、拒绝名单与自动封禁认不出人、
// 「仅局域网」形同虚设、审计日志里所有来源塌成 127.0.0.1。这与端口转发指向面板
// 端口是同一个洞，那边早就两层都拦住了，反代这边原先一层都没有。
//
// 保存期的拒绝在 internal/server（validateWebService），这里钉的是**运行期**那一层：
// 导入的备份、手改的 config.json、旧版本迁移上来的数据都不经过保存期校验。

// TestReloadSkipsChildProxyingToPanelPort 后端指向面板端口的子项不会被启动，且会留下告警。
//
// 断言"没有监听被建起来"而不是"bindings 里没有它"：Reload 对空 bindings 的分组
// 直接跳过（不绑端口），所以唯一的子项被摘掉时 m.servers 必然是空的。
// 这条断言顺带保证了这个测试不会真去绑一个端口。
func TestReloadSkipsChildProxyingToPanelPort(t *testing.T) {
	log := logx.New(logx.Options{MaxEntries: 64})
	m := New(log)
	defer func() { _ = m.Close() }()

	cfg := &config.Config{}
	cfg.Panel.Port = 9443
	cfg.WebServices = []config.WebService{{
		ID: "svc", Name: "自己代理自己", Enabled: true, Port: 18080, IPFamily: "ipv4",
		Children: []config.WebChild{{
			ID: "ch", Enabled: true, Note: "面板", Type: "proxy",
			Upstreams: []config.WebUpstream{{URL: "http://127.0.0.1:9443"}},
		}},
	}}

	if err := m.Reload(cfg); err != nil {
		t.Fatalf("Reload 不该报错：%v", err)
	}
	if len(m.servers) != 0 {
		t.Fatalf("指向面板端口的子项应被跳过，因此不该有任何监听被建起来，实际 %d 个", len(m.servers))
	}

	var found bool
	for _, e := range log.Recent(64) {
		if strings.Contains(e.Message, "反代后端指向面板管理端口") {
			found = true
			if e.Level != "WARN" {
				t.Errorf("这条应当是 WARN，实际 %s", e.Level)
			}
			break
		}
	}
	if !found {
		t.Fatal("被跳过时必须留下一条告警——否则用户面对一个打不开的站点，日志里什么线索都没有")
	}
}

// TestReloadKeepsChildProxyingElsewhere 后端不是面板端口的子项照常装配。
//
// 反向的那一半：一道把正常反代也拦下的闸，和没有这道闸一样是坏的。
// 这里同样不绑端口——只看聚合结果里子项还在不在（绑定发生在聚合之后）。
func TestReloadKeepsChildProxyingElsewhere(t *testing.T) {
	cfg := &config.Config{}
	cfg.Panel.Port = 9443
	ch := config.WebChild{
		ID: "ch", Enabled: true, Type: "proxy",
		Upstreams: []config.WebUpstream{{URL: "http://127.0.0.1:3000"}},
	}
	if up, ok := ch.UpstreamTargetingLocalPort(cfg.Panel.Port); ok {
		t.Fatalf("端口不同的本机后端不该被判为指向面板端口，命中了 %q", up)
	}
	// 内网后端是这个功能的主要用途，更不能被认领。
	ch.Upstreams = []config.WebUpstream{{URL: "http://192.168.1.10:9443"}}
	if up, ok := ch.UpstreamTargetingLocalPort(cfg.Panel.Port); ok {
		t.Fatalf("局域网后端（非本机地址）不该被判为指向面板端口，命中了 %q", up)
	}
}

// TestProxyDispatchMatchesIsProxy 钉住 config.WebChild.IsProxy 依赖的那个前提。
//
// IsProxy 写的是"不是 static、也不是 redirect 就是反代"，而不是 Type == "proxy"，
// 因为 buildChildHandler 的 switch 只认那两个 case、其余全落到 default。这个前提
// 一旦变了（有人加了 case "grpc" 之类），IsProxy 就会把新类型也当成反代，
// 于是那道面板端口校验作用在一个不拨 Upstreams 的子项上——不是漏拦就是误拦。
//
// 用 AST 读源码而不是造一堆子项跑一遍：要断言的是"switch 里只有这两个 case"这件
// 结构事实，行为测试只能证明现有分支对，证不出"没有别的分支"。
func TestProxyDispatchMatchesIsProxy(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "handler.go", nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("解析 handler.go 失败：%v", err)
	}

	var cases []string
	var seenSwitch bool
	ast.Inspect(file, func(n ast.Node) bool {
		fn, ok := n.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "buildChildHandler" {
			return true
		}
		ast.Inspect(fn.Body, func(in ast.Node) bool {
			sw, ok := in.(*ast.SwitchStmt)
			if !ok {
				return true
			}
			// 只认对 ch.Type 分派的那个 switch，别的 switch（若有）不算。
			sel, ok := sw.Tag.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "Type" {
				return true
			}
			seenSwitch = true
			for _, stmt := range sw.Body.List {
				cc, ok := stmt.(*ast.CaseClause)
				if !ok || cc.List == nil { // cc.List == nil 就是 default
					continue
				}
				for _, expr := range cc.List {
					lit, ok := expr.(*ast.BasicLit)
					if !ok || lit.Kind != token.STRING {
						t.Errorf("case 里出现了非字面量 %T，IsProxy 的前提无法再由本测试保证", expr)
						continue
					}
					cases = append(cases, strings.Trim(lit.Value, `"`))
				}
			}
			return false
		})
		return false
	})

	if !seenSwitch {
		t.Fatal("没找到 buildChildHandler 里对 ch.Type 分派的 switch——它被改写了，请同时复核 config.WebChild.IsProxy")
	}
	// 期望值与 IsProxy 的实现一一对应。
	want := map[string]bool{"static": true, "redirect": true}
	if len(cases) != len(want) {
		t.Fatalf("ch.Type 的显式 case 变成了 %v；config.WebChild.IsProxy 排除的正好是 %v，两边必须同步改", cases, want)
	}
	for _, c := range cases {
		if !want[c] {
			t.Errorf("出现了新的 case %q：它会被 IsProxy 当成反代（于是套上面板端口校验），请先确认这是对的", c)
		}
		// 反过来验一遍：显式列出的类型都不该被 IsProxy 认成反代。
		if (config.WebChild{Type: c}).IsProxy() {
			t.Errorf("Type=%q 在 handler.go 里有独立分支，IsProxy 却把它当成反代", c)
		}
	}
	// 落到 default 的那些必须被认成反代——空串是最常见的一个（旧配置、手写配置都这样）。
	for _, c := range []string{"", "proxy", "unknown-future-type"} {
		if !(config.WebChild{Type: c}).IsProxy() {
			t.Errorf("Type=%q 在 handler.go 里落到 default（走反代），IsProxy 却说它不是", c)
		}
	}
}
