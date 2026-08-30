package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"mantou/internal/auth"
	"mantou/internal/config"
	"mantou/internal/logx"
	"mantou/internal/version"
)

// 本文件盯两件事（确认项 A1）：
//
//  1. **匿名访问者拿不到版本号。** 免鉴权的 /init/status 只回 initialized 一个字段，
//     /meta/version 整个挪到了登录之后。精确版本号是一条能被匿名取走、且取的过程
//     不留任何痕迹的指纹，拿到它就能对着已知漏洞列表挑一个来试。
//
//  2. **未登录时撞上受保护地址，那一页上什么都不多说。** 只有状态码和一句
//     「需要先登录」——不说是哪种失败、不指路、不回显路径、不带版本号。
//
// 这两件事都属于"少给一点信息"，天然没有正向功能可验证，只能靠"某些内容不出现"来钉。
// 所以每条断言都反着写：出现了就是回退。

// versionAuthEngine 造一个真实路由的面板：已初始化、有管理员账号，可登录。
//
// 必须走 New() 拿真实 engine 而不是自己拼一个 gin.Engine：本文件要验证的正是
// registerRoutes 里"这个路由挂在哪个组下"，手拼路由会把被测对象一起绕过去。
func versionAuthEngine(t *testing.T, basePath string) (*Server, *gin.Engine) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	manager := config.NewManager(filepath.Join(t.TempDir(), "config.json"))
	if err := manager.Load(); err != nil {
		t.Fatal(err)
	}
	hash, err := auth.HashPassword(testLoginPass)
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.Update(func(cfg *config.Config) {
		cfg.Panel.BasePath = basePath
		cfg.Auth.Initialized = true
		cfg.Auth.Username = testLoginUser
		cfg.Auth.PasswordHash = hash
	}); err != nil {
		t.Fatal(err)
	}
	s := New(Deps{Config: manager, Log: logx.New(logx.Options{})})
	engine, ok := s.http.Handler.(*gin.Engine)
	if !ok {
		t.Fatalf("面板 Handler 不是 *gin.Engine，而是 %T", s.http.Handler)
	}
	t.Cleanup(s.sessions.close)
	return s, engine
}

// loginCookie 走真实登录接口拿会话 Cookie。
func loginCookie(t *testing.T, engine *gin.Engine, basePath string) *http.Cookie {
	t.Helper()
	body := `{"username":"` + testLoginUser + `","password":"` + testLoginPass + `"}`
	req := httptest.NewRequest(http.MethodPost, basePath+"/api/auth/login", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	engine.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("测试前提不成立：登录应当成功，得到 %d：%s", rec.Code, rec.Body.String())
	}
	for _, c := range rec.Result().Cookies() {
		if c.Name == sessionCookie && c.Value != "" {
			return c
		}
	}
	t.Fatal("登录成功却没拿到会话 Cookie")
	return nil
}

// /init/status 免鉴权，所以它的返回值等于"任何人都能看到的东西"。
// 这里逐个键点名，而不是只断言 version 不在：加字段的人不会想到来读这个测试，
// 但会被"多了一个键"直接拦住，那时才好判断这个新字段该不该给匿名访问者看。
func TestInitStatusExposesOnlyInitialized(t *testing.T) {
	for _, initialized := range []bool{false, true} {
		s, engine := versionAuthEngine(t, "")
		// 未初始化那一侧同样是匿名可见的，不能因为"还没配好"就多说点什么。
		// handleInitStatus 每次请求都重新 Snapshot，所以建好之后再改也生效。
		if err := s.deps.Config.Update(func(cfg *config.Config) {
			cfg.Auth.Initialized = initialized
		}); err != nil {
			t.Fatal(err)
		}
		req := httptest.NewRequest(http.MethodGet, "/api/init/status", nil)
		rec := httptest.NewRecorder()
		engine.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("初始化状态应当 200，得到 %d：%s", rec.Code, rec.Body.String())
		}
		var wrap struct {
			Data map[string]any `json:"data"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &wrap); err != nil {
			t.Fatalf("响应不是预期的 JSON：%v（%s）", err, rec.Body.String())
		}
		if len(wrap.Data) != 1 {
			t.Fatalf("这个接口免鉴权，只该回 initialized 一个字段，实际 %d 个：%s",
				len(wrap.Data), rec.Body.String())
		}
		got, ok := wrap.Data["initialized"]
		if !ok {
			t.Fatalf("initialized 必须留在免鉴权这一侧（前端靠它决定画向导还是登录页），实际 %s",
				rec.Body.String())
		}
		if got != initialized {
			t.Fatalf("initialized 应为 %v，实际 %v", initialized, got)
		}
		// 版本号不能以任何形式出现：既不能有 version 键，正文里也不能出现版本号本身
		//（防止有人把它塞进别的键名里）。
		if _, ok := wrap.Data["version"]; ok {
			t.Errorf("免鉴权接口不得回版本号：%s", rec.Body.String())
		}
		if v := version.Load().Version; v != "" && strings.Contains(rec.Body.String(), v) {
			t.Errorf("响应正文里出现了版本号 %q：%s", v, rec.Body.String())
		}
	}
}

// 未登录取 /meta/version 必须被拦下，且拦下的那一刻也不能顺手把版本号带出去。
func TestVersionRequiresLogin(t *testing.T) {
	for _, basePath := range []string{"", "/mymantou"} {
		_, engine := versionAuthEngine(t, basePath)
		req := httptest.NewRequest(http.MethodGet, basePath+"/api/meta/version", nil)
		rec := httptest.NewRecorder()
		engine.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("basePath=%q：未登录取版本号应当 401，得到 %d：%s",
				basePath, rec.Code, rec.Body.String())
		}
		if v := version.Load().Version; v != "" && strings.Contains(rec.Body.String(), v) {
			t.Errorf("basePath=%q：401 的响应里仍然出现了版本号 %q：%s", basePath, v, rec.Body.String())
		}
	}
}

// 反方向：挪到鉴权之后不等于挪没了。「关于」页登录后照样要看得到版本号。
func TestVersionAvailableAfterLogin(t *testing.T) {
	_, engine := versionAuthEngine(t, "")
	cookie := loginCookie(t, engine, "")

	req := httptest.NewRequest(http.MethodGet, "/api/meta/version", nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	engine.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("登录后取版本号应当 200，得到 %d：%s", rec.Code, rec.Body.String())
	}
	var wrap struct {
		Data map[string]any `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &wrap); err != nil {
		t.Fatalf("响应不是预期的 JSON：%v（%s）", err, rec.Body.String())
	}
	if got, want := wrap.Data["version"], version.Load().Version; got != want {
		t.Fatalf("登录后应拿到版本号 %q，实际 %v", want, got)
	}
}

// 浏览器直接敲一个受保护地址：给一页卡片，且这一页上除了「需要先登录」什么都没有。
func TestUnauthorizedBrowserPageSaysOnlyLoginRequired(t *testing.T) {
	const basePath = "/mymantou"
	_, engine := versionAuthEngine(t, basePath)

	req := httptest.NewRequest(http.MethodGet, basePath+"/api/meta/version", nil)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	rec := httptest.NewRecorder()
	engine.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("应当 401，得到 %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "text/html") {
		t.Fatalf("浏览器导航应拿到 HTML 卡片页，实际 Content-Type=%q", ct)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "需要先登录") {
		t.Fatalf("卡片页上应当写着「需要先登录」：%s", body)
	}
	// 不该出现的东西。每一条都对应一类"替对方把下一步做完了"的提示。
	for _, leak := range []struct{ what, why string }{
		{basePath, "面板访问路径前缀：这正是本轮要求删掉的那类提示"},
		{"/api/meta/version", "请求路径：写出来只会让这一页看着像「确实有这个东西」"},
		{version.Load().Version, "版本号：整项改动就是为了不给匿名访问者这个"},
		{"未登录", "具体原因：对使用者是同一件事，对探测者是有用的差异"},
		{"会话", "具体原因（同上）"},
		{"登录页", "指路"},
	} {
		if leak.what == "" {
			continue
		}
		if strings.Contains(body, leak.what) {
			t.Errorf("卡片页上不该出现 %q（%s）：\n%s", leak.what, leak.why, body)
		}
	}
}

// 面板前端自己的请求仍要拿到 JSON：它靠状态码跳登录页、靠 error 字段显示原因，
// 塞一页 HTML 过去会让提示变成一堆标签。
func TestUnauthorizedXHRStillGetsJSON(t *testing.T) {
	_, engine := versionAuthEngine(t, "")
	for _, tc := range []struct {
		name   string
		accept string
		xhr    bool
	}{
		{name: "fetch 默认", accept: "*/*"},
		{name: "明确要 JSON", accept: "application/json"},
		{name: "不带 Accept", accept: ""},
		{name: "XMLHttpRequest 即使要 HTML 也给 JSON", accept: "text/html", xhr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/api/meta/version", nil)
			if tc.accept != "" {
				req.Header.Set("Accept", tc.accept)
			}
			if tc.xhr {
				req.Header.Set("X-Requested-With", "XMLHttpRequest")
			}
			rec := httptest.NewRecorder()
			engine.ServeHTTP(rec, req)

			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("应当 401，得到 %d", rec.Code)
			}
			if strings.Contains(rec.Body.String(), "<!doctype html") {
				t.Fatalf("接口调用方不该拿到 HTML：%s", rec.Body.String())
			}
			var wrap struct {
				Error string `json:"error"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &wrap); err != nil {
				t.Fatalf("接口调用方应拿到 JSON：%v（%s）", err, rec.Body.String())
			}
			if wrap.Error == "" {
				t.Fatalf("error 字段不能为空，前端的提示是从这里读的：%s", rec.Body.String())
			}
		})
	}
}

var errPageTimeRe = regexp.MustCompile(`<div class="time">[^<]*</div>`)

// 三种失败方式（没带令牌 / 令牌解不开 / 服务端会话已不在）给出的页面必须一模一样。
//
// 这是本项里唯一有实际攻击面的一条：如果三者页面有差别，探测者就能区分
// "这个令牌曾经有效" 和 "压根没带令牌"，等于拿到一个免费的验证器。
//
// 分两步走，第一步不是多余的。第一版只比了三张卡片是否相同，结果它**测不出**
// "只有一种失败走卡片、另外两种回 JSON" 这个回退——因为那一版里当作"解不开的令牌"
// 用的是一串中文，而 Cookie 值不允许非 ASCII 字节，net/http 写入时会把它整个滤掉，
// 于是那一格根本没走到解析失败，退化成了跟"没带令牌"一模一样的请求。
// 所以先用 JSON 形态确认三格确实落在三个不同分支上，再去比 HTML 形态是否一致。
func TestUnauthorizedPageHidesWhichFailureItWas(t *testing.T) {
	s := newAuthTestServer(t)
	cfg := s.deps.Config.Snapshot()
	live, err := auth.IssueToken(cfg.Auth.JWTSecret, cfg.Auth.Username, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	// 刻意不 s.sessions.add：JWT 验得过，但服务端会话不存在（退出登录后的形态）。

	engine := gin.New()
	engine.Use(s.authRequired())
	engine.GET("/protected", func(c *gin.Context) { c.Status(http.StatusNoContent) })

	cases := []struct{ name, cookie string }{
		{name: "没带令牌", cookie: ""},
		// 必须是合法的 Cookie 值（纯 ASCII），否则会被 net/http 滤掉，
		// 这一格就退化成上面那一格了。
		{name: "令牌解不开", cookie: "not-a-real-token"},
		{name: "服务端会话已不在", cookie: live},
	}

	ask := func(name, cookie, accept string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/protected", nil)
		req.Header.Set("Accept", accept)
		if cookie != "" {
			req.AddCookie(&http.Cookie{Name: sessionCookie, Value: cookie})
		}
		rec := httptest.NewRecorder()
		engine.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("%s（Accept=%s）：应当 401，得到 %d：%s", name, accept, rec.Code, rec.Body.String())
		}
		return rec
	}

	// 第一步：确认三格真的走了三个不同分支——内部原因两两不同。
	reasons := make(map[string]string, len(cases))
	for _, tc := range cases {
		rec := ask(tc.name, tc.cookie, "application/json")
		var wrap struct {
			Error string `json:"error"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &wrap); err != nil {
			t.Fatalf("%s：接口形态应是 JSON：%v（%s）", tc.name, err, rec.Body.String())
		}
		for prev, msg := range reasons {
			if msg == wrap.Error {
				t.Fatalf("测试前提不成立：「%s」与「%s」落在同一个分支上（都回 %q），"+
					"这一格没在验它该验的东西", prev, tc.name, msg)
			}
		}
		reasons[tc.name] = wrap.Error
	}

	// 第二步：三种失败对外必须长得一模一样。卡片上有一行当前时间，比对前先抹掉。
	var first, firstName string
	for _, tc := range cases {
		page := errPageTimeRe.ReplaceAllString(ask(tc.name, tc.cookie, "text/html").Body.String(), "")
		if !strings.Contains(page, "需要先登录") {
			t.Fatalf("%s：应当拿到「需要先登录」卡片，实际：%s", tc.name, page)
		}
		if firstName == "" {
			first, firstName = page, tc.name
			continue
		}
		if page != first {
			t.Fatalf("「%s」与「%s」对外不一致，探测者可据此区分失败原因\n%s\n---\n%s",
				firstName, tc.name, first, page)
		}
	}
}
