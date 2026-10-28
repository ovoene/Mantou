package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"mantou/internal/config"
)

// 本文件钉住白名单 / 黑名单的逐条增删（POST /global-firewall/lists/add、/lists/remove）。
//
// 这两条口子替掉了原先"文本框整张提交"的做法，要守住的是：
//   - 分拣（新增 / 已存在 / 重复 / 无效 / 超额）在预览与真添加里是同一个结论；
//   - 名单有硬上限，超出的必须被报出来，而不是静默丢掉；
//   - 删除只动点到的那几条，附属信息（备注 / 时间）跟着条目一起消失；
//   - 一个什么都没带的删除请求不能被理解成"全删"。

type listEntryResp struct {
	IP      string `json:"ip"`
	Note    string `json:"note"`
	AddedAt int64  `json:"addedAt"`
	Source  string `json:"source"`
}

type listAddResp struct {
	Data struct {
		DryRun bool `json:"dryRun"`
		Plan   struct {
			Added     []string `json:"added"`
			Existing  []string `json:"existing"`
			Duplicate []string `json:"duplicate"`
			Invalid   []string `json:"invalid"`
			Capped    []string `json:"capped"`
		} `json:"plan"`
		Entries []listEntryResp `json:"entries"`
	} `json:"data"`
}

type listRemoveResp struct {
	Data struct {
		Removed int             `json:"removed"`
		Entries []listEntryResp `json:"entries"`
	} `json:"data"`
}

func callListHandler(t *testing.T, h gin.HandlerFunc, path, body string, out any) int {
	t.Helper()
	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	ctx.Request = newSchemeRequest(t, false, http.MethodPost, path, body)
	h(ctx)
	if w.Code == http.StatusOK && out != nil {
		if err := json.Unmarshal(w.Body.Bytes(), out); err != nil {
			t.Fatalf("解析响应失败: %v（原文 %s）", err, w.Body.String())
		}
	}
	return w.Code
}

func postListAdd(t *testing.T, s *Server, body string) (int, listAddResp) {
	t.Helper()
	var out listAddResp
	code := callListHandler(t, s.handleAddGlobalFirewallList, "/global-firewall/lists/add", body, &out)
	return code, out
}

func postListRemove(t *testing.T, s *Server, body string) (int, listRemoveResp) {
	t.Helper()
	var out listRemoveResp
	code := callListHandler(t, s.handleRemoveGlobalFirewallList, "/global-firewall/lists/remove", body, &out)
	return code, out
}

// 一批里五类各来一条：分拣结果要逐类对上，且只有"新增"那一类真的进了名单、带上备注与时间。
func TestListAddClassifies(t *testing.T) {
	s := newDenyTestServer(t)
	if code, _ := postListAdd(t, s, `{"list":"allow","items":[{"ip":"10.0.0.0/8"}]}`); code != http.StatusOK {
		t.Fatalf("预置条目失败：%d", code)
	}
	code, res := postListAdd(t, s, `{"list":"allow","items":[
		{"ip":" 203.0.113.0/24 ","note":"办公网"},
		{"ip":"203.0.113.0/24"},
		{"ip":"10.0.0.0/8"},
		{"ip":"not-an-ip"},
		{"ip":"1.2.3.4-1.2.3.9","note":"机房"}
	]}`)
	if code != http.StatusOK {
		t.Fatalf("应成功，得到 %d", code)
	}
	p := res.Data.Plan
	if fmt.Sprint(p.Added) != "[203.0.113.0/24 1.2.3.4-1.2.3.9]" ||
		fmt.Sprint(p.Duplicate) != "[203.0.113.0/24]" ||
		fmt.Sprint(p.Existing) != "[10.0.0.0/8]" ||
		fmt.Sprint(p.Invalid) != "[not-an-ip]" || len(p.Capped) != 0 {
		t.Fatalf("分拣结果不对：%+v", p)
	}
	g := s.deps.Config.Snapshot().GlobalFirewall
	if fmt.Sprint(g.AllowIPs) != "[10.0.0.0/8 203.0.113.0/24 1.2.3.4-1.2.3.9]" {
		t.Fatalf("名单应按原顺序追加新增的两条，实际 %v", g.AllowIPs)
	}
	m := g.AllowMeta["203.0.113.0/24"]
	if m.Note != "办公网" || m.AddedAt == 0 || m.Source != "" {
		t.Fatalf("新增条目应带备注与加入时间、来源为手工，实际 %+v", m)
	}
	if len(res.Data.Entries) != 3 || res.Data.Entries[1].Note != "办公网" {
		t.Fatalf("回传的表格行应与名单一致，实际 %+v", res.Data.Entries)
	}
}

// 预览不落盘，且预览的分拣与随后真添加的分拣完全一致。
func TestListAddDryRunMatchesRealAdd(t *testing.T) {
	s := newDenyTestServer(t)
	body := `{"list":"deny","items":[{"ip":"198.51.100.7"},{"ip":"oops"}],"dryRun":true}`
	code, dry := postListAdd(t, s, body)
	if code != http.StatusOK || !dry.Data.DryRun {
		t.Fatalf("预览应成功并标明 dryRun，得到 %d %+v", code, dry.Data)
	}
	if n := len(s.deps.Config.Snapshot().GlobalFirewall.DenyIPs); n != 0 {
		t.Fatalf("预览不该写进名单，实际已有 %d 条", n)
	}
	_, real := postListAdd(t, s, strings.Replace(body, `"dryRun":true`, `"dryRun":false`, 1))
	if fmt.Sprintf("%+v", dry.Data.Plan) != fmt.Sprintf("%+v", real.Data.Plan) {
		t.Fatalf("预览与真添加的分拣不一致：\n预览 %+v\n实际 %+v", dry.Data.Plan, real.Data.Plan)
	}
}

// 名单满了之后，多出来的必须进 capped 而不是悄悄消失；已在名单里的仍算 existing。
func TestListAddReportsCapped(t *testing.T) {
	s := newDenyTestServer(t)
	items := make([]string, 0, config.GlobalFirewallMaxIPs+2)
	for i := 0; i < config.GlobalFirewallMaxIPs; i++ {
		items = append(items, fmt.Sprintf(`{"ip":"10.1.%d.%d"}`, i/256, i%256))
	}
	if code, _ := postListAdd(t, s, `{"list":"deny","items":[`+strings.Join(items, ",")+`]}`); code != http.StatusOK {
		t.Fatalf("填满名单失败：%d", code)
	}
	_, res := postListAdd(t, s, `{"list":"deny","items":[{"ip":"10.1.0.0"},{"ip":"192.0.2.1"}]}`)
	if fmt.Sprint(res.Data.Plan.Existing) != "[10.1.0.0]" || fmt.Sprint(res.Data.Plan.Capped) != "[192.0.2.1]" {
		t.Fatalf("满表时应报 existing=[10.1.0.0] capped=[192.0.2.1]，实际 %+v", res.Data.Plan)
	}
	if n := len(s.deps.Config.Snapshot().GlobalFirewall.DenyIPs); n != config.GlobalFirewallMaxIPs {
		t.Fatalf("名单不应超过上限，实际 %d 条", n)
	}
}

// 非法请求：名单名不认得、空批、批过大、备注超长，都要 400，且不改配置。
func TestListAddRejectsBadRequests(t *testing.T) {
	s := newDenyTestServer(t)
	big := strings.Repeat(`{"ip":"1.1.1.1"},`, gfwListMaxBatch) + `{"ip":"1.1.1.1"}`
	cases := map[string]string{
		"名单名不认得":  `{"list":"grey","items":[{"ip":"1.1.1.1"}]}`,
		"空批":      `{"list":"allow","items":[]}`,
		"批过大":     `{"list":"allow","items":[` + big + `]}`,
		"备注超长":    `{"list":"allow","items":[{"ip":"1.1.1.1","note":"` + strings.Repeat("长", config.MaxIPListNoteRunes+1) + `"}]}`,
		"不是 JSON": `list=allow`,
	}
	for name, body := range cases {
		if code, _ := postListAdd(t, s, body); code != http.StatusBadRequest {
			t.Errorf("%s：应 400，得到 %d", name, code)
		}
	}
	if g := s.deps.Config.Snapshot().GlobalFirewall; len(g.AllowIPs) != 0 {
		t.Fatalf("被拒的请求不该改动名单，实际 %v", g.AllowIPs)
	}
}

// 删除只动点到的那几条，被删条目的附属信息一起消失；all=true 清空；空请求不等于全删。
func TestListRemove(t *testing.T) {
	s := newDenyTestServer(t)
	postListAdd(t, s, `{"list":"allow","items":[{"ip":"10.0.0.1","note":"a"},{"ip":"10.0.0.2","note":"b"},{"ip":"10.0.0.3"}]}`)

	if code, _ := postListRemove(t, s, `{"list":"allow"}`); code != http.StatusBadRequest {
		t.Fatalf("什么都没带的删除应 400（不能被理解成全删），得到 %d", code)
	}
	code, res := postListRemove(t, s, `{"list":"allow","ips":["10.0.0.1","10.0.0.9"]}`)
	if code != http.StatusOK || res.Data.Removed != 1 {
		t.Fatalf("应删掉 1 条（10.0.0.9 本来就不在），得到 %d removed=%d", code, res.Data.Removed)
	}
	g := s.deps.Config.Snapshot().GlobalFirewall
	if fmt.Sprint(g.AllowIPs) != "[10.0.0.2 10.0.0.3]" {
		t.Fatalf("应只剩没点到的两条，实际 %v", g.AllowIPs)
	}
	if _, ok := g.AllowMeta["10.0.0.1"]; ok {
		t.Fatal("被删条目的附属信息应一起清掉")
	}
	if g.AllowMeta["10.0.0.2"].Note != "b" {
		t.Fatal("没被点到的条目的备注不该受影响")
	}

	_, res = postListRemove(t, s, `{"list":"allow","all":true}`)
	if res.Data.Removed != 2 || len(res.Data.Entries) != 0 {
		t.Fatalf("all=true 应清空整张名单，removed=%d entries=%d", res.Data.Removed, len(res.Data.Entries))
	}
	if g := s.deps.Config.Snapshot().GlobalFirewall; g.AllowIPs != nil || g.AllowMeta != nil {
		t.Fatalf("清空后名单与附属信息都应为 nil，实际 %v / %v", g.AllowIPs, g.AllowMeta)
	}
}

// 从自动封禁一键升级进黑名单的条目要带加入时间与来源标记，界面靠它注明来历。
func TestDenyBanStampsListMeta(t *testing.T) {
	s := newDenyTestServer(t)
	const target = "203.0.113.77"
	banSource(t, s, target)
	if code, _ := postDeny(t, s, `{"ip":"`+target+`"}`); code != http.StatusOK {
		t.Fatalf("升级失败：%d", code)
	}
	m := s.deps.Config.Snapshot().GlobalFirewall.DenyMeta[target]
	if m.Source != config.IPListSourceAutoBan || m.AddedAt == 0 {
		t.Fatalf("升级进来的条目应标明来自自动封禁并记下时间，实际 %+v", m)
	}
}

// PUT 整体替换名单时：原有条目的备注保留，新出现的条目补上加入时间。
func TestPutListKeepsMetaAndStampsNew(t *testing.T) {
	s := newDenyTestServer(t)
	postListAdd(t, s, `{"list":"allow","items":[{"ip":"10.0.0.1","note":"保留我"}]}`)

	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	ctx.Request = newSchemeRequest(t, false, http.MethodPut, "/global-firewall", `{"allowIps":["10.0.0.1","10.0.0.2"]}`)
	s.handleUpdateGlobalFirewall(ctx)
	if w.Code != http.StatusOK {
		t.Fatalf("PUT 应成功，得到 %d：%s", w.Code, w.Body.String())
	}
	g := s.deps.Config.Snapshot().GlobalFirewall
	if g.AllowMeta["10.0.0.1"].Note != "保留我" {
		t.Fatalf("原有条目的备注应保留，实际 %+v", g.AllowMeta)
	}
	if g.AllowMeta["10.0.0.2"].AddedAt == 0 {
		t.Fatalf("新替换进来的条目应有加入时间，实际 %+v", g.AllowMeta)
	}
}
