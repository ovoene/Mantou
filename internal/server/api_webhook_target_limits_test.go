package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"mantou/internal/config"
)

// 本文件盯的是通知目标内部的规模上限（2.14-C）。
//
// 在此之前，同一个文件里关键词、字段映射、条件、分支都有 checkLimit，
// 唯独通知目标的请求头、请求体模板、@手机号三项一个数都不限：
// 一条目标可以带任意多个请求头、任意长的模板存进 config.json，
// 之后每次 Snapshot 都照样复制一份。面板入口的 1MB 请求体上限只能挡"单次保存"，
// 挡不住"存 50 条这样的目标"。
//
// 每一项都成对地测：**正好等于上限要放过、超一个字节要拒**。
// 只测超限那一半的话，把判断写成 >= 也一样绿——而那种差一错的后果是
// 用户填了一个正好 4096 字节的 token 却被告知过长，没人能猜到是差一。

// httpTarget 造一条通过全部前置校验的 type=http 目标，再交给调用方改想测的那一格。
// 前置校验（名称、类型、地址、脱敏占位）都得先过，否则测的就不是长度那一句了。
func httpTarget() config.NotifyTarget {
	return config.NotifyTarget{
		Name: "自建接口",
		Type: "http",
		URL:  "https://example.com/in",
	}
}

// 请求头条数：正好 MaxNotifyHeaders 条要过，多一条要拒。
func TestNotifyTargetHeaderCountLimit(t *testing.T) {
	full := httpTarget()
	full.Headers = make(map[string]string, config.MaxNotifyHeaders)
	for i := 0; i < config.MaxNotifyHeaders; i++ {
		full.Headers[fmt.Sprintf("X-H%02d", i)] = "v"
	}
	if err := validateNotifyTarget(full); err != nil {
		t.Fatalf("正好 %d 条应放过，实际 %v", config.MaxNotifyHeaders, err)
	}

	over := httpTarget()
	over.Headers = make(map[string]string, len(full.Headers)+1)
	for k, v := range full.Headers {
		over.Headers[k] = v
	}
	over.Headers["X-One-More"] = "v"
	err := validateNotifyTarget(over)
	if err == nil {
		t.Fatalf("%d 条应被拒", len(over.Headers))
	}
	// 措辞与同文件里其它 checkLimit 一致，且要报出实际条数——
	// 只说"超过上限"用户还得自己去数有几条。
	want := fmt.Sprintf("附加请求头数量超过上限 %d 条（当前 %d 条）", config.MaxNotifyHeaders, config.MaxNotifyHeaders+1)
	if err.Error() != want {
		t.Fatalf("报错措辞不对：\n want %q\n  got %q", want, err.Error())
	}
}

// 请求头名称长度：正好 MaxNotifyHeaderKeyLen 要过，多一个字节要拒且点名是哪一个。
func TestNotifyTargetHeaderKeyLenLimit(t *testing.T) {
	exact := httpTarget()
	exact.Headers = map[string]string{"X-" + strings.Repeat("k", config.MaxNotifyHeaderKeyLen-2): "v"}
	if err := validateNotifyTarget(exact); err != nil {
		t.Fatalf("正好 %d 字节的头名应放过，实际 %v", config.MaxNotifyHeaderKeyLen, err)
	}

	over := httpTarget()
	longKey := "X-" + strings.Repeat("k", config.MaxNotifyHeaderKeyLen-1)
	over.Headers = map[string]string{longKey: "v"}
	err := validateNotifyTarget(over)
	if err == nil {
		t.Fatalf("%d 字节的头名应被拒", len(longKey))
	}
	if !strings.Contains(err.Error(), "请求头名称") || !strings.Contains(err.Error(), "过长") {
		t.Fatalf("报错应说明头名过长：%q", err.Error())
	}
	// 名字本身要出现（截断过），否则填了好几个头的人不知道是哪一个。
	if !strings.Contains(err.Error(), "X-kkk") {
		t.Fatalf("报错应点名是哪个头：%q", err.Error())
	}
	// 但不该把整个超长的名字原样抄回去。
	if strings.Contains(err.Error(), longKey) {
		t.Fatalf("报错不该回显完整的超长头名：%q", err.Error())
	}
}

// 请求头取值长度：正好 MaxNotifyHeaderValueLen 要过，多一个字节要拒。
//
// 附带一条比长度本身更要紧的断言：报错里**不能出现取值**。
// 请求头的值是加密落盘、界面上脱敏显示的（最常见就是 Authorization），
// 把它抄进错误消息等于让一个凭证经由响应体流出去——而响应体是会被前端弹窗显示、
// 被反向代理记进访问日志的。
func TestNotifyTargetHeaderValueLenLimit(t *testing.T) {
	exact := httpTarget()
	exact.Headers = map[string]string{"Authorization": strings.Repeat("t", config.MaxNotifyHeaderValueLen)}
	if err := validateNotifyTarget(exact); err != nil {
		t.Fatalf("正好 %d 字节的取值应放过，实际 %v", config.MaxNotifyHeaderValueLen, err)
	}

	over := httpTarget()
	secret := "Bearer " + strings.Repeat("t", config.MaxNotifyHeaderValueLen-6)
	over.Headers = map[string]string{"Authorization": secret}
	err := validateNotifyTarget(over)
	if err == nil {
		t.Fatalf("%d 字节的取值应被拒", len(secret))
	}
	if !strings.Contains(err.Error(), "Authorization") || !strings.Contains(err.Error(), "过长") {
		t.Fatalf("报错应点名是哪个头的取值过长：%q", err.Error())
	}
	if strings.Contains(err.Error(), "Bearer") || strings.Contains(err.Error(), "ttt") {
		t.Fatalf("报错回显了请求头的取值，这是把凭证写进响应体：%q", err.Error())
	}
	// 长度要报出来：只说"过长"的话，用户不知道自己差多少。
	if !strings.Contains(err.Error(), fmt.Sprintf("当前 %d 字节", len(secret))) {
		t.Fatalf("报错应带上实际长度：%q", err.Error())
	}
}

// 多个请求头同时超长时，报的必须是同一个（按键名排序），而不是随 map 遍历顺序变。
// 与 TestTargetMaskedHeaderErrorIsDeterministic 同一个理由：
// 同一份输入连着保存两次得到两句不同的话，用户会以为自己改的地方不对。
func TestNotifyTargetHeaderLimitErrorIsDeterministic(t *testing.T) {
	tgt := httpTarget()
	long := strings.Repeat("t", config.MaxNotifyHeaderValueLen+1)
	tgt.Headers = map[string]string{"Z-Last": long, "A-First": long, "M-Mid": long}

	first := ""
	for i := 0; i < 20; i++ {
		err := validateNotifyTarget(tgt)
		if err == nil {
			t.Fatal("超长取值应报错")
		}
		if i == 0 {
			first = err.Error()
			continue
		}
		if err.Error() != first {
			t.Fatalf("同一份输入报了两句不同的话：\n%s\n%s", first, err.Error())
		}
	}
	if !strings.Contains(first, "A-First") {
		t.Fatalf("应报排序最前的那个键，实际 %q", first)
	}
}

// 请求体模板长度：正好 MaxNotifyBodyTemplateLen 要过，多一个字节要拒。
//
// 正好等于上限那一份必须是**语法正确**的模板，否则它被 tmplx.Compile 拦下来，
// 这一半就没在验"长度放过"这件事。
func TestNotifyTargetBodyTemplateLenLimit(t *testing.T) {
	const head = `{"text":"{{.message}}","pad":"`
	const tail = `"}`
	pad := config.MaxNotifyBodyTemplateLen - len(head) - len(tail)

	exact := httpTarget()
	exact.BodyTemplate = head + strings.Repeat("x", pad) + tail
	if len(exact.BodyTemplate) != config.MaxNotifyBodyTemplateLen {
		t.Fatalf("这条用例要求正好等于上限：%d vs %d", len(exact.BodyTemplate), config.MaxNotifyBodyTemplateLen)
	}
	if err := validateNotifyTarget(exact); err != nil {
		t.Fatalf("正好 %d 字节的模板应放过，实际 %v", config.MaxNotifyBodyTemplateLen, err)
	}

	over := httpTarget()
	over.BodyTemplate = head + strings.Repeat("x", pad+1) + tail
	err := validateNotifyTarget(over)
	if err == nil {
		t.Fatalf("%d 字节的模板应被拒", len(over.BodyTemplate))
	}
	want := fmt.Sprintf("请求体模板过长（上限 %d 字节，当前 %d 字节）", config.MaxNotifyBodyTemplateLen, len(over.BodyTemplate))
	if err.Error() != want {
		t.Fatalf("报错措辞不对：\n want %q\n  got %q", want, err.Error())
	}
}

// 长度不分通知类型都判：模板只有 type=http 会真的用上，但不管哪种类型它都照样
// 存进 config.json、照样跟着每次快照复制一份。
// 少了这一条，"把长度判断塞进 type == http 那个分支里"就没人拦——
// 而那样一条 type=dingtalk 的目标仍可带着 100MB 模板存进去。
func TestNotifyTargetBodyTemplateLenCheckedForAllTypes(t *testing.T) {
	tgt := httpTarget()
	tgt.Type = "dingtalk"
	tgt.URL = "https://oapi.dingtalk.com/robot/send?access_token=x"
	tgt.BodyTemplate = strings.Repeat("x", config.MaxNotifyBodyTemplateLen+1)

	err := validateNotifyTarget(tgt)
	if err == nil {
		t.Fatal("超长模板在任何通知类型下都该被拒")
	}
	if !strings.Contains(err.Error(), "请求体模板过长") {
		t.Fatalf("报错不对：%q", err.Error())
	}
}

// 长度判在编译之前：一份既超长又语法不通的模板，报的必须是"过长"。
//
// 次序反了的话，超长模板会先被送进 tmplx.Compile——为一份可以有几十 MB 的源文本
// 建一棵比它还大的语法树，而结论压根不取决于编译结果。
func TestNotifyTargetBodyTemplateLenCheckedBeforeCompile(t *testing.T) {
	tgt := httpTarget()
	// {{ 不闭合：语法一定编不过。
	tgt.BodyTemplate = "{{" + strings.Repeat("x", config.MaxNotifyBodyTemplateLen)

	err := validateNotifyTarget(tgt)
	if err == nil {
		t.Fatal("又超长又语法错的模板应被拒")
	}
	if !strings.Contains(err.Error(), "过长") {
		t.Fatalf("应先报过长（说明长度判在编译之前），实际 %q", err.Error())
	}
	if strings.Contains(err.Error(), "语法") {
		t.Fatalf("超长的模板不该被送去编译：%q", err.Error())
	}
}

// @ 的手机号：条数与单条长度都有界。
func TestNotifyTargetAtMobilesLimit(t *testing.T) {
	full := httpTarget()
	full.AtMobiles = make([]string, 0, config.MaxNotifyAtMobiles)
	for i := 0; i < config.MaxNotifyAtMobiles; i++ {
		full.AtMobiles = append(full.AtMobiles, fmt.Sprintf("139%08d", i))
	}
	if err := validateNotifyTarget(full); err != nil {
		t.Fatalf("正好 %d 个应放过，实际 %v", config.MaxNotifyAtMobiles, err)
	}

	over := httpTarget()
	over.AtMobiles = append(append([]string(nil), full.AtMobiles...), "13900000000")
	err := validateNotifyTarget(over)
	if err == nil {
		t.Fatalf("%d 个应被拒", len(over.AtMobiles))
	}
	if !strings.Contains(err.Error(), "数量超过上限") {
		t.Fatalf("报错不对：%q", err.Error())
	}

	longOne := httpTarget()
	longOne.AtMobiles = []string{strings.Repeat("1", config.MaxNotifyAtMobileLen)}
	if err := validateNotifyTarget(longOne); err != nil {
		t.Fatalf("正好 %d 字节应放过，实际 %v", config.MaxNotifyAtMobileLen, err)
	}
	longOne.AtMobiles = []string{strings.Repeat("1", config.MaxNotifyAtMobileLen+1)}
	if err := validateNotifyTarget(longOne); err == nil {
		t.Fatal("超长的手机号应被拒")
	} else if !strings.Contains(err.Error(), "过长") {
		t.Fatalf("报错不对：%q", err.Error())
	}
}

// 走一遍真实路由：上限确实接在保存路径上，且被拒之后一条都不存。
// 只在 validateNotifyTarget 上测的话，"这个函数压根没被 CRUD 调用"这种接线错漏不出来。
func TestNotifyTargetLimitsEnforcedOnSave(t *testing.T) {
	manager, router := newWebhookAPITest(t)
	before := len(manager.Get().NotifyTargets)

	pairs := make([]string, 0, config.MaxNotifyHeaders+1)
	for i := 0; i <= config.MaxNotifyHeaders; i++ {
		pairs = append(pairs, fmt.Sprintf(`"X-H%02d":"v"`, i))
	}
	body := fmt.Sprintf(`{"name":"自建接口","enabled":true,"type":"http","url":"https://example.com/in","headers":{%s}}`,
		strings.Join(pairs, ","))

	w := performJSONRequest(router, http.MethodPost, "/webhook/targets", body)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("超上限应被拦住，实际 %d：%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "附加请求头数量超过上限") {
		t.Fatalf("报错不对：%s", w.Body.String())
	}
	if got := len(manager.Get().NotifyTargets); got != before {
		t.Fatalf("不该存下任何目标：%d → %d", before, got)
	}
}

// 元数据接口下发的上限必须就是校验用的那几个常量。
//
// 界面上目前不拦这几项（拦要动 UI，得先问过），下发是为了将来要拦时前端不必再抄一遍数字。
// 抄一遍的结果就是常量改了界面没跟着改，于是界面说还能填、后端说已超限。
func TestWebhookMetaExposesTargetLimits(t *testing.T) {
	_, router := newWebhookAPITest(t)

	w := performJSONRequest(router, http.MethodGet, "/webhook/meta", "")
	if w.Code != http.StatusOK {
		t.Fatalf("元数据接口应成功，实际 %d：%s", w.Code, w.Body.String())
	}
	var resp struct {
		Data struct {
			Limits map[string]int `json:"limits"`
		} `json:"data"`
		Limits map[string]int `json:"limits"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	limits := resp.Limits
	if limits == nil {
		limits = resp.Data.Limits
	}
	want := map[string]int{
		"headers":         config.MaxNotifyHeaders,
		"headerKeyLen":    config.MaxNotifyHeaderKeyLen,
		"headerValueLen":  config.MaxNotifyHeaderValueLen,
		"bodyTemplateLen": config.MaxNotifyBodyTemplateLen,
		"atMobiles":       config.MaxNotifyAtMobiles,
	}
	for k, v := range want {
		got, ok := limits[k]
		if !ok {
			t.Fatalf("元数据里缺少 limits.%s（响应：%s）", k, w.Body.String())
		}
		if got != v {
			t.Fatalf("limits.%s 与常量不一致：%d vs %d", k, got, v)
		}
	}
}
