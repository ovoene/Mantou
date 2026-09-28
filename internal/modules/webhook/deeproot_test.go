package webhook

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// 本文件盯的是"解得开、却回不去"的载荷：嵌套到九千九百多层的 JSON。
//
// JSON 解码允许一万层，而 encoding/json 序列化超过一万层就报错。Root 要整个放进面板的
// 接口响应（试运行抓包、样本试运行、模板预览），响应外面又包了几层，于是这种载荷一进来，
// gin 吞掉序列化错误、面板收到空的 200——抓包能留三小时，试运行面板就空白三小时。
// 修法是嵌套超过 maxRootDepth 层就不下发 Root（见 rootTooDeep），其余结果照常给。

// nested 造一份 depth 层的 [[[…]]]。
func nested(depth int) string { return strings.Repeat("[", depth) + strings.Repeat("]", depth) }

// mustEncodeAsResponse 按接口响应的样子包一层再序列化：序列化失败就是面板收到空 200 的那条路。
func mustEncodeAsResponse(t *testing.T, v any) {
	t.Helper()
	if _, err := json.Marshal(map[string]any{"data": map[string]any{"capture": map[string]any{"result": v}}}); err != nil {
		t.Fatalf("接口响应序列化失败（面板会收到空的 200）：%v", err)
	}
}

func TestLiveCaptureOfDeepPayloadStaysEncodable(t *testing.T) {
	h := newHarness(t, hitCfg(nil))
	mustStart(t, h, "r1")

	if code, body := h.post(t, "/hook", nested(9999)); code != http.StatusOK {
		t.Fatalf("对方仍应收到 200，实际 %d：%s", code, body)
	}
	st := h.m.TestRunState("r1")
	if st.Capture == nil || st.Capture.Result == nil {
		t.Fatalf("应抓到这一条：%+v", st)
	}
	r := st.Capture.Result
	if r.Root != nil || !r.RootTooDeep {
		t.Fatalf("嵌套过深的载荷不该下发字段树：rootTooDeep=%v", r.RootTooDeep)
	}
	// 命中与渲染照常给出：右栏除了字段树，其余都应该还在。
	if r.Matched != 1 || len(r.Messages) != 1 {
		t.Fatalf("处理结果应照常给出：%+v", r)
	}
	mustEncodeAsResponse(t, st)
}

func TestDryRunAndPreviewOfDeepSampleStayEncodable(t *testing.T) {
	h := newHarness(t, hitCfg(nil))

	out, err := h.m.DryRun("r1", []byte(nested(9999)), nil, "")
	if err != nil {
		t.Fatal(err)
	}
	if out.Root != nil || !out.RootTooDeep {
		t.Fatalf("样本试运行：嵌套过深不该下发字段树：rootTooDeep=%v", out.RootTooDeep)
	}
	mustEncodeAsResponse(t, out)

	pv := h.m.PreviewTemplate("r1", []byte(nested(9999)), nil, "", TemplateSpec{Format: "text", Body: "{{toJSONIndent .body}}"})
	if pv.Root != nil || !pv.RootTooDeep {
		t.Fatalf("模板预览：嵌套过深不该下发字段树：rootTooDeep=%v", pv.RootTooDeep)
	}
	if !pv.Truncated || !strings.HasPrefix(pv.Body, "[\n  [") {
		t.Fatalf("渲染照常进行，且按输出上限截断：truncated=%v", pv.Truncated)
	}
	mustEncodeAsResponse(t, pv)
}

// 正常深度的载荷不受影响：字段树照常下发。
func TestNormalDepthRootIsKept(t *testing.T) {
	h := newHarness(t, hitCfg(nil))
	for _, depth := range []int{1, 20, maxRootDepth - 2} {
		out, err := h.m.DryRun("r1", []byte(nested(depth)), nil, "")
		if err != nil {
			t.Fatal(err)
		}
		if out.Root == nil || out.RootTooDeep {
			t.Fatalf("%d 层的载荷应照常下发字段树", depth)
		}
	}
	out, _ := h.m.DryRun("r1", []byte(`{"消息编号":"MSG-1","items":[{"名称":"a"}]}`), nil, "")
	if out.Root == nil || out.RootTooDeep {
		t.Fatal("普通载荷应照常下发字段树")
	}
}

// 判定本身：上限处的边界，以及宽而浅的载荷不算深。
func TestRootTooDeepBoundary(t *testing.T) {
	var v any = "leaf"
	for i := 0; i < maxRootDepth; i++ {
		v = []any{v}
	}
	if rootTooDeep(v) {
		t.Fatalf("正好 %d 层不该判深", maxRootDepth)
	}
	if !rootTooDeep([]any{v}) {
		t.Fatalf("%d 层应判深", maxRootDepth+1)
	}
	wide := make([]any, 100000)
	for i := range wide {
		wide[i] = map[string]any{"k": []any{"x"}}
	}
	if rootTooDeep(wide) {
		t.Fatal("宽而浅的载荷不该判深")
	}
}
