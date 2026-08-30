package webhook

import (
	"fmt"
	"net/http"
	"net/url"

	"mantou/internal/config"
	"mantou/internal/tmplx"
)

// 本文件是「消息模板 → 预览」。
//
// 它与试运行是一对，回答的问题不同：试运行说的是"这条消息会不会命中规则、会发给谁"，
// 预览说的是"这个模板渲染出来长什么样"。所以预览刻意不需要规则、不需要通知目标，
// 甚至不需要接收器——用户新建一个模板时，这几样通常都还没配。
//
// 两条要点：
//
//   - 渲染走的是 process.go 的 renderBranch，与真实投递同一段代码。预览里看到的标题拼法、
//     缺字段计数、截断标记因此必然与真发出去的一致；另写一遍就等于让用户照着一个
//     不存在的样子调模板。
//   - 预览的对象是**编辑框里还没保存的草稿**。保存前就能看到结果，才谈得上"照着改"；
//     要求先保存再预览的话，用户为了试一版排版得先把一个错模板存进配置里。
//
// 另外，Root 会原样回给界面：它是别名解析之后的信封，界面拿它列字段、判断哪个别名是
// 数组，从而把「常用写法」那段循环骨架按用户自己的字段生成出来（而不是写死 items）。

// TemplateSpec 待预览的模板草稿。
//
// 字段与 config.MessageTemplate 的同名字段一一对应，但刻意不复用那个结构：
// 预览的是编辑框里的当前内容，它可能还没有 ID、也可能永远不会被保存。
type TemplateSpec struct {
	Format     string `json:"format"`
	Title      string `json:"title"`
	Body       string `json:"body"`
	TitleStyle string `json:"titleStyle"`
}

// PreviewResult 一次预览的结果。
//
// 出错时也照样把已经渲染出来的正文给出来（与试运行同口径）：一段"渲染到一半"的正文
// 往往正好指出模板在哪一行写歪了，比只给一句错误有用得多。
type PreviewResult struct {
	Title   string `json:"title"`
	Body    string `json:"body"`
	Format  string `json:"format"`
	Missing int    `json:"missing"`
	// Truncated 正文超出长度上限已被截断（真实投递也会截断，见 tmplx.MaxRenderBytes）。
	Truncated bool   `json:"truncated,omitempty"`
	Error     string `json:"error,omitempty"`

	// Root 别名注入之后的完整信封，Unresolved 是在这段样本里取不到值的别名。
	// 界面用它们列可用字段、生成参照模板，并提示"这几个别名这条样本里没有值"。
	Root       map[string]any `json:"root"`
	Unresolved []string       `json:"unresolved"`
	// Sniffed 这段样本被判成什么形态（json / kv / txt），与抓包上的标签同一个判据。
	Sniffed string `json:"sniffed,omitempty"`
	// Receiver 实际用来解析样本、提供别名的接收器名。为空表示没挑接收器：
	// 此时别名一律取不到值，界面据此提示用户选一个，而不是让他以为是模板写错了。
	Receiver string `json:"receiver,omitempty"`
}

// previewReceiver 预览要用的接收器运行态。
//
// 找不到（或压根没传 ID）时**不报错**，而是造一个空接收器：没有别名、没有 RootPath、
// 来源类型按自动识别。理由是新建模板时接收器往往还不存在，而"贴一段样本看看模板长什么样"
// 这件事本身并不依赖接收器。真依赖别名的用户会发现别名取不到值，Receiver 为空正是提示。
func (m *Module) previewReceiver(id string) *receiverRT {
	if id != "" {
		for _, cand := range m.routes.Load().list {
			if cand.cfg.ID == id {
				return cand
			}
		}
	}
	return compileReceiver(config.WebhookReceiver{Path: "preview", SourceType: "auto"}, nil)
}

// PreviewTemplate 用一段样本载荷渲染一份**未保存**的模板草稿。
//
// spec.Body 为空时只解析样本、不渲染：界面刚打开预览、正文还没写时要的就是"有哪些字段
// 可以用"，此时报一句"渲染结果为空"没有任何帮助。
func (m *Module) PreviewTemplate(receiverID string, raw []byte, headers map[string]string,
	rawQuery string, spec TemplateSpec) *PreviewResult {

	rc := m.previewReceiver(receiverID)

	req := &http.Request{
		Method: http.MethodPost,
		Header: http.Header{},
		URL:    &url.URL{Path: "/" + rc.cfg.Path, RawQuery: rawQuery},
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	ev := buildEvent(rc, req, raw, "预览")
	out := &PreviewResult{
		Format:     spec.Format,
		Root:       ev.Root,
		Unresolved: ev.Unresolved,
		Receiver:   rc.cfg.Name,
	}
	if len(raw) > 0 {
		out.Sniffed = SniffSourceType(raw)
	}
	if spec.Body == "" {
		return out
	}

	// 草稿现编译成一个输出分支的运行态，再交给 renderBranch——与真实投递共用的那一段。
	ru := &branchRT{format: spec.Format, titleStyle: spec.TitleStyle}
	body, err := tmplx.Compile("preview:body", spec.Body)
	if err != nil {
		out.Error = fmt.Sprintf("正文语法错误：%v", err)
		return out
	}
	ru.body = body
	if spec.Title != "" {
		title, terr := tmplx.Compile("preview:title", spec.Title)
		if terr != nil {
			out.Error = fmt.Sprintf("标题语法错误：%v", terr)
			return out
		}
		ru.title = title
	}

	t, b, missing, truncated, rerr := renderBranch(ev, ru)
	out.Title, out.Body, out.Missing, out.Truncated = t, b, missing, truncated
	if rerr != nil {
		out.Error = rerr.Error()
	}
	return out
}
