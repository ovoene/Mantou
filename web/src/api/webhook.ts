import api from './client'
import { resourceApi } from './resources'

// 消息路由（Webhook → 规则 → 模板 → 通知）的前端接口层。
// 字段名与 Go 侧的 json tag 一一对应，改后端结构时这里要一起改。

export interface Condition {
  path: string
  op: string
  value: string
  not: boolean
}

export interface FieldMapping {
  name: string
  path: string
  default: string
  note: string
}

// RuleBranch 一条规则的一个输出分支：在规则的公共条件之上再筛一层，
// 各自选自己的模板与目标。用来表达"同一批消息按细分条件发不同的人"，
// 以前只能拆成多条规则、把公共条件在两处各维护一遍。
export interface RuleBranch {
  name: string
  match: string
  conditions: Condition[]
  templateRef: string
  targets: string[]
}

export interface WebhookRule {
  id?: string
  name: string
  enabled: boolean
  priority: number
  match: string
  conditions: Condition[]
  templateRef: string
  targets: string[]
  // 命中后是否继续比对后续规则；默认 false = 首个命中即停。
  continue: boolean
  // branches 输出分支。为空（默认，也是所有老配置的形态）时这条规则只有一个输出，
  // 就是上面的 templateRef + targets；配了分支之后那两项不再参与运行。
  branches?: RuleBranch[]
  // firstBranchOnly 命中即停：只发第一个命中的分支；默认（false）是命中的分支全都发。
  firstBranchOnly?: boolean
}

// 「发送规则」那一页的一行：规则本体 + 它归哪个接收器。
// receiverEnabled 用来提示"规则开着，但它所在的接收器是停用的，此刻不会执行"。
export interface WebhookRuleItem extends WebhookRule {
  id: string
  receiverId: string
  receiverName: string
  receiverEnabled: boolean
}

export interface WebhookReceiver {
  id?: string
  name: string
  enabled: boolean
  note: string
  path: string
  authType: string
  authHeader: string
  token: string
  rateLimit: number
  maxBodyKb: number
  ipFilter: boolean
  ipFilterMode: string
  allowIps: string[]
  denyIps: string[]
  // keywordFilter 关键词准入：与钉钉／企业微信的自定义关键词同一个思路，方向相反——
  // 要求收到的消息里带上约定的词，带了才往下走。keywordMode: any=任一 / all=全部。
  keywordFilter: boolean
  keywords: string[]
  keywordMode: string
  // sourceType 来源消息类型：auto=自动识别（默认，每条消息各判一次）/ json / kv / txt。
  sourceType: string
  // pairSep / kvSep 仅 sourceType=kv 时有意义：字段之间用什么符号隔开、字段名与值之间
  // 用什么符号连接（a=1&b=2 里分别是 & 和 =）。两个都留空表示自动识别。
  pairSep: string
  kvSep: string
  rootPath: string
  mappings: FieldMapping[]
  rules: WebhookRule[]
  defaultTargets: string[]
  // 统计，后端只在列表里返回，只读。这几个数只在服务端内存里，重启归零，
  // 保存时不会带回去（后端也不接收）。
  lastReceivedAt?: number
  lastStatus?: string
  receivedCount?: number
  rejectedCount?: number
}

export interface NotifyTarget {
  id?: string
  name: string
  enabled: boolean
  type: string
  note: string
  url: string
  secret: string
  method: string
  contentType: string
  headers: Record<string, string>
  bodyTemplate: string
  atMobiles: string[]
  atAll: boolean
  timeoutSec: number
  retry: number
  // 统计，后端只在列表里返回，只读。这几个数只在服务端内存里，重启归零，
  // 保存时不会带回去（后端也不接收）。
  lastSentAt?: number
  lastStatus?: string
  sentCount?: number
  failCount?: number
}

export interface MessageTemplate {
  id?: string
  name: string
  note: string
  format: string
  title: string
  body: string
  // titleStyle markdown 模式下标题以什么样式插进正文：h1/h2/h3/bold/none。
  // 钉钉的 markdown.title 只显示在会话列表里，企业微信干脆没有这个字段，
  // 所以标题得真正写进正文才看得见（后端 process.go markdownTitled）。
  titleStyle: string
  updated?: number
}

export interface WebhookServer {
  // created 模块那一行存在不存在。它不是 enabled 的同义词：未创建时「模块设置」是一个
  // 空列表 + 新建按钮，接收器也无法启用（没有监听就没有域名、没有可访问的地址）。
  created: boolean
  enabled: boolean
  listen: string
  port: number
  // domain 在模块级而不在 https 下：端口 80 / 443 与 Web 服务共用同一条监听时，
  // 即使不开 HTTPS 也要靠域名把请求分给本模块。https.domain 只为读得到旧配置。
  domain: string
  note: string
  // sourceRetainMb 被拒收 / 被丢弃的入站原文，最多在内存里留多少 MB（0 表示不留存）。
  // 上限见后端 config.MaxSourceRetainMB。
  sourceRetainMb: number
  https: { enabled: boolean; certId: string; domain?: string }
}

export interface WebhookStatus {
  // enabled 仅在模块整体不可用时由后端单独下发（此时其余字段全部缺省）。
  enabled?: boolean
  message?: string
  healthy?: boolean
  total?: number
  active?: number
  received?: number
  rejected?: number
  dropped?: number
  sent?: number
  failed?: number
  sendDropped?: number
  pending?: number
}

// 执行历史一条。event 取值见后端 history.go：received / rejected / matched / sent / failed 等。
export interface HistoryEntry {
  time: number
  event: string
  eventId?: string
  receiverId?: string
  receiver?: string
  remote?: string
  status?: number
  rule?: string
  target?: string
  reason?: string
  ms?: number
  // sourceId 指向内存里留存的入站原文，只有被拒收 / 被丢弃的记录才有。
  // 有值时「来源」那一格做成可点的，点开取 source(id)。
  sourceId?: string
}

// 一条留存的入站原文。字段与后端 SourceRecord 对应。
export interface SourceRecord {
  id: string
  time: number
  event: string
  eventId?: string
  receiverId?: string
  receiver?: string
  remote?: string
  status?: number
  reason?: string
  method?: string
  path?: string
  query?: string
  headers?: Record<string, string>
  body?: string
  // bodyRead 为 false 不等于"正文是空的"：鉴权、限流、IP 名单这些闸都在读正文之前，
  // 被它们拦下的请求根本没有正文。界面上必须把这两种情况分开说。
  bodyRead: boolean
  bodySize: number
  bodyTruncated?: boolean
  sniffed?: string
}

// 留存的用量与上限，给对话框底部那行说明用。
export interface SourceStats {
  count: number
  bytes: number
  budget: number
  bodyMax: number
  maxEntries: number
}

export interface DryRunMessage {
  ruleId: string
  ruleName: string
  // branch 产出这条消息的输出分支名；没配分支的规则为空。
  // 界面上显示成「规则名 / 分支名」，与执行历史里的写法一致。
  branch?: string
  // template 渲染这条消息的模板名。多分支下这一项才真正有用：两个分支的正文常常
  // 长得很像，只看渲染结果分不出是分支条件筛错了还是模板选错了。
  template?: string
  title: string
  body: string
  format: string
  targets: string[]
  missing: number
  error?: string
}

export interface DryRunResult {
  eventId: string
  root: Record<string, any>
  unresolved: string[]
  matched: number
  // noBranch 命中了规则、但没有任何输出分支的条件成立的规则名。
  // 这是"配好了却收不到"的另一种：规则条件过了、分支条件没过。必须与"没有规则命中"
  // 分开说，否则用户会回头去改已经对了的那一层条件。
  noBranch?: string[]
  truncated: boolean
  messages: DryRunMessage[]
  targetNames: Record<string, string>
  // blocked 这条样本会被关键词准入拒收。渲染结果照样给出：用户此刻正在调词表，
  // 既要知道"这条会被拦"，也要看到"不拦的话会发出什么"。
  blocked?: boolean
  blockedReason?: string
}

// 元数据由后端下发：算子、模板函数、内置字段名、上限与默认值。
// 前端不再另存一份——两边各写一遍必然会漂，用户会在下拉框里选到运行期不认得的算子。
// 实时试运行抓到的一条消息：左栏显示第三方原样发来的东西，右栏是 result 跑出来的结果。
// rejected 为真时没有 result（流水线没跑），reason 说明是被什么挡下的。
export interface TestRunCapture {
  time: number
  remote: string
  method: string
  query: string
  headers: Record<string, string>
  body: string
  // sniffed 后端对这一条判出的形态（json / kv / txt），只作为抓包上的标签展示。
  // 刻意不回写「来源消息类型」：一条消息的形态不等于整个接收器的类型。
  sniffed: string
  rejected: boolean
  reason: string
  status: number
  result?: DryRunResult
  // bodySize 正文的原始字节数（截断之前）。
  bodySize?: number
  // bodyTruncated 正文超过后端的抓包上限，这里只是前一截。
  // 界面必须标出来：这一份当样本用会解析失败，而那不是模板写错了。
  bodyTruncated?: boolean
  // rootDropped 这一份没带字段树（只在正文被截断时发生，字段树是按整段正文解出来的）。
  rootDropped?: boolean
}

export interface TestRunState {
  running: boolean
  startedAt: number
  expiresAt: number
  count: number
  // capture 最新抓到的那一条，**只留一条**。它同时就是全局唯一的样本载荷：
  // 模板预览、字段映射、条件调试都用它，用户不必在几个弹窗之间搬运同一段 JSON。
  capture?: TestRunCapture
  // captureExpiresAt 这份抓包被销毁的时刻（秒）。抓包里有完整请求头与业务字段，
  // 所以它最多留 3 小时（后端 webhook.CaptureTTL，也由 meta.defaults.sampleTtlS 下发）。
  captureExpiresAt?: number
  // captureExpired 抓到过样本、但已经到期销毁了。与"从没抓到过"要分开：
  // 界面上一句是"去第三方系统点一次推送"，另一句是"上一份已销毁，重开一次"。
  captureExpired?: boolean
  sniffed?: string
  // stoppedReason 非空表示上一次是超时自动停的。
  stoppedReason?: string
}

// 模板预览：把编辑框里**还没保存**的草稿配一段样本载荷渲染一次。
// 与试运行的分工——试运行看"命中哪条规则、发给谁"，预览看"这个模板长什么样"，
// 因此不需要规则、不需要通知目标，接收器也可以不选（不选时别名一律取不到值）。
export interface TemplatePreviewReq {
  receiverId?: string
  format: string
  title: string
  titleStyle: string
  body: string
  sample: string
  headers?: Record<string, string>
  query?: string
}

export interface TemplatePreviewResult {
  title: string
  body: string
  format: string
  missing: number
  truncated?: boolean
  error?: string
  // root 别名注入后的完整信封；unresolved 是这段样本里取不到值的别名。
  root: Record<string, any>
  unresolved: string[]
  sniffed?: string
  // receiver 实际借用的接收器名；为空表示没挑接收器。
  receiver?: string
}

export interface WebhookMeta {
  operators: string[]
  // countOperators 比"取到几个值"的算子，比较值必须填数字。
  countOperators: string[]
  sourceTypes: string[]
  templateFuncs: string[]
  reservedFields: string[]
  targetTypes: string[]
  titleStyles: string[]
  limits: Record<string, number>
  defaults: Record<string, number>
}

export const receiversApi = resourceApi<WebhookReceiver>('webhook/receivers')
export const notifyTargetsApi = resourceApi<NotifyTarget>('webhook/targets')
export const messageTemplatesApi = resourceApi<MessageTemplate>('webhook/templates')

// 发送规则不用 resourceApi：规则住在接收器下面，一条规则的地址是「哪个接收器的哪条」
// （规则 ID 只在接收器内唯一），而列表要的是跨接收器的一张扁平表。
// 只回传单条、不整份写回接收器，理由见后端 api_webhook_rules.go 开头那段。
export const rulesApi = {
  list: (silent?: boolean) =>
    api.get<WebhookRuleItem[]>('/webhook/rules', undefined, silent ? { silent: true } : undefined),
  create: (receiverId: string, v: WebhookRule) =>
    api.post<WebhookRuleItem>(`/webhook/receivers/${receiverId}/rules`, v),
  // body 里的 receiverId 表示"把这条规则挪到那个接收器下"，与路径相同则是原地保存。
  update: (receiverId: string, id: string, v: WebhookRule & { receiverId?: string }) =>
    api.put<WebhookRuleItem>(`/webhook/receivers/${receiverId}/rules/${id}`, v),
  toggle: (receiverId: string, id: string, enabled: boolean) =>
    api.post<{ id: string; receiverId: string; enabled: boolean }>(
      `/webhook/receivers/${receiverId}/rules/${id}/toggle`,
      { enabled },
    ),
  remove: (receiverId: string, id: string) =>
    api.del<{ ok: boolean }>(`/webhook/receivers/${receiverId}/rules/${id}`),
}

export const webhookActions = {
  status: (silent?: boolean) =>
    api.get<WebhookStatus>('/webhook/status', undefined, silent ? { silent: true } : undefined),
  getServer: () => api.get<WebhookServer>('/webhook/server'),
  saveServer: (v: Omit<WebhookServer, 'listen' | 'created'>) =>
    api.put<{ ok: boolean; message?: string; healthy?: boolean }>('/webhook/server', v),
  // 删除模块那一行：停止监听、抹掉端口/域名/证书，那一页回到"未创建"。
  // 接收器、模板、通知目标、规则一律不动——用户删的是这台机器上的入站监听，
  // 不是他配了半天的路由。仍有接收器启用中时后端会拒绝并点名是谁挡着。
  deleteServer: () => api.del<{ ok: boolean }>('/webhook/server'),
  // 模块设置那一行的开关：只发 enabled，端口 / 域名 / HTTPS 一律沿用已存的那份
  // （与接收器、通知目标的开关同一种端点；启用时后端照样跑完整校验）。
  toggleServer: (enabled: boolean) =>
    api.post<{ ok: boolean; enabled: boolean; message?: string; healthy?: boolean }>(
      '/webhook/server/toggle',
      { enabled },
    ),
  meta: () => api.get<WebhookMeta>('/webhook/meta'),
  // 随机入站路径由后端生成：它是这个入口的主要保护，不该依赖浏览器的随机源。
  newPath: () => api.get<{ path: string }>('/webhook/newpath'),
  // event 是事件类型（received / rejected / ...），筛选在后端做：limit 也在后端生效，
  // 拿到 200 条再在浏览器里筛会漏掉第 201 条往后的记录。
  history: (params?: { receiverId?: string; event?: string; limit?: number }, silent?: boolean) =>
    api.get<HistoryEntry[]>('/webhook/history', params, silent ? { silent: true } : undefined),
  // found 为 false 表示这条原文已经被新记录顶掉了（留存只在内存里、按预算淘汰）。
  // 这不是错误，所以后端也返回 200——界面照这个值提示"已不在内存里"。
  source: (id: string) =>
    api.get<{ found: boolean; record?: SourceRecord }>('/webhook/history/source', { id }),
  sourceStats: (silent?: boolean) =>
    api.get<SourceStats>('/webhook/history/source/stats', undefined, silent ? { silent: true } : undefined),
  // 清空留存的原文。额度不动，下一条消息照常留存；要"从此不再留"是把额度调成 0。
  clearSources: () => api.post<{ cleared: number }>('/webhook/history/source/clear', {}),
  dryRun: (id: string, payload: { body: string; headers?: Record<string, string>; query?: string }) =>
    api.post<DryRunResult>(`/webhook/receivers/${id}/dryrun`, payload),
  // 预览不带模板 ID：草稿还没保存（也可能永远不保存）。
  previewTemplate: (payload: TemplatePreviewReq, silent?: boolean) =>
    api.post<TemplatePreviewResult>(
      '/webhook/templates/preview',
      payload,
      silent ? { silent: true } : undefined,
    ),
  testRunState: (id: string, silent?: boolean) =>
    api.get<TestRunState>(`/webhook/receivers/${id}/testrun`, undefined, silent ? { silent: true } : undefined),
  testRunStart: (id: string) => api.post<TestRunState>(`/webhook/receivers/${id}/testrun/start`, {}),
  testRunStop: (id: string) => api.post<TestRunState>(`/webhook/receivers/${id}/testrun/stop`, {}),
  // 测试发送的内容全部手填，不走模板、不做变量渲染：面板里发什么，通道里就收到什么。
  testTarget: (id: string, payload?: { message?: string; format?: string; title?: string; titleStyle?: string }) =>
    api.post<{ ok: boolean; costMs: number; status: string }>(`/webhook/targets/${id}/test`, payload || {}),
}
