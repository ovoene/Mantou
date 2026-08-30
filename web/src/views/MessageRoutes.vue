<script setup lang="ts">
import { computed, onActivated, onDeactivated, onUnmounted, reactive, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import { ElMessage, ElMessageBox } from 'element-plus'
import { Plus, Setting, Refresh, CopyDocument } from '@element-plus/icons-vue'
import api from '@/api/client'
import PageCard from '@/components/PageCard.vue'
import { useResource, fmtTime, fmtTimeMs, fmtBytes } from '@/composables/useResource'
import { useCloseOnLeave } from '@/composables/useCloseOnLeave'
import ReceiverDialog from '@/components/webhook/ReceiverDialog.vue'
import RuleDialog from '@/components/webhook/RuleDialog.vue'
import TargetDialog from '@/components/webhook/TargetDialog.vue'
import TargetTestDialog from '@/components/webhook/TargetTestDialog.vue'
import TemplateDialog from '@/components/webhook/TemplateDialog.vue'
import DryRunPanel from '@/components/webhook/DryRunPanel.vue'
import { rulesApi, webhookActions } from '@/api/webhook'
import type {
  HistoryEntry,
  MessageTemplate,
  NotifyTarget,
  SourceRecord,
  SourceStats,
  TestRunState,
  WebhookMeta,
  WebhookReceiver,
  WebhookRule,
  WebhookRuleItem,
  WebhookServer,
  WebhookStatus,
} from '@/api/webhook'

// 消息路由页：模块设置 / 接收器 / 消息模板 / 通知目标 / 发送规则 / 执行历史。
//
// 这几类资源放一页而不是几个菜单项：它们只有串起来才有意义
//（收到 → 判断 → 渲染 → 发出），分开摆用户得在几个页面之间来回对 ID。
// 标签顺序刻意跟着这条链走：接收器 → 消息模板 → 通知目标 → 发送规则，
// 规则排在最后是因为它要引用前面三样——先有入口、模板和目标，才配得出一条规则。

const { t } = useI18n()

interface CertOption {
  id?: string
  name: string
  domains: string[]
}

const tab = ref('receivers')
const meta = ref<WebhookMeta | null>(null)
const status = ref<WebhookStatus>({})
const history = ref<HistoryEntry[]>([])
const historyFilter = ref('')
const historyEvent = ref('')
const historyLoading = ref(false)

// 执行历史分页。默认只摆 20 条：这张表最常见的用法是"刚推了一条，看看它去哪了"，
// 一屏 200 行反而要往下翻。想看更多就改「每页显示条数」。
//
// 分页在前端做：历史只活在内存环里，条数天花板就是后端那 2000（history.go
// historyMaxEntries），一次取回来就是全部——所以「共 N 条」是准的，翻页也不用再打接口。
const HISTORY_SIZES = [20, 50, 100, 200, 500]
const HISTORY_MAX = 2000
const historyPage = ref(1)
const historyPageSize = ref(HISTORY_SIZES[0])
const pagedHistory = computed(() => {
  const from = (historyPage.value - 1) * historyPageSize.value
  return history.value.slice(from, from + historyPageSize.value)
})
// 改每页条数会让当前页码可能落到范围外（第 8 页 × 20 条，切成 500 条就没有第 8 页了）。
watch(historyPageSize, () => (historyPage.value = 1))

// sample 是「接收器 → 解析」「试运行」「消息模板」共用的样本载荷，并落 localStorage。
// 配一个来源系统要在这几处之间来回切，每次重贴一遍原始包会让"不写代码"
// 这件事重新变成体力活。模板编辑器拿它做两件事：列出还没起别名的原始字段，
// 以及给预览当渲染数据（见 TemplateDialog）。
//
// 它有存活上限。这份东西是第三方真实推过来的载荷，里面有业务字段（金额、客户名、
// 手机号），而 localStorage 是**落盘**的——比后端那份还持久。后端的抓包最长留
// 3 小时（webhook.CaptureTTL，由 meta.defaults.sampleTtlS 下发），本地这份必须
// 同口径过期，否则界面上会一直挂着一份后端早就销毁了的载荷。
const SAMPLE_KEY = 'mantou.mroute.sample'
const SAMPLE_AT_KEY = 'mantou.mroute.sampleAt'
// meta 还没拉回来时的兜底值，和后端 CaptureTTL 一样是 3 小时。
const SAMPLE_TTL_FALLBACK_MS = 3 * 3600_000
function sampleTtlMs(): number {
  const s = meta.value?.defaults?.sampleTtlS
  return s && s > 0 ? s * 1000 : SAMPLE_TTL_FALLBACK_MS
}
const sample = ref(readSample())
// readSample 读本地那份并就地判过期。没有时间戳的是旧版本存下来的：它可能是几个月前
// 的载荷，判不出年龄就按过期处理——宁可让用户重新试运行一次，也不留一份来历不明的。
function readSample(): string {
  try {
    const body = localStorage.getItem(SAMPLE_KEY) || ''
    if (!body) return ''
    const at = Number(localStorage.getItem(SAMPLE_AT_KEY) || 0)
    if (!at || Date.now() - at >= sampleTtlMs()) {
      localStorage.removeItem(SAMPLE_KEY)
      localStorage.removeItem(SAMPLE_AT_KEY)
      return ''
    }
    return body
  } catch {
    return ''
  }
}
function setSample(v: string) {
  sample.value = v
  try {
    if (v) {
      localStorage.setItem(SAMPLE_KEY, v)
      // 时间戳跟着每次写入重置：口径和后端一致——"最后一次拿到样本之后 3 小时"。
      localStorage.setItem(SAMPLE_AT_KEY, String(Date.now()))
    } else {
      localStorage.removeItem(SAMPLE_KEY)
      localStorage.removeItem(SAMPLE_AT_KEY)
    }
  } catch {
    // 隐私模式下 localStorage 写入会抛，样本丢了不影响本次使用。
  }
  armSampleTimer()
}
// 到点主动销毁，而不是等下次进页面才判：用户可能就停在这一页对着它改模板，
// 那份载荷该消失的时候就得消失（后端那边同样是定时器主动清，见 testrun.go）。
let sampleTimer = 0
function armSampleTimer() {
  if (sampleTimer) window.clearTimeout(sampleTimer)
  sampleTimer = 0
  if (!sample.value) return
  const at = Number(localStorage.getItem(SAMPLE_AT_KEY) || 0) || Date.now()
  const left = at + sampleTtlMs() - Date.now()
  if (left <= 0) {
    dropSample()
    return
  }
  sampleTimer = window.setTimeout(dropSample, left)
}
function dropSample() {
  if (!sample.value) return
  setSample('')
  // 输入框忽然空掉会让人以为出了故障，说一句。
  ElMessage.info(t('mroute.sampleGone'))
}
armSampleTimer()

function emptyReceiver(): WebhookReceiver {
  return {
    name: '',
    enabled: true,
    note: '',
    path: '',
    authType: 'none',
    authHeader: '',
    token: '',
    rateLimit: 60,
    maxBodyKb: meta.value?.defaults?.bodyKb || 256,
    ipFilter: false,
    ipFilterMode: 'deny',
    allowIps: [],
    denyIps: [],
    keywordFilter: false,
    keywords: [],
    keywordMode: 'any',
    rootPath: 'body',
    sourceType: 'auto',
    pairSep: '',
    kvSep: '',
    mappings: [],
    rules: [],
    defaultTargets: [],
  }
}
function emptyTarget(): NotifyTarget {
  return {
    name: '',
    enabled: true,
    type: 'dingtalk',
    note: '',
    url: '',
    secret: '',
    method: 'POST',
    contentType: 'application/json',
    headers: {},
    bodyTemplate: '',
    atMobiles: [],
    atAll: false,
    timeoutSec: meta.value?.defaults?.timeout || 10,
    retry: meta.value?.defaults?.retry ?? 2,
  }
}
function emptyTemplate(): MessageTemplate {
  return { name: '', note: '', format: 'text', title: '', body: '', titleStyle: 'h3' }
}

const recv = useResource<WebhookReceiver>('webhook/receivers', emptyReceiver, { afterChange: loadStatus })
const targ = useResource<NotifyTarget>('webhook/targets', emptyTarget, { afterChange: loadStatus })
const tmpl = useResource<MessageTemplate>('webhook/templates', emptyTemplate)

// ---- 模块监听设置 ----
const serverVisible = ref(false)
const savingServer = ref(false)
const certs = ref<CertOption[]>([])
// 原文留存额度的取值范围。与后端 config.DefaultSourceRetainMB / MaxSourceRetainMB 对应；
// 后端越界会夹住，这里设成同样的范围只是别让用户先填出一个会被改掉的数。
const SOURCE_RETAIN_DEFAULT = 2
const SOURCE_RETAIN_MAX = 3
const server = reactive<WebhookServer>({
  created: false,
  enabled: false,
  listen: '',
  port: 25667,
  domain: '',
  note: '',
  sourceRetainMb: 2,
  https: { enabled: false, certId: '' },
})

// 模块设置那一页是**一行**表格：这个模块只有一个入站监听，多行会让人以为能加第二个。
// 用表格而不是一堆键值对，是为了和页面上其余几页长得一样（同一套列 → 同一处「操作」）。
// 未创建时这张表是**空的**（配一个"新建"按钮）：那一行代表"这台机器上有一个入站监听"，
// 没建起来就不该有行——否则删除之后那一行还在，用户不知道自己到底删掉了什么。
const serverRows = computed(() => (server.created ? [server] : []))

// 监听地址：0.0.0.0 表示所有网卡。与 Web 服务共用端口时这条监听归 Web 服务持有，
// 地址仍是同一个，谁绑的写在上方状态栏的说明里。
const listenAddr = computed(() => `${server.listen || '0.0.0.0'}:${server.port || 0}`)

// 80 / 443 是浏览器与第三方系统的默认端口，面板 / Web 服务 / 消息路由都可能要，
// 一个端口只能被一个进程绑定——此时域名是唯一的分流依据，后端会强制要求填。
const publicPort = computed(() => server.port === 80 || server.port === 443)

function applyServer(s: Partial<WebhookServer>) {
  server.created = !!s.created
  server.enabled = !!s.enabled
  server.listen = s.listen || ''
  server.port = s.port || meta.value?.defaults?.port || 25667
  server.domain = s.domain || s.https?.domain || '' // 旧配置的域名在 https 下
  server.note = s.note || ''
  // 留存额度：0 是「不留存」这个有效取值，不能用 || 兜——那会把用户选的 0 换成 2。
  server.sourceRetainMb = typeof s.sourceRetainMb === 'number' ? s.sourceRetainMb : SOURCE_RETAIN_DEFAULT
  server.https.enabled = !!s.https?.enabled
  server.https.certId = s.https?.certId || ''
}

async function openServer() {
  try {
    applyServer(await webhookActions.getServer())
  } catch {
    /* 取不到就用默认值，用户仍可保存 */
  }
  await loadCerts()
  serverVisible.value = true
}

// openCreateServer 「新建」：模块那一行还不存在时走这里。用的是同一个弹窗——
// 要填的东西一模一样（端口、域名、HTTPS），另做一个"创建向导"只会多一份要维护的表单。
// 保存即创建（后端 PUT /webhook/server 把 created 置真，并给路径为空的接收器补上随机路径）。
async function openCreateServer() {
  applyServer({ port: meta.value?.defaults?.port, enabled: true })
  await loadCerts()
  serverVisible.value = true
}

// 证书下拉框跟着 /settings 一起下发（同设置页的 certOptions），
// 只在打开这个弹窗时才取：/certs 会把每张证书的 ACME 状态机都算一遍。
async function loadCerts() {
  try {
    const s: any = await api.get('/settings')
    if (Array.isArray(s?.certs)) certs.value = s.certs as CertOption[]
  } catch {
    /* ignore */
  }
}

// removeServer 删掉模块那一行：停止监听、抹掉端口 / 域名 / 证书，这一页回到"未创建"。
//
// 接收器、模板、通知目标、规则一律不动——用户删的是这台机器上的入站监听，
// 不是他配了半天的路由。但删掉之后接收器就没有可访问的地址了，所以后端要求
// 先把启用中的接收器停掉，拒绝时会点名是哪几个（那句话直接摆给用户看）。
const deletingServer = ref(false)
async function removeServer() {
  try {
    await ElMessageBox.confirm(t('mroute.srv.deleteConfirm'), '', {
      confirmButtonText: t('common.delete'),
      cancelButtonText: t('common.cancel'),
      type: 'warning',
    })
  } catch {
    return
  }
  deletingServer.value = true
  try {
    await webhookActions.deleteServer()
    ElMessage.success(t('mroute.srv.deleted'))
    await reloadServer()
    await loadStatus()
    // 接收器列表要跟着重读：模块没了之后后端会把它们一律按停用处理（normalizeWebhook），
    // 页面上那几个开关必须如实变灰，否则用户会以为它们还在收消息。
    await recv.load()
  } catch (e: any) {
    ElMessage.error(e?.message || t('common.saveFailed'))
  } finally {
    deletingServer.value = false
  }
}

// reloadServer 弹窗关掉之后把已存的那份读回来，接在 @closed 上（取消、右上角叉、ESC 都会走到）。
// 必须回读：这一行表格与「接收器」页的入站地址都直接绑在 server 上，保存被拒
//（例如域名写了通配符）之后留着那个值，列表里会显示一个根本没存下来的域名，
// 接收器地址也会跟着变成一条不存在的 URL。保存成功时同样要读——监听地址由后端决定
//（共用端口时不是本模块自己绑的）。
async function reloadServer() {
  try {
    applyServer(await webhookActions.getServer())
  } catch {
    /* 取不到就保持现状，下次打开还会再读一次 */
  }
}

async function saveServer() {
  savingServer.value = true
  try {
    const res = await webhookActions.saveServer({
      enabled: server.enabled,
      port: server.port,
      domain: server.domain,
      note: server.note,
      sourceRetainMb: server.sourceRetainMb,
      https: { enabled: server.https.enabled, certId: server.https.certId },
    })
    serverVisible.value = false
    ElMessage.success(t('msg.saveOk'))
    // 后端保存后同步重载了监听，直接把它回来的状态摆出来，省一次手动刷新。
    if (res?.message) {
      if (res.healthy === false) ElMessage.warning(res.message)
      else ElMessage.info(res.message)
    }
    await loadStatus()
    // 监听地址等由后端决定的字段在弹窗关掉后由 @closed → reloadServer 统一读回。
  } catch (e: any) {
    ElMessage.error(e?.message || t('common.saveFailed'))
  } finally {
    savingServer.value = false
  }
}

// 列表里那个开关：只把 enabled 发过去（POST /webhook/server/toggle），端口 / 域名 / HTTPS
// 一律沿用已存的那份——和接收器、通知目标的开关同一种端点，也就不存在"页面手里的旧值
// 顺手把别处刚改的设置盖回去"。
// 后端在启用这一侧照样跑完整校验（80 / 443 上必须有域名、HTTPS 必须选证书……），
// 被拒就把开关拨回去，并把后端那句话直接摆出来——那是照着改的依据。
const togglingServer = ref(false)
async function toggleServer(next: boolean) {
  togglingServer.value = true
  try {
    const res = await webhookActions.toggleServer(next)
    if (res?.message) {
      if (res.healthy === false) ElMessage.warning(res.message)
      else ElMessage.info(res.message)
    }
    await loadStatus()
    try {
      applyServer(await webhookActions.getServer())
    } catch {
      /* ignore */
    }
  } catch (e: any) {
    server.enabled = !next
    ElMessage.error(e?.message || t('common.saveFailed'))
  } finally {
    togglingServer.value = false
  }
}

// ---- 状态 / 历史 ----
async function loadStatus() {
  try {
    status.value = await webhookActions.status(true)
  } catch {
    /* ignore */
  }
}

// histSeq 只解决一件事：两个筛选框连着改（或改完立刻点刷新）会同时发出两个请求，
// 而先发的那个可能后到，结果是下拉框写着"拒收"、表格里却是上一次的全量数据。
// 每次发起自增，回来时对不上号就丢掉——不是超时，是这份结果已经过期了。
let histSeq = 0

async function loadHistory() {
  const seq = ++histSeq
  historyLoading.value = true
  try {
    const list = await webhookActions.history({
      receiverId: historyFilter.value || undefined,
      event: historyEvent.value || undefined,
      limit: HISTORY_MAX,
    })
    if (seq !== histSeq) return
    history.value = list
    historyPage.value = 1
  } catch (e: any) {
    if (seq !== histSeq) return
    ElMessage.error(e?.message || t('common.loadFailed'))
  } finally {
    if (seq === histSeq) historyLoading.value = false
  }
}

// ---- 入站原文 ----
//
// 被拒收与被丢弃的记录，原因只是一句结论（"没命中关键词" / "没有规则命中"）。
// 光看结论查不下去：到底对方发了什么？所以后端把当时收到的原文留了一份在内存里
// （见后端 source.go），这里按需取，不跟着历史列表一起拉——一条原文可能有几十 KB，
// 列表里几百行全带上就是每次刷新都传一遍。
const sourceVisible = ref(false)
const sourceLoading = ref(false)
const sourceRec = ref<SourceRecord | null>(null)
// sourceGone 原文已被新记录顶掉。必须与"还没加载完"分开：一片空白会被当成界面坏了。
const sourceGone = ref(false)
const sourceStats = ref<SourceStats | null>(null)

// srcSeq 与 histSeq 同理：关掉弹窗立刻点另一行，两个请求都在路上，
// 先发的后到就会把内容换成上一条的原文——而弹窗上没有任何地方能看出这件事。
let srcSeq = 0

async function openSource(row: HistoryEntry) {
  if (!row.sourceId) return
  const seq = ++srcSeq
  sourceVisible.value = true
  sourceLoading.value = true
  sourceRec.value = null
  sourceGone.value = false
  try {
    const res = await webhookActions.source(row.sourceId)
    if (seq !== srcSeq) return
    if (res.found && res.record) {
      sourceRec.value = res.record
    } else {
      sourceGone.value = true
    }
  } catch (e: any) {
    if (seq !== srcSeq) return
    ElMessage.error(e?.message || t('common.loadFailed'))
    sourceVisible.value = false
    return
  } finally {
    if (seq === srcSeq) sourceLoading.value = false
  }
  // 用量顺手取一次：用户看到"已不在内存里"时，紧接着要问的就是"那能留多少"。
  // 单独一个 try：它只喂页脚那一行字，失败了不该把已经取到的原文一起关掉。
  try {
    const st = await webhookActions.sourceStats(true)
    if (seq === srcSeq) sourceStats.value = st
  } catch {
    /* 页脚少一行字而已 */
  }
}

// clearSources 清空全部留存的原文。
//
// 要一次确认：这份数据只在内存里、不落盘，清掉就没了，而正在查问题的人可能
// 还要回头看前几条。清完把当前这条也一并置成"已不在内存里"——它刚刚被清掉了，
// 弹窗上还摆着内容会让人以为没生效。
const clearingSources = ref(false)
async function clearSources() {
  try {
    await ElMessageBox.confirm(t('mroute.hist.clearSourcesConfirm'), '', {
      confirmButtonText: t('mroute.hist.clearSources'),
      cancelButtonText: t('common.cancel'),
      type: 'warning',
    })
  } catch {
    return
  }
  clearingSources.value = true
  try {
    const res = await webhookActions.clearSources()
    ElMessage.success(t('mroute.hist.clearSourcesOk', { n: res?.cleared ?? 0 }))
    sourceRec.value = null
    sourceGone.value = true
    // 用量那一行要跟着归零：它是用户判断"清干净了没有"的唯一依据。
    try {
      sourceStats.value = await webhookActions.sourceStats(true)
    } catch {
      sourceStats.value = null
    }
    // 历史列表不动：那些「来源」链接还在，点进去会说"已不在内存里"——
    // 与被新记录顶掉之后完全一样的说法，界面上早就有这一条路。
    // 抹掉链接得改历史记录本身（另一个环、还会落盘），代价与收益不成比例。
  } catch (e: any) {
    ElMessage.error(e?.message || t('common.saveFailed'))
  } finally {
    clearingSources.value = false
  }
}

// 请求头按名字排序显示：map 的遍历顺序每次都可能不同，而用户会前后两次点开对照着看。
const sourceHeaders = computed(() => {
  const h = sourceRec.value?.headers || {}
  return Object.keys(h)
    .sort()
    .map((k) => ({ k, v: h[k] }))
})

// 字节数说成人话的 fmtBytes 在 useResource 里（试运行面板也要用同一个口径）。

// 入站地址前缀：启用 HTTPS 后必须用配置的域名（模块此时没有明文回落，
// 用 location.hostname 拼出来的地址在证书上对不上），否则用当前访问的主机名。
const baseUrl = computed(() => {
  const port = server.port || meta.value?.defaults?.port || 25667
  if (server.https.enabled) {
    const host = server.domain || location.hostname
    return port === 443 ? `https://${host}` : `https://${host}:${port}`
  }
  // 没开 HTTPS 也可能填了域名（共用 80 端口时靠它分流），有就用它——
  // 那才是第三方系统真正要访问的主机名。
  const host = server.domain || location.hostname
  return port === 80 ? `http://${host}` : `http://${host}:${port}`
})

// ---- 接收器动作 ----
const dryVisible = ref(false)
const dryReceiver = ref<WebhookReceiver | null>(null)

// ---- 实时试运行 ----
//
// 状态在后端内存里，前端只轮询。轮询而不是 SSE / WebSocket：这条通道只在
// 用户盯着这个页面的那几分钟里活着，两秒一次的 GET 比为它维护一条长连接简单得多，
// 也不必处理断线重连（面板本身就在同一个进程里）。
//
// 只在页面处于前台且**确实有接收器在试运行**时才轮询：试运行期间这个接收器的消息
// 不会真实转发，一个忘了关的试运行是要付代价的，所以它的状态必须一直是最新的；
// 但没人在试运行时，这个页面不该每两秒打一次接口。
const TESTRUN_POLL_MS = 2000
const testRuns = ref<Record<string, TestRunState>>({})
const testRunBusy = ref<Record<string, boolean>>({})
let pollTimer: number | undefined

function isTesting(id?: string): boolean {
  return !!(id && testRuns.value[id]?.running)
}
const anyTesting = computed(() => Object.values(testRuns.value).some((s) => s.running))

async function pollTestRun(id: string, silent = true) {
  try {
    const st = await webhookActions.testRunState(id, silent)
    testRuns.value = { ...testRuns.value, [id]: st }
    return st
  } catch {
    return undefined
  }
}

function schedulePoll() {
  if (pollTimer !== undefined) return
  pollTimer = window.setInterval(async () => {
    const ids = Object.keys(testRuns.value).filter((id) => testRuns.value[id]?.running)
    if (!ids.length) {
      stopPoll()
      return
    }
    const before = ids.filter((id) => testRuns.value[id]?.running)
    await Promise.all(ids.map((id) => pollTestRun(id)))
    // 超时自停要主动告诉用户：他以为消息还被拦着，实际上已经恢复转发了。
    for (const id of before) {
      const st = testRuns.value[id]
      if (st && !st.running && st.stoppedReason) ElMessage.warning(st.stoppedReason)
    }
  }, TESTRUN_POLL_MS)
}

function stopPoll() {
  if (pollTimer !== undefined) {
    clearInterval(pollTimer)
    pollTimer = undefined
  }
}

async function startTestRun(row: WebhookReceiver) {
  if (!row.id) return
  testRunBusy.value = { ...testRunBusy.value, [row.id]: true }
  try {
    const st = await webhookActions.testRunStart(row.id)
    testRuns.value = { ...testRuns.value, [row.id]: st }
    schedulePoll()
  } catch (e: any) {
    ElMessage.error(e?.message || t('common.saveFailed'))
  } finally {
    const next = { ...testRunBusy.value }
    delete next[row.id]
    testRunBusy.value = next
  }
}

async function stopTestRun(row: WebhookReceiver) {
  if (!row.id) return
  testRunBusy.value = { ...testRunBusy.value, [row.id]: true }
  try {
    const st = await webhookActions.testRunStop(row.id)
    testRuns.value = { ...testRuns.value, [row.id]: st }
    if (!anyTesting.value) stopPoll()
    ElMessage.success(t('mroute.dry.stopped'))
  } catch (e: any) {
    ElMessage.error(e?.message || t('common.saveFailed'))
  } finally {
    const next = { ...testRunBusy.value }
    delete next[row.id]
    testRunBusy.value = next
  }
}

// urlPath 地址里"路径"那一截，带前导斜杠。列表分两行显示时用它。
function urlPath(row: WebhookReceiver): string {
  return `/${row.path || ''}`
}

// fullUrl 接收器的完整入站地址。第三方系统里要填的就是这一整串，
// 让用户自己把前缀和路径拼起来是最容易出错的一步（少一个斜杠就是 404）。
//
// 由 baseUrl + urlPath 拼出来，与列表里分两行摆的正是同两截：
// 各算一遍的话，改了其中一处就会出现"看到的地址"和"复制到的地址"不一样。
function fullUrl(row: WebhookReceiver): string {
  return baseUrl.value + urlPath(row)
}

async function copyUrl(row: WebhookReceiver) {
  const text = fullUrl(row)
  try {
    // 面板可能跑在 http 上（clipboard API 只在安全上下文可用），
    // 所以留一条 textarea + execCommand 的退路：复制不成功就等于这个按钮不存在。
    if (navigator.clipboard && window.isSecureContext) {
      await navigator.clipboard.writeText(text)
    } else {
      const ta = document.createElement('textarea')
      ta.value = text
      ta.style.position = 'fixed'
      ta.style.opacity = '0'
      document.body.appendChild(ta)
      ta.select()
      const ok = document.execCommand('copy')
      document.body.removeChild(ta)
      if (!ok) throw new Error('copy failed')
    }
    ElMessage.success(t('mroute.copied'))
  } catch {
    ElMessage.warning(t('mroute.copyFail'))
  }
}

async function openEditReceiver(row: WebhookReceiver) {
  recv.openEdit(row)
  // 顺手把试运行状态拉一次：那条抓包就是样本载荷，弹窗一开就要能用上最新的一条。
  if (row.id) await pollTestRun(row.id)
}

async function newPath() {
  try {
    const { path } = await webhookActions.newPath()
    ;(recv.editing.value as WebhookReceiver).path = path
  } catch (e: any) {
    ElMessage.error(e?.message || t('common.loadFailed'))
  }
}

async function openDryRun(row: WebhookReceiver) {
  dryReceiver.value = row
  if (row.id) await pollTestRun(row.id)
  dryVisible.value = true
}

// refreshTestRuns 把每个接收器的试运行状态拉一遍。
// 进入页面时必须做一次：试运行是后端内存里的状态，用户可能是在另一个标签页
// （甚至上一次会话里）开的，页面上必须如实显示"这个接收器现在不会转发消息"。
async function refreshTestRuns() {
  const ids = recv.list.value.map((r) => r.id).filter(Boolean) as string[]
  if (!ids.length) return
  const states = await Promise.all(ids.map((id) => webhookActions.testRunState(id, true).catch(() => undefined)))
  const next: Record<string, TestRunState> = {}
  ids.forEach((id, i) => {
    const st = states[i]
    if (st) next[id] = st
  })
  testRuns.value = next
  if (anyTesting.value) schedulePoll()
}

// 实时试运行的开关只留在「试运行」面板与接收器弹窗里（列表上不再有）：
// 它与样本试运行是同一件事的两种入料方式——一种等真实消息，一种贴一段样本，
// 面板里两者挨着摆，选哪种一目了然；列表上再放一个开关只会让人以为是两个功能。

// ---- 通知目标动作 ----
// 测试发送不直接发：先弹一个手填 txt / markdown 的框（见 TargetTestDialog），
// 用户要看的是"这条消息在钉钉里长什么样"，而不是一句固定的"测试消息"通不通。
const testVisible = ref(false)
const testRow = ref<NotifyTarget | null>(null)
const testSending = ref(false)
function openTest(row: NotifyTarget) {
  if (!row.id) return
  testRow.value = row
  testVisible.value = true
}
async function sendTest(payload: { message: string; format: string; title: string; titleStyle: string }) {
  const id = testRow.value?.id
  if (!id) return
  testSending.value = true
  try {
    const res = await webhookActions.testTarget(id, payload)
    ElMessage.success(t('mroute.target.testOk', { ms: res.costMs }))
    // 弹窗留着不关：调样式的人要改一句再发一次，关掉等于每次都重填。
    await targ.load({ silent: true })
  } catch (e: any) {
    ElMessage.error(e?.message || t('mroute.target.testFail'))
  } finally {
    testSending.value = false
  }
}

// ---- 展示辅助 ----
function targetNames(ids: string[]): string {
  if (!ids?.length) return '—'
  return ids.map((id) => targ.list.value.find((x) => x.id === id)?.name || id).join('、')
}
function templateName(id: string): string {
  return tmpl.list.value.find((x) => x.id === id)?.name || id || '—'
}
function typeLabel(tp: string): string {
  const key = `mroute.target.type.${tp}`
  const s = t(key)
  return s === key ? tp : s
}
function eventLabel(e: string): string {
  const key = `mroute.event.${e}`
  const s = t(key)
  return s === key ? e : s
}
// 键的顺序就是筛选下拉框的顺序（见 EVENT_OPTIONS），照一条消息的经历排：
// 收到 → 被拒 / 被丢 / 出错 → 发出 → 重试 → 失败。
const EVENT_TAG: Record<string, string> = {
  received: 'info',
  rejected: 'warning',
  dropped: 'danger',
  error: 'danger',
  sent: 'success',
  retrying: 'warning',
  failed: 'danger',
}
// 筛选项直接取自 EVENT_TAG：分成两份清单的话，后端加一种事件时总会漏掉其中一份。
const EVENT_OPTIONS = Object.keys(EVENT_TAG)
// 停用的模板 / 目标被规则引用时要能看出来，否则规则看着正常却发不出去。
//
// 多分支的规则必须逐个分支查：那种规则的模板与目标都住在分支里，规则本体的两个字段
// 不参与运行（见 config.WebhookRule.Branches）。只查规则本体的话，一条分支引用了
// 已删除模板的规则会显示"一切正常"，而它上线后每条消息都会失败。
function missingRefs(row: WebhookReceiver): string[] {
  const out: string[] = []
  for (const ru of row.rules || []) {
    const label = ru.name || ru.id
    const outputs = (ru.branches || []).length
      ? (ru.branches || []).map((b) => ({
          // 分支名带进去：一条规则有好几个出口时，只说规则名等于让用户自己去挨个翻。
          label: `${label} / ${b.name || ''}`,
          templateRef: b.templateRef,
          targets: b.targets,
        }))
      : [{ label, templateRef: ru.templateRef, targets: ru.targets }]
    for (const o of outputs) {
      if (o.templateRef && !tmpl.list.value.some((x) => x.id === o.templateRef)) {
        out.push(`${o.label} → ${t('mroute.recv.template')}`)
      }
      for (const id of o.targets || []) {
        const hit = targ.list.value.find((x) => x.id === id)
        if (!hit) out.push(`${o.label} → ${id}`)
        else if (!hit.enabled) out.push(`${o.label} → ${hit.name}`)
      }
    }
  }
  return out
}

// ---- 发送规则 ----
//
// 规则在配置里住在接收器下面，但用户想的是"一条规则"：哪条规则把哪种消息发到哪个群。
// 所以这一页是一张跨接收器的扁平表，增删改各自打接收器下的子接口（见 api_webhook_rules.go）。
// 列表顺序（接收器物理序 → 优先级）由后端排好，直接照着渲染即可。
const rules = ref<WebhookRuleItem[]>([])
const rulesLoading = ref(false)
async function loadRules(opts?: { silent?: boolean }) {
  const silent = opts?.silent === true
  if (!silent) rulesLoading.value = true
  try {
    rules.value = await rulesApi.list(silent)
  } catch (e: any) {
    if (!silent) ElMessage.error(e?.message || t('common.loadFailed'))
  } finally {
    if (!silent) rulesLoading.value = false
  }
}

// 规则编辑草稿：规则本体 + 它归哪个接收器。receiverId 可改（编辑弹窗里那个下拉框），
// 新建时默认落到第一个接收器上——没有接收器时「新建」按钮本就禁着（规则得有入口才有意义）。
const ruleVisible = ref(false)
const ruleIsNew = ref(true)
const ruleSaving = ref(false)
const ruleFrom = ref('') // 打开编辑时这条规则原本属于哪个接收器（保存要按它定位）
const ruleModel = ref<WebhookRule & { receiverId: string }>(emptyRule())
function emptyRule(): WebhookRule & { receiverId: string } {
  return {
    name: '',
    enabled: true,
    priority: 0,
    match: 'all',
    conditions: [],
    templateRef: '',
    targets: [],
    continue: false,
    receiverId: recv.list.value[0]?.id || '',
  }
}
function openCreateRule() {
  ruleModel.value = emptyRule()
  ruleFrom.value = ruleModel.value.receiverId
  ruleIsNew.value = true
  ruleVisible.value = true
}
async function openEditRule(row: WebhookRuleItem) {
  const { receiverId, receiverName, receiverEnabled, ...rule } = row
  ruleModel.value = { ...JSON.parse(JSON.stringify(rule)), receiverId }
  ruleFrom.value = receiverId
  ruleIsNew.value = false
  ruleVisible.value = true
  // 顺手把这个接收器的试运行状态拉一次：右栏字段树按它的解析设置解样本载荷。
  if (receiverId) await pollTestRun(receiverId)
}
// openCopyRule 以某一条规则为底子新建一条：打开的是**新建**弹窗，保存时才落库，
// 所以用户可以先改完再决定要不要留。id 必须去掉，否则保存会走更新、把源那条覆盖掉。
//
// 规则本身不含脱敏字段（令牌在接收器上、地址在通知目标上），整条深拷贝是安全的——
// 这也是「复制」只给模板和规则、不给接收器与目标的原因（见 useResource.openCopy）。
//
// 为什么规则需要它：一条规则只装得下「一组条件 → 一个模板 → 一批目标」。
// 要表达"满足 X 用模板 A 发给 B、满足 Y 用模板 C 发给 D"，就得是两条规则；
// 而这两条通常只差条件和模板，从头点一遍四个步骤纯属重复劳动。
async function openCopyRule(row: WebhookRuleItem) {
  const { receiverId, receiverName: _n, receiverEnabled: _e, ...rule } = row
  const copy = JSON.parse(JSON.stringify(rule)) as WebhookRule
  delete copy.id
  copy.name = t('mroute.rule.copyName', { name: rule.name || '' }).trim()
  ruleModel.value = { ...copy, receiverId }
  ruleFrom.value = receiverId
  ruleIsNew.value = true
  ruleVisible.value = true
  // 与 openEditRule 同理：右栏字段树要按这个接收器的解析设置解样本载荷。
  if (receiverId) await pollTestRun(receiverId)
}
async function saveRule() {
  const { receiverId, ...rule } = ruleModel.value
  if (!receiverId) {
    ElMessage.error(t('mroute.rule.receiverRequired'))
    return
  }
  ruleSaving.value = true
  try {
    if (ruleIsNew.value) {
      await rulesApi.create(receiverId, rule as WebhookRule)
    } else {
      // update 走原接收器的地址，body 里的 receiverId 表示"挪到那个接收器下"。
      await rulesApi.update(ruleFrom.value, (rule as WebhookRule).id!, { ...(rule as WebhookRule), receiverId })
    }
    ruleVisible.value = false
    await Promise.all([loadRules(), recv.load({ silent: true })])
    await loadStatus()
    ElMessage.success(t('msg.saveOk'))
  } catch (e: any) {
    ElMessage.error(e?.message || t('common.saveFailed'))
  } finally {
    ruleSaving.value = false
  }
}
async function toggleRule(row: WebhookRuleItem) {
  const next = row.enabled
  try {
    await rulesApi.toggle(row.receiverId, row.id, next)
    await Promise.all([loadRules({ silent: true }), recv.load({ silent: true })])
    await loadStatus()
  } catch (e: any) {
    row.enabled = !next
    ElMessage.error(e?.message || t('common.saveFailed'))
  }
}
async function removeRule(row: WebhookRuleItem) {
  try {
    await ElMessageBox.confirm(t('common.confirmDelete'), '', {
      confirmButtonText: t('common.delete'),
      cancelButtonText: t('common.cancel'),
      type: 'warning',
    })
  } catch {
    return
  }
  try {
    await rulesApi.remove(row.receiverId, row.id)
    await Promise.all([loadRules(), recv.load({ silent: true })])
    await loadStatus()
    ElMessage.success(t('common.deleted'))
  } catch (e: any) {
    ElMessage.error(e?.message || t('common.saveFailed'))
  }
}
function ruleReceiverName(row: WebhookRuleItem): string {
  return row.receiverEnabled ? row.receiverName : `${row.receiverName}（${t('common.disabled')}）`
}

onActivated(async () => {
  if (!meta.value) {
    try {
      meta.value = await webhookActions.meta()
      // 样本存活上限以后端为准（sampleTtlS），拉到之后按真值重算一次。
      armSampleTimer()
    } catch {
      /* ignore */
    }
  }
  await Promise.all([
    recv.load(),
    targ.load(),
    tmpl.load(),
    loadRules(),
    loadStatus(),
    webhookActions
      .getServer()
      .then(applyServer)
      .catch(() => undefined),
  ])
  // 全新安装（模块没开、也还没有接收器）直接落在「模块设置」上：
  // 那一页没配好之前，别的页配得再对也一条都收不到。有接收器之后就不再抢用户的页签。
  if (!server.enabled && recv.list.value.length === 0) tab.value = 'module'
  if (tab.value === 'history') await loadHistory()
  await refreshTestRuns()
})

// 离开页面就停轮询：后端的试运行不受影响（它有自己的超时），
// 但没人在看的时候不该继续每两秒打一次接口。
onDeactivated(stopPoll)
onUnmounted(() => {
  stopPoll()
  // 销毁定时器只在组件活着的时候有意义；组件没了，下次进来 readSample 会重新判过期。
  if (sampleTimer) window.clearTimeout(sampleTimer)
})

// 本页自己开的这几个弹窗在切页时一并收起（接收器 / 目标 / 模板那三个在 useResource 里）。
useCloseOnLeave(serverVisible, sourceVisible, dryVisible, testVisible, ruleVisible)
</script>

<template>
  <PageCard :title="t('mroute.title')" :subtitle="t('mroute.subtitle')">
    <template #actions>
      <div class="stat-row">
        <el-tag :type="server.enabled ? (status.healthy ? 'success' : 'danger') : 'info'" disable-transitions>
          {{ server.enabled ? (status.healthy ? t('mroute.running') : t('mroute.abnormal')) : t('mroute.stopped') }}
        </el-tag>
        <span v-if="status.message" class="mt-subtle msg">{{ status.message }}</span>
      </div>
    </template>

    <div v-if="server.enabled" class="metrics">
      <span>{{ t('mroute.mReceived') }} <b>{{ status.received ?? 0 }}</b></span>
      <span>{{ t('mroute.mRejected') }} <b>{{ status.rejected ?? 0 }}</b></span>
      <span>{{ t('mroute.mSent') }} <b>{{ status.sent ?? 0 }}</b></span>
      <span>{{ t('mroute.mFailed') }} <b>{{ status.failed ?? 0 }}</b></span>
      <span>{{ t('mroute.mPending') }} <b>{{ status.pending ?? 0 }}</b></span>
      <span v-if="(status.dropped ?? 0) + (status.sendDropped ?? 0) > 0" class="mt-danger-text">
        {{ t('mroute.mDropped') }} <b>{{ (status.dropped ?? 0) + (status.sendDropped ?? 0) }}</b>
      </span>
    </div>
    <el-alert v-else type="info" :closable="false" :title="t('mroute.disabledHint')" class="al" />

    <el-tabs v-model="tab" @tab-change="(name: any) => name === 'history' && loadHistory()">
      <!-- ========== 模块设置 ==========
           摆在最前面：这一页没配好（端口 / 域名 / HTTPS），后面三页配得再对也一条都收不到。 -->
      <el-tab-pane :label="t('mroute.moduleSettings')" name="module">
        <div class="bar">
          <!-- 未创建时这一页只有一个「新建」：这台机器上还没有入站监听，
               能做的第一件事就是把它建起来（建好接收器才谈得上启用）。 -->
          <el-button v-if="!server.created" type="primary" :icon="Plus" @click="openCreateServer">
            {{ t('common.add') }}
          </el-button>
          <span class="mt-subtle">{{ server.created ? t('mroute.moduleIntro') : t('mroute.srv.notCreated') }}</span>
        </div>
        <el-table :data="serverRows" stripe>
          <template #empty>{{ t('mroute.srv.emptyHint') }}</template>
          <el-table-column :label="t('common.status')" width="100">
            <template #default="{ row }">
              <!-- 与其他模块的列表同一种控件：开关就地生效，不用先进弹窗。
                   开着但不健康时在下面补一行红字——开关只说得清"要不要跑"，
                   说不清"跑起来了没有"（证书没选、端口被占都是这种情形）。 -->
              <el-switch v-model="row.enabled" :loading="togglingServer" @change="toggleServer" />
              <div v-if="row.enabled && status.healthy === false" class="mt-danger-text tiny">
                {{ t('mroute.abnormal') }}
              </div>
            </template>
          </el-table-column>
          <el-table-column :label="t('mroute.srv.domainCol')" min-width="170" show-overflow-tooltip>
            <template #default="{ row }">
              <span v-if="row.domain">{{ row.domain }}</span>
              <span v-else class="mt-subtle">{{ publicPort ? t('mroute.srv.domainMissing') : '—' }}</span>
            </template>
          </el-table-column>
          <el-table-column label="HTTPS" width="90">
            <template #default="{ row }">
              <el-tag :type="row.https.enabled ? 'success' : 'info'" size="small" disable-transitions>
                {{ row.https.enabled ? t('common.enabled') : t('common.disabled') }}
              </el-tag>
            </template>
          </el-table-column>
          <el-table-column :label="t('mroute.srv.addrCol')" min-width="150">
            <template #default>
              <code class="path">{{ listenAddr }}</code>
            </template>
          </el-table-column>
          <el-table-column :label="t('mroute.srv.receivedCol')" width="100">
            <template #default>{{ status.received ?? 0 }}</template>
          </el-table-column>
          <el-table-column :label="t('mroute.note')" min-width="130" show-overflow-tooltip>
            <template #default="{ row }">{{ row.note || '—' }}</template>
          </el-table-column>
          <el-table-column :label="t('common.actions')" width="170" align="right">
            <template #default>
              <el-button size="small" :icon="Setting" @click="openServer">{{ t('common.edit') }}</el-button>
              <el-button size="small" type="danger" text :loading="deletingServer" @click="removeServer">
                {{ t('common.delete') }}
              </el-button>
            </template>
          </el-table-column>
        </el-table>
      </el-tab-pane>

      <!-- ========== 接收器 ========== -->
      <el-tab-pane :label="t('mroute.tabReceivers')" name="receivers">
        <div class="bar">
          <el-button type="primary" :icon="Plus" @click="recv.openCreate()">{{ t('common.add') }}</el-button>
          <span class="mt-subtle">{{ t('mroute.recvIntro') }}</span>
        </div>
        <!-- 模块没建起来就没有监听、没有域名、没有可访问的地址：接收器可以照常配，
             但不能启用（那个绿开关会让人以为它在收消息）。这句话把出路直接写出来。 -->
        <el-alert
          v-if="!server.created"
          type="warning"
          :closable="false"
          show-icon
          :title="t('mroute.recv.needModule')"
          class="al"
        />
        <!-- 列宽预算：加了「备注」列之后各列都让出一点，务必让所有列之和留在一屏内。
             一旦超出，el-table 只能横向滚动，最右边的「操作」按钮就得先滚才点得到。 -->
        <el-table :data="recv.list.value" v-loading="recv.loading.value" stripe row-key="id">
          <el-table-column :label="t('common.status')" width="90">
            <template #default="{ row }">
              <el-switch
                v-model="row.enabled"
                :disabled="!server.created && !row.enabled"
                @change="recv.toggle(row, t('common.saveFailed'))"
              />
              <div v-if="isTesting(row.id)" class="mt-warn-text tiny">{{ t('mroute.dry.badge') }}</div>
            </template>
          </el-table-column>
          <el-table-column :label="t('common.name')" min-width="120">
            <template #default="{ row }">
              <div>{{ row.name }}</div>
              <div v-if="missingRefs(row).length" class="mt-danger-text tiny">
                {{ t('mroute.recv.badRefs', { list: missingRefs(row).join('; ') }) }}
              </div>
            </template>
          </el-table-column>
          <!-- 入站地址分两行：前缀一行、路径一行。挤在一行时 word-break 会把地址从任意
               位置折开（`https://ho` / `st:25667/ab…`），反而更难认；分行之后每行都短，
               列宽也就能让给别的列。复制出去的仍是完整地址。 -->
          <el-table-column :label="t('mroute.recv.urlCol')" min-width="150">
            <template #default="{ row }">
              <div class="url-cell">
                <div class="url-parts" :title="fullUrl(row)">
                  <code class="path origin mt-subtle">{{ baseUrl }}</code>
                  <code class="path">{{ urlPath(row) }}</code>
                </div>
                <el-button
                  :icon="CopyDocument"
                  size="small"
                  text
                  :title="t('mroute.copy')"
                  @click="copyUrl(row)"
                />
              </div>
            </template>
          </el-table-column>
          <el-table-column :label="t('mroute.recv.rulesCol')" width="70">
            <template #default="{ row }">{{ (row.rules || []).length }}</template>
          </el-table-column>
          <el-table-column :label="t('mroute.recv.lastRecv')" width="180">
            <template #default="{ row }">
              <div class="mt-cell-2row">
                <div>{{ fmtTime(row.lastReceivedAt) }}</div>
                <!-- 收下与被挡掉分两个数：混成一个的话，"累计 72 次"里可能有 70 次
                     是被限流或令牌不对挡掉的，而这两件事要查的地方完全不同。
                     没有被挡掉过就不显示后半句，免得给每一行都添一个 0。 -->
                <div class="mt-subtle tiny" :title="row.lastStatus || ''">
                  {{
                    row.rejectedCount
                      ? t('mroute.recv.countColRejected', { n: row.receivedCount || 0, r: row.rejectedCount })
                      : t('mroute.recv.countCol', { n: row.receivedCount || 0 })
                  }}
                  <template v-if="row.lastStatus"> · {{ row.lastStatus }}</template>
                </div>
              </div>
            </template>
          </el-table-column>
          <el-table-column :label="t('mroute.note')" min-width="100" show-overflow-tooltip>
            <template #default="{ row }">{{ row.note || '—' }}</template>
          </el-table-column>
          <el-table-column :label="t('common.actions')" width="190" align="right">
            <template #default="{ row }">
              <!-- 只有一个「试运行」：等真实消息还是贴一段样本，都在面板里选，
                   列表上不再重复放实时试运行的开关（那会看着像两个功能）。 -->
              <el-button size="small" type="primary" @click="openDryRun(row)">
                {{ t('mroute.dry.sampleBtn') }}
              </el-button>
              <el-button size="small" @click="openEditReceiver(row)">{{ t('common.edit') }}</el-button>
              <el-button size="small" type="danger" text @click="recv.remove(row, t('common.confirmDelete'))">
                {{ t('common.delete') }}
              </el-button>
            </template>
          </el-table-column>
        </el-table>
      </el-tab-pane>

      <!-- ========== 消息模板 ========== -->
      <el-tab-pane :label="t('mroute.tabTemplates')" name="templates">
        <div class="bar">
          <el-button type="primary" :icon="Plus" @click="tmpl.openCreate()">{{ t('common.add') }}</el-button>
          <span class="mt-subtle">{{ t('mroute.tmplIntro') }}</span>
        </div>
        <el-table :data="tmpl.list.value" v-loading="tmpl.loading.value" stripe row-key="id">
          <el-table-column :label="t('common.name')" min-width="140">
            <template #default="{ row }">{{ row.name }}</template>
          </el-table-column>
          <el-table-column :label="t('mroute.tmpl.format')" width="110">
            <template #default="{ row }">{{ row.format === 'markdown' ? 'Markdown' : t('mroute.tmpl.text') }}</template>
          </el-table-column>
          <el-table-column :label="t('mroute.tmpl.bodyCol')" min-width="200">
            <template #default="{ row }">
              <code class="excerpt">{{ (row.body || '').slice(0, 90) }}</code>
            </template>
          </el-table-column>
          <el-table-column :label="t('mroute.tmpl.updated')" width="160">
            <template #default="{ row }">{{ fmtTime(row.updated) }}</template>
          </el-table-column>
          <el-table-column :label="t('mroute.note')" min-width="110" show-overflow-tooltip>
            <template #default="{ row }">{{ row.note || '—' }}</template>
          </el-table-column>
          <el-table-column :label="t('common.actions')" width="200" align="right">
            <template #default="{ row }">
              <el-button size="small" @click="tmpl.openEdit(row)">{{ t('common.edit') }}</el-button>
              <!-- 复制只给消息模板和发送规则：这两样没有脱敏字段。接收器的令牌、通知目标的地址
                   读回来是 ****** 占位符，复制出来的那条会把占位符当真值存下去（见 openCopy）。 -->
              <el-button
                size="small"
                @click="tmpl.openCopy(row, (r) => t('mroute.tmpl.copyName', { name: r.name }))"
              >
                {{ t('mroute.tmpl.duplicate') }}
              </el-button>
              <el-button size="small" type="danger" text @click="tmpl.remove(row, t('common.confirmDelete'))">
                {{ t('common.delete') }}
              </el-button>
            </template>
          </el-table-column>
        </el-table>
      </el-tab-pane>

      <!-- ========== 通知目标 ========== -->
      <el-tab-pane :label="t('mroute.tabTargets')" name="targets">
        <div class="bar">
          <el-button type="primary" :icon="Plus" @click="targ.openCreate()">{{ t('common.add') }}</el-button>
          <span class="mt-subtle">{{ t('mroute.targetIntro') }}</span>
        </div>
        <!-- 各列宽度之和必须留在一屏之内：多一列就多一份宽度，超出后 el-table 只能横向滚
             （而横向滚动条几乎没人会去找），最右边的「操作」按钮就点不到了。
             加「备注」这一列时把左边几列各让出一点，正是为此。 -->
        <el-table :data="targ.list.value" v-loading="targ.loading.value" stripe row-key="id">
          <el-table-column :label="t('common.status')" width="80">
            <template #default="{ row }">
              <el-switch v-model="row.enabled" @change="targ.toggle(row, t('common.saveFailed'))" />
            </template>
          </el-table-column>
          <el-table-column :label="t('common.name')" min-width="130" show-overflow-tooltip>
            <template #default="{ row }">{{ row.name }}</template>
          </el-table-column>
          <el-table-column :label="t('mroute.target.type.label')" width="110">
            <template #default="{ row }">{{ typeLabel(row.type) }}</template>
          </el-table-column>
          <el-table-column :label="t('mroute.target.lastSent')" min-width="160">
            <template #default="{ row }">
              <div>{{ fmtTime(row.lastSentAt) }}</div>
              <div class="mt-subtle tiny">
                {{ t('mroute.target.counts', { sent: row.sentCount || 0, fail: row.failCount || 0 }) }}
                <template v-if="row.lastStatus"> · {{ row.lastStatus }}</template>
              </div>
            </template>
          </el-table-column>
          <!-- 备注独占一列（而不是缀在名称下面）：目标名往往是"钉钉运维群"这类短名，
               真正说明"这个群是干什么的"是备注，独立一列才有宽度显示。
               太长时截断并挂 tooltip，不让它把这一行撑高。 -->
          <el-table-column :label="t('mroute.note')" min-width="130" show-overflow-tooltip>
            <template #default="{ row }">
              <span v-if="row.note">{{ row.note }}</span>
              <span v-else class="mt-subtle">—</span>
            </template>
          </el-table-column>
          <el-table-column :label="t('common.actions')" width="200" align="right">
            <template #default="{ row }">
              <el-button size="small" @click="openTest(row)">
                {{ t('mroute.target.test') }}
              </el-button>
              <el-button size="small" @click="targ.openEdit(row)">{{ t('common.edit') }}</el-button>
              <el-button size="small" type="danger" text @click="targ.remove(row, t('common.confirmDelete'))">
                {{ t('common.delete') }}
              </el-button>
            </template>
          </el-table-column>
        </el-table>
      </el-tab-pane>

      <!-- ========== 发送规则 ========== -->
      <el-tab-pane :label="t('mroute.tabRules')" name="rules">
        <div class="bar">
          <el-button
            type="primary"
            :icon="Plus"
            :disabled="!recv.list.value.length"
            @click="openCreateRule"
          >
            {{ t('common.add') }}
          </el-button>
          <span class="mt-subtle">{{ recv.list.value.length ? t('mroute.rulesIntro') : t('mroute.rulesNoRecv') }}</span>
        </div>
        <el-table :data="rules" v-loading="rulesLoading" stripe row-key="id">
          <template #empty>{{ t('mroute.rulesEmpty') }}</template>
          <el-table-column :label="t('common.status')" width="90">
            <template #default="{ row }">
              <el-switch v-model="row.enabled" @change="toggleRule(row)" />
              <!-- 规则开着，但它所在的接收器停用了：此刻这条规则不会被执行，得说出来。 -->
              <div v-if="row.enabled && !row.receiverEnabled" class="mt-warn-text tiny">
                {{ t('mroute.rule.recvOff') }}
              </div>
            </template>
          </el-table-column>
          <el-table-column :label="t('mroute.rule.priority')" width="80">
            <template #default="{ row }">{{ row.priority }}</template>
          </el-table-column>
          <el-table-column :label="t('common.name')" min-width="120" show-overflow-tooltip>
            <template #default="{ row }">
              {{ row.name || '—' }}
              <!-- 多分支的规则在别的列里长得和单输出很不一样（模板/目标是一串），
                   先在名字旁边说明白它是几个出口，那几列才读得懂。 -->
              <el-tag
                v-if="(row.branches || []).length"
                size="small"
                type="success"
                effect="plain"
                disable-transitions
                class="b-tag"
              >
                {{ t('mroute.rule.branchCount', { n: row.branches.length }) }}
              </el-tag>
              <el-tag
                v-if="(row.branches || []).length && row.firstBranchOnly"
                size="small"
                type="info"
                effect="plain"
                disable-transitions
                class="b-tag"
              >
                {{ t('mroute.rule.firstOnlyTag') }}
              </el-tag>
            </template>
          </el-table-column>
          <el-table-column :label="t('mroute.tabReceivers')" min-width="110" show-overflow-tooltip>
            <template #default="{ row }">{{ ruleReceiverName(row) }}</template>
          </el-table-column>
          <el-table-column :label="t('mroute.recv.conditions')" width="80">
            <template #default="{ row }">
              <span v-if="(row.conditions || []).length">{{ (row.conditions || []).length }}</span>
              <!-- 没有条件 = 永远命中，是一条兜底规则；用文字说清楚，别让人以为漏配了。 -->
              <span v-else class="mt-subtle">{{ t('mroute.rule.condAny') }}</span>
            </template>
          </el-table-column>
          <!-- 多分支的规则在这两列里不能照着 templateRef / targets 念：那两个字段在分支模式下
               根本不参与运行（见 config.WebhookRule.Branches），照念等于告诉用户一个假答案。
               改成把每个分支列出来，一眼看得到"哪个分支用哪个模板发给谁"。 -->
          <el-table-column :label="t('mroute.recv.template')" min-width="110" show-overflow-tooltip>
            <template #default="{ row }">
              <template v-if="(row.branches || []).length">
                <div v-for="(b, i) in row.branches" :key="i" class="tiny-line">
                  {{ templateName(b.templateRef) }}
                </div>
              </template>
              <span v-else>{{ templateName(row.templateRef) }}</span>
            </template>
          </el-table-column>
          <el-table-column :label="t('mroute.rule.targets')" min-width="130" show-overflow-tooltip>
            <template #default="{ row }">
              <template v-if="(row.branches || []).length">
                <div v-for="(b, i) in row.branches" :key="i" class="tiny-line">
                  <span class="b-chip">{{ b.name }}</span>
                  {{ (b.targets || []).length ? targetNames(b.targets) : t('mroute.rule.targetsFallback') }}
                </div>
              </template>
              <template v-else>
                <span v-if="(row.targets || []).length">{{ targetNames(row.targets) }}</span>
                <span v-else class="mt-subtle">{{ t('mroute.rule.targetsFallback') }}</span>
              </template>
            </template>
          </el-table-column>
          <el-table-column :label="t('common.actions')" width="210" align="right">
            <template #default="{ row }">
              <el-button size="small" @click="openEditRule(row)">{{ t('common.edit') }}</el-button>
              <!-- 复制：一条规则只装得下「一组条件 → 一个模板 → 一批目标」，多分支只能拆成多条，
                   而它们往往只差条件和模板。规则里没有脱敏字段，整条拷贝是安全的（见 openCopyRule）。 -->
              <el-tooltip :content="t('mroute.rule.copyHint')" placement="top" :show-after="400">
                <el-button size="small" @click="openCopyRule(row)">
                  {{ t('mroute.rule.duplicate') }}
                </el-button>
              </el-tooltip>
              <el-button size="small" type="danger" text @click="removeRule(row)">
                {{ t('common.delete') }}
              </el-button>
            </template>
          </el-table-column>
        </el-table>
      </el-tab-pane>

      <!-- ========== 执行历史 ========== -->
      <el-tab-pane :label="t('mroute.tabHistory')" name="history">
        <div class="bar">
          <el-select
            v-model="historyFilter"
            clearable
            :placeholder="t('mroute.hist.allReceivers')"
            style="width: 220px"
            @change="loadHistory"
          >
            <el-option v-for="rc in recv.list.value" :key="rc.id" :label="rc.name" :value="rc.id!" />
          </el-select>
          <el-select
            v-model="historyEvent"
            clearable
            :placeholder="t('mroute.hist.allEvents')"
            style="width: 150px"
            @change="loadHistory"
          >
            <el-option v-for="ev in EVENT_OPTIONS" :key="ev" :label="eventLabel(ev)" :value="ev" />
          </el-select>
          <el-button :icon="Refresh" @click="loadHistory">{{ t('common.refresh') }}</el-button>
          <span class="mt-subtle">{{ t('mroute.hist.memoryOnly') }}</span>
        </div>
        <el-table :data="pagedHistory" v-loading="historyLoading" stripe>
          <el-table-column :label="t('mroute.hist.time')" width="170">
            <template #default="{ row }">{{ fmtTimeMs(row.time) }}</template>
          </el-table-column>
          <el-table-column :label="t('mroute.hist.event')" width="110">
            <template #default="{ row }">
              <el-tag size="small" :type="(EVENT_TAG[row.event] as any) || 'info'" disable-transitions>
                {{ eventLabel(row.event) }}
              </el-tag>
            </template>
          </el-table-column>
          <!-- 路径不存在的拒收记录没有接收器（请求根本没落到任何一个入口上），
               这一格留空会像是渲染坏了；跟旁边几列一样用「—」把"确实没有"写出来。 -->
          <el-table-column :label="t('mroute.tabReceivers')" min-width="130">
            <template #default="{ row }">{{ row.receiver || '—' }}</template>
          </el-table-column>
          <el-table-column :label="t('mroute.hist.rule')" min-width="120">
            <template #default="{ row }">{{ row.rule || '—' }}</template>
          </el-table-column>
          <el-table-column :label="t('mroute.hist.target')" min-width="120">
            <template #default="{ row }">{{ row.target || '—' }}</template>
          </el-table-column>
          <el-table-column :label="t('mroute.hist.detail')" min-width="200">
            <template #default="{ row }">
              <!-- 原因与来源 IP 一起给，而不是二选一：拒收记录里"为什么被拦"和"谁在敲"
                   是同一个问题的两半——只有原因，用户判断不了该去改 IP 名单还是去找那个来源；
                   而拒收恰恰是最需要看来源的一类记录（令牌错、名单外、路径不存在的探测）。 -->
              <div v-if="row.reason" class="mt-danger-text">{{ row.reason }}</div>
              <div v-if="row.remote" class="mt-subtle">{{ row.remote }}</div>
              <span v-if="!row.reason && !row.remote" class="mt-subtle">—</span>
              <!-- 只有被拒收 / 被丢弃的记录带 sourceId：那两类的原因是一句结论，
                   不看对方到底发了什么就查不下去。其余事件类型没有原文可看，不放这个链接。 -->
              <el-link v-if="row.sourceId" type="primary" :underline="false" @click="openSource(row)">
                {{ t('mroute.hist.viewSource') }}
              </el-link>
            </template>
          </el-table-column>
          <el-table-column :label="t('mroute.hist.cost')" width="90" align="right">
            <template #default="{ row }">{{ row.ms ? row.ms + ' ms' : '—' }}</template>
          </el-table-column>
        </el-table>
        <!-- 页码用 Element 自带的，但「共 N 条」「每页显示条数」用本项目的词条：
             Element 的分页文案跟着它自己的 locale 走，这个项目没装它的中文包。 -->
        <div v-if="history.length" class="hist-foot">
          <span class="mt-subtle">{{ t('mroute.hist.total', { n: history.length }) }}</span>
          <span class="mt-subtle">{{ t('mroute.hist.pageSize') }}</span>
          <el-select v-model="historyPageSize" size="small" style="width: 90px">
            <el-option v-for="n in HISTORY_SIZES" :key="n" :value="n" :label="String(n)" />
          </el-select>
          <el-pagination
            v-model:current-page="historyPage"
            :page-size="historyPageSize"
            :total="history.length"
            :pager-count="5"
            layout="prev, pager, next"
            small
            background
          />
        </div>
      </el-tab-pane>
    </el-tabs>

    <!-- 入站原文 -->
    <el-dialog
      v-model="sourceVisible"
      :title="t('mroute.hist.sourceTitle')"
      width="min(720px, 94vw)"
      append-to-body
      :close-on-click-modal="false"
    >
      <div v-loading="sourceLoading">
        <!-- 已被顶掉：这不是错误，是留存只在内存里、按预算淘汰的正常结果，
             所以要把"为什么没了"和"能留多少"一起说，而不是只报一句没有数据。 -->
        <el-alert v-if="sourceGone" type="info" :closable="false" :title="t('mroute.hist.sourceGone')" />
        <template v-else-if="sourceRec">
          <div class="src-meta">
            <span>{{ fmtTimeMs(sourceRec.time) }}</span>
            <el-tag size="small" :type="(EVENT_TAG[sourceRec.event] as any) || 'info'" disable-transitions>
              {{ eventLabel(sourceRec.event) }}
            </el-tag>
            <span v-if="sourceRec.status">HTTP {{ sourceRec.status }}</span>
            <span v-if="sourceRec.receiver">{{ sourceRec.receiver }}</span>
            <span v-if="sourceRec.remote">{{ sourceRec.remote }}</span>
            <el-tag v-if="sourceRec.sniffed" size="small" type="info" disable-transitions>
              {{ sourceRec.sniffed }}
            </el-tag>
          </div>
          <div v-if="sourceRec.reason" class="mt-danger-text src-reason">{{ sourceRec.reason }}</div>

          <div class="src-label">{{ t('mroute.hist.srcRequest') }}</div>
          <pre class="src-box">{{ (sourceRec.method || '') + ' ' + (sourceRec.path || '') }}</pre>
          <!-- 查询串单独一行：有些系统只能在 URL 上带参数推送，那时它就是消息正文本身。
               令牌一类的参数由后端打过码（见 redactQuery），这里照原样显示。 -->
          <template v-if="sourceRec.query">
            <div class="src-label">{{ t('mroute.hist.srcQuery') }}</div>
            <pre class="src-box">{{ sourceRec.query }}</pre>
          </template>

          <template v-if="sourceHeaders.length">
            <div class="src-label">{{ t('mroute.hist.srcHeaders') }}</div>
            <pre class="src-box">{{ sourceHeaders.map((h) => h.k + ': ' + h.v).join('\n') }}</pre>
          </template>

          <div class="src-label">
            {{ t('mroute.hist.srcBody') }}
            <span v-if="sourceRec.bodyRead" class="mt-subtle">
              {{ fmtBytes(sourceRec.bodySize) }}
              <template v-if="sourceRec.bodyTruncated"> · {{ t('mroute.hist.srcTruncated') }}</template>
            </span>
          </div>
          <!-- 「没读过正文」与「正文是空的」必须分开说：入站检查刻意排成鉴权、限流在前，
               体积、关键词在后（见后端 handler.go 顶部），前面几道闸拦下的请求根本没有正文。
               混成一句"正文为空"，用户会以为对方发了个空包，转头去查对方的程序。 -->
          <el-alert
            v-if="!sourceRec.bodyRead"
            type="info"
            :closable="false"
            :title="t('mroute.hist.srcBodyUnread')"
          />
          <el-empty v-else-if="!sourceRec.body" :description="t('mroute.hist.srcBodyEmpty')" :image-size="48" />
          <pre v-else class="src-box src-body">{{ sourceRec.body }}</pre>
        </template>
      </div>
      <template #footer>
        <span v-if="sourceStats" class="mt-subtle src-foot">
          {{
            t('mroute.hist.sourceUsage', {
              n: sourceStats.count,
              max: sourceStats.maxEntries,
              used: fmtBytes(sourceStats.bytes),
              budget: fmtBytes(sourceStats.budget),
              body: fmtBytes(sourceStats.bodyMax),
            })
          }}
        </span>
        <!-- 清空：这份数据只在内存里、不落盘，别处没有能删它的地方。
             留了 0 条时禁用，免得点了一下什么都没发生。 -->
        <el-button
          :disabled="!sourceStats || sourceStats.count === 0"
          :loading="clearingSources"
          @click="clearSources"
        >
          {{ t('mroute.hist.clearSources') }}
        </el-button>
        <el-button @click="sourceVisible = false">{{ t('common.close') }}</el-button>
      </template>
    </el-dialog>

    <!-- 模块监听设置 -->
    <el-dialog
      v-model="serverVisible"
      :title="t('mroute.moduleSettings')"
      width="min(560px, 94vw)"
      append-to-body
      :close-on-click-modal="false"
      @closed="reloadServer"
    >
      <el-form label-position="top">
        <el-form-item :label="t('mroute.srv.enabled')">
          <el-switch v-model="server.enabled" />
        </el-form-item>
        <el-form-item :label="t('mroute.srv.port')">
          <el-input-number v-model="server.port" :min="1" :max="65535" />
          <span class="mt-subtle hint">{{ t('mroute.srv.portHint') }}</span>
        </el-form-item>
        <el-form-item :label="t('mroute.srv.https')">
          <el-switch v-model="server.https.enabled" />
        </el-form-item>
        <el-alert
          v-if="server.https.enabled"
          type="warning"
          :closable="false"
          :title="t('mroute.srv.httpsOnly')"
          class="al"
        />
        <el-form-item v-if="server.https.enabled" :label="t('mroute.srv.cert')">
          <el-select v-model="server.https.certId" :placeholder="t('mroute.srv.certRequired')" style="width: 100%">
            <el-option
              v-for="c in certs"
              :key="c.id"
              :label="`${c.name} (${(c.domains || []).join(', ')})`"
              :value="c.id!"
            />
          </el-select>
          <span class="mt-subtle hint">{{ t('mroute.srv.certHint') }}</span>
        </el-form-item>
        <!-- 域名不再跟着 HTTPS 开关走：端口 80 / 443 与 Web 服务共用同一条监听时，
             即使是明文也要靠域名把请求分给本模块（见后端 domains.go）。 -->
        <el-form-item :label="t('mroute.srv.domain')">
          <el-input v-model="server.domain" placeholder="hook.example.com" />
          <span class="mt-subtle hint">{{ t('mroute.srv.domainHint') }}</span>
        </el-form-item>
        <el-alert
          v-if="publicPort"
          type="warning"
          :closable="false"
          :title="t('mroute.srv.publicPortHint')"
          class="al"
        />
        <el-form-item :label="t('mroute.note')">
          <el-input v-model="server.note" :placeholder="t('mroute.srv.notePlaceholder')" />
        </el-form-item>
        <!-- 原文留存额度：与监听无关，但这一页就是本模块唯一的模块级设置页。
             0 表示不留存，此时执行历史上不再出现「来源」链接。 -->
        <el-form-item :label="t('mroute.srv.sourceRetain')">
          <el-input-number v-model="server.sourceRetainMb" :min="0" :max="SOURCE_RETAIN_MAX" />
          <span class="mt-subtle hint">
            {{ t('mroute.srv.sourceRetainHint', { max: SOURCE_RETAIN_MAX }) }}
          </span>
        </el-form-item>
        <p class="mt-subtle hint">{{ t('mroute.srv.listening', { addr: listenAddr }) }}</p>
      </el-form>
      <template #footer>
        <el-button @click="serverVisible = false">{{ t('common.cancel') }}</el-button>
        <el-button type="primary" :loading="savingServer" @click="saveServer">{{ t('common.save') }}</el-button>
      </template>
    </el-dialog>

    <ReceiverDialog
      v-model:visible="recv.dialogVisible.value"
      :model="recv.editing.value as WebhookReceiver"
      :is-new="recv.isNew.value"
      :saving="recv.saving.value"
      :meta="meta"
      :templates="tmpl.list.value"
      :targets="targ.list.value"
      :sample="sample"
      :base-url="baseUrl"
      :test-run="recv.editing.value.id ? testRuns[recv.editing.value.id!] : undefined"
      :test-run-busy="!!(recv.editing.value.id && testRunBusy[recv.editing.value.id!])"
      @update:sample="setSample"
      @new-path="newPath"
      @start-test-run="startTestRun(recv.editing.value as WebhookReceiver)"
      @stop-test-run="stopTestRun(recv.editing.value as WebhookReceiver)"
      @save="recv.save()"
    />

    <TargetDialog
      v-model:visible="targ.dialogVisible.value"
      :model="targ.editing.value as NotifyTarget"
      :is-new="targ.isNew.value"
      :saving="targ.saving.value"
      :meta="meta"
      @save="targ.save()"
    />

    <TargetTestDialog
      v-model:visible="testVisible"
      :target="testRow"
      :sending="testSending"
      :meta="meta"
      @send="sendTest"
    />

    <TemplateDialog
      v-model:visible="tmpl.dialogVisible.value"
      :model="tmpl.editing.value as MessageTemplate"
      :is-new="tmpl.isNew.value"
      :saving="tmpl.saving.value"
      :meta="meta"
      :receivers="recv.list.value"
      :sample="sample"
      :test-runs="testRuns"
      @save="tmpl.save()"
      @update:sample="setSample"
    />

    <RuleDialog
      v-model:visible="ruleVisible"
      :model="ruleModel"
      :is-new="ruleIsNew"
      :saving="ruleSaving"
      :meta="meta"
      :receivers="recv.list.value"
      :templates="tmpl.list.value"
      :targets="targ.list.value"
      :sample="sample"
      @save="saveRule"
    />

    <DryRunPanel
      v-model:visible="dryVisible"
      :receiver="dryReceiver"
      :sample="sample"
      :test-run="dryReceiver?.id ? testRuns[dryReceiver.id] : undefined"
      :test-run-busy="!!(dryReceiver?.id && testRunBusy[dryReceiver.id])"
      @update:sample="setSample"
      @start-test-run="dryReceiver && startTestRun(dryReceiver)"
      @stop-test-run="dryReceiver && stopTestRun(dryReceiver)"
    />
  </PageCard>
</template>

<style scoped>
.stat-row {
  display: flex;
  align-items: center;
  gap: 10px;
  min-width: 0;
}
.msg {
  font-size: 12px;
  max-width: 320px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
/* 窄屏：这一行（状态标签 + 监听说明）被 PageCard 收到标题下面独占一行，
 * 但 320 的定宽加不换行仍然放不下，整页会横向溢出。这一档改成能换行，
 * 让说明折成两行而不是被裁掉——里面的监听地址是这句话最有用的部分。 */
@media (max-width: 640px) {
  .stat-row {
    flex-wrap: wrap;
    justify-content: flex-end;
  }
  .msg {
    max-width: 100%;
    white-space: normal;
    text-align: right;
    line-height: 1.5;
  }
}
.metrics {
  display: flex;
  flex-wrap: wrap;
  gap: 18px;
  font-size: 13px;
  margin-bottom: 14px;
}
.metrics b {
  font-variant-numeric: tabular-nums;
}
.al {
  margin-bottom: 14px;
}
.bar {
  display: flex;
  align-items: center;
  gap: 12px;
  margin-bottom: 12px;
  font-size: 12px;
}
.hist-foot {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 10px;
  margin-top: 12px;
  font-size: 12px;
}
.tiny {
  font-size: 12px;
  line-height: 1.5;
}
/* 多分支规则在「模板」「通知目标」两列里是一行一个分支，行高压紧才装得下 10 个分支
 * 而不把整张表撑成一屏一行。 */
.tiny-line {
  font-size: 12px;
  line-height: 1.6;
}
/* 分支名前缀：目标那一列里必须看得出"这一行是哪个分支发的"，否则几行群名并排等于没有信息。 */
.b-chip {
  display: inline-block;
  margin-right: 4px;
  padding: 0 4px;
  border-radius: 3px;
  font-size: 11px;
  color: var(--el-text-color-regular);
  background: var(--el-fill-color-light);
}
.b-tag {
  margin-left: 4px;
}
.path,
.excerpt {
  font-family: ui-monospace, Menlo, Consolas, monospace;
  font-size: 12px;
  word-break: break-all;
}
.url-cell {
  display: flex;
  align-items: center;
  gap: 4px;
  min-width: 0;
}
/* 前缀一行、路径一行。复制按钮在右边竖向居中（align-items: center 由 .url-cell 给）。 */
.url-parts {
  flex: 1;
  min-width: 0;
  display: flex;
  flex-direction: column;
  line-height: 1.5;
}
.url-parts .path {
  display: block;
}
/* 前缀那一行装不下就截断（完整地址挂在父元素的 title 上，复制按钮也仍给完整地址）：
 * 放开换行的话，一个长域名会把这一格顶成三四行，"分两行"也就名存实亡了。
 * 路径那一行不截——它是随机生成的十来个字符，本来就短，且是这一格真正要看的东西。 */
.url-parts .origin {
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}
.mt-danger-text {
  color: var(--mt-danger, #f56c6c);
}
.mt-warn-text {
  color: var(--mt-warning, #e6a23c);
}
.hint {
  font-size: 12px;
  margin-left: 10px;
}
/* ---- 入站原文对话框 ---- */
.src-meta {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 10px;
  font-size: 12px;
  color: var(--el-text-color-regular);
}
.src-reason {
  margin-top: 8px;
  font-size: 13px;
  word-break: break-all;
}
.src-label {
  display: flex;
  align-items: center;
  gap: 8px;
  margin: 12px 0 4px;
  font-size: 12px;
  font-weight: 600;
}
/* 原文照原样显示：空格、缩进、换行都是判断"对方到底发了什么"的线索，
 * 所以用 pre 而不是普通文本，同时允许长行换行（正文常常是一整行 JSON）。 */
.src-box {
  margin: 0;
  padding: 8px 10px;
  border-radius: 4px;
  background: var(--el-fill-color-light);
  font-family: ui-monospace, Menlo, Consolas, monospace;
  font-size: 12px;
  line-height: 1.6;
  white-space: pre-wrap;
  word-break: break-all;
}
/* 正文可能有几十 KB，给个高度上限，别把对话框撑成无限长。 */
.src-body {
  max-height: 320px;
  overflow: auto;
}
/* 用量说明放页脚左侧，关闭按钮仍在右侧。 */
.src-foot {
  float: left;
  max-width: 78%;
  font-size: 12px;
  line-height: 1.5;
  text-align: left;
}
</style>
