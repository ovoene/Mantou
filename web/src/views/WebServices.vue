<script setup lang="ts">
import { computed, onActivated, onDeactivated, onUnmounted, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import { ElMessage, ElMessageBox } from 'element-plus'
import { Plus, Delete, Edit } from '@element-plus/icons-vue'
import PageCard from '@/components/PageCard.vue'
import RowActions from '@/components/RowActions.vue'
import TagInput from '@/components/TagInput.vue'
import { useResource } from '@/composables/useResource'
import { useCloseOnLeave } from '@/composables/useCloseOnLeave'
import { useNarrow } from '@/composables/useNarrow'
import { maxCountOf } from '@/api/limits'
import { webServicesApi, actions, type WebAccessLog } from '@/api/resources'

const { t } = useI18n()

// 窄屏时子项表的操作列只剩一个「更多」按钮，列宽跟着收窄。
// 父项那一行的三个操作也收进「更多」，不过那件事由 RowActions 自己判宽度。
const narrow = useNarrow()

interface Upstream {
  url: string
  weight: number
}
interface ProxyOptions {
  insecureSkipVerify: boolean
  preserveHost: boolean
  accessLog: boolean
  accessLogLimit: number
}
interface Redirect {
  target: string
  code: number
  keepPath: boolean
  keepQuery: boolean
}
interface StaticCfg {
  root: string
  index: string
  spaFallback: boolean
  gzip: boolean
  dirList: boolean
}
interface Access {
  basicAuth: boolean
  basicAuthUser: string
  basicAuthPass: string
  allowIps: string[]
  denyIps: string[]
  rateLimit: number
  ipFilter: boolean
  ipFilterMode: 'allow' | 'deny'
}
// 子项规则：同一父项（端口 + 地址族）下按前端地址分流到后端。
interface Child {
  id: string
  enabled: boolean
  note: string
  domains: string[]
  type: string
  upstreams: Upstream[]
  lb: string
  static: StaticCfg
  redirect: Redirect
  proxy: ProxyOptions
  headers: Record<string, string>
  access: Access
  tls: boolean
  tlsMinVersion: string
  redirectHttps: boolean
  hsts: boolean
  trustProxyHeaders: boolean
}
// 父项规则：一个 (端口, 地址族) 监听。
interface Parent {
  id?: string
  name: string
  enabled: boolean
  port: number
  ipFamily: string
  probeInterval: number // 主动探测间隔（秒），作用于该父项下所有子项；默认 60
  children: Child[]
}

// 前端生成子项 ID（后端仅为父项分配 ID，子项 ID 需前端提供，用于连接数/日志映射）。
function genChildId(): string {
  const buf = new Uint8Array(6)
  if (typeof crypto !== 'undefined' && crypto.getRandomValues) {
    crypto.getRandomValues(buf)
  } else {
    for (let i = 0; i < buf.length; i++) buf[i] = Math.floor(Math.random() * 256)
  }
  return Array.from(buf, (b) => b.toString(16).padStart(2, '0')).join('')
}

function emptyChild(): Child {
  return {
    id: genChildId(),
    enabled: true,
    note: '',
    domains: [],
    type: 'proxy',
    upstreams: [{ url: '', weight: 1 }],
    lb: 'roundrobin',
    static: { root: '', index: 'index.html', spaFallback: true, gzip: true, dirList: false },
    redirect: { target: '', code: 302, keepPath: false, keepQuery: false },
    proxy: { insecureSkipVerify: false, preserveHost: false, accessLog: false, accessLogLimit: 20 },
    headers: {},
    access: {
      basicAuth: false,
      basicAuthUser: '',
      basicAuthPass: '',
      allowIps: [],
      denyIps: [],
      rateLimit: 0,
      ipFilter: false,
      ipFilterMode: 'allow',
    },
    tls: false,
    tlsMinVersion: '1.2',
    redirectHttps: false,
    hsts: false,
    trustProxyHeaders: false,
  }
}
function emptyParent(): Parent {
  return { name: '', enabled: true, port: 8080, ipFamily: 'both', probeInterval: 60, children: [emptyChild()] }
}

const r = useResource<Parent>('webservices', emptyParent)

// 单个父项下的子项数上限，由后端下发（见 @/api/limits）。真正花钱的是子项而不是父项：
// 每个反代子项各自持有一个连接池，空闲连接数按子项数增长（详见后端 config.MaxWebChildren）。
// 前端不写死这个数——写死就有两份，改了后端忘了这里，界面会让你加、保存时被拒。
// 拿不到时给 0，此时不禁按钮也不显示那句提示：让后端在保存时拦，总比界面上凭一个
// 没拉回来的数把功能先关掉要好。
const maxChildren = computed<number>(() => maxCountOf('webservices/children'))
// 某个父项的子项是否已到上限。列表上那个「添加子项」按钮据此禁用。
function childrenFull(p: Parent): boolean {
  return maxChildren.value > 0 && (p.children?.length || 0) >= maxChildren.value
}
// 编辑弹窗里那个「添加子项」按钮：看的是正在编辑的那一份（可能已经加了几个还没保存）。
const editingChildrenFull = computed<boolean>(
  () => maxChildren.value > 0 && ((r.editing.value as Parent).children?.length || 0) >= maxChildren.value,
)

// 探测间隔下拉选项（秒）：固定 15/30/60/300；若导入配置带了其它值，则额外补上以保证可回显与往返。
const probeIntervalBase = [15, 30, 60, 300]
const probeIntervalOptions = computed<number[]>(() => {
  const cur = r.editing.value?.probeInterval
  const opts = [...probeIntervalBase]
  if (typeof cur === 'number' && cur > 0 && !opts.includes(cur)) {
    opts.push(cur)
  }
  return opts
})

// ---- 运行态：各子项活跃连接数（轮询）与连接日志 ----
const stats = ref<Record<string, number>>({})
// 各子项链接状态（最近成功 / 失败时间 + 失败状态码）。
const childStatus = ref<Record<string, { lastOK: number; lastErr: number; lastStatus: number }>>({})
let statsTimer: number | undefined

async function refreshStats(silent = false) {
  try {
    stats.value = await actions.webStats(silent ? { silent: true } : undefined)
  } catch {
    /* 忽略瞬时错误 */
  }
}

async function refreshChildStatus(silent = false) {
  try {
    childStatus.value = await actions.webChildStatus(silent ? { silent: true } : undefined)
  } catch {
    /* 忽略瞬时错误 */
  }
}

// 该子项是否已配置后端链接（反代上游 / 重定向目标 / 静态根目录）。
// 用于在无访问记录时也给出「正常」状态，避免「链接状态」一栏始终空白。
function hasConfiguredLink(ch: Child): boolean {
  if (ch.type === 'proxy') {
    return (ch.upstreams || []).some((u) => u.url.trim())
  }
  if (ch.type === 'redirect') {
    return ch.redirect.target.trim() !== ''
  }
  // 静态站点：本地根目录即视为已配置。
  return ch.static.root.trim() !== ''
}

// 依据「是否启用 + 是否配置链接 + 最近成功/失败访问」判定链接状态文案、颜色与是否闪烁。
// - 最近一次失败晚于（或等于）最近成功 → 红色闪烁「访问错误」（附状态码）；
// - 已启用且配置了后端链接 → 绿色「正常」（即便尚未有任何访问记录，也给出明确状态）；
// - 其余（未启用 / 未配置后端）→ 中性「未访问」。
function linkInfo(row: Child): { text: string; type: 'success' | 'danger' | 'info'; blink: boolean } {
  const st = childStatus.value[row.id]
  if (st && st.lastErr > 0 && st.lastErr >= st.lastOK) {
    // 状态 0 表示探测连接失败（无 HTTP 响应），区别于后端返回的 >=400 错误码。
    const text = st.lastStatus > 0 ? `${t('webservice.linkFail')} (${st.lastStatus})` : t('webservice.linkUnreachable')
    return { text, type: 'danger', blink: true }
  }
  if (row.enabled && hasConfiguredLink(row)) {
    return { text: t('webservice.linkNormal'), type: 'success', blink: false }
  }
  return { text: t('webservice.linkIdle'), type: 'info', blink: false }
}

function normFamily(f: string): string {
  return f === 'v4' || f === 'v6' ? f : 'both'
}
function familyLabel(f: string): string {
  const n = normFamily(f)
  if (n === 'v4') return t('webservice.familyV4')
  if (n === 'v6') return t('webservice.familyV6')
  return t('webservice.familyBoth')
}
function typeLabel(type: string): string {
  if (type === 'static') return t('webservice.typeStatic')
  if (type === 'redirect') return t('webservice.typeRedirect')
  return t('webservice.typeProxy')
}
function frontendText(ch: Child): string {
  const ds = (ch.domains || []).filter((d) => d.trim())
  return ds.length ? ds.join(', ') : '*'
}
function backendText(ch: Child): string {
  if (ch.type === 'static') return ch.static.root || '—'
  if (ch.type === 'redirect') return ch.redirect.target || '—'
  const us = (ch.upstreams || []).map((u) => u.url).filter((u) => u.trim())
  return us.length ? us.join(', ') : '—'
}

// 前端地址快捷打开：按子项是否启用 TLS 决定 http/https，并拼上父项监听端口。
function frontendUrl(ch: Child, p: Parent, domain: string): string {
  const proto = ch.tls ? 'https' : 'http'
  return `${proto}://${domain}:${p.port}`
}
// 后端真实地址（可点击打开）：反代为上游 URL、重定向为目标 URL；静态站点为本地路径，不可直接打开。
function backendUrls(ch: Child): string[] {
  if (ch.type === 'static') return []
  if (ch.type === 'redirect') return ch.redirect.target ? [ch.redirect.target] : []
  return (ch.upstreams || []).map((u) => u.url).filter((u) => u.trim())
}

// 子项的派生展示数据（链接状态 + 后端地址列表），整张表一次算好。
//
// 模板里原本对每一行调用 linkInfo() 三次（type / blink / text 各取一次）、backendUrls() 两次，
// 而这张表每 5 秒随轮询整体重绘一次——行数一多，同一份判断就被反复重算，输入却大多没变。
// 收成 computed 后每行只算一次，且只在真正相关的数据变化时才重算：
// 规则列表、childStatus（轮询结果）、界面语言。
//
// 用 WeakMap 以「子项对象本身」为键，而不是以 ch.id 为键：子项 ID 由前端生成
// （见上面 newChildId 的说明），历史配置里理论上可能存在空 ID，按 ID 做键会让两行取到同一份
// 状态——那是把优化做成 bug。以对象为键则不可能撞，且万一将来 el-table 不再原样透传行对象、
// 身份对不上，viewOf 会退回现算一份，行为与优化前完全一致（只是少了这层缓存）。
const childView = computed(() => {
  const map = new WeakMap<
    Child,
    { link: { text: string; type: 'success' | 'danger' | 'info'; blink: boolean }; backends: string[] }
  >()
  for (const p of r.list.value as Parent[]) {
    for (const ch of p.children || []) {
      map.set(ch, { link: linkInfo(ch), backends: backendUrls(ch) })
    }
  }
  return map
})

// 查表取派生数据；取不到就现算（见上面关于身份的说明）。
function viewOf(ch: Child) {
  return childView.value.get(ch) || { link: linkInfo(ch), backends: backendUrls(ch) }
}

// 后端地址渲染成可点击链接：缺协议前缀时浏览器会当作相对路径（点开跳到当前页），
// 这里兜底补全 http://，确保新标签打开的是真实后端地址（与保存期自动补全双保险）。
function backendHref(u: string): string {
  const s = (u || '').trim()
  if (s === '') return '#'
  if (/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(s)) return s
  return 'http://' + s
}

// ---- 列表内联启用/停用：调专用轻量端点，乐观更新 + 失败回滚 ----
// 用户硬性要求：列表内联开关是 UI 轻量操作，**不写"配置已保存"审计日志**，
// 也无需走完整 PUT 路径校验。后端提供专用 /toggle 端点处理：仅持久化 +
// 热重载，不调用 logOp("保存", ...)。编辑弹窗底部「保存」按钮仍走完整 PUT
// 路径产生正常的「启用/禁用/保存」审计条目，与本开关互不干扰。
// 失败时回滚 UI（el-switch 由 v-model 绑定 p.enabled，自然跟随）。
async function toggleParent(p: Parent) {
  if (!p.id) return
  const next = p.enabled // el-switch 的 v-model 已翻好值
  try {
    await actions.toggleWebService(p.id, next)
  } catch (e: any) {
    p.enabled = !next
    ElMessage.error(e?.message || t('common.failed'))
  }
}
async function toggleChild(p: Parent, ch: Child) {
  if (!p.id || !ch.id) return
  const next = ch.enabled
  try {
    await actions.toggleWebServiceChild(p.id, ch.id, next)
  } catch (e: any) {
    ch.enabled = !next
    ElMessage.error(e?.message || t('common.failed'))
  }
}

// 列表内联删除子项：复用通用删除确认弹窗范式，调用专用轻量 DELETE 端点，
// 乐观从本地 children 移除 + 成功 toast；后端落库后热重载回收监听/路由，
// 并记「删除 Web 服务 下 父项 的子项 子项名」审计（动词"删除"而非"保存"）。
async function deleteChild(p: Parent, ch: Child) {
  if (!p.id || !ch.id) return
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
    await actions.deleteWebServiceChild(p.id, ch.id)
    const idx = p.children.findIndex((c) => c.id === ch.id)
    if (idx >= 0) p.children.splice(idx, 1)
    ElMessage.success(t('common.deleted'))
  } catch (e: any) {
    ElMessage.error(e?.message || t('common.failed'))
  }
}

// ---- 父项对话框：管理父项字段 + 其下多个子项 ----
const activeChildPanels = ref<string[]>([])

// 访问认证口令的输入草稿（子项 ID → 用户新输入的口令）。
// 后端只保存哈希、不回显明文，因此输入框刻意不与 ch.access.basicAuthPass 直接绑定：
// 草稿为空 = 不修改（保存时沿用已存的哈希），草稿非空 = 设置为新口令。
// 直接绑定的话，输入框里躺着的是 60 个字符的哈希；用户随手删掉一两位再保存，
// 就会得到一个"看着像哈希、其实是新口令"的值——谁也不知道它是什么。
const basicPassDraft = ref<Record<string, string>>({})

function openCreateParent() {
  r.openCreate()
  basicPassDraft.value = {}
  activeChildPanels.value = ((r.editing.value as Parent).children || []).map((c) => c.id)
}
// 打开父项编辑：默认所有子项折叠（用户按需展开或单独编辑）。
function openEditParent(p: Parent) {
  r.openEdit(p as any)
  basicPassDraft.value = {}
  // 兼容旧数据：确保子项均有 ID。
  const e = r.editing.value as Parent
  for (const c of e.children || []) {
    if (!c.id) c.id = genChildId()
    // 兼容旧配置：访问日志条数未设置时回退为默认 20（≤0 视为未设置）。
    if (!c.proxy) {
      c.proxy = { insecureSkipVerify: false, preserveHost: false, accessLog: false, accessLogLimit: 20 }
    } else if (!(c.proxy.accessLogLimit > 0)) {
      c.proxy.accessLogLimit = 20
    }
  }
  activeChildPanels.value = []
}
// 从父项行直接「新增子项」：打开父项编辑，追加一个新子项并只展开它。
function addChildToParent(p: Parent) {
  openEditParent(p)
  addChild()
}
// 从子项行直接「编辑」：打开父项编辑，只展开该子项。
function editChild(p: Parent, ch: Child) {
  openEditParent(p)
  activeChildPanels.value = [ch.id]
}
function addChild() {
  const e = r.editing.value as Parent
  if (!Array.isArray(e.children)) e.children = []
  // 按钮已经禁用了，这里再挡一次：addChildToParent 也走这个函数，而那条路径上
  // 按钮的禁用状态与"打开之后弹窗里已有几个"不是同一个判断。
  if (maxChildren.value > 0 && e.children.length >= maxChildren.value) return
  const c = emptyChild()
  e.children.push(c)
  activeChildPanels.value.push(c.id)
}
function removeChild(i: number) {
  const e = r.editing.value as Parent
  e.children.splice(i, 1)
}
// 切换 IP 过滤模式（白名单 / 黑名单）时，清空另一侧名单，避免两套名单同时生效。
function onIpFilterModeChange(ch: Child) {
  if (ch.access.ipFilterMode === 'allow') ch.access.denyIps = []
  else ch.access.allowIps = []
}
function onTLSChange(ch: Child, enabled: boolean) {
  const e = r.editing.value as Parent
  if (e.children.some((item) => item !== ch && item.tls !== enabled)) {
    ch.tls = !enabled
    ElMessage.warning(t('webservice.mixedProtocol'))
    return
  }
  if (enabled) {
    // 启用 TLS 即强制开启「强制 HTTPS」（开关随之锁定；后端 normalizeWebService 同样兜底）。
    ch.redirectHttps = true
  } else {
    // 关闭 TLS 后访问认证不再可见：一并关掉开关，避免留下一道看不见却仍在生效的认证。
    // 账号与已存的口令哈希原样保留，重新启用 TLS 时不必再输一遍。
    ch.access.basicAuth = false
  }
}
function childTitle(ch: Child, i: number): string {
  if (ch.note) return ch.note
  const f = (ch.domains || []).filter((d) => d.trim())
  if (f.length) return f.join(', ')
  return `${t('webservice.childSummary')} ${i + 1}`
}

async function saveParent() {
  const e = r.editing.value as Parent
  if (!e.children || e.children.length === 0) {
    ElMessage.warning(t('webservice.needChild'))
    return
  }
  const protocols = new Set(e.children.map((ch) => ch.tls))
  if (protocols.size > 1) {
    ElMessage.warning(t('webservice.mixedProtocol'))
    return
  }
  // 访问认证：把口令草稿落到待保存的数据上（用户没输入就沿用已存的哈希），并校验必填项。
  for (const ch of e.children) {
    const draft = basicPassDraft.value[ch.id] || ''
    if (draft !== '') ch.access.basicAuthPass = draft
    ch.access.basicAuthUser = (ch.access.basicAuthUser || '').trim()
  }
  const lacking = e.children.find(
    (ch) => ch.access.basicAuth && (!ch.access.basicAuthUser || !ch.access.basicAuthPass),
  )
  if (lacking) {
    ElMessage.warning(t('webservice.basicAuthNeedCred'))
    return
  }
  // 唯一性：同一 (端口, 地址族) 只能有一个父项。
  const dup = (r.list.value as Parent[]).find(
    (p) => p.id !== e.id && p.port === e.port && normFamily(p.ipFamily) === normFamily(e.ipFamily),
  )
  if (dup) {
    ElMessage.warning(t('webservice.dupParent'))
    return
  }
  await r.save()
}

// ---- 连接日志对话框 ----
const logsVisible = ref(false)
const logsLoading = ref(false)
interface WebLogRow extends WebAccessLog {
  // 预解析后的中文访问摘要片段，供对话框按主题色渲染。
  line: { ip: string; verb: string; parent: string; child: string; err: string }
}
const logsData = ref<WebLogRow[]>([])
const logsTitle = ref('')

// 将结构化访问记录解析为「ip为…访问了Web服务下 父项 规则 下的 子项 服务」所需片段。
function fmtLogLine(row: WebAccessLog): WebLogRow['line'] {
  const parts = (row.service || '').split(' / ')
  const parent = (parts[0] || '').trim()
  const child = parts.slice(1).join(' / ').trim()
  let verb = '访问了'
  if (row.method === '断开') verb = '断开了'
  else if (row.method === '错误') verb = '访问'
  else if (row.method === '拒绝') verb = '被拒绝'
  const err = row.method === '错误' && row.status > 0 ? ` 出错（${row.status}）` : ''
  return { ip: row.remote || '', verb, parent, child, err }
}

// 将结构化访问记录映射为「结果」标签文案与颜色：
// connect→成功(green)；disconnect→断开(gray)；denied→拒绝+代码(danger)；error→错误+代码(danger)。
// probe→成功/错误（绿色/红色），由 60s 周期主动探测写入，详情见「后端状态」列。
function statusInfo(row: WebAccessLog): {
  text: string
  type: 'success' | 'info' | 'warning' | 'danger'
} {
  switch (row.event) {
    case 'connect':
      return { text: t('webservice.logStatusSuccess'), type: 'success' }
    case 'disconnect':
      return { text: t('webservice.logStatusDisconnect'), type: 'info' }
    case 'denied':
      return { text: `${t('webservice.logStatusDenied')} ${row.status}`, type: 'danger' }
    case 'error':
      return { text: `${t('webservice.logStatusError')} ${row.status}`, type: 'danger' }
    case 'probe':
      // 探测结果：以 reason 是否为空判定成功/失败。
      // 注意 status=0 对「静态/重定向成功」与「连接失败」均会出现，不能仅凭状态码判断，
      // 否则连接失败的子项会误显示为绿色「成功」，与「后端状态」列的红色错误原因自相矛盾。
      if (!row.reason) {
        return { text: t('webservice.logStatusSuccess'), type: 'success' }
      }
      return {
        text: row.status > 0 ? `${t('webservice.logStatusError')} ${row.status}` : t('webservice.logStatusError'),
        type: 'danger',
      }
    default:
      return { text: String(row.status), type: 'info' }
  }
}

async function openLogs(p: Parent, ch: Child) {
  logsTitle.value = `${p.name || t('common.unnamed')} / ${childTitle(ch, 0)}`
  logsVisible.value = true
  logsLoading.value = true
  logsData.value = []
  try {
    const lim = ch.proxy.accessLogLimit > 0 ? ch.proxy.accessLogLimit : 20
    const raw = await actions.webChildLogs(ch.id, lim)
    logsData.value = raw.map((e) => ({ ...e, line: fmtLogLine(e) }))
  } catch (e: any) {
    ElMessage.error(e?.message || t('common.loadFailed'))
  } finally {
    logsLoading.value = false
  }
}
function fmtLogTime(ms: number): string {
  return new Date(ms).toLocaleString()
}

// 轮询只在页面处于激活状态时存在，切走即停（见 onDeactivated）。
function startPolling() {
  if (statsTimer) return
  statsTimer = window.setInterval(() => {
    refreshStats(true)
    refreshChildStatus(true)
  }, 5000)
}

function stopPolling() {
  if (statsTimer) window.clearInterval(statsTimer)
  statsTimer = undefined
}

// 页面被激活（keep-alive 下首次挂载同样会触发一次，因此这里是唯一入口）。
// 三个请求彼此独立（规则列表 / 连接数 / 链接状态），并发发出：
// 原先串行等于把三个往返首尾相接，首屏要等最后一个回来才成形。
onActivated(() => {
  startPolling()
  r.load()
  refreshStats()
  refreshChildStatus()
})

// 被缓存的页面必须停掉轮询：否则待在别的模块里时，这个 5 秒定时器仍在后台打两个接口。
onDeactivated(stopPolling)
onUnmounted(stopPolling)

// 本页另开的日志弹窗也在切页时收起；新增 / 编辑那个在 useResource 里。
useCloseOnLeave(logsVisible)
</script>

<template>
  <PageCard :title="t('webservice.title')" :subtitle="t('webservice.subtitle')" :max-count="r.maxCount.value">
    <template #actions>
      <el-button type="primary" :icon="Plus" @click="openCreateParent">{{ t('common.add') }}</el-button>
    </template>

    <p class="mt-subtle hint-block">{{ t('webservice.parentHint') }}</p>

    <div v-loading="r.loading.value">
      <el-empty v-if="!r.list.value.length" :description="t('common.empty')" />

      <!-- 一级：父项（端口 + 地址族） -->
      <div v-for="p in (r.list.value as Parent[])" :key="p.id" class="parent-block mt-glass">
        <div class="parent-head">
          <el-switch v-model="p.enabled" @change="toggleParent(p)" />
          <!-- title 不分宽窄都挂：名字在任何宽度下都可能被截断，看不全时靠它补上。 -->
          <strong class="pname" :title="p.name || t('common.unnamed')">
            {{ p.name || t('common.unnamed') }}
          </strong>
          <div class="parent-meta">
            <el-tag size="small" effect="light" type="primary">{{ t('webservice.port') }} {{ p.port }}</el-tag>
            <el-tag size="small" effect="plain">{{ familyLabel(p.ipFamily) }}</el-tag>
          </div>
          <span class="spacer" />
          <!-- 三个操作包成一组：宽度不够时要整组落到第二行，散着放会各自单独换行，
               操作被拆到两三行上。窄屏由 RowActions 收进「更多」（全站列表同一个菜单）。 -->
          <div class="parent-actions">
            <RowActions>
              <el-button size="small" :icon="Edit" @click="openEditParent(p)">{{ t('common.edit') }}</el-button>
              <el-button
                size="small"
                type="primary"
                :icon="Plus"
                :disabled="childrenFull(p)"
                :title="childrenFull(p) ? t('webservice.childrenFull', { n: maxChildren }) : ''"
                @click="addChildToParent(p)"
              >
                {{ t('webservice.addChild') }}
              </el-button>
              <el-button size="small" type="danger" text @click="r.remove(p as any, t('common.confirmDelete'))">
                {{ t('common.delete') }}
              </el-button>
            </RowActions>
          </div>
        </div>

        <p v-if="!p.enabled" class="mt-subtle disabled-hint">{{ t('webservice.parentDisabledHint') }}</p>

        <!-- 二级：子项（前端地址 → 后端地址） -->
        <el-table :data="p.children || []" size="small" class="child-table">
          <el-table-column :label="t('common.status')" width="70">
            <template #default="{ row }">
              <el-switch v-model="row.enabled" size="small" :disabled="!p.enabled" @change="toggleChild(p, row)" />
            </template>
          </el-table-column>
          <el-table-column :label="t('webservice.type')" width="100">
            <template #default="{ row }">{{ typeLabel(row.type) }}</template>
          </el-table-column>
          <el-table-column :label="t('webservice.frontAddr')" min-width="170">
            <template #default="{ row }">
              <span v-if="!row.domains || !row.domains.length" class="mt-subtle">*</span>
              <span v-else class="addr-links">
                <a
                  v-for="d in row.domains"
                  :key="d"
                  class="addr-link"
                  :href="frontendUrl(row, p, d)"
                  target="_blank"
                  rel="noopener"
                >{{ d }}</a>
              </span>
            </template>
          </el-table-column>
          <el-table-column :label="t('webservice.backAddr')" min-width="170">
            <template #default="{ row }">
              <span v-if="row.type === 'static'" class="mt-subtle">{{ row.static.root || '—' }}</span>
              <span v-else-if="!viewOf(row).backends.length" class="mt-subtle">—</span>
              <span v-else class="addr-links">
                <a
                  v-for="u in viewOf(row).backends"
                  :key="u"
                  class="addr-link"
                  :href="backendHref(u)"
                  target="_blank"
                  rel="noopener"
                >{{ u }}</a>
              </span>
            </template>
          </el-table-column>
          <el-table-column :label="t('webservice.linkStatus')" width="120" align="center">
            <template #default="{ row }">
              <el-tag size="small" :type="viewOf(row).link.type" effect="light" round :class="{ blink: viewOf(row).link.blink }">{{ viewOf(row).link.text }}</el-tag>
            </template>
          </el-table-column>
          <!-- 备注紧挨「操作」左边：全站列表一律这个位置，用户扫到最右边找按钮时顺路读到它。
               子项表在父项卡片里，可用宽度比整页窄，各列宽度之和必须留在这个卡片内——
               超出就横向滚动，最右边的「删除」得先滚才点得到。 -->
          <el-table-column :label="t('webservice.childNote')" min-width="100" show-overflow-tooltip>
            <template #default="{ row }">
              <span>{{ row.note || '—' }}</span>
            </template>
          </el-table-column>
          <el-table-column :label="t('common.actions')" :min-width="narrow ? 90 : 180" align="right">
            <template #default="{ row }">
              <RowActions>
                <el-button size="small" text type="primary" @click="editChild(p, row)">
                  {{ t('common.edit') }}
                </el-button>
                <el-button
                  v-if="row.proxy && row.proxy.accessLog"
                  size="small"
                  text
                  type="primary"
                  @click="openLogs(p, row)"
                >
                  {{ t('webservice.viewLogs') }}
                </el-button>
                <el-button
                  size="small"
                  text
                  type="danger"
                  @click="deleteChild(p, row)"
                >
                  {{ t('common.delete') }}
                </el-button>
              </RowActions>
            </template>
          </el-table-column>
        </el-table>
      </div>
    </div>

    <!-- 父项 + 子项编辑对话框 -->
    <el-dialog
      v-model="r.dialogVisible.value"
      :title="r.isNew.value ? t('common.add') : t('common.edit')"
      width="min(720px, 94vw)"
      append-to-body
      :close-on-click-modal="false"
    >
      <el-form label-position="top">
        <!-- 父项：端口 + 地址族（主规则），粗边框分段 -->
        <div class="section-box">
          <div class="section-title">{{ t('webservice.port') }}</div>
          <div class="grid4">
            <el-form-item :label="t('webservice.svcName')">
              <el-input v-model="(r.editing.value as Parent).name" />
            </el-form-item>
            <el-form-item :label="t('webservice.port')">
              <el-input-number
                v-model="(r.editing.value as Parent).port"
                :min="1"
                :max="65535"
                :controls="false"
                style="width: 100%"
              />
            </el-form-item>
            <el-form-item :label="t('webservice.ipFamily')">
              <el-select v-model="(r.editing.value as Parent).ipFamily" style="width: 100%">
                <el-option :label="t('webservice.familyBoth')" value="both" />
                <el-option :label="t('webservice.familyV4')" value="v4" />
                <el-option :label="t('webservice.familyV6')" value="v6" />
              </el-select>
            </el-form-item>
            <el-form-item :label="t('common.status')">
              <el-switch v-model="(r.editing.value as Parent).enabled" />
            </el-form-item>
            <el-form-item :label="t('webservice.probeInterval')">
              <el-select v-model="(r.editing.value as Parent).probeInterval" style="width: 100%">
                <el-option v-for="v in probeIntervalOptions" :key="v" :label="`${v}s`" :value="v" />
              </el-select>
            </el-form-item>
          </div>
          <div class="field-hint">{{ t('webservice.probeIntervalHint') }}</div>
        </div>

        <!-- 子项列表：仅保留「+ 添加子项」，粗边框分段 -->
        <div class="section-box">
          <div class="section-head">
            <!-- 上限那句话摆在按钮左边：这一行是右对齐的，按钮变灰时用户第一眼往左看就是"为什么"。 -->
            <span v-if="maxChildren > 0" class="mt-subtle child-cap">
              {{ t('webservice.childrenCap', { n: maxChildren }) }}
            </span>
            <el-button link type="primary" :icon="Plus" :disabled="editingChildrenFull" @click="addChild">
              {{ t('webservice.addChild') }}
            </el-button>
          </div>

        <el-collapse v-model="activeChildPanels">
          <el-collapse-item
            v-for="(ch, ci) in (r.editing.value as Parent).children"
            :key="ch.id"
            :name="ch.id"
          >
            <template #title>
              <span class="child-panel-title">{{ childTitle(ch, ci) }}</span>
            </template>

            <div class="grid3">
              <el-form-item :label="t('webservice.childNote')">
                <el-input v-model="ch.note" />
              </el-form-item>
              <el-form-item :label="t('webservice.type')">
                <el-select v-model="ch.type" style="width: 100%">
                  <el-option :label="t('webservice.typeProxy')" value="proxy" />
                  <el-option :label="t('webservice.typeStatic')" value="static" />
                  <el-option :label="t('webservice.typeRedirect')" value="redirect" />
                </el-select>
              </el-form-item>
              <el-form-item :label="t('common.status')">
                <el-switch v-model="ch.enabled" />
              </el-form-item>
            </div>

            <!-- 前端地址：输入框长度拉满（整行）。 -->
            <div class="row mt-glass">
              <el-form-item :label="t('webservice.stepFront')" style="flex: 1; margin-bottom: 0">
                <TagInput v-model="ch.domains" placeholder="example.com" />
              </el-form-item>
            </div>
            <p class="mt-subtle hint-block">{{ t('webservice.frontHint') }}</p>

            <!-- 后端：反向代理 -->
            <template v-if="ch.type === 'proxy'">
              <div class="back-head">
                <span>{{ t('webservice.upstreams') }}</span>
              </div>
              <div v-for="(u, ui) in ch.upstreams" :key="ui" class="row mt-glass">
                <el-input v-model="u.url" placeholder="http://127.0.0.1:3000" style="flex: 1" />
              </div>
              <p class="mt-subtle hint-block">{{ t('webservice.backHint') }}</p>

              <div class="section-box">
                <div class="section-title">{{ t('webservice.proxyOptions') }}</div>
                <!-- 记录访问日志放左列：两列网格里，「显示最近条数」跟在它后面换行，正好落在它正下方。 -->
                <div class="grid2">
                  <el-form-item :label="t('webservice.accessLog')">
                    <el-switch v-model="ch.proxy.accessLog" />
                  </el-form-item>
                  <el-form-item :label="t('webservice.insecureSkipVerify')">
                    <el-switch v-model="ch.proxy.insecureSkipVerify" />
                  </el-form-item>
                  <el-form-item v-if="ch.proxy.accessLog" :label="t('webservice.accessLogLimit')">
                    <el-input-number v-model="ch.proxy.accessLogLimit" :min="1" :max="2000" />
                  </el-form-item>
                </div>
                <el-form-item :label="t('webservice.preserveHost')">
                  <el-switch v-model="ch.proxy.preserveHost" />
                </el-form-item>
                <p class="mt-subtle hint-block">{{ t('webservice.preserveHostHint') }}</p>

                <!-- IP 过滤：总开关 + 模式下拉（白/黑名单）+ 大输入框 -->
                <el-form-item :label="t('webservice.ipFilter')">
                  <el-switch
                    v-model="ch.access.ipFilter"
                    @change="(v: any) => { if (!v) { ch.access.allowIps = []; ch.access.denyIps = [] } }"
                  />
                  <el-select
                    v-if="ch.access.ipFilter"
                    v-model="ch.access.ipFilterMode"
                    style="width: 160px; margin-left: 12px"
                    @change="onIpFilterModeChange(ch)"
                  >
                    <el-option :label="t('webservice.ipWhitelist')" value="allow" />
                    <el-option :label="t('webservice.ipBlacklist')" value="deny" />
                  </el-select>
                </el-form-item>
                <el-form-item v-if="ch.access.ipFilter" :label="t('webservice.ipList')">
                  <TagInput
                    v-if="ch.access.ipFilterMode === 'allow'"
                    v-model="ch.access.allowIps"
                    class="ip-large"
                    :placeholder="t('webservice.ipListPlaceholder')"
                  />
                  <TagInput
                    v-else
                    v-model="ch.access.denyIps"
                    class="ip-large"
                    :placeholder="t('webservice.ipListPlaceholder')"
                  />
                  <p class="mt-subtle hint-block">{{ t('webservice.ipFilterHint') }}</p>
                </el-form-item>

                <!-- 请求速率限制：总开关（rateLimit 0/非0）+ 每秒请求数。
                     注意：el-switch 不能既把同一字段既当 number（active/inactive-value）又当
                     truthy 开关用——一旦 change 回调把值改成 20，el-switch 的 v-model
                     既不等于 active-value 也不等于 inactive-value，组件视觉状态会出现"按钮
                     不变色、无法关闭"的卡死现象。改为 :model-value + @change 显式同步，
                     switch 的开/关状态严格由 rateLimit>0 派生，避免任何值域不匹配。 -->
                <el-form-item :label="t('webservice.rateLimit')">
                  <el-switch
                    :model-value="ch.access.rateLimit > 0"
                    @change="(v: any) => {
                      if (v) {
                        if (ch.access.rateLimit <= 0) ch.access.rateLimit = 20
                      } else {
                        ch.access.rateLimit = 0
                      }
                    }"
                  />
                  <el-input-number
                    v-if="ch.access.rateLimit > 0"
                    v-model="ch.access.rateLimit"
                    :min="1"
                    :max="10000"
                    style="margin-left: 12px"
                  />
                </el-form-item>
                <p v-if="ch.access.rateLimit > 0" class="mt-subtle hint-block">{{ t('webservice.rateLimitHint') }}</p>
              </div>
            </template>

            <!-- 后端：静态站点 -->
            <template v-else-if="ch.type === 'static'">
              <el-form-item :label="t('webservice.root')">
                <el-input v-model="ch.static.root" placeholder="/data/www" />
              </el-form-item>
              <div class="grid2">
                <el-form-item label="Index">
                  <el-input v-model="ch.static.index" />
                </el-form-item>
                <el-form-item label="SPA Fallback">
                  <el-switch v-model="ch.static.spaFallback" />
                </el-form-item>
              </div>
              <el-form-item :label="t('webservice.gzip')">
                <el-switch v-model="ch.static.gzip" />
              </el-form-item>
              <p class="mt-subtle hint-block">{{ t('webservice.gzipHint') }}</p>
              <el-form-item :label="t('webservice.dirList')">
                <el-switch v-model="ch.static.dirList" />
              </el-form-item>
              <p class="mt-subtle hint-block">{{ t('webservice.dirListHint') }}</p>
            </template>

            <!-- 后端：重定向 / 跳转 -->
            <template v-else>
              <el-form-item :label="t('webservice.redirectTarget')">
                <el-input v-model="ch.redirect.target" :placeholder="t('webservice.redirectHint')" />
              </el-form-item>
              <div class="grid3">
                <el-form-item :label="t('webservice.redirectCode')">
                  <el-select v-model="ch.redirect.code" style="width: 100%">
                    <el-option label="301" :value="301" />
                    <el-option label="302" :value="302" />
                    <el-option label="307" :value="307" />
                    <el-option label="308" :value="308" />
                  </el-select>
                </el-form-item>
                <el-form-item :label="t('webservice.keepPath')">
                  <el-switch v-model="ch.redirect.keepPath" />
                </el-form-item>
                <el-form-item :label="t('webservice.keepQuery')">
                  <el-switch v-model="ch.redirect.keepQuery" />
                </el-form-item>
              </div>
            </template>

            <div class="section-box">
              <div class="section-title">{{ t('webservice.proxyOptions') }}</div>
              <div class="grid3">
                <el-form-item :label="t('webservice.tls')">
                  <el-switch v-model="ch.tls" @change="(v: any) => onTLSChange(ch, Boolean(v))" />
                </el-form-item>
                <el-form-item v-if="ch.tls" :label="t('webservice.tlsMinVersion')">
                  <el-select v-model="ch.tlsMinVersion" style="width: 100%">
                    <el-option :label="t('webservice.tlsVersionAuto')" value="" />
                    <el-option label="TLS 1.0" value="1.0" />
                    <el-option label="TLS 1.1" value="1.1" />
                    <el-option label="TLS 1.2" value="1.2" />
                    <el-option label="TLS 1.3" value="1.3" />
                  </el-select>
                </el-form-item>
                <el-form-item v-if="ch.tls" :label="t('webservice.hsts')">
                  <el-switch v-model="ch.hsts" />
                </el-form-item>
              </div>
              <!-- 强制 HTTPS：启用 TLS 后由系统置真并锁定（后端 normalizeWebService 同样兜底），
                   未启用 TLS 时才可手动开启——那正是"80 端口跳 443"要用的场景。 -->
              <el-form-item :label="t('webservice.redirectHttps')">
                <el-switch v-model="ch.redirectHttps" :disabled="ch.tls" />
              </el-form-item>
              <p class="mt-subtle hint-block">
                {{ ch.tls ? t('webservice.redirectHttpsLocked') : t('webservice.redirectHttpsHint') }}
              </p>
              <!-- 采信上游代理的协议头：只在未启用 TLS 时有意义（启用后本机连接本身就是 HTTPS）。 -->
              <el-form-item v-if="!ch.tls" :label="t('webservice.trustProxyHeaders')">
                <el-switch v-model="ch.trustProxyHeaders" />
              </el-form-item>
              <p v-if="!ch.tls" class="mt-subtle hint-block">{{ t('webservice.trustProxyHeadersHint') }}</p>

              <!-- 访问认证：仅在该子项启用 TLS 后出现（明文 HTTP 上传口令等于直接暴露）。
                   关闭 TLS 时 onTLSChange 会一并关掉本开关，但账号与已存的口令哈希保留。 -->
              <template v-if="ch.tls">
                <el-form-item :label="t('webservice.basicAuth')">
                  <el-switch v-model="ch.access.basicAuth" />
                </el-form-item>
                <div v-if="ch.access.basicAuth" class="grid2">
                  <el-form-item :label="t('webservice.basicAuthUser')">
                    <el-input v-model="ch.access.basicAuthUser" autocomplete="off" />
                  </el-form-item>
                  <el-form-item :label="t('webservice.basicAuthPass')">
                    <el-input
                      v-model="basicPassDraft[ch.id]"
                      type="password"
                      show-password
                      autocomplete="new-password"
                      :placeholder="
                        ch.access.basicAuthPass
                          ? t('webservice.basicAuthPassSet')
                          : t('webservice.basicAuthPassNew')
                      "
                    />
                  </el-form-item>
                </div>
                <p class="mt-subtle hint-block">{{ t('webservice.basicAuthHint') }}</p>
              </template>
            </div>

            <div class="child-foot">
              <el-button size="small" type="danger" text :icon="Delete" @click="removeChild(ci)">
                {{ t('webservice.child') }} · {{ t('common.delete') }}
              </el-button>
            </div>
          </el-collapse-item>
        </el-collapse>
        </div>
      </el-form>

      <template #footer>
        <el-button @click="r.dialogVisible.value = false">{{ t('common.cancel') }}</el-button>
        <el-button type="primary" :loading="r.saving.value" @click="saveParent">{{ t('common.save') }}</el-button>
      </template>
    </el-dialog>

    <!-- 连接日志对话框 -->
    <el-dialog v-model="logsVisible" :title="t('webservice.logsTitle')" width="min(1000px, 94vw)" append-to-body :close-on-click-modal="false">
      <p class="mt-subtle hint-block">{{ logsTitle }}</p>
      <el-table :data="logsData" v-loading="logsLoading" size="small" :empty-text="t('webservice.noLogs')">
        <el-table-column :label="t('webservice.logTime')" width="170">
          <template #default="{ row }">{{ fmtLogTime(row.time) }}</template>
        </el-table-column>
        <el-table-column :label="t('webservice.logRemote')" width="150">
          <template #default="{ row }">
            <span v-if="row.remote" class="ws-log-ip">{{ row.remote }}</span>
            <span v-else class="mt-subtle">—</span>
          </template>
        </el-table-column>
        <el-table-column :label="t('webservice.logReq')" width="110">
          <template #default="{ row }">
            <span :class="{ 'ws-log-denied': row.event === 'denied', 'ws-log-error': row.event === 'error', 'ws-log-probe': row.event === 'probe' }">{{ row.method }}</span>
          </template>
        </el-table-column>
        <el-table-column :label="t('webservice.logStatus')" width="110" align="center">
          <template #default="{ row }">
            <el-tag size="small" :type="statusInfo(row).type" effect="light">{{ statusInfo(row).text }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column :label="t('webservice.logReason')" min-width="320">
          <template #default="{ row }">
            <!-- 探测成功（event=probe 且无 reason）：显示绿色「连接正常」与「结果」列的成功标签呼应 -->
            <span v-if="row.event === 'probe' && !row.reason" class="ws-log-reason-ok">{{ t('webservice.logBackendOk') }}</span>
            <span v-else-if="row.reason" class="ws-log-reason">{{ row.reason }}</span>
            <span v-else class="mt-subtle">—</span>
          </template>
        </el-table-column>
        <el-table-column :label="t('webservice.logDur')" width="90" align="right">
          <template #default="{ row }">{{ row.ms }}</template>
        </el-table-column>
      </el-table>
    </el-dialog>
  </PageCard>
</template>

<style scoped>
.parent-block {
  padding: 14px 16px;
  margin-bottom: 16px;
  border-radius: 12px;
}
.parent-head {
  display: flex;
  align-items: center;
  gap: 10px;
  /* 允许换行，且不挑阈值：这一行平铺开要 590 像素上下，宽度不够时最后那组操作自己落到
   * 第二行。不放开的话，标签和按钮都是 nowrap、压不动，先被压扁的是名字——它会缩成
   * 一个字宽的竖条，而操作照样溢出到屏幕外。 */
  flex-wrap: wrap;
}
/* 名字是这一行里唯一压得动的东西，长了就截断。
 * min-width: 0 必须写：flex 项默认不会小于自身内容宽度，少了它截断根本不生效。 */
.pname {
  font-size: 15px;
  min-width: 0;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}
/* 两个标签包一层：窄屏要把它们整组挪到第二行，散着放只会各自单独换行。 */
.parent-meta {
  display: flex;
  align-items: center;
  gap: 10px;
  flex-wrap: wrap;
}
/* 换到第二行时靠右，跟宽屏时按钮所在的位置一致。 */
.parent-actions {
  display: flex;
  align-items: center;
  gap: 10px;
  margin-left: auto;
}
.spacer {
  flex: 1;
}
.disabled-hint {
  font-size: 12px;
  margin: 8px 0 0;
}
.child-table {
  margin-top: 12px;
  background: transparent;
}
/* 列表中的前端/后端地址改为可点击链接：点击新增页签打开对应地址。 */
.addr-links {
  display: flex;
  flex-direction: column;
  gap: 2px;
  word-break: break-all;
}
.addr-link {
  color: var(--el-color-primary);
  text-decoration: none;
}
.addr-link:hover {
  text-decoration: underline;
}
/* 访问失败时链接状态红色闪烁（闪缩），与日志 ERR 状态对应。 */
@keyframes ws-blink {
  0%, 100% { opacity: 1; }
  50% { opacity: 0.25; }
}
.blink {
  animation: ws-blink 1s ease-in-out infinite;
}
.child-panel-title {
  font-weight: 600;
}
.child-foot {
  display: flex;
  justify-content: flex-end;
  margin-top: 4px;
}
.grid2 {
  display: grid;
  grid-template-columns: minmax(0, 1fr) minmax(0, 1fr);
  gap: 0 16px;
}
.grid3 {
  display: grid;
  grid-template-columns: repeat(3, minmax(0, 1fr));
  gap: 0 12px;
}
.grid4 {
  display: grid;
  grid-template-columns: minmax(0, 2fr) repeat(3, minmax(0, 1fr));
  gap: 0 12px;
}
.row {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 10px 12px;
  margin-bottom: 10px;
  border-radius: 8px;
}
.back-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 10px;
}
.hint-block {
  font-size: 12px;
  margin: -4px 0 10px;
}
/* 连接日志：来源列 IP 淡蓝（与总览程序日志一致），请求列仅事件类型；被 IP 规则拒绝的行整格标红。 */
.ws-log-ip {
  color: var(--ws-ip-color);
  font-weight: 600;
}
/* 被 IP 规则拒绝的行整格标红（跟随主题明暗），与「连接/错误」明显区分。 */
.ws-log-denied {
  color: var(--ws-denied-color);
  font-weight: 600;
}
/* 上游错误（502/500 等）的「请求」列标注为告警橙，与「拒绝（红）」区分。 */
.ws-log-error {
  color: var(--el-color-warning);
  font-weight: 600;
}
/* 周期主动探测的「动作」列标注为蓝色，与真实访问事件（连接/断开/错误/拒绝）明显区分。 */
.ws-log-probe {
  color: var(--el-color-primary);
  font-weight: 600;
}
/* 拒绝 / 错误的具体原因：跟随主题的可读强调色，长文本自动换行。 */
.ws-log-reason {
  color: var(--ws-denied-color);
  font-size: 12px;
  word-break: break-all;
}
/* 探测成功时的「后端状态」：绿色「连接正常」，与「结果」列的成功标签呼应。 */
.ws-log-reason-ok {
  color: var(--el-color-success);
  font-size: 12px;
  font-weight: 600;
}
/* 粗边框分段：父项 / 子项 / 安全设置 用统一的分段容器。 */
.section-box {
  border: 2px solid var(--mt-primary);
  border-radius: var(--mt-card-radius, 14px);
  padding: 14px 16px 6px;
  margin-bottom: 16px;
}
.section-title {
  font-size: 14px;
  font-weight: 650;
  color: var(--mt-primary);
  margin-bottom: 10px;
}
.section-head {
  display: flex;
  justify-content: flex-end;
  align-items: center;
  gap: 10px;
  margin-bottom: 4px;
}
/* 子项数上限那句话：与按钮同一行，字号压小，只在需要时才看。 */
.child-cap {
  font-size: 12px;
}
/* IP 过滤录入框：加高，便于一次性粘贴多个 / 范围 IP。 */
.ip-large {
  width: 100%;
}
.ip-large :deep(.tag-input) {
  min-height: 72px;
  align-items: flex-start;
  align-content: flex-start;
  padding-top: 8px;
}

/* 窄屏：父项那一行排成两行——第一行「开关 + 名字 + 更多」，第二行两个标签。
 * 平铺时这一行要 531 像素，而窄屏下它只有 200 上下。换行本身由基础样式那边的
 * flex-wrap 负责，这里只管这一档特有的两件事：三个按钮换成一个「更多」（那一步在
 * RowActions 里，300 像素的三联排在 200 里塞不下），以及把标签组整组挪到第二行——
 * 纯靠自然换行的话第一行只放得下开关和名字，标签和「更多」各占一行，一共三行。
 * 改这里的 640 要一并改 useNarrow 的阈值。 */
@media (max-width: 640px) {
  .parent-block {
    /* 左右各让出 6 像素给内容：两个标签并排正好差这么点就要折成两行。 */
    padding: 12px 10px;
  }
  /* 名字占满第一行的剩余宽度（截断规则在基础样式里）。
   * 基准宽度必须写 0：flex 换行是按基准宽度排的，写 auto 就等于按名字的完整文字宽去排，
   * 「更多」当场被挤到第二行、还只能靠左，父项行凭空多出一行。 */
  .pname {
    flex: 1 1 0;
  }
  /* order 把标签组排到「更多」之后，width 让它独占第二行。 */
  .parent-meta {
    order: 1;
    width: 100%;
  }
  /* 名字已经在撑开剩余宽度，占位符多余；留着它会把「更多」挤下去。 */
  .spacer {
    display: none;
  }
}

/* 窄屏两档：列越多越早收。三联排与四联排里塞的是端口、协议这类短字段，
 * 但标签是中文，一栏不足 160 像素就要折两三行；两联排能多撑一档。 */
@media (max-width: 640px) {
  .grid3,
  .grid4 {
    grid-template-columns: minmax(0, 1fr);
  }
}
@media (max-width: 560px) {
  .grid2 {
    grid-template-columns: minmax(0, 1fr);
  }
}
</style>
