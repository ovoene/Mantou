<script setup lang="ts">
import { ref, reactive, computed, onActivated, onDeactivated, onBeforeUnmount, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import { ElMessage, ElMessageBox } from 'element-plus'
import { Plus } from '@element-plus/icons-vue'
import PageCard from '@/components/PageCard.vue'
import RichText from '@/components/RichText.vue'
import RowActions from '@/components/RowActions.vue'
import {
  actions,
  type GfwConfig,
  type GfwPreset,
  type GfwUpdateReq,
  type GfwDenyResp,
  type GfwListEntry,
  type GfwListName,
  type GfwAddPlan,
  type FirewallBan,
} from '@/api/resources'
import { fmtTime, fmtBytes } from '@/composables/useResource'
import { useNarrow } from '@/composables/useNarrow'
import { gfwLevelLabel } from '@/composables/gfwText'
import { splitIpListText } from '@/composables/ipListText'

const { t } = useI18n()

// 窄屏下表单标签改到字段上方（与设置页同一条理由：内容区太窄时右置标签会把字段挤成一条缝）。
const narrow = useNarrow()
const labelPos = computed(() => (narrow.value ? 'top' : 'right'))

// labelWidth 标签列宽度。写成常量而不是散在两处模板里：保存按钮那一行不在 el-form 里，
// 要靠同一个数字缩进才能和上面各字段的输入框对齐（见 .save-row 的 padding-left）。
//
// 132px 是按最长标签定的——中文最长 4 字（约 56px），英文 "Detection level" / "Regular window"
// 约 105px，加上 el-form-item 标签自带的 12px 右内边距。给窄了英文标签会折成两行，
// 标签盒子随之变高，于是"文字和框不齐平"。
const labelWidth = '132px'
const contentIndent = computed(() => (narrow.value ? '0' : labelWidth))

// 首屏是否已经拿到服务端配置。配置项都带硬编码初值，数据回来前先用一层 loading 盖住，
// 而不是 v-if 销毁重建——否则切页回来又得从零挂载，把 keep-alive 的收益抵消掉。
const loaded = ref(false)
const saving = ref(false)
const activeTab = ref('settings')

// defaultGfw 数据回来之前的占位值。**enabled 必须是 false**，与服务端的默认值一致
// （见 config.defaultGlobalFirewall）：这里写 true 的话，全新安装的用户打开本页会看到
// 一个"已启用"的开关，而服务端其实是关着的——他若不点保存就一直以为自己受保护。
// 其余数值取均衡档，只为占位；load() 会用服务端的值整份覆盖。
function defaultGfw(): GfwConfig {
  return {
    enabled: false,
    level: 'balanced',
    allowIps: [],
    denyIps: [],
    autoBan: true,
    windowSeconds: 60,
    windowLimit: 12,
    burstSeconds: 3,
    burstLimit: 4,
    banMinutes: 120,
    memoryMB: 5,
  }
}
const cfg = reactive<GfwConfig>(defaultGfw())

// 两张名单的表格行（地址 + 备注 + 加入时间 + 来源）。
//
// 名单的增删**不**走「设置」页那个保存按钮：每一次添加 / 删除都直接调服务端的专用口子，
// 读—改—写在配置写锁里完成（同「加入黑名单」）。原先的文本框 + 整体 PUT 有两个毛病：
// 期间别处加的条目会被整张替换抹掉；以及改了名单却忘了点保存，看上去加了、实际没生效。
const listNames: GfwListName[] = ['allow', 'deny']
const entries = reactive<Record<GfwListName, GfwListEntry[]>>({ allow: [], deny: [] })

// 额度上限与预设档位表都由后端下发：表单上的"最多 N 条""最大 M 分钟"以及各档位的数值，
// 必须和服务端真正用的那一份同源。前端自己抄一份的代价是两边可以各改各的，
// 而且没人会发现——界面上显示的档位数值与实际执行的可以完全不同。
const limits = reactive<{
  maxIps: number
  maxBatch: number
  maxNoteRunes: number
  maxMemoryMB: number
  maxBanMinutes: number
  minWindowSeconds: number
  maxWindowSeconds: number
  minLimit: number
  maxLimit: number
  levels: string[]
  presets: GfwPreset[]
}>({
  maxIps: 256,
  maxBatch: 1024,
  maxNoteRunes: 64,
  maxMemoryMB: 15,
  maxBanMinutes: 10080,
  minWindowSeconds: 1,
  maxWindowSeconds: 3600,
  minLimit: 1,
  maxLimit: 100000,
  levels: ['loose', 'balanced', 'strict', 'custom'],
  presets: [],
})

// 档位是否为「自定义」。只有它才允许手填数值：其余档位的数值由服务端按档位重写
// （见 config.normalizeGlobalFirewall），让用户在那里输入等于让他改一个不会生效的数。
const isCustom = computed(() => cfg.level === 'custom')

// maxBanDays 封禁时长上限折算成天，只用于说明文案。
//
// 上限是 10080 分钟，而"10080 分钟"这个数字读不出量级——用户想知道的是"能封多久"。
// 从 limits.maxBanMinutes 折算而不是在语言包里写死"7 天"：上限由后端下发，
// 写死就意味着改了常量之后两个语言包里各有一处会悄悄对不上。
// 取一位小数再去掉多余的 ".0"，于是整天数显示成 7 而不是 7.0。
const maxBanDays = computed(() => {
  const d = limits.maxBanMinutes / 1440
  return d >= 1 ? String(Math.round(d * 10) / 10) : d.toFixed(2)
})

// levelLabel 档位的译名。用 composables/gfwText 里那一份，与两个业务页顶部的状态条同源：
// 各自写一份的话，"均衡"在模块页和状态条上能显示成两个不同的词，且不会有任何报错。
function levelLabel(level: string): string {
  return gfwLevelLabel(t, level)
}

// levelDesc 档位下方那行说明：把该档的实际数值念出来。
// 数值取自后端下发的预设表，因此"说明里写的"与"选中后填进去的"必然一致。
function levelDesc(level: string): string {
  const key = `gfw.levelPreset${level.charAt(0).toUpperCase()}${level.slice(1)}`
  const p = limits.presets.find((x) => x.level === level)
  if (!p) return t(key) // custom 没有预设，文案里也没有数值占位
  return t(key, {
    ws: p.windowSeconds,
    wl: p.windowLimit,
    bs: p.burstSeconds,
    bl: p.burstLimit,
    bm: p.banMinutes,
  })
}

// onLevelChange 换档位时**立刻**把该档的预设数值写进表单。
//
// 这是"点了档位却什么都不变"的前端一半：服务端已经改成"档位是权威值、保存时按档位重写数值"，
// 但用户在点下单选钮的那一刻看不到任何变化，只能保存完再刷新才知道自己选了什么。
// 用 @change 而不是 watch(cfg.level)：load() 也会写 cfg.level，watch 会连带把服务端刚返回的
// 数值又覆盖一遍——对预设档位是同值覆盖（无害但多余），对将来任何"服务端存的与预设不同"
// 的情形则是把真实值悄悄改掉。只在用户真的点了的时候才动数值。
function onLevelChange(level: string | number | boolean | undefined) {
  const p = limits.presets.find((x) => x.level === level)
  if (!p) return // custom：保留用户当前填的数值，让他从这一组开始改
  cfg.windowSeconds = p.windowSeconds
  cfg.windowLimit = p.windowLimit
  cfg.burstSeconds = p.burstSeconds
  cfg.burstLimit = p.burstLimit
  cfg.banMinutes = p.banMinutes
}

// setEntries 用服务端回来的整份名单刷新表格，并同步 cfg 里的地址数组。
//
// 老版本的后端没有 allowEntries / denyEntries，只有地址数组：那时按"没有备注、时间不详"补齐，
// 而不是让表格空着——空着会让人以为名单被清掉了。
function setEntries(name: GfwListName, rows: GfwListEntry[] | undefined, ips?: string[]) {
  const list = Array.isArray(rows)
    ? rows
    : (Array.isArray(ips) ? ips : []).map((ip) => ({ ip, note: '', addedAt: 0, source: '' }))
  entries[name] = list
  if (name === 'allow') cfg.allowIps = list.map((e) => e.ip)
  else cfg.denyIps = list.map((e) => e.ip)
}

// 内存占用与上限（自动封禁页的度量卡用）。
const memUsedBytes = ref(0)
const memLimitMB = ref(0)

// 当前封禁名单。total 与 items.length 可能不等（后端按 limit 截断）。
const bans = ref<FirewallBan[]>([])
const banTotal = ref(0)
const bansLoading = ref(false)

async function load() {
  // 不在这里把 loaded 置回 false：loaded 管的是「首屏」——第一次拿到配置之前用一层加载中盖住。
  // 之后每次进页面、保存后重拉，画面上已经是上一份配置，原地换成新的即可；
  // 原先每次都置回 false，于是每次点进本页都整页盖一层遮罩、闪一下。
  try {
    const res = await actions.globalFirewall()
    const c = res.config
    cfg.enabled = !!c.enabled
    cfg.level = c.level || 'balanced'
    cfg.allowIps = Array.isArray(c.allowIps) ? c.allowIps : []
    cfg.denyIps = Array.isArray(c.denyIps) ? c.denyIps : []
    cfg.autoBan = c.autoBan !== false
    cfg.windowSeconds = typeof c.windowSeconds === 'number' ? c.windowSeconds : 60
    cfg.windowLimit = typeof c.windowLimit === 'number' ? c.windowLimit : 12
    cfg.burstSeconds = typeof c.burstSeconds === 'number' ? c.burstSeconds : 3
    cfg.burstLimit = typeof c.burstLimit === 'number' ? c.burstLimit : 4
    cfg.banMinutes = typeof c.banMinutes === 'number' ? c.banMinutes : 120
    cfg.memoryMB = typeof c.memoryMB === 'number' ? c.memoryMB : 5
    setEntries('allow', c.allowEntries, cfg.allowIps)
    setEntries('deny', c.denyEntries, cfg.denyIps)
    if (res.limits) {
      const l = res.limits
      if (l.maxIps > 0) limits.maxIps = l.maxIps
      if (l.maxBatch > 0) limits.maxBatch = l.maxBatch
      if (l.maxNoteRunes > 0) limits.maxNoteRunes = l.maxNoteRunes
      if (l.maxMemoryMB > 0) limits.maxMemoryMB = l.maxMemoryMB
      if (l.maxBanMinutes > 0) limits.maxBanMinutes = l.maxBanMinutes
      if (l.minWindowSeconds > 0) limits.minWindowSeconds = l.minWindowSeconds
      if (l.maxWindowSeconds > 0) limits.maxWindowSeconds = l.maxWindowSeconds
      if (l.minLimit > 0) limits.minLimit = l.minLimit
      if (l.maxLimit > 0) limits.maxLimit = l.maxLimit
      if (Array.isArray(l.levels) && l.levels.length) limits.levels = l.levels
      if (Array.isArray(l.presets)) limits.presets = l.presets
    }
    memUsedBytes.value = res.memory?.usedBytes ?? 0
    memLimitMB.value = res.memory?.limitMB ?? cfg.memoryMB
    await loadBans()
  } catch (e: any) {
    ElMessage.error(e?.message || t('gfw.loadFailed'))
  } finally {
    loaded.value = true
  }
}

// 保存服务防护配置。后端按"缺省即沿用当前值"合并后，再规范化、校验、落盘。
// 落盘会整体替换快照指针，inboundfw 的名单缓存据此自动失效，下一次判定即读到新值。
//
// **不带**两张名单：名单由白名单 / 黑名单页签逐条增删、当场落盘。这里带上的话，
// 带的就是打开页面那一刻的旧名单，会把期间别处（另一个标签页、「加入黑名单」）加的条目整体抹掉。
async function save() {
  const payload: GfwUpdateReq = {
    enabled: cfg.enabled,
    level: cfg.level,
    autoBan: cfg.autoBan,
    windowSeconds: cfg.windowSeconds,
    windowLimit: cfg.windowLimit,
    burstSeconds: cfg.burstSeconds,
    burstLimit: cfg.burstLimit,
    banMinutes: cfg.banMinutes,
    memoryMB: cfg.memoryMB,
  }
  saving.value = true
  try {
    await actions.updateGlobalFirewall(payload)
    ElMessage.success(t('common.saved'))
    // 重新拉一次：档位会被服务端按预设重写数值，不重拉的话表单上还是提交前的那组数。
    await load()
  } catch (e: any) {
    ElMessage.error(e?.message || t('common.saveFailed'))
  } finally {
    saving.value = false
  }
}

async function loadBans() {
  bansLoading.value = true
  try {
    const res = await actions.globalFirewallBans()
    bans.value = res.items || []
    banTotal.value = res.total ?? 0
    if (typeof res.now === 'number' && res.now > 0) clockSkew = res.now - Math.floor(Date.now() / 1000)
  } catch {
    /* 只读展示，拉不到不该打断整页 */
  } finally {
    bansLoading.value = false
    lastBansLoad = Date.now()
  }
}

// ---------- 「剩余」一列的倒计时 ----------
//
// 到期时间是服务端的钟，浏览器的钟可能快几分钟或慢几分钟：直接拿 Date.now() 去减，
// 倒计时会整体偏掉。clockSkew 是每次拉名单时服务端时间与本机时间的差，计算剩余时先补上。
let clockSkew = 0
const nowSec = ref(Math.floor(Date.now() / 1000))
let tickTimer: number | undefined
let lastBansLoad = 0

// 只在「自动封禁」页签可见时走秒：别的页签用不到它，后台每秒触发一次重渲染没有意义。
function startTick() {
  if (tickTimer !== undefined) return
  nowSec.value = Math.floor(Date.now() / 1000) + clockSkew
  tickTimer = window.setInterval(() => {
    nowSec.value = Math.floor(Date.now() / 1000) + clockSkew
    // 有条目走到 0 就重拉一次：到期的封禁服务端已经不算了，表格上不该还挂着它。
    // 至少隔 5 秒：同一秒里到期好几条时只拉一次，服务端那边的清扫也有个落地的时间。
    if (!bansLoading.value && Date.now() - lastBansLoad > 5000 && bans.value.some((b) => b.until <= nowSec.value)) {
      loadBans()
    }
  }, 1000)
}
function stopTick() {
  if (tickTimer !== undefined) window.clearInterval(tickTimer)
  tickTimer = undefined
}

// remainText 剩余时长说成人话：天+小时 / 小时+分 / 分+秒 / 秒，只留两级——
// "1 小时 52 分 7 秒"多出来的那一级只会让这一列每秒都在跳，读起来反而费劲。
function remainText(until: number): string {
  const left = until - nowSec.value
  if (left <= 0) return t('gfw.banExpired')
  const d = Math.floor(left / 86400)
  const h = Math.floor((left % 86400) / 3600)
  const m = Math.floor((left % 3600) / 60)
  const s = left % 60
  if (d > 0) return t('gfw.banRemainD', { d, h })
  if (h > 0) return t('gfw.banRemainH', { h, m })
  if (m > 0) return t('gfw.banRemainM', { m, s })
  return t('gfw.banRemainS', { s })
}

// reasonText / triggerText 「触发原因」一列：信号 + 越过的那道线（"突发：3 秒内 4 次"）。
// 触发数值是封禁那一刻记下的，不是现读的配置——之后改了档位，这里写的仍是当初那道线。
function reasonText(b: FirewallBan): string {
  if (b.reason === 'tls-handshake' || !b.reason) return t('gfw.banReasonTls')
  return b.reason
}
function triggerText(b: FirewallBan): string {
  const v = { s: b.triggerSeconds ?? 0, n: b.triggerLimit ?? 0 }
  if (b.trigger === 'burst') return t('gfw.banTriggerBurst', v)
  if (b.trigger === 'window') return t('gfw.banTriggerWindow', v)
  return ''
}

async function unban(ip: string) {
  try {
    await actions.clearGlobalFirewallBans(ip)
    ElMessage.success(t('gfw.banUnbanOk'))
    await loadBans()
  } catch (e: any) {
    ElMessage.error(e?.message || t('common.saveFailed'))
  }
}

async function clearBans() {
  try {
    await ElMessageBox.confirm(t('gfw.banClearConfirm'), '', {
      confirmButtonText: t('common.confirm'),
      cancelButtonText: t('common.cancel'),
      type: 'warning',
    })
  } catch {
    return
  }
  try {
    const res = await actions.clearGlobalFirewallBans()
    ElMessage.success(t('gfw.banClearOk', { n: res.cleared ?? 0 }))
    await loadBans()
  } catch (e: any) {
    ElMessage.error(e?.message || t('common.saveFailed'))
  }
}

// 「加入黑名单」= 把一条临时封禁升级成永久的拒绝名单条目。
//
// 走后端专用口子（POST /global-firewall/bans/deny）而不是通用的名单添加口子：
// 服务端那条口子会在同一次请求里解除对应的临时封禁、并给条目打上"来自自动封禁"的来源标记，
// 不会留下"名单加上了、封禁还挂着"的中间态。
const denying = ref(false)

// askDeny 一键升级前的确认，返回用户是否继续。
//
// 单个升级**不弹**：与同一行的「解除」同口径——一次点击对应一条记录，后果看得见、
// 也能在黑名单页签里删回去，为它加一次确认只是给常用操作加摩擦。
// 批量升级一定要确认：一次可能写进几十条永久条目，而共用出口 IP 的场合会连带把人关在门外。
// （原先这里还要提醒"黑名单页签有未保存的编辑会被覆盖"——名单改成逐条当场落盘之后，
// 已经没有"未保存的名单"这回事了。）
async function askDeny(n: number): Promise<boolean> {
  try {
    await ElMessageBox.confirm(t('gfw.banDenyAllConfirm', { n }), '', {
      confirmButtonText: t('common.confirm'),
      cancelButtonText: t('common.cancel'),
      type: 'warning',
    })
    return true
  } catch {
    return false
  }
}
// applyDenyResult 用服务端返回的整份黑名单刷新表格，并把结果说清楚。
//
// 只动黑名单这一张表，**不**整页 load()：用户可能正在设置页改着档位和阈值，
// 一次 load() 会把那些还没保存的改动全部冲掉——为了刷新一张名单而丢掉别处的输入不划算。
function applyDenyResult(res: GfwDenyResp) {
  setEntries('deny', res.denyEntries, res.denyIps)
  const stat = {
    added: res.added ?? 0,
    skipped: res.skipped ?? 0,
    unbanned: res.unbanned ?? 0,
    max: res.maxIps || limits.maxIps,
  }
  // 截断必须报出来：悄悄丢掉后半截，用户会以为一键之后所有来源都封死了。
  if (res.capped) ElMessage.warning(t('gfw.banDenyCapped', stat))
  else ElMessage.success(t('gfw.banDenyOk', stat))
}

// denyOne 单个加入黑名单。
async function denyOne(ip: string) {
  if (denying.value) return
  denying.value = true
  try {
    applyDenyResult(await actions.denyGlobalFirewallBans({ ip }))
    await loadBans()
  } catch (e: any) {
    ElMessage.error(e?.message || t('common.saveFailed'))
  } finally {
    denying.value = false
  }
}

// denyAll 一键加入黑名单：升级当前**全部**生效封禁，不止界面上列出的那些。
// 服务端按封禁表全量快照办事（界面只列前 gfwBanListLimit 条），所以确认文案里用的是
// banTotal 而不是 bans.length——说的数与实际发生的必须是一回事。
async function denyAll() {
  if (denying.value || bans.value.length === 0) return
  if (!(await askDeny(banTotal.value))) return
  denying.value = true
  try {
    applyDenyResult(await actions.denyGlobalFirewallBans({ all: true }))
    await loadBans()
  } catch (e: any) {
    ElMessage.error(e?.message || t('common.saveFailed'))
  } finally {
    denying.value = false
  }
}

// ---------------------------------------------------------------------------
// 白名单 / 黑名单：表格、删除、批量添加
// ---------------------------------------------------------------------------

// 各表当前勾选的行。删除之后服务端回来的是新名单，勾选要跟着清掉（见 removeEntries）。
const selected = reactive<Record<GfwListName, GfwListEntry[]>>({ allow: [], deny: [] })
const tableRefs: Partial<Record<GfwListName, { clearSelection: () => void }>> = {}
const listBusy = ref(false)

function listLabel(name: GfwListName): string {
  return t(name === 'allow' ? 'gfw.tabAllow' : 'gfw.tabDeny')
}

// removeEntries 删除几条，或 all=true 清空整张表。
//
// 只删一条时不确认：与「解除」同口径，一次点击对应一行，删错了重新添加即可。
// 删多条、清空要确认——尤其是黑名单，一次清空会让一批来源当场重新获得访问权。
async function removeEntries(name: GfwListName, ips: string[] | 'all') {
  if (listBusy.value) return
  const all = ips === 'all'
  const n = all ? entries[name].length : ips.length
  if (n === 0) return
  if (n > 1 || all) {
    const msg = all
      ? t(name === 'allow' ? 'gfw.listDeleteAllConfirmAllow' : 'gfw.listDeleteAllConfirmDeny', { n })
      : t('gfw.listDeleteSelectedConfirm', { n, list: listLabel(name) })
    try {
      await ElMessageBox.confirm(msg, '', {
        confirmButtonText: t('common.confirm'),
        cancelButtonText: t('common.cancel'),
        type: 'warning',
      })
    } catch {
      return
    }
  }
  listBusy.value = true
  try {
    const res = await actions.removeGlobalFirewallList(all ? { list: name, all: true } : { list: name, ips })
    setEntries(name, res.entries)
    tableRefs[name]?.clearSelection()
    selected[name] = []
    ElMessage.success(t('gfw.listDeleted', { n: res.removed ?? 0 }))
  } catch (e: any) {
    ElMessage.error(e?.message || t('common.saveFailed'))
  } finally {
    listBusy.value = false
  }
}

// ---------- 批量添加对话框 ----------
//
// 用户可以一次贴进一大段（每行一个、逗号分隔、甚至整段日志），前端负责拆，服务端负责判：
// 拆出来的每一条连同备注发去 dryRun，回来的分拣结果（可添加 / 已在名单 / 重复 / 无效 / 超额）
// 就是预览。真添加走同一个接口、同一个分拣函数，于是"预览说加 3 条"与实际结果不会对不上。
const addOpen = ref(false)
const addList = ref<GfwListName>('allow')
const addText = ref('')
const addNote = ref('')
const adding = ref(false)
const preview = ref<GfwAddPlan | null>(null)
const previewErr = ref('')
const checking = ref(false)
let previewSeq = 0
let previewTimer: number | undefined

const split = computed(() => splitIpListText(addText.value))
// 行内「# 备注」优先于对话框里那个公共备注：一行一行写清楚的，比统一填的那句更具体。
const addItems = computed(() =>
  split.value.items.map((it) => ({ ip: it.ip, note: it.note || addNote.value.trim() })),
)
const tooMany = computed(() => addItems.value.length > limits.maxBatch)
const canAdd = computed(
  () => !checking.value && !adding.value && !previewErr.value && !!preview.value && preview.value.added.length > 0,
)
// 无效条目最多列出这么多个，剩下的只报个数：贴了整段日志时，几百个红字只会把对话框撑爆。
const INVALID_SHOW = 20

// 「详细说明」的各条，顺序即显示顺序。
const explainKeys = [
  'gfw.explainWhat',
  'gfw.explainModules',
  'gfw.explainVsPanel',
  'gfw.explainDefends',
  'gfw.explainNotDefends',
  'gfw.explainOrder',
]

function openAdd(name: GfwListName) {
  addList.value = name
  addText.value = ''
  addNote.value = ''
  preview.value = null
  previewErr.value = ''
  addOpen.value = true
}

// 输入一变就先把按钮锁住（checking=true），再等 250ms 没有新输入才真的去问服务端。
// 不先锁的话，从"改了输入"到"新预览回来"之间，按钮上显示的还是上一版的条数，点下去加的却是新的。
watch([addText, addNote], () => {
  if (!addOpen.value) return
  window.clearTimeout(previewTimer)
  checking.value = true
  previewTimer = window.setTimeout(runPreview, 250)
})

async function runPreview() {
  const seq = ++previewSeq
  const items = addItems.value
  if (items.length === 0 || tooMany.value) {
    preview.value = null
    previewErr.value = tooMany.value ? t('gfw.addTooMany', { max: limits.maxBatch, n: items.length }) : ''
    checking.value = false
    return
  }
  try {
    const res = await actions.addGlobalFirewallList({ list: addList.value, items, dryRun: true })
    if (seq !== previewSeq) return // 已经有更新的一轮在路上，这一轮的结果作废
    preview.value = res.plan
    previewErr.value = ''
  } catch (e: any) {
    if (seq !== previewSeq) return
    preview.value = null
    previewErr.value = e?.message || t('common.loadFailed')
  } finally {
    if (seq === previewSeq) checking.value = false
  }
}

async function confirmAdd() {
  if (!canAdd.value) return
  const name = addList.value
  adding.value = true
  try {
    const res = await actions.addGlobalFirewallList({ list: name, items: addItems.value })
    setEntries(name, res.entries)
    const p = res.plan
    const parts = [t('gfw.addDone', { n: p.added.length })]
    if (p.existing.length) parts.push(t('gfw.addPartExisting', { n: p.existing.length }))
    if (p.capped.length) parts.push(t('gfw.addPartCapped', { n: p.capped.length, max: res.maxIps || limits.maxIps }))
    if (p.invalid.length) {
      // 写错的那几条留在输入框里，改好可以直接再点一次添加；加进去了的已经从输入框里拿掉。
      parts.push(t('gfw.addPartInvalid', { n: p.invalid.length }))
      addText.value = p.invalid.join('\n')
    } else {
      addOpen.value = false
    }
    const msg = parts.join(t('gfw.addPartSep'))
    if (p.invalid.length || p.capped.length) ElMessage.warning(msg)
    else ElMessage.success(msg)
  } catch (e: any) {
    ElMessage.error(e?.message || t('common.saveFailed'))
  } finally {
    adding.value = false
  }
}

// 切到「自动封禁」才去拉封禁名单：它是内存里随时在变的东西，要的是"打开时看到当下"，
// 而不是进页面时抓的那一眼。倒计时也只在这个页签上走。
watch(activeTab, (tab) => {
  if (tab === 'bans') {
    loadBans()
    startTick()
  } else {
    stopTick()
  }
})

// keep-alive 下 onActivated 首次挂载时也会触发，因此只挂它一个——与其余各模块页一致
// （Overview / WebServices / Certs … 都只写 onActivated）。再加一个 onMounted 的后果是
// 每次进页面都把 /api/global-firewall 与 /bans 各请求两遍。
onActivated(() => {
  load()
  if (activeTab.value === 'bans') startTick()
})
// 离开页面（keep-alive 只是隐藏、不销毁）时停表：否则这个页面在后台每秒重渲染一次。
onDeactivated(stopTick)
onBeforeUnmount(() => {
  stopTick()
  window.clearTimeout(previewTimer)
})
</script>

<template>
  <PageCard :title="t('gfw.title')">
    <template #actions>
      <!-- 滑动开关 + 标签：放在 card-hd 右侧，与「设置」页的入站防护同一套交互。
           它是表单的一部分，改完需点「保存」才生效（见下方 saveHint）。 -->
      <div class="hd-switch">
        <el-switch v-model="cfg.enabled" />
        <span class="sw-label">{{ cfg.enabled ? t('gfw.enabled') : t('gfw.disabled') }}</span>
      </div>
    </template>

    <div v-loading="!loaded">
      <p class="brief">{{ t('gfw.brief') }}</p>

      <el-tabs v-model="activeTab">
        <el-tab-pane :label="t('gfw.tabSettings')" name="settings" />
        <el-tab-pane :label="t('gfw.tabAllow')" name="allow" />
        <el-tab-pane :label="t('gfw.tabDeny')" name="deny" />
        <el-tab-pane :label="t('gfw.tabBans')" name="bans" />
      </el-tabs>

      <!-- 设置 -->
      <div v-show="activeTab === 'settings'">
        <!-- 每个字段的结构都是 el-form-item > .field（纵向）> 控件 + .field-hint。
             灰色说明一律在控件**下方**：el-form-item 的内容区是 flex 行，直接塞一个 <p>
             会变成控件右边的一个 flex 兄弟，于是说明贴在输入框右侧、把整行撑高，
             标签也就跟着不齐平了。套一层纵向容器之后，标签始终对齐第一行控件。 -->
        <el-form :label-width="labelWidth" :label-position="labelPos">
          <el-form-item :label="t('gfw.level')">
            <div class="field">
              <el-radio-group v-model="cfg.level" @change="onLevelChange">
                <el-radio v-for="lv in limits.levels" :key="lv" :value="lv">{{ levelLabel(lv) }}</el-radio>
              </el-radio-group>
              <p class="field-hint">{{ t('gfw.levelHint') }}</p>
              <p class="field-hint">{{ levelDesc(cfg.level) }}</p>
            </div>
          </el-form-item>

          <el-form-item :label="t('gfw.autoBan')">
            <div class="field">
              <el-switch v-model="cfg.autoBan" />
              <p class="field-hint">{{ t('gfw.autoBanHint') }}</p>
            </div>
          </el-form-item>

          <el-form-item :label="t('gfw.window')">
            <div class="field">
              <div class="num-row">
                <el-input-number
                  v-model="cfg.windowSeconds"
                  :min="limits.minWindowSeconds"
                  :max="limits.maxWindowSeconds"
                  :step="1"
                  :disabled="!isCustom || !cfg.autoBan"
                  style="width: 120px"
                />
                <span class="unit">{{ t('gfw.windowJoin') }}</span>
                <el-input-number
                  v-model="cfg.windowLimit"
                  :min="limits.minLimit"
                  :max="limits.maxLimit"
                  :step="1"
                  :disabled="!isCustom || !cfg.autoBan"
                  style="width: 120px"
                />
                <span class="unit">{{ t('gfw.unitTimes') }}</span>
              </div>
              <!-- 这里不再重复"数值被服务端按档位锁定、要手填请切自定义"那句话：
                   上面档位那一行的 levelHint 已经把这件事连同受影响的三行一起说清了，
                   紧挨着再说一遍只是把同一句话摊到两处。 -->
              <p class="field-hint">{{ t('gfw.windowHint') }}</p>
            </div>
          </el-form-item>

          <el-form-item :label="t('gfw.burst')">
            <div class="field">
              <div class="num-row">
                <el-input-number
                  v-model="cfg.burstSeconds"
                  :min="limits.minWindowSeconds"
                  :max="limits.maxWindowSeconds"
                  :step="1"
                  :disabled="!isCustom || !cfg.autoBan"
                  style="width: 120px"
                />
                <span class="unit">{{ t('gfw.windowJoin') }}</span>
                <el-input-number
                  v-model="cfg.burstLimit"
                  :min="limits.minLimit"
                  :max="limits.maxLimit"
                  :step="1"
                  :disabled="!isCustom || !cfg.autoBan"
                  style="width: 120px"
                />
                <span class="unit">{{ t('gfw.unitTimes') }}</span>
              </div>
              <p class="field-hint">{{ t('gfw.burstHint') }}</p>
            </div>
          </el-form-item>

          <el-form-item :label="t('gfw.banMinutes')">
            <div class="field">
              <div class="num-row">
                <el-input-number
                  v-model="cfg.banMinutes"
                  :min="1"
                  :max="limits.maxBanMinutes"
                  :step="1"
                  :disabled="!isCustom || !cfg.autoBan"
                  style="width: 150px"
                />
                <span class="unit">{{ t('gfw.unitMinutes') }}</span>
              </div>
              <p class="field-hint">{{ t('gfw.banMinutesHint', { max: limits.maxBanMinutes, days: maxBanDays }) }}</p>
            </div>
          </el-form-item>

          <el-form-item :label="t('gfw.memoryMB')">
            <div class="field">
              <div class="num-row">
                <el-input-number
                  v-model="cfg.memoryMB"
                  :min="1"
                  :max="limits.maxMemoryMB"
                  :step="1"
                  style="width: 130px"
                />
                <span class="unit">MB</span>
              </div>
              <p class="field-hint">{{ t('gfw.memoryHint') }}</p>
            </div>
          </el-form-item>
        </el-form>

        <!-- 保存行：缩进到与上面各输入框同一列（标签列宽度见 labelWidth），说明在按钮下方。
             不放进 el-form 里做一个空标签的 form-item：那会渲染出一个空的 <label>，
             读屏软件会念出一个没有内容的标签。 -->
        <div class="save-row" :style="{ paddingLeft: contentIndent }">
          <el-button type="primary" :loading="saving" @click="save">{{ t('common.save') }}</el-button>
          <p class="field-hint save-hint">{{ t('gfw.saveHint') }}</p>
        </div>
        <!-- 「来源自检」原先在这里，已移到「自动封禁」页签：它念的是实时封禁数据，
             与那一页的名单是同一份来源，放在设置页要么显示的是进页面时抓的旧值，
             要么得为它单独再拉一次。设置页因此不再需要一条分隔线（下方还有全局的那条）。 -->
      </div>

      <!-- 白名单 / 黑名单：两张表结构完全相同，用同一段模板按名单名渲染。
           增删当场落盘（见 removeEntries / confirmAdd），所以这两页没有保存按钮。 -->
      <div v-for="name in listNames" v-show="activeTab === name" :key="name">
        <div class="list-bar">
          <el-button :icon="Plus" @click="openAdd(name)">{{ t('gfw.listAdd') }}</el-button>
          <el-button
            type="danger"
            plain
            :disabled="selected[name].length === 0 || listBusy"
            @click="removeEntries(name, selected[name].map((e) => e.ip))"
          >
            {{ t('gfw.listDeleteSelected', { n: selected[name].length }) }}
          </el-button>
          <el-button type="danger" :disabled="entries[name].length === 0 || listBusy" @click="removeEntries(name, 'all')">
            {{ t('gfw.listDeleteAll') }}
          </el-button>
          <span class="field-hint list-count">{{ t('gfw.listCount', { n: entries[name].length, max: limits.maxIps }) }}</span>
        </div>
        <el-table
          :ref="(el: any) => (tableRefs[name] = el ?? undefined)"
          :data="entries[name]"
          row-key="ip"
          class="gfw-table"
          :empty-text="t(name === 'allow' ? 'gfw.listEmptyAllow' : 'gfw.listEmptyDeny')"
          @selection-change="(rows: GfwListEntry[]) => (selected[name] = rows)"
        >
          <el-table-column type="selection" width="44" />
          <el-table-column :label="t('gfw.listColIp')" min-width="190">
            <template #default="{ row }">
              <span class="mono">{{ row.ip }}</span>
            </template>
          </el-table-column>
          <el-table-column :label="t('gfw.listColNote')" min-width="170">
            <template #default="{ row }">
              <span v-if="row.note">{{ row.note }}</span>
              <span v-else-if="row.source === 'autoban'" class="muted">{{ t('gfw.listFromAutoBan') }}</span>
              <span v-else-if="row.source === 'legacy'" class="muted">{{ t('gfw.listLegacy') }}</span>
              <span v-else class="muted">—</span>
            </template>
          </el-table-column>
          <el-table-column :label="t('gfw.listColAddedAt')" min-width="170">
            <template #default="{ row }">
              <!-- 升级前就在名单里的条目：时间是升级那一刻补的（真实时间无从得知），灰显以示区别。 -->
              <span :class="{ muted: !row.addedAt || row.source === 'legacy' }">{{ fmtTime(row.addedAt) }}</span>
            </template>
          </el-table-column>
          <el-table-column :label="t('gfw.listColAction')" width="90">
            <template #default="{ row }">
              <el-button link type="primary" :disabled="listBusy" @click="removeEntries(name, [row.ip])">
                {{ t('gfw.listDelete') }}
              </el-button>
            </template>
          </el-table-column>
        </el-table>
        <p class="field-hint list-hint">
          <RichText :text="t(name === 'allow' ? 'gfw.allowHint' : 'gfw.denyHint', { max: limits.maxIps })" />
        </p>
      </div>

      <!-- 自动封禁 -->
      <div v-show="activeTab === 'bans'">
        <div class="metrics">
          <div class="metric"><b>{{ banTotal }}</b><span>{{ t('gfw.banActive') }}</span></div>
          <div class="metric"><b>{{ fmtBytes(memUsedBytes) }}</b><span>{{ t('gfw.banMemoryUsed') }}</span></div>
          <div class="metric"><b>{{ memLimitMB }} MB</b><span>{{ t('gfw.banMemoryLimit') }}</span></div>
        </div>
        <div class="storage-bar" style="margin: 14px 0">
          <el-button :loading="bansLoading" @click="loadBans">{{ t('common.refresh') }}</el-button>
          <!-- 一键加入黑名单：把当前全部生效封禁升级成永久拒绝名单条目。
               放在「解除全部封禁」左边——两个按钮的后果相反（一个放行、一个封死），
               危险色那个留在最右，手滑点到的那个就不会是不可逆的这一侧。 -->
          <el-button type="warning" :disabled="bans.length === 0 || denying" :loading="denying" @click="denyAll">
            {{ t('gfw.banDenyAll') }}
          </el-button>
          <el-button type="danger" :disabled="bans.length === 0" @click="clearBans">{{ t('gfw.banClearAll') }}</el-button>
          <span class="field-hint">
            {{ t('gfw.banTotal', { n: banTotal }) }}
            <template v-if="banTotal > bans.length">{{ t('gfw.banTruncated', { n: bans.length }) }}</template>
          </span>
        </div>
        <p class="field-hint" style="margin: 0 0 12px">
          <RichText :text="t('gfw.banDenyHint', { max: limits.maxIps })" />
        </p>
        <el-table :data="bans" row-key="ip" class="gfw-table" :empty-text="t('gfw.banEmpty')">
          <el-table-column :label="t('gfw.banColIp')" min-width="150">
            <template #default="{ row }">
              <span class="mono">{{ row.ip }}</span>
            </template>
          </el-table-column>
          <el-table-column :label="t('gfw.banColReason')" min-width="200">
            <template #default="{ row }">
              <div class="reason">
                <span>{{ reasonText(row) }}</span>
                <span v-if="triggerText(row)" class="muted">{{ triggerText(row) }}</span>
              </div>
            </template>
          </el-table-column>
          <el-table-column :label="t('gfw.banColRounds')" min-width="90">
            <template #default="{ row }">
              <!-- 累计被封 ≥2 轮：解封后又来，标橙，好和"误伤一次"分开。 -->
              <el-tag v-if="row.rounds > 1" size="small" type="warning" disable-transitions>{{ row.rounds }}</el-tag>
              <span v-else>{{ row.rounds }}</span>
            </template>
          </el-table-column>
          <el-table-column :label="t('gfw.banColBannedAt')" min-width="170">
            <template #default="{ row }">{{ fmtTime(row.bannedAt) }}</template>
          </el-table-column>
          <el-table-column :label="t('gfw.banColUntil')" min-width="170">
            <template #default="{ row }">{{ fmtTime(row.until) }}</template>
          </el-table-column>
          <el-table-column :label="t('gfw.banColRemain')" min-width="110">
            <template #default="{ row }">{{ remainText(row.until) }}</template>
          </el-table-column>
          <el-table-column :label="t('gfw.banColAction')" :width="narrow ? 96 : 170">
            <template #default="{ row }">
              <!-- 行内两个动作按同一条理由排序：升级（不可逆）在前，解除在后，
                   于是最右边那个是"放行"而不是"永久封死"。窄屏收进「更多」。 -->
              <RowActions>
                <el-button link type="warning" :disabled="denying" @click="denyOne(row.ip)">
                  {{ t('gfw.banDeny') }}
                </el-button>
                <el-button link type="primary" @click="unban(row.ip)">{{ t('gfw.banUnban') }}</el-button>
              </RowActions>
            </template>
          </el-table-column>
        </el-table>
        <p class="field-hint list-hint">
          <RichText :text="t('gfw.banTableHint')" />
        </p>

        <!-- 来源自检：它念的就是本页这份实时封禁数据——
             「服务防护确实看到了真实来源 IP 并已在拦截」这个信号，和名单放在一起才有对照。
             原先这里还列着"最近被拦截的 5 个来源"，名单改成表格之后就在正上方，不再重复列一遍。 -->
        <el-divider />
        <div class="selfcheck">
          <div class="sc-title">{{ t('gfw.selfCheck') }}</div>
          <p class="field-hint"><RichText :text="t('gfw.selfCheckHint')" /></p>
          <p v-if="banTotal > 0" class="field-hint"><RichText :text="t('gfw.selfCheckActive', { n: banTotal })" /></p>
          <p v-else class="field-hint"><RichText :text="t('gfw.selfCheckEmpty')" /></p>
        </div>
      </div>

      <!-- 详细说明：始终可见，与所属标签页无关（放在标签页内容之外）。
           关键词用 RichText 的标记上色（[ok:管] [no:不管] [b:…]），文案仍在语言包里。 -->
      <el-divider />
      <div class="callout">
        <h4>{{ t('gfw.explainTitle') }}</h4>
        <ul>
          <li v-for="k in explainKeys" :key="k"><RichText :text="t(k)" /></li>
        </ul>
      </div>
    </div>

    <!-- 批量添加对话框 -->
    <el-dialog
      v-model="addOpen"
      :title="t(addList === 'allow' ? 'gfw.addTitleAllow' : 'gfw.addTitleDeny')"
      width="min(580px, 94vw)"
      append-to-body
      :close-on-click-modal="false"
    >
      <el-form label-position="top" @submit.prevent>
        <el-form-item :label="t('gfw.addTextLabel')">
          <div class="field">
            <el-input
              v-model="addText"
              type="textarea"
              :rows="8"
              :placeholder="t('gfw.addTextPlaceholder')"
              spellcheck="false"
            />
            <p class="field-hint"><RichText :text="t('gfw.addTextHint', { max: limits.maxBatch })" /></p>
          </div>
        </el-form-item>
        <el-form-item :label="t('gfw.addNoteLabel')">
          <div class="field">
            <el-input
              v-model="addNote"
              :maxlength="limits.maxNoteRunes"
              show-word-limit
              :placeholder="t('gfw.addNotePlaceholder')"
            />
          </div>
        </el-form-item>
      </el-form>

      <!-- 预览：服务端 dryRun 的分拣结果。 -->
      <div class="add-preview">
        <span v-if="addItems.length === 0" class="field-hint">{{ t('gfw.addPreviewEmpty') }}</span>
        <span v-else-if="previewErr" class="err">{{ previewErr }}</span>
        <template v-else>
          <div class="stats">
            <span class="field-hint">{{ t('gfw.addPreviewTotal', { n: addItems.length }) }}</span>
            <template v-if="preview && !checking">
              <el-tag size="small" type="success" disable-transitions>{{ t('gfw.addStatAdd', { n: preview.added.length }) }}</el-tag>
              <el-tag v-if="preview.existing.length" size="small" type="info" disable-transitions>
                {{ t('gfw.addStatExisting', { n: preview.existing.length }) }}
              </el-tag>
              <el-tag v-if="preview.duplicate.length" size="small" type="info" disable-transitions>
                {{ t('gfw.addStatDuplicate', { n: preview.duplicate.length }) }}
              </el-tag>
              <el-tag v-if="preview.invalid.length" size="small" type="danger" disable-transitions>
                {{ t('gfw.addStatInvalid', { n: preview.invalid.length }) }}
              </el-tag>
              <el-tag v-if="preview.capped.length" size="small" type="warning" disable-transitions>
                {{ t('gfw.addStatCapped', { n: preview.capped.length }) }}
              </el-tag>
            </template>
            <span v-else class="field-hint">{{ t('gfw.addPreviewChecking') }}</span>
            <span v-if="split.ignored" class="field-hint">{{ t('gfw.addStatIgnored', { n: split.ignored }) }}</span>
          </div>
          <p v-if="preview && !checking && preview.invalid.length" class="field-hint invalid-line">
            {{ t('gfw.addInvalidList') }}
            <span class="mono err">{{ preview.invalid.slice(0, INVALID_SHOW).join('、') }}</span>
            <template v-if="preview.invalid.length > INVALID_SHOW">
              {{ t('gfw.addInvalidMore', { n: preview.invalid.length - INVALID_SHOW }) }}
            </template>
          </p>
          <p v-if="preview && !checking && preview.capped.length" class="field-hint">
            {{ t('gfw.addCappedHint', { max: limits.maxIps }) }}
          </p>
        </template>
      </div>

      <template #footer>
        <el-button @click="addOpen = false">{{ t('common.cancel') }}</el-button>
        <el-button type="primary" :loading="adding" :disabled="!canAdd" @click="confirmAdd">
          {{ t('gfw.addConfirm', { n: preview && !checking ? preview.added.length : 0 }) }}
        </el-button>
      </template>
    </el-dialog>
  </PageCard>
</template>

<style scoped>
.brief {
  color: var(--mt-text-soft);
  font-size: 13px;
  margin: 0 0 14px;
}
.hd-switch {
  display: flex;
  align-items: center;
  gap: 8px;
}
.sw-label {
  color: var(--mt-text-soft);
  font-size: 13px;
}
/* 字段容器：控件在上、灰色说明在下，纵向排列。
 *
 * 这一层是"说明不许贴在输入框右边"的实现：el-form-item 的内容区本身是
 * display:flex 的一行，说明直接放进去就成了控件右侧的兄弟节点，既把行撑高、
 * 让右置标签看起来与输入框错位，又在窄屏上把输入框挤成一条缝。
 * width:100% 让它吃满内容区，align-items:flex-start 保证控件不被拉伸。 */
.field {
  display: flex;
  flex-direction: column;
  align-items: flex-start;
  gap: 6px;
  width: 100%;
}
/* 灰色小字说明。统一用这一个类，不再用没有定义过的 .hint
 * （原先写的是 class="mt-subtle hint"，而 .hint 在本文件与全局样式里都不存在，
 * 于是说明与正文同样大小，看着像正文而不是注解）。 */
.field-hint {
  display: block;
  margin: 0;
  font-size: 12px;
  line-height: 1.6;
  color: var(--mt-text-subtle, #909399);
}
/* 数值行：输入框与单位同一行，纵向居中。 */
.num-row {
  display: flex;
  align-items: center;
  gap: 8px;
  flex-wrap: wrap;
}
.num-row .unit {
  color: var(--mt-text-soft);
  font-size: 13px;
}
/* 保存行：缩进到与上面各输入框同一列（内联样式给 padding-left = 标签列宽），
 * 说明在按钮下方而不是右边。 */
.save-row {
  margin-top: 4px;
  display: flex;
  flex-direction: column;
  align-items: flex-start;
  gap: 6px;
}
.save-hint {
  margin: 0;
}
.selfcheck {
  border: 1px dashed var(--mt-border, #dcdfe6);
  border-radius: var(--mt-card-radius, 14px);
  padding: 12px 14px;
  background: var(--mt-bg-soft, #fafafa);
}
.sc-title {
  font-weight: 600;
  margin-bottom: 4px;
}
.metrics {
  display: flex;
  gap: 12px;
  flex-wrap: wrap;
}
.metric {
  display: inline-flex;
  flex-direction: column;
  gap: 4px;
  border: 1px solid var(--mt-border, #ebeef5);
  border-radius: var(--mt-card-radius, 14px);
  padding: 14px 18px;
  min-width: 150px;
  background: var(--mt-bg-soft, #f5f7fa);
}
.metric b {
  font-size: 20px;
  color: var(--mt-text);
}
.metric span {
  font-size: 12px;
  color: var(--mt-text-soft);
}
.storage-bar {
  display: flex;
  align-items: center;
  gap: 10px;
  flex-wrap: wrap;
}
/* 名单页签的工具条：添加 / 删除所选 / 全部删除，条数靠右。 */
.list-bar {
  display: flex;
  align-items: center;
  gap: 10px;
  flex-wrap: wrap;
  margin: 4px 0 14px;
}
.list-bar .el-button + .el-button {
  margin-left: 0; /* 间距由 gap 管，el-button 相邻自带的左外边距会让间距不匀 */
}
.list-count {
  margin-left: auto;
}
.list-hint {
  margin: 10px 0 0;
}
/* 表格：与截图一致的浅灰表头、无斑马纹。表头底色取文字色的浅调而不是写死的灰，
 * 深色模式下才不会是一条亮条。 */
.gfw-table :deep(th.el-table__cell) {
  background: color-mix(in srgb, var(--mt-text) 5%, transparent);
  color: var(--mt-text-soft);
  font-weight: 500;
}
.mono {
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  color: var(--mt-text);
}
.muted {
  color: var(--mt-text-subtle, #909399);
}
/* 触发原因：信号与阈值上下两行，阈值是补充信息、字小一号。 */
.reason {
  display: flex;
  flex-direction: column;
  line-height: 1.5;
}
.reason .muted {
  font-size: 12px;
}
/* 添加对话框里的预览区。 */
.add-preview {
  min-height: 24px;
}
.add-preview .stats {
  display: flex;
  align-items: center;
  gap: 8px;
  flex-wrap: wrap;
}
.add-preview .invalid-line {
  margin: 8px 0 0;
  word-break: break-all;
}
.err {
  color: var(--el-color-danger, #f56c6c);
  font-size: 12px;
}
/* 详细说明卡片：与 mockup 一致的蓝色提示框。 */
.callout {
  border: 1px solid color-mix(in srgb, var(--mt-primary) 35%, transparent);
  background: color-mix(in srgb, var(--mt-primary) 8%, transparent);
  border-radius: var(--mt-card-radius, 14px);
  padding: 14px 16px;
}
.callout h4 {
  margin: 0 0 8px;
  color: var(--mt-primary);
  font-size: 14px;
}
.callout ul {
  margin: 6px 0 0;
  padding-left: 18px;
  color: var(--mt-text-soft);
  font-size: 13px;
}
.callout li {
  margin: 6px 0;
  line-height: 1.6;
}
</style>
