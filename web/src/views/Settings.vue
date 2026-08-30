<script setup lang="ts">
import {
  onActivated,
  onDeactivated,
  onBeforeUnmount,
  defineComponent,
  h,
  reactive,
  ref,
  watch,
  computed,
  nextTick,
} from 'vue'
import { useI18n } from 'vue-i18n'
import { ElMessage, ElMessageBox } from 'element-plus'
import PageCard from '@/components/PageCard.vue'
import api from '@/api/client'
import { actions, type StorageItem } from '@/api/resources'
import { fmtTime, fmtTimeMs, fmtBytes } from '@/composables/useResource'
import { useCloseOnLeave } from '@/composables/useCloseOnLeave'
import { useNarrow } from '@/composables/useNarrow'
import { useAppearanceStore, applyAppearance } from '@/stores/appearance'
import { defaultAppearance, cloneAppearance, type Appearance } from '@/stores/appearanceTypes'
import { useAuthStore } from '@/stores/auth'
import { useRouter } from 'vue-router'
import { setLocale, currentLocale } from '@/i18n'

const { t, tm, rt } = useI18n()
const appStore = useAppearanceStore()
const auth = useAuthStore()
const router = useRouter()

const activeTab = ref('appearance')

// 标签位置：本页几个表单的标签宽 140～200，手机上（内容区约 221）会把字段挤成一条缝——
// 实测 140 的那档只剩 81 像素，200 的那档更窄。窄屏改成标签在字段上方，字段就能拿到整行宽。
// label-width 保持原样：label-position 为 top 时 Element Plus 不用它。
const narrow = useNarrow()
const labelPos = computed(() => (narrow.value ? 'top' : 'right'))

// 首屏是否已经拿到服务端设置。
//
// 设置页的每个表单都带硬编码初值（端口 0、日志 1000 条、失败 5 次…），数据回来之前
// 直接渲染就会先闪一遍这些假值、再整片跳成真值——这正是「点设置比别的模块慢」里
// 最刺眼的那部分观感。用一层 loading 遮罩盖住这段空窗，而**不是** v-if：
// v-if 会销毁重建整棵表单，切页回来又得从零挂载一遍，等于把 keep-alive 的收益抵消掉。
const loaded = ref(false)

interface LogCfg { levels: string[]; maxEntries: number; console: boolean; showOnHome: boolean; homeLimit: number }
interface PanelInfo { port: number; basePath: string; https: { enabled: boolean; certId: string; domain: string } }
interface CertOption { id?: string; name: string; domains: string[] }
// 「在线更新」配置：自托管清单优先于 GitHub 仓库；二者均可独立留空，留空回退默认值。
interface UpdateCfg {
  manifestUrl: string
  releaseUrl: string
  githubRepo: string
  signKey: string
  allowUnsignedUpdate: boolean
}
const lang = ref<'zh-CN' | 'en-US'>(currentLocale())
const panel = reactive<PanelInfo>({ port: 0, basePath: '', https: { enabled: false, certId: '', domain: '' } })
const certs = ref<CertOption[]>([])
const log = reactive<LogCfg>({ levels: ['info', 'warn', 'error'], maxEntries: 1000, console: true, showOnHome: true, homeLimit: 50 })
// 总览页展示条数的上限：200 是渲染开销的取舍（面板每 3 秒整体重绘、无虚拟滚动），
// 同时不得超过「日志最大条数」——环里没有的条数展示不出来，
// 写一个永远达不到的数字只会让人以为设置没生效。后端 NormalizeLogHomeLimit 同样兜底。
const homeLimitMax = computed(() => Math.min(200, log.maxEntries || 200))
const savingGeneral = ref(false)
const savingLog = ref(false)

// 日志文件信息（路径 / 文件数 / 合计大小 MB），设置 → 日志页展示并支持一键清空。
const logInfo = reactive<{ path: string; count: number; sizeMB: number }>({ path: '', count: 0, sizeMB: 0 })
const logInfoLoading = ref(false)

async function refreshLogInfo() {
  logInfoLoading.value = true
  try {
    const info = await actions.logInfo()
    logInfo.path = info.path || ''
    logInfo.count = info.count ?? 0
    logInfo.sizeMB = info.sizeMB ?? 0
  } catch {
    /* 忽略瞬时错误 */
  } finally {
    logInfoLoading.value = false
  }
}

async function clearLogs() {
  try {
    await ElMessageBox.confirm(t('settings.clearLogsConfirm'), '', {
      confirmButtonText: t('common.confirm'),
      cancelButtonText: t('common.cancel'),
      type: 'warning',
    })
  } catch {
    return
  }
  try {
    await actions.clearLogs()
    ElMessage.success(t('settings.clearLogsOk'))
    await refreshLogInfo()
  } catch (e: any) {
    ElMessage.error((e?.message || '') || t('settings.clearLogsFailed'))
  }
}

/* ---------- 存储占用：数据目录里没人引用的文件 ---------- */
// 换掉的背景图、删掉证书后剩下的 .crt/.key、导入配置中断留下的暂存目录，都不会自己消失。
// 这里只做「列出来 + 按列表删」，勾选状态留在前端，删除时把路径发回去由服务端重新核对。
const storage = reactive<{ items: StorageItem[]; totalSize: number; truncated: boolean; limit: number }>({
  items: [],
  totalSize: 0,
  truncated: false,
  limit: 0,
})
const storageLoading = ref(false)
const storageCleaning = ref(false)
const storagePicked = ref<string[]>([])
// 已勾选的合计大小：给「要腾多少地方」一个直接的数，不用自己加。
const storagePickedSize = computed(() =>
  storage.items.reduce((sum, it) => (storagePicked.value.includes(it.path) ? sum + it.size : sum), 0),
)

async function refreshStorage() {
  storageLoading.value = true
  try {
    const info = await actions.storageInfo()
    storage.items = info.items || []
    storage.totalSize = info.totalSize ?? 0
    storage.truncated = !!info.truncated
    storage.limit = info.limit ?? 0
    // 列表变了就把勾选收回到还在列表里的那些，否则会拿着已经不存在的路径去删。
    const alive = new Set(storage.items.map((it) => it.path))
    storagePicked.value = storagePicked.value.filter((p) => alive.has(p))
  } catch (e: any) {
    ElMessage.error(e?.message || t('settings.storageLoadFailed'))
  } finally {
    storageLoading.value = false
  }
}

async function cleanupStorage() {
  const paths = [...storagePicked.value]
  if (paths.length === 0) return
  try {
    await ElMessageBox.confirm(
      t('settings.storageCleanupConfirm', { count: paths.length, size: fmtBytes(storagePickedSize.value) }),
      '',
      { confirmButtonText: t('common.confirm'), cancelButtonText: t('common.cancel'), type: 'warning' },
    )
  } catch {
    return
  }
  storageCleaning.value = true
  try {
    const r = await actions.cleanupStorage(paths)
    if (r.removed > 0) {
      ElMessage.success(t('settings.storageCleanupOk', { count: r.removed, size: fmtBytes(r.freed) }))
    }
    // skipped 不是失败：列表是几分钟前拉的，中间那条可能已经被删了或者又被引用上了。
    if (r.skipped > 0) ElMessage.info(t('settings.storageCleanupSkipped', { count: r.skipped }))
    if (r.failed?.length) ElMessage.warning(t('settings.storageCleanupFailed', { count: r.failed.length }))
    storagePicked.value = []
    await refreshStorage()
  } catch (e: any) {
    ElMessage.error(e?.message || t('settings.storageCleanupFailed', { count: paths.length }))
  } finally {
    storageCleaning.value = false
  }
}

// 备份与恢复那一页打开时才去扫盘：这是一次目录遍历，没必要每次进设置页都做一遍。
watch(activeTab, (tab) => {
  if (tab === 'backup') refreshStorage()
})

/* ---------- 在线更新（更新源 / 签名密钥） ---------- */
// 默认值与后端保持一致：manifestUrl/releaseUrl/githubRepo 留空表示走默认行为（GitHub ovoene/Mantou）。
// signKey 默认空，此时是否接收更新包由 allowUnsignedUpdate 决定，默认关闭（后端同样默认拒收）。
const update = reactive<UpdateCfg>({ manifestUrl: '', releaseUrl: '', githubRepo: '', signKey: '', allowUnsignedUpdate: false })
const savingUpdate = ref(false)

// 路径前缀只允许 ASCII（英文 / 数字 / 符号）。检测到中文等非 ASCII 字符则判定非法，禁止保存。
const basePathInvalid = computed(() => /[^\x00-\x7F]/.test(panel.basePath.trim()))

/* ---------- 登录安全（可配置失败次数上限与锁定时长） ---------- */
const login = reactive<{ maxFails: number; lockMinutes: number; sessionHours: number; idleMinutes: number }>({ maxFails: 5, lockMinutes: 10, sessionHours: 1, idleMinutes: 30 })
const savingLogin = ref(false)

/* ---------- 出站请求内网防护（默认关闭；开启后取址 / 计划任务 HTTP 目标解析到内网或保留地址将被拒绝） ---------- */
const security = reactive<{ blockPrivateNetwork: boolean }>({ blockPrivateNetwork: false })
const savingSecurity = ref(false)

/* ---------- 重启（立即重启 + 定时重启） ---------- */
// 三种模式各用各的字段：weekly 看 weekdays，dates 看 dates，interval 看 everyDays + startDate。
// 切换模式不清空另外两组——用户来回比较时不该丢掉刚填的内容，后端也只读当前模式那一组。
interface RestartCfg {
  enabled: boolean
  mode: 'weekly' | 'dates' | 'interval'
  weekdays: number[]
  dates: string[]
  everyDays: number
  startDate: string
  hour: number
  minute: number
}
const restart = reactive<RestartCfg>({
  enabled: false,
  mode: 'weekly',
  weekdays: [0],
  dates: [],
  everyDays: 7,
  startDate: '',
  hour: 4,
  minute: 0,
})
// 上次 / 下次执行时间都由后端给（秒）。下次执行**不在前端算**：
// 周 / 日历 / 间隔三种模式的边界判断只写在后端一处，前端再实现一遍必然在某个边界上不一致，
// 而"界面显示的时间"与"实际执行的时间"不一样是最难被发现的一类问题。
const restartLastRunAt = ref(0)
const restartNextRunAt = ref(0)
const savingRestart = ref(false)
const restartingNow = ref(false)

// 星期选项复用计划任务那份文案（cron.weekdayNames），同一组名字不在两处各写一遍。
const weekdayOptions = computed(() => {
  const names = tm('cron.weekdayNames') as unknown as any[]
  return (names || []).map((n, i) => ({ label: rt(n), value: i }))
})

// el-time-picker 用 HH:mm 字符串，配置里存的是时、分两个数字。
const restartAt = computed<string>({
  get: () => `${String(restart.hour).padStart(2, '0')}:${String(restart.minute).padStart(2, '0')}`,
  set: (v: string) => {
    const [h, m] = (v || '00:00').split(':').map((x) => Number(x))
    restart.hour = Number.isFinite(h) ? h : 0
    restart.minute = Number.isFinite(m) ? m : 0
  },
})

// 语言即时切换，让界面文案立刻响应（保存按钮再落库）。
function onLangChange(v: 'zh-CN' | 'en-US') {
  setLocale(v)
}

async function loadSettings() {
  try {
    const s = await api.get<any>('/settings')
    if (s.panel) {
      panel.port = s.panel.port ?? 0
      panel.basePath = s.panel.basePath ?? ''
      panel.https.enabled = s.panel.https?.enabled ?? false
      panel.https.certId = s.panel.https?.certId ?? ''
      panel.https.domain = s.panel.https?.domain ?? s.panel.https?.allowedHosts?.[0] ?? ''
    }
    if (s.log) {
      // 后端未下发级别（null/undefined，如旧配置里 Levels:nil=记录所有）时，
      // 落到默认勾选「信息/警告/错误」三项，与初次安装保持一致；
      // 用户主动清空（empty array）则保留空——表示显式不勾任何级别。
      log.levels = s.log.levels ?? ['info', 'warn', 'error']
      log.maxEntries = s.log.maxEntries > 0 ? s.log.maxEntries : 1000
      log.console = s.log.console ?? true
      log.showOnHome = s.log.showOnHome ?? true
      log.homeLimit = s.log.homeLimit > 0 ? s.log.homeLimit : 50
    }
    if (s.language === 'zh-CN' || s.language === 'en-US') lang.value = s.language
    if (s.auth) {
      login.maxFails = typeof s.auth.loginMaxFails === 'number' ? s.auth.loginMaxFails : 5
      login.lockMinutes = typeof s.auth.loginLockMinutes === 'number' ? s.auth.loginLockMinutes : 10
      login.sessionHours = typeof s.auth.sessionHours === 'number' ? s.auth.sessionHours : 1
      login.idleMinutes = typeof s.auth.sessionIdleMinutes === 'number' ? s.auth.sessionIdleMinutes : 30
    }
    if (s.update) {
      update.manifestUrl = s.update.manifestUrl ?? ''
      update.releaseUrl = s.update.releaseUrl ?? ''
      update.githubRepo = s.update.githubRepo ?? ''
      update.signKey = s.update.signKey ?? ''
      update.allowUnsignedUpdate = !!s.update.allowUnsignedUpdate
    }
    if (s.security) {
      security.blockPrivateNetwork = !!s.security.blockPrivateNetwork
    }
    if (s.restart) {
      restart.enabled = !!s.restart.enabled
      restart.mode = s.restart.mode === 'dates' || s.restart.mode === 'interval' ? s.restart.mode : 'weekly'
      restart.weekdays = Array.isArray(s.restart.weekdays) ? s.restart.weekdays : []
      restart.dates = Array.isArray(s.restart.dates) ? s.restart.dates : []
      restart.everyDays = s.restart.everyDays > 0 ? s.restart.everyDays : 7
      restart.startDate = s.restart.startDate ?? ''
      restart.hour = typeof s.restart.hour === 'number' ? s.restart.hour : 4
      restart.minute = typeof s.restart.minute === 'number' ? s.restart.minute : 0
      restartLastRunAt.value = s.restart.lastRunAt ?? 0
      restartNextRunAt.value = s.restart.nextRunAt ?? 0
    }
    // 面板 HTTPS 的证书下拉框数据随 /settings 一起下发（后端 certOptions）。
    // 原先这里另发一个 /certs 请求，而那个接口会把每张证书的完整状态（ACME 状态机、
    // 续期进度、磁盘路径）都算出来返回，下拉框却只用得上 id/name/domains 三个字段。
    // 合成一次往返后，设置页首屏不再"等最慢的那个请求"。
    if (Array.isArray(s.certs)) certs.value = s.certs as CertOption[]
  } catch {
    /* ignore */
  }
}

async function saveSecurity() {
  savingSecurity.value = true
  try {
    await api.put('/settings', { security: { blockPrivateNetwork: security.blockPrivateNetwork } })
    ElMessage.success(t('msg.saveOk'))
  } catch (e: any) {
    ElMessage.error(e?.message || t('common.saveFailed'))
  } finally {
    savingSecurity.value = false
  }
}

// 定时重启：保存前先在前端挡住"开着但填不全"的组合，让人在原地看到缺什么，
// 而不是提交之后读一句服务端报错。后端 RestartPolicy.Valid 有同一套判断（绕过界面也拦得住）。
async function saveRestart() {
  if (restart.enabled) {
    if (restart.mode === 'weekly' && restart.weekdays.length === 0) {
      ElMessage.warning(t('settings.restartWeekdayRequired'))
      return
    }
    if (restart.mode === 'dates' && restart.dates.length === 0) {
      ElMessage.warning(t('settings.restartDatesRequired'))
      return
    }
    if (restart.mode === 'interval' && !restart.startDate) {
      ElMessage.warning(t('settings.restartStartDateRequired'))
      return
    }
  }
  savingRestart.value = true
  try {
    await api.put('/settings', { restart: { ...restart } })
    ElMessage.success(t('msg.saveOk'))
    // 重新拉一次：下次执行时间是后端算的，不重拉就还显示保存前的那个时间。
    await loadSettings()
  } catch (e: any) {
    ElMessage.error(e?.message || t('common.saveFailed'))
  } finally {
    savingRestart.value = false
  }
}

// 重启倒计时提示：挂载后从 5 倒数，归零自动刷新整页。
// 单独做成组件是为了让 ElMessage 里的秒数真的在动——把纯文本塞进消息体不会随外部 ref 重渲染。
const RestartCountdown = defineComponent({
  setup() {
    const remaining = ref(5)
    const timer = setInterval(() => {
      // 减到 1 就直接刷新，不再往下渲染：否则浏览器会先把「0 秒」这一帧画出来才跳转。
      if (remaining.value <= 1) {
        clearInterval(timer)
        location.reload()
        return
      }
      remaining.value -= 1
    }, 1000)
    onBeforeUnmount(() => clearInterval(timer))
    return () => h('span', t('settings.restartNowCountdown', { n: remaining.value }))
  },
})

// 立即重启：换掉整个进程。二次确认是必要的——这会中断所有模块（端口转发的连接、
// 正在跑的计划任务），而按钮点下去没有撤销机会。
async function doRestartNow() {
  try {
    await ElMessageBox.confirm(t('settings.restartNowConfirm'), t('settings.restartNow'), {
      type: 'warning',
      confirmButtonText: t('common.confirm'),
      cancelButtonText: t('common.cancel'),
    })
  } catch {
    return
  }
  restartingNow.value = true
  try {
    await actions.restartNow()
    // 进程重建期间这一页发出的任何请求都会失败几秒，等一会儿整页刷新是最省心的收尾。
    // 秒数摆在眼前，用户知道这几秒是在等而不是卡住了；归零由组件自己刷新页面。
    // 不自动关闭（duration: 0）：提示消失了倒计时也就跟着停了。
    // 按钮保持 loading 直到刷新，避免这段时间里被再点一次。
    ElMessage({
      message: h(RestartCountdown),
      type: 'success',
      duration: 0,
      showClose: false,
    })
  } catch (e: any) {
    ElMessage.error(e?.message || t('common.failed'))
    restartingNow.value = false
  }
}

async function saveLoginSecurity() {
  savingLogin.value = true
  try {
    await api.put('/settings', {
      auth: {
        loginMaxFails: login.maxFails,
        loginLockMinutes: login.lockMinutes,
        sessionHours: login.sessionHours,
        sessionIdleMinutes: login.idleMinutes,
      },
    })
    ElMessage.success(t('msg.saveOk'))
  } catch (e: any) {
    ElMessage.error(e?.message || t('common.saveFailed'))
  } finally {
    savingLogin.value = false
  }
}

// 规范化路径前缀：空或「/」→ 空；否则确保以「/」开头、无末尾「/」。
function normalizeBasePath(bp: string): string {
  let v = (bp || '').trim()
  if (v === '' || v === '/') return ''
  if (!v.startsWith('/')) v = '/' + v
  if (v.endsWith('/')) v = v.slice(0, -1)
  return v
}

async function saveGeneral() {
  if (basePathInvalid.value) {
    ElMessage.warning(t('settings.basePathInvalid'))
    return
  }
  if (panel.https.enabled && !panel.https.certId) {
    ElMessage.warning(t('settings.panelCertRequired'))
    return
  }
  if (panel.https.enabled && !panel.https.domain.trim()) {
    ElMessage.warning(t('settings.panelDomainRequired'))
    return
  }
  savingGeneral.value = true
  try {
    const res = await api.put<{ ok: boolean; restartRequired: boolean }>('/settings', {
      language: lang.value,
      panel: { port: panel.port, basePath: panel.basePath, https: { ...panel.https } },
    })
    setLocale(lang.value)
    if (res?.restartRequired) {
      // 端口 / 路径前缀变更需重启：后端会自动重启，前端跳转到新地址。
      const np = normalizeBasePath(panel.basePath)
      const protocol = panel.https.enabled ? 'https:' : 'http:'
      const hostname = panel.https.enabled ? panel.https.domain.trim() : location.hostname
      const url = `${protocol}//${hostname}:${panel.port}${np}/`
      ElMessage.success(t('msg.restarting'))
      setTimeout(() => {
        location.href = url
      }, 3000)
      return
    }
    ElMessage.success(t('msg.saveOk'))
  } catch (e: any) {
    ElMessage.error(e?.message || t('common.failed'))
  } finally {
    savingGeneral.value = false
  }
}

async function saveLog() {
  savingLog.value = true
  try {
    await api.put('/settings', { log: { ...log } })
    ElMessage.success(t('msg.saveOk'))
  } catch (e: any) {
    ElMessage.error(e?.message || t('common.failed'))
  } finally {
    savingLog.value = false
  }
}

async function saveUpdate() {
  // 不做强制校验：前四个字段均允许留空（manifestUrl 空 → 回退 GitHub；githubRepo 空 → 默认 ovoene/Mantou；
  // releaseUrl 空 → 回退清单/GitHub 返回的下载页）。留空即代表「用默认」，与后端 trimSpace 行为一致。
  // signKey 留空且未打开 allowUnsignedUpdate 时，后端不接收更新包——这是默认状态，不在这里拦，
  // 因为「暂时不打算用在线覆盖更新」的用户本就该能把这两项都留在默认值上保存。
  savingUpdate.value = true
  try {
    await api.put('/settings', {
      update: {
        manifestUrl: update.manifestUrl,
        releaseUrl: update.releaseUrl,
        githubRepo: update.githubRepo,
        signKey: update.signKey,
        allowUnsignedUpdate: update.allowUnsignedUpdate,
      },
    })
    ElMessage.success(t('msg.saveOk'))
  } catch (e: any) {
    ElMessage.error(e?.message || t('common.failed'))
  } finally {
    savingUpdate.value = false
  }
}

/* ---------- 外观设置（实时预览） ---------- */
const local = reactive<Appearance>(cloneAppearance(appStore.appearance))
const savingAppearance = ref(false)
// 见 restoreSavedAppearance：还原表单时抑制下面那个深度 watch。
let restoring = false

// 背景纯色为空即「跟随主题色」：整页背景由主色自动生成，改主色时背景一并变化。
const bgFollowTheme = computed({
  get: () => local.background.value === '',
  set: (v: boolean) => {
    local.background.value = v ? '' : '#eef1f8'
  },
})

// 任意改动都实时写入 :root，达成所见即所得的预览。
// restoring 期间跳过：还原函数自己已经同步写过一次 :root，不必等下一拍再写一遍
// （写 :root 会让整篇文档的样式失效重算，能省的就省）。
watch(local, () => {
  if (restoring) return
  applyAppearance(cloneAppearance(local))
}, { deep: true })

async function uploadBg(opt: any) {
  const fd = new FormData()
  fd.append('file', opt.file)
  try {
    const resp = await api.raw.post('/settings/background', fd)
    const url = resp.data?.data?.url || resp.data?.url
    if (url) {
      local.background.type = 'image'
      local.background.value = url
    }
    ElMessage.success(t('msg.uploadOk'))
  } catch (e: any) {
    ElMessage.error(e?.message || t('common.failed'))
  }
}

// 删除已上传的背景图：删除服务器文件并重置为默认渐变（配置备份不再包含该图片）。
async function deleteBg() {
  try {
    await ElMessageBox.confirm(t('settings.deleteBgConfirm'), '', {
      confirmButtonText: t('common.confirm'),
      cancelButtonText: t('common.cancel'),
      type: 'warning',
    })
  } catch {
    return
  }
  try {
    await api.del('/settings/background')
    // 同步本地预览：重置为默认渐变背景。
    local.background.type = 'gradient'
    local.background.value = 'linear-gradient(135deg,#e6efff 0%,#f3f0ff 100%)'
    local.background.blur = 0
    local.background.overlayOpacity = 0.15
    await saveAppearance()
    ElMessage.success(t('settings.deleteBgOk'))
  } catch (e: any) {
    ElMessage.error(e?.message || t('common.failed'))
  }
}

async function saveAppearance() {
  savingAppearance.value = true
  try {
    await Promise.all([
      appStore.save(cloneAppearance(local)),
      api.put('/settings', { language: lang.value }),
    ])
    setLocale(lang.value)
    ElMessage.success(t('msg.saveOk'))
  } catch (e: any) {
    ElMessage.error(e?.message || t('common.failed'))
  } finally {
    savingAppearance.value = false
  }
}

function resetAppearance() {
  Object.assign(local, defaultAppearance())
}

/* ---------- 备份与恢复 ---------- */
const exporting = ref(false)
const importing = ref(false)
// 加密备份所需的凭据对话框（导入时），以及暂存待导入文件。
const importCredsVisible = ref(false)
const importFile = ref<File | null>(null)
const importAccount = ref('')
const importPassword = ref('')

// 导入前的身份验证。导入会覆盖配置，其中可能包含管理员账户本身，
// 所以先确认「我是这台面板当前的管理员」（接口那道校验才是真正的闸，见 handleImportConfig）。
//
// 刻意分成前后两个弹窗、不合成一屏：界面上任何时候只出现一个密码框。
// 这一步填的是**本机当前**的密码，下一步填的是**这份备份**的解密口令，
// 两者是两套不同的东西，摆在一起最容易填反。
const importAuthVisible = ref(false)
const importAuthAccount = ref('')
const importAuthPassword = ref('')
const importAuthChecking = ref(false)
// 选中的文件是否为加密备份（决定验完身份后是进"解密口令 + 范围"那一步，还是直接提交）。
const importEncrypted = ref(false)

/* ---------- 选择性导入：按功能模块勾选 ---------- */
// 标识与后端 internal/server/import_scope.go 的 importModule 逐字对应（接口契约），
// 顺序与左侧导航一致，好让用户在对话框里从上往下对着导航找。
const importModuleKeys = [
  'ddns', 'webservice', 'messageroute', 'forward', 'wol', 'cron', 'cert', 'credential', 'panel',
] as const
// 模块标签复用导航文案，"面板与设置"另起一个键（它比导航上的「设置」多含账户与外观）。
const importModuleLabels: Record<string, string> = {
  ddns: 'nav.ddns',
  webservice: 'nav.webservice',
  messageroute: 'nav.mroute',
  forward: 'nav.forward',
  wol: 'nav.wol',
  cron: 'nav.cron',
  cert: 'nav.cert',
  credential: 'nav.cred',
  panel: 'settings.importScopePanel',
}
// 硬依赖：勾了左边就必须一起导入右边。与后端 importDeps 是同一张表，
// 两边都算一遍——前端算是为了让用户看见"为什么这一项锁住了"，后端算才是保证。
const importModuleDeps: Record<string, string[]> = {
  cert: ['credential'],
  ddns: ['credential'],
  webservice: ['cert'],
  messageroute: ['cert'],
  panel: ['cert'],
}
const importModules = ref<string[]>([...importModuleKeys])

// importLocked 被已勾选模块依赖、因而必须一起导入的模块：界面上勾上并禁用。
const importLocked = computed<Set<string>>(() => {
  const req = new Set<string>()
  const visit = (m: string) => {
    for (const d of importModuleDeps[m] || []) {
      if (!req.has(d)) {
        req.add(d)
        visit(d)
      }
    }
  }
  for (const m of importModules.value) visit(m)
  return req
})

// normalizeImportModules 勾选变化后补齐依赖闭包。上界取模块数，图再长也不会转不出来。
function normalizeImportModules() {
  const set = new Set(importModules.value)
  for (let i = 0; i < importModuleKeys.length; i++) {
    let grew = false
    for (const m of Array.from(set)) {
      for (const d of importModuleDeps[m] || []) {
        if (!set.has(d)) {
          set.add(d)
          grew = true
        }
      }
    }
    if (!grew) break
  }
  importModules.value = importModuleKeys.filter((k) => set.has(k))
}

// 导出：备份始终以「登录账户名 + 密码」加密，账户名自动取当前登录账户，仅需用户输入密码。
async function exportConfig() {
  let password = ''
  try {
    const r = await ElMessageBox.prompt(t('settings.exportPwdHint'), t('settings.exportEncrypt'), {
      inputType: 'password',
      confirmButtonText: t('common.confirm'),
      cancelButtonText: t('common.cancel'),
      inputValidator: (v: string) => (v && v.length > 0) || t('common.required'),
    })
    password = r.value || ''
  } catch {
    return // 用户取消
  }
  if (!password) return
  exporting.value = true
  try {
    const resp = await api.raw.post('/settings/export', { account: auth.username, password })
    const text = JSON.stringify(resp.data, null, 2)
    const blob = new Blob([text], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    const cd = (resp.headers?.['content-disposition'] as string) || ''
    const m = /filename="?([^"]+)"?/.exec(cd)
    a.download = m ? m[1] : `Mantou-${Date.now()}.json`
    document.body.appendChild(a)
    a.click()
    a.remove()
    URL.revokeObjectURL(url)
    ElMessage.success(t('msg.configExported'))
  } catch (e: any) {
    ElMessage.error(e?.message || t('common.failed'))
  } finally {
    exporting.value = false
  }
}

// 导入：选好文件后先验一次本机管理员身份，通过了再进到下一步。
// 加密备份的下一步是「填解密口令 + 选范围」那个弹窗；不是加密备份的直接提交，由接口拒收。
async function importConfig(opt: any) {
  const file = opt.file as File
  let encrypted = false
  try {
    const text = await file.text()
    const obj = JSON.parse(text)
    encrypted = !!obj.encrypted
  } catch {
    /* 解析失败留待后端校验 */
  }
  importFile.value = file
  importEncrypted.value = encrypted
  importAccount.value = ''
  importPassword.value = ''
  // 每次打开对话框都回到"全部导入"：上一次只导了两个模块，不该影响下一次。
  importModules.value = [...importModuleKeys]
  // 账户名预填当前登录账户（与加密导出同款），一般只需再填一次密码。
  importAuthAccount.value = auth.username
  importAuthPassword.value = ''
  importAuthVisible.value = true
}

// confirmImportAuth 身份验证通过后，才放人进到下一步。
//
// 这里只是把失败提前，免得范围与口令都填完了最后才被打回来；真正的验证在导入接口里，
// 这一步拿到 200 不代表后面那一步免验，两处填的是同一对凭据。
async function confirmImportAuth() {
  const account = importAuthAccount.value.trim()
  if (!account || !importAuthPassword.value) {
    ElMessage.warning(t('common.required'))
    return
  }
  importAuthChecking.value = true
  try {
    await api.post('/auth/verify', { account, password: importAuthPassword.value })
  } catch (e: any) {
    ElMessage.error(e?.message || t('common.failed'))
    return
  } finally {
    importAuthChecking.value = false
  }
  const file = importFile.value
  if (importEncrypted.value) {
    importAuthVisible.value = false
    importCredsVisible.value = true
    return
  }
  importAuthVisible.value = false
  if (file) await doImport(file, '', '')
}

// cancelImportAuth 放弃导入：暂存的文件一并丢掉（密码由 onImportAuthClosed 清）。
function cancelImportAuth() {
  importAuthVisible.value = false
  importFile.value = null
}

// onImportAuthClosed 弹窗关掉（取消、✕、Esc、切页）就把密码清掉。
// 唯一的例外是"验证通过、进到下一步"——那时它还要随导入一起提交给接口再验一次。
function onImportAuthClosed() {
  if (!importCredsVisible.value) importAuthPassword.value = ''
}

// onImportCredsClosed 同上。关掉这一步就意味着这次导入没走完，两对密码都不必留着。
// 提交时的那份由 doImport 在一开始就取好了本地副本，不受这里影响。
function onImportCredsClosed() {
  importPassword.value = ''
  importAuthPassword.value = ''
}

async function confirmImportCreds() {
  if (!importAccount.value.trim() || !importPassword.value) {
    ElMessage.warning(t('common.required'))
    return
  }
  if (importModules.value.length === 0) {
    ElMessage.warning(t('settings.importScopeEmpty'))
    return
  }
  const file = importFile.value
  importCredsVisible.value = false
  if (file) await doImport(file, importAccount.value.trim(), importPassword.value)
}

async function doImport(file: File, account: string, password: string) {
  // 本机管理员那一对在这里就取好本地副本：弹窗关闭的动画结束后会把 ref 清掉（见
  // onImportAuthClosed / onImportCredsClosed），而下面还要等用户点确认框，届时 ref 可能已经空了。
  const authAccount = importAuthAccount.value.trim()
  const authPassword = importAuthPassword.value
  // 只导一部分时，确认框换一句更准的话：把实际会被覆盖的模块名列出来，
  // 免得用户以为"没勾的那些会被清空"。
  const partial = importModules.value.length > 0 && importModules.value.length < importModuleKeys.length
  const confirmText = partial
    ? t('settings.importConfirmPartial', {
        modules: importModules.value.map((m) => t(importModuleLabels[m])).join('、'),
      })
    : t('settings.importConfirm')
  try {
    await ElMessageBox.confirm(confirmText, '', {
      confirmButtonText: t('common.import'),
      cancelButtonText: t('common.cancel'),
      type: 'warning',
    })
  } catch {
    // 在确认框上放弃：两对密码同样不留在内存里。
    importPassword.value = ''
    importAuthPassword.value = ''
    return
  }
  importing.value = true
  try {
    const fd = new FormData()
    fd.append('file', file)
    if (account) fd.append('account', account)
    if (password) fd.append('password', password)
    // 本机管理员那一对（与上面那对不是同一套，见 importAuthVisible 处的说明）。
    // 前面那个认证弹窗只是引导，接口自己还要再验一次，所以这里必须一起提交。
    if (authAccount) fd.append('authAccount', authAccount)
    if (authPassword) fd.append('authPassword', authPassword)
    // 全选时也照样带上：接口把"字段缺失"当作全选，显式提交能让请求自己说明范围。
    if (importModules.value.length > 0) fd.append('modules', importModules.value.join(','))
    const resp = await api.raw.post('/settings/import', fd)
    const res = (resp.data && resp.data.data) || resp.data
    ElMessage.success(t('msg.configImported'))
    if (res?.restartRequired) ElMessage.warning(t('msg.restartRequired'))
    if (res?.credentialsChanged) {
      // 备份里的管理员账户已经生效，当前会话已被作废（见 handleImportConfig）。
      // 这时不再去拉设置——那一步会 401 把人直接弹回登录页，连提示都来不及看见。
      ElMessage.warning({ message: t('msg.importCredsChanged'), duration: 8000 })
      setTimeout(() => location.reload(), 3000)
      return
    }
    await loadSettings()
    setTimeout(() => location.reload(), 1200)
  } catch (e: any) {
    ElMessage.error(e?.message || t('common.failed'))
  } finally {
    importing.value = false
    // 两对凭据都不留在内存里。失败后重来一遍是从选文件开始的，届时会重新填。
    importPassword.value = ''
    importAuthPassword.value = ''
  }
}

/* ---------- 账户（可改用户名 + 密码） ---------- */
const acct = reactive({ username: '', old: '', neo: '', confirm: '' })
const savingAcct = ref(false)
const pwdMismatch = computed(() => acct.confirm.length > 0 && acct.neo !== acct.confirm)

async function submitAccount() {
  if (!acct.old) {
    ElMessage.warning(t('account.needOldPassword'))
    return
  }
  const changeName = acct.username.trim() !== '' && acct.username.trim() !== auth.username
  const changePass = acct.neo !== ''
  if (!changeName && !changePass) {
    ElMessage.warning(t('account.nothingToChange'))
    return
  }
  if (changePass && acct.neo.length < 6) {
    ElMessage.warning(t('setup.hintPass'))
    return
  }
  if (changePass && acct.neo !== acct.confirm) {
    ElMessage.warning(t('account.passwordMismatch'))
    return
  }
  savingAcct.value = true
  try {
    const r = await auth.changeAccount({
      username: changeName ? acct.username.trim() : undefined,
      oldPassword: acct.old,
      newPassword: changePass ? acct.neo : undefined,
    })
    acct.old = acct.neo = acct.confirm = ''
    if (r.usernameChanged) {
      ElMessage.success(t('account.usernameChangedRelogin'))
      setTimeout(() => auth.logout().then(() => router.replace({ name: 'login' })), 800)
    } else {
      ElMessage.success(t('settings.accountSaved'))
    }
  } catch (e: any) {
    ElMessage.error(e?.message || t('common.saveFailed'))
  } finally {
    savingAcct.value = false
  }
}

/* ---------- 关于页面（独立路由 /about）承载更新包上传与版本信息 ---------- */

// 页面被激活（keep-alive 下首次挂载也会走这里）。
// 每次进来都重新拉一遍设置：配置可能在别处被改过（另一个标签页、面板重启、导入备份），
// 缓存下来的旧值不能直接当真。未保存的编辑会被覆盖掉——这与原先「离开即销毁组件、
// 回来重新挂载」的表现完全一致，用户不会看到被留下来的半截改动。
onActivated(async () => {
  // 证书下拉框数据现在随 /settings 一并返回，首屏因此只有一次往返。
  await loadSettings()
  loaded.value = true
  // 日志文件大小会随时间增长，切回来时顺手刷新；不阻塞首屏。
  refreshLogInfo()
  // keep-alive 记着上次停在哪一页，停在备份页时 watch 不会触发，这里补一次。
  if (activeTab.value === 'backup') refreshStorage()
  acct.username = auth.username
})

// 离开页面时恢复已保存的外观，避免未保存的预览残留。
//
// keep-alive 下组件不会被销毁，所以除了还原 :root，还必须把表单里的值一并还原：
// 否则切回来会出现「表单显示改过的颜色、页面却是已保存的外观」这种错位——
// 而且深度 watch 不会因为"值没变"而重新应用预览，错位会一直留着。
// 原先这一步是靠组件销毁、local 重新从 store 初始化自动达成的。
function restoreSavedAppearance() {
  restoring = true
  try {
    Object.assign(local, cloneAppearance(appStore.appearance))
    applyAppearance(appStore.appearance)
  } finally {
    // 深度 watch 是 pre-flush（下一拍才执行），所以标志不能立刻放下，
    // 必须等这一批调度队列冲刷完——否则抑制不到上面那次赋值触发的回调。
    nextTick(() => {
      restoring = false
    })
  }
}
onDeactivated(restoreSavedAppearance)
// keep-alive 缓存被销毁时（退出登录 / 整个布局卸载）同样要还原，否则未保存的预览会残留到登录页。
onBeforeUnmount(restoreSavedAppearance)

// 导入备份时那两个弹窗（身份验证、解密口令与范围）都在切页时收起（理由见 useCloseOnLeave）。
useCloseOnLeave(importCredsVisible)
useCloseOnLeave(importAuthVisible)
</script>

<template>
  <PageCard :title="t('settings.title')" :subtitle="t('settings.subtitle')">
    <!-- lazy：只构建当前这一页。六个面板加起来约 146 个 Element Plus 组件，但一次
         只看得见其中一个（其余原本是构建完再 display:none 藏起来，白付一次挂载开销）。
         lazy 一旦渲染过就不再销毁（Element Plus 内部用 loaded 闩住），所以在标签页之间
         来回切不会反复重建，各页的表单状态照旧保留。
         v-loading 见 loaded 的注释：盖住"先闪硬编码初值、再跳成真值"的那一小段。 -->
    <el-tabs v-model="activeTab" v-loading="!loaded">
      <!-- 外观 -->
      <el-tab-pane :label="t('settings.tabAppearance')" name="appearance" lazy>
        <el-row :gutter="24">
          <el-col :md="12">
            <el-form label-width="140px" :label-position="labelPos">
              <el-form-item :label="t('settings.language')">
                <el-select v-model="lang" style="width: 220px" @change="onLangChange">
                  <el-option label="简体中文" value="zh-CN" />
                  <el-option label="English" value="en-US" />
                </el-select>
              </el-form-item>
              <el-form-item :label="t('settings.themeMode')">
                <el-radio-group v-model="local.themeMode">
                  <el-radio-button value="light">{{ t('settings.light') }}</el-radio-button>
                  <el-radio-button value="dark">{{ t('settings.dark') }}</el-radio-button>
                  <el-radio-button value="auto">{{ t('settings.auto') }}</el-radio-button>
                </el-radio-group>
              </el-form-item>

              <el-form-item :label="t('settings.colors')">
                <div class="color-row">
                  <div class="color-item">
                    <el-color-picker v-model="local.colors.primary" show-alpha />
                    <span class="mt-subtle">{{ t('settings.primary') }}</span>
                  </div>
                  <div class="color-item">
                    <el-color-picker v-model="local.colors.accent" show-alpha />
                    <span class="mt-subtle">{{ t('settings.accent') }}</span>
                  </div>
                </div>
              </el-form-item>

              <el-form-item :label="t('settings.background')">
                <div style="width: 100%">
                  <el-radio-group v-model="local.background.type" style="margin-bottom: 12px">
                    <el-radio-button value="color">{{ t('settings.bgColor') }}</el-radio-button>
                    <el-radio-button value="gradient">{{ t('settings.bgGradient') }}</el-radio-button>
                    <el-radio-button value="image">{{ t('settings.bgImage') }}</el-radio-button>
                  </el-radio-group>

                  <div v-if="local.background.type === 'color'">
                    <el-checkbox v-model="bgFollowTheme">{{ t('settings.bgFollowTheme') }}</el-checkbox>
                    <el-color-picker v-if="!bgFollowTheme" v-model="local.background.value" />
                    <span v-else class="mt-subtle hint">{{ t('settings.bgFollowThemeHint') }}</span>
                  </div>

                  <div v-else-if="local.background.type === 'gradient'">
                    <el-input
                      v-model="local.background.value"
                      type="textarea"
                      :rows="2"
                      :placeholder="'linear-gradient(135deg, #e9edfb 0%, #f4eef9 50%)'"
                    />
                  </div>

                  <div v-else>
                    <el-input v-model="local.background.value" placeholder="/uploads/bg-xxx.png" style="margin-bottom: 8px">
                      <template #append>
                        <el-upload
                          :show-file-list="false"
                          :http-request="uploadBg"
                          accept="image/png,image/jpeg,image/webp,image/gif"
                        >
                          <el-button>{{ t('settings.uploadBg') }}</el-button>
                        </el-upload>
                      </template>
                    </el-input>
                    <el-button
                      v-if="local.background.value"
                      type="danger"
                      plain
                      size="small"
                      @click="deleteBg"
                    >
                      {{ t('settings.deleteBg') }}
                    </el-button>
                  </div>

                  <div class="slider-row">
                    <span class="mt-subtle">{{ t('settings.blur') }}</span>
                    <el-slider v-model="local.background.blur" :min="0" :max="40" style="width: 180px" />
                  </div>
                  <div class="slider-row">
                    <span class="mt-subtle">{{ t('settings.overlay') }}</span>
                    <el-slider v-model="local.background.overlayOpacity" :min="0" :max="1" :step="0.05" style="width: 180px" />
                  </div>
                </div>
              </el-form-item>

              <el-divider />

              <el-form-item :label="t('settings.card')">
                <div style="width: 100%">
                  <div class="slider-row">
                    <span class="mt-subtle">{{ t('settings.cardOpacity') }}</span>
                    <el-slider v-model="local.card.opacity" :min="0.2" :max="1" :step="0.02" style="width: 180px" />
                  </div>
                  <!-- 「卡片模糊」这一栏已去掉：卡片早就改成了实底 + 细边框（style.css 的
                       .mt-glass），这个滑块调的 --mt-card-blur 没有任何地方在读，拖动它
                       什么也不会变。把它做成真的毛玻璃需要给每张卡加 backdrop-filter，
                       那正是"滚一下就掉帧"的经典来源，所以是撤掉而不是补上。 -->
                  <div class="slider-row">
                    <span class="mt-subtle">{{ t('settings.cardRadius') }}</span>
                    <el-slider v-model="local.card.radius" :min="0" :max="40" style="width: 180px" />
                  </div>
                </div>
              </el-form-item>

              <el-form-item :label="t('settings.font')">
                <div style="width: 100%">
                  <div class="slider-row">
                    <span class="mt-subtle">{{ t('settings.fontScale') }}</span>
                    <el-slider v-model="local.font.scale" :min="0.8" :max="1.6" :step="0.05" style="width: 180px" />
                  </div>
                  <div class="slider-row">
                    <span class="mt-subtle">{{ t('settings.fontWeight') }}</span>
                    <el-slider v-model="local.font.weight" :min="300" :max="700" :step="100" style="width: 180px" />
                  </div>
                </div>
              </el-form-item>

              <el-form-item>
                <el-button type="primary" :loading="savingAppearance" @click="saveAppearance">
                  {{ t('common.save') }}
                </el-button>
                <el-button @click="resetAppearance">{{ t('settings.resetAppearance') }}</el-button>
              </el-form-item>
            </el-form>
          </el-col>

          <!-- 实时预览 -->
          <el-col :md="12">
            <div class="preview-panel">
              <div class="mt-subtle" style="margin-bottom: 8px">{{ t('settings.preview') }}</div>
              <el-card class="mt-glass">
                <h3 style="margin: 0 0 8px; color: var(--mt-primary)">{{ t('settings.previewText') }}</h3>
                <p class="mt-subtle" style="margin: 0 0 12px">
                  {{ t('settings.previewText') }}
                </p>
                <el-button type="primary" size="small">{{ t('common.save') }}</el-button>
                <el-button size="small" type="warning">{{ t('common.run') }}</el-button>
              </el-card>
            </div>
          </el-col>
        </el-row>
      </el-tab-pane>

      <!-- 账户 -->
      <el-tab-pane :label="t('settings.tabAccount')" name="account" lazy>
        <el-form label-width="140px" :label-position="labelPos" style="max-width: 620px">
          <el-form-item :label="t('settings.accountUsername')">
            <el-input v-model="acct.username" autocomplete="off" />
            <span class="mt-subtle hint">{{ t('settings.accountUsernameHint') }}</span>
          </el-form-item>
          <el-form-item :label="t('settings.oldPassword')">
            <el-input v-model="acct.old" type="password" show-password autocomplete="current-password" />
          </el-form-item>
          <el-form-item :label="t('settings.newPassword')">
            <el-input
              v-model="acct.neo"
              type="password"
              show-password
              autocomplete="new-password"
              :placeholder="t('settings.newPasswordHint')"
            />
          </el-form-item>
          <el-form-item :label="t('settings.confirmNew')">
            <el-input v-model="acct.confirm" type="password" show-password autocomplete="new-password" />
            <span v-if="pwdMismatch" class="mt-danger-text" style="margin-left: 12px">
              {{ t('account.passwordMismatch') }}
            </span>
          </el-form-item>
          <el-form-item>
            <el-button type="primary" :loading="savingAcct" @click="submitAccount">
              {{ t('settings.changePassword') }}
            </el-button>
          </el-form-item>
        </el-form>
      </el-tab-pane>

      <!-- 日志 -->
      <el-tab-pane :label="t('settings.tabLog')" name="log" lazy>
        <el-form label-width="140px" :label-position="labelPos" style="max-width: 460px">
          <el-form-item :label="t('settings.logLevel')">
            <el-select
              v-model="log.levels"
              multiple
              clearable
              :placeholder="t('settings.logLevelAll')"
              style="width: 280px"
            >
              <el-option :label="t('settings.levelDebug')" value="debug" />
              <el-option :label="t('settings.levelInfo')" value="info" />
              <el-option :label="t('settings.levelWarn')" value="warn" />
              <el-option :label="t('settings.levelError')" value="error" />
            </el-select>
            <span class="mt-subtle" style="margin-left: 10px">{{ t('settings.logLevelHint') }}</span>
          </el-form-item>
          <el-form-item :label="t('settings.logConsole')">
            <el-switch v-model="log.console" />
          </el-form-item>
          <el-form-item :label="t('settings.logMaxEntries')">
            <el-input-number v-model="log.maxEntries" :min="100" :max="5000" :step="100" />
            <span class="mt-subtle" style="margin-left: 10px">{{ t('settings.logMaxEntriesHint') }}</span>
          </el-form-item>
          <el-form-item :label="t('settings.showOnHome')">
            <el-switch v-model="log.showOnHome" />
          </el-form-item>
          <el-form-item v-if="log.showOnHome" :label="t('settings.homeLimit')">
            <el-input-number v-model="log.homeLimit" :min="1" :max="homeLimitMax" :step="10" />
            <span class="mt-subtle" style="margin-left: 10px">{{ t('settings.homeLimitHint') }}</span>
          </el-form-item>
          <el-form-item>
            <el-button type="primary" :loading="savingLog" @click="saveLog">
              {{ t('common.save') }}
            </el-button>
          </el-form-item>

          <el-divider content-position="left">{{ t('settings.logFileInfo') }}</el-divider>
          <el-form-item :label="t('settings.logPath')">
            <span class="log-path">{{ logInfoLoading ? t('settings.logInfoLoading') : (logInfo.path || t('settings.logInfoLoading')) }}</span>
          </el-form-item>
          <el-form-item :label="t('settings.logFiles')">
            <span>{{ logInfoLoading ? t('settings.logInfoLoading') : logInfo.count }}</span>
          </el-form-item>
          <el-form-item :label="t('settings.logSize')">
            <span>{{ logInfoLoading ? t('settings.logInfoLoading') : `${logInfo.sizeMB} ${t('settings.logSizeUnit')}` }}</span>
          </el-form-item>
          <el-form-item>
            <el-button type="danger" :loading="logInfoLoading" @click="clearLogs">
              {{ t('settings.clearLogs') }}
            </el-button>
            <span class="mt-subtle" style="margin-left: 10px">{{ t('settings.clearLogsHint') }}</span>
          </el-form-item>
        </el-form>
      </el-tab-pane>

      <!-- 登录安全 -->
      <el-tab-pane :label="t('settings.tabSecurity')" name="security" lazy>
        <el-form label-width="200px" :label-position="labelPos" style="max-width: 720px">
          <el-divider content-position="left">{{ t('settings.panelConfig') }}</el-divider>
          <el-form-item :label="t('settings.panelPort')">
            <el-input-number v-model="panel.port" :min="1" :max="65535" :controls="false" style="width: 220px" />
            <span class="mt-subtle" style="margin-left: 12px">{{ t('settings.portHint') }}</span>
          </el-form-item>
          <el-form-item :label="t('settings.basePath')">
            <el-input v-model="panel.basePath" placeholder="/Mantou" style="width: 220px" />
            <span class="mt-subtle" style="margin-left: 12px">{{ t('settings.basePathHint') }}</span>
            <p v-if="basePathInvalid" class="mt-danger-text" style="margin: 6px 0 0">{{ t('settings.basePathInvalid') }}</p>
          </el-form-item>
          <el-form-item :label="t('settings.panelHttps')">
            <el-switch v-model="panel.https.enabled" />
          </el-form-item>
          <el-form-item v-if="panel.https.enabled" :label="t('settings.panelCert')">
            <el-select v-model="panel.https.certId" :placeholder="t('settings.panelCertRequired')" style="width: 360px">
              <el-option
                v-for="cert in certs"
                :key="cert.id"
                :label="`${cert.name} (${(cert.domains || []).join(', ')})`"
                :value="cert.id!"
              />
            </el-select>
            <span class="mt-subtle hint">{{ t('settings.panelCertHint') }}</span>
          </el-form-item>
          <el-form-item v-if="panel.https.enabled" :label="t('settings.panelDomain')">
            <el-input
              v-model="panel.https.domain"
              :placeholder="t('settings.panelDomainPlaceholder')"
              style="width: 360px"
            />
            <span class="mt-subtle hint">{{ t('settings.panelDomainHint') }}</span>
          </el-form-item>
          <el-form-item>
            <el-button type="primary" :loading="savingGeneral" @click="saveGeneral">{{ t('common.save') }}</el-button>
          </el-form-item>
          <el-divider content-position="left">{{ t('settings.tabSecurity') }}</el-divider>
          <el-form-item :label="t('settings.sessionHours')">
            <el-input-number v-model="login.sessionHours" :min="1" :max="8760" :step="1" style="width: 160px" />
            <span class="mt-subtle hint" style="margin-left: 12px">{{ t('settings.sessionHoursHint') }}</span>
          </el-form-item>
          <el-form-item :label="t('settings.sessionIdleMinutes')">
            <el-input-number v-model="login.idleMinutes" :min="0" :max="43200" :step="5" style="width: 160px" />
            <span class="mt-subtle hint" style="margin-left: 12px">{{ t('settings.sessionIdleMinutesHint') }}</span>
          </el-form-item>
          <el-form-item :label="t('settings.loginMaxFails')">
            <el-input-number v-model="login.maxFails" :min="0" :max="100" :step="1" style="width: 160px" />
            <span class="mt-subtle hint" style="margin-left: 12px">{{ t('settings.loginMaxFailsHint') }}</span>
          </el-form-item>
          <el-form-item :label="t('settings.loginLockMinutes')">
            <el-input-number v-model="login.lockMinutes" :min="1" :max="1440" :step="1" style="width: 160px" />
            <span class="mt-subtle hint" style="margin-left: 12px">{{ t('settings.loginLockMinutesHint') }}</span>
          </el-form-item>
          <el-form-item>
            <el-button type="primary" :loading="savingLogin" @click="saveLoginSecurity">
              {{ t('common.save') }}
            </el-button>
          </el-form-item>

          <el-divider content-position="left">{{ t('settings.outboundGuard') }}</el-divider>
          <el-alert
            :title="t('settings.blockPrivateNetworkDesc')"
            type="info"
            :closable="false"
            show-icon
            style="margin-bottom: 12px"
          />
          <el-form-item :label="t('settings.blockPrivateNetwork')">
            <el-switch v-model="security.blockPrivateNetwork" />
            <span class="mt-subtle hint" style="margin-left: 12px">{{ t('settings.blockPrivateNetworkHint') }}</span>
          </el-form-item>
          <el-form-item>
            <el-button type="primary" :loading="savingSecurity" @click="saveSecurity">
              {{ t('common.save') }}
            </el-button>
          </el-form-item>
        </el-form>
      </el-tab-pane>

      <!-- 重启 -->
      <el-tab-pane :label="t('settings.tabRestart')" name="restart" lazy>
        <el-form label-width="160px" :label-position="labelPos" style="max-width: 720px">
          <el-divider content-position="left">{{ t('settings.restartNow') }}</el-divider>
          <el-alert :title="t('settings.restartNowDesc')" type="info" :closable="false" show-icon style="margin-bottom: 12px" />
          <el-form-item>
            <el-button type="danger" plain :loading="restartingNow" @click="doRestartNow">
              {{ t('settings.restartNow') }}
            </el-button>
          </el-form-item>

          <el-divider content-position="left">{{ t('settings.restartSchedule') }}</el-divider>
          <el-form-item :label="t('settings.restartScheduleEnabled')">
            <el-switch v-model="restart.enabled" />
            <span class="mt-subtle hint" style="margin-left: 12px">{{ t('settings.restartScheduleHint') }}</span>
          </el-form-item>
          <el-form-item :label="t('settings.restartMode')">
            <el-radio-group v-model="restart.mode">
              <el-radio-button value="weekly">{{ t('settings.restartModeWeekly') }}</el-radio-button>
              <el-radio-button value="dates">{{ t('settings.restartModeDates') }}</el-radio-button>
              <el-radio-button value="interval">{{ t('settings.restartModeInterval') }}</el-radio-button>
            </el-radio-group>
          </el-form-item>
          <el-form-item v-if="restart.mode === 'weekly'" :label="t('settings.restartWeekdays')">
            <el-select v-model="restart.weekdays" multiple style="width: 360px">
              <el-option v-for="w in weekdayOptions" :key="w.value" :label="w.label" :value="w.value" />
            </el-select>
          </el-form-item>
          <el-form-item v-if="restart.mode === 'dates'" :label="t('settings.restartDates')">
            <el-date-picker
              v-model="restart.dates"
              type="dates"
              value-format="YYYY-MM-DD"
              :placeholder="t('settings.restartDatesPlaceholder')"
              style="width: 360px"
            />
            <span class="mt-subtle hint">{{ t('settings.restartDatesHint') }}</span>
          </el-form-item>
          <template v-if="restart.mode === 'interval'">
            <el-form-item :label="t('settings.restartEveryDays')">
              <el-input-number v-model="restart.everyDays" :min="1" :max="365" :step="1" style="width: 160px" />
              <span class="mt-subtle hint" style="margin-left: 12px">{{ t('settings.restartEveryDaysHint') }}</span>
            </el-form-item>
            <el-form-item :label="t('settings.restartStartDate')">
              <el-date-picker
                v-model="restart.startDate"
                type="date"
                value-format="YYYY-MM-DD"
                :placeholder="t('settings.restartStartDatePlaceholder')"
                style="width: 220px"
              />
              <span class="mt-subtle hint">{{ t('settings.restartStartDateHint') }}</span>
            </el-form-item>
          </template>
          <el-form-item :label="t('settings.restartAt')">
            <el-time-picker v-model="restartAt" format="HH:mm" value-format="HH:mm" style="width: 160px" />
            <span class="mt-subtle hint" style="margin-left: 12px">{{ t('settings.restartAtHint') }}</span>
          </el-form-item>
          <el-form-item :label="t('settings.restartNextRun')">
            <span>{{ restartNextRunAt ? fmtTime(restartNextRunAt) : t('settings.restartNoNextRun') }}</span>
            <span v-if="restartLastRunAt" class="mt-subtle hint" style="margin-left: 12px">
              {{ t('settings.restartLastRun') }}{{ fmtTime(restartLastRunAt) }}
            </span>
          </el-form-item>
          <el-form-item>
            <el-button type="primary" :loading="savingRestart" @click="saveRestart">{{ t('common.save') }}</el-button>
          </el-form-item>
        </el-form>
      </el-tab-pane>

      <!-- 在线更新 -->
      <el-tab-pane :label="t('settings.tabUpdate')" name="update" lazy>
        <el-form label-width="160px" :label-position="labelPos" style="max-width: 720px">
          <el-alert
            :title="t('settings.updatePriorityHint')"
            type="info"
            :closable="false"
            show-icon
            style="margin-bottom: 16px"
          />
          <el-form-item :label="t('settings.updateManifestUrl')">
            <el-input
              v-model="update.manifestUrl"
              placeholder="https://example.com/mantou/manifest.json"
              clearable
              style="width: 480px"
            />
            <p class="mt-subtle hint">{{ t('settings.updateManifestUrlHint') }}</p>
          </el-form-item>
          <el-form-item :label="t('settings.updateReleaseUrl')">
            <el-input
              v-model="update.releaseUrl"
              placeholder="https://example.com/mantou/releases"
              clearable
              style="width: 480px"
            />
            <p class="mt-subtle hint">{{ t('settings.updateReleaseUrlHint') }}</p>
          </el-form-item>
          <el-form-item :label="t('settings.updateGithubRepo')">
            <el-input
              v-model="update.githubRepo"
              placeholder="ovoene/Mantou"
              clearable
              style="width: 480px"
            />
            <p class="mt-subtle hint">{{ t('settings.updateGithubRepoHint') }}</p>
          </el-form-item>
          <el-form-item :label="t('settings.updateSignKey')">
            <el-input
              v-model="update.signKey"
              placeholder="Base64-encoded Ed25519 public key (32 bytes)"
              clearable
              style="width: 480px"
            />
            <p class="mt-subtle hint">{{ t('settings.updateSignKeyHint') }}</p>
          </el-form-item>
          <el-form-item :label="t('settings.updateAllowUnsigned')">
            <el-switch v-model="update.allowUnsignedUpdate" />
            <p class="mt-subtle hint">{{ t('settings.updateAllowUnsignedHint') }}</p>
          </el-form-item>
          <el-form-item>
            <el-button type="primary" :loading="savingUpdate" @click="saveUpdate">
              {{ t('common.save') }}
            </el-button>
          </el-form-item>
        </el-form>
      </el-tab-pane>

      <!-- 备份与恢复 -->
      <el-tab-pane :label="t('settings.tabBackup')" name="backup" lazy>
        <el-form label-width="140px" :label-position="labelPos" style="max-width: 620px">
          <el-form-item :label="t('settings.exportConfig')">
            <div style="width: 100%">
              <el-button type="primary" :loading="exporting" @click="exportConfig">
                {{ t('settings.exportBtn') }}
              </el-button>
              <p class="mt-subtle hint">{{ t('settings.exportDesc') }}</p>
              <el-alert
                :title="t('settings.exportEncryptedHint')"
                type="warning"
                :closable="false"
                show-icon
                style="margin-top: 8px"
              />
            </div>
          </el-form-item>
          <el-divider />
          <el-form-item :label="t('settings.importConfig')">
            <div style="width: 100%">
              <el-upload
                :show-file-list="false"
                :http-request="importConfig"
                accept=".json,application/json"
                :disabled="importing"
              >
                <el-button :loading="importing">{{ t('settings.chooseFile') }}</el-button>
              </el-upload>
              <p class="mt-subtle hint">{{ t('settings.importDesc') }}</p>
              <el-alert :title="t('settings.importWarn')" type="warning" :closable="false" show-icon style="margin-top: 8px" />
            </div>
          </el-form-item>
          <el-divider />

          <!-- 配置主密钥：凭证字段在磁盘上是加密的，"直接拷 data 目录"这种备份方式必须连带
               master.key，否则新环境解不开。加密导出的备份不受此限（凭证由导出口令保护）。 -->
          <el-form-item :label="t('settings.masterKey')">
            <div style="width: 100%">
              <p class="mt-subtle hint">{{ t('settings.masterKeyDesc') }}</p>
              <el-alert
                :title="t('settings.masterKeyWarn')"
                type="warning"
                :closable="false"
                show-icon
                style="margin-top: 8px"
              />
              <p class="mt-subtle hint">{{ t('settings.masterKeyEnvHint') }}</p>
            </div>
          </el-form-item>

          <el-divider content-position="left">{{ t('settings.storageTitle') }}</el-divider>
          <el-form-item :label="t('settings.storageList')">
            <div style="width: 100%">
              <p class="mt-subtle hint">{{ t('settings.storageDesc') }}</p>
              <div class="storage-bar">
                <el-button :loading="storageLoading" @click="refreshStorage">
                  {{ t('settings.storageRescan') }}
                </el-button>
                <el-button
                  type="danger"
                  :loading="storageCleaning"
                  :disabled="storagePicked.length === 0"
                  @click="cleanupStorage"
                >
                  {{ t('settings.storageCleanup') }}
                </el-button>
                <span class="mt-subtle hint">
                  {{
                    storagePicked.length > 0
                      ? t('settings.storagePicked', { count: storagePicked.length, size: fmtBytes(storagePickedSize) })
                      : t('settings.storageTotal', { count: storage.items.length, size: fmtBytes(storage.totalSize) })
                  }}
                </span>
              </div>
              <el-empty
                v-if="!storageLoading && storage.items.length === 0"
                :description="t('settings.storageEmpty')"
                :image-size="60"
              />
              <el-checkbox-group v-else v-model="storagePicked" class="storage-list">
                <el-checkbox v-for="it in storage.items" :key="it.path" :value="it.path" class="storage-row">
                  <span class="storage-path">{{ it.path }}</span>
                  <el-tag size="small" type="info" disable-transitions>{{ t(`settings.storageKind.${it.kind}`) }}</el-tag>
                  <el-tag v-if="it.note === 'fresh'" size="small" type="warning" disable-transitions>
                    {{ t('settings.storageNoteFresh') }}
                  </el-tag>
                  <span class="mt-subtle hint">{{ fmtBytes(it.size) }} · {{ fmtTimeMs(it.modTime) }}</span>
                </el-checkbox>
              </el-checkbox-group>
              <p v-if="storage.truncated" class="mt-subtle hint">
                {{ t('settings.storageTruncated', { limit: storage.limit }) }}
              </p>
            </div>
          </el-form-item>

          <!-- 导入第一步：验证本机管理员身份。与下一个弹窗刻意分开，界面上只出现一个密码框 -->
          <el-dialog
            v-model="importAuthVisible"
            :title="t('settings.importAuthTitle')"
            width="min(460px, 94vw)"
            append-to-body
            :close-on-click-modal="false"
            @closed="onImportAuthClosed"
          >
            <el-alert :title="t('settings.importAuthDesc')" type="info" :closable="false" show-icon />
            <el-form label-position="top" style="margin-top: 12px" @submit.prevent="confirmImportAuth">
              <el-form-item :label="t('settings.importAuthAccount')">
                <el-input v-model="importAuthAccount" autocomplete="off" />
              </el-form-item>
              <el-form-item :label="t('settings.importAuthPassword')">
                <div style="width: 100%">
                  <el-input
                    v-model="importAuthPassword"
                    type="password"
                    show-password
                    autocomplete="off"
                    @keyup.enter="confirmImportAuth"
                  />
                  <p class="mt-subtle hint">{{ t('settings.importAuthPwdHint') }}</p>
                </div>
              </el-form-item>
            </el-form>
            <template #footer>
              <el-button @click="cancelImportAuth">{{ t('common.cancel') }}</el-button>
              <el-button type="primary" :loading="importAuthChecking" @click="confirmImportAuth">
                {{ t('settings.importAuthNext') }}
              </el-button>
            </template>
          </el-dialog>

          <!-- 导入第二步：输入导出时使用的账户名与密码，并选择要覆盖哪些模块 -->
          <el-dialog
            v-model="importCredsVisible"
            :title="t('settings.importDecrypt')"
            width="min(560px, 94vw)"
            append-to-body
            :close-on-click-modal="false"
            @closed="onImportCredsClosed"
          >
            <el-form label-position="top">
              <el-form-item :label="t('settings.importAccount')">
                <el-input v-model="importAccount" autocomplete="off" />
              </el-form-item>
              <el-form-item :label="t('settings.importPassword')">
                <el-input v-model="importPassword" type="password" show-password autocomplete="off" />
              </el-form-item>
              <p class="mt-subtle hint">{{ t('settings.importPwdHint') }}</p>
              <el-divider style="margin: 14px 0" />
              <el-form-item>
                <template #label>
                  <div class="import-scope-head">
                    <span>{{ t('settings.importScope') }}</span>
                    <span>
                      <el-button link type="primary" @click="importModules = [...importModuleKeys]">
                        {{ t('settings.importScopeAll') }}
                      </el-button>
                      <el-button link type="primary" @click="importModules = []">
                        {{ t('settings.importScopeNone') }}
                      </el-button>
                    </span>
                  </div>
                </template>
                <div style="width: 100%">
                  <el-checkbox-group v-model="importModules" class="import-scope-grid" @change="normalizeImportModules">
                    <el-checkbox
                      v-for="m in importModuleKeys"
                      :key="m"
                      :value="m"
                      :disabled="importLocked.has(m)"
                    >
                      {{ t(importModuleLabels[m]) }}
                      <span v-if="importLocked.has(m)" class="hint">（{{ t('settings.importScopeLocked') }}）</span>
                    </el-checkbox>
                  </el-checkbox-group>
                  <p class="mt-subtle hint">{{ t('settings.importScopeHint') }}</p>
                </div>
              </el-form-item>
            </el-form>
            <template #footer>
              <el-button @click="importCredsVisible = false">{{ t('common.cancel') }}</el-button>
              <el-button type="primary" :disabled="importModules.length === 0" @click="confirmImportCreds">
                {{ t('common.confirm') }}
              </el-button>
            </template>
          </el-dialog>
        </el-form>
      </el-tab-pane>
    </el-tabs>
  </PageCard>
</template>

<style scoped>
.color-row {
  display: flex;
  gap: 24px;
}
.color-item {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 6px;
}
.slider-row {
  display: flex;
  align-items: center;
  gap: 12px;
  margin-bottom: 4px;
}
.preview-panel {
  position: sticky;
  top: 16px;
}
.mt-danger-text {
  color: var(--mt-danger);
}
.hint {
  font-size: 12px;
  margin: 6px 0 0;
}
.log-path {
  word-break: break-all;
}
/* 存储占用列表：一行一个文件，路径可能很长，让它自己占满剩下的宽度并允许换行。 */
.storage-bar {
  display: flex;
  align-items: center;
  flex-wrap: wrap;
  gap: 8px;
  margin: 8px 0;
}
.storage-bar .hint {
  margin: 0;
}
.storage-list {
  display: flex;
  flex-direction: column;
  width: 100%;
}
.storage-row {
  display: flex;
  align-items: flex-start;
  width: 100%;
  height: auto;
  margin-right: 0;
  padding: 2px 0;
}
.storage-row :deep(.el-checkbox__label) {
  display: flex;
  align-items: center;
  flex-wrap: wrap;
  gap: 8px;
  width: 100%;
  line-height: 1.6;
  white-space: normal;
}
.storage-path {
  word-break: break-all;
  font-family: ui-monospace, Menlo, Consolas, monospace;
}
.storage-row .hint {
  margin: 0;
}
/* 选择性导入的模块勾选：两列固定，九项排四行，对话框高度不会随语言变化跳动。 */
.import-scope-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  width: 100%;
}
.import-scope-grid {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 0 12px;
  width: 100%;
}
.import-scope-grid :deep(.el-checkbox) {
  margin-right: 0;
}
/* 锁定项后面那句说明跟着复选框走，不另起一行。 */
.import-scope-grid .hint {
  margin: 0;
}

/* 窄屏：勾选项后面跟着一句说明，两栏各不足 240 像素时那句说明要折三四行，
 * 反而比一栏更难看。 */
@media (max-width: 560px) {
  .import-scope-grid {
    grid-template-columns: minmax(0, 1fr);
  }
}
</style>
