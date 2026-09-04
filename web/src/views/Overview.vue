<script setup lang="ts">
import { ref, computed, onActivated, onDeactivated, onBeforeUnmount, watch, nextTick } from 'vue'
import { useI18n } from 'vue-i18n'
import * as echarts from 'echarts/core'
import { LineChart } from 'echarts/charts'
import {
  GridComponent,
  TooltipComponent,
  LegendComponent,
} from 'echarts/components'
import { CanvasRenderer } from 'echarts/renderers'
import api from '@/api/client'
import { usePolling } from '@/composables/usePolling'
import { useAppearanceStore } from '@/stores/appearance'
import { currentLocale } from '@/i18n'

echarts.use([LineChart, GridComponent, TooltipComponent, LegendComponent, CanvasRenderer])

const { t, locale } = useI18n()
const appearance = useAppearanceStore()

interface Sample {
  time: number
  sysCpu: number
  procCpu: number
  // sysMem 只用在卡片上，不画成曲线：容器里读到的是容器可见的那个上限（见 sysMemScope）。
  sysMem: number
  downRate: number
  upRate: number
  // 与 info.memUsedMB 同一口径（容器整体或本进程），画在 CPU 图的右轴上。
  memUsedMB: number
}
interface Info {
  startedAt: number
  procMemMB: number
  // 面板显示的那个数：在容器里是整个容器的占用（与 docker stats 同口径），
  // 不在容器里就等于 procMemMB。后端两个都发，见 internal/metrics/cgroupmem.go。
  memUsedMB: number
  // 上面那个数到底是哪一种口径。两者差得挺多（容器那个含页缓存等），
  // 而读不到 cgroup 时会静默退到本程序——标出来才不会被当成"程序省内存了"。
  memScope: 'container' | 'process'
  // 系统内存的已用与总量 MB。与 sysMem 那个百分比出自同一次读取，故三个数对得上。
  sysMemUsedMB: number
  sysMemTotalMB: number
  // 上面那三个数是站在哪儿看的。容器里 /proc/meminfo 往往已被容器化，读到的是容器
  // 可见的上限而不是宿主机内存——从容器内部拿不到宿主机的真值，所以只能标明口径。
  sysMemScope: 'container' | 'host'
  recvTotal: number
  sentTotal: number
  version: string
}
interface ModStatus {
  name: string
  total: number
  active: number
  healthy: boolean
}

const info = ref<Info | null>(null)
const latest = ref<Sample | null>(null)
const statuses = ref<ModStatus[]>([])
type LogEntry = {
  time: string
  level: string
  message: string
  fields?: Record<string, unknown>
}

// LogRow 是一条日志「渲染就绪」的形态：级别样式、时间串、消息分词、字段串全部预先算好。
//
// 为什么不在模板里直接调 fmtProgramLogLine / formatFields：这个面板每 3 秒整体刷新一次，
// 模板里的函数调用没有缓存，每次重绘都要为每一行重跑一遍分词（fmtProgramLogLine 是个
// 几十行的状态机）+ 两次 formatFields（原模板里 v-if 和插值各调一次）+ 一次
// toLocaleTimeString（Intl 调用，单次约几十微秒）。数据每 3 秒才变一次，
// 却按重绘次数付费，纯属浪费。挪到 load() 里就变成「每条日志算一次」。
type LogRow = {
  key: string
  level: string
  levelCls: string
  timeStr: string
  tokens: LogToken[]
  fields: string
}

const logRows = ref<LogRow[]>([])
// 是否渲染程序日志面板：由设置「首页显示日志」控制（服务端按 homeLimit 限量返回）。
const showLogs = ref(true)

// 顶部动态时钟已移至主框架顶栏（MainLayout），此处不再渲染。

const cpuEl = ref<HTMLDivElement>()
const netEl = ref<HTMLDivElement>()
let cpuChart: echarts.ECharts | null = null
let netChart: echarts.ECharts | null = null

function fmtBytes(n: number): string {
  if (!n) return '0 B'
  const u = ['B', 'KB', 'MB', 'GB', 'TB']
  let i = 0
  let v = n
  while (v >= 1024 && i < u.length - 1) {
    v /= 1024
    i++
  }
  return `${v.toFixed(v >= 100 || i === 0 ? 0 : 1)} ${u[i]}`
}
function fmtRate(n: number): string {
  return `${fmtBytes(n)}/s`
}
function fmtUptime(startedMs: number): string {
  const s = Math.max(0, Math.floor((Date.now() - startedMs) / 1000))
  const d = Math.floor(s / 86400)
  const h = Math.floor((s % 86400) / 3600)
  const m = Math.floor((s % 3600) / 60)
  if (d > 0) return `${d}d ${h}h ${m}m`
  if (h > 0) return `${h}h ${m}m`
  return `${m}m`
}

// 启动日期（按语言）：中文 x年x月x日；英文 xxxx-xx-xx。入参 Unix 毫秒。
function fmtDate(ms?: number): string {
  if (!ms) return '—'
  const d = new Date(ms)
  const p = (n: number) => (n < 10 ? '0' + n : '' + n)
  if (currentLocale() === 'zh-CN') {
    return `${d.getFullYear()}年${d.getMonth() + 1}月${d.getDate()}日`
  }
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}`
}

// 启动时间（时分秒）：HH:mm:ss，与上方年月日同语言展示。入参 Unix 毫秒。
function fmtTime(ms?: number): string {
  if (!ms) return ''
  const d = new Date(ms)
  const p = (n: number) => (n < 10 ? '0' + n : '' + n)
  return `${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`
}

function baseChart(el: HTMLDivElement) {
  const c = echarts.init(el)
  return c
}

// SERIES_CAP 本地保留的采样点数，与后端 metrics 采集器的环形容量一致。
const SERIES_CAP = 180
// POLL_MS 轮询间隔。
const POLL_MS = 3000

// 图表数据按「列」维护并就地增删：每轮只推入新点、丢掉溢出的旧点。
// 早先每 3 秒都要把 /series 返回的 180 个采样点 × 4 条序列重新 map 一遍再整体 setOption，
// 七百多个数据点的重建在低端设备（树莓派上开浏览器、手机访问）上有可感知的卡顿与持续 GC 压力。
const cols = {
  times: [] as string[],
  sysCpu: [] as number[],
  procCpu: [] as number[],
  memMB: [] as number[],
  down: [] as number[],
  up: [] as number[],
}
// lastSampleTime 已取到的最新采样点时间戳，作为下一轮增量拉取的游标（0 表示尚无数据，取全量）。
let lastSampleTime = 0

function clearCols() {
  cols.times.length = 0
  cols.sysCpu.length = 0
  cols.procCpu.length = 0
  cols.memMB.length = 0
  cols.down.length = 0
  cols.up.length = 0
  lastSampleTime = 0
}

function pushSample(s: Sample) {
  cols.times.push(new Date(s.time).toLocaleTimeString())
  cols.sysCpu.push(s.sysCpu)
  cols.procCpu.push(s.procCpu)
  cols.memMB.push(s.memUsedMB)
  cols.down.push(s.downRate)
  cols.up.push(s.upRate)
  if (cols.times.length > SERIES_CAP) {
    cols.times.shift()
    cols.sysCpu.shift()
    cols.procCpu.shift()
    cols.memMB.shift()
    cols.down.shift()
    cols.up.shift()
  }
  if (s.time > lastSampleTime) lastSampleTime = s.time
}

// 图例一行放不下时会自动折成第二行，而格子（grid）的上边距是定值——
// 不跟着变的话第二行图例正好压在纵轴最上面那个刻度上（375 像素屏实测：
// 第三个序列名压住「100%」）。于是把上边距做成按容器宽度取值：
// 窄到图例要折行时，多留一行图例的高度。
//
// 不用 legend 的 scroll 模式：那样图例永远只剩一行，末尾多出「1/3 ‹ ›」的翻页箭头，
// 序列名还会被截成半截，比多留一行空白难看得多。
const LEGEND_ROW = 22
const GRID_TOP = 30

// oneRowMin 是"图例还能排在一行里"的最小容器宽度，按各图自己的序列名量：
// 每项是图标 25 + 间隙 5 + 文字，项与项之间再加 10。
function gridTop(el: HTMLElement | null | undefined, oneRowMin: number): number {
  const w = el ? el.clientWidth : 0
  // 容器还没量到（首次渲染早于挂载）时按宽屏算，随后 ResizeObserver 会纠正。
  if (w === 0) return GRID_TOP
  return w < oneRowMin ? GRID_TOP + LEGEND_ROW : GRID_TOP
}

// CPU 图左轴是百分比（系统 / 进程 CPU），右轴是内存（MB），图例共三项。
// 「系统内存」那条早已移走——容器里它读的是容器可见的上限，画成一条随时间走的线
// 太容易被当成整机内存趋势。三项里英文名最长：System CPU / Process CPU / Memory usage，
// 按 echarts 默认字体（12px）量出来一行要 329 像素，取 360 留点余量；中文那三项只要 259，
// 于是 259~360 这一段其实排得下一行却也多留了 22 像素——那只是格子矮一点，不误读数。
//
// 第三项的名字直接用「内存占用」那条文案（overview.memUsed），与上面那张指标卡同一个键：
// 图上这条线画的就是卡片上那个数（同一口径，见后端 effectiveMemLocked），
// 两处叫法不一样只会让人以为是两个指标。
const CPU_LEGEND_MIN = 360
const NET_LEGEND_MIN = 150

function renderCharts() {
  const primary = appearance.appearance.colors.primary
  const accent = appearance.appearance.colors.accent
  const memColor = appearance.appearance.colors.warning
  const times = cols.times.slice()
  const axisColor = 'rgba(140,150,170,0.5)'

  cpuChart?.setOption({
    // 右轴刻度带单位（「300 MB」），比左轴的「100%」宽，右留 16 会把标签画出画布右缘。
    // 取 58 是按四位数量的：12px 字体下「3000 MB」47 像素 + 轴标签默认留白 8 = 55。
    // 容器口径下几个 GB 很常见，按三位数留就会把最后一位裁掉。
    grid: { left: 42, right: 58, top: gridTop(cpuEl.value, CPU_LEGEND_MIN), bottom: 24 },
    // confine：提示框不越出这一格。窄屏上格子只有两百来像素宽，
    // 不加这一条它会探到屏幕外面去（见下方 .chart 的注释）。
    tooltip: { trigger: 'axis', confine: true },
    legend: {
      data: [t('overview.sysCpu'), t('overview.procCpu'), t('overview.memUsed')],
      top: 0,
      textStyle: { color: axisColor },
    },
    xAxis: { type: 'category', data: times, axisLine: { lineStyle: { color: axisColor } }, axisLabel: { color: axisColor, hideOverlap: true } },
    // 两条纵轴共享同一格：左轴百分比（0–100），右轴内存 MB（0 起——曲线从 40 还是
    // 45 开始，视觉上会放大波动的幅度，让几十 MB 的差别看起来像翻了一倍）。
    //
    // alignTicks 让右轴的刻度数跟左轴对齐。不加这一条时两轴各自算刻度：左轴固定 6 个
    // （0/20/…/100），右轴按数据范围自己挑，实测挑成 7 个（0/5/…/30 MB）。
    // 而横向网格线只由左轴画，于是右侧那几个 MB 标签落在两条网格线中间——
    // 首尾对得上、中间对不上，看着像是网格线错位了。
    yAxis: [
      { type: 'value', max: 100, splitLine: { lineStyle: { color: 'rgba(140,150,170,0.14)' } }, axisLabel: { color: axisColor, formatter: '{value}%' } },
      { type: 'value', min: 0, alignTicks: true, splitLine: { show: false }, axisLabel: { color: axisColor, formatter: '{value} MB' } },
    ],
    series: [
      { name: t('overview.sysCpu'), type: 'line', smooth: true, showSymbol: false, data: cols.sysCpu.slice(), lineStyle: { width: 2, color: primary }, areaStyle: { color: primary, opacity: 0.1 }, tooltip: { valueFormatter: (v: number) => `${v}%` } },
      { name: t('overview.procCpu'), type: 'line', smooth: true, showSymbol: false, data: cols.procCpu.slice(), lineStyle: { width: 2, color: accent }, tooltip: { valueFormatter: (v: number) => `${v}%` } },
      // 内存值与「内存占用」卡片同一个口径（容器整体或本进程，见后端 effectiveMemLocked），
      // 颜色用警告橙而非成功绿：青绿的强调色和绿色相近，两条线会分不清。
      // 三条线的 tooltip 各带各的单位：纵轴都分了两条，提示里再不标单位，45 和 5.6 摆一起，
      // 十有八九被当成同一类数。
      {
        name: t('overview.memUsed'),
        type: 'line',
        smooth: true,
        showSymbol: false,
        data: cols.memMB.slice(),
        yAxisIndex: 1,
        lineStyle: { width: 2, color: memColor },
        tooltip: { valueFormatter: (v: number) => `${v} MB` },
      },
    ],
  })

  netChart?.setOption({
    grid: { left: 56, right: 16, top: gridTop(netEl.value, NET_LEGEND_MIN), bottom: 24 },
    tooltip: { trigger: 'axis', confine: true, valueFormatter: (v: number) => fmtRate(v) },
    legend: {
      data: [t('overview.down'), t('overview.up')],
      top: 0,
      textStyle: { color: axisColor },
    },
    xAxis: { type: 'category', data: times, axisLine: { lineStyle: { color: axisColor } }, axisLabel: { color: axisColor, hideOverlap: true } },
    yAxis: { type: 'value', splitLine: { lineStyle: { color: 'rgba(140,150,170,0.14)' } }, axisLabel: { color: axisColor, formatter: (v: number) => fmtBytes(v) } },
    series: [
      { name: t('overview.down'), type: 'line', smooth: true, showSymbol: false, data: cols.down.slice(), lineStyle: { width: 2, color: '#2fb37f' }, areaStyle: { color: '#2fb37f', opacity: 0.1 } },
      { name: t('overview.up'), type: 'line', smooth: true, showSymbol: false, data: cols.up.slice(), lineStyle: { width: 2, color: '#e6a23c' } },
    ],
  })
}

// updateCharts 只推数据，不重建坐标轴 / 图例 / 配色等结构，让 ECharts 走最小 diff。
function updateCharts() {
  const times = cols.times.slice()
  cpuChart?.setOption(
    {
      xAxis: { data: times },
      series: [{ data: cols.sysCpu.slice() }, { data: cols.procCpu.slice() }, { data: cols.memMB.slice() }],
    },
    { lazyUpdate: true },
  )
  netChart?.setOption(
    {
      xAxis: { data: times },
      series: [{ data: cols.down.slice() }, { data: cols.up.slice() }],
    },
    { lazyUpdate: true },
  )
}

// applySeries 消化一次 /overview/series 的响应。
// full=true（首次拉取，或游标已被后端环形缓冲淘汰）时整体替换并重建图表；
// 否则把增量追加到本地列上，走轻量更新。没有新点时连 setOption 都不调。
function applySeries(series: Sample[], full: boolean) {
  if (full) {
    clearCols()
    series.forEach(pushSample)
    renderCharts()
    return
  }
  if (series.length === 0) return
  series.forEach(pushSample)
  updateCharts()
}

async function load(silent = false) {
  const opts = silent ? { silent: true } : undefined
  // 带上游标只取新采样点：全量约 18 KB，增量（3 秒内 1–2 个点）约 200 B。
  const seriesParams = lastSampleTime > 0 ? { since: String(lastSampleTime) } : undefined
  const [ov, sr, lg] = await Promise.all([
    api.get<{ info: Info; latest?: Sample; statuses: ModStatus[] }>('/overview', undefined, opts),
    api.get<{ series: Sample[]; full?: boolean }>('/overview/series', seriesParams, opts),
    api.get<{ logs: LogEntry[]; showOnHome?: boolean }>('/logs', { home: '1' }, opts),
  ])
  info.value = ov.info
  latest.value = ov.latest || null
  statuses.value = ov.statuses || []
  showLogs.value = lg.showOnHome !== false
  logRows.value = buildLogRows(lg.logs || [])
  // full 缺省按全量处理，兼容不返回该字段的旧后端。
  applySeries(sr.series || [], sr.full !== false)
}

const resize = () => {
  cpuChart?.resize()
  netChart?.resize()
  // 容器宽度变了，图例是一行还是两行也可能跟着变——把格子的上边距重算一遍。
  // 只推 grid 一项，坐标轴与数据都不动（见 updateCharts 的说明）。
  cpuChart?.setOption(
    { grid: { top: gridTop(cpuEl.value, CPU_LEGEND_MIN) } },
    { lazyUpdate: true },
  )
  netChart?.setOption(
    { grid: { top: gridTop(netEl.value, NET_LEGEND_MIN) } },
    { lazyUpdate: true },
  )
}

// 画布跟着容器走，不跟着窗口走。
//
// 从前听的是 window 的 resize。可容器变宽变窄有几种情形根本不经过窗口：折叠侧栏、
// 改字号。那时画布留在上一次的尺寸上——echarts 把宽高写成行内 px——容器变宽就在右边留一条白，
// 变窄则整块画布探到卡片外面去，把页面顶出一条横向滚动。ResizeObserver 直接量容器，
// 这几种情形连同窗口缩放、手机横竖屏切换一并覆盖。
let ro: ResizeObserver | null = null

function observeCharts() {
  if (ro) return
  ro = new ResizeObserver(resize)
  if (cpuEl.value) ro.observe(cpuEl.value)
  if (netEl.value) ro.observe(netEl.value)
}

function unobserveCharts() {
  ro?.disconnect()
  ro = null
}

// 轮询：切页停、标签页不可见停、重新可见补一次，三条都在 usePolling 里
//（那里也记着为什么值得停——后台标签页的轮询白占上行带宽，还让后端为无人查看的页面采样）。
//
// poll.start() 在页面切走后会自动变成空操作，因此下面 onActivated 里那句
// 「await load() 之后再 start」不需要自己记一个 alive 标记：若这期间用户已经切到别的模块，
// 这一句什么也不做，不会留下一个谁都不会停掉的定时器。
const poll = usePolling(() => load(true), POLL_MS)

// 页面被激活（含首次挂载——keep-alive 下 onActivated 在 onMounted 之后同样会触发一次，
// 因此这里是唯一的入口，不需要"首次挂载"分支）。
// 图表实例与容器尺寸监听在这里成对建立、在 onDeactivated 成对拆除。
onActivated(async () => {
  await nextTick()
  // 复用缓存实例：keep-alive 保留了 DOM，切回来时 cpuEl/netEl 仍是同一批元素，
  // 重新 init 会泄漏掉旧实例（echarts 以 DOM 为键，重复 init 会告警）。
  if (!cpuChart && cpuEl.value) cpuChart = baseChart(cpuEl.value)
  if (!netChart && netEl.value) netChart = baseChart(netEl.value)
  // 离开期间侧栏可能被折叠、窗口可能被缩放，那时监听已摘除，容器尺寸与画布不一致。
  resize()
  observeCharts()
  // 拉取失败不应连带把轮询也一起废掉（否则一次瞬时错误就让页面永久停在旧数据上）。
  try {
    await load()
  } catch {
    /* 忽略瞬时错误，交给下一轮轮询 */
  }
  poll.start()
})

onDeactivated(unobserveCharts)

// keep-alive 缓存被销毁时（退出登录 / 整个布局卸载）才真正释放 echarts 实例。
onBeforeUnmount(() => {
  unobserveCharts()
  cpuChart?.dispose()
  netChart?.dispose()
  cpuChart = null
  netChart = null
})

// 主题色 / 语言变化时重建图表结构（配色与图例文案），本地已有数据，无需再拉一次。
watch(
  () => appearance.appearance.colors,
  () => renderCharts(),
  { deep: true },
)
watch(locale, () => renderCharts())

// 模块名一律由后端给键名（webhook / notify / ddns…），译名放在 overview.modName 里。
// 查不到就原样显示那个键名——这是兜底，不是设计：新增模块时必须补上中英两份译名，
// 否则中文界面会冒出一个英文单词（用户看到的是「notify 是什么」）。
function modLabel(name: string): string {
  const key = `overview.modName.${name}`
  const s = t(key)
  return s === key ? name : s
}

function formatFields(fields?: Record<string, unknown>): string {
  if (!fields) return ''
  return Object.entries(fields)
    .filter(([, value]) => value !== undefined && value !== null && value !== '')
    .map(([key, value]) => `${key}=${String(value)}`)
    .join(' ')
}

// 程序日志行的结构化上色：仅对「访问日志」类消息（含 ip为 + Web服务下）做分词，
// 将 IP 上 ip 色、父/子规则名上 rule 色；其余系统消息（Web 服务已启动 等）保持原样。
// 返回 token 数组（非 v-html，避免 XSS）。
type LogToken = {
  text: string
  cls?: 'log-ip' | 'log-rule' | 'log-reason' | 'log-days-urgent' | 'log-days-soon' | 'log-days-ok'
}
function fmtProgramLogLine(message: string): LogToken[] {
  const ipLabel = 'ip为'
  const webLabel = 'Web服务下'
  // 子项分隔符三种写法（UI 统一渲染为「 规则下 」）：
  // 1) 新格式「 规则下 」（无内部空格，当前后端产出）；2) 旧格式「规则下的」；3) 早期格式「 规则 下的 」。
  const ruleSep = ' 规则下 '
  const ruleSepAlt = '规则下的'
  const ruleSepLegacy = ' 规则 下的 '

  const ipPos = message.indexOf(ipLabel)
  const webPos = message.indexOf(webLabel)
  // 非访问日志：直接原样返回（单 token 纯文本）。
  if (ipPos === -1 || webPos === -1 || ipPos > webPos) {
    return [{ text: message }]
  }

  const tokens: LogToken[] = []
  let s = message

  // 前缀（通常为空）
  if (ipPos > 0) tokens.push({ text: s.slice(0, ipPos) })

  // 「ip为」标签 + 空格 + IP 值（一并上 ip 色；标签与值之间恒留一个空格）
  let ipValStart = ipPos + ipLabel.length
  while (ipValStart < s.length && s[ipValStart] === ' ') ipValStart++
  const comma = s.indexOf('，', ipPos)
  const ipEnd = comma === -1 ? s.length : comma
  tokens.push({ text: s.slice(ipPos, ipValStart), cls: 'log-ip' })
  tokens.push({ text: ' ' })
  tokens.push({ text: s.slice(ipValStart, ipEnd), cls: 'log-ip' })

  // 中段：「，动词 Web服务下 」直到父项规则名开始
  const webFull = s.indexOf(webLabel + ' ', ipEnd)
  let parentStart: number
  if (webFull !== -1) {
    parentStart = webFull + webLabel.length + 1
  } else {
    const webNoSpace = s.indexOf(webLabel, ipEnd)
    if (webNoSpace === -1) {
      tokens.push({ text: s.slice(ipEnd) })
      return tokens
    }
    parentStart = webNoSpace + webLabel.length
  }
  tokens.push({ text: s.slice(ipEnd, parentStart) })

  // 子项规则分隔符：优先新格式「 规则下 」，其次旧格式「规则下的」，再其次早期格式「 规则 下的 」
  const cNew = s.indexOf(ruleSep, parentStart)
  const cOld = s.indexOf(ruleSepAlt, parentStart)
  const cLegacy = s.indexOf(ruleSepLegacy, parentStart)
  let childSep = -1
  let childSepLen = 0
  if (cNew !== -1 && (cOld === -1 || cNew <= cOld) && (cLegacy === -1 || cNew <= cLegacy)) {
    childSep = cNew
    childSepLen = ruleSep.length
  } else if (cOld !== -1 && (cLegacy === -1 || cOld <= cLegacy)) {
    childSep = cOld
    childSepLen = ruleSepAlt.length
  } else if (cLegacy !== -1) {
    childSep = cLegacy
    childSepLen = ruleSepLegacy.length
  }

  // 父项规则名结束于子项分隔符或「 服务」
  const svcSep = s.indexOf(' 服务', parentStart)
  const parentEnd = childSep !== -1 ? childSep : svcSep === -1 ? s.length : svcSep
  tokens.push({ text: s.slice(parentStart, parentEnd).trim(), cls: 'log-rule' })

  if (childSep !== -1) {
    // 分隔符本身（纯文本）；不论源串是「 规则下 」「规则下的」还是「 规则 下的 」，UI 统一渲染为「 规则下 」（保留前后词间距，去掉内部空格）。
    tokens.push({ text: ' 规则下 ' })
    const childStart = childSep + childSepLen
    const childEnd = svcSep === -1 ? s.length : svcSep
    tokens.push({ text: s.slice(childStart, childEnd).trim(), cls: 'log-rule' })
    // 末尾：拒绝 / 错误的具体原因（被拒绝（403 …）/ 出错（502 …）），整段以告警色高亮。
    const tail = s.slice(childEnd)
    if (tail.includes('被拒绝（') || tail.includes('出错（')) {
      tokens.push({ text: tail, cls: 'log-reason' })
    } else {
      tokens.push({ text: tail })
    }
  } else {
    const tail = s.slice(parentEnd)
    if (tail.includes('被拒绝（') || tail.includes('出错（')) {
      tokens.push({ text: tail, cls: 'log-reason' })
    } else {
      tokens.push({ text: tail })
    }
  }

  return tokens
}

// 证书日志里的剩余天数与「已过期」，按紧迫程度上色。
//
// 为什么要上色：证书检查那条日志一行里可能报好几张证书，天数混在文字中间，扫一眼看不出
// 哪个数字要紧——而这条日志的全部用处就是"要紧的那张能被一眼看见"。
//
// 「剩余有效期 N 天」（含「不少于 N 天」）是紧迫程度，上色；
// 「将在 N 天后自动续期」是排期，不上色——它数字越小越安全，跟着一起变红只会让人误读。
const certDaysRe = /(剩余有效期(?:不少于)?\s*)(\d+\s*天)|(已过期)/g

// certDayCls 天数对应的颜色档。阈值固定：一周内红、一个月内橙、再往后绿。
// 不跟「提前续期天数」联动：那是每张证书各自的设置，同一行里两张证书用两套阈值，
// 颜色就失去了"横向比较哪张更急"的意义。
function certDayCls(days: number): LogToken['cls'] {
  if (days <= 7) return 'log-days-urgent'
  if (days <= 30) return 'log-days-soon'
  return 'log-days-ok'
}

// colorizeCertDays 把已分好词的 token 再过一遍，只切开还没上色的纯文本部分。
// 已有 cls 的（IP、规则名那些）原样放过：那些段里不会出现证书天数，切开只会打乱既有配色。
function colorizeCertDays(tokens: LogToken[]): LogToken[] {
  const out: LogToken[] = []
  for (const tk of tokens) {
    if (tk.cls || !tk.text.includes('天') && !tk.text.includes('已过期')) {
      out.push(tk)
      continue
    }
    let last = 0
    certDaysRe.lastIndex = 0
    for (let m = certDaysRe.exec(tk.text); m; m = certDaysRe.exec(tk.text)) {
      if (m.index > last) out.push({ text: tk.text.slice(last, m.index) })
      if (m[3]) {
        out.push({ text: m[3], cls: 'log-days-urgent' })
      } else {
        out.push({ text: m[1] })
        out.push({ text: m[2], cls: certDayCls(parseInt(m[2], 10)) })
      }
      last = m.index + m[0].length
    }
    if (last === 0) {
      out.push(tk)
    } else if (last < tk.text.length) {
      out.push({ text: tk.text.slice(last) })
    }
  }
  return out
}

// buildLogRows 把后端返回的日志（旧→新）翻成倒序（新→旧）并一次性算好每行的展示形态。
//
// key 用「时间戳 + 同一时间戳内的序号」而不是数组下标：下标做 key 时，每次轮询有新日志进来，
// 所有行的下标都会平移一位，Vue 只能判定"每一行都变了"从而重建整段 DOM；
// 用内容相关的 key，未变的旧日志能被原地复用，只有新增/移出的那几行才动。
// 后端时间戳是纳秒精度的 RFC3339，同一时间戳撞车极少见，但仍用计数器兜住以免 key 重复。
function buildLogRows(entries: LogEntry[]): LogRow[] {
  const seen = new Map<string, number>()
  const rows: LogRow[] = []
  for (let i = entries.length - 1; i >= 0; i--) {
    const e = entries[i]
    const dup = seen.get(e.time) ?? 0
    seen.set(e.time, dup + 1)
    rows.push({
      key: dup === 0 ? e.time : `${e.time}#${dup}`,
      level: e.level,
      levelCls: e.level.toLowerCase(),
      timeStr: new Date(e.time).toLocaleTimeString(),
      tokens: colorizeCertDays(fmtProgramLogLine(e.message)),
      fields: formatFields(e.fields),
    })
  }
  return rows
}

// 系统内存卡片下面那行「已用 / 总量 MB」。
//
// 光有百分比不够用：同样的 30%，在 1.5 GB 的小机器和 64 GB 的机器上是两码事，
// 而这个面板恰好常跑在前者上。总量摆出来，百分比才有得参照。
const sysMemPair = computed(() => {
  if (!info.value || info.value.sysMemTotalMB <= 0) return ''
  return `${info.value.sysMemUsedMB.toFixed(0)} / ${info.value.sysMemTotalMB.toFixed(0)} MB`
})

// 系统内存卡片最下面那行口径标注。
//
// 为什么非标不可：容器里的 /proc/meminfo 往往已经被容器化过（第三方容器平台常用 lxcfs
// 那类做法），读到的是**本容器可见的那个上限**，不是宿主机的物理内存；再往外套一层容器，
// 看到的就是外层那一层的视角。从容器内部拿不到宿主机的真值，这是隔离本身要做的事。
// 既然改不了，就把它标出来——用户不会再拿这个数去跟宿主机那边的监控对账。
const sysMemScopeText = computed(() => {
  if (!info.value) return ''
  return info.value.sysMemScope === 'container'
    ? t('overview.sysMemScopeContainer')
    : t('overview.sysMemScopeHost')
})

// 内存占用卡片下面那行口径标注。
//
// 为什么非标不可：容器整体与本程序是两个差得挺多的数——前者含页缓存、内核为这个容器
// 分配的内存以及容器里的其他进程，通常比后者大不少。而读不到 cgroup 文件时后端会
// 静默地从前者退到后者，不标出来，数字小了一截也看不出是换了口径。
const memScopeText = computed(() => {
  if (!info.value) return ''
  return info.value.memScope === 'container'
    ? t('overview.memScopeContainer')
    : t('overview.memScopeProcess')
})
</script>

<template>
  <div class="ov">
    <div class="page-title">
      <div class="page-title-main">
        <h2 class="mt-title">{{ t('overview.title') }}</h2>
        <p class="mt-subtle">{{ t('overview.subtitle') }}</p>
      </div>
    </div>

    <!-- 关键指标卡片 -->
    <div class="stat-grid">
      <div class="mt-glass stat">
        <span class="stat-label">{{ t('overview.sysCpu') }}</span>
        <span class="stat-val">{{ latest ? latest.sysCpu.toFixed(1) : '—' }}<i>%</i></span>
      </div>
      <div class="mt-glass stat">
        <span class="stat-label">{{ t('overview.sysMem') }}</span>
        <span class="stat-val">{{ latest ? latest.sysMem.toFixed(1) : '—' }}<i>%</i></span>
        <span class="stat-sub">{{ sysMemPair }}</span>
        <span class="stat-sub">{{ sysMemScopeText }}</span>
      </div>
      <div class="mt-glass stat">
        <span class="stat-label">{{ t('overview.memUsed') }}</span>
        <span class="stat-val">{{ info ? info.memUsedMB.toFixed(0) : '—' }}<i>MB</i></span>
        <span class="stat-sub">{{ memScopeText }}</span>
      </div>
      <div class="mt-glass stat">
        <span class="stat-label">{{ t('overview.startedAt') }}</span>
        <span class="stat-val small">
          <span class="date-main">{{ info ? fmtDate(info.startedAt) : '—' }}</span>
          <span class="date-time">{{ info ? fmtTime(info.startedAt) : '' }}</span>
        </span>
      </div>
      <div class="mt-glass stat uptime-mini">
        <span class="stat-label">{{ t('overview.uptime') }}</span>
        <span class="stat-val small">{{ info ? fmtUptime(info.startedAt) : '—' }}</span>
      </div>
      <div class="mt-glass stat wide">
        <span class="stat-label">{{ t('overview.down') }} / {{ t('overview.up') }}</span>
        <span class="stat-val small">
          {{ latest ? fmtRate(latest.downRate) : '—' }}
          <em>/ {{ latest ? fmtRate(latest.upRate) : '—' }}</em>
        </span>
      </div>
    </div>

    <!-- 图表 -->
    <div class="chart-grid">
      <div class="mt-glass chart-card">
        <div class="chart-head">{{ t('overview.realtime') }} · CPU / {{ t('overview.memUsed') }}</div>
        <div ref="cpuEl" class="chart"></div>
      </div>
      <div class="mt-glass chart-card">
        <div class="chart-head">{{ t('overview.net') }}</div>
        <div ref="netEl" class="chart"></div>
      </div>
    </div>

    <div class="bottom-grid">
      <!-- 模块状态 -->
      <div class="mt-glass panel">
        <div class="panel-head">{{ t('overview.modules') }}</div>
        <div class="mod-list">
          <div v-for="m in statuses" :key="m.name" class="mod-row">
            <span class="dot" :class="{ bad: !m.healthy }"></span>
            <span class="mod-name">{{ modLabel(m.name) }}</span>
            <span class="mod-meta">
              {{ t('overview.active') }} {{ m.active }} / {{ m.total }}
            </span>
            <el-tag :type="m.healthy ? 'success' : 'danger'" size="small" effect="light" round>
              {{ m.healthy ? t('overview.healthy') : t('overview.unhealthy') }}
            </el-tag>
          </div>
          <div v-if="!statuses.length" class="mt-subtle empty">{{ t('common.empty') }}</div>
        </div>
      </div>

      <!-- 日志 -->
      <div v-if="showLogs" class="mt-glass panel">
        <div class="panel-head">{{ t('overview.logs') }}</div>
        <div class="log-list">
          <div v-for="l in logRows" :key="l.key" class="log-row">
            <span class="log-level" :class="l.levelCls">{{ l.level }}</span>
            <span class="log-time">{{ l.timeStr }}</span>
            <span class="log-msg">
              <template v-for="(tk, ti) in l.tokens" :key="ti">
                <span v-if="tk.cls" :class="tk.cls">{{ tk.text }}</span>
                <span v-else>{{ tk.text }}</span>
              </template>
              <span v-if="l.fields" class="log-fields">{{ l.fields }}</span>
            </span>
          </div>
          <div v-if="!logRows.length" class="mt-subtle empty">{{ t('overview.noLogs') }}</div>
        </div>
      </div>
    </div>
  </div>
</template>

<style scoped>
.ov {
  display: flex;
  flex-direction: column;
  gap: 14px;
}
.page-title {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 16px;
}
.page-title h2 {
  margin: 0;
}
.page-title p {
  margin: 3px 0 0;
}
.stat-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
  gap: 12px;
}
.stat {
  padding: 16px 16px 14px;
  display: flex;
  flex-direction: column;
  gap: 8px;
}
.stat-label {
  font-size: 12.5px;
  color: var(--mt-text-soft);
}
.stat-val {
  font-size: 26px;
  font-weight: 680;
  line-height: 1;
}
.stat-val.small {
  font-size: 16px;
  font-weight: 600;
}
/* 指标卡的副行（内存那两张卡用）。
 *
 * 字号比主数字小一大截、颜色用弱化色：它是给主数字作注解的，不该跟主数字抢。
 * margin-top 是负的，把 flex 的 8px 间距收回一部分——副行紧贴主数字才读得出"这是同一件事"。 */
.stat-sub {
  margin-top: -3px;
  font-size: 12px;
  font-weight: 500;
  line-height: 1.2;
  color: var(--mt-text-soft);
  /* 空串时（后端还没返回）不要塌成 0 高，否则同一行里的卡片会先矮一下再跳高。 */
  min-height: 14px;
}
/* 启动日期：年-月-日 与 时分秒 同字号，时分秒置于其下方 */
.date-main {
  display: block;
}
.date-time {
  display: block;
  margin-top: 4px;
  font-size: 16px;
  font-weight: 600;
  color: var(--mt-text-soft);
}
/* 上行/下行卡片加宽，避免实时速率换行 */
.stat.wide {
  grid-column: span 2;
}
.stat.wide .stat-val {
  white-space: nowrap;
}
/* 运行时长卡片更紧凑 */
.stat.uptime-mini {
  padding: 11px 14px;
}
.stat.uptime-mini .stat-val.small {
  font-size: 15px;
}
.stat-val i {
  font-size: 13px;
  font-weight: 500;
  font-style: normal;
  color: var(--mt-text-soft);
  margin-left: 3px;
}
.stat-val em {
  font-style: normal;
  color: var(--mt-text-soft);
  font-weight: 500;
}
.chart-grid {
  display: grid;
  /* minmax(0, 1fr) 而不是 1fr：1fr 的下限是 auto，也就是格子内容的最小宽度，
   * 而 echarts 会把画布尺寸写成行内 px。窗口一旦变窄（手机横竖屏切换就是），
   * 列宽被上一次的画布宽度顶住不肯收，图表卡便探到页面右边去，整篇文档跟着变宽；
   * 而 resize 回调量的又是这个被顶住的容器，于是画布再也回不去——只能变宽不能变窄。
   * 下限改成 0，列宽跟着容器走，画布随后由 resize 回调重画。 */
  grid-template-columns: minmax(0, 1fr) minmax(0, 1fr);
  gap: 14px;
}
.chart-card {
  padding: 16px 16px 8px;
}
.chart-head {
  font-size: 14px;
  font-weight: 600;
  margin-bottom: 6px;
}
.chart {
  height: 240px;
  width: 100%;
  /* 裁掉停在格子外的提示框。
   *
   * echarts 的提示框是挂在这一格里的绝对定位节点，收起时只是 visibility: hidden——
   * 节点仍留在布局里。于是手机上碰过一次图表，那个不换行的提示框就一直顶在页面右边，
   * 整篇文档跟着变宽、始终能横向滚（320px 屏上实测 scrollWidth 476）。
   * 上面的 confine 管住新弹出的位置，这一层裁剪管住它停在上一次位置的那段时间。 */
  overflow: hidden;
}
.bottom-grid {
  display: grid;
  /* 同 .chart-grid：下限给 0，格内那些不换行的内容（日志行、状态标签）不再把列撑宽。 */
  grid-template-columns: minmax(0, 1fr) minmax(0, 1fr);
  gap: 14px;
}
.panel {
  padding: 18px 18px 16px;
}
.panel-head {
  font-size: 15px;
  font-weight: 640;
  margin-bottom: 12px;
}
.mod-list {
  display: flex;
  flex-direction: column;
  gap: 8px;
}
.mod-row {
  display: flex;
  align-items: center;
  /* row-gap 比 column-gap 小：换行之后那一行是同一条记录的续行，靠紧一点才看得出是一组。 */
  gap: 4px 10px;
  /* 允许换行。这一行是「圆点 + 模块名 + 活跃数 + 状态标签」，四样都已经缩到最小
   * （名字和活跃数是能折行的文字，标签自己 nowrap，宽 60），加上间距一共要 216 像素。
   * 320 像素宽的屏上这一格只有 178，不给换行的话标签就会伸到卡片外面去——
   * 整篇文档跟着变宽、右边多出一条横向滚动条，也就是"要缩放才能看全"的来处之一。
   * 放得下的时候这一条不生效，宽屏一个像素都没动。 */
  flex-wrap: wrap;
  padding: 7px 0;
  border-bottom: 1px solid rgba(140, 150, 170, 0.12);
}
.dot {
  width: 9px;
  height: 9px;
  border-radius: 50%;
  background: var(--mt-success);
  flex-shrink: 0;
}
.dot.bad {
  background: var(--mt-danger);
}
.mod-name {
  font-weight: 550;
}
.mod-meta {
  margin-left: auto;
  font-size: 12.5px;
  color: var(--mt-text-soft);
}
.empty {
  padding: 18px 0;
  text-align: center;
}
.log-list {
  display: flex;
  flex-direction: column;
  gap: 3px;
  max-height: 268px;
  overflow-y: auto;
  font-family: 'SFMono-Regular', ui-monospace, Menlo, Consolas, monospace;
  font-size: 12px;
}
.log-row {
  display: flex;
  gap: 8px;
  padding: 3px 4px;
  border-radius: 6px;
  font-weight: 600;
}
.log-row:hover {
  background: rgba(140, 150, 170, 0.08);
}
.log-level {
  flex-shrink: 0;
  width: 46px;
  font-weight: 700;
  color: var(--mt-text-soft);
}
.log-level.info {
  color: var(--mt-primary);
}
.log-level.warn {
  color: var(--mt-warning);
}
.log-level.error {
  color: var(--mt-danger);
}
.log-time {
  flex-shrink: 0;
  color: var(--mt-text-soft);
}
.log-msg {
  color: var(--mt-text);
  word-break: break-all;
}
.log-ip {
  color: var(--ws-ip-color);
}
.log-rule {
  color: var(--ws-rule-color);
}
.log-reason {
  color: var(--ws-denied-color);
}
/* 证书剩余天数三档。只给颜色不加粗：日志行整行本来就是 600，再加一次没有任何效果
   （改前实测如此），要区分只能往 700 上走，那又比这一页其他任何文字都重。 */
.log-days-urgent {
  color: var(--mt-danger);
}
.log-days-soon {
  color: var(--mt-warning);
}
.log-days-ok {
  color: var(--mt-success);
}
.log-fields {
  color: var(--mt-text-soft);
  margin-left: 6px;
}
@media (max-width: 1100px) {
  .stat-grid {
    grid-template-columns: repeat(3, minmax(0, 1fr));
  }
  .chart-grid,
  .bottom-grid {
    grid-template-columns: minmax(0, 1fr);
  }
}

/* 手机：指标卡固定两列。
 *
 * 原先是 auto-fit + minmax(150px, 1fr)：窄屏只排得下一列，而「下行 / 上行」那张卡
 * 跨两列，网格便自己长出一条隐式列——隐式列按内容取宽，于是整排卡片被顶到页面右边去。
 * 固定两列后跨列依然成立，且两列都是 minmax(0, 1fr)，不会再被内容撑宽。
 * 「运行时长」一并跨两列，是为了不在最后留一格空洞（五张单列卡 + 一张跨列卡凑不满两列）。 */
@media (max-width: 480px) {
  .stat-grid {
    grid-template-columns: repeat(2, minmax(0, 1fr));
  }
  .stat {
    padding: 13px 12px 12px;
  }
  /* 两列布局下卡片只剩 104px 内宽，而「10217 / 16285 MB」在 12px 时正好是 105px——
   * 差 1px 就会折成两行，那一行读起来还断在斜杠上。降一档字号留出余量。
   * 不用 nowrap：宁可折行也不能让文字顶出卡片。 */
  .stat-sub {
    font-size: 11px;
  }
  .stat.uptime-mini {
    grid-column: span 2;
  }
}
</style>
