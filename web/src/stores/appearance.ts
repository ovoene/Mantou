import { defineStore } from 'pinia'
import { ref } from 'vue'
import api, { withBase } from '@/api/client'
import {
  type Appearance,
  defaultAppearance,
  cloneAppearance,
} from './appearanceTypes'

const CACHE_KEY = 'mantou.appearance'
const SHADOW_MAP: Record<string, string> = {
  none: 'none',
  sm: '0 4px 14px rgba(20, 27, 45, 0.08)',
  md: '0 8px 30px rgba(20, 27, 45, 0.12)',
  lg: '0 16px 48px rgba(20, 27, 45, 0.2)',
}

// hex → rgba，供卡片不透明度使用。
function hexToRgba(hex: string, alpha: number): string {
  const m = hex.replace('#', '')
  const full = m.length === 3 ? m.split('').map((c) => c + c).join('') : m
  const r = parseInt(full.slice(0, 2), 16) || 255
  const g = parseInt(full.slice(2, 4), 16) || 255
  const b = parseInt(full.slice(4, 6), 16) || 255
  return `rgba(${r}, ${g}, ${b}, ${alpha})`
}

// hex → [r,g,b]。
function hexToRgb(hex: string): [number, number, number] {
  const m = hex.replace('#', '')
  const full = m.length === 3 ? m.split('').map((c) => c + c).join('') : m
  return [
    parseInt(full.slice(0, 2), 16) || 255,
    parseInt(full.slice(2, 4), 16) || 255,
    parseInt(full.slice(4, 6), 16) || 255,
  ]
}

// 将两种 hex 颜色按比例混合（amount 为 a 所占比重 0..1），用于由主色生成整页背景色调。
function mixHex(a: string, b: string, amount: number): string {
  const pa = hexToRgb(a)
  const pb = hexToRgb(b)
  const ch = (x: number, y: number) => Math.round(x * amount + y * (1 - amount))
  const r = ch(pa[0], pb[0])
  const g = ch(pa[1], pb[1])
  const bl = ch(pa[2], pb[2])
  return `#${[r, g, bl].map((v) => v.toString(16).padStart(2, '0')).join('')}`
}

// 校验渐变值语法：仅允许 linear/radial/conic-gradient，禁止可逃逸的属性注入字符与外部资源。
function isSafeGradient(v: string): boolean {
  const s = (v || '').trim()
  if (!/^(linear|radial|conic)-gradient\(/i.test(s)) return false
  if (/[;{}]/.test(s)) return false
  if (/url\s*\(/i.test(s)) return false
  return true
}

// 校验纯色值：仅允许 hex（3/6/8 位）或 rgb/rgba。
function isSafeColor(v: string): boolean {
  const s = (v || '').trim()
  if (/^#([0-9a-fA-F]{3}|[0-9a-fA-F]{6}|[0-9a-fA-F]{8})$/.test(s)) return true
  return /^rgba?\(\s*\d{1,3}\s*,\s*\d{1,3}\s*,\s*\d{1,3}\s*(,\s*(0|1|0?\.\d+)\s*)?\)$/i.test(s)
}

// 转义背景图路径中的引号，防止拼接 url("...") 时逃逸。
function escapeUrlPath(p: string): string {
  return (p || '').replace(/"/g, '%22').replace(/'/g, '&#39;')
}

// 将一份外观配置写入 :root 的 CSS 变量——这是「实时预览」的核心。
export function applyAppearance(a: Appearance) {
  const root = document.documentElement

  // 主题模式（auto 跟随系统）。
  let dark = a.themeMode === 'dark'
  if (a.themeMode === 'auto') {
    dark = window.matchMedia('(prefers-color-scheme: dark)').matches
  }
  root.setAttribute('data-theme', dark ? 'dark' : 'light')
  // Element Plus 深色变量（main.ts 引入的 dark/css-vars.css）只在 html.dark 类下生效，
  // 必须与 data-theme 同步切换，否则 EP 组件（输入框/下拉/表格/表单标签/弹窗）仍是浅色主题的
  // 深色文字，叠在深色玻璃卡片上导致「字看不清、颜色不协调」。
  root.classList.toggle('dark', dark)

  // 主题色。
  root.style.setProperty('--mt-primary', a.colors.primary)
  root.style.setProperty('--mt-accent', a.colors.accent)
  root.style.setProperty('--mt-success', a.colors.success)
  root.style.setProperty('--mt-warning', a.colors.warning)
  root.style.setProperty('--mt-danger', a.colors.danger)
  root.style.setProperty('--el-color-primary', a.colors.primary)

  // 背景层。
  // 整页背景默认跟随主色自动生成柔和色调（light: 主色极淡；dark: 主色沉底），
  // 因此「改主题色 → 整页背景一并变化」，实现整体统一的观感；
  // 用户若显式指定了纯色/渐变/图片背景，则以其为准。
  const autoBg = dark
    ? mixHex(a.colors.primary, '#0b0e14', 0.2)
    : mixHex(a.colors.primary, '#ffffff', 0.12)
  const bg = a.background
  if (bg.type === 'image' && bg.value) {
    // 上传的背景图为后端相对路径（/uploads/...），子路径部署时需拼上访问前缀；转义路径引号防逃逸。
    root.style.setProperty('--mt-bg-image', `url("${escapeUrlPath(withBase(bg.value))}")`)
  } else if (bg.type === 'gradient' && bg.value && isSafeGradient(bg.value)) {
    root.style.setProperty('--mt-bg-image', bg.value)
  } else {
    root.style.setProperty('--mt-bg-image', 'none')
  }
  // 背景底色：显式纯色用其值，否则跟随主色自动生成（整页主题统一）。
  if (bg.type === 'color' && bg.value && isSafeColor(bg.value)) {
    root.style.setProperty('--mt-bg-color', bg.value)
  } else {
    root.style.setProperty('--mt-bg-color', autoBg)
  }
  root.style.setProperty('--mt-bg-fit', bg.fit || 'cover')
  root.style.setProperty('--mt-bg-position', bg.position || 'center')
  // 背景模糊为 0（默认）时把 filter 关成 none，而不是写 blur(0px)：只要它不是 none，
  // 浏览器就得为整屏背景单独开一张合成层、每次重绘重新光栅化，而默认设置下模糊的是
  // 0 像素——纯亏（见 style.css 的 .mt-backdrop）。
  const bgBlur = Math.max(0, bg.blur || 0)
  root.style.setProperty('--mt-bg-filter', bgBlur ? `blur(${bgBlur}px)` : 'none')
  // 外扩量抵消模糊糊出来的边缘留白，随半径线性增长——所以从 0 调到 1 只是稍微糊一点，
  // 不会像固定 scale(1.04) 那样让整张图突然跳大一截。3 倍是可见扩散约 3σ（见 style.css）。
  root.style.setProperty('--mt-bg-bleed', `${bgBlur * 3}px`)
  root.style.setProperty(
    '--mt-overlay',
    `rgba(${dark ? '0,0,0' : '255,255,255'}, ${bg.overlayOpacity || 0})`,
  )

  // 卡片。--mt-card-blur 不再写：卡片是实底 + 细边框，没有任何样式在读它
  // （见 style.css 的 .mt-glass），「设置 → 外观」里那个滑块也随之撤掉了。
  const cardBase = dark ? '#1c222e' : '#ffffff'
  root.style.setProperty('--mt-card-bg', hexToRgba(cardBase, a.card.opacity))
  root.style.setProperty('--mt-card-radius', `${a.card.radius}px`)
  root.style.setProperty('--mt-card-shadow', SHADOW_MAP[a.card.shadow] || SHADOW_MAP.md)

  // 字体。
  if (a.font.family && a.font.family !== 'system') {
    root.style.setProperty(
      '--mt-font-family',
      `${a.font.family}, system-ui, -apple-system, 'PingFang SC', 'Microsoft YaHei', sans-serif`,
    )
  }
  root.style.setProperty('--mt-font-scale', String(a.font.scale))
  root.style.setProperty('--mt-font-weight', String(a.font.weight))
}

export const useAppearanceStore = defineStore('appearance', () => {
  const appearance = ref<Appearance>(defaultAppearance())
  // synced 本次页面加载有没有真的从服务端取到过外观。取到之后就不必再取：
  // 外观只在设置页改，改的那一刻 save() 自己会更新。
  const synced = ref(false)
  // inflight 正在进行的那次请求。守卫每次导航都会调 ensureFetched，
  // 首次进入面板时可能连着两次导航（重定向），没有它就会发两次一样的请求。
  let inflight: Promise<void> | null = null

  // 首屏：应用本地缓存（若有），避免闪烁。
  function applyLocalCache() {
    try {
      const raw = localStorage.getItem(CACHE_KEY)
      if (raw) {
        appearance.value = { ...defaultAppearance(), ...JSON.parse(raw) }
      }
    } catch {
      /* ignore */
    }
    applyAppearance(appearance.value)

    // 跟随系统深浅色变化。
    window
      .matchMedia('(prefers-color-scheme: dark)')
      .addEventListener('change', () => {
        if (appearance.value.themeMode === 'auto') applyAppearance(appearance.value)
      })
  }

  // 从服务端拉取并应用。
  async function fetch() {
    try {
      const a = await api.get<Appearance>('/settings/appearance')
      appearance.value = { ...defaultAppearance(), ...a }
      synced.value = true
      cache()
      applyAppearance(appearance.value)
    } catch {
      /* 未登录或失败时保持本地缓存 */
    }
  }

  // ensureFetched 本次页面加载内至多取一次服务端外观，由路由守卫在进入面板前调用。
  //
  // 为什么不能只在守卫里「校验登录态那一支」取：从登录页进来时，auth.login() 内部已经
  // 用 /auth/me 证实过会话并把 authed 置为 true，守卫于是不再走那一支 —— 结果是首次登录的
  // 设备一次都没取过服务端外观，页面还画着前端内置的默认值，非得手动刷新一次才对。
  // 放在守卫里每次导航都调、由这里挡重复，比在登录成功处补一行更难漏。
  function ensureFetched(): Promise<void> {
    if (synced.value) return Promise.resolve()
    if (!inflight) {
      inflight = fetch().finally(() => {
        inflight = null
      })
    }
    return inflight
  }

  // 实时预览：仅应用到界面，不落库。
  function preview(a: Appearance) {
    appearance.value = a
    applyAppearance(a)
  }

  // 保存到服务端并持久化本地缓存。
  async function save(a: Appearance) {
    await api.put('/settings/appearance', a)
    appearance.value = cloneAppearance(a)
    // 刚存进去的就是服务端那份，不必再取一次。
    synced.value = true
    cache()
    applyAppearance(appearance.value)
  }

  function reset() {
    preview(defaultAppearance())
  }

  function cache() {
    try {
      localStorage.setItem(CACHE_KEY, JSON.stringify(appearance.value))
    } catch {
      /* ignore */
    }
  }

  return { appearance, applyLocalCache, fetch, ensureFetched, preview, save, reset }
})
