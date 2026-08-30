import { createI18n } from 'vue-i18n'
import { ref } from 'vue'
import zhCN from './zh-CN'
import enUS from './en-US'
// Element Plus 内置文案（表格空态「No Data」、下拉框占位「Select」等）需要单独的 locale，
// 否则始终以英文默认显示，无法跟随界面语言切换。
import zhCn from 'element-plus/es/locale/lang/zh-cn'
import enLocale from 'element-plus/es/locale/lang/en'

const STORAGE_KEY = 'mantou.lang'

function detectLocale(): string {
  const saved = localStorage.getItem(STORAGE_KEY)
  if (saved === 'zh-CN' || saved === 'en-US') return saved
  const nav = navigator.language || 'zh-CN'
  return nav.toLowerCase().startsWith('zh') ? 'zh-CN' : 'en-US'
}

// 当前 Element Plus locale（与 Vue I18n 的 locale 保持同步）。
export const elLocale = ref(detectLocale() === 'zh-CN' ? zhCn : enLocale)

export const i18n = createI18n({
  legacy: false,
  locale: detectLocale(),
  fallbackLocale: 'en-US',
  messages: { 'zh-CN': zhCN, 'en-US': enUS },
})

export function setLocale(locale: 'zh-CN' | 'en-US') {
  i18n.global.locale.value = locale
  localStorage.setItem(STORAGE_KEY, locale)
  document.documentElement.lang = locale
  // 同步切换 Element Plus 内置文案语言。
  elLocale.value = locale === 'zh-CN' ? zhCn : enLocale
}

export function currentLocale(): 'zh-CN' | 'en-US' {
  return i18n.global.locale.value as 'zh-CN' | 'en-US'
}
