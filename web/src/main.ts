import { createApp } from 'vue'
import { createPinia } from 'pinia'
import ElementPlus from 'element-plus'
import 'element-plus/dist/index.css'
import 'element-plus/theme-chalk/dark/css-vars.css'

import App from './App.vue'
import router from './router'
import { i18n } from './i18n'
import './style.css'
import { useAppearanceStore } from './stores/appearance'
import { basePath } from './api/client'

const app = createApp(App)
app.use(createPinia())
app.use(router)
app.use(i18n)
app.use(ElementPlus)

// 应用本地缓存的外观，避免首屏闪烁（登录后会再从服务端同步）。
useAppearanceStore().applyLocalCache()

app.mount('#app')

// 关闭页面时主动注销：仅当"最后一个标签"真实关闭才向服务端发送软注销信标；刷新页面不登出
// （服务端宽限内复用同一会话保活）。
// 多标签页协调：用 localStorage 维护「存活标签心跳表」（tabId -> 最近心跳时间戳），每个标签定时
// 写入心跳；加载/卸载时清理过期条目，修复标签页崩溃/强杀（pagehide 不触发）导致的计数泄漏，
// 仅当本标签是「最后一个存活标签」时才发信标，关掉多个标签中的某一个不登出。
// 刷新判定：pagehide 时写入 sessionStorage 标记，下一次 load 若读到该标记即视为刷新，不发送信标。
const TABS_KEY = 'mantou_tabs' // 存活标签心跳表：tabId -> 最近心跳时间戳(ms)
const RELOAD_MARKER = 'mantou_reload_marker' // sessionStorage：上一页面卸载标记，用于区分刷新
const HEARTBEAT_TTL = 15000 // 心跳过期时间（ms），超过即视为标签已失效
const HEARTBEAT_INTERVAL = 5000 // 心跳写入间隔（ms）

function myTabId(): string {
  let id = sessionStorage.getItem('mantou_tab_id')
  if (!id) {
    id = 't_' + Math.random().toString(36).slice(2) + Date.now().toString(36)
    sessionStorage.setItem('mantou_tab_id', id)
  }
  return id
}

function readTabs(): Record<string, number> {
  try {
    return JSON.parse(localStorage.getItem(TABS_KEY) || '{}')
  } catch {
    return {}
  }
}

function writeTabs(t: Record<string, number>) {
  try {
    localStorage.setItem(TABS_KEY, JSON.stringify(t))
  } catch {
    /* ignore */
  }
}

// 清理过期（崩溃/强杀未卸载）的标签心跳；返回清理后的存活表并写回。
function pruneTabs(): Record<string, number> {
  const t = readTabs()
  const now = Date.now()
  let changed = false
  for (const k of Object.keys(t)) {
    if (now - t[k] > HEARTBEAT_TTL) {
      delete t[k]
      changed = true
    }
  }
  if (changed) writeTabs(t)
  return t
}

function attachLogoutOnUnload() {
  const id = myTabId()
  // 刷新判定：本标签上一轮卸载写过标记 → 本次 load 是刷新，不登出。
  const isReload = sessionStorage.getItem(RELOAD_MARKER) === '1'
  if (isReload) sessionStorage.removeItem(RELOAD_MARKER)

  // 登记本标签心跳（顺便在加载时清理其它崩溃标签）。
  const beat = () => {
    const t = pruneTabs()
    t[id] = Date.now()
    writeTabs(t)
  }
  beat()
  const hb = window.setInterval(beat, HEARTBEAT_INTERVAL)

  const sendLogoutBeacon = () => {
    try {
      // 软注销信标：标记会话待删除（服务端宽限），不删除 Cookie——刷新可在宽限内保活。
      navigator.sendBeacon(
        basePath + '/api/auth/session/close',
        new Blob(['{}'], { type: 'application/json' }),
      )
    } catch {
      // 卸载期尽力而为，忽略失败（如浏览器已无网络）。
    }
  }

  const onUnload = () => {
    window.clearInterval(hb)
    // 移除本标签心跳并清理其它标签中可能过期的条目（崩溃/强杀未卸载）。
    const t = readTabs()
    delete t[id]
    const now = Date.now()
    for (const k of Object.keys(t)) {
      if (now - t[k] > HEARTBEAT_TTL) delete t[k]
    }
    writeTabs(t)
    // 标记「即将卸载」，供下一次 load 判定是否为刷新（刷新则不发信标）。
    try {
      sessionStorage.setItem(RELOAD_MARKER, '1')
    } catch {
      /* ignore */
    }
    // 仅「最后一个存活标签真实关闭（非刷新）」才发送软注销信标。
    if (Object.keys(t).length <= 0 && !isReload) sendLogoutBeacon()
  }
  window.addEventListener('pagehide', onUnload)
}
attachLogoutOnUnload()
