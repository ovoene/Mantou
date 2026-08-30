import { defineStore } from 'pinia'
import { ref } from 'vue'
import api from '@/api/client'
import { actions, type UpdateCheck } from '@/api/resources'

// 版本 / 在线更新状态。版本号、官网地址、编译时间统一来自后端 /api/meta/version
// 接口（由后端 version 包在编译期经 gen.go 注入）；在线更新检测（最新版本比对）仅在「关于」页触发。
export const useSystemStore = defineStore('system', () => {
  const check = ref<UpdateCheck | null>(null)
  const checking = ref(false)
  // 版本文件内容：版本号 / 官网地址 / 编译时间 / 运行平台。
  const versionInfo = ref<{ version: string; officialUrl: string; buildTime: string; os: string; arch: string } | null>(null)

  // 读取后端 /meta/version 接口返回的版本信息（构建时经 gen.go 写入编译时间）。
  async function loadVersion(): Promise<void> {
    try {
      versionInfo.value = await api.get<{ version: string; officialUrl: string; buildTime: string; os: string; arch: string }>(
        '/meta/version',
      )
    } catch {
      versionInfo.value = null
    }
  }

  // force=true 时跳过缓存强制重新检测（供「检查更新」按钮使用），保证断网/限流后点按钮能立刻重试。
  async function refreshUpdate(force = false): Promise<void> {
    if (checking.value) return
    checking.value = true
    try {
      check.value = await actions.updateCheck(force)
    } catch {
      // 网络/接口异常统一按「网络无法连接」处理。
      check.value = {
        currentVersion: '',
        latestVersion: '',
        hasUpdate: false,
        configured: true,
        networkError: true,
        checked: false,
        releaseUrl: '',
        buildTime: '',
        description: '',
      }
    } finally {
      checking.value = false
    }
  }

  return { check, checking, versionInfo, loadVersion, refreshUpdate }
})
