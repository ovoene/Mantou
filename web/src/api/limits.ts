import { ref } from 'vue'
import api from '@/api/client'

// 各资源的条数上限（后端 GET /api/meta/limits）。
//
// 存在这里而不是各页面自己写一个常量：显示的数必须和新增时真正拦人的那个数同源。
// 抄一遍就有两份，改了后端忘了前端，界面就会写着一个数、保存时报出另一个数——
// 而这种不一致只在用户快加满时才暴露，等于埋着不响。
//
// 一个模块级单例，不是 pinia store：这一份是"编译进后端的常量"，
// 同一次运行里不会变，没有需要跟着状态重算的东西，缓存住就够了。
const caps = ref<Record<string, number>>({})

// inflight 让同时挂载的多个页面只发一次请求。
// 失败不缓存（finally 里置回 null），下次进页面还能再试。
let inflight: Promise<void> | null = null

// maxCountOf 取某个资源的条数上限；未知或该资源没有上限时返回 0。
// 调用方据此决定要不要显示那句说明——返回 0 就什么都不显示，而不是显示「最多 0 条」。
// 读的是 ref，因此写在 computed 里能随加载完成自动重算。
export function maxCountOf(name: string): number {
  return caps.value[name] || 0
}

export function loadResourceCaps(): Promise<void> {
  if (Object.keys(caps.value).length > 0) return Promise.resolve()
  if (inflight) return inflight
  inflight = api
    .get<Record<string, number>>('/meta/limits')
    .then((m) => {
      caps.value = m || {}
    })
    .catch(() => {
      // 静默：这一份只用来在说明里多写一句确切数字，拿不到不影响任何操作——
      // 真正的上限仍由后端在新增时拦住并报出数字。
    })
    .finally(() => {
      inflight = null
    })
  return inflight
}
