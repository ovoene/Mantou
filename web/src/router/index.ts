import { createRouter, createWebHistory, type RouteRecordRaw } from 'vue-router'
import { ElMessageBox } from 'element-plus'
import { useAuthStore } from '@/stores/auth'
import { useAppearanceStore } from '@/stores/appearance'
import { setUnauthorizedHandler, basePath } from '@/api/client'

// views 各模块页面的懒加载器，键即路由名。摊成一张表而不是直接写在路由里，是为了能在
// 用户点之前先把代码取回来（见 MainLayout 的 prefetchView）：每个页面是一份独立 chunk，
// 第一次点某个模块要先下载 + 解析那一份，这期间点击没有任何回应——"鼠标都移过去了却
// 觉得卡"多半就是这一下。Vite 的动态 import 自带缓存，重复调用不会重复下载。
export const views = {
  overview: () => import('@/views/Overview.vue'),
  ddns: () => import('@/views/DDNS.vue'),
  webservice: () => import('@/views/WebServices.vue'),
  mroute: () => import('@/views/MessageRoutes.vue'),
  globalfirewall: () => import('@/views/GlobalFirewall.vue'),
  forward: () => import('@/views/Forwards.vue'),
  wol: () => import('@/views/Wol.vue'),
  cron: () => import('@/views/CronTasks.vue'),
  cert: () => import('@/views/Certs.vue'),
  cred: () => import('@/views/Credentials.vue'),
  settings: () => import('@/views/Settings.vue'),
  about: () => import('@/views/About.vue'),
}

// prefetchView 取一份页面代码。取不到（离线、被拦）就算了：真正导航过去时路由自己
// 还会再试一次，这里抛出去只会在控制台留一条没人看得懂的红字。
export function prefetchView(name: string): Promise<unknown> {
  const load = (views as Record<string, (() => Promise<unknown>) | undefined>)[name]
  return load ? load().catch(() => undefined) : Promise.resolve()
}

// 子路由直接由 views 生成：路径与路由名都用同一个键，省掉"表里加了一项、路由忘了加"
// 这类只在点某个菜单时才暴露的错。
const moduleRoutes: RouteRecordRaw[] = Object.entries(views).map(([name, component]) => ({
  path: name,
  name,
  component,
}))

const routes: RouteRecordRaw[] = [
  { path: '/login', name: 'login', component: () => import('@/views/Login.vue'), meta: { public: true } },
  { path: '/setup', name: 'setup', component: () => import('@/views/Setup.vue'), meta: { public: true } },
  {
    path: '/',
    component: () => import('@/layouts/MainLayout.vue'),
    children: [{ path: '', redirect: '/overview' }, ...moduleRoutes],
  },
  { path: '/:pathMatch(.*)*', redirect: '/overview' },
]

const router = createRouter({
  history: createWebHistory(basePath || '/'),
  routes,
})

// 全局守卫：先判断是否已初始化，再判断登录态。
router.beforeEach(async (to) => {
  const auth = useAuthStore()

  if (auth.initialized === null) {
    try {
      await auth.checkInit()
    } catch {
      /* 网络异常时放行到目标页，由页面自行提示 */
    }
  }

  if (auth.initialized === false && to.name !== 'setup') {
    return { name: 'setup' }
  }
  if (auth.initialized === true && to.name === 'setup') {
    return { name: 'login' }
  }

  if (to.meta.public) return true

  if (!auth.authed) {
    const ok = await auth.me()
    if (!ok) return { name: 'login', query: { redirect: to.fullPath } }
  }
  // 登录有效：同步服务端外观。放在 if 外面 —— 从登录页进来时 authed 已经是 true（login()
  // 内部用 /auth/me 证实过会话），写在 if 里就等于首次登录不同步，得手动刷新一次颜色才对。
  // 重复调用由 store 自己挡掉（见 ensureFetched），不会每次切页都请求。
  useAppearanceStore().ensureFetched()
  return true
})

// 切页后收起还开着的确认框 / 输入框（删除确认、导出口令那一类）。
//
// 这类框不是页面模板里的元素，而是 Element Plus 现挂到 body 上的一份独立实例，
// 页面切走不会带走它。留着它有实际风险：框里问的是「确定删除？」，而它记住的是**上一页**
// 那一行；等用户在新页面上点了「删除」，删掉的是刚才那一页的东西，且看不见发生了什么。
//
// 与各页面的弹窗（见 composables/useCloseOnLeave）保持同一条规则：切页即收起。
// 放在 afterEach 而不是 beforeEach——被守卫拦掉、改道的那些导航不该顺手把框关了。
router.afterEach(() => {
  ElMessageBox.close()
})

// 401 时回登录页。
setUnauthorizedHandler(() => {
  const auth = useAuthStore()
  auth.authed = false
  if (router.currentRoute.value.name !== 'login') {
    router.replace({ name: 'login' })
  }
})

export default router
