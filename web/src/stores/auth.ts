import { defineStore } from 'pinia'
import { ref } from 'vue'
import { ElMessage } from 'element-plus'
import api, { notifyUnauthorized } from '@/api/client'
// store 不是组件，拿不到 useI18n()；直接用全局实例翻译，抛给视图层的错误文案才能跟随语言。
import { i18n } from '@/i18n'

interface InitStatus {
  initialized: boolean
}
interface MeResp {
  username: string
  twoFA: { enabled: boolean }
  // 本次会话距「令牌有效时长」到期还剩多少秒。后端取不到会话时不带这个字段，
  // 因此是可选的——缺失时看门狗不排闹钟，退回"下次请求被 401 弹走"的老行为。
  expiresIn?: number
}

export const useAuthStore = defineStore('auth', () => {
  const username = ref<string>('')
  const authed = ref<boolean>(false)
  const initialized = ref<boolean | null>(null)

  // ── 会话到期看门狗 ──────────────────────────────────────────────────────────
  //
  // 「令牌有效时长」（设置 → 登录安全，Auth.SessionHours）是从登录那一刻起算的绝对上限。
  // 到点之后服务端就会拒绝这条会话，但浏览器不会自己知道：页面上没有任何请求要发，
  // 界面就停在原样，直到用户点了什么或按了刷新，才被一个 401 弹回登录页。
  // 于是"面板明明开着、点一下才发现早就掉线了"——多开窗口时更难看：
  // 有的窗口已经跳走，有的还亮着一个能填的表单。
  //
  // 做法：/auth/me 顺带下发剩余秒数（见 handleMe），前端在本地排一个到期闹钟，
  // 到点先向服务端确认一次再退出，并把结果广播给同源的其它窗口。
  const EXPIRY_KEY = 'mantou_session_expired' // 跨窗口广播用的 localStorage 键
  const TICK_MS = 20_000 // 墙钟巡检周期；也是"问不到服务端"时的重试间隔
  // setTimeout 的延时上限约 2^31 毫秒（24.8 天），超过就会**立刻**触发。
  // 令牌有效时长可以设得比这更长，因此长延时要分段排，不能一次交给 setTimeout。
  const MAX_TIMEOUT_MS = 2_147_483_000

  let deadline = 0 // 本地时间轴上的到期时刻（ms）；0 表示没有在计时
  let expiryTimer: ReturnType<typeof setTimeout> | null = null
  let tickTimer: ReturnType<typeof setInterval> | null = null
  let expiring = false // 正在处置到期：闹钟、巡检、切回前台三条路可能同时到，只处置一次
  let watching = false // 全局监听器只挂一次（store 是单例，但 armExpiryWatch 会被反复调用）

  function clearExpiryWatch() {
    deadline = 0
    if (expiryTimer !== null) {
      clearTimeout(expiryTimer)
      expiryTimer = null
    }
    if (tickTimer !== null) {
      clearInterval(tickTimer)
      tickTimer = null
    }
  }

  // armExpiryWatch 按"还剩多少秒"排闹钟。
  //
  // expiresIn 缺失或不是正数时**不排**：那种情况下宁可退回原来的行为（下次请求被 401 弹走），
  // 也不要靠猜一个有效期把人踢下线——猜错的方向是"还能用却被赶出去"。
  function armExpiryWatch(expiresIn: unknown) {
    clearExpiryWatch()
    if (typeof expiresIn !== 'number' || !Number.isFinite(expiresIn) || expiresIn <= 0) return
    deadline = Date.now() + expiresIn * 1000
    expiryTimer = setTimeout(checkExpiry, Math.min(expiresIn * 1000, MAX_TIMEOUT_MS))
    // 墙钟巡检：定时器只看流逝的时间，看不到"系统时钟往前跳了一大截"（休眠唤醒、对时）。
    tickTimer = setInterval(checkExpiry, TICK_MS)
    installExpiryListeners()
  }

  // checkExpiry 到点了没有？没到就把闹钟重排一次。
  //
  // "没到就重排"这一条同时兜住两件事：超过 24.8 天被 setTimeout 截断成立刻触发的长延时，
  // 以及系统时钟往后跳导致的提前叫醒。两者都不该让人下线。
  function checkExpiry() {
    if (!deadline || expiring) return
    const left = deadline - Date.now()
    if (left > 0) {
      if (expiryTimer !== null) clearTimeout(expiryTimer)
      expiryTimer = setTimeout(checkExpiry, Math.min(left, MAX_TIMEOUT_MS))
      return
    }
    void handleExpired()
  }

  // handleExpired 到点了：先向服务端确认一次，再决定退不退。
  //
  // 为什么不直接退——本地这个到期时刻可能已经不准了：改密码会换发新令牌（见后端
  // rotateCurrentSession），有效时长也可以在设置页改大，两者都把真正的到期时间推后，
  // 而这个窗口手里还是旧的那份。直接踢下线就成了"明明还有效却被赶出去"。
  // 多问一次的代价是一个请求，而这个请求本身就是判决：成功即说明会话还活着
  // （顺带拿回新的剩余秒数并重排闹钟），401 才是真的失效。
  //
  // 断网、网关报错这类"问不到"一律不当作失效：闹钟已经响过，之后由巡检每 TICK_MS 再问一次，
  // 网络回来就自然收敛。把"连不上服务器"当成"会话过期"会在每次短暂断网时把人赶下线。
  async function handleExpired() {
    if (expiring) return
    expiring = true
    // 先记下"本窗口原本是登录着的"，别等确认回来再看：401 会先经过 api/client 的响应拦截器，
    // 而那里注册的处置（见 router/index.ts 的 setUnauthorizedHandler）已经把 authed 清成 false，
    // 于是下面的 forceLogout 再去读就分不出该不该说明原因了。分不出的代价正好落在最要紧的
    // 那条路上：面板闲置到令牌到期，页面一声不响地跳回登录页，而"为什么我被退出了"没人回答。
    const wasAuthed = authed.value
    try {
      await fetchMe()
    } catch (e: any) {
      if (e?.status === 401) forceLogout(true, wasAuthed)
    } finally {
      expiring = false
    }
  }

  // forceLogout 会话已失效时的本地退出：清状态、说明原因、通知别的窗口、回登录页。
  //
  // 不调 /auth/logout：会话在服务端已经没了，那个请求只会换回一个 401。
  // broadcast=false 用于"别的窗口告诉我它过期了"这条路——收到广播的窗口不再往回广播，
  // 否则两个窗口会互相触发。
  //
  // wasAuthed 决定要不要说明原因，默认现读。调用方能提前取到更准的值时应当传进来
  // （见 handleExpired：401 的处置会先把 authed 清掉，到这里就已经读不出原样了）。
  function forceLogout(broadcast = true, wasAuthed = authed.value) {
    clearExpiryWatch()
    authed.value = false
    username.value = ''
    if (broadcast) broadcastExpired()
    // 本来就没登录时不弹提示：那是刷新页面、或者本来就停在登录页的正常状态，
    // 冒出一句"会话已过期"只会让人以为出了错。
    if (wasAuthed) ElMessage.warning({ message: i18n.global.t('login.expired'), duration: 6000 })
    notifyUnauthorized()
  }

  // broadcastExpired 通知同源的其它窗口一起退出。
  //
  // 必须广播，不能让每个窗口各自等自己的闹钟：后台标签页的定时器会被浏览器降频到分钟级，
  // 被冻结的标签页干脆一点都不跑。最坏情况下前台窗口已经回到登录页，后台那个还亮着表单，
  // 而"所有窗口都退出"正是这件事要的结果。
  //
  // 用 localStorage 而不是 BroadcastChannel：多窗口协调本项目已经在用 localStorage
  // （见 main.ts 的标签页心跳），同一件事不必再引第二套机制。值里带随机数是为了让每次写入
  // 都与上次不同——写入同值时部分浏览器不派发 storage 事件。
  function broadcastExpired() {
    try {
      localStorage.setItem(EXPIRY_KEY, `${Date.now()}-${Math.random()}`)
    } catch {
      /* 隐私模式下可能不可写：广播失败只是别的窗口晚一点自己发现，不影响本窗口 */
    }
  }

  // installExpiryListeners 挂上三个"到点了要立刻知道"的补充信号，只挂一次。
  function installExpiryListeners() {
    if (watching || typeof window === 'undefined') return
    watching = true
    // 切回前台立刻查一次：后台标签页的定时器被降频，休眠期间可能整段没跑。
    document.addEventListener('visibilitychange', () => {
      if (document.visibilityState === 'visible') checkExpiry()
    })
    window.addEventListener('focus', checkExpiry)
    // 别的窗口先发现到期：本窗口不必再问服务端一遍，直接退出。
    // storage 事件只在**其它**窗口触发，不会打到写入方自己身上。
    window.addEventListener('storage', (e) => {
      if (e.key !== EXPIRY_KEY || !e.newValue) return
      if (!authed.value) return
      forceLogout(false)
    })
  }

  async function checkInit(): Promise<boolean> {
    const s = await api.get<InitStatus>('/init/status')
    initialized.value = s.initialized
    return s.initialized
  }

  async function setup(user: string, pass: string) {
    await api.post('/init/setup', { username: user, password: pass })
    initialized.value = true
  }

  // 登录：接口 200 只说明「用户名密码对」，不说明浏览器真的存下了会话 Cookie。
  // 所以这里不再乐观地置 authed=true，而是紧接着请求一次 /auth/me 做实证——
  // 那次请求会带上浏览器实际持有的 Cookie，成功即证明会话链路通了（me() 内部会置 authed）。
  //
  // 为什么必须实证：面板启用过 HTTPS 又关掉、之后从 http + 同一域名访问时，浏览器里可能残留
  // 一条 Secure 会话 Cookie，按 RFC 6265bis 的 Strict Secure Cookies 规则，明文来源下发的
  // 同名 Cookie 会被整条丢弃（服务端也无法删除它）。后端已改为按协议分用不同的 Cookie 名来绕开
  // （见 internal/server/middleware.go），但只要「登录成功却没拿到会话」还有可能发生
  // （例如浏览器拦截了本站点全部 Cookie），乐观赋值就会让路由守卫跳过 me() 校验、放行进入面板，
  // 再被首个业务接口的 401 弹回登录页——也就是用户看到的「闪一下」。
  // 实证失败时直接抛出可读原因，比闪一下有用得多。
  async function login(user: string, pass: string) {
    await api.post('/auth/login', { username: user, password: pass })
    if (!(await me())) {
      username.value = ''
      throw new Error(i18n.global.t('login.noSession'))
    }
  }

  // fetchMe 取当前登录信息并顺手排好到期闹钟。会抛出——调用方要能区分 401（真的失效）
  // 与断网（问不到），这正是 me() 的 try/catch 吃掉的那点信息，而看门狗必须知道。
  async function fetchMe(): Promise<MeResp> {
    const m = await api.get<MeResp>('/auth/me')
    username.value = m.username
    authed.value = true
    armExpiryWatch(m.expiresIn)
    return m
  }

  async function me(): Promise<boolean> {
    try {
      await fetchMe()
      return true
    } catch {
      authed.value = false
      clearExpiryWatch() // 会话不成立就没有到期时刻可言，别留一个孤零零的定时器在跑
      return false
    }
  }

  async function logout() {
    try {
      await api.post('/auth/logout')
    } finally {
      clearExpiryWatch()
      authed.value = false
      username.value = ''
    }
  }

  // 修改账户：可选改用户名 + 改密码（改密码需验旧密码）。
  // 返回是否修改了用户名（用于前端提示重新登录）。
  async function changeAccount(payload: {
    username?: string
    oldPassword: string
    newPassword?: string
  }): Promise<{ usernameChanged: boolean; passwordChanged: boolean }> {
    const r = await api.post<{ usernameChanged: boolean; passwordChanged: boolean }>(
      '/auth/account',
      payload,
    )
    if (payload.username && !r.usernameChanged) {
      // 后端认为用户名未变（与现值相同），保持本地不变。
    } else if (r.usernameChanged && payload.username) {
      username.value = payload.username
    }
    return r
  }

  return {
    username,
    authed,
    initialized,
    checkInit,
    setup,
    login,
    me,
    logout,
    changeAccount,
  }
})
