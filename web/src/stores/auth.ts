import { defineStore } from 'pinia'
import { ref } from 'vue'
import api from '@/api/client'
// store 不是组件，拿不到 useI18n()；直接用全局实例翻译，抛给视图层的错误文案才能跟随语言。
import { i18n } from '@/i18n'

interface InitStatus {
  initialized: boolean
}
interface MeResp {
  username: string
  twoFA: { enabled: boolean }
}

export const useAuthStore = defineStore('auth', () => {
  const username = ref<string>('')
  const authed = ref<boolean>(false)
  const initialized = ref<boolean | null>(null)

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

  async function me(): Promise<boolean> {
    try {
      const m = await api.get<MeResp>('/auth/me')
      username.value = m.username
      authed.value = true
      return true
    } catch {
      authed.value = false
      return false
    }
  }

  async function logout() {
    try {
      await api.post('/auth/logout')
    } finally {
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
