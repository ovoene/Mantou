import axios, { type AxiosInstance } from 'axios'

// 运行期访问路径前缀：由后端在 index.html 注入 window.__MANTOU_BASE__（子路径部署时）。
declare global {
  interface Window {
    __MANTOU_BASE__?: string
  }
}

// 规范化后的访问前缀（""或"/xxx"，无末尾斜杠）。
export const basePath = (() => {
  const raw = (typeof window !== 'undefined' && window.__MANTOU_BASE__) || ''
  if (!raw || raw === '/') return ''
  return raw.replace(/\/+$/, '')
})()

// 将后端相对路径（如 /uploads/bg.png）拼上访问前缀。
export function withBase(path: string): string {
  if (!path) return path
  if (/^https?:\/\//i.test(path)) return path
  if (path.startsWith('/')) return basePath + path
  return path
}

// 统一的 HTTP 客户端。
// 后端约定：成功返回 { data: ... }，失败返回 { error: "消息" } 且带非 2xx 状态码。
// 会话使用 HttpOnly Cookie，同时支持 Bearer；此处以 Cookie 为主，无需手动附带。
const http: AxiosInstance = axios.create({
  baseURL: basePath + '/api',
  timeout: 20000,
  withCredentials: true,
})

// 401 时跳转登录页（由路由守卫兜底，这里只清理状态）。
let onUnauthorized: (() => void) | null = null
export function setUnauthorizedHandler(fn: () => void) {
  onUnauthorized = fn
}

// notifyUnauthorized 手工触发上面那套「会话已失效」的处置（清登录态 + 回登录页）。
//
// 给不存在 401 响应的场合用：会话到期看门狗在本地就能算出令牌已过期（见 stores/auth.ts），
// 那一刻并没有一个请求可以借它的状态码。处置逻辑仍然只有一份——否则"到期退出"与
// "401 退出"会走两条不同的路，其中一条早晚会漏掉某个该清的状态。
export function notifyUnauthorized() {
  onUnauthorized?.()
}

// ApiError 在 Error 之外多带一个 HTTP 状态码。
//
// 之前拦截器只把错误消息包成 Error 抛出，状态码就此丢掉——于是调用方只能靠比对
// 报错文案来区分错误种类，而那串文案是会被翻译、会被改写的。
// 需要区分的场合确实存在：入站防护保存时的 409 表示「参数没错，但后果要你确认一次」，
// 界面据此弹确认框；同一处的 400 是「参数写错了」，只该直接把消息显示出来。
// 仍然继承 Error，因此所有只读 e.message 的既有代码不受影响。
export class ApiError extends Error {
  status: number
  constructor(message: string, status: number) {
    super(message)
    this.name = 'ApiError'
    this.status = status
  }
}

http.interceptors.response.use(
  (resp) => resp,
  (err) => {
    const status = err?.response?.status
    if (status === 401 && onUnauthorized) onUnauthorized()
    const msg = err?.response?.data?.error || err?.message || '请求失败'
    return Promise.reject(new ApiError(msg, typeof status === 'number' ? status : 0))
  },
)

// 解包 { data } 信封。
async function unwrap<T>(p: Promise<{ data: any }>): Promise<T> {
  const resp = await p
  const body = resp.data
  if (body && typeof body === 'object' && 'data' in body) return body.data as T
  return body as T
}

// 请求扩展选项：silent=true 表示后台轮询/信标请求。后端据此不救活处于「待删除」宽限的会话，
// 使「关闭最后一个标签页」能可靠到期失效，不被周期轮询反复复活。
export type RequestOpts = { silent?: boolean }
function silentHeaders(opts?: RequestOpts): Record<string, string> | undefined {
  return opts?.silent ? { 'X-Mantou-Silent': '1' } : undefined
}

export const api = {
  get: <T>(url: string, params?: any, opts?: RequestOpts) =>
    unwrap<T>(http.get(url, { params, headers: silentHeaders(opts) })),
  post: <T>(url: string, data?: any, opts?: RequestOpts) =>
    unwrap<T>(http.post(url, data, { headers: silentHeaders(opts) })),
  put: <T>(url: string, data?: any, opts?: RequestOpts) =>
    unwrap<T>(http.put(url, data, { headers: silentHeaders(opts) })),
  del: <T>(url: string, opts?: RequestOpts) =>
    unwrap<T>(http.delete(url, { headers: silentHeaders(opts) })),
  raw: http,
}

export default api
