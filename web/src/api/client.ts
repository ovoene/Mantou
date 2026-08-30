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

http.interceptors.response.use(
  (resp) => resp,
  (err) => {
    const status = err?.response?.status
    if (status === 401 && onUnauthorized) onUnauthorized()
    const msg = err?.response?.data?.error || err?.message || '请求失败'
    return Promise.reject(new Error(msg))
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
