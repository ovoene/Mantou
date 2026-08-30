import api, { type RequestOpts } from './client'

// 通用资源 CRUD 客户端，对应后端 /api/<name> 的 list/create/update/delete。
// create 的返回可能携带后端透传的非致命告警（如 DDNS 首次同步失败提示），供前端 toast。
export interface ResourceCreateResult<T> {
  item: T
  warning?: string
}

export function resourceApi<T extends { id?: string }>(name: string) {
  const base = `/${name}`
  return {
    list: (opts?: RequestOpts) => api.get<T[]>(base, undefined, opts),
    create: (item: Partial<T>) => api.post<ResourceCreateResult<T>>(base, item),
    update: (id: string, item: Partial<T>) => api.put<T>(`${base}/${id}`, item),
    remove: (id: string) => api.del<{ ok: boolean }>(`${base}/${id}`),
    // 列表里那个启用开关专用：只发 enabled，后端在已存的那份配置上改这一项。
    // 只有后端声明了 setEnabled 的资源才有这个端点（消息路由接收器 / 通知目标、网络唤醒），
    // 其余资源调用会 404 —— 页面上没有内联开关，也就不会调到。
    toggle: (id: string, enabled: boolean) =>
      api.post<{ id: string; enabled: boolean }>(`${base}/${id}/toggle`, { enabled }),
  }
}

// 数据目录里一条没人引用的文件（或暂存目录）。kind / note 是键名，界面上另行翻译。
export interface StorageItem {
  path: string
  kind: 'upload' | 'cert' | 'restore' | 'temp'
  size: number
  modTime: number
  isDir?: boolean
  note?: string
}

// DNS 服务商元信息（供前端动态渲染凭证表单）。
export interface ProviderField {
  key: string
  required: boolean
  secret: boolean
}
export interface ProviderInfo {
  name: string
  fields: ProviderField[]
}

// 更新检测结果。
export interface UpdateCheck {
  currentVersion: string
  latestVersion: string
  hasUpdate: boolean
  configured: boolean
  networkError: boolean
  // 是否因 GitHub API 限额（未认证 60 次/小时/IP）被拒；与 networkError 区分：限流是"请求太频繁"，不是断网。
  rateLimited?: boolean
  // 限流时可重试的剩余秒数（来自 GitHub X-RateLimit-Reset）；可能缺失。
  retryAfterSec?: number
	checked: boolean
	releaseUrl: string
	// 编译时间，来自后端 version 接口的 buildTime；空字符串表示未知。
	buildTime?: string
	// 官网地址，来自后端 version 接口的 officialUrl。
	officialUrl?: string
	// 程序说明：从在线清单（ManifestURL）的 description 字段拉取，关于页只读展示。
	description?: string
}

// Web 服务子项访问（连接）日志一条。
export interface WebAccessLog {
  time: number
  childId: string
  service: string
  method: string
  host: string
  status: number
  ms: number
  remote: string
  // 事件类型：connect=连接 / disconnect=断开 / error=错误 / denied=被 IP 规则拒绝。
  event: string
  // 错误 / 拒绝的具体原因（上游 err 或 IP 规则动作描述）；连接 / 断开时为空。
  reason?: string
}

// 网络唤醒候选网卡（后端 wol.InterfaceInfo）。
// auto 标记「自动」模式实际会用到的网卡：虚拟网卡（容器网桥/虚拟机/隧道）与公网网卡
// 都被排除——往它们广播既唤不醒设备，又会把目标 MAC 送给容器对端或同机房邻居。
export interface WOLInterface {
  name: string
  ip: string
  broadcast: string
  virtual: boolean
  public: boolean
  auto: boolean
}

// 各功能资源。
export const credentialsApi = resourceApi('credentials')
export const ddnsApi = resourceApi('ddns')
export const webServicesApi = resourceApi('webservices')
export const forwardsApi = resourceApi('forwards')
export const wolApi = resourceApi('wol')
export const cronApi = resourceApi('crontasks')
export const certsApi = resourceApi('certs')
export const acmeAccountsApi = resourceApi('acme-accounts')

// 资源动作。
export const actions = {
  wake: (id: string) => api.post<{ ok: boolean; result: string }>(`/wol/${id}/wake`),
  runDdns: (id: string) => api.post<{ ok: boolean; result: string }>(`/ddns/${id}/run`),
  runCron: (id: string) => api.post<{ ok: boolean; result: string }>(`/crontasks/${id}/run`),
  cronDescribe: (expr: string, lang?: string) =>
    api.get<{ text: string }>(`/meta/cron-describe`, { expr, lang }),
  // 批量翻译：一次往返问完整张列表的描述（后端按重复的 expr= 读取，items 与传入顺序一致）。
  // 手工拼查询串而不是把数组交给 axios 序列化——axios 默认会拼成 `expr[]=A&expr[]=B`，
  // 而后端读的是重复的 `expr=`（Gin 的 c.QueryArray("expr")），带方括号就一条都取不到。
  cronDescribeBatch: (exprs: string[], lang?: string) => {
    const qs = new URLSearchParams()
    for (const e of exprs) qs.append('expr', e)
    if (lang) qs.append('lang', lang)
    return api.get<{ text: string; items: string[] }>(`/meta/cron-describe?${qs.toString()}`)
  },
  issueCert: (id: string) => api.post<{ ok: boolean; result: string }>(`/certs/${id}/issue`),
  // 导出默认带私钥：证书离开面板一般是要装到别的服务上，只有公钥那半边装不起来。
  // 后端仅在 includePrivateKey=true 时才读私钥文件并回 keyPem。
  exportCert: (id: string, includePrivateKey = true) =>
    api.get<{ certPem: string; keyPem?: string }>(
      `/certs/${id}/export${includePrivateKey ? '?includePrivateKey=true' : ''}`,
    ),
  importCert: (payload: { id: string; certPem: string; keyPem: string }) =>
    api.post<{ ok: boolean }>(`/certs/import`, payload),
  // 启用/禁用证书（列表快捷操作）；禁用被面板 HTTPS 引用的证书时后端返回 409。
  toggleCert: (id: string, enabled: boolean) =>
    api.post<{ id: string; enabled: boolean }>(`/certs/${id}/toggle`, { enabled }),
  providers: () => api.get<{ dns: ProviderInfo[] }>(`/meta/providers`),
  // 网络唤醒候选网卡。挂在 /meta 下而非 /wol/interfaces：后者与 /wol/:id 在后端路由树同层冲突。
  wolInterfaces: () => api.get<WOLInterface[]>(`/meta/wol-interfaces`),
  // 检查更新。force=true 时附加 ?force=1 跳过后端 30 分钟缓存，
  // 用于「检查更新」按钮：确保断网/限流等瞬态不可达状态不被缓存挡住，点按钮立即重连检测。
  updateCheck: (force?: boolean) =>
    api.get<UpdateCheck>(`/meta/update-check${force ? '?force=1' : ''}`),
  // 上传 tar.gz 更新包执行自更新（非 Windows 生效）。
  selfUpdate: (form: FormData) =>
    api.raw.post(`/meta/self-update`, form, { headers: { 'Content-Type': 'multipart/form-data' } }),
  // 修改账户：可选改用户名 + 改密码（改密码需验旧密码）。
  changeAccount: (payload: { username?: string; oldPassword: string; newPassword?: string }) =>
    api.post<{ ok: boolean; usernameChanged: boolean; passwordChanged: boolean }>(`/auth/account`, payload),
  // Web 服务运行态：各子项活跃连接数（childId -> 数量）。
  // 周期轮询类请求传 { silent: true }，后端不据此救活待删除会话。
  webStats: (opts?: RequestOpts) => api.get<Record<string, number>>(`/web/stats`, undefined, opts),
  // Web 服务各子项链接状态（childId -> {lastOK, lastErr, lastStatus}）。
  webChildStatus: (opts?: RequestOpts) =>
    api.get<Record<string, { lastOK: number; lastErr: number; lastStatus: number }>>(`/web/child-status`, undefined, opts),
  // Web 服务子项访问（连接）日志。
  webChildLogs: (child: string, limit?: number) =>
    api.get<WebAccessLog[]>(`/web/child-logs`, { child, limit }),
  // 列表内联开关：专用轻量端点，**不写"配置已保存"审计日志**（用户硬性要求）。
  // 与 toggleCert 同思路；编辑弹窗底部「保存」按钮走完整 PUT 路径产生审计日志。
  toggleWebService: (id: string, enabled: boolean) =>
    api.post<{ id: string; enabled: boolean }>(`/webservices/${id}/toggle`, { enabled }),
  toggleWebServiceChild: (pid: string, cid: string, enabled: boolean) =>
    api.post<{ id: string; child: string; enabled: boolean }>(`/webservices/${pid}/children/${cid}/toggle`, { enabled }),
  // 列表子项删除：专用轻量端点，审计用"删除"动词（非"保存"）。
  deleteWebServiceChild: (pid: string, cid: string) =>
    api.del<{ ok: boolean }>(`/webservices/${pid}/children/${cid}`),
  // 日志文件信息：当前路径、文件个数、合计大小（MB）。
  logInfo: () => api.get<{ path: string; count: number; sizeMB: number }>(`/settings/logs/info`),
  // 手动清空所有日志：删除日志文件及其历史备份后自动创建空日志文件，并清空内存环形缓冲。
  clearLogs: () => api.post<{ ok: boolean }>(`/settings/logs/clear`),
  // 数据目录里没人再引用的文件：换掉的背景图、删掉证书后剩下的文件、导入中断留下的暂存目录。
  storageInfo: () =>
    api.get<{ items: StorageItem[]; count: number; totalSize: number; truncated: boolean; limit: number }>(
      `/settings/storage`,
    ),
  // 按列表清理。服务端会重新扫一遍、只删这次也扫得出来的那些，对不上号的记进 skipped。
  cleanupStorage: (paths: string[]) =>
    api.post<{ ok: boolean; removed: number; skipped: number; freed: number; failed: string[] }>(
      `/settings/storage/cleanup`,
      { paths },
    ),
  // 立即重启整个程序（换掉进程，不是面板内部重启）。
  // 响应先回、进程后换，因此这个请求会正常返回，随后连接才断开。
  restartNow: () => api.post<{ ok: boolean; restarting: boolean }>(`/settings/restart-now`),
}
