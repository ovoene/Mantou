import { computed, ref } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { resourceApi, type ResourceCreateResult } from '@/api/resources'
import { loadResourceCaps, maxCountOf } from '@/api/limits'
import { useCloseOnLeave } from '@/composables/useCloseOnLeave'

// 通用资源页逻辑：列表加载、对话框开关、保存、删除。
// 各页面提供空表单工厂与资源名，即可复用统一的增删改查流程。
export function useResource<T extends { id?: string }>(
  name: string,
  emptyFactory: () => Partial<T>,
  opts?: { afterChange?: () => void },
) {
  const repo = resourceApi<T>(name)
  const list = ref<T[]>([])
  const loading = ref(false)
  const dialogVisible = ref(false)
  const editing = ref<Partial<T>>(emptyFactory())
  const isNew = ref(true)
  const saving = ref(false)

  // 切走页面时收起这个弹窗（理由见 useCloseOnLeave）。各资源页的新增 / 编辑弹窗都在这里，
  // 一处就够；页面自己另开的那些弹窗（导入、日志……）由页面各自调一次。
  useCloseOnLeave(dialogVisible)

  // 该资源的条数上限，取自后端（见 @/api/limits）。0 = 这个资源没有上限，或还没拉回来。
  // 页面拿它在标题下方那句说明里写出确切数字；显示与拦人用的是同一个数。
  const maxCount = computed(() => maxCountOf(name))

  async function load(opts?: { silent?: boolean }) {
    const silent = opts?.silent === true
    // 跟着列表一起拉，且只在整个前端里拉一次（同时挂载的多个页面共用一次请求）。
    // 不 await：上限只影响那句说明，让它挡住列表渲染没有道理。
    void loadResourceCaps()
    if (!silent) loading.value = true
    try {
      list.value = (await repo.list(silent ? { silent: true } : undefined)) as any
    } catch (e: any) {
      if (!silent) ElMessage.error(e?.message || '加载失败')
    } finally {
      if (!silent) loading.value = false
    }
  }

  function openCreate() {
    editing.value = emptyFactory()
    isNew.value = true
    dialogVisible.value = true
  }

  // withBlanks 把行里"空集合"那几个字段补回空数组 / 空对象。
  //
  // 后端的空切片序列化成 JSON 的 null（Go 里 nil 切片就是这个结果），而弹窗里到处是
  // `model.xxx.length` 这样的写法，于是编辑一条没有映射的接收器时渲染直接抛
  // TypeError——弹窗还能画出来（Vue 捕获了），但抛异常那一小块之后的内容会缺，
  // 且控制台里只有一行看不出出处的 minified 报错。
  //
  // 只补空表单里本来是数组 / 对象的那些字段：这类字段"空"和"没有"是一回事，
  // 补齐不改变保存结果。数字、字符串一律原样保留，免得把后端真的存了 null 的值
  // 悄悄换成默认值。
  function withBlanks(row: T): Partial<T> {
    const clone = JSON.parse(JSON.stringify(row)) as Record<string, unknown>
    const blank = emptyFactory() as Record<string, unknown>
    for (const key of Object.keys(blank)) {
      const proto = blank[key]
      if (clone[key] == null && proto !== null && typeof proto === 'object') {
        clone[key] = Array.isArray(proto) ? [] : {}
      }
    }
    return clone as Partial<T>
  }

  function openEdit(row: T) {
    editing.value = withBlanks(row)
    isNew.value = false
    dialogVisible.value = true
  }

  // openCopy 以某一条为底子新建一条：打开的是**新建**对话框，保存时才落库，
  // 所以用户可以先改名字、改完再决定要不要留。id 必须去掉，否则保存会走更新、
  // 把源那条覆盖掉。
  //
  // 只给不含脱敏字段的资源用。令牌 / 地址这类字段读回来是 ****** 占位符，
  // 复制出来的那条会把占位符当成真值存进去（见接收器令牌、通知目标 URL 的 maskedSecret），
  // 表现是新条目"看着填好了"但根本发不出去。
  function openCopy(row: T, nameOf?: (row: T) => string) {
    const copy = withBlanks(row) as Record<string, unknown>
    delete copy.id
    if (nameOf) copy.name = nameOf(row)
    editing.value = copy as Partial<T>
    isNew.value = true
    dialogVisible.value = true
  }

  async function save(): Promise<boolean> {
    saving.value = true
    try {
      let warning: string | undefined
      if (isNew.value) {
        const res = (await repo.create(editing.value)) as ResourceCreateResult<T> | undefined
        warning = res?.warning
      } else {
        await repo.update((editing.value as any).id, editing.value)
      }
      dialogVisible.value = false
      await load()
      opts?.afterChange?.()
      ElMessage.success('已保存')
      // 非致命告警（如 DDNS 首次同步失败）单独提示，不覆盖「已保存」成功态。
      if (warning) ElMessage.warning(warning)
      return true
    } catch (e: any) {
      ElMessage.error(e?.message || '保存失败')
      return false
    } finally {
      saving.value = false
    }
  }

  // toggle 列表里那个启用开关：只发 enabled 这一项（POST <资源>/:id/toggle），
  // 与证书、Web 服务的开关走同一种轻量端点。整行 PUT 的做法已经弃用——那要求页面把
  // 手里的那份"整行"原样回传，一旦别处（另一个标签页、直接调 API）刚改过这条配置，
  // 拨一下开关就把那些改动覆盖回去了；脱敏的令牌 / 地址还得靠占位符往返一趟。
  //
  // 后端只在启用这一侧校验，所以"停用状态下配了一半"的条目在这里被拒是对的；
  // 被拒就把开关拨回去——留在打开的样子会让用户以为已经生效了。
  async function toggle(row: T, failText = '保存失败') {
    const next = (row as any).enabled
    try {
      await repo.toggle((row as any).id, next)
      await load({ silent: true })
      opts?.afterChange?.()
    } catch (e: any) {
      ;(row as any).enabled = !next
      ElMessage.error(e?.message || failText)
    }
  }

  async function remove(row: T, confirmText: string) {
    try {
      await ElMessageBox.confirm(confirmText, '', {
        confirmButtonText: '删除',
        cancelButtonText: '取消',
        type: 'warning',
      })
    } catch {
      return
    }
    try {
      await repo.remove((row as any).id)
      await load()
      opts?.afterChange?.()
      ElMessage.success('已删除')
    } catch (e: any) {
      ElMessage.error(e?.message || '删除失败')
    }
  }

  return {
    list,
    loading,
    dialogVisible,
    editing,
    isNew,
    saving,
    maxCount,
    load,
    openCreate,
    openEdit,
    openCopy,
    save,
    remove,
    toggle,
  }
}

// 时间戳（秒）→ 本地时间字符串。
export function fmtTime(sec?: number): string {
  if (!sec) return '—'
  return new Date(sec * 1000).toLocaleString()
}

// 时间戳（毫秒）→ 本地时间字符串。
// 后端两种单位都在用：配置类字段（lastReceivedAt / updated…）是秒，
// 日志与抓包类字段（执行历史 time、Packet.time、抓包 time）是毫秒。
// 拿 fmtTime 去格式化毫秒会得到五万年后的日期，所以这两个函数必须分开，
// 也不做"数值大就当毫秒"的自动猜测——猜错时的表现同样是一个看不懂的年份。
export function fmtTimeMs(ms?: number): string {
  if (!ms) return '—'
  return new Date(ms).toLocaleString()
}

// 字节数说成人话。用 1024 进制与后端各处预算的口径一致（2 MiB 就显示 2 MB）。
// 只到 MB：这里量的都是内存预算与单条消息的大小，出现 GB 就是别处出了问题。
export function fmtBytes(n?: number): string {
  if (!n || n <= 0) return '0 B'
  if (n < 1024) return `${n} B`
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`
  return `${(n / 1024 / 1024).toFixed(2)} MB`
}
