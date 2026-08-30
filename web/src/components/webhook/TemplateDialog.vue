<script setup lang="ts">
import { computed, onBeforeUnmount, ref, nextTick, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import { ElMessage, ElMessageBox } from 'element-plus'
import { webhookActions } from '@/api/webhook'
import type {
  FieldMapping,
  MessageTemplate,
  TemplatePreviewResult,
  TestRunState,
  WebhookMeta,
  WebhookReceiver,
} from '@/api/webhook'
import FieldTree from './FieldTree.vue'
import type { FieldNode } from '@/composables/fieldPaths'
import { aliasCandidates, buildFieldTree, collectArrays, findNode, parseSample } from '@/composables/fieldPaths'

// 消息模板编辑器。
//
// 右侧那半边是这个模块「不写代码」的落点，字段有两个来源：
//
//	别名     用户在「接收器 → 解析」里给字段起过的短名，点一下插 {{.别名}}；
//	载荷字段 还没起别名时，直接列样本载荷的原始结构，点一下插 {{.body.原始路径}}
//
// 别名在渲染时被注入模板数据的根上（见 event.go 的 root[m.name]），所以 {{.别名}}
// 就是可用写法。没起别名的字段也能用：信封里永远有一份完整载荷挂在 body 下，
// 于是 {{.body.data.编号}} 一定取得到——用户不必为了发一条消息先去配一遍别名。
//
// 另外两件事同属"不写代码"：
//
//	参照模板 按用户**自己的**别名与样本字段生成一整份能直接跑的正文。字段名、数组路径
//	         全部来自当前接收器与当前样本，没有任何写死的字段名或行业说法。
//	预览     跟着编辑框实时渲染：正文、标题、格式一改，下面那一栏立刻变成"这份草稿现在
//	         发出去长什么样"，连会话列表里的标题行都算上（后端 preview.go 与投递共用
//	         renderRule）。改一行看一眼，不必先存再试，也不必去点什么按钮。

const props = defineProps<{
  visible: boolean
  model: MessageTemplate
  isNew: boolean
  saving: boolean
  meta: WebhookMeta | null
  receivers: WebhookReceiver[]
  // sample 与「接收器 → 解析」「试运行」共用的样本载荷，用来列出还没起别名的原始字段。
  sample: string
  // testRuns 各接收器的实时试运行状态（接收器 ID → 状态）。预览的样本可以直接取
  // 抓到的真实消息：那是最贴近生产的一份数据，比手贴的样本可信。
  testRuns?: Record<string, TestRunState>
}>()
const emit = defineEmits<{
  (e: 'update:visible', v: boolean): void
  (e: 'save'): void
  // update:sample 预览里用的样本回写到共用样本：贴一次，右栏的载荷字段与试运行页一起更新。
  (e: 'update:sample', v: string): void
}>()

const { t } = useI18n()

const bodyRef = ref<any>(null)
const titleRef = ref<any>(null)
// 最后聚焦过的输入框：决定字段插到正文还是标题里。
const lastFocus = ref<'body' | 'title'>('body')

// 空字符串 = 还没手选过，此时优先挑一个已经配了字段映射的接收器，
// 免得默认落在一个空接收器上、右边看着像坏了。
const picked = ref('')
const activeRecv = computed<WebhookReceiver | null>(() => {
  const list = props.receivers || []
  if (!list.length) return null
  return (
    list.find((r) => r.id === picked.value) ||
    list.find((r) => (r.mappings || []).length > 0) ||
    list[0]
  )
})
const fields = computed(() =>
  (activeRecv.value?.mappings || []).filter((m) => (m.name || '').trim() !== ''),
)
// 下拉框读的是**实际生效的**那个接收器，而不是 picked：否则没手选过时下拉里
// 是空的，右边却已经列着某个接收器的字段，看着像列错了。
const pickedId = computed({
  get: () => activeRecv.value?.id || '',
  set: (v: string) => {
    picked.value = v
  },
})

const funcs = computed(() => props.meta?.templateFuncs || [])
const reserved = computed(() => props.meta?.reservedFields || [])
// 取值由后端下发（config.MarkdownTitleStyles），前端只负责给每个取值配一句中文。
const titleStyles = computed(() => props.meta?.titleStyles || ['h1', 'h2', 'h3', 'bold', 'none'])

function insert(text: string) {
  const target = lastFocus.value === 'title' ? titleRef.value : bodyRef.value
  const el = target?.textarea || target?.input
  const key = lastFocus.value === 'title' ? 'title' : 'body'
  const cur = (props.model as any)[key] || ''
  if (!el) {
    ;(props.model as any)[key] = cur + text
    return
  }
  const s = el.selectionStart ?? cur.length
  const e = el.selectionEnd ?? s
  ;(props.model as any)[key] = cur.slice(0, s) + text + cur.slice(e)
  nextTick(() => {
    el.focus()
    const p = s + text.length
    el.setSelectionRange(p, p)
  })
}

// caretBefore 光标之前的那段正文。判断"是不是已经在循环里"要看它；
// 取不到输入框（还没聚焦过）时按"光标在末尾"处理，与 insert 的兜底一致。
function caretBefore(): string {
  const target = lastFocus.value === 'title' ? titleRef.value : bodyRef.value
  const el = target?.textarea || target?.input
  const cur = (props.model as any)[lastFocus.value] || ''
  const s = el?.selectionStart
  return typeof s === 'number' ? cur.slice(0, s) : cur
}

function pickField(name: string) {
  insert(`{{.${name}}}`)
}

// ---- 载荷字段（没起别名时的入口）----

// previewText 这个弹窗手上的那段样本，也是预览渲染用的那一段。声明在这儿而不是
// 跟预览的其它状态放一起，是因为右栏的字段树得跟着它走：预览已经照着这段样本渲染出
// 结果了，右边却说"还没有样本载荷"、「生成参照模板」还是灰的，那是自相矛盾。
// 回写到共用样本另说，由用户的动作触发（见 takeCapture / onSampleCommit）。
const previewText = ref('')
// sampleText 当前照着解的那段样本：预览框里那份优先——它可能是刚从试运行抓包取来、
// 还没回写共用样本的；没有才退回共用样本（用户在「接收器 → 解析」里贴过的那段）。
const sampleText = computed(() => previewText.value || props.sample)

// 解样本时要带上当前接收器的来源类型：键值文本不是 JSON，不按分隔符拆一遍
// 这里就是空的，而用户看到的是"载荷字段列不出来"。
const payloadNodes = computed(() =>
  buildFieldTree(parseSample(sampleText.value, activeRecv.value || undefined)),
)

// 没有别名时默认展开：那时上面的别名区是空的，这里是唯一的字段来源。
const payloadOpen = ref<string[]>([])
watch(
  () => [props.visible, fields.value.length] as const,
  ([open, n]) => {
    if (open) payloadOpen.value = n === 0 ? ['payload'] : []
  },
  { immediate: true },
)

// ---- 数组 ----
//
// 数组是整份载荷里唯一"必须多做一步"的字段：别的字段 {{.x}} 就取到了，数组直接取到的是
// Go 的切片字面量（一行 [map[...] map[...]]），得走 {{range}} 才列得出来。
// 所以这里主动把它们找出来：右栏标黄、「列表逐条列出」按它开关、没起别名时提示一句。
const arrays = computed(() => collectArrays(payloadNodes.value))

// arrayAlias 这个数组在当前接收器里起过的别名，没起过给空串。
// 别名的取值路径写法不止一种（items / body.items / 带取值根路径的那种），
// 折算的活交给 aliasCandidates——少认一种就会反复催用户去做一件他已经做完的事。
function arrayAlias(path: string): string {
  const hit = (activeRecv.value?.mappings || []).find(
    (m) =>
      (m.name || '').trim() !== '' &&
      aliasCandidates(m.path, activeRecv.value?.rootPath).includes(path),
  )
  return hit ? hit.name : ''
}
const unaliasedArrays = computed(() => arrays.value.filter((n) => !arrayAlias(n.path)))

// arrayNagged 这一轮已经提示过"数组该起个别名"了。没起别名照样插得进去（原始路径的
// 循环真的跑得通），所以这句提示一轮只出一次：同一件事弹三遍，用户下次会条件反射点掉。
const arrayNagged = ref(false)
watch(
  () => props.visible,
  (open) => {
    if (open) arrayNagged.value = false
  },
)

// nagUnaliasedArrays 提示一次，返回 false 表示用户选了"我去起别名"、这次不插。
async function nagUnaliasedArrays(): Promise<boolean> {
  const list = unaliasedArrays.value
  if (arrayNagged.value || !list.length) return true
  arrayNagged.value = true
  const recv = (activeRecv.value?.name || '').trim()
  try {
    await ElMessageBox.confirm(
      recv
        ? t('mroute.tmpl.arrNoAliasMsg', { list: list.map((n) => n.path).join('、'), recv })
        : t('mroute.tmpl.arrNoAliasMsgAny', { list: list.map((n) => n.path).join('、') }),
      t('mroute.tmpl.arrNoAliasTitle'),
      {
        confirmButtonText: t('mroute.tmpl.arrNoAliasRaw'),
        cancelButtonText: t('mroute.tmpl.arrNoAliasGo'),
        type: 'warning',
      },
    )
    return true
  } catch {
    return false
  }
}


//（见 event.go 的 buildEvent）。用 {{.编号}} 这种短写法要看根路径设成了什么，
// 在这里给出去会时对时错，而模板里取错值的表现只是"消息少了一段"，很难查。
function exprFor(path: string, top: boolean): string {
  const i = path.indexOf('[*]')
  if (i < 0) return `{{.${path}}}`
  // 数组必须走循环：直接 {{.items}} 打印出来的是 Go 的切片字面量。
  // 用 list 包一层是因为很多来源只有一条时不发数组、直接发那个对象，
  // 裸 {{range}} 遇到对象会去遍历它的值，{{.字段}} 当场报错、整条消息发不出去。
  const arr = path.slice(0, i)
  const rest = path.slice(i + 3).replace(/^\./, '')
  const inner = rest ? exprFor(rest, false) : '{{.}}'
  return top ? `{{range list .${arr}}}\n- ${inner}\n{{end}}` : `{{range list .${arr}}}${inner}{{end}}`
}

// 换行按当前格式来：钉钉 markdown 里单个 \n 不换行，一条一行就得空一行。
function br(): string {
  return props.model.format === 'markdown' ? '\n\n' : '\n'
}

// MAX_COLS 循环里一行最多排几列。列全了那一行就长到手机上要横着读，
// 而多出来的列用户删起来比补起来麻烦。
const MAX_COLS = 6

// childLabels 数组元素的字段名。元素是纯值（数组里装的是字符串）时为空数组。
function childLabels(n: FieldNode | null): string[] {
  return (n?.children || []).map((c) => c.label).slice(0, MAX_COLS)
}

// loopBlock 遍历一组数据的整段循环。
//
// 用 list 包一层是因为很多来源只有一条记录时不发数组、直接发那个对象，
// 裸 {{range}} 遇到对象会去遍历它的值，{{.字段}} 当场报错、整条消息发不出去。
// 元素有字段就"标签: 取值"逐列排开，元素是纯值就直接打印；行首的 "- "
// 在纯文本与 markdown 下都是通用的列表写法。
function loopBlock(path: string, cols: string[]): string {
  const line = cols.length ? '- ' + cols.map((c) => `${c}: {{.${c}}}`).join(' | ') : '- {{.}}'
  return `{{range list .${path}}}${line}${br()}{{end}}`
}

// openRangeArray 光标所在的那个 {{range}} 遍历的是谁，不在循环里时返回空串。
// 只往前找最近的 {{range}} 与 {{end}}：够用，且不会把已经闭合的循环算进来。
function openRangeArray(): string {
  const before = caretBefore()
  const i = before.lastIndexOf('{{range')
  if (i < 0 || i < before.lastIndexOf('{{end}}')) return ''
  const m = /^\{\{range\s+(?:list\s+)?\.([^\s}]+)\s*\}\}/.exec(before.slice(i))
  return m ? m[1] : ''
}

async function pickPayload(path: string) {
  const node = findNode(payloadNodes.value, path)
  // 数组点一下给的是整段循环，而不是 {{.body.items}}——后者渲染出来是 Go 的
  // 切片字面量（[map[...] map[...]]），用户看到的是一行乱码，还以为是程序坏了。
  if (node?.array) {
    // 这一条还没起别名就先提示一句：起过别名之后，正文里这段循环读起来是
    // 用户自己起的名字，而不是一长串第三方路径。
    if (!arrayAlias(path) && !(await nagUnaliasedArrays())) return
    insert(loopBlock(`body.${path}`, childLabels(node)))
    return
  }
  const i = path.indexOf('[*]')
  // 光标已经在遍历这个数组的循环里，就只插裸字段：再套一层循环会把每条记录
  // 乘一遍，而渲染结果看着"差不多对"，这种错极难查。
  if (i >= 0 && openRangeArray().endsWith(path.slice(0, i))) {
    insert(exprFor(path.slice(i + 3).replace(/^\./, ''), false))
    return
  }
  insert(exprFor(`body.${path}`, true))
}

// 一个别名映射到的是一组数据（一条消息带 N 条记录）时，直接 {{.别名}} 只会打印出
// Go 的切片字面量，必须走循环。元素有哪些字段能问出来（预览解出的信封、或样本）就带上，
// 问不出来才给 {{.}}——那种情况下元素很可能本来就是纯值。
function pickList(m: FieldMapping) {
  insert(loopBlock(m.name, childLabels(aliasNode(m))))
}

// 换行按各家的规矩插：钉钉 markdown 里单个 \n 不换行，得空一行；
// 企业微信 markdown 与纯文本单个 \n 就够。用户不该去记这个差别。
function insertBreak() {
  insert(br())
}

// ---- 预览 ----
//
// 实时渲染：正文、标题、标题样式、格式，任何一样一改，手停下来那一瞬就重渲染一遍。
// 做成实时而不是"点一下渲染一次"，是因为调排版全靠对照——换一种标题样式、把一行拆成两行，
// 得当场看见差别才改得下去；隔着一个按钮，用户改两回就懒得看了。
//
// 渲染在后端做（preview.go 与真实投递共用 renderRule），markdown 的标题也在那边按
// 「标题样式」拼进正文。所以这一栏显示的就是发出去的那一份，连会话列表里的标题行都算上。
// 前端另写一套渲染只会得出一个好看但不真实的结果。
//
// 样本用的是全局共用的那一份：试运行只留最新一条真实消息，它就是这份样本。
// 也可以在下面手贴一段——贴完会回写到共用样本，右栏的载荷字段与试运行页一起跟着变。

// PREVIEW_DELAY 手停多久之后才发渲染请求。太短会在打字中途连着发一串，
// 太长就不像"实时"了。
const PREVIEW_DELAY = 350

// previewText（当前样本）声明在上面的「载荷字段」那一段：右栏的字段树也要读它。
const previewBusy = ref(false)
const preview = ref<TemplatePreviewResult | null>(null)
// sampleOpen 下面那块样本是否展开。有样本时收起：用户要看的是渲染结果，
// 摊开一个大文本框只会把结果挤出屏幕。
const sampleOpen = ref<string[]>([])
// capturedFrom 当前这段样本是从抓包原样取来的。仍然一致时连请求头与 query 一起送去渲染
//（模板里的 {{.headers.x}}、{{.query.x}} 取的就是它们）；用户一改，那两样就不再属于这段样本。
const capturedFrom = ref('')
const capturedHeaders = ref<Record<string, string>>({})
const capturedQuery = ref('')

// 抓包只留最新一条，且只在有正文时可用：被拒的请求（令牌错、IP 不在名单里）
// 留着的是一条空记录，拿它预览只会渲染出一片空白，看着像模板坏了。
const capture = computed(() => {
  const c = props.testRuns?.[pickedId.value]?.capture
  return c && (c.body || '') !== '' ? c : null
})

// fromCapture 手上这段样本还是抓包原文。渲染时据此决定要不要把请求头与 query 一起送：
// 用户手改过之后，那两样与这段正文已经不是同一条请求了，跟着送过去会渲染出一条
// 现实中不存在的消息。界面上也用它标一句"这就是刚抓到的那条"。
const fromCapture = computed(
  () => capturedFrom.value !== '' && capturedFrom.value === previewText.value,
)

function takeCapture() {
  const c = capture.value
  if (!c) return
  previewText.value = c.body
  capturedFrom.value = c.body
  capturedHeaders.value = c.headers || {}
  capturedQuery.value = c.query || ''
  // 点这个按钮是"就用这条当样本"的明确表态，所以顺手回写到共用样本。
  emit('update:sample', c.body)
  // 渲染不用在这儿调：previewText 变了，下面那个 watch 会接手。
}

// onSampleCommit 样本输入框失焦 / 回车后才回写到共用样本，贴一次两处都有
//（右栏的载荷字段、试运行页）。
//
// 刻意不在渲染里回写：共用样本会落 localStorage，而这段东西往往是真实数据
//（数值、联系人、手机号）。留不留下来得由用户的动作决定，不能打开弹窗自动渲染一次
// 就顺手存进去了——渲染本身只读。
function onSampleCommit() {
  if (previewText.value && previewText.value !== props.sample) {
    emit('update:sample', previewText.value)
  }
}

let previewTimer: ReturnType<typeof setTimeout> | null = null
// previewSeq 只认最后一次请求的结果。打字期间前后两次渲染的耗时不保证一致，
// 早发的那次晚回来会把新结果盖成旧的——屏幕上的表现是"改了没反应"。
let previewSeq = 0

function schedulePreview(delay: number) {
  if (previewTimer) {
    clearTimeout(previewTimer)
    previewTimer = null
  }
  // 样本与正文都空着就没什么可渲染的：不发请求，也把上一次的结果清掉，
  // 免得屏幕上留着一份对不上当前草稿的旧结果。递增 seq 顺带作废在飞的那次。
  if (previewText.value.trim() === '' && (props.model.body || '').trim() === '') {
    previewSeq++
    preview.value = null
    previewBusy.value = false
    return
  }
  previewTimer = setTimeout(() => {
    previewTimer = null
    void renderPreview()
  }, delay)
}

async function renderPreview() {
  const mine = ++previewSeq
  previewBusy.value = true
  try {
    // silent：实时渲染下模板写到一半必然语法不通，每次都弹一条全局报错会刷屏。
    // 真正的错误后端放在 error 字段里返回，就显示在下面那块预览里。
    const out = await webhookActions.previewTemplate(
      {
        receiverId: pickedId.value || undefined,
        format: props.model.format || 'text',
        title: props.model.title || '',
        titleStyle: props.model.titleStyle || '',
        body: props.model.body || '',
        sample: previewText.value,
        headers: fromCapture.value ? capturedHeaders.value : undefined,
        query: fromCapture.value ? capturedQuery.value : undefined,
      },
      true,
    )
    if (mine !== previewSeq) return
    preview.value = out
  } catch {
    // 网络层的失败（超长样本被后端拒掉之类）只把上一次的结果清掉，
    // 免得用户以为屏幕上那份是刚跑出来的。
    if (mine === previewSeq) preview.value = null
  } finally {
    if (mine === previewSeq) previewBusy.value = false
  }
}

// 打开弹窗时把预览用的样本先备好：优先共用样本（用户刚在别处贴过），否则取最新抓包。
// 这个 watch 必须排在下面那个渲染 watch 前面：同一批里先跑的先赋值，
// 渲染那次读到的才是刚备好的样本。
watch(
  () => props.visible,
  (open) => {
    if (!open) return
    preview.value = null
    capturedFrom.value = ''
    const latest = capture.value
    if (props.sample) {
      previewText.value = props.sample
    } else {
      previewText.value = latest?.body || ''
      if (latest) {
        capturedFrom.value = latest.body
        capturedHeaders.value = latest.headers || {}
        capturedQuery.value = latest.query || ''
      }
    }
    // 一段样本都没有时把下面那块摊开：预览必然是空的，这里是用户唯一的入口。
    sampleOpen.value = previewText.value ? [] : ['sample']
  },
  { immediate: true },
)

// 实时渲染的触发面：草稿里影响渲染结果的每一样 + 样本 + 借用的接收器（别名从它来）。
// 名称与备注不在里面——它们不参与渲染，跟着重渲染只是白跑一趟请求。
watch(
  () => [
    props.visible,
    props.model.format,
    props.model.title,
    props.model.titleStyle,
    props.model.body,
    previewText.value,
    pickedId.value,
  ] as const,
  ([open], old) => {
    if (!open) {
      if (previewTimer) {
        clearTimeout(previewTimer)
        previewTimer = null
      }
      return
    }
    // 刚打开的那一次不等防抖：用户点进来就是要看现在长什么样。
    schedulePreview(old?.[0] ? PREVIEW_DELAY : 0)
  },
  { immediate: true },
)

// 弹窗销毁时把还没跑的那次取消掉：组件都没了还发一次请求，回来只会写进一个
// 已经卸载的 ref。
onBeforeUnmount(() => {
  if (previewTimer) clearTimeout(previewTimer)
})

// ---- 取材：别名 → 样本 ----
//
// 「列表逐条列出」与「生成参照模板」都从这里取字段，优先顺序刻意如此：
//
//	1. 别名 + 预览解出的信封  别名是用户自己起的名字，信封是后端按真实取值规则解出来的，
//	                          "哪个别名指向一组数据"在这里是事实，不是猜的
//	2. 别名 + 样本字段树      还没预览过时，拿别名的取值路径去样本树里比一次
//	3. 样本原始字段          一个别名都没配时的兜底，取值路径一律从 body 起
//
// 三样都没有就**什么都不生成**，只提示"先贴一段样本或抓一条消息"。编一份带
// items 之类字段名的骨架插进去，看着像能用、真跑起来每一行都取不到值——
// 那比不给更糟，也正是这次要去掉的老毛病。

// previewRoot 后端解出来的信封（含别名注入），预览跑过一次之后才有。
const previewRoot = computed<FieldNode[]>(() => buildFieldTree(preview.value?.root || null))

// aliasNode 别名在信封 / 样本里对应的那个节点。
// 取值路径可能写成 items 也可能写成 body.items，两种都得认（与后端 buildEvent 的
// 两步取值同一个道理），否则明明配好的别名在这里会被当成"不是数组"。
function aliasNode(m: FieldMapping): FieldNode | null {
  const byRoot = findNode(previewRoot.value, m.name)
  if (byRoot) return byRoot
  const p = (m.path || '').replace(/^body\./, '')
  return p ? findNode(payloadNodes.value, p) : null
}

// MAX_HEAD 参照模板最多列几个头部字段。一条通知能被人读完的长度有限，
// 列全了反而没人看；少了用户再点两下补上，比删十几行容易。
const MAX_HEAD = 10

interface FieldPick {
  // path 写进取值表达式的路径：别名就是别名本身，原始字段带 body. 前缀。
  path: string
  label: string
  cols?: string[]
  // aliased 这一段是照着别名取的。false 说明走的是样本里的原始路径——能跑，
  // 但正文里会是一长串第三方路径，界面据此提示用户去起个别名。
  aliased?: boolean
}

// picks 取材结果：head 每行一个字段，list 是那段循环（没有则为 null）。
const picks = computed<{ head: FieldPick[]; list: FieldPick | null }>(() => {
  const head: FieldPick[] = []
  let list: FieldPick | null = null

  for (const m of fields.value) {
    const node = aliasNode(m)
    if (node?.array) {
      // 多个数组别名只用第一个：两段循环拼在一起，用户十有八九要删掉一段，
      // 而删的时候得先看懂模板语法。
      if (!list) list = { path: m.name, label: m.name, cols: childLabels(node), aliased: true }
      continue
    }
    head.push({ path: m.name, label: m.name })
  }

  // 数组这一段与"有没有别名"分开算。曾经是"一个别名都没配时才去看样本"，
  // 于是只要用户配过一个普通别名，样本里明明有一组数据，「列表逐条列出」也会说
  // "没有成组的数据"——而那正是他配模板时最想摆出来的一段。
  if (!list && arrays.value.length) {
    const arr = arrays.value[0]
    list = { path: `body.${arr.path}`, label: arr.label, cols: childLabels(arr), aliased: false }
  }
  if (head.length) return { head: head.slice(0, MAX_HEAD), list }

  // 头部字段一个都没取到（没配别名，或者配的全是数组）时退回样本的顶层标量字段。
  for (const n of payloadNodes.value) {
    if (n.array || n.children || head.length >= MAX_HEAD) continue
    head.push({ path: `body.${n.path}`, label: n.label })
  }
  return { head, list }
})

// hasFields 取到材料了没有。界面据此把两个按钮置灰并给出提示，
// 而不是让用户点了之后什么都没发生。
const hasFields = computed(() => picks.value.head.length > 0 || picks.value.list !== null)

// referenceBody 一份用**用户自己的字段**写成、能直接跑的完整正文。
//
// 这是"不写代码"的最后一段：点一下就有一份参照，之后只要改标签文字、删掉不想发的行。
// 刻意不加任何客套话（"以上请及时跟进"这类）：那是各家自己的说法，替用户写进去
// 只会让他先删一遍，而删的时候还得连带看懂模板语法。
function referenceBody(): string {
  const { head, list } = picks.value
  const nl = br()
  const loop = list ? loopBlock(list.path, list.cols || []) : ''
  const out = head.map((p) => `${p.label}: {{.${p.path}}}`).join(nl)
  if (!loop) return out
  return out ? out + nl + loop : loop
}

// applyReference 用参照模板填满正文。正文已经有内容时先问一句：
// 那可能是用户改了半天的东西，覆盖掉没有撤销的余地。
async function applyReference() {
  const text = referenceBody()
  if (!text) {
    ElMessage.warning(t('mroute.tmpl.refNoFields'))
    return
  }
  // 参照模板里那段循环走的是原始路径时先提示一句：这份正文是要留下来长期用的，
  // 别名在这时候补上最省事，等正文写满了再改，用户得回来逐处替换。
  if (picks.value.list && !picks.value.list.aliased && !(await nagUnaliasedArrays())) return
  if ((props.model.body || '').trim()) {
    try {
      await ElMessageBox.confirm(t('mroute.tmpl.refConfirm'), '', {
        confirmButtonText: t('common.confirm'),
        cancelButtonText: t('common.cancel'),
        type: 'warning',
      })
    } catch {
      return
    }
  }
  props.model.body = text
  ElMessage.success(t('mroute.tmpl.refDone'))
}

// 常用写法。刻意**不给"这条消息发给谁"的条件**：那由接收器的「消息规则」决定，
// 模板只管消息长什么样。把它写进模板等于同一件事有两个地方能配，
// 而排查「为什么这条没发出去」时用户得同时看两处。
//
// 每一条插进去的都是**当前接收器 / 当前样本里真实存在的**字段，取不到材料时
// 宁可提示一句也不插——见上面「取材」那段。
// 「列表逐条列出」只对数组有意义：它插的就是一段 {{range}}，样本里没有数组时
// 插进去的循环永远跑空一次。所以没有数组就置灰，而不是等用户点了再弹一句提示。
const snippets = computed(() => [
  { key: 'each', label: t('mroute.tmpl.snipEach'), disabled: !picks.value.list },
  { key: 'default', label: t('mroute.tmpl.snipDefault'), disabled: !hasFields.value },
  { key: 'break', label: t('mroute.tmpl.snipBreak'), disabled: false },
])

// snipEachTip 「列表逐条列出」下面那句话说什么，三种情形三句话：
// 没有数组（这个按钮用不上）／有数组但还没起别名（建议去起）／已经起过别名（照别名插）。
const snipEachTip = computed(() => {
  const list = picks.value.list
  if (!list) return t('mroute.tmpl.snipEachNone')
  if (list.aliased) return t('mroute.tmpl.snipEachAliased', { name: list.path })
  return t('mroute.tmpl.snipEachRaw', { path: list.path })
})

async function useSnippet(key: string) {
  if (key === 'break') {
    insertBreak()
    return
  }
  if (key === 'default') {
    const first = picks.value.head[0] || picks.value.list
    if (!first) {
      ElMessage.warning(t('mroute.tmpl.refNoFields'))
      return
    }
    insert(`{{default "${t('mroute.tmpl.defaultWord')}" .${first.path}}}`)
    return
  }
  const list = picks.value.list
  if (!list) {
    ElMessage.warning(t('mroute.tmpl.snipEachNoList'))
    return
  }
  if (!list.aliased && !(await nagUnaliasedArrays())) return
  insert(loopBlock(list.path, list.cols || []))
}
</script>

<template>
  <el-dialog
    :model-value="visible"
    :title="isNew ? t('mroute.tmpl.add') : t('mroute.tmpl.edit')"
    width="min(920px, 94vw)"
    append-to-body
    :close-on-click-modal="false"
    @update:model-value="(v: boolean) => emit('update:visible', v)"
  >
    <div class="tpl-wrap">
      <div class="tpl-left">
        <el-form label-position="top">
          <div class="grid2">
            <el-form-item :label="t('common.name')">
              <el-input v-model="model.name" :placeholder="t('mroute.tmpl.namePlaceholder')" />
            </el-form-item>
            <el-form-item :label="t('mroute.tmpl.format')">
              <el-radio-group v-model="model.format">
                <el-radio-button value="text">{{ t('mroute.tmpl.text') }}</el-radio-button>
                <el-radio-button value="markdown">Markdown</el-radio-button>
              </el-radio-group>
            </el-form-item>
          </div>

          <el-form-item v-if="model.format === 'markdown'" :label="t('mroute.tmpl.title')">
            <el-input
              ref="titleRef"
              v-model="model.title"
              :placeholder="t('mroute.tmpl.titlePlaceholder')"
              @focus="lastFocus = 'title'"
            />
            <div class="mt-subtle hint">{{ t('mroute.tmpl.titleHint') }}</div>
          </el-form-item>
          <el-form-item v-if="model.format === 'markdown'" :label="t('mroute.tmpl.titleStyle')">
            <el-select v-model="model.titleStyle" style="width: 220px">
              <el-option
                v-for="s in titleStyles"
                :key="s"
                :value="s"
                :label="t(`mroute.tmpl.style.${s}`)"
              />
            </el-select>
            <div class="mt-subtle hint">{{ t('mroute.tmpl.titleStyleHint') }}</div>
          </el-form-item>
          <el-alert
            v-if="model.format === 'markdown'"
            type="warning"
            :closable="false"
            :title="t('mroute.tmpl.wecomMdNoAt')"
            class="tip-alert"
          />

          <!-- 数组没起别名的常驻提示。只靠弹窗不够：弹窗点掉就没了，而这件事在整个
               配模板的过程里都成立；摆在「快速开始」上面，是因为下面两个按钮插出来的
               循环就是它说的那一段。 -->
          <el-alert
            v-if="unaliasedArrays.length"
            type="warning"
            :closable="false"
            show-icon
            class="tip-alert"
            :title="
              t('mroute.tmpl.arrNoAliasTip', {
                list: unaliasedArrays.map((n) => n.path).join('、'),
              })
            "
          />

          <!-- 「快速开始」与「常用写法」摆在正文**上面**：用户点进来面对的是一个空的
               正文框，而这两栏就是"不用自己写"的那两条路——摆在正文下面等于要他先滚过
               一屏才发现。预览仍然紧贴正文（见下面那一段），改一行往下瞄一眼不受影响。 -->
          <el-form-item :label="t('mroute.tmpl.build')">
            <div class="chips">
              <el-button
                size="small"
                type="primary"
                plain
                :disabled="!hasFields"
                @click="applyReference"
              >
                {{ t('mroute.tmpl.reference') }}
              </el-button>
            </div>
            <div class="mt-subtle hint">
              {{ hasFields ? t('mroute.tmpl.referenceHint') : t('mroute.tmpl.refNoFields') }}
            </div>
          </el-form-item>

          <el-form-item :label="t('mroute.tmpl.snippets')">
            <div class="chips">
              <!-- 逐条列出这一条没有数组就置灰：它插的就是一段循环，样本里没有成组的
                   数据时插进去只会空跑一次，而用户看不出那是因为"这里本来就没有数组"。 -->
              <el-button
                v-for="s in snippets"
                :key="s.key"
                size="small"
                :disabled="s.disabled"
                @click="useSnippet(s.key)"
              >
                {{ s.label }}
              </el-button>
            </div>
            <div class="mt-subtle hint">{{ snipEachTip }}</div>
            <div class="mt-subtle hint">{{ t('mroute.tmpl.newlineHint') }}</div>
          </el-form-item>

          <el-form-item :label="t('mroute.tmpl.body')">
            <el-input
              ref="bodyRef"
              v-model="model.body"
              type="textarea"
              :rows="12"
              class="mono"
              :placeholder="t('mroute.tmpl.bodyPlaceholder')"
              @focus="lastFocus = 'body'"
            />
          </el-form-item>

          <div class="mt-subtle hint pull-down">{{ t('mroute.tmpl.noCondHint') }}</div>

          <!-- 预览。刻意紧贴在正文下面：它跟着上面那个输入框实时重渲染，
               改一行往下瞄一眼就行，中间隔着别的东西这件事就不成立了。
               样式与试运行页那一栏一致（同一套 .preview/.pv-* 类），显示的正文也是
               同一段代码渲染的（后端 preview.go 与投递共用 renderRule）。 -->
          <div class="pv-wrap">
            <div class="pv-head">
              <strong>{{ t('mroute.tmpl.previewTitle') }}</strong>
              <el-tag size="small" type="info">
                {{ model.format === 'markdown' ? 'Markdown' : t('mroute.tmpl.text') }}
              </el-tag>
              <el-tag v-if="preview?.sniffed" size="small">
                {{ t('mroute.dry.sniffed', { type: preview.sniffed }) }}
              </el-tag>
              <el-tag v-if="preview?.missing" size="small" type="warning">
                {{ t('mroute.dry.missingFields', { n: preview.missing }) }}
              </el-tag>
              <el-tag v-if="preview?.truncated" size="small" type="warning">
                {{ t('mroute.tmpl.previewTruncated') }}
              </el-tag>
              <span class="grow"></span>
              <span class="mt-subtle live">
                {{ previewBusy ? t('mroute.tmpl.previewRendering') : t('mroute.tmpl.previewLive') }}
              </span>
            </div>

            <el-alert
              v-if="preview?.error"
              :title="preview.error"
              type="error"
              :closable="false"
              show-icon
              class="pv-al"
            />
            <el-alert
              v-if="preview && !preview.receiver && fields.length"
              :title="t('mroute.tmpl.previewNoRecv')"
              type="info"
              :closable="false"
              show-icon
              class="pv-al"
            />
            <el-alert
              v-if="preview?.unresolved?.length"
              :title="t('mroute.dry.unresolved')"
              type="warning"
              :closable="false"
              show-icon
              class="pv-al"
            >
              <div class="mono small">{{ preview.unresolved.join('\n') }}</div>
            </el-alert>

            <div v-if="preview && (preview.body || preview.title)" class="preview">
              <!-- 标题这一行是「会话列表里的那行预览」，不是消息内容本身：markdown 的标题
                   已经按「标题样式」拼进正文了（后端 MarkdownTitled），不加标签看着就像
                   同一个标题出现了两遍。 -->
              <div v-if="preview.title" class="pv-title">
                <span class="pv-tag">{{ t('mroute.dry.pushTitle') }}</span>
                <span>{{ preview.title }}</span>
              </div>
              <div class="pv-body">{{ preview.body }}</div>
            </div>
            <!-- 空的时候要说清是缺哪一样：缺样本、缺正文、还是模板取不到值。
                 只写一句"什么都没渲染出来"的话，用户下一步该干什么全靠猜。 -->
            <div v-else class="mt-subtle hint">
              {{
                !previewText.trim()
                  ? t('mroute.tmpl.previewNoSample')
                  : !(model.body || '').trim()
                    ? t('mroute.tmpl.previewNoBody')
                    : t('mroute.tmpl.previewEmpty')
              }}
            </div>

            <!-- 样本：试运行抓到的那条就在这里，也能手贴一段（会回写到共用样本）。
                 收在折叠里是因为它是"数据来源"而不是"要看的东西"；一段样本都没有时
                 默认展开，那时它是用户唯一的入口。 -->
            <el-collapse v-model="sampleOpen" class="pv-sample">
              <el-collapse-item name="sample">
                <template #title>
                  <span>{{ t('mroute.tmpl.previewSampleTitle') }}</span>
                  <el-tag v-if="fromCapture" size="small" type="success" class="pv-from">
                    {{ t('mroute.tmpl.previewFromCapture') }}
                  </el-tag>
                </template>
                <el-input
                  v-model="previewText"
                  type="textarea"
                  :rows="4"
                  class="mono"
                  :placeholder="t('mroute.tmpl.previewSample')"
                  @change="onSampleCommit"
                />
                <div class="pv-row">
                  <el-button v-if="capture" size="small" @click="takeCapture">
                    {{ t('mroute.tmpl.useCapture') }}
                  </el-button>
                  <span class="mt-subtle hint">{{ t('mroute.tmpl.previewHint') }}</span>
                </div>
              </el-collapse-item>
            </el-collapse>
          </div>

          <el-form-item :label="t('mroute.note')">
            <el-input v-model="model.note" :placeholder="t('mroute.tmpl.notePlaceholder')" />
          </el-form-item>
        </el-form>
      </div>

      <div class="tpl-right">
        <h4 class="side-h">{{ t('mroute.tmpl.fields') }}</h4>
        <el-select
          v-if="receivers.length"
          v-model="pickedId"
          size="small"
          class="recv-pick"
          :placeholder="t('mroute.tmpl.recvPicker')"
        >
          <el-option
            v-for="r in receivers"
            :key="r.id"
            :value="r.id || ''"
            :label="`${r.name} · ${(r.mappings || []).length}`"
          />
        </el-select>

        <p v-if="!receivers.length" class="mt-subtle side-tip">
          {{ t('mroute.tmpl.noReceiver') }}
        </p>
        <p v-else-if="!fields.length" class="mt-subtle side-tip">
          {{ t('mroute.tmpl.noMappings') }}
        </p>
        <template v-else>
          <div class="f-list">
            <!-- 别名点一下插值，「列表」插循环。两个入口都摆出来，不藏在 hover 后面。 -->
            <div v-for="m in fields" :key="m.name" class="f-row">
              <code class="chip f-name" :title="m.note || m.path" @click="pickField(m.name)">{{
                m.name
              }}</code>
              <span class="f-path mt-subtle">{{ m.path }}</span>
              <button type="button" class="f-as" @click="pickList(m)">
                {{ t('mroute.tmpl.asList') }}
              </button>
            </div>
          </div>
          <p class="mt-subtle side-tip">{{ t('mroute.tmpl.recvPickerHint') }}</p>
        </template>

        <!-- 载荷字段：没起别名也要能配模板。默认展开的条件就是"这个接收器还没有别名"，
             那种情况下上面那块是空的，这里才是用户唯一的入口。 -->
        <el-collapse v-if="receivers.length" v-model="payloadOpen" class="pl-collapse">
          <el-collapse-item :title="t('mroute.tmpl.payloadFields')" name="payload">
            <FieldTree
              :nodes="payloadNodes"
              :empty-hint="t('mroute.tmpl.payloadEmpty')"
              @pick="pickPayload"
            />
            <p v-if="payloadNodes.length" class="mt-subtle side-tip">
              {{ t('mroute.tmpl.payloadHint') }}
            </p>
          </el-collapse-item>
        </el-collapse>

        <h4 class="side-h">{{ t('mroute.tmpl.builtinFields') }}</h4>
        <div class="chips">
          <code v-for="f in reserved" :key="f" class="chip" @click="insert(`{{.${f}}}`)">{{ f }}</code>
        </div>
        <p class="mt-subtle side-tip">{{ t('mroute.tmpl.builtinHint') }}</p>

        <h4 class="side-h">{{ t('mroute.tmpl.funcs') }}</h4>
        <div class="chips">
          <code v-for="f in funcs" :key="f" class="chip" @click="insert(`{{${f} }}`)">{{ f }}</code>
        </div>
        <p class="mt-subtle side-tip">{{ t('mroute.tmpl.funcsHint') }}</p>
      </div>
    </div>

    <template #footer>
      <el-button @click="emit('update:visible', false)">{{ t('common.cancel') }}</el-button>
      <el-button type="primary" :loading="saving" @click="emit('save')">{{ t('common.save') }}</el-button>
    </template>
  </el-dialog>
</template>

<style scoped>
.tpl-wrap {
  display: grid;
  /* minmax(0, 1fr)：1fr 的最小值是 min-content，左栏里的定宽输入框会把左轨道顶宽，
   * 把右栏挤出容器——表现就是右边的说明文字被切掉。 */
  grid-template-columns: minmax(0, 1fr) 300px;
  gap: 18px;
}
.tpl-wrap > * {
  min-width: 0;
}
/* 这里刻意不设 max-height/overflow：滚动交给弹窗正文（见 style.css）。
 * 嵌套一层自己的滚动条会出现「外面滚不动、里面看不见滚条」的死角。 */
.tpl-right {
  border-left: 1px solid var(--mt-border, rgba(20, 27, 45, 0.12));
  padding-left: 16px;
}
.grid2 {
  display: grid;
  grid-template-columns: minmax(0, 1fr) minmax(0, 1fr);
  gap: 0 16px;
}
.side-h {
  margin: 14px 0 6px;
  font-size: 13px;
  font-weight: 600;
}
.side-h:first-child {
  margin-top: 0;
}
.side-tip {
  font-size: 12px;
  margin: 6px 0 0;
  line-height: 1.6;
}
.hint {
  font-size: 12px;
  margin-top: 4px;
  line-height: 1.6;
}
.pull-down {
  margin: -14px 0 14px;
  line-height: 1.6;
}
.tip-alert {
  margin-bottom: 14px;
}
/* 预览区。类名与试运行页那一栏刻意保持一致（.preview / .pv-title / .pv-tag / .pv-body）：
 * 两处显示的是同一段后端渲染结果，长得不一样只会让人怀疑其中一处不准。 */
.pv-wrap {
  margin: 0 0 16px;
  padding: 10px 12px;
  border: 1px solid var(--el-border-color);
  border-radius: 6px;
  background: var(--el-fill-color-blank);
}
.pv-head {
  display: flex;
  align-items: center;
  gap: 6px;
  margin-bottom: 8px;
  flex-wrap: wrap;
}
.grow {
  flex: 1 1 auto;
}
.pv-row {
  display: flex;
  align-items: center;
  gap: 8px;
  margin: 8px 0;
  flex-wrap: wrap;
}
/* 「实时渲染 / 渲染中…」那一小行。它是状态而不是按钮，所以压得比正文小、不加边框：
 * 用户需要的只是"这份结果是刚跑出来的"这一点确认。 */
.live {
  font-size: 12px;
  flex: 0 0 auto;
}
/* 样本折叠。el-collapse 自带上下边框，在预览框里再画一道就成了双线。 */
.pv-sample {
  margin-top: 8px;
  border-top: none;
}
.pv-sample :deep(.el-collapse-item__header) {
  font-size: 12px;
  font-weight: 600;
  height: 32px;
  line-height: 32px;
  border-bottom: none;
}
.pv-sample :deep(.el-collapse-item__wrap) {
  border-bottom: none;
}
.pv-sample :deep(.el-collapse-item__content) {
  padding-bottom: 4px;
}
.pv-from {
  margin-left: 6px;
}
.pv-al {
  margin-bottom: 8px;
}
.preview {
  padding: 8px;
  background: var(--el-fill-color-light);
  border-radius: 4px;
}
.pv-title {
  display: flex;
  align-items: baseline;
  gap: 6px;
  margin-bottom: 4px;
  font-weight: 600;
}
.pv-tag {
  flex: 0 0 auto;
  font-size: 11px;
  font-weight: 400;
  padding: 0 5px;
  border-radius: 4px;
  background: rgba(140, 150, 170, 0.18);
  opacity: 0.85;
}
.pv-body {
  white-space: pre-wrap;
  word-break: break-all;
  font-size: 13px;
}
/* 选择器写成 .pv-al .small：单靠 .small 会被后面那条 .mono 的字号盖掉
 * （同权重、后者胜），而这段未解析别名列表要比正文小一号。 */
.pv-al .small {
  font-size: 12px;
  white-space: pre-wrap;
}
.recv-pick {
  width: 100%;
  margin-bottom: 8px;
}
.pl-collapse {
  margin-top: 10px;
}
.pl-collapse :deep(.el-collapse-item__header) {
  font-size: 13px;
  font-weight: 600;
}
.f-list {
  display: flex;
  flex-direction: column;
  gap: 4px;
}
.f-row {
  display: flex;
  align-items: center;
  gap: 6px;
}
.f-name {
  flex: 0 0 auto;
  max-width: 130px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.f-path {
  flex: 1 1 auto;
  min-width: 0;
  font-size: 11px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.f-as {
  flex: 0 0 auto;
  border: none;
  background: transparent;
  padding: 0;
  font-size: 11px;
  font-family: inherit;
  color: var(--mt-primary);
  cursor: pointer;
  opacity: 0.75;
}
.f-as:hover {
  opacity: 1;
  text-decoration: underline;
}
.chips {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
}
.chip {
  font-family: ui-monospace, Menlo, Consolas, monospace;
  font-size: 12px;
  padding: 2px 6px;
  border-radius: 5px;
  background: rgba(140, 150, 170, 0.14);
  cursor: pointer;
}
.chip:hover {
  background: color-mix(in srgb, var(--mt-primary) 18%, transparent);
  color: var(--mt-primary);
}
.mono :deep(textarea),
.mono :deep(input),
/* .mono 也要能直接作用在普通元素上：未解析别名那一段列表就是一个 div
 * （与试运行页同一种写法）。 */
.mono {
  font-family: ui-monospace, Menlo, Consolas, monospace;
  font-size: 13px;
}
/* 窄屏两档。
 * 900：侧栏定宽 300。弹窗宽 min(920px, 94vw)，900 像素屏上主区只剩约 496，
 * 模板编辑区与它下面那排按钮开始互相挤。这一档把侧栏落到下方，
 * 分隔线跟着从左边框换成上边框——分隔的方向变了。
 * 560：两联排改成一栏。 */
@media (max-width: 900px) {
  .tpl-wrap {
    grid-template-columns: minmax(0, 1fr);
  }
  .tpl-right {
    border-left: none;
    border-top: 1px solid var(--mt-border, rgba(20, 27, 45, 0.12));
    padding-left: 0;
    padding-top: 14px;
  }
}
@media (max-width: 560px) {
  .grid2 {
    grid-template-columns: minmax(0, 1fr);
  }
}
</style>
