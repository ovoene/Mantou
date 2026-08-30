<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import { ElMessage } from 'element-plus'
import { Plus, Delete, Refresh, DocumentCopy, VideoPlay, VideoPause } from '@element-plus/icons-vue'
import TagInput from '@/components/TagInput.vue'
import FieldTree from './FieldTree.vue'
import {
  aliasCandidates,
  buildFieldTree,
  collectArrays,
  detectSampleType,
  parseSample,
  sniffKVSeps,
} from '@/composables/fieldPaths'
import type {
  NotifyTarget,
  TestRunState,
  WebhookMeta,
  WebhookReceiver,
} from '@/api/webhook'

// 接收器编辑器：一个第三方来源系统的全部配置。
//
// 分成三页而不是一长条表单：一次配好一个接收器要填的东西横跨"入口地址、
// 鉴权与限流、怎么取值"这几件事，混在一起用户找不到自己要改的那一项。
// 「什么消息发给谁」不在这里——那是「发送规则」那一页，一条规则一行，
// 因为用户改规则时想的是"哪条规则发到哪个群"，而不是"它挂在哪个接收器下"。

const props = defineProps<{
  visible: boolean
  model: WebhookReceiver
  isNew: boolean
  saving: boolean
  meta: WebhookMeta | null
  targets: NotifyTarget[]
  sample: string
  // baseUrl 入站地址前缀（协议 + 主机 + 端口），由页面按模块的监听设置算出。
  baseUrl: string
  // testRun 这个接收器的实时试运行状态，由页面统一轮询后下发（见 MessageRoutes.vue）。
  testRun?: TestRunState
  testRunBusy?: boolean
}>()
const emit = defineEmits<{
  (e: 'update:visible', v: boolean): void
  (e: 'update:sample', v: string): void
  (e: 'save'): void
  (e: 'newPath'): void
  (e: 'start-test-run'): void
  (e: 'stop-test-run'): void
}>()

const { t } = useI18n()
const tab = ref('basic')

const limits = computed(() => props.meta?.limits || {})
const reserved = computed(() => props.meta?.reservedFields || [])

const fullURL = computed(() => `${props.baseUrl}/${props.model.path || ''}`)

// 「不校验 + 短路径」这个组合下，这个入口实际上没有任何保护。
//
// 两个条件都要看：只是路径短不算问题（配了令牌就行），只是不校验也不算问题
//（32 位随机路径猜不到）。门槛取后端下发的 weakPathLen，不在这里另写一个数。
// 只提示、不拦保存——改成自定义路径常常是对方系统的硬性要求。
//
// 路径留空是"保存时自动生成随机路径"，不是短路径，所以不提示。
const pathWeak = computed(() => {
  const path = props.model.path || ''
  if (!path) return false
  return props.model.authType === 'none' && path.length < (limits.value.weakPathLen || 16)
})

const parsed = computed(() => parseSample(props.sample, props.model))
const nodes = computed(() => buildFieldTree(parsed.value))
// 只有用户**显式**选定了 JSON 或键值文本、而样本不是那个形态时才标红：
// 自动识别下"解不出字段结构"是正常结局（对方发的就是一段纯文本），
// 纯文本来源更是本来就没有字段结构。这两种情况下改用 detectNote 说明这条按什么解。
const sampleBad = computed(
  () =>
    (props.model.sourceType === 'json' || props.model.sourceType === 'kv') &&
    props.sample.trim() !== '' &&
    parsed.value === null,
)

// ---- 这一条按什么解的 ----
//
// 自动识别是默认，所以必须让用户看得见判定结果——否则"字段树为什么是这样"无从解释。
// 显式选定的类型与样本形态不符时也要说：那正是"接收器写着键值文本、对方推来 JSON"
// 这类问题唯一能被看见的地方。
const detected = computed(() => detectSampleType(props.sample, props.model.pairSep, props.model.kvSep))
function typeLabel(st: string): string {
  if (st === 'json') return 'JSON'
  if (st === 'kv') return t('mroute.recv.sourceKV')
  if (st === 'txt') return t('mroute.recv.sourceTxt')
  return t('mroute.recv.sourceAuto')
}
const detectNote = computed(() => {
  if (!detected.value || sampleBad.value) return ''
  const st = props.model.sourceType || 'auto'
  if (st === 'auto') return t('mroute.recv.detected', { type: typeLabel(detected.value) })
  if (st !== detected.value) {
    return t('mroute.recv.detectMismatch', {
      type: typeLabel(detected.value),
      current: typeLabel(st),
    })
  }
  return ''
})

// ---- 键值文本的分隔符 ----
//
// 两栏留空就是自动识别，而"留空也行"这件事必须让用户看得见：这里把实际用上的符号
// 和拆出的字段数写在输入框下面。填了就按填的算（同一个函数，force 参数），
// 于是改一个字符立刻能看出是拆多了还是拆少了。
const kvSniff = computed(() => {
  if (props.model.sourceType !== 'kv' || props.sample.trim() === '') return null
  return sniffKVSeps(props.sample.trim(), props.model.pairSep || '', props.model.kvSep || '')
})
// 换行与制表符要显示成看得见的写法——输入框里用户也正是这么填的。
function sepLabel(s: string): string {
  return s === '\n' ? '\\n' : s === '\t' ? '\\t' : s
}

async function copy(text: string) {
  try {
    await navigator.clipboard.writeText(text)
    ElMessage.success(t('mroute.copied'))
  } catch {
    // 非 HTTPS 页面下 clipboard 不可用，此时提示用户手动复制而不是静默失败。
    ElMessage.warning(t('mroute.copyFail'))
  }
}

function targetLabel(id: string): string {
  const hit = props.targets.find((x) => x.id === id)
  if (!hit) return id
  return hit.enabled ? hit.name : `${hit.name}（${t('common.disabled')}）`
}

// ---- 解析试运行 ----
//
// 配"怎么取值"这一步最需要的就是一条真实消息：来源到底发 JSON 还是纯文本、
// 字段包在哪一层，光看对方文档经常是错的。这里直接收一条真的填进样本，
// 类型不用用户判断——默认的自动识别是逐条判的（见后端 decodeBody）。
const live = computed(() => !!props.testRun?.running)
// 试运行只留最新一条抓包，它同时就是全局样本载荷（见 DryRunPanel.vue 的说明）。
const latest = computed(() => props.testRun?.capture ?? null)

watch(
  () => latest.value?.time,
  (at) => {
    const c = latest.value
    if (!at || !c || c.rejected) return
    // 收到就把样本换成这一条：用户开这个试运行的目的就是拿真实载荷来配取值路径。
    //
    // 刻意**不**把判定结果回写进「来源消息类型」：那等于把一条消息的形态固化成
    // 整个接收器的类型。曾经有一条开头带 BOM 的 JSON 被判成键值文本回写了进去，
    // 从那一刻起连后面正常的 JSON 也被按符号拆坏。判定结果只用来提示（见 detectNote）。
    emit('update:sample', c.body || '')
  },
)

// ---- 字段映射 ----
function addMapping() {
  if (props.model.mappings.length >= (limits.value.mappings || 50)) return
  props.model.mappings.push({ name: '', path: '', default: '', note: '' })
}
function removeMapping(i: number) {
  props.model.mappings.splice(i, 1)
}
// 与内置字段同名的映射会被信封覆盖，取不到用户想要的值；后端保存时也会拦，
// 这里先在界面上标红，省一次"保存失败"的往返。
function mappingClash(name: string): boolean {
  return reserved.value.includes(name.trim())
}
// 空取值路径的别名永远取不到值，后端会拒绝保存，这里同样先标红。
function mapPathBad(path: string): boolean {
  return path.trim() === ''
}

// ---- 数组字段 ----
//
// 数组是整份载荷里唯一"需要用户多做一步"的字段：别的字段 {{.别名}} 就取到了，
// 数组直接取到的是 Go 的切片字面量（一行 [map[...] map[...]]），必须在模板里走
// {{range}} 才列得出来。而"哪个字段是数组"光看载荷得一层层数括号。
//
// 所以这里主动找出来、醒目标一句，并给一颗按钮把别名一次配齐：起过别名之后，
// 模板那边的「列表逐条列出」直接就是 {{.别名}} 的循环，用户一行代码都不用写。
const arrays = computed(() => collectArrays(nodes.value))

// aliasOf 这个数组已经起过的别名，没有则空串。
function aliasOf(path: string): string {
  const hit = (props.model.mappings || []).find(
    (m) =>
      (m.name || '').trim() !== '' &&
      aliasCandidates(m.path, props.model.rootPath).includes(path),
  )
  return hit ? hit.name : ''
}
const arraysNoAlias = computed(() => arrays.value.filter((n) => !aliasOf(n.path)))
const mapFull = computed(() => props.model.mappings.length >= (limits.value.mappings || 50))

// suggestAliasName 给数组起的默认别名：就用它自己的字段名。
// 刻意不替用户编叫法（"列表""条目"），那是各家自己的说法，写进去用户还得改一遍；
// 与已有别名或内置字段撞名时加个序号——撞名的别名保存时会被后端拒。
function suggestAliasName(label: string): string {
  const taken = new Set([
    ...reserved.value,
    ...(props.model.mappings || []).map((m) => (m.name || '').trim()),
  ])
  const base = (label || '').trim() || 'list'
  if (!taken.has(base)) return base
  for (let i = 2; i < 100; i++) {
    if (!taken.has(`${base}${i}`)) return `${base}${i}`
  }
  return base
}

// addArrayAliases 把还没起别名的数组一次配齐。取值路径填字段树里那一条（相对载荷根）：
// 后端取值的第二步就是按载荷解的，这么填一定取得到（见 aliasCandidates 的说明）。
function addArrayAliases() {
  for (const n of arraysNoAlias.value) {
    if (mapFull.value) break
    props.model.mappings.push({
      name: suggestAliasName(n.label),
      path: n.path,
      default: '',
      note: '',
    })
  }
}
</script>

<template>
  <el-dialog
    :model-value="visible"
    :title="isNew ? t('mroute.recv.add') : t('mroute.recv.edit')"
    width="min(1040px, 94vw)"
    append-to-body
    :close-on-click-modal="false"
    @update:model-value="(v: boolean) => emit('update:visible', v)"
  >
    <el-tabs v-model="tab" class="recv-tabs">
      <!-- ========== 基础 ========== -->
      <el-tab-pane :label="t('mroute.recv.tabBasic')" name="basic">
        <el-form label-position="top">
          <div class="grid2">
            <el-form-item :label="t('common.name')">
              <el-input v-model="model.name" :placeholder="t('mroute.recv.namePlaceholder')" />
            </el-form-item>
            <el-form-item :label="t('common.status')">
              <el-switch v-model="model.enabled" />
            </el-form-item>
          </div>

          <el-form-item :label="t('mroute.recv.path')">
            <div class="path-row">
              <el-input v-model="model.path" :placeholder="t('mroute.recv.pathPlaceholder')" />
              <el-button :icon="Refresh" @click="emit('newPath')">{{ t('mroute.recv.regen') }}</el-button>
            </div>
            <div class="mt-subtle hint">{{ t('mroute.recv.pathHint') }}</div>
            <!-- 「安全」页在默认状态下没人会打开，而不校验正是默认值——
                 所以这条提示放在改路径的地方，而不是放在鉴权那一页。 -->
            <el-alert
              v-if="pathWeak"
              type="warning"
              :closable="false"
              show-icon
              class="mt-subtle"
              :title="t('mroute.recv.pathWeak', { n: limits.weakPathLen || 16 })"
            />
          </el-form-item>

          <el-form-item :label="t('mroute.recv.fullUrl')">
            <div class="path-row">
              <el-input :model-value="fullURL" readonly class="mono" />
              <el-button :icon="DocumentCopy" @click="copy(fullURL)">{{ t('mroute.copy') }}</el-button>
            </div>
            <div class="mt-subtle hint">{{ t('mroute.recv.fullUrlHint') }}</div>
          </el-form-item>

          <el-form-item :label="t('mroute.note')">
            <el-input v-model="model.note" :placeholder="t('mroute.recv.notePlaceholder')" />
          </el-form-item>

          <!-- 兜底目标：某条规则没自己选目标时才用得上。它是接收器级的设置，
               所以留在这里；每条规则各自的目标在「发送规则」那一页配。 -->
          <el-divider content-position="left">{{ t('mroute.recv.fallbackSection') }}</el-divider>
          <el-form-item :label="t('mroute.recv.defaultTargets')">
            <el-select
              v-model="model.defaultTargets"
              multiple
              style="width: 100%"
              :placeholder="t('mroute.recv.defaultTargetsPlaceholder')"
            >
              <el-option
                v-for="tg in targets"
                :key="tg.id"
                :label="targetLabel(tg.id!)"
                :value="tg.id!"
              />
            </el-select>
            <div class="mt-subtle hint">{{ t('mroute.recv.defaultTargetsHint') }}</div>
          </el-form-item>
        </el-form>
      </el-tab-pane>

      <!-- ========== 安全 ========== -->
      <el-tab-pane :label="t('mroute.recv.tabSecurity')" name="security">
        <el-form label-position="top">
          <el-form-item :label="t('mroute.recv.authType')">
            <el-radio-group v-model="model.authType">
              <el-radio-button value="none">{{ t('mroute.recv.authNone') }}</el-radio-button>
              <el-radio-button value="token">{{ t('mroute.recv.authToken') }}</el-radio-button>
              <el-radio-button value="header">{{ t('mroute.recv.authHeader') }}</el-radio-button>
            </el-radio-group>
            <div class="mt-subtle hint">{{ t(`mroute.recv.authHint.${model.authType}`) }}</div>
          </el-form-item>

          <div v-if="model.authType !== 'none'" class="grid2">
            <el-form-item :label="t('mroute.recv.headerName')">
              <el-input
                v-model="model.authHeader"
                :placeholder="model.authType === 'token' ? 'X-Mantou-Token' : 'X-Signature'"
              />
            </el-form-item>
            <el-form-item :label="t('mroute.recv.token')">
              <el-input v-model="model.token" autocomplete="off" show-password />
            </el-form-item>
          </div>

          <div class="grid2">
            <el-form-item :label="t('mroute.recv.rateLimit')">
              <el-input-number v-model="model.rateLimit" :min="0" :max="100000" style="width: 100%" />
              <div class="mt-subtle hint">{{ t('mroute.recv.rateLimitHint') }}</div>
            </el-form-item>
            <el-form-item :label="t('mroute.recv.maxBody')">
              <el-input-number
                v-model="model.maxBodyKb"
                :min="1"
                :max="limits.maxBodyKb || 4096"
                style="width: 100%"
              />
              <div class="mt-subtle hint">{{ t('mroute.recv.maxBodyHint') }}</div>
            </el-form-item>
          </div>

          <el-divider content-position="left">{{ t('mroute.recv.ipFilter') }}</el-divider>
          <el-form-item :label="t('mroute.recv.ipFilterOn')">
            <el-switch v-model="model.ipFilter" />
          </el-form-item>
          <template v-if="model.ipFilter">
            <el-form-item :label="t('mroute.recv.ipMode')">
              <el-radio-group v-model="model.ipFilterMode">
                <el-radio-button value="deny">{{ t('mroute.recv.ipDeny') }}</el-radio-button>
                <el-radio-button value="allow">{{ t('mroute.recv.ipAllow') }}</el-radio-button>
              </el-radio-group>
            </el-form-item>
            <el-form-item
              :label="model.ipFilterMode === 'allow' ? t('mroute.recv.allowList') : t('mroute.recv.denyList')"
            >
              <TagInput
                v-if="model.ipFilterMode === 'allow'"
                v-model="model.allowIps"
                :placeholder="t('mroute.recv.ipPlaceholder')"
              />
              <TagInput v-else v-model="model.denyIps" :placeholder="t('mroute.recv.ipPlaceholder')" />
              <div class="mt-subtle hint">{{ t('mroute.recv.ipHint') }}</div>
            </el-form-item>
          </template>

          <el-divider content-position="left">{{ t('mroute.recv.keywordFilter') }}</el-divider>
          <el-form-item :label="t('mroute.recv.keywordOn')">
            <el-switch v-model="model.keywordFilter" />
            <div class="mt-subtle hint">{{ t('mroute.recv.keywordOnHint') }}</div>
          </el-form-item>
          <template v-if="model.keywordFilter">
            <el-form-item :label="t('mroute.recv.keywordMode')">
              <el-radio-group v-model="model.keywordMode">
                <el-radio-button value="any">{{ t('mroute.recv.keywordAny') }}</el-radio-button>
                <el-radio-button value="all">{{ t('mroute.recv.keywordAll') }}</el-radio-button>
              </el-radio-group>
            </el-form-item>
            <el-form-item :label="t('mroute.recv.keywords')">
              <TagInput v-model="model.keywords" :placeholder="t('mroute.recv.keywordPlaceholder')" />
              <div class="mt-subtle hint">{{ t('mroute.recv.keywordHint') }}</div>
              <!-- 开着开关却没填词是保存不下去的（后端会拒），在这里先说清楚，
                   免得用户填完别的页面才被一句错误打回来。 -->
              <el-alert
                v-if="!(model.keywords || []).length"
                type="warning"
                :closable="false"
                show-icon
                class="mt-subtle"
                :title="t('mroute.recv.keywordEmpty')"
              />
            </el-form-item>
          </template>
        </el-form>
      </el-tab-pane>

      <!-- ========== 解析 ========== -->
      <el-tab-pane :label="t('mroute.recv.tabParse')" name="parse">
        <div class="two-col">
          <div>
            <el-form label-position="top">
              <el-form-item :label="t('mroute.recv.sourceType')">
                <el-select v-model="model.sourceType" style="width: 100%">
                  <el-option :label="t('mroute.recv.sourceAuto')" value="auto" />
                  <el-option label="JSON" value="json" />
                  <el-option :label="t('mroute.recv.sourceKV')" value="kv" />
                  <el-option :label="t('mroute.recv.sourceTxt')" value="txt" />
                </el-select>
                <div class="mt-subtle hint">{{ t('mroute.recv.sourceTypeHint') }}</div>
              </el-form-item>

              <!-- 分隔符只在键值文本下出现：别的类型上摆着一组不起作用的输入框，
                   用户改了没反应，比看不见更糟（后端保存时也会把它们清空）。 -->
              <el-form-item v-if="model.sourceType === 'kv'" :label="t('mroute.recv.kvSeps')">
                <div class="sep-row">
                  <el-input v-model="model.pairSep" :placeholder="t('mroute.recv.kvAuto')">
                    <template #prepend>{{ t('mroute.recv.kvPairSep') }}</template>
                  </el-input>
                  <el-input v-model="model.kvSep" :placeholder="t('mroute.recv.kvAuto')">
                    <template #prepend>{{ t('mroute.recv.kvKVSep') }}</template>
                  </el-input>
                </div>
                <div class="mt-subtle hint">{{ t('mroute.recv.kvSepsHint') }}</div>
                <div v-if="kvSniff && kvSniff.pairs" class="mt-subtle hint">
                  {{
                    t('mroute.recv.kvSniffed', {
                      pair: sepLabel(kvSniff.pairSep),
                      kv: sepLabel(kvSniff.kvSep),
                      n: kvSniff.pairs,
                    })
                  }}
                </div>
              </el-form-item>

              <el-form-item :label="t('mroute.recv.rootPath')">
                <el-input v-model="model.rootPath" placeholder="body" />
                <div class="mt-subtle hint">{{ t('mroute.recv.rootPathHint') }}</div>
              </el-form-item>

              <!-- 数组提示。摆在字段别名上面而不是收在右栏，是因为它要的动作就在下面这一栏：
                   数组不起别名，模板里就只能照着一长串原始路径写循环，而这正是
                   "不用写代码"要消掉的那一步。已经全起过别名时转成一句确认，不再催——
                   催一个已经做完的动作比不提示更让人困惑。 -->
              <el-alert
                v-if="arraysNoAlias.length"
                type="warning"
                :closable="false"
                show-icon
                class="arr-alert"
                :title="t('mroute.recv.arrayFound', { n: arraysNoAlias.length })"
              >
                <div class="arr-list">
                  <code v-for="n in arraysNoAlias" :key="n.path" class="arr-chip">
                    {{ n.path }}<span class="mt-subtle">{{ n.preview }}</span>
                  </code>
                </div>
                <div class="arr-act">
                  <el-button size="small" type="warning" plain :disabled="mapFull" @click="addArrayAliases">
                    {{ t('mroute.recv.arrayAddAlias') }}
                  </el-button>
                  <span class="mt-subtle hint">{{ t('mroute.recv.arrayHint') }}</span>
                </div>
              </el-alert>
              <el-alert
                v-else-if="arrays.length"
                type="success"
                :closable="false"
                show-icon
                class="arr-alert"
                :title="t('mroute.recv.arrayAllAliased', { list: arrays.map((n) => `${n.path} → ${aliasOf(n.path)}`).join('、') })"
              />

              <el-form-item :label="t('mroute.recv.mappings')">
                <div class="map-list">
                  <div v-for="(m, i) in model.mappings" :key="i" class="map-row">
                    <el-input
                      v-model="m.name"
                      :placeholder="t('mroute.recv.mapNamePlaceholder')"
                      :class="{ 'is-bad': mappingClash(m.name) }"
                    />
                    <el-input
                      v-model="m.path"
                      :placeholder="t('mroute.recv.mapPathPlaceholder')"
                      :class="{ 'is-bad': mapPathBad(m.path) }"
                    />
                    <el-input v-model="m.default" :placeholder="t('mroute.recv.mapDefault')" />
                    <el-input v-model="m.note" :placeholder="t('mroute.recv.mapNote')" />
                    <el-button :icon="Delete" text type="danger" @click="removeMapping(i)" />
                  </div>
                  <el-button
                    size="small"
                    :icon="Plus"
                    :disabled="model.mappings.length >= (limits.mappings || 50)"
                    @click="addMapping"
                  >
                    {{ t('mroute.recv.addMapping') }}
                  </el-button>
                </div>
                <div class="mt-subtle hint">{{ t('mroute.recv.mappingsHint') }}</div>
                <div class="mt-subtle hint">{{ t('mroute.recv.mapExample') }}</div>
                <div v-if="model.mappings.some((m) => mappingClash(m.name))" class="mt-danger-text hint">
                  {{ t('mroute.recv.mapClash', { list: reserved.join(' / ') }) }}
                </div>
                <div v-if="model.mappings.some((m) => mapPathBad(m.path))" class="mt-danger-text hint">
                  {{ t('mroute.recv.mapPathRequired') }}
                </div>
                <!-- 带 [*] 的路径在取值时只拿得到第一条（见 lookupOne）：条件里够用，
                     模板里想逐条列就必须映射数组本身。这个坑不说出来，用户只会看到
                     "只发出来一条"，而配置看着完全正确。 -->
                <div v-if="model.mappings.some((m) => (m.path || '').includes('[*]'))" class="mt-subtle hint">
                  {{ t('mroute.recv.mapArrayHint') }}
                </div>
              </el-form-item>
            </el-form>
          </div>
          <div class="side">
            <h4 class="side-h">{{ t('mroute.dry.rawLbl') }}</h4>
            <div class="tr-row">
              <el-button
                size="small"
                :type="live ? 'success' : 'primary'"
                :icon="live ? VideoPause : VideoPlay"
                :loading="testRunBusy"
                :disabled="isNew"
                @click="live ? emit('stop-test-run') : emit('start-test-run')"
              >
                {{ live ? t('mroute.dry.stop') : t('mroute.dry.start') }}
              </el-button>
              <span v-if="live" class="mt-subtle side-tip">
                {{ t('mroute.dry.got', { n: testRun?.count ?? 0 }) }}
              </span>
            </div>
            <p class="mt-subtle side-tip">
              {{ isNew ? t('mroute.recv.testRunNeedSave') : t('mroute.recv.parseTestHint') }}
            </p>

            <h4 class="side-h">{{ t('mroute.sample') }}</h4>
            <div v-if="live && !latest" class="waiting mono">{{ t('mroute.dry.waiting') }}</div>
            <el-input
              v-else
              :model-value="sample"
              type="textarea"
              :rows="8"
              class="mono"
              :placeholder="t('mroute.samplePlaceholder')"
              @update:model-value="(v: string) => emit('update:sample', v)"
            />
            <div class="side-actions">
              <!-- 抓到的那一条已经自动填进上面的框了；这颗按钮是"手改坏了想回到原样"用的。 -->
              <el-button size="small" :disabled="!latest" @click="emit('update:sample', latest?.body || '')">
                {{ t('mroute.dry.useAsSample') }}
              </el-button>
            </div>
            <p v-if="sampleBad" class="mt-danger-text side-tip">
              {{ model.sourceType === 'kv' ? t('mroute.sampleBadKV') : t('mroute.sampleBad') }}
            </p>
            <p v-else-if="detectNote" class="mt-subtle side-tip">{{ detectNote }}</p>
            <p v-else class="mt-subtle side-tip">{{ t('mroute.sampleHint') }}</p>
            <h4 class="side-h">{{ t('mroute.fields') }}</h4>
            <FieldTree :nodes="nodes" @pick="copy" />
          </div>
        </div>
      </el-tab-pane>

    </el-tabs>

    <template #footer>
      <el-button @click="emit('update:visible', false)">{{ t('common.cancel') }}</el-button>
      <el-button type="primary" :loading="saving" @click="emit('save')">{{ t('common.save') }}</el-button>
    </template>
  </el-dialog>
</template>

<style scoped>
/* 高度不在这里限制，交给弹窗本身（.el-dialog__body 滚动，见 style.css）。
 * 曾经这里写 max-height + overflow:auto，结果是：Element 的 .el-tabs__content
 * 带 overflow:hidden，超出部分不计入本元素的 scrollHeight，滚动条不出现，
 * 「安全」「解析」两页底部的内容既看不到也滚不到。
 * min-height 只是为了切页签时高度不要来回跳。 */
.recv-tabs {
  min-height: 46vh;
}
.recv-tabs :deep(.el-tabs__content) {
  overflow: visible;
}
.grid2 {
  display: grid;
  grid-template-columns: minmax(0, 1fr) minmax(0, 1fr);
  gap: 0 16px;
}
/* minmax(0, 1fr) 而不是 1fr：1fr 的最小值是 min-content，左栏里那些定宽
 * 输入框会把左轨道顶宽，把右边那 300px 挤出容器——表现就是右栏文字被切掉。 */
.two-col {
  display: grid;
  grid-template-columns: minmax(0, 1fr) 300px;
  gap: 18px;
}
.two-col > * {
  min-width: 0;
}
.side {
  border-left: 1px solid var(--mt-border, rgba(20, 27, 45, 0.12));
  padding-left: 16px;
}
.side-h {
  margin: 12px 0 6px;
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
.side-actions {
  margin-top: 8px;
}
.tr-row {
  display: flex;
  align-items: center;
  gap: 8px;
}
.waiting {
  display: flex;
  align-items: center;
  justify-content: center;
  height: 132px;
  border: 1px dashed var(--el-border-color);
  border-radius: 6px;
  color: var(--el-text-color-secondary);
  font-size: 13px;
}
.hint {
  font-size: 12px;
  margin-top: 4px;
  line-height: 1.6;
}
.path-row {
  display: grid;
  grid-template-columns: minmax(0, 1fr) auto;
  gap: 8px;
  width: 100%;
}
.map-list {
  width: 100%;
}
/* 数组提示。醒目但不喧哗：它是一句"你还差这一步"，不是错误。 */
.arr-alert {
  margin-bottom: 14px;
}
.arr-list {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
  margin: 4px 0 8px;
}
.arr-chip {
  font-family: ui-monospace, Menlo, Consolas, monospace;
  font-size: 12px;
  padding: 1px 6px;
  border-radius: 5px;
  background: color-mix(in srgb, var(--mt-warning) 18%, transparent);
}
.arr-chip span {
  margin-left: 6px;
}
.arr-act {
  display: flex;
  align-items: center;
  gap: 10px;
  flex-wrap: wrap;
}
.arr-act .hint {
  margin-top: 0;
}
/* 两个分隔符并排：它们是一件事的两半，拆成上下两行会显得像两项独立设置。 */
.sep-row {
  display: grid;
  grid-template-columns: minmax(0, 1fr) minmax(0, 1fr);
  gap: 8px;
  width: 100%;
}
.map-row {
  display: grid;
  /* 别名 / 取值路径 / 缺省值 / 备注 / 删除 */
  grid-template-columns: minmax(0, 1fr) minmax(0, 1.3fr) minmax(0, 0.9fr) minmax(0, 0.9fr) auto;
  gap: 8px;
  margin-bottom: 8px;
}
.is-bad :deep(.el-input__wrapper) {
  box-shadow: 0 0 0 1px var(--el-color-danger) inset;
}
.mono :deep(textarea),
.mono :deep(input) {
  font-family: ui-monospace, Menlo, Consolas, monospace;
  font-size: 13px;
}
/* 窄屏三档。
 * 900：侧栏定宽 300。弹窗宽 min(1040px, 94vw)，900 像素屏上主区只剩约 496，
 * 而字段映射行（五格）硬下限比这还大。侧栏落到下方，分隔线从左边框换成上边框。
 * 640：五格的映射行改成三行——别名与取值路径一行、缺省值与备注一行、删除收在末行靠右。
 * 560：两联排改成一栏。 */
@media (max-width: 900px) {
  .two-col {
    grid-template-columns: minmax(0, 1fr);
  }
  .side {
    border-left: none;
    border-top: 1px solid var(--mt-border, rgba(20, 27, 45, 0.12));
    padding-left: 0;
    padding-top: 14px;
  }
}
@media (max-width: 640px) {
  .map-row {
    grid-template-columns: minmax(0, 1fr) minmax(0, 1fr);
  }
  .map-row > :last-child {
    grid-column: 1 / -1;
    justify-self: end;
  }
}
@media (max-width: 560px) {
  .grid2 {
    grid-template-columns: minmax(0, 1fr);
  }
}
</style>
