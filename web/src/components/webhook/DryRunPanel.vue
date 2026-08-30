<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import { ElMessage } from 'element-plus'
import { VideoPlay, VideoPause } from '@element-plus/icons-vue'
import { webhookActions } from '@/api/webhook'
import type { DryRunResult, TestRunCapture, TestRunState, WebhookReceiver } from '@/api/webhook'
import { fmtTime, fmtTimeMs, fmtBytes } from '@/composables/useResource'
import FieldTree from './FieldTree.vue'
import { buildFieldTree } from '@/composables/fieldPaths'

// 试运行面板。两种用法共用同一个右栏：
//
//	实时监听  开着的时候，第三方推来的真实消息进到这里就停下——**不会转发**，
//	          左栏实时显示对方原样发来的东西，右栏是这条消息跑完流水线的结果
//	样本载荷  手贴一段 JSON / 文本，立刻看结果；不需要等对方推送
//
// 右栏两种来源完全一致（后端是同一个 dryRunOf），所以"试运行页看到的"
// 与"真实转发出去的"永远是同一份渲染结果——这是这个功能唯一的价值所在。
//
// 抓包**只留最新一条**（后端 TestRunState.capture）：调模板、配映射、看预览，
// 要的永远是刚刚推过来的那一条。它同时就是全局唯一的样本载荷。

const props = defineProps<{
  visible: boolean
  receiver: WebhookReceiver | null
  sample: string
  testRun?: TestRunState
  testRunBusy?: boolean
}>()
const emit = defineEmits<{
  (e: 'update:visible', v: boolean): void
  (e: 'update:sample', v: string): void
  (e: 'start-test-run'): void
  (e: 'stop-test-run'): void
}>()

const { t } = useI18n()

const query = ref('')
const headerText = ref('')
const running = ref(false)
const sampleResult = ref<DryRunResult | null>(null)

const live = computed(() => !!props.testRun?.running)
// current 试运行抓到的那一条（只有一条）。停止之后它仍然在——那就是样本载荷。
const current = computed<TestRunCapture | null>(() => props.testRun?.capture ?? null)

// result 右栏渲染的那一份：有抓包就用抓包的，否则用手贴样本跑出来的。
const result = computed<DryRunResult | null>(() => current.value?.result ?? sampleResult.value)

watch(
  () => props.visible,
  (open) => {
    if (!open) sampleResult.value = null
  },
)
// 换接收器就把上一份结果丢掉：右栏留着别人的渲染结果比空着更容易误判。
watch(
  () => props.receiver?.id,
  () => {
    sampleResult.value = null
  },
)
// 新抓包顶掉旧的时，手贴样本那份结果就过期了——留着会让右栏说的不是左栏那一条。
watch(
  () => current.value?.time,
  () => {
    sampleResult.value = null
  },
)

// 请求头按"每行 名: 值"填，比一张键值表快得多——用户通常是从对方文档里整段抄过来的。
const headers = computed(() => {
  const out: Record<string, string> = {}
  for (const line of headerText.value.split('\n')) {
    const i = line.indexOf(':')
    if (i <= 0) continue
    const k = line.slice(0, i).trim()
    if (k) out[k] = line.slice(i + 1).trim()
  }
  return out
})

const rootNodes = computed(() => buildFieldTree(result.value?.root ?? null))

// leftText 左栏显示的内容：实时模式下是抓到的原始载荷（只读），否则是可编辑的样本。
const leftText = computed(() => (current.value ? current.value.body : props.sample))

// countdown 试运行还剩多久自动停止。到期自停是刻意的（见后端 TestRunTTL）：
// 一个忘了关的试运行会一直吞掉真实推送，所以剩余时间必须一直摆在眼前。
const now = ref(Date.now())
let tick: number | undefined
watch(
  live,
  (on) => {
    if (on && tick === undefined) {
      tick = window.setInterval(() => (now.value = Date.now()), 1000)
    } else if (!on && tick !== undefined) {
      clearInterval(tick)
      tick = undefined
    }
  },
  { immediate: true },
)
const remainText = computed(() => {
  const exp = props.testRun?.expiresAt
  if (!live.value || !exp) return ''
  const left = Math.max(0, exp * 1000 - now.value)
  const m = Math.floor(left / 60000)
  const s = Math.floor((left % 60000) / 1000)
  return `${m}:${String(s).padStart(2, '0')}`
})

// useAsSample 把抓到的这条原始载荷变成共用样本，供模板与字段映射那两个弹窗接着用。
function useAsSample() {
  const c = current.value
  if (!c) return
  emit('update:sample', c.body || '')
  query.value = c.query || ''
  headerText.value = Object.entries(c.headers || {})
    .map(([k, v]) => `${k}: ${v}`)
    .join('\n')
  ElMessage.success(t('mroute.dry.usedAsSample'))
}

function targetName(id: string): string {
  return result.value?.targetNames?.[id] || id
}

async function run() {
  if (!props.receiver?.id) return
  if (!props.sample.trim()) {
    ElMessage.warning(t('mroute.dry.needBody'))
    return
  }
  running.value = true
  try {
    sampleResult.value = await webhookActions.dryRun(props.receiver.id, {
      body: props.sample,
      headers: headers.value,
      query: query.value,
    })
  } finally {
    running.value = false
  }
}
</script>

<template>
  <el-dialog
    :model-value="visible"
    :title="t('mroute.dry.title', { name: receiver?.name || '' })"
    width="min(1080px, 94vw)"
    top="6vh"
    @update:model-value="(v: boolean) => emit('update:visible', v)"
  >
    <div class="dry-wrap">
      <div class="dry-left">
        <!-- 实时监听开关。蓝=没开，绿=开着；开着期间这个接收器的消息只进这里，不发出去。 -->
        <div class="tr-row">
          <el-button
            :type="live ? 'success' : 'primary'"
            :icon="live ? VideoPause : VideoPlay"
            :loading="testRunBusy"
            @click="live ? emit('stop-test-run') : emit('start-test-run')"
          >
            {{ live ? t('mroute.dry.stop') : t('mroute.dry.start') }}
          </el-button>
          <span v-if="live" class="tr-meta">
            {{ t('mroute.dry.got', { n: testRun?.count ?? 0 }) }} ·
            {{ t('mroute.dry.remain', { time: remainText }) }}
          </span>
        </div>
        <div class="tip">{{ live ? t('mroute.dry.liveNote') : t('mroute.dry.startHint') }}</div>
        <el-alert
          v-if="!live && testRun?.stoppedReason"
          :title="testRun.stoppedReason"
          type="info"
          :closable="false"
          show-icon
          class="al"
        />
        <!-- 抓包有存活上限（后端 CaptureTTL）：到点真被销毁了要说清楚，否则用户看到的是
             一个"收到过 N 条却什么都没有"的面板，只会以为坏了。 -->
        <el-alert
          v-if="!current && testRun?.captureExpired"
          :title="t('mroute.dry.capGone')"
          type="warning"
          :closable="false"
          show-icon
          class="al"
        />

        <!-- 抓包只留最新一条：调模板、配映射要的永远是刚推过来的那一条，
             翻旧记录的需求由「执行历史」承担（那里才是留档的地方）。 -->
        <template v-if="current">
          <div class="sec-h">{{ t('mroute.dry.rawLbl') }}</div>
          <div class="cap-meta">
            <el-tag size="small" type="info">{{ current.method }}</el-tag>
            <el-tag v-if="current.sniffed" size="small">
              {{ t('mroute.dry.sniffed', { type: current.sniffed }) }}
            </el-tag>
            <el-tag v-if="current.rejected" size="small" type="danger">{{ current.status }}</el-tag>
            <span class="tr-meta">{{ fmtTimeMs(current.time) }} · {{ current.remote || '—' }}</span>
            <!-- 这一份什么时候被销毁。写绝对时刻而不是倒计时：面板停下来之后没有秒表在跑，
                 一个不动的"还剩 2 小时 41 分"比一个准确的时间点更容易让人误判。 -->
            <span v-if="testRun?.captureExpiresAt" class="tr-meta">
              · {{ t('mroute.dry.capExpires', { time: fmtTime(testRun.captureExpiresAt) }) }}
            </span>
          </div>
          <el-alert
            v-if="current.rejected"
            :title="t('mroute.dry.capRejectedNote', { reason: current.reason })"
            type="error"
            :closable="false"
            show-icon
            class="al"
          />
          <!-- 正文超过抓包上限时只留了前一截（后端 captureBodyMax）。必须说出来：
               这一份拿去当样本会解析失败，而那不是模板写错了。 -->
          <el-alert
            v-if="current.bodyTruncated"
            :title="t('mroute.dry.capTruncated', { size: fmtBytes(current.bodySize) })"
            type="warning"
            :closable="false"
            show-icon
            class="al"
          />
          <el-input :model-value="leftText" type="textarea" :rows="10" readonly class="mono" />
          <div class="btn-row">
            <el-button size="small" @click="useAsSample">{{ t('mroute.dry.useAsSample') }}</el-button>
            <span class="tip">{{ t('mroute.dry.latestOnly') }}</span>
          </div>
        </template>

        <!-- 等消息进来时不给编辑框：此刻能做的事只有"去第三方系统里点一下推送"。 -->
        <template v-else-if="live">
          <div class="sec-h">{{ t('mroute.dry.rawLbl') }}</div>
          <div class="waiting mono">{{ t('mroute.dry.waiting') }}</div>
        </template>

        <template v-else>
          <div class="sec-h">{{ t('mroute.dry.input') }}</div>
          <el-input
            :model-value="sample"
            type="textarea"
            :rows="12"
            :placeholder="t('mroute.samplePlaceholder')"
            class="mono"
            @update:model-value="(v: string) => emit('update:sample', v)"
          />
          <el-collapse class="more">
            <el-collapse-item :title="t('mroute.dry.more')" name="more">
              <div class="lbl">{{ t('mroute.dry.query') }}</div>
              <el-input v-model="query" placeholder="a=1&b=2" />
              <div class="lbl">{{ t('mroute.dry.headers') }}</div>
              <el-input v-model="headerText" type="textarea" :rows="3" class="mono" />
              <div class="tip">{{ t('mroute.dry.headersHint') }}</div>
            </el-collapse-item>
          </el-collapse>
          <div class="btn-row">
            <el-button type="primary" :loading="running" @click="run">{{ t('mroute.dry.run') }}</el-button>
          </div>
          <div class="tip">{{ t('mroute.dry.noSend') }}</div>
        </template>
      </div>

      <div class="dry-right">
        <div v-if="!result" class="tip pad">{{ t('mroute.dry.empty') }}</div>
        <template v-else>
          <div class="sum-row">
            <el-tag size="small" type="info">{{ result.eventId }}</el-tag>
            <el-tag size="small" :type="result.matched > 0 ? 'success' : 'warning'">
              {{ t('mroute.dry.matched', { n: result.matched }) }}
            </el-tag>
            <el-tag v-if="result.truncated" size="small" type="warning">{{ t('mroute.dry.truncated') }}</el-tag>
            <el-tag v-if="result.blocked" size="small" type="danger">{{ t('mroute.dry.blockedTag') }}</el-tag>
          </div>

          <!-- 关键词准入会把这条拦在流水线之前。下面的渲染结果照样给出（后端刻意算完了），
               否则用户配好词表、试运行一切正常，上线后一条也进不来。 -->
          <el-alert
            v-if="result.blocked"
            :title="t('mroute.dry.blocked')"
            type="error"
            :closable="false"
            show-icon
            class="al"
          >
            <div class="small">{{ result.blockedReason }}</div>
            <div class="small">{{ t('mroute.dry.blockedHint') }}</div>
          </el-alert>

          <el-alert
            v-if="result.unresolved?.length"
            :title="t('mroute.dry.unresolved')"
            type="warning"
            :closable="false"
            show-icon
            class="al"
          >
            <div class="mono small">{{ result.unresolved.join('\n') }}</div>
          </el-alert>

          <!-- 命中了规则、但分支条件都不成立：与"没有规则命中"是两回事，
               混成同一句话会让用户回头去改已经对了的那一层条件。 -->
          <el-alert
            v-if="result.noBranch?.length"
            :title="t('mroute.dry.noBranch', { rules: result.noBranch.join('、') })"
            type="warning"
            :closable="false"
            show-icon
            class="al"
          >
            <div class="small">{{ t('mroute.dry.noBranchHint') }}</div>
          </el-alert>

          <el-alert
            v-if="!result.messages?.length && !result.noBranch?.length"
            :title="t('mroute.dry.noMessage')"
            type="info"
            :closable="false"
            show-icon
            class="al"
          />

          <div v-for="(m, i) in result.messages || []" :key="i" class="msg">
            <div class="msg-head">
              <strong>{{ m.ruleName }}</strong>
              <!-- 分支名单独一个标签：一条规则有两个出口之后，这一格是判断
                   "哪个出口发了、哪个没发"的唯一依据。模板名紧跟其后——两个分支的正文
                   常常长得很像，只看渲染结果分不出是分支条件筛错了还是模板选错了。 -->
              <el-tag v-if="m.branch" size="small" type="success" effect="plain">{{ m.branch }}</el-tag>
              <span v-if="m.template" class="tip">{{ t('mroute.dry.viaTemplate', { name: m.template }) }}</span>
              <el-tag v-if="m.missing" size="small" type="warning">
                {{ t('mroute.dry.missingFields', { n: m.missing }) }}
              </el-tag>
              <el-tag v-if="m.error" size="small" type="danger">{{ m.error }}</el-tag>
            </div>
            <div class="msg-to">
              <span class="tip">{{ t('mroute.dry.sendTo') }}</span>
              <el-tag v-for="tid in m.targets" :key="tid" size="small">{{ targetName(tid) }}</el-tag>
              <span v-if="!m.targets?.length" class="mt-danger-text">{{ t('mroute.dry.noTarget') }}</span>
            </div>
            <div class="preview">
              <!-- 标题这一行是「会话列表里的那行预览」，不是消息内容本身：markdown 的标题
                   已经按模板上的「标题样式」拼进正文了（后端 MarkdownTitled），不加标签
                   看着就像同一个标题出现了两遍。 -->
              <div v-if="m.title" class="pv-title">
                <span class="pv-tag">{{ t('mroute.dry.pushTitle') }}</span>
                <span>{{ m.title }}</span>
              </div>
              <div class="pv-body">{{ m.body }}</div>
            </div>
          </div>

          <el-collapse class="more">
            <el-collapse-item :title="t('mroute.dry.rootFields')" name="root">
              <!-- 正文被截断的那一份不带字段树（后端 RootDropped）：字段树是按整段正文
                   解出来的，留着它等于没截。这里要把原因说清楚，而不是显示一棵空树。 -->
              <div class="tip">
                {{ current?.rootDropped ? t('mroute.dry.rootDropped') : t('mroute.dry.rootHint') }}
              </div>
              <FieldTree v-if="!current?.rootDropped" :nodes="rootNodes" />
            </el-collapse-item>
          </el-collapse>
        </template>
      </div>
    </div>
  </el-dialog>
</template>

<style scoped>
.dry-wrap {
  display: grid;
  grid-template-columns: 420px minmax(0, 1fr);
  gap: 16px;
}
.dry-left,
.dry-right {
  min-width: 0;
}
.dry-right {
  max-height: 62vh;
  overflow: auto;
}
.tr-row {
  display: flex;
  align-items: center;
  gap: 10px;
  margin-bottom: 6px;
}
.tr-meta {
  font-size: 12px;
  color: var(--el-text-color-secondary);
}
.cap-meta {
  display: flex;
  gap: 6px;
  margin: 6px 0;
}
.waiting {
  display: flex;
  align-items: center;
  justify-content: center;
  height: 200px;
  border: 1px dashed var(--el-border-color);
  border-radius: 6px;
  color: var(--el-text-color-secondary);
}
.sec-h {
  margin: 10px 0 6px;
  font-weight: 600;
}
.lbl {
  margin: 8px 0 4px;
  font-size: 13px;
  color: var(--el-text-color-regular);
}
.tip {
  font-size: 12px;
  color: var(--el-text-color-secondary);
  line-height: 1.6;
}
.tip.pad {
  padding: 24px 8px;
}
.btn-row {
  display: flex;
  align-items: center;
  gap: 8px;
  margin: 10px 0 6px;
}
.more {
  margin-top: 8px;
}
.sum-row {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
}
.al {
  margin: 8px 0;
}
.msg {
  margin: 10px 0;
  padding: 10px;
  border: 1px solid var(--el-border-color-lighter);
  border-radius: 6px;
}
.msg-head {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 8px;
}
.msg-to {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 6px;
  margin: 6px 0;
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
.small {
  font-size: 12px;
}
.mt-danger-text {
  color: var(--mt-danger, #f56c6c);
  font-size: 12px;
}
.mono :deep(textarea),
.mono {
  font-family: ui-monospace, Menlo, Consolas, monospace;
}

/* 窄屏：左栏定宽 420，加上右栏与 16 的间距，弹窗宽 min(1080px, 94vw) 在 900 像素屏上
 * 只有 1015 × 0.94 ≈ 846 - 32 = 814 的正文宽——右栏只剩不到 380，抓包那栏的原文
 * 每行都要折。这一档改成上下两段，左边那段不再定宽。 */
@media (max-width: 900px) {
  .dry-wrap {
    grid-template-columns: minmax(0, 1fr);
  }
}
</style>
