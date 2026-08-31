<script setup lang="ts">
import { onActivated, ref, reactive, computed, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import { ElMessage } from 'element-plus'
import { Plus } from '@element-plus/icons-vue'
import PageCard from '@/components/PageCard.vue'
import RowActions from '@/components/RowActions.vue'
import { useNarrow } from '@/composables/useNarrow'
import { useResource, fmtTime } from '@/composables/useResource'
import { ddnsApi, wolApi, cronApi, actions } from '@/api/resources'

const { t, tm, rt, locale } = useI18n()

// 窄屏时操作列只剩一个「更多」按钮，列宽跟着收窄，省下的宽度留给前面几列。
const narrow = useNarrow()

interface Schedule {
  type: string
  minute: number
  hour: number
  weekdays: number[]
  day: number
  everyMinutes: number
  everyUnit: string
  expr: string
}
interface Task {
  id?: string
  name: string
  enabled: boolean
  cron: string
  schedule: Schedule
  action: { type: string; params: Record<string, string> }
  timeoutSec: number
  lastRunAt?: number
  nextRunAt?: number
  lastStatus?: string
}
function emptySchedule(): Schedule {
  return { type: 'daily', minute: 0, hour: 3, weekdays: [1], day: 1, everyMinutes: 5, everyUnit: 'minutes', expr: '' }
}
function empty(): Task {
  return {
    name: '',
    enabled: true,
    cron: '0 3 * * *',
    schedule: emptySchedule(),
    action: { type: 'ddns.refresh', params: {} },
    timeoutSec: 0,
  }
}
const r = useResource<Task>('crontasks', empty, { afterChange: () => refreshDescriptions() })

const ddnsRules = ref<{ id: string; name: string }[]>([])
const wolDevices = ref<{ id: string; name: string }[]>([])
const running = ref<Record<string, boolean>>({})

// 动作类型 → i18n 键（避免点号键在 vue-i18n 组合式下被当作嵌套路径）。
const ACTION_KEY: Record<string, string> = {
  'ddns.refresh': 'ddnsRefresh',
  'wol.wake': 'wolWake',
  'cert.renew': 'certRenew',
  http: 'http',
}
function actionLabel(type: string): string {
  const k = ACTION_KEY[type]
  return k ? t(`cron.actionType.${k}`) : type
}

const actionType = computed({
  get: () => (r.editing.value as Task).action.type,
  set: (v: string) => {
    ;(r.editing.value as Task).action = { type: v, params: {} }
  },
})

// 星期选项（i18n 数组）。
const weekdayOptions = computed(() => {
  const names = tm('cron.weekdayNames') as unknown as any[]
  return (names || []).map((n, i) => ({ label: rt(n), value: i }))
})

// 时刻选择器（HH:mm）↔ schedule.hour/minute。
const atTime = computed<string>({
  get: () => {
    const s = (r.editing.value as Task).schedule
    return `${String(s.hour).padStart(2, '0')}:${String(s.minute).padStart(2, '0')}`
  },
  set: (v: string) => {
    const s = (r.editing.value as Task).schedule
    const [h, m] = (v || '00:00').split(':').map((x) => Number(x))
    s.hour = Number.isFinite(h) ? h : 0
    s.minute = Number.isFinite(m) ? m : 0
  },
})

// 间隔单位上限：分钟 1-59，小时 1-23（保证生成的 cron 合法）。
const intervalMax = computed(() => ((r.editing.value as Task).schedule.everyUnit === 'hours' ? 23 : 59))

// 由结构化调度生成标准 5 段 cron（分 时 日 月 周）。
function buildCron(s: Schedule): string {
  const m = s.minute || 0
  const h = s.hour || 0
  switch (s.type) {
    case 'minutely':
      return '* * * * *'
    case 'hourly':
      return `${m} * * * *`
    case 'daily':
      return `${m} ${h} * * *`
    case 'weekly': {
      const days = s.weekdays && s.weekdays.length ? [...s.weekdays].sort((a, b) => a - b).join(',') : '*'
      return `${m} ${h} * * ${days}`
    }
    case 'monthly':
      return `${m} ${h} ${s.day || 1} * *`
    case 'interval': {
      const n = s.everyMinutes || 1
      // 按分钟：*/N（N∈1-59）；按小时：0 */N（N∈1-23）——避免出现越界的步进值。
      if (s.everyUnit === 'hours') {
        const hh = Math.min(Math.max(n, 1), 23)
        return `0 */${hh} * * *`
      }
      const mm = Math.min(Math.max(n, 1), 59)
      return `*/${mm} * * * *`
    }
    case 'custom':
      return s.expr || ''
    default:
      return `${m} ${h} * * *`
  }
}

// 调度变化时实时回写 cron 字段（保存时随任务一并提交）。
watch(
  () => (r.editing.value as Task).schedule,
  (s) => {
    if (s) (r.editing.value as Task).cron = buildCron(s)
  },
  { deep: true, immediate: true },
)

// ---------- 人类可读描述（按表达式缓存，避免重复请求） ----------
const descCache = reactive<Record<string, string>>({})

async function ensureDesc(expr: string) {
  const e = (expr || '').trim()
  if (!e) return
  const key = `${locale.value}::${e}`
  if (key in descCache) return
  descCache[key] = '' // 占位，防止并发重复请求
  try {
    const res = await actions.cronDescribe(e, locale.value)
    descCache[key] = res?.text || e
  } catch {
    descCache[key] = e
  }
}
function describe(expr: string): string {
  const e = (expr || '').trim()
  if (!e) return '—'
  return descCache[`${locale.value}::${e}`] || e
}

// 一批表达式的描述写入缓存。失败时回落成表达式原文（与 ensureDesc 的 catch 同义）：
// 不能把占位空串留在缓存里——key 已存在就再也不会重试，那一栏会一直显示表达式原文却永不修正。
async function fillDescriptions(exprs: string[], lang: string) {
  try {
    const res = await actions.cronDescribeBatch(exprs, lang)
    const items = res?.items || []
    exprs.forEach((e, i) => {
      descCache[`${lang}::${e}`] = items[i] || e
    })
  } catch {
    for (const e of exprs) descCache[`${lang}::${e}`] = e
  }
}

// 整张列表的描述一次问完。
//
// 原先是逐条 ensureDesc()，N 条规则就发 N 个请求：它们都排在列表渲染之后，
// 于是「表格已经出来了、描述那一栏还在一条条陆续填」。批量之后固定一次往返。
// 相同表达式先去重（多条任务共用一个表达式很常见），缓存里已有的不再问。
function refreshDescriptions() {
  const lang = locale.value
  const pending: string[] = []
  const seen = new Set<string>()
  for (const task of r.list.value as Task[]) {
    const e = (task.cron || '').trim()
    if (!e || seen.has(e) || `${lang}::${e}` in descCache) continue
    seen.add(e)
    pending.push(e)
  }
  if (!pending.length) return
  // 占位，防止本轮在途时又被触发一遍（与 ensureDesc 里同样的去重手法）。
  for (const e of pending) descCache[`${lang}::${e}`] = ''
  // 与后端 maxBatch 对齐分批，避免规则数超过上限时后面几条被静默截掉。
  const chunk = 200
  for (let i = 0; i < pending.length; i += chunk) {
    void fillDescriptions(pending.slice(i, i + chunk), lang)
  }
}

// 编辑弹窗内实时预览当前生成表达式的描述。
watch(
  () => (r.editing.value as Task).cron,
  (c) => {
    if (r.dialogVisible.value) ensureDesc(c)
  },
)
// 语言切换后重新拉取列表内的描述。
watch(locale, () => refreshDescriptions())

// ---------- 立即执行 ----------
async function runNow(row: Task) {
  if (!row.id) return
  running.value[row.id] = true
  try {
    const res = await actions.runCron(row.id)
    ElMessage.success(res?.result || t('cron.runOk'))
    await r.load()
    refreshDescriptions()
  } catch (e: any) {
    ElMessage.error(e?.message || t('cron.runFail'))
  } finally {
    running.value[row.id] = false
  }
}

// 列表快捷启用/禁用：整体 PUT 该任务（启用状态变化会触发后端审计日志）。
async function toggleCron(row: Task) {
  const prev = row.enabled
  try {
    await cronApi.update(row.id!, { ...row })
  } catch (e: any) {
    row.enabled = prev
    ElMessage.error(e?.message || t('common.saveFailed'))
  }
}

// 页面被激活（keep-alive 下首次挂载同样会触发一次，因此这里是唯一入口）。
// 三个请求彼此独立，并发发出；只有描述必须排在列表之后——refreshDescriptions
// 遍历的正是 r.list。
// 顺带把 ddns / wol 拆成两个各自的 catch：原先共用一个 try，ddns 一失败 wol 就整条被跳过，
// 于是「触发目标」下拉框里少一半选项，成功路径的行为不变。
onActivated(async () => {
  await Promise.all([
    r.load().then(() => refreshDescriptions()),
    ddnsApi
      .list()
      .then((items) => {
        ddnsRules.value = items as any
      })
      .catch(() => undefined),
    wolApi
      .list()
      .then((items) => {
        wolDevices.value = items as any
      })
      .catch(() => undefined),
  ])
})
</script>

<template>
  <PageCard :title="t('cron.title')" :subtitle="t('cron.subtitle')" :max-count="r.maxCount.value">
    <template #actions>
      <el-button type="primary" :icon="Plus" @click="r.openCreate()">{{ t('common.add') }}</el-button>
    </template>

    <el-table :data="r.list.value" v-loading="r.loading.value" stripe row-key="id">
      <el-table-column :label="t('common.status')" width="90">
        <template #default="{ row }">
          <el-switch v-model="row.enabled" @change="toggleCron(row)" />
        </template>
      </el-table-column>
      <el-table-column :label="t('cron.taskName')" min-width="130">
        <template #default="{ row }"><strong>{{ row.name || t('common.unnamed') }}</strong></template>
      </el-table-column>
      <el-table-column :label="t('cron.expr')" min-width="180">
        <template #default="{ row }">
          <code>{{ row.cron }}</code>
          <div class="mt-subtle desc">{{ describe(row.cron) }}</div>
        </template>
      </el-table-column>
      <el-table-column :label="t('cron.action')" min-width="110">
        <template #default="{ row }">{{ actionLabel(row.action.type) }}</template>
      </el-table-column>
      <el-table-column :label="t('cron.lastRun')" min-width="180">
        <template #default="{ row }">
          <div class="mt-cell-2row">
            <div>{{ fmtTime(row.lastRunAt) }}</div>
            <div v-if="row.lastStatus" class="mt-subtle desc" :title="row.lastStatus">
              {{ row.lastStatus }}
            </div>
          </div>
        </template>
      </el-table-column>
      <el-table-column :label="t('cron.nextRun')" min-width="180">
        <template #default="{ row }">
          <div class="mt-cell-2row">
            <div>{{ row.enabled ? fmtTime(row.nextRunAt) : '—' }}</div>
          </div>
        </template>
      </el-table-column>
      <el-table-column :label="t('common.actions')" :width="narrow ? 90 : 200" align="right">
        <template #default="{ row }">
          <RowActions>
            <el-button size="small" :loading="running[row.id]" @click="runNow(row)">{{ t('cron.runNow') }}</el-button>
            <el-button size="small" @click="r.openEdit(row)">{{ t('common.edit') }}</el-button>
            <el-button size="small" type="danger" text @click="r.remove(row, t('common.confirmDelete'))">
              {{ t('common.delete') }}
            </el-button>
          </RowActions>
        </template>
      </el-table-column>
    </el-table>

    <el-dialog v-model="r.dialogVisible.value" :title="r.isNew.value ? t('common.add') : t('common.edit')" width="min(540px, 94vw)" append-to-body :close-on-click-modal="false">
      <el-form label-position="top">
        <div class="grid2">
          <el-form-item :label="t('cron.taskName')">
            <el-input v-model="(r.editing.value as Task).name" />
          </el-form-item>
          <el-form-item :label="t('common.status')">
            <el-switch v-model="(r.editing.value as Task).enabled" />
          </el-form-item>
        </div>

        <el-divider content-position="left">{{ t('cron.scheduleType') }}</el-divider>
        <el-form-item :label="t('cron.scheduleType')">
          <el-select v-model="(r.editing.value as Task).schedule.type" style="width: 100%">
            <el-option :label="t('cron.type.minutely')" value="minutely" />
            <el-option :label="t('cron.type.hourly')" value="hourly" />
            <el-option :label="t('cron.type.daily')" value="daily" />
            <el-option :label="t('cron.type.weekly')" value="weekly" />
            <el-option :label="t('cron.type.monthly')" value="monthly" />
            <el-option :label="t('cron.type.interval')" value="interval" />
            <el-option :label="t('cron.type.custom')" value="custom" />
          </el-select>
        </el-form-item>

        <!-- 每小时：仅分钟 -->
        <el-form-item v-if="(r.editing.value as Task).schedule.type === 'hourly'" :label="t('cron.atMinute')">
          <el-input-number v-model="(r.editing.value as Task).schedule.minute" :min="0" :max="59" style="width: 100%" />
        </el-form-item>

        <!-- 每天/每周/每月：时刻 -->
        <template v-if="['daily', 'weekly', 'monthly'].includes((r.editing.value as Task).schedule.type)">
          <div class="grid2">
            <el-form-item :label="t('cron.atTime')">
              <el-time-picker v-model="atTime" format="HH:mm" value-format="HH:mm" style="width: 100%" />
            </el-form-item>
            <el-form-item v-if="(r.editing.value as Task).schedule.type === 'monthly'" :label="t('cron.day')">
              <el-input-number v-model="(r.editing.value as Task).schedule.day" :min="1" :max="31" style="width: 100%" />
            </el-form-item>
          </div>
          <el-form-item v-if="(r.editing.value as Task).schedule.type === 'weekly'" :label="t('cron.weekday')">
            <el-select v-model="(r.editing.value as Task).schedule.weekdays" multiple style="width: 100%">
              <el-option v-for="w in weekdayOptions" :key="w.value" :label="w.label" :value="w.value" />
            </el-select>
          </el-form-item>
        </template>

        <!-- 固定间隔：数值 + 单位（分钟/小时），保证生成合法 cron -->
        <el-form-item v-if="(r.editing.value as Task).schedule.type === 'interval'" :label="t('cron.everyN')">
          <div class="grid2">
            <el-input-number v-model="(r.editing.value as Task).schedule.everyMinutes" :min="1" :max="intervalMax" style="width: 100%" />
            <el-select v-model="(r.editing.value as Task).schedule.everyUnit" style="width: 100%">
              <el-option :label="t('cron.unit.minutes')" value="minutes" />
              <el-option :label="t('cron.unit.hours')" value="hours" />
            </el-select>
          </div>
        </el-form-item>

        <!-- 自定义 -->
        <el-form-item v-if="(r.editing.value as Task).schedule.type === 'custom'" :label="t('cron.customExpr')">
          <el-input v-model="(r.editing.value as Task).schedule.expr" placeholder="0 3 * * *" />
          <div class="mt-subtle hint">{{ t('cron.exprHint') }}</div>
        </el-form-item>

        <el-form-item :label="t('cron.generated')">
          <div>
            <code class="gen">{{ (r.editing.value as Task).cron || '—' }}</code>
            <span class="mt-subtle preview">{{ describe((r.editing.value as Task).cron) }}</span>
          </div>
        </el-form-item>

        <el-divider content-position="left">{{ t('cron.action') }}</el-divider>
        <el-form-item :label="t('cron.action')">
          <el-select v-model="actionType" style="width: 100%">
            <el-option :label="t('cron.actionType.ddnsRefresh')" value="ddns.refresh" />
            <el-option :label="t('cron.actionType.wolWake')" value="wol.wake" />
            <el-option :label="t('cron.actionType.certRenew')" value="cert.renew" />
            <el-option :label="t('cron.actionType.http')" value="http" />
          </el-select>
        </el-form-item>

        <el-form-item v-if="actionType === 'ddns.refresh'" :label="t('cron.target')">
          <el-select v-model="(r.editing.value as Task).action.params.ruleId" style="width: 100%">
            <el-option v-for="d in ddnsRules" :key="d.id" :label="d.name" :value="d.id" />
          </el-select>
        </el-form-item>
        <el-form-item v-if="actionType === 'wol.wake'" :label="t('cron.target')">
          <el-select v-model="(r.editing.value as Task).action.params.deviceId" style="width: 100%">
            <el-option v-for="d in wolDevices" :key="d.id" :label="d.name" :value="d.id" />
          </el-select>
        </el-form-item>

        <!-- HTTP 动作 -->
        <template v-if="actionType === 'http'">
          <div class="grid-url">
            <el-form-item :label="t('cron.method')">
              <el-select v-model="(r.editing.value as Task).action.params.method" style="width: 100%">
                <el-option label="GET" value="GET" />
                <el-option label="POST" value="POST" />
                <el-option label="PUT" value="PUT" />
                <el-option label="DELETE" value="DELETE" />
                <el-option label="HEAD" value="HEAD" />
              </el-select>
            </el-form-item>
            <el-form-item :label="t('cron.url')">
              <el-input v-model="(r.editing.value as Task).action.params.url" placeholder="https://example.com/hook" />
            </el-form-item>
          </div>
        </template>

        <!-- 超时：对 HTTP / 证书续期动作生效 -->
        <el-form-item v-if="['http', 'cert.renew'].includes(actionType)" :label="t('cron.timeout')">
          <el-input-number v-model="(r.editing.value as Task).timeoutSec" :min="0" :max="86400" style="width: 100%" />
          <div class="mt-subtle hint">{{ t('cron.timeoutHint') }}</div>
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="r.dialogVisible.value = false">{{ t('common.cancel') }}</el-button>
        <el-button type="primary" :loading="r.saving.value" @click="r.save()">{{ t('common.save') }}</el-button>
      </template>
    </el-dialog>
  </PageCard>
</template>

<style scoped>
.grid2 {
  display: grid;
  grid-template-columns: minmax(0, 1fr) minmax(0, 1fr);
  gap: 0 16px;
}
.grid-url {
  display: grid;
  grid-template-columns: 120px minmax(0, 1fr);
  gap: 0 16px;
}
.hint {
  font-size: 12px;
  margin-top: 4px;
}
.desc {
  font-size: 12px;
  margin-top: 2px;
  line-height: 1.4;
}
code {
  font-family: ui-monospace, Menlo, Consolas, monospace;
  background: rgba(140, 150, 170, 0.14);
  padding: 2px 6px;
  border-radius: 5px;
}
.gen {
  display: inline-block;
  font-size: 14px;
  padding: 4px 10px;
}
.preview {
  margin-left: 10px;
  font-size: 13px;
}

/* 窄屏：每栏不足 240 像素时，定时表达式那几个框看不到一整条，改成一栏。 */
@media (max-width: 560px) {
  .grid2 {
    grid-template-columns: minmax(0, 1fr);
  }
}
</style>
