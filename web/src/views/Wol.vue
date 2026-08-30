<script setup lang="ts">
import { computed, ref, onActivated, onDeactivated, onBeforeUnmount } from 'vue'
import { useI18n } from 'vue-i18n'
import { ElMessage } from 'element-plus'
import { Plus } from '@element-plus/icons-vue'
import PageCard from '@/components/PageCard.vue'
import { useResource, fmtTime } from '@/composables/useResource'
import { actions, type WOLInterface } from '@/api/resources'

const { t } = useI18n()

// Schedule 两种触发方式各自只用到一部分字段（与后端 config.WOLSchedule 一致）：
//   - fixed（固定时间）：time + count —— 每天在 time 这一个时间点，于 1 秒内发 count 个包。
//   - range（时间范围）：start + end + intervalSec —— 从 start 到 end，每 intervalSec 秒发 1 个包。
// 另一方式的字段不参与计算，表单里也不展示，避免出现「填了却没用」的输入框。
interface Schedule {
  enabled: boolean
  calendarEnabled: boolean
  mode: string
  startDate: string
  endDate: string
  time: string
  start: string
  end: string
  count: number
  intervalSec: number
}
interface Device {
  id?: string
  enabled?: boolean
  name: string
  mac: string
  broadcast: string
  port: number
  // 指定从哪张网卡发出（网卡名）。留空 = 自动：只用内网物理网卡，
  // 虚拟网卡与公网网卡会被后端排除（见 wol.selectTargets）。
  interface: string
  note: string
  schedule: Schedule
  // 统计，后端只在列表里返回，只读。这几个数只在服务端内存里，重启归零，
  // 保存时不会带回去（后端也不接收）。
  lastWakeAt?: number
  lastResult?: string
  wakeCount?: number
}
function empty(): Device {
  return {
    enabled: true,
    name: '',
    mac: '',
    broadcast: '255.255.255.255',
    port: 9,
    interface: '',
    note: '',
    schedule: { enabled: false, calendarEnabled: false, mode: 'fixed', startDate: '', endDate: '', time: '08:00', start: '08:00', end: '18:00', count: 1, intervalSec: 5 },
  }
}
const r = useResource<Device>('wol', empty)

// 设备一多就要提醒：每台启用了定时唤醒的设备各占一条常驻协程，且每一拍都要串行回写运行态，
// 总成本随设备数与拍频同时增长（详见后端 config.MaxWOLDevices）。
// 阈值取 50，远低于硬上限——上限那个数由后端下发（见 @/api/limits，已写在标题下方那句说明里），
// 前端不复制这个常量，免得两处哪天不一致；这里只负责在还来得及的时候提醒一句。
const crowdedThreshold = 50
const scheduledCount = computed<number>(
  () => r.list.value.filter((d) => d.enabled && d.schedule?.enabled).length,
)
const crowdedHint = computed<string>(() => {
  if (r.list.value.length < crowdedThreshold) return ''
  return t('wol.manyDevices', { total: r.list.value.length, scheduled: scheduledCount.value })
})

// 候选网卡列表。只在打开编辑弹窗时拉一次（后端有 30 秒缓存，重复请求也不会每次去问内核要全表）。
const ifaces = ref<WOLInterface[]>([])
const ifacesLoaded = ref(false)
async function loadIfaces() {
  try {
    ifaces.value = await actions.wolInterfaces()
  } catch {
    // 拿不到列表不影响保存：下拉框允许自由输入，留空即自动。
    ifaces.value = []
  }
  ifacesLoaded.value = true
}

// 「自动」模式实际会用到的网卡。把它摆到界面上是这个提示存在的理由：
// 用户看得见「会从这几张发出」，才可能发现「怎么还会从 docker0 发出」；
// 一张都没有时（VPS 只有公网网卡、或纯容器宿主机只剩网桥）后端会拒绝发送，
// 这里提前把话说清楚，免得用户等到点唤醒才撞上报错。
const autoIfaces = computed<WOLInterface[]>(() => ifaces.value.filter((i) => i.auto))
const autoHint = computed<string>(() => {
  if (!ifacesLoaded.value) return ''
  if (!ifaces.value.length) return t('wol.ifaceNoneFound')
  if (!autoIfaces.value.length) return t('wol.ifaceNoAuto')
  return t('wol.ifaceAutoUses', {
    list: autoIfaces.value.map((i) => `${i.name} (${i.ip})`).join('、'),
  })
})

// 下拉项的副标题：地址 + 为什么它不在自动集合里。
function ifaceTag(i: WOLInterface): string {
  const tags: string[] = []
  if (i.virtual) tags.push(t('wol.ifaceVirtual'))
  if (i.public) tags.push(t('wol.ifacePublic'))
  if (i.auto) tags.push(t('wol.ifaceAuto'))
  return tags.join(' · ')
}

// 当前编辑对象的定时设置，供模板与下方计算属性复用。
const sch = computed<Schedule>(() => (r.editing.value as Device).schedule)
const scheduleDates = computed<[string, string] | []>({
  get: (): [string, string] | [] => {
    const s = sch.value
    return s.startDate && s.endDate ? [s.startDate, s.endDate] : []
  },
  set: (value: [string, string] | []) => {
    const s = sch.value
    s.startDate = value?.[0] || ''
    s.endDate = value?.[1] || ''
  },
})

// "HH:MM" → 当日零点起的秒数；非法返回 null。
function hmToSec(s: string): number | null {
  const m = /^\s*(\d{1,2})\s*:\s*(\d{1,2})\s*$/.exec(s || '')
  if (!m) return null
  const h = Number(m[1])
  const mi = Number(m[2])
  if (h > 23 || mi > 59) return null
  return h * 3600 + mi * 60
}

// 时间范围模式当天的发送次数。与后端节拍循环同一口径：从开始时间起每 intervalSec 一拍，
// 直到超过结束时间为止，开始时间本身算第一拍；结束不晚于开始时退化为 1 次。
// 之所以要把这个数摆到界面上：间隔从 60 改成 5 只是一个字符的差别，发包量却是 12 倍，
// 光看「每 5 秒一次」很难对一天的广播量有感觉。
const rangeTicks = computed<number>(() => {
  const s = sch.value
  const start = hmToSec(s.start)
  const end = hmToSec(s.end)
  if (start === null || end === null) return 0
  if (end <= start) return 1
  const iv = Math.max(1, Math.floor(s.intervalSec || 0))
  return Math.floor((end - start) / iv) + 1
})

// 结束时间不晚于开始时间：后端退化为「只在开始时间发一次」，这里明确提示，
// 免得用户以为整段设置没生效。
const rangeEndBeforeStart = computed<boolean>(() => {
  const start = hmToSec(sch.value.start)
  const end = hmToSec(sch.value.end)
  return start !== null && end !== null && end <= start
})

// 切换触发方式时补齐该方式必需的字段。
// 「时间范围」模式保存时后端会把发包次数归零（该方式不使用它，见 normalizeWOL），
// 因此切回「固定时间」必须补回 1，否则输入框显示 0——一个既无意义也保存不出去的值。
function onModeChange() {
  const s = sch.value
  if (s.mode === 'range') {
    if (!(s.intervalSec >= 1)) s.intervalSec = 5
  } else if (!(s.count >= 1)) {
    s.count = 1
  }
}

// 打开编辑：把历史数据里缺失/越界的定时字段补成表单能正常显示的值。
// 编辑对象是列表行的深拷贝（见 useResource.openEdit），改它不影响列表展示。
function openEditDevice(row: Device) {
  r.openEdit(row)
  const d = r.editing.value as Device
  if (typeof d.interface !== 'string') d.interface = ''
  // 手改 config.json 或极旧的备份里可能整段缺失 schedule，补一份默认值兜住模板取值。
  if (!d.schedule) d.schedule = empty().schedule
  const s = d.schedule
  if (s.mode !== 'range') s.mode = 'fixed'
  if (typeof s.calendarEnabled !== 'boolean') s.calendarEnabled = false
  if (!s.startDate) s.startDate = ''
  if (!s.endDate) s.endDate = ''
  if (!s.time) s.time = '08:00'
  if (!s.start) s.start = '08:00'
  if (!s.end) s.end = '18:00'
  onModeChange()
  void loadIfaces()
}

function openCreateDevice() {
  r.openCreate()
  void loadIfaces()
}

function scheduleText(d: Device): string {
  const s = d.schedule
  if (!s || !s.enabled) return t('wol.scheduleOff')
  if (s.mode === 'range') {
    return t('wol.listRange', { start: s.start, end: s.end, sec: Math.max(1, s.intervalSec || 1) })
  }
  return t('wol.listFixed', { time: s.time, count: Math.max(1, s.count || 1) })
}

async function wake(row: Device) {
  const loading = ElMessage({ message: t('wol.waking'), type: 'info', duration: 0 })
  try {
    const res = await actions.wake(row.id!)
    loading.close()
    ElMessage.success(res.result || t('msg.wakeSent'))
    await r.load({ silent: true })
  } catch (e: any) {
    loading.close()
    await r.load({ silent: true })
    ElMessage.error(e?.message || t('common.failed'))
  }
}

let refreshTimer: ReturnType<typeof setInterval> | undefined
function startRefresh() {
  if (refreshTimer) return
  refreshTimer = setInterval(() => r.load({ silent: true }), 3000)
}
function stopRefresh() {
  if (!refreshTimer) return
  clearInterval(refreshTimer)
  refreshTimer = undefined
}

onActivated(() => {
  void r.load()
  startRefresh()
})
onDeactivated(stopRefresh)
onBeforeUnmount(stopRefresh)
</script>

<template>
  <PageCard :title="t('wol.title')" :subtitle="t('wol.subtitle')" :max-count="r.maxCount.value">
    <template #actions>
      <el-button type="primary" :icon="Plus" @click="openCreateDevice()">{{ t('common.add') }}</el-button>
    </template>

    <el-alert v-if="crowdedHint" type="warning" :closable="false" show-icon class="crowd-hint">
      {{ crowdedHint }}
    </el-alert>

    <el-table :data="r.list.value" v-loading="r.loading.value" stripe row-key="id">
      <el-table-column :label="t('common.status')" width="80">
        <template #default="{ row }">
          <el-switch v-model="row.enabled" @change="r.toggle(row, t('common.saveFailed'))" />
        </template>
      </el-table-column>
      <el-table-column :label="t('wol.devName')" min-width="110">
        <template #default="{ row }"><strong>{{ row.name || t('common.unnamed') }}</strong></template>
      </el-table-column>
      <el-table-column prop="mac" :label="t('wol.mac')" min-width="130" />
      <el-table-column :label="t('wol.schedule')" min-width="110">
        <template #default="{ row }"><span class="mt-subtle">{{ scheduleText(row) }}</span></template>
      </el-table-column>
      <!-- 唤醒次数与结果并进「最近唤醒」这一格（与消息路由的接收器列表同一种写法）：
           三列各占一份宽度会把列宽之和顶出一屏，那时 el-table 只能横向滚，
           最右边的「删除」得先滚才点得到；这两项本来也是看完时间之后才关心的次要信息。 -->
      <el-table-column :label="t('wol.lastWake')" min-width="180">
        <template #default="{ row }">
          <div class="mt-cell-2row">
            <div>{{ fmtTime(row.lastWakeAt) }}</div>
            <div class="mt-subtle tiny" :title="row.lastResult || ''">
              {{ t('wol.wakeCount') }} {{ row.wakeCount || 0 }}
              <template v-if="row.lastResult"> · {{ row.lastResult }}</template>
            </div>
          </div>
        </template>
      </el-table-column>
      <!-- 备注紧挨「操作」左边（全站列表统一这个位置）。 -->
      <el-table-column :label="t('wol.note')" min-width="100" show-overflow-tooltip>
        <template #default="{ row }"><span class="mt-subtle">{{ row.note || '—' }}</span></template>
      </el-table-column>
      <el-table-column :label="t('common.actions')" width="180" align="right">
        <template #default="{ row }">
          <el-button size="small" type="primary" @click="wake(row)">{{ t('wol.wake') }}</el-button>
          <el-button size="small" @click="openEditDevice(row)">{{ t('common.edit') }}</el-button>
          <el-button size="small" type="danger" text @click="r.remove(row, t('common.confirmDelete'))">
            {{ t('common.delete') }}
          </el-button>
        </template>
      </el-table-column>
    </el-table>

    <el-dialog v-model="r.dialogVisible.value" :title="r.isNew.value ? t('common.add') : t('common.edit')" width="min(520px, 94vw)" append-to-body :close-on-click-modal="false">
      <el-form label-position="top">
        <el-form-item :label="t('wol.devName')">
          <el-input v-model="(r.editing.value as Device).name" />
        </el-form-item>
        <el-form-item :label="t('common.status')">
          <el-switch v-model="(r.editing.value as Device).enabled" />
        </el-form-item>
        <el-form-item :label="t('wol.mac')">
          <el-input v-model="(r.editing.value as Device).mac" placeholder="AA:BB:CC:DD:EE:FF" />
          <span class="field-hint">{{ t('wol.macHint') }}</span>
        </el-form-item>
        <el-form-item :label="t('wol.broadcast')">
          <el-input
            v-model="(r.editing.value as Device).broadcast"
            placeholder="192.168.1.255 / 192.168.1.100"
          />
          <span class="field-hint">{{ t('wol.broadcastHint') }}</span>
        </el-form-item>
        <el-form-item :label="t('wol.port')">
          <el-input-number v-model="(r.editing.value as Device).port" :min="1" :max="65535" style="width: 100%" />
        </el-form-item>
        <!-- 网卡：留空 = 自动（只用内网物理网卡）。allow-create + filterable 保留手工输入，
             因为配置可能是从别的主机导入的，那台机器的网卡名在本机列表里并不存在。 -->
        <el-form-item :label="t('wol.iface')">
          <el-select
            v-model="(r.editing.value as Device).interface"
            filterable
            allow-create
            default-first-option
            clearable
            :placeholder="t('wol.ifaceAutoOption')"
            style="width: 100%"
          >
            <el-option :label="t('wol.ifaceAutoOption')" value="" />
            <el-option v-for="i in ifaces" :key="i.name + i.ip" :label="i.name" :value="i.name">
              <span>{{ i.name }}</span>
              <span class="opt-tag">{{ i.ip }}<template v-if="ifaceTag(i)"> · {{ ifaceTag(i) }}</template></span>
            </el-option>
          </el-select>
          <span class="field-hint">{{ t('wol.ifaceHint') }}</span>
          <span v-if="autoHint" class="field-hint" :class="{ 'sch-warn': ifacesLoaded && !autoIfaces.length }">
            {{ autoHint }}
          </span>
        </el-form-item>
        <el-form-item :label="t('wol.note')">
          <el-input v-model="(r.editing.value as Device).note" type="textarea" :rows="2" />
        </el-form-item>

        <el-divider content-position="left">{{ t('wol.schedule') }}</el-divider>
        <el-form-item :label="t('wol.scheduleEnabled')">
          <el-switch v-model="(r.editing.value as Device).schedule.enabled" />
        </el-form-item>

        <template v-if="(r.editing.value as Device).schedule.enabled">
          <el-form-item :label="t('wol.calendarEnabled')">
            <el-switch v-model="(r.editing.value as Device).schedule.calendarEnabled" />
          </el-form-item>
          <el-form-item v-if="(r.editing.value as Device).schedule.calendarEnabled" :label="t('wol.calendar')">
            <el-date-picker
              v-model="scheduleDates"
              type="daterange"
              value-format="YYYY-MM-DD"
              :range-separator="t('wol.calendarTo')"
              :start-placeholder="t('wol.calendarStart')"
              :end-placeholder="t('wol.calendarEnd')"
              style="width: 100%"
            />
          </el-form-item>
          <el-form-item :label="t('wol.mode')">
            <el-radio-group v-model="(r.editing.value as Device).schedule.mode" @change="onModeChange">
              <el-radio-button value="fixed">{{ t('wol.modeFixed') }}</el-radio-button>
              <el-radio-button value="range">{{ t('wol.modeRange') }}</el-radio-button>
            </el-radio-group>
          </el-form-item>

          <!-- 固定时间：时间 + 一秒内的发包次数。该方式不使用发送间隔，故不展示。 -->
          <template v-if="(r.editing.value as Device).schedule.mode === 'fixed'">
            <div class="grid2">
              <el-form-item :label="t('wol.time')">
                <el-time-picker
                  v-model="(r.editing.value as Device).schedule.time"
                  format="HH:mm"
                  value-format="HH:mm"
                  style="width: 100%"
                />
              </el-form-item>
              <el-form-item :label="t('wol.count')">
                <el-input-number
                  v-model="(r.editing.value as Device).schedule.count"
                  :min="1"
                  :max="100"
                  style="width: 100%"
                />
              </el-form-item>
            </div>
            <p class="mt-subtle sch-hint">{{ t('wol.hintFixed') }}</p>
          </template>

          <!-- 时间范围：起止时间 + 发送间隔。该方式不使用发送次数，故不展示。 -->
          <template v-else>
            <div class="grid2">
              <el-form-item :label="t('wol.start')">
                <el-time-picker
                  v-model="(r.editing.value as Device).schedule.start"
                  format="HH:mm"
                  value-format="HH:mm"
                  style="width: 100%"
                />
              </el-form-item>
              <el-form-item :label="t('wol.end')">
                <el-time-picker
                  v-model="(r.editing.value as Device).schedule.end"
                  format="HH:mm"
                  value-format="HH:mm"
                  style="width: 100%"
                />
              </el-form-item>
            </div>
            <el-form-item :label="t('wol.interval')">
              <el-input-number
                v-model="(r.editing.value as Device).schedule.intervalSec"
                :min="1"
                :max="86400"
                style="width: 100%"
              />
            </el-form-item>
            <p class="mt-subtle sch-hint">{{ t('wol.hintRange') }}</p>
            <p v-if="rangeEndBeforeStart" class="mt-subtle sch-hint">{{ t('wol.rangeEndBeforeStart') }}</p>
            <p v-else-if="rangeTicks > 0" class="mt-subtle sch-hint">
              {{
                t('wol.rangePreview', {
                  start: (r.editing.value as Device).schedule.start,
                  end: (r.editing.value as Device).schedule.end,
                  n: rangeTicks,
                })
              }}
            </p>
            <p v-if="!rangeEndBeforeStart && (r.editing.value as Device).schedule.intervalSec < 30" class="sch-hint sch-warn">
              {{ t('wol.rangePreviewDense') }}
            </p>
          </template>
        </template>
      </el-form>
      <template #footer>
        <el-button @click="r.dialogVisible.value = false">{{ t('common.cancel') }}</el-button>
        <el-button type="primary" :loading="r.saving.value" @click="r.save()">{{ t('common.save') }}</el-button>
      </template>
    </el-dialog>
  </PageCard>
</template>

<style scoped>
.tiny {
  font-size: 12px;
  line-height: 1.5;
}
.grid2 {
  display: grid;
  grid-template-columns: minmax(0, 1fr) minmax(0, 1fr);
  gap: 0 16px;
}
.sch-hint {
  font-size: 12px;
  line-height: 1.5;
  margin: -4px 0 8px;
}
/* 间隔过小的量级提醒：不阻塞保存，只把后果说清楚。 */
.sch-warn {
  color: var(--el-color-warning);
}
.field-hint {
  display: block;
  margin-top: 4px;
  font-size: 12px;
  line-height: 1.5;
  color: var(--mt-text-subtle, #909399);
}
/* 下拉项右侧的地址与分类标记（虚拟 / 公网 / 自动会用到）。 */
.opt-tag {
  float: right;
  margin-left: 16px;
  font-size: 12px;
  color: var(--mt-text-subtle, #909399);
}
.crowd-hint {
  margin-bottom: 12px;
}

/* 窄屏：每栏不足 240 像素时，MAC 与网卡那两个框装不下一整串，改成一栏。 */
@media (max-width: 560px) {
  .grid2 {
    grid-template-columns: minmax(0, 1fr);
  }
}
</style>
