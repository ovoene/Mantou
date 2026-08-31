<script setup lang="ts">
import { computed, onActivated } from 'vue'
import { useI18n } from 'vue-i18n'
import { ElMessage } from 'element-plus'
import { Plus } from '@element-plus/icons-vue'
import PageCard from '@/components/PageCard.vue'
import RowActions from '@/components/RowActions.vue'
import { useNarrow } from '@/composables/useNarrow'
import { useResource } from '@/composables/useResource'
import { forwardsApi } from '@/api/resources'

const { t } = useI18n()

// 窄屏时操作列只剩一个「更多」按钮，列宽跟着收窄，省下的宽度留给前面几列。
const narrow = useNarrow()

interface Rule {
  id?: string
  name: string
  enabled: boolean
  protocol: string
  listenPort: number
  listenPortEnd: number
  targetHost: string
  targetPort: number
  sameTargetPort: boolean
  family: string
  bind?: string
  lastError?: string
}
function empty(): Rule {
  return {
    name: '',
    enabled: true,
    protocol: 'tcp',
    listenPort: 0,
    listenPortEnd: 0,
    targetHost: '',
    targetPort: 0,
    sameTargetPort: false,
    family: 'dual',
    bind: '',
  }
}
const r = useResource<Rule>('forwards', empty)

function familyLabel(f: string): string {
  if (f === 'v4') return t('forward.familyV4')
  if (f === 'v6') return t('forward.familyV6')
  return t('forward.familyDual')
}

// 端口范围开关：编辑态下 listenPortEnd > listenPort 视为已启用范围。
const rangeEnabled = computed<boolean>({
  get: () => {
    const e = r.editing.value as Rule
    return e.listenPortEnd > e.listenPort
  },
  set: (v: boolean) => {
    const e = r.editing.value as Rule
    e.listenPortEnd = v ? Math.max(e.listenPort + 1, e.listenPortEnd || e.listenPort + 1) : 0
  },
})

// 目标端口是否走「递增对应」：仅在成段（rangeEnabled）且未选多对一时成立。
// 决定目标端口标签（起始目标端口 vs 目标端口）与说明文案。
const targetIncrement = computed<boolean>(() => {
  return rangeEnabled.value && !(r.editing.value as Rule).sameTargetPort
})

// 列表中监听端口展示：范围时显示「起-止」。
function listenLabel(row: Rule): string {
  return row.listenPortEnd && row.listenPortEnd > row.listenPort
    ? `${row.listenPort}-${row.listenPortEnd}`
    : String(row.listenPort)
}

// 列表中目标展示：递增且成段时目标也是一段（起-止），其余显示单个目标端口。
// 与 listenLabel 对称——多对一显示单端口、递增显示端口段，两种映射方式在列表上从此可区分，
// 也顺带补上递增模式原先只显示目标起点、看不出目标其实是一段的缺口。
function targetLabel(row: Rule): string {
  if (row.listenPortEnd && row.listenPortEnd > row.listenPort && !row.sameTargetPort) {
    const end = Math.min(65535, row.targetPort + (row.listenPortEnd - row.listenPort))
    return `${row.targetHost}:${row.targetPort}-${end}`
  }
  return `${row.targetHost}:${row.targetPort}`
}

// 页面被激活（keep-alive 下首次挂载同样会触发一次）。每次进来都重新拉一遍，
// 缓存下来的列表可能在别处已经改过。
onActivated(() => r.load())

// 列表快捷启用/禁用：整体 PUT 该规则（启用状态变化会触发后端审计日志）。
async function toggleForward(row: Rule) {
  const prev = row.enabled
  try {
    await forwardsApi.update(row.id!, { ...row })
  } catch (e: any) {
    row.enabled = prev
    ElMessage.error(e?.message || t('common.saveFailed'))
  }
}
</script>

<template>
  <PageCard :title="t('forward.title')" :subtitle="t('forward.subtitle')" :max-count="r.maxCount.value">
    <template #actions>
      <el-button type="primary" :icon="Plus" @click="r.openCreate()">{{ t('common.add') }}</el-button>
    </template>

    <el-table :data="r.list.value" v-loading="r.loading.value" stripe row-key="id">
      <el-table-column :label="t('common.status')" width="110">
        <template #default="{ row }">
          <div class="status-cell">
            <el-switch v-model="row.enabled" @change="toggleForward(row)" />
            <el-tooltip v-if="row.lastError" :content="row.lastError" placement="top">
              <span class="err-dot">!</span>
            </el-tooltip>
          </div>
        </template>
      </el-table-column>
      <el-table-column :label="t('common.name')" min-width="130">
        <template #default="{ row }"><strong>{{ row.name || t('common.unnamed') }}</strong></template>
      </el-table-column>
      <el-table-column :label="t('forward.protocol')" width="100">
        <template #default="{ row }">{{ row.protocol === 'both' ? 'TCP+UDP' : row.protocol.toUpperCase() }}</template>
      </el-table-column>
      <el-table-column :label="t('forward.listenPort')" width="110" align="center">
        <template #default="{ row }">{{ listenLabel(row) }}</template>
      </el-table-column>
      <el-table-column :label="t('forward.targetHost')" min-width="180">
        <template #default="{ row }">
          <span class="mt-subtle">{{ targetLabel(row) }}</span>
        </template>
      </el-table-column>
      <el-table-column :label="t('forward.family')" width="100">
        <template #default="{ row }">{{ familyLabel(row.family) }}</template>
      </el-table-column>
      <el-table-column :label="t('forward.runStatus')" min-width="120">
        <template #default="{ row }">
          <el-tag v-if="row.lastError" type="danger" size="small" effect="light">{{ t('forward.lastError') }}</el-tag>
          <el-tag v-else type="success" size="small" effect="light">{{ t('forward.normal') }}</el-tag>
        </template>
      </el-table-column>
      <el-table-column :label="t('common.actions')" :width="narrow ? 90 : 150" align="right">
        <template #default="{ row }">
          <RowActions>
            <el-button size="small" @click="r.openEdit(row)">{{ t('common.edit') }}</el-button>
            <el-button size="small" type="danger" text @click="r.remove(row, t('common.confirmDelete'))">
              {{ t('common.delete') }}
            </el-button>
          </RowActions>
        </template>
      </el-table-column>
    </el-table>

    <el-dialog v-model="r.dialogVisible.value" :title="r.isNew.value ? t('common.add') : t('common.edit')" width="min(520px, 94vw)" append-to-body :close-on-click-modal="false">
      <el-form label-position="top">
        <div class="grid2">
          <el-form-item :label="t('forward.ruleName')">
            <el-input v-model="(r.editing.value as Rule).name" />
          </el-form-item>
          <el-form-item :label="t('common.status')">
            <el-switch v-model="(r.editing.value as Rule).enabled" />
          </el-form-item>
          <el-form-item :label="t('forward.protocol')">
            <el-select v-model="(r.editing.value as Rule).protocol" style="width: 100%">
              <el-option label="TCP" value="tcp" />
              <el-option label="UDP" value="udp" />
              <el-option label="TCP + UDP" value="both" />
            </el-select>
          </el-form-item>
          <el-form-item :label="t('forward.family')">
            <el-select v-model="(r.editing.value as Rule).family" style="width: 100%">
              <el-option :label="t('forward.familyDual')" value="dual" />
              <el-option :label="t('forward.familyV4')" value="v4" />
              <el-option :label="t('forward.familyV6')" value="v6" />
            </el-select>
          </el-form-item>
          <el-form-item :label="t('forward.bind')">
            <el-input v-model="(r.editing.value as Rule).bind" :placeholder="t('forward.bindHint')" />
          </el-form-item>
        </div>

        <el-divider content-position="left">{{ t('forward.listenPort') }} → {{ t('forward.targetHost') }}</el-divider>

        <el-form-item :label="t('forward.enableRange')">
          <el-switch v-model="rangeEnabled" />
        </el-form-item>

        <div v-if="rangeEnabled" class="grid2">
          <el-form-item :label="t('forward.listenPortStart')">
            <el-input-number v-model="(r.editing.value as Rule).listenPort" :min="1" :max="65535" style="width: 100%" />
          </el-form-item>
          <el-form-item :label="t('forward.listenPortEnd')">
            <el-input-number v-model="(r.editing.value as Rule).listenPortEnd" :min="1" :max="65535" style="width: 100%" />
          </el-form-item>
        </div>
        <el-form-item v-else :label="t('forward.listenPort')">
          <el-input-number v-model="(r.editing.value as Rule).listenPort" :min="1" :max="65535" style="width: 100%" />
        </el-form-item>

        <!-- 目标端口映射：仅端口范围下有意义。递增对应=按偏移逐个映射；多对一=全部落到同一个目标端口。 -->
        <template v-if="rangeEnabled">
          <el-form-item :label="t('forward.targetMode')">
            <el-radio-group v-model="(r.editing.value as Rule).sameTargetPort">
              <el-radio-button :value="false">{{ t('forward.targetModeIncrement') }}</el-radio-button>
              <el-radio-button :value="true">{{ t('forward.targetModeSame') }}</el-radio-button>
            </el-radio-group>
          </el-form-item>
          <p class="mt-subtle range-hint">{{ targetIncrement ? t('forward.rangeHint') : t('forward.rangeHintSame') }}</p>
        </template>

        <div class="grid2">
          <el-form-item :label="t('forward.targetHost')">
            <el-input v-model="(r.editing.value as Rule).targetHost" :placeholder="t('forward.targetHint')" />
          </el-form-item>
          <el-form-item :label="targetIncrement ? t('forward.targetPortStart') : t('forward.targetPort')">
            <el-input-number v-model="(r.editing.value as Rule).targetPort" :min="1" :max="65535" style="width: 100%" />
          </el-form-item>
        </div>
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
.status-cell {
  display: flex;
  align-items: center;
  gap: 6px;
}
.err-dot {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  width: 16px;
  height: 16px;
  border-radius: 50%;
  background: var(--el-color-danger);
  color: #fff;
  font-size: 11px;
  font-weight: 700;
  cursor: help;
}
.range-hint {
  font-size: 12px;
  margin: -4px 0 4px;
}

/* 窄屏：每栏不足 240 像素时，端口那几个数字框按不到 +/-，中文标签也要折两行。 */
@media (max-width: 560px) {
  .grid2 {
    grid-template-columns: minmax(0, 1fr);
  }
}
</style>
