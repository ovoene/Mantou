<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import { Plus, Delete } from '@element-plus/icons-vue'
import TagInput from '@/components/TagInput.vue'
import type { NotifyTarget, WebhookMeta } from '@/api/webhook'

// 通知目标编辑器：钉钉 / 企业微信 / 自定义 HTTP。
//
// 「测试发送」刻意不放在这里，只放在列表行上：测试打的是**已保存**的配置，
// 放在编辑弹窗里会让用户以为测的是刚改还没保存的那份。

const props = defineProps<{
  visible: boolean
  model: NotifyTarget
  isNew: boolean
  saving: boolean
  meta: WebhookMeta | null
}>()
const emit = defineEmits<{
  (e: 'update:visible', v: boolean): void
  (e: 'save'): void
}>()

const { t } = useI18n()

// 上限一律取后端下发的那份（/api/webhook/meta），前端不另存一套数字：
// 抄一遍就有两份，改了一边忘了另一边的话，界面上让你加、保存时被拒。
// 后面的 || 只是 meta 还没拉回来时的兜底，取的是后端同名常量的当前值。
const limits = computed(() => props.meta?.limits || {})
const maxHeaders = computed(() => limits.value.headers || 20)
const headersFull = computed(() => headerRows.value.length >= maxHeaders.value)

// 请求头在配置里是 map，界面上要能改键名，因此用一个本地数组做中转。
const headerRows = ref<{ k: string; v: string }[]>([])
watch(
  () => props.visible,
  (open) => {
    if (open) {
      headerRows.value = Object.entries(props.model.headers || {}).map(([k, v]) => ({ k, v }))
    }
  },
  { immediate: true },
)
watch(
  headerRows,
  (rows) => {
    if (!props.visible) return
    const out: Record<string, string> = {}
    for (const r of rows) {
      const k = r.k.trim()
      if (k) out[k] = r.v
    }
    props.model.headers = out
  },
  { deep: true },
)

// 到上限就不再加。按钮那边也禁掉了，这里再挡一次是因为按钮不是唯一入口——
// 键名重复、空行都可能让行数与实际生效的头数不一致（见下面的 watch：空键名不进配置）。
function addHeader() {
  if (headersFull.value) return
  headerRows.value.push({ k: '', v: '' })
}
function removeHeader(i: number) {
  headerRows.value.splice(i, 1)
}

function typeLabel(tp: string): string {
  const key = `mroute.target.type.${tp}`
  const s = t(key)
  return s === key ? tp : s
}

const urlPlaceholder: Record<string, string> = {
  dingtalk: 'https://oapi.dingtalk.com/robot/send?access_token=…',
  wecom: 'https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=…',
  http: 'https://example.com/notify',
}

// 提示文案里要出现模板写法本身。放在 script 里作为参数传进 t()：
// 直接写在模板的 {{ }} 插值里，里面那对花括号会被 Vue 当成插值结束。
const msgJSONExpr = '{{.messageJSON}}'
</script>

<template>
  <el-dialog
    :model-value="visible"
    :title="isNew ? t('mroute.target.add') : t('mroute.target.edit')"
    width="min(620px, 94vw)"
    append-to-body
    :close-on-click-modal="false"
    @update:model-value="(v: boolean) => emit('update:visible', v)"
  >
    <el-form label-position="top">
      <div class="grid3">
        <el-form-item :label="t('common.name')">
          <el-input v-model="model.name" :placeholder="t('mroute.target.namePlaceholder')" />
        </el-form-item>
        <el-form-item :label="t('mroute.target.type.label')">
          <el-select v-model="model.type" style="width: 100%">
            <el-option
              v-for="tp in meta?.targetTypes || ['dingtalk', 'wecom', 'http']"
              :key="tp"
              :label="typeLabel(tp)"
              :value="tp"
            />
          </el-select>
        </el-form-item>
        <el-form-item :label="t('common.status')">
          <el-switch v-model="model.enabled" />
        </el-form-item>
      </div>

      <el-form-item :label="t('mroute.target.url')">
        <el-input v-model="model.url" :placeholder="urlPlaceholder[model.type] || ''" autocomplete="off" />
        <div class="mt-subtle hint">{{ t('mroute.target.urlHint') }}</div>
      </el-form-item>

      <el-form-item v-if="model.type === 'dingtalk'" :label="t('mroute.target.secret')">
        <el-input v-model="model.secret" placeholder="SEC…" autocomplete="off" show-password />
        <div class="mt-subtle hint">{{ t('mroute.target.secretHint') }}</div>
      </el-form-item>

      <!-- 群机器人：@ 选项 -->
      <template v-if="model.type === 'dingtalk' || model.type === 'wecom'">
        <el-form-item :label="t('mroute.target.atMobiles')">
          <TagInput v-model="model.atMobiles" :placeholder="t('mroute.target.atMobilesPlaceholder')" />
          <div class="mt-subtle hint">{{ t('mroute.target.atMobilesHint') }}</div>
        </el-form-item>
        <el-form-item :label="t('mroute.target.atAll')">
          <el-switch v-model="model.atAll" />
        </el-form-item>
        <el-alert
          v-if="model.type === 'wecom'"
          type="info"
          :closable="false"
          :title="t('mroute.target.wecomAtNote')"
          class="tip-alert"
        />
      </template>

      <!-- 自定义 HTTP -->
      <template v-if="model.type === 'http'">
        <div class="grid2">
          <el-form-item :label="t('mroute.target.method')">
            <el-select v-model="model.method" style="width: 100%">
              <el-option label="POST" value="POST" />
              <el-option label="PUT" value="PUT" />
            </el-select>
          </el-form-item>
          <el-form-item :label="t('mroute.target.contentType')">
            <el-input v-model="model.contentType" placeholder="application/json" />
          </el-form-item>
        </div>

        <el-form-item :label="t('mroute.target.headers')">
          <div class="hdr-list">
            <div v-for="(h, i) in headerRows" :key="i" class="hdr-row">
              <el-input v-model="h.k" :placeholder="t('mroute.target.headerName')" />
              <el-input v-model="h.v" :placeholder="t('mroute.target.headerValue')" autocomplete="off" />
              <el-button :icon="Delete" text type="danger" @click="removeHeader(i)" />
            </div>
            <el-button size="small" :icon="Plus" :disabled="headersFull" @click="addHeader">
              {{ t('mroute.target.addHeader') }}
            </el-button>
          </div>
          <div class="mt-subtle hint">{{ t('mroute.target.headersHint', { n: maxHeaders }) }}</div>
        </el-form-item>

        <el-form-item :label="t('mroute.target.bodyTemplate')">
          <el-input
            v-model="model.bodyTemplate"
            type="textarea"
            :rows="5"
            class="mono"
            placeholder='{"content": {{.messageJSON}}}'
          />
          <div class="mt-subtle hint">{{ t('mroute.target.bodyTemplateHint', { expr: msgJSONExpr }) }}</div>
        </el-form-item>
      </template>

      <div class="grid2">
        <el-form-item :label="t('mroute.target.timeout')">
          <el-input-number
            v-model="model.timeoutSec"
            :min="1"
            :max="meta?.limits?.maxTimeout || 120"
            style="width: 100%"
          />
        </el-form-item>
        <el-form-item :label="t('mroute.target.retry')">
          <el-input-number v-model="model.retry" :min="0" :max="meta?.limits?.maxRetry || 10" style="width: 100%" />
        </el-form-item>
      </div>
      <div class="mt-subtle hint retry-hint">{{ t('mroute.target.retryHint') }}</div>

      <el-form-item :label="t('mroute.note')">
        <el-input v-model="model.note" :placeholder="t('mroute.target.notePlaceholder')" />
      </el-form-item>
    </el-form>

    <template #footer>
      <el-button @click="emit('update:visible', false)">{{ t('common.cancel') }}</el-button>
      <el-button type="primary" :loading="saving" @click="emit('save')">{{ t('common.save') }}</el-button>
    </template>
  </el-dialog>
</template>

<style scoped>
.grid2 {
  display: grid;
  grid-template-columns: minmax(0, 1fr) minmax(0, 1fr);
  gap: 0 16px;
}
.grid3 {
  display: grid;
  grid-template-columns: minmax(0, 1.4fr) minmax(0, 1fr) 90px;
  gap: 0 16px;
}
.hint {
  font-size: 12px;
  margin-top: 4px;
  line-height: 1.6;
}
.retry-hint {
  margin: -10px 0 14px;
}
.tip-alert {
  margin-bottom: 14px;
}
.hdr-list {
  width: 100%;
}
.hdr-row {
  display: grid;
  grid-template-columns: minmax(0, 1fr) minmax(0, 1.4fr) auto;
  gap: 8px;
  margin-bottom: 8px;
}
.mono :deep(textarea) {
  font-family: ui-monospace, Menlo, Consolas, monospace;
  font-size: 13px;
}
/* 窄屏两档。
 * 640：请求头那行（名字 / 值 / 删除）改成两行——名字独占一行，值与删除并排；
 * 三联排里有个定宽 90，一栏不足 200 像素时挤不下，也改成上下排。
 * 560：两联排改成一栏。 */
@media (max-width: 640px) {
  .grid3 {
    grid-template-columns: minmax(0, 1fr);
  }
  .hdr-row {
    grid-template-columns: minmax(0, 1fr) auto;
  }
  .hdr-row > :first-child {
    grid-column: 1 / -1;
  }
}
@media (max-width: 560px) {
  .grid2 {
    grid-template-columns: minmax(0, 1fr);
  }
}
</style>
