<script setup lang="ts">
import { onActivated, ref, computed } from 'vue'
import { useI18n } from 'vue-i18n'
import { ElMessage } from 'element-plus'
import { Plus } from '@element-plus/icons-vue'
import PageCard from '@/components/PageCard.vue'
import RowActions from '@/components/RowActions.vue'
import { useNarrow } from '@/composables/useNarrow'
import { useResource } from '@/composables/useResource'
import { actions, type ProviderInfo } from '@/api/resources'

const { t, te } = useI18n()

// 窄屏时操作列只剩一个「更多」按钮，列宽跟着收窄，省下的宽度留给前面几列。
const narrow = useNarrow()

interface Credential {
  id?: string
  name: string
  provider: string
  secrets: Record<string, string>
}
function empty(): Credential {
  return { name: '', provider: '', secrets: {} }
}
const r = useResource<Credential>('credentials', empty)

// 服务商元信息（含各家所需的凭证字段），用于动态渲染表单。
const providers = ref<ProviderInfo[]>([])
async function loadProviders() {
  try {
    const res = await actions.providers()
    providers.value = res.dns || []
  } catch (e: any) {
    ElMessage.error(e?.message || t('common.failed'))
  }
}

// 当前编辑对象选中的服务商字段定义。
const currentFields = computed(() => {
  const p = providers.value.find((x) => x.name === (r.editing.value as Credential).provider)
  return p?.fields || []
})

// 服务商标识 → 展示名（i18n，找不到就回退原始标识）。
function providerLabel(name: string): string {
  const key = `cred.providerName.${name}`
  return te(key) ? t(key) : name
}
// 字段键 → 展示名（i18n，找不到就回退键名）。
function fieldLabel(key: string): string {
  const k = `cred.fieldLabel.${key}`
  return te(k) ? t(k) : key
}

// 切换服务商时，重置 secrets 只保留新服务商需要的键。
function onProviderChange() {
  const c = r.editing.value as Credential
  const next: Record<string, string> = {}
  for (const f of currentFields.value) next[f.key] = c.secrets?.[f.key] || ''
  c.secrets = next
}

// 列表里展示某服务商需要哪些字段的摘要。
function fieldSummary(row: Credential): string {
  const p = providers.value.find((x) => x.name === row.provider)
  if (!p) return '—'
  return p.fields.map((f) => fieldLabel(f.key)).join(' · ')
}

// 页面被激活（keep-alive 下首次挂载同样会触发一次）。两个请求本来就是并发发出的，
// 保持原样。
onActivated(() => {
  loadProviders()
  r.load()
})
</script>

<template>
  <PageCard :title="t('cred.title')" :subtitle="t('cred.subtitle')">
    <template #actions>
      <el-button type="primary" :icon="Plus" @click="r.openCreate()">{{ t('common.add') }}</el-button>
    </template>

    <el-empty v-if="!r.loading.value && r.list.value.length === 0" :description="t('cred.emptyHint')" />

    <el-table v-else :data="r.list.value" v-loading="r.loading.value" stripe row-key="id">
      <el-table-column :label="t('cred.credName')" min-width="160">
        <template #default="{ row }"><strong>{{ row.name || t('common.unnamed') }}</strong></template>
      </el-table-column>
      <el-table-column :label="t('cred.provider')" min-width="140">
        <template #default="{ row }">{{ providerLabel(row.provider) }}</template>
      </el-table-column>
      <el-table-column :label="t('cred.fields')" min-width="220">
        <template #default="{ row }"><span class="mt-subtle">{{ fieldSummary(row) }}</span></template>
      </el-table-column>
      <el-table-column :label="t('common.actions')" :width="narrow ? 90 : 180" align="right">
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

    <el-dialog
      v-model="r.dialogVisible.value"
      :title="r.isNew.value ? t('common.add') : t('common.edit')"
      width="min(480px, 94vw)"
      append-to-body
      :close-on-click-modal="false"
    >
      <el-form label-position="top">
        <el-form-item :label="t('cred.credName')">
          <el-input v-model="(r.editing.value as Credential).name" />
        </el-form-item>
        <el-form-item :label="t('cred.provider')">
          <el-select
            v-model="(r.editing.value as Credential).provider"
            style="width: 100%"
            @change="onProviderChange"
          >
            <el-option
              v-for="p in providers"
              :key="p.name"
              :value="p.name"
              :label="providerLabel(p.name)"
            />
          </el-select>
        </el-form-item>

        <template v-if="currentFields.length">
          <el-divider content-position="left">{{ t('cred.fields') }}</el-divider>
          <el-form-item
            v-for="f in currentFields"
            :key="f.key"
            :label="fieldLabel(f.key)"
            :required="f.required"
          >
            <el-input
              v-model="(r.editing.value as Credential).secrets[f.key]"
              :type="f.secret ? 'password' : 'text'"
              :show-password="f.secret"
              autocomplete="off"
            />
          </el-form-item>
        </template>
      </el-form>
      <template #footer>
        <el-button @click="r.dialogVisible.value = false">{{ t('common.cancel') }}</el-button>
        <el-button type="primary" :loading="r.saving.value" @click="r.save()">{{ t('common.save') }}</el-button>
      </template>
    </el-dialog>
  </PageCard>
</template>
