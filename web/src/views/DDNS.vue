<script setup lang="ts">
import { onActivated, ref, computed } from 'vue'
import { useI18n } from 'vue-i18n'
import { ElMessage } from 'element-plus'
import { Plus, Delete } from '@element-plus/icons-vue'
import PageCard from '@/components/PageCard.vue'
import TagInput from '@/components/TagInput.vue'
import { useResource } from '@/composables/useResource'
import { actions, credentialsApi, ddnsApi } from '@/api/resources'

const { t } = useI18n()

interface Target {
  credentialRef: string
  provider: string
  domain: string
  subdomains: string[]
  allowRoot: boolean
  recordType: string
  ttl: number
  line: string
}
interface Rule {
  id?: string
  name: string
  enabled: boolean
  stack: string
  source: { type: string; iface: string; url: string; regex: string }
  intervalSec: number
  targets: Target[]
  lastIP?: string
  lastStatus?: string
  lastUpdateAt?: number
}

function empty(): Rule {
  return {
    name: '',
    enabled: true,
    stack: 'ipv4',
    source: { type: 'public', iface: '', url: 'https://api.ipify.org', regex: '' },
    intervalSec: 600,
    targets: [],
  }
}

const r = useResource<Rule>('ddns', empty)
const credentials = ref<{ id: string; name: string; provider: string }[]>([])

// 是否暴露校验红框：默认 false，仅当用户点击保存且校验未通过时才显示，
// 避免打开弹窗时（空表单）默认全红。
const revealErrors = ref(false)

// 归一化一个目标：兼容旧配置（subdomains 可能为 null），并补齐 allowRoot。
function normalizeTarget(tg: any): Target {
  return {
    credentialRef: tg.credentialRef || '',
    provider: tg.provider || '',
    domain: tg.domain || '',
    subdomains: Array.isArray(tg.subdomains) ? tg.subdomains : [],
    allowRoot: !!tg.allowRoot,
    recordType: tg.recordType || '',
    ttl: typeof tg.ttl === 'number' ? tg.ttl : 0,
    line: tg.line || '',
  }
}

// 打开编辑：在通用 openEdit 基础上归一化各目标，避免 null 破坏多标签输入。
function openEditRule(row: Rule) {
  r.openEdit(row)
  const rule = r.editing.value as Rule
  rule.targets = (rule.targets || []).map(normalizeTarget)
  revealErrors.value = false
}

// 打开新增：重置校验红框。
function openCreateRule() {
  r.openCreate()
  revealErrors.value = false
}

function addTarget() {
  ;(r.editing.value as Rule).targets.push({
    credentialRef: '',
    provider: '',
    domain: '',
    subdomains: [],
    allowRoot: false,
    recordType: '',
    ttl: 0,
    line: '',
  })
}
function removeTarget(i: number) {
  ;(r.editing.value as Rule).targets.splice(i, 1)
}

// 自动 TTL 提示文案：根据目标所属服务商区分语义。
// Cloudflare 的 TTL=1 即 API 约定的"自动"（按流量动态调整）；
// 其余服务商（阿里/腾讯/百度/GoDaddy）无自适应 TTL，TTL<=0 时回退到其允许的最小 TTL（约 600 秒）。
function ttlAutoHint(tg: Target): string {
  const provider =
    credentials.value.find((c) => c.id === tg.credentialRef)?.provider || tg.provider
  if (provider === 'cloudflare') return t('ddns.ttlAutoHintCloudflare')
  return t('ddns.ttlAutoHintOther')
}

// 单条目标是否合法：域名服务商（凭证）与 主域名 必填，且需至少配置一个主机记录或允许根域名。
function targetValid(tg: Target): boolean {
  return (
    (tg.credentialRef || '').trim() !== '' &&
    (tg.domain || '').trim() !== '' &&
    (tg.allowRoot || (tg.subdomains?.length ?? 0) > 0)
  )
}

// 整条规则是否可保存：至少一个目标且全部合法。
const formValid = computed(() => {
  const rule = r.editing.value as Rule
  const targets = rule.targets || []
  return targets.length > 0 && targets.every(targetValid)
})

// 保存前再次校验：未通过则暴露红框、提示并拦截提交。
async function onSave() {
  if (!formValid.value) {
    revealErrors.value = true
    ElMessage.warning(t('ddns.requiredHint'))
    return
  }
  await r.save()
}

async function runNow(row: Rule) {
  try {
    const res = await actions.runDdns(row.id!)
    ElMessage.success(res.result || t('msg.ddnsRun'))
    r.load()
  } catch (e: any) {
    ElMessage.error(e?.message || t('common.failed'))
  }
}

// 列表内联启用/停用：即时保存并触发后端热重载。
// 注意：后端 PUT 会整体覆盖该条规则，故必须传完整 row（而非仅 {enabled}），
// 否则其余字段（域名/目标等）会被清空，表现为「禁用再启用后配置消失」。
async function toggleDdns(row: Rule) {
  const prev = row.enabled
  try {
    await ddnsApi.update(row.id!, { ...row })
  } catch (e: any) {
    row.enabled = prev
    ElMessage.error(e?.message || t('common.saveFailed'))
  }
}

// 将一条规则的多个目标拼成完整域名展示（如 home.example.com），根域名单独列出。
function domainText(rule: Rule): string {
  const parts: string[] = []
  for (const tg of rule.targets || []) {
    const domain = (tg.domain || '').trim()
    if (!domain) continue
    for (const sub of tg.subdomains || []) {
      const s = sub.trim()
      if (s && s !== '@') parts.push(`${s}.${domain}`)
    }
    if (tg.allowRoot) parts.push(domain)
  }
  return parts.length ? parts.join('、') : '—'
}

// 时间戳（秒）→ 年-月-日 时:分:秒。
function fmtDateTime(sec?: number): string {
  if (!sec) return '—'
  const d = new Date(sec * 1000)
  const p = (n: number) => (n < 10 ? '0' + n : '' + n)
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(
    d.getMinutes(),
  )}:${p(d.getSeconds())}`
}

// 页面被激活（keep-alive 下首次挂载也会触发一次，因此这里是唯一入口）。
// 规则列表与凭据列表互不依赖，并发拉取：串行等于白等两个往返，
// 而首屏在两者都回来之前都是空的，快的那个先到也帮不上忙。
onActivated(async () => {
  await Promise.all([
    r.load(),
    credentialsApi
      .list()
      .then((items) => {
        credentials.value = items as any
      })
      .catch(() => undefined) /* 凭据拉不到不影响规则列表展示（与原先的 try/catch 同义） */,
  ])
})
</script>

<template>
  <PageCard :title="t('ddns.title')" :subtitle="t('ddns.subtitle')" :max-count="r.maxCount.value">
    <template #actions>
      <el-button type="primary" :icon="Plus" @click="openCreateRule()">{{ t('common.add') }}</el-button>
    </template>

    <el-table :data="r.list.value" v-loading="r.loading.value" stripe row-key="id">
      <el-table-column :label="t('common.status')" width="90">
        <template #default="{ row }">
          <el-switch v-model="row.enabled" @change="toggleDdns(row)" />
        </template>
      </el-table-column>
      <el-table-column :label="t('common.name')" min-width="140">
        <template #default="{ row }">
          <strong>{{ row.name || t('common.unnamed') }}</strong>
        </template>
      </el-table-column>
      <el-table-column :label="t('ddns.stack')" width="90">
        <template #default="{ row }">{{ row.stack === 'ipv6' ? 'IPv6' : 'IPv4' }}</template>
      </el-table-column>
      <el-table-column :label="t('ddns.targets')" min-width="200">
        <template #default="{ row }"><span class="mt-subtle">{{ domainText(row) }}</span></template>
      </el-table-column>
      <el-table-column :label="t('ddns.lastIp')" min-width="130">
        <template #default="{ row }">{{ row.lastIP || '—' }}</template>
      </el-table-column>
      <el-table-column :label="t('ddns.lastStatus')" min-width="150">
        <template #default="{ row }"><span class="mt-subtle">{{ row.lastStatus || '—' }}</span></template>
      </el-table-column>
      <el-table-column :label="t('ddns.lastUpdateCol')" min-width="170">
        <template #default="{ row }"><span class="mt-subtle">{{ fmtDateTime(row.lastUpdateAt) }}</span></template>
      </el-table-column>
      <el-table-column :label="t('common.actions')" width="210" align="right">
        <template #default="{ row }">
          <el-button size="small" :disabled="!row.enabled" @click="runNow(row)">{{ t('ddns.runNow') }}</el-button>
          <el-button size="small" @click="openEditRule(row)">{{ t('common.edit') }}</el-button>
          <el-button size="small" type="danger" text @click="r.remove(row, t('common.confirmDelete'))">
            {{ t('common.delete') }}
          </el-button>
        </template>
      </el-table-column>
    </el-table>

    <el-dialog v-model="r.dialogVisible.value" :title="r.isNew.value ? t('common.add') : t('common.edit')" width="min(680px, 94vw)" append-to-body :close-on-click-modal="false">
      <el-form label-position="top">
        <div class="grid2">
          <el-form-item :label="t('ddns.ruleName')">
            <el-input v-model="(r.editing.value as Rule).name" />
          </el-form-item>
          <el-form-item :label="t('common.status')">
            <el-switch v-model="(r.editing.value as Rule).enabled" />
          </el-form-item>
          <el-form-item :label="t('ddns.stack')">
            <el-select v-model="(r.editing.value as Rule).stack" style="width: 100%">
              <el-option label="IPv4" value="ipv4" />
              <el-option label="IPv6" value="ipv6" />
            </el-select>
          </el-form-item>
          <el-form-item :label="t('ddns.interval')">
            <el-input-number v-model="(r.editing.value as Rule).intervalSec" :min="30" :step="30" style="width: 100%" />
          </el-form-item>
        </div>

        <el-divider content-position="left">{{ t('ddns.source') }}</el-divider>
        <div class="grid2">
          <el-form-item :label="t('ddns.source')">
            <el-select v-model="(r.editing.value as Rule).source.type" style="width: 100%">
              <el-option :label="t('ddns.sourceType.public')" value="public" />
              <el-option :label="t('ddns.sourceType.interface')" value="interface" />
              <el-option :label="t('ddns.sourceType.url')" value="url" />
            </el-select>
          </el-form-item>
          <el-form-item v-if="(r.editing.value as Rule).source.type === 'interface'" :label="t('ddns.iface')">
            <el-input v-model="(r.editing.value as Rule).source.iface" placeholder="eth0" />
          </el-form-item>
          <el-form-item v-if="(r.editing.value as Rule).source.type === 'url'" :label="t('ddns.url')">
            <el-input v-model="(r.editing.value as Rule).source.url" />
          </el-form-item>
          <el-form-item v-if="(r.editing.value as Rule).source.type === 'url'" :label="t('ddns.regex')">
            <el-input v-model="(r.editing.value as Rule).source.regex" :placeholder="t('common.optional')" />
          </el-form-item>
        </div>
        <p v-if="(r.editing.value as Rule).source.type === 'public'" class="mt-subtle cmd-hint">
          {{ t('ddns.publicHint') }}
        </p>

        <el-divider content-position="left">
          {{ t('ddns.targets') }}
          <el-button link type="primary" :icon="Plus" @click="addTarget">{{ t('ddns.addTarget') }}</el-button>
        </el-divider>

        <el-alert
          :title="t('ddns.subdomainExample')"
          type="info"
          :closable="false"
          show-icon
          style="margin-bottom: 12px"
        />

        <el-alert
          v-if="!credentials.length"
          :title="t('ddns.noCredential')"
          type="warning"
          :closable="false"
          show-icon
          style="margin-bottom: 12px"
        />

        <div v-for="(tg, i) in (r.editing.value as Rule).targets" :key="i" class="target-row mt-glass">
          <div class="target-grid">
            <el-form-item
              :label="t('ddns.credential')"
              class="cell"
              :class="{ 'field-error': revealErrors && !targetValid(tg) }"
            >
              <el-select v-model="tg.credentialRef" style="width: 100%">
                <el-option v-for="c in credentials" :key="c.id" :label="`${c.name} (${c.provider})`" :value="c.id" />
              </el-select>
            </el-form-item>
            <el-form-item
              :label="t('ddns.domain')"
              class="cell"
              :class="{ 'field-error': revealErrors && !targetValid(tg) }"
            >
              <el-input v-model="tg.domain" placeholder="example.com" style="width: 100%" />
            </el-form-item>
            <el-form-item :label="t('ddns.recordType')" class="cell-sm">
              <el-select v-model="tg.recordType" style="width: 100%">
                <el-option :label="t('common.none')" value="" />
                <el-option label="A" value="A" />
                <el-option label="AAAA" value="AAAA" />
              </el-select>
            </el-form-item>
            <!-- 主机记录（二级域名）整行录入。 -->
            <el-form-item
              :label="t('ddns.subdomains')"
              class="cell-wide"
              :class="{ 'field-error': revealErrors && !targetValid(tg) }"
            >
              <TagInput v-model="tg.subdomains" :disabled="tg.allowRoot" :placeholder="t('ddns.subdomainsPlaceholder')" />
            </el-form-item>
            <el-form-item :label="t('ddns.ttl')" class="cell-sm">
              <el-select v-model="tg.ttl" style="width: 100%">
                <el-option :label="t('ddns.ttlAuto')" :value="0" />
                <el-option v-for="n in [60, 300, 600, 1800, 3600]" :key="n" :label="`${n} ${t('ddns.ttlUnit')}`" :value="n" />
              </el-select>
              <span v-if="tg.ttl === 0" class="ttl-hint">{{ ttlAutoHint(tg) }}</span>
            </el-form-item>
            <el-form-item :label="t('ddns.line')" class="cell-sm">
              <el-input v-model="tg.line" :placeholder="t('ddns.lineHint')" />
            </el-form-item>
            <el-form-item :label="t('ddns.allowRoot')" class="cell">
              <el-switch v-model="tg.allowRoot" @change="(val: any) => { if (val) tg.subdomains = [] }" />
              <span class="root-hint" :class="{ danger: tg.allowRoot }">{{ t('ddns.allowRootHint') }}</span>
            </el-form-item>
          </div>
          <el-button :icon="Delete" circle text type="danger" @click="removeTarget(i)" />
        </div>
        <p v-if="!(r.editing.value as Rule).targets.length" class="mt-subtle">{{ t('common.empty') }}</p>
        <p v-if="revealErrors && !formValid" class="mt-danger-text ddns-req-hint">{{ t('ddns.requiredHint') }}</p>
      </el-form>
      <template #footer>
        <el-button @click="r.dialogVisible.value = false">{{ t('common.cancel') }}</el-button>
        <el-button type="primary" :loading="r.saving.value" :disabled="!formValid" @click="onSave">
          {{ t('common.save') }}
        </el-button>
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
.target-row {
  display: flex;
  align-items: flex-start;
  gap: 10px;
  padding: 12px 12px 0;
  margin-bottom: 10px;
}
.target-grid {
  display: grid;
  grid-template-columns: repeat(3, minmax(0, 1fr));
  gap: 0 12px;
  flex: 1;
}
.cell {
  grid-column: span 1;
}
.cell-wide {
  grid-column: span 3;
}
/* 必填项缺失且已触发校验：输入框跳红提示。 */
.field-error :deep(.el-input__wrapper) {
  box-shadow: 0 0 0 1px var(--el-color-danger) inset;
}
.field-error :deep(.tag-input) {
  border-color: var(--el-color-danger);
}
.ddns-req-hint {
  margin: 8px 0 0;
}
.cell-sm {
  grid-column: span 1;
}
.ttl-hint {
  margin-top: 4px;
  font-size: 12px;
  line-height: 1.3;
  color: var(--mt-text-subtle, #909399);
}
.root-hint {
  margin-left: 10px;
  font-size: 12px;
  color: var(--mt-text-subtle, #909399);
}
.root-hint.danger {
  color: var(--el-color-danger);
}
.hint {
  font-size: 12px;
  margin: -4px 0 4px;
}
.cmd-hint {
  font-size: 12px;
  margin: -4px 0 8px;
}

/* 窄屏两档。
 * 640：一条记录里的三联排（记录类型 / 主机名 / TTL）先收成一栏——它挤在
 * .target-row 的剩余宽度里，比页面上别处更早不够用。
 * 跨栏那格要显式写 1 / -1：留着 span 3 会在一栏的网格上再生出两条隐式列，
 * 于是三栏原样回来，这一档等于没生效。
 * 560：两联排改成一栏。 */
@media (max-width: 640px) {
  .target-grid {
    grid-template-columns: minmax(0, 1fr);
  }
  .cell-wide {
    grid-column: 1 / -1;
  }
}
@media (max-width: 560px) {
  .grid2 {
    grid-template-columns: minmax(0, 1fr);
  }
}
</style>
