<script setup lang="ts">
import { onActivated, ref, reactive } from 'vue'
import { useI18n } from 'vue-i18n'
import { ElMessage } from 'element-plus'
import { Plus, Key, Upload } from '@element-plus/icons-vue'
import PageCard from '@/components/PageCard.vue'
import RowActions from '@/components/RowActions.vue'
import TagInput from '@/components/TagInput.vue'
import { useNarrow } from '@/composables/useNarrow'
import { usePolling } from '@/composables/usePolling'
import { useResource } from '@/composables/useResource'
import { useCloseOnLeave } from '@/composables/useCloseOnLeave'
import { actions, credentialsApi } from '@/api/resources'
import { currentLocale } from '@/i18n'

const { t } = useI18n()

// 窄屏时操作列只剩一个「更多」按钮，列宽跟着收窄，省下的宽度留给前面几列。
const narrow = useNarrow()

interface OperationStatus {
  state: string
  message: string
  updatedAt: number
}

interface Cert {
  id?: string
  name: string
  enabled: boolean
  domains: string[]
  method: string
  certPath: string
  keyPath: string
  acmeChallenge: string
  credentialRef: string
  acmeAccountRef: string
  autoRenew: boolean
  renewBeforeDays: number
  renewTime: string
  notAfter?: number
  status?: string
  issueStatus?: OperationStatus
  renewStatus?: OperationStatus
  lastRenewAt?: number
}
function empty(): Cert {
  return {
    name: '',
    enabled: true,
    domains: [],
    method: 'file',
    certPath: '',
    keyPath: '',
    acmeChallenge: 'dns01',
    credentialRef: '',
    acmeAccountRef: '',
    autoRenew: true,
    renewBeforeDays: 30,
    renewTime: '09:00',
  }
}
const r = useResource<Cert>('certs', empty)

// ACME 账户（复用通用资源逻辑，供证书表单选择 + 独立管理对话框）。
interface AcmeAccount {
  id?: string
  name: string
  ca: string
  email: string
  eabKid: string
  eabHmac: string
}
function emptyAcme(): AcmeAccount {
  return { name: '', ca: 'letsencrypt', email: '', eabKid: '', eabHmac: '' }
}
const acme = useResource<AcmeAccount>('acme-accounts', emptyAcme)
const acmeManageVisible = ref(false)

const credentials = ref<{ id: string; name: string; provider: string }[]>([])

function methodLabel(m: string): string {
  if (m === 'path') return t('cert.methodPath')
  if (m === 'acme') return t('cert.methodAcme')
  return t('cert.methodFile')
}
function caLabel(ca: string): string {
  const key = `cert.caName.${ca}`
  return t(key) !== key ? t(key) : ca
}

function operationType(state?: string): 'success' | 'warning' | 'danger' | 'info' {
  if (state === 'success') return 'success'
  if (state === 'running' || state === 'pending') return 'warning'
  if (state === 'failed' || state === 'error') return 'danger'
  return 'info'
}

function currentOperation(row: Cert): (OperationStatus & { kind: 'issue' | 'renew' }) | undefined {
  const issue = row.issueStatus
  const renew = row.renewStatus
  // 只采纳带有效 state 的记录；state 为空会让 opLabel 返回空文案，
  // 进而被渲染成空 <el-tag>（看起来像一个异常的空白方框）。这里把它们视作"无操作"。
  const validIssue = issue && issue.state ? issue : undefined
  const validRenew = renew && renew.state ? renew : undefined
  if (!validIssue && !validRenew) return undefined
  if (!validIssue) return { ...validRenew!, kind: 'renew' }
  if (!validRenew) return { ...validIssue, kind: 'issue' }
  return validIssue.updatedAt >= validRenew.updatedAt
    ? { ...validIssue, kind: 'issue' }
    : { ...validRenew!, kind: 'renew' }
}

// 把后端下发的「操作状态码 + 类型」翻译为当前语言的标签。
// state 为 running/pending/success/failed；failed 且 message=interrupted 表示被进程重启中断。
function opLabel(op?: OperationStatus & { kind?: 'issue' | 'renew' }): string {
  if (!op || !op.state) return ''
  if (op.state === 'failed' && op.message === 'interrupted') return t('cert.status.interrupted')
  const map: Record<string, Record<string, string>> = {
    pending: { issue: 'cert.status.pendingIssue', renew: 'cert.status.pendingRenew' },
    running: { issue: 'cert.status.issuing', renew: 'cert.status.renewing' },
    success: { issue: 'cert.status.issueSuccess', renew: 'cert.status.renewSuccess' },
    failed: { issue: 'cert.status.issueFailed', renew: 'cert.status.renewFailed' },
  }
  const key = map[op.state]?.[op.kind || 'issue']
  return key ? t(key) : op.state
}

// 操作细节：已知进度/结果码翻译为当前语言；原始错误与 ACME 进度细节（技术性）原样展示。
function opDetail(op?: OperationStatus & { kind?: 'issue' | 'renew' }): string {
  if (!op || !op.message) return ''
  const codeMap: Record<string, string> = {
    'issue-pending': 'cert.status.pendingIssue',
    'renew-pending': 'cert.status.pendingRenew',
    'issue-running': 'cert.status.issuing',
    'renew-running': 'cert.status.renewing',
    'issue-success': 'cert.status.issueSuccess',
    'renew-success': 'cert.status.renewSuccess',
    interrupted: 'cert.status.interrupted',
  }
  if (codeMap[op.message]) return t(codeMap[op.message])
  return op.message
}

// 证书剩余/已过期天数（按当前时间计算），连同它该用哪一档颜色。
//
// 阈值固定：一周内红、一个月内橙、再往后绿；已过期与读不到到期时间的一律红。
// 与总览页那条证书检查日志用同一套阈值（见 Overview.vue 的 certDayCls），
// 否则同一张证书在两页显示成两种颜色，用户只能猜哪个算准。
//
// 不跟每张证书各自的「提前续期天数」联动：那样一列里几行用几套阈值，颜色就没法横向比较了；
// 而且导入的证书压根没有这个设置。
function certHealthDays(row: Cert): { text: string; cls: string } {
  if (!row.notAfter) return { text: '—', cls: 'mt-subtle' }
  const now = Math.floor(Date.now() / 1000)
  const diff = row.notAfter - now
  if (diff <= 0) {
    const days = Math.ceil(-diff / 86400)
    return { text: t('cert.expiredDays', { n: days }), cls: 'cert-days-urgent' }
  }
  const days = Math.ceil(diff / 86400)
  const cls = days <= 7 ? 'cert-days-urgent' : days <= 30 ? 'cert-days-soon' : 'cert-days-ok'
  return { text: t('cert.remainingDays', { n: days }), cls }
}

// 证书健康状态标签（valid/expired/missing），由列表接口下发，按语言翻译。
function healthInfo(row: Cert): { text: string; type: 'success' | 'danger' | 'warning' } | undefined {
  switch (row.status) {
    case 'valid':
      return { text: t('cert.status.valid'), type: 'success' }
    case 'expired':
      return { text: t('cert.status.expired'), type: 'danger' }
    case 'missing':
      return { text: t('cert.status.missing'), type: 'warning' }
    default:
      return undefined
  }
}

// 名称列综合状态：有进行中/失败操作则展示操作状态，否则展示健康状态（均按语言翻译）。
// 兜底：当操作状态本身没文案（如 state 为空）时不渲染任何标签，避免出现空方框。
function nameStatus(row: Cert): { text: string; type: 'success' | 'danger' | 'warning' | 'info' } | undefined {
  const op = currentOperation(row)
  if (op) {
    const text = opLabel(op)
    if (!text) return healthInfo(row)
    return { text, type: operationType(op.state) }
  }
  return healthInfo(row)
}

// 日期时间（按语言）：中文 x年x月x日 时:分:秒；英文 xxxx-xx-xx 时:分:秒。
// 入参为 Unix 秒；无效则返回占位符。
function fmtDateTime(sec?: number): string {
  if (!sec) return '—'
  const d = new Date(sec * 1000)
  const p = (n: number) => (n < 10 ? '0' + n : '' + n)
  const hh = p(d.getHours())
  const mm = p(d.getMinutes())
  const ss = p(d.getSeconds())
  if (currentLocale() === 'zh-CN') {
    return `${d.getFullYear()}年${d.getMonth() + 1}月${d.getDate()}日 ${hh}:${mm}:${ss}`
  }
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${hh}:${mm}:${ss}`
}

// 下一次续期时间（Unix 秒）：到期前 renewBeforeDays 天的续期检查时刻（renewTime，每天此时触发）即为首次续期点。
// 若已过该临界点（已进入续期窗口或已过期），则取下一个 >= 当前的 renewTime（每日触发）。
// 无到期时间则返回 0（由 fmtDateTime 显示为占位符）。
function nextRenewTime(row: Cert): number {
  if (!row.notAfter) return 0
  const renewBySec = row.notAfter - (row.renewBeforeDays || 0) * 86400
  const [h, m] = (row.renewTime || '03:00').split(':').map((x) => Number(x) || 0)
  const d = new Date(renewBySec * 1000)
  d.setHours(h, m, 0, 0)
  let candidate = Math.floor(d.getTime() / 1000)
  const now = Math.floor(Date.now() / 1000)
  // 已错过首次续期点：取最近一个 >= 现在的 renewTime（当天或次日）。
  if (candidate <= now) {
    const today = new Date(now * 1000)
    today.setHours(h, m, 0, 0)
    candidate = Math.floor(today.getTime() / 1000)
    if (candidate <= now) candidate += 86400
  }
  return candidate
}

// 触发一次浏览器下载。
function download(name: string, text: string) {
  const url = URL.createObjectURL(new Blob([text], { type: 'application/x-pem-file' }))
  const a = document.createElement('a')
  a.href = url
  a.download = name
  document.body.appendChild(a)
  a.click()
  a.remove()
  URL.revokeObjectURL(url)
}

// 导出证书 + 私钥两个文件，与「导入 PEM」的两个输入框一一对应：
// 导出的 .pem / .key 原样贴回（或选文件）就能在另一台机器上还原同一张证书。
// 分成两个文件而不是拼成一个：绝大多数服务端（nginx / 也包括本模块的导入）
// 要的就是分开的证书链与私钥，拼在一起用户还得自己剪。
async function exportCert(row: Cert) {
  const base = (row.name || 'certificate').replace(/[\\/:*?"<>|]/g, '_')
  try {
    const result = await actions.exportCert(row.id!)
    download(`${base}.pem`, result.certPem)
    if (result.keyPem) {
      download(`${base}.key`, result.keyPem)
      ElMessage.success(t('cert.exportedWithKey'))
    } else {
      ElMessage.warning(t('cert.exportedNoKey'))
    }
  } catch {
    // 带私钥读不出来时后端是整个请求报错（比如 path 方式只填了证书路径），
    // 但只有半边也总比什么都拿不到好：退回去只导证书，并说清少了什么。
    try {
      const only = await actions.exportCert(row.id!, false)
      download(`${base}.pem`, only.certPem)
      ElMessage.warning(t('cert.exportedNoKey'))
    } catch (e2: any) {
      ElMessage.error(e2?.message || t('common.failed'))
    }
  }
}

const importVisible = ref(false)
const importForm = reactive({ id: '', certPem: '', keyPem: '' })
const issuingIds = ref(new Set<string>())

function isIssuing(row: Cert): boolean {
  const state = currentOperation(row)?.state
  return issuingIds.value.has(row.id || '') || state === 'pending' || state === 'running'
}

async function issue(row: Cert) {
  const id = row.id!
  issuingIds.value.add(id)
  try {
    const res = await actions.issueCert(id)
    ElMessage.success(res.result || t('msg.certIssued'))
    await r.load()
  } catch (e: any) {
    ElMessage.error(e?.message || t('common.failed'))
  } finally {
    issuingIds.value.delete(id)
  }
}

function openImport(row: Cert) {
  importForm.id = row.id || ''
  importForm.certPem = ''
  importForm.keyPem = ''
  importVisible.value = true
}

// 选文件导入。「导出」给出的就是 .pem + .key 两个文件，这里按同样的两格收回去；
// 读成文本填进文本框而不是直接上传，是为了让用户在提交前能看见自己选中的是什么。
async function pickPem(which: 'certPem' | 'keyPem', e: Event) {
  const input = e.target as HTMLInputElement
  const file = input.files?.[0]
  input.value = '' // 允许重复选同一个文件
  if (!file) return
  try {
    const text = await file.text()
    if (!text.includes('-----BEGIN')) {
      ElMessage.warning(t('cert.notPemFile'))
      return
    }
    importForm[which] = text
  } catch (err: any) {
    ElMessage.error(err?.message || t('common.failed'))
  }
}
async function doImport() {
  try {
    await actions.importCert({ id: importForm.id, certPem: importForm.certPem, keyPem: importForm.keyPem })
    importVisible.value = false
    ElMessage.success(t('msg.certIssued'))
    r.load()
  } catch (e: any) {
    ElMessage.error(e?.message || t('common.failed'))
  }
}

// 列表内联启用/禁用（滑块开关，置于列表最前，类似 Web 服务开关）。
// 开关随 v-model 先行翻转，提交后端做自检查：若证书正被面板或 Web 服务使用，
// 后端返回 409 并附模块列表，此处回滚开关并提示用户；否则保存成功。
async function toggleCert(row: Cert) {
  const target = row.enabled
  try {
    const res = await actions.toggleCert(row.id!, target)
    ElMessage.success(res.enabled ? t('cert.enable') + ' ✓' : t('cert.disable') + ' ✓')
    await r.load()
  } catch (e: any) {
    row.enabled = !target
    ElMessage.error(e?.message || t('common.failed'))
  }
}

// 有签发 / 续期在跑的时候才拉列表，2 秒一轮。停 / 恢复的三条规则（切页停、
// 标签页不可见停、重新可见补一次）都在 usePolling 里，这里只表达"这一页需要轮询"。
//
// 定时器本身常驻（而不是"有任务时才建、任务完就拆"）：任务是从别处开始的（点按钮、
// 另一个浏览器标签、后端自动续期），拆掉之后没有谁负责把它建回来。
const poll = usePolling(() => {
  if (
    r.list.value.some((item) => {
      const state = currentOperation(item)?.state
      return state === 'pending' || state === 'running'
    })
  ) {
    r.load({ silent: true })
  }
}, 2000)

// 页面被激活（keep-alive 下首次挂载同样会触发一次，因此这里是唯一入口）。
// 三个请求彼此独立（证书列表 / ACME 账户 / 凭据），并发发出即可：
// 原先串行等于把三个往返首尾相接，首屏要等最后一个回来。
onActivated(() => {
  poll.start()
  r.load()
  acme.load()
  credentialsApi
    .list()
    .then((items) => {
      credentials.value = items as any
    })
    .catch(() => undefined) /* 凭据拉不到不影响证书列表（与原先的 try/catch 同义） */
})

// 本页另开的两个弹窗（导入 PEM、ACME 账户）也在切页时收起；新增 / 编辑那个在 useResource 里。
useCloseOnLeave(importVisible, acmeManageVisible)
</script>

<template>
  <PageCard :title="t('cert.title')" :subtitle="t('cert.subtitle')" :max-count="r.maxCount.value" collapse-actions>
    <template #actions>
      <el-button :icon="Key" @click="acmeManageVisible = true">{{ t('cert.manageAcme') }}</el-button>
      <el-button type="primary" :icon="Plus" @click="r.openCreate()">{{ t('common.add') }}</el-button>
    </template>

    <el-table :data="r.list.value" v-loading="r.loading.value" stripe row-key="id">
      <el-table-column :label="t('common.status')" width="90">
        <template #default="{ row }">
          <el-switch v-model="row.enabled" @change="toggleCert(row)" />
        </template>
      </el-table-column>
      <el-table-column :label="t('cert.certName')" min-width="160">
        <template #default="{ row }">
          <div><strong>{{ row.name || t('common.unnamed') }}</strong></div>
          <el-tag v-if="nameStatus(row)" size="small" :type="nameStatus(row)!.type" effect="plain">{{ nameStatus(row)!.text }}</el-tag>
        </template>
      </el-table-column>
      <el-table-column :label="t('cert.domains')" min-width="180">
        <template #default="{ row }"><span class="mt-subtle">{{ (row.domains || []).join(', ') }}</span></template>
      </el-table-column>
      <el-table-column :label="t('cert.method')" width="120">
        <template #default="{ row }">{{ methodLabel(row.method) }}</template>
      </el-table-column>
      <el-table-column :label="t('cert.path')" min-width="210">
        <template #default="{ row }">
          <div class="cert-paths mt-subtle">
            <span>{{ row.certPath || '—' }}</span>
            <span>{{ row.keyPath || '—' }}</span>
          </div>
        </template>
      </el-table-column>
      <el-table-column :label="t('cert.certStatus')" min-width="140">
        <template #default="{ row }">
          <div class="cert-health">
            <el-tag v-if="healthInfo(row)" size="small" :type="healthInfo(row)!.type" effect="plain">{{ healthInfo(row)!.text }}</el-tag>
            <span v-else class="mt-subtle">—</span>
            <span class="cert-health-days" :class="certHealthDays(row).cls">{{ certHealthDays(row).text }}</span>
          </div>
        </template>
      </el-table-column>
      <el-table-column :label="t('cert.notAfter')" min-width="160">
        <template #default="{ row }">{{ fmtDateTime(row.notAfter) }}</template>
      </el-table-column>
      <el-table-column :label="t('cert.nextRenew')" min-width="190">
        <template #default="{ row }">
          <div class="renew-next">
            <span>{{ t('cert.renewInAdvance', { n: row.renewBeforeDays }) }}</span>
            <span class="mt-subtle renew-time">{{ fmtDateTime(nextRenewTime(row)) }}</span>
          </div>
        </template>
      </el-table-column>
      <el-table-column :label="t('common.actions')" :width="narrow ? 90 : 320" align="right">
        <template #default="{ row }">
          <RowActions>
            <el-button
              v-if="row.method === 'acme'"
              size="small"
              :loading="isIssuing(row)"
              :disabled="isIssuing(row)"
              @click="issue(row)"
            >
              {{ t('cert.issue') }}
            </el-button>
            <el-button v-if="row.method === 'file'" size="small" @click="openImport(row)">{{ t('cert.importPem') }}</el-button>
            <el-button size="small" @click="exportCert(row)">{{ t('cert.export') }}</el-button>
            <el-button size="small" @click="r.openEdit(row)">{{ t('common.edit') }}</el-button>
            <el-button size="small" type="danger" text @click="r.remove(row, t('common.confirmDelete'))">
              {{ t('common.delete') }}
            </el-button>
          </RowActions>
        </template>
      </el-table-column>
    </el-table>

    <!-- 新增/编辑证书 -->
    <el-dialog v-model="r.dialogVisible.value" :title="r.isNew.value ? t('common.add') : t('common.edit')" width="min(560px, 94vw)" append-to-body :close-on-click-modal="false">
      <el-form label-position="top">
        <el-form-item :label="t('cert.certName')">
          <el-input v-model="(r.editing.value as Cert).name" />
        </el-form-item>
        <el-form-item :label="t('cert.enable')">
          <el-switch v-model="(r.editing.value as Cert).enabled" />
        </el-form-item>
          <el-form-item :label="t('cert.domains')">
            <div>
              <TagInput v-model="(r.editing.value as Cert).domains" :placeholder="t('cert.domainsPlaceholder')" />
              <p class="mt-subtle hint">{{ t('cert.domainsHint') }}</p>
            </div>
          </el-form-item>
        <el-form-item :label="t('cert.method')">
          <el-radio-group v-model="(r.editing.value as Cert).method">
            <el-radio-button value="file">{{ t('cert.methodFile') }}</el-radio-button>
            <el-radio-button value="path">{{ t('cert.methodPath') }}</el-radio-button>
            <el-radio-button value="acme">{{ t('cert.methodAcme') }}</el-radio-button>
          </el-radio-group>
        </el-form-item>

        <!-- 文件粘贴 -->
        <el-alert
          v-if="(r.editing.value as Cert).method === 'file'"
          :title="t('cert.fileHint')"
          type="info"
          :closable="false"
          show-icon
        />

        <!-- 磁盘路径 -->
        <template v-else-if="(r.editing.value as Cert).method === 'path'">
          <el-form-item :label="t('cert.certPath')">
            <el-input v-model="(r.editing.value as Cert).certPath" placeholder="/etc/ssl/example.crt" />
          </el-form-item>
          <el-form-item :label="t('cert.keyPath')">
            <el-input v-model="(r.editing.value as Cert).keyPath" placeholder="/etc/ssl/example.key" />
          </el-form-item>
          <p class="mt-subtle hint">{{ t('cert.pathHint') }}</p>
        </template>

        <!-- ACME 自动签发（仅 DNS-01 验证，天然支持通配符证书） -->
        <template v-else>
          <el-form-item :label="t('cert.acme')">
            <el-select v-model="(r.editing.value as Cert).acmeAccountRef" style="width: 100%">
              <el-option v-for="a in acme.list.value" :key="a.id" :label="a.name" :value="a.id!" />
            </el-select>
          </el-form-item>
          <el-alert
            v-if="!acme.list.value.length"
            :title="t('cert.noAccount')"
            type="warning"
            :closable="false"
            show-icon
            style="margin-bottom: 12px"
          />
          <el-form-item :label="t('cert.credential')">
            <el-select v-model="(r.editing.value as Cert).credentialRef" style="width: 100%">
              <el-option v-for="c in credentials" :key="c.id" :label="`${c.name} (${c.provider})`" :value="c.id" />
            </el-select>
          </el-form-item>
          <div class="grid2">
            <el-form-item :label="t('cert.autoRenew')">
              <el-switch v-model="(r.editing.value as Cert).autoRenew" />
            </el-form-item>
            <el-form-item :label="t('cert.renewBefore')">
              <el-input-number v-model="(r.editing.value as Cert).renewBeforeDays" :min="1" :max="89" style="width: 100%" />
            </el-form-item>
          </div>
          <el-form-item :label="t('cert.execTime')">
            <div>
              <el-time-picker
                v-model="(r.editing.value as Cert).renewTime"
                format="HH:mm"
                value-format="HH:mm"
                :clearable="false"
                style="width: 160px"
              />
              <p class="mt-subtle hint">{{ t('cert.renewTimeHint') }}</p>
            </div>
          </el-form-item>
          <p class="mt-subtle hint">{{ t('cert.dns01Hint') }}</p>
        </template>
      </el-form>
      <template #footer>
        <el-button @click="r.dialogVisible.value = false">{{ t('common.cancel') }}</el-button>
        <el-button type="primary" :loading="r.saving.value" @click="r.save()">{{ t('common.save') }}</el-button>
      </template>
    </el-dialog>

    <!-- 导入 PEM。两格与「导出」产出的 .pem / .key 一一对应。 -->
    <el-dialog v-model="importVisible" :title="t('cert.importPem')" width="min(560px, 94vw)" append-to-body :close-on-click-modal="false">
      <el-form label-position="top">
        <el-form-item :label="t('cert.certPem')">
          <div class="pem-head">
            <label class="pem-pick">
              <input type="file" accept=".pem,.crt,.cer,.txt" @change="(e) => pickPem('certPem', e)" />
              <el-button size="small" :icon="Upload" tag="span">{{ t('cert.chooseFile') }}</el-button>
            </label>
            <span class="mt-subtle hint">{{ t('cert.orPaste') }}</span>
          </div>
          <el-input v-model="importForm.certPem" type="textarea" :rows="5" placeholder="-----BEGIN CERTIFICATE-----" />
        </el-form-item>
        <el-form-item :label="t('cert.keyPem')">
          <div class="pem-head">
            <label class="pem-pick">
              <input type="file" accept=".key,.pem,.txt" @change="(e) => pickPem('keyPem', e)" />
              <el-button size="small" :icon="Upload" tag="span">{{ t('cert.chooseFile') }}</el-button>
            </label>
            <span class="mt-subtle hint">{{ t('cert.orPaste') }}</span>
          </div>
          <el-input v-model="importForm.keyPem" type="textarea" :rows="5" placeholder="-----BEGIN PRIVATE KEY-----" />
        </el-form-item>
        <p class="mt-subtle hint">{{ t('cert.importPairHint') }}</p>
      </el-form>
      <template #footer>
        <el-button @click="importVisible = false">{{ t('common.cancel') }}</el-button>
        <el-button type="primary" @click="doImport">{{ t('cert.import') }}</el-button>
      </template>
    </el-dialog>

    <!-- ACME 账户管理 -->
    <el-dialog v-model="acmeManageVisible" :title="t('cert.acmeTitle')" width="min(620px, 94vw)" append-to-body :close-on-click-modal="false">
      <div class="acme-head">
        <el-button type="primary" size="small" :icon="Plus" @click="acme.openCreate()">{{ t('common.add') }}</el-button>
      </div>
      <el-table :data="acme.list.value" v-loading="acme.loading.value" stripe row-key="id">
        <el-table-column :label="t('cert.accountName')" min-width="130">
          <template #default="{ row }"><strong>{{ row.name || t('common.unnamed') }}</strong></template>
        </el-table-column>
        <el-table-column :label="t('cert.ca')" min-width="130">
          <template #default="{ row }">{{ caLabel(row.ca) }}</template>
        </el-table-column>
        <el-table-column :label="t('cert.email')" min-width="150">
          <template #default="{ row }"><span class="mt-subtle">{{ row.email || '—' }}</span></template>
        </el-table-column>
        <el-table-column :label="t('common.actions')" :width="narrow ? 90 : 140" align="right">
          <template #default="{ row }">
            <RowActions>
              <el-button size="small" @click="acme.openEdit(row)">{{ t('common.edit') }}</el-button>
              <el-button size="small" type="danger" text @click="acme.remove(row, t('common.confirmDelete'))">
                {{ t('common.delete') }}
              </el-button>
            </RowActions>
          </template>
        </el-table-column>
      </el-table>
    </el-dialog>

    <!-- ACME 账户 新增/编辑 -->
    <el-dialog v-model="acme.dialogVisible.value" :title="acme.isNew.value ? t('common.add') : t('common.edit')" width="min(480px, 94vw)" append-to-body :close-on-click-modal="false">
      <el-form label-position="top">
        <el-form-item :label="t('cert.accountName')">
          <el-input v-model="(acme.editing.value as AcmeAccount).name" />
        </el-form-item>
        <div class="grid2">
          <el-form-item :label="t('cert.ca')">
            <el-select v-model="(acme.editing.value as AcmeAccount).ca" style="width: 100%">
              <el-option :label="t('cert.caName.letsencrypt')" value="letsencrypt" />
              <el-option :label="t('cert.caName.zerossl')" value="zerossl" />
              <el-option :label="t('cert.caName.buypass')" value="buypass" />
            </el-select>
          </el-form-item>
          <el-form-item :label="t('cert.email')">
            <el-input v-model="(acme.editing.value as AcmeAccount).email" placeholder="admin@example.com" />
          </el-form-item>
        </div>
        <div class="grid2">
          <el-form-item :label="t('cert.eabKid')">
            <el-input v-model="(acme.editing.value as AcmeAccount).eabKid" />
          </el-form-item>
          <el-form-item :label="t('cert.eabHmac')">
            <el-input v-model="(acme.editing.value as AcmeAccount).eabHmac" type="password" show-password />
          </el-form-item>
        </div>
        <p class="mt-subtle hint">{{ t('cert.eabHint') }}</p>
      </el-form>
      <template #footer>
        <el-button @click="acme.dialogVisible.value = false">{{ t('common.cancel') }}</el-button>
        <el-button type="primary" :loading="acme.saving.value" @click="acme.save()">{{ t('common.save') }}</el-button>
      </template>
    </el-dialog>
  </PageCard>
</template>

<style scoped>
/* 隐藏原生 file 控件、只露出 el-button：原生控件在各平台长得都不一样，
 * 且没法跟着主题走。label 包住 input，点按钮等于点 input。 */
.pem-pick > input[type='file'] {
  position: absolute;
  width: 1px;
  height: 1px;
  opacity: 0;
  pointer-events: none;
}
.pem-pick {
  position: relative;
  display: inline-flex;
  cursor: pointer;
}
.pem-head {
  display: flex;
  align-items: center;
  gap: 10px;
  margin-bottom: 6px;
}
.grid2 {
  display: grid;
  grid-template-columns: minmax(0, 1fr) minmax(0, 1fr);
  gap: 0 16px;
}
.hint {
  font-size: 12px;
  margin-top: 4px;
}
.cert-paths {
  display: flex;
  flex-direction: column;
  gap: 2px;
  word-break: break-all;
}
.renew-time {
  margin-top: 4px;
  font-size: 12px;
}
.renew-next {
  display: flex;
  flex-direction: column;
  gap: 4px;
}
.cert-health {
  display: flex;
  flex-direction: column;
  gap: 4px;
  align-items: flex-start;
}
.cert-health-days {
  font-size: 12px;
  line-height: 1.2;
}
/* 剩余天数三档，阈值见 certHealthDays。加粗只给要紧的两档：
   绿色那档是"不用管"，不该跟着抢注意力。 */
.cert-days-urgent {
  color: var(--mt-danger);
  font-weight: 600;
}
.cert-days-soon {
  color: var(--mt-warning);
  font-weight: 600;
}
.cert-days-ok {
  color: var(--mt-success);
}
.acme-head {
  display: flex;
  justify-content: flex-end;
  margin-bottom: 12px;
}

/* 窄屏：每栏不足 240 像素时，域名与路径那几个框只能看到开头几个字，改成一栏。 */
@media (max-width: 560px) {
  .grid2 {
    grid-template-columns: minmax(0, 1fr);
  }
}
</style>
