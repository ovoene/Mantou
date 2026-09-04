<script setup lang="ts">
import { ref, reactive, computed, onActivated, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import { ElMessage, ElMessageBox } from 'element-plus'
import PageCard from '@/components/PageCard.vue'
import { actions, type GfwConfig, type GfwPreset, type GfwUpdateReq, type FirewallBan } from '@/api/resources'
import { fmtTime, fmtBytes } from '@/composables/useResource'
import { useNarrow } from '@/composables/useNarrow'
import { gfwLevelLabel } from '@/composables/gfwText'

const { t } = useI18n()

// 窄屏下表单标签改到字段上方（与设置页同一条理由：内容区太窄时右置标签会把字段挤成一条缝）。
const narrow = useNarrow()
const labelPos = computed(() => (narrow.value ? 'top' : 'right'))

// labelWidth 标签列宽度。写成常量而不是散在两处模板里：保存按钮那一行不在 el-form 里，
// 要靠同一个数字缩进才能和上面各字段的输入框对齐（见 .save-row 的 padding-left）。
//
// 132px 是按最长标签定的——中文最长 4 字（约 56px），英文 "Detection level" / "Regular window"
// 约 105px，加上 el-form-item 标签自带的 12px 右内边距。给窄了英文标签会折成两行，
// 标签盒子随之变高，于是"文字和框不齐平"。
const labelWidth = '132px'
const contentIndent = computed(() => (narrow.value ? '0' : labelWidth))

// 首屏是否已经拿到服务端配置。配置项都带硬编码初值，数据回来前先用一层 loading 盖住，
// 而不是 v-if 销毁重建——否则切页回来又得从零挂载，把 keep-alive 的收益抵消掉。
const loaded = ref(false)
const saving = ref(false)
const activeTab = ref('settings')

// defaultGfw 数据回来之前的占位值。**enabled 必须是 false**，与服务端的默认值一致
// （见 config.defaultGlobalFirewall）：这里写 true 的话，全新安装的用户打开本页会看到
// 一个"已启用"的开关，而服务端其实是关着的——他若不点保存就一直以为自己受保护。
// 其余数值取均衡档，只为占位；load() 会用服务端的值整份覆盖。
function defaultGfw(): GfwConfig {
  return {
    enabled: false,
    level: 'balanced',
    allowIps: [],
    denyIps: [],
    autoBan: true,
    windowSeconds: 60,
    windowLimit: 12,
    burstSeconds: 3,
    burstLimit: 4,
    banMinutes: 120,
    memoryMB: 5,
  }
}
const cfg = reactive<GfwConfig>(defaultGfw())

// 名单在界面上是每行一条的文本框，配置里是字符串数组：两个方向都在 listToText /
// textToList 里转，不在模板里就地 split，好让"用户看到的"与"提交的"只有一处定义。
const allowText = ref('')
const denyText = ref('')

// 额度上限与预设档位表都由后端下发：表单上的"最多 N 条""最大 M 分钟"以及各档位的数值，
// 必须和服务端真正用的那一份同源。前端自己抄一份的代价是两边可以各改各的，
// 而且没人会发现——界面上显示的档位数值与实际执行的可以完全不同。
const limits = reactive<{
  maxIps: number
  maxMemoryMB: number
  maxBanMinutes: number
  minWindowSeconds: number
  maxWindowSeconds: number
  minLimit: number
  maxLimit: number
  levels: string[]
  presets: GfwPreset[]
}>({
  maxIps: 256,
  maxMemoryMB: 15,
  maxBanMinutes: 1440,
  minWindowSeconds: 1,
  maxWindowSeconds: 3600,
  minLimit: 1,
  maxLimit: 100000,
  levels: ['loose', 'balanced', 'strict', 'custom'],
  presets: [],
})

// 档位是否为「自定义」。只有它才允许手填数值：其余档位的数值由服务端按档位重写
// （见 config.normalizeGlobalFirewall），让用户在那里输入等于让他改一个不会生效的数。
const isCustom = computed(() => cfg.level === 'custom')

// levelLabel 档位的译名。用 composables/gfwText 里那一份，与两个业务页顶部的状态条同源：
// 各自写一份的话，"均衡"在模块页和状态条上能显示成两个不同的词，且不会有任何报错。
function levelLabel(level: string): string {
  return gfwLevelLabel(t, level)
}

// levelDesc 档位下方那行说明：把该档的实际数值念出来。
// 数值取自后端下发的预设表，因此"说明里写的"与"选中后填进去的"必然一致。
function levelDesc(level: string): string {
  const key = `gfw.levelPreset${level.charAt(0).toUpperCase()}${level.slice(1)}`
  const p = limits.presets.find((x) => x.level === level)
  if (!p) return t(key) // custom 没有预设，文案里也没有数值占位
  return t(key, {
    ws: p.windowSeconds,
    wl: p.windowLimit,
    bs: p.burstSeconds,
    bl: p.burstLimit,
    bm: p.banMinutes,
  })
}

// onLevelChange 换档位时**立刻**把该档的预设数值写进表单。
//
// 这是"点了档位却什么都不变"的前端一半：服务端已经改成"档位是权威值、保存时按档位重写数值"，
// 但用户在点下单选钮的那一刻看不到任何变化，只能保存完再刷新才知道自己选了什么。
// 用 @change 而不是 watch(cfg.level)：load() 也会写 cfg.level，watch 会连带把服务端刚返回的
// 数值又覆盖一遍——对预设档位是同值覆盖（无害但多余），对将来任何"服务端存的与预设不同"
// 的情形则是把真实值悄悄改掉。只在用户真的点了的时候才动数值。
function onLevelChange(level: string | number | boolean | undefined) {
  const p = limits.presets.find((x) => x.level === level)
  if (!p) return // custom：保留用户当前填的数值，让他从这一组开始改
  cfg.windowSeconds = p.windowSeconds
  cfg.windowLimit = p.windowLimit
  cfg.burstSeconds = p.burstSeconds
  cfg.burstLimit = p.burstLimit
  cfg.banMinutes = p.banMinutes
}

function listToText(list: unknown): string {
  return Array.isArray(list) ? list.join('\n') : ''
}
// 每行一条，去空行与首尾空白。条数不在这里截断：超限要让后端报出来，
// 前端悄悄截掉等于把用户多填的那些无声丢掉。
function textToList(text: string): string[] {
  return text
    .split('\n')
    .map((s) => s.trim())
    .filter((s) => s.length > 0)
}

// 内存占用与上限（自动封禁页的度量卡用）。
const memUsedBytes = ref(0)
const memLimitMB = ref(0)

// 当前封禁名单。total 与 items.length 可能不等（后端按 limit 截断）。
const bans = ref<FirewallBan[]>([])
const banTotal = ref(0)
const bansLoading = ref(false)

async function load() {
  loaded.value = false
  try {
    const res = await actions.globalFirewall()
    const c = res.config
    cfg.enabled = !!c.enabled
    cfg.level = c.level || 'balanced'
    cfg.allowIps = Array.isArray(c.allowIps) ? c.allowIps : []
    cfg.denyIps = Array.isArray(c.denyIps) ? c.denyIps : []
    cfg.autoBan = c.autoBan !== false
    cfg.windowSeconds = typeof c.windowSeconds === 'number' ? c.windowSeconds : 60
    cfg.windowLimit = typeof c.windowLimit === 'number' ? c.windowLimit : 12
    cfg.burstSeconds = typeof c.burstSeconds === 'number' ? c.burstSeconds : 3
    cfg.burstLimit = typeof c.burstLimit === 'number' ? c.burstLimit : 4
    cfg.banMinutes = typeof c.banMinutes === 'number' ? c.banMinutes : 120
    cfg.memoryMB = typeof c.memoryMB === 'number' ? c.memoryMB : 5
    allowText.value = listToText(cfg.allowIps)
    denyText.value = listToText(cfg.denyIps)
    if (res.limits) {
      const l = res.limits
      if (l.maxIps > 0) limits.maxIps = l.maxIps
      if (l.maxMemoryMB > 0) limits.maxMemoryMB = l.maxMemoryMB
      if (l.maxBanMinutes > 0) limits.maxBanMinutes = l.maxBanMinutes
      if (l.minWindowSeconds > 0) limits.minWindowSeconds = l.minWindowSeconds
      if (l.maxWindowSeconds > 0) limits.maxWindowSeconds = l.maxWindowSeconds
      if (l.minLimit > 0) limits.minLimit = l.minLimit
      if (l.maxLimit > 0) limits.maxLimit = l.maxLimit
      if (Array.isArray(l.levels) && l.levels.length) limits.levels = l.levels
      if (Array.isArray(l.presets)) limits.presets = l.presets
    }
    memUsedBytes.value = res.memory?.usedBytes ?? 0
    memLimitMB.value = res.memory?.limitMB ?? cfg.memoryMB
    await loadBans()
  } catch (e: any) {
    ElMessage.error(e?.message || t('gfw.loadFailed'))
  } finally {
    loaded.value = true
  }
}

// 保存服务防护配置。整份提交：后端按"缺省即沿用当前值"合并后，再规范化、校验、落盘。
// 落盘会整体替换快照指针，inboundfw 的名单缓存据此自动失效，下一次判定即读到新值。
async function save() {
  const payload: GfwUpdateReq = {
    enabled: cfg.enabled,
    level: cfg.level,
    allowIps: textToList(allowText.value),
    denyIps: textToList(denyText.value),
    autoBan: cfg.autoBan,
    windowSeconds: cfg.windowSeconds,
    windowLimit: cfg.windowLimit,
    burstSeconds: cfg.burstSeconds,
    burstLimit: cfg.burstLimit,
    banMinutes: cfg.banMinutes,
    memoryMB: cfg.memoryMB,
  }
  saving.value = true
  try {
    await actions.updateGlobalFirewall(payload)
    ElMessage.success(t('common.saved'))
    // 重新拉一次：名单里写错的条目会被后端丢掉，不重拉的话用户还以为它存进去了。
    await load()
  } catch (e: any) {
    ElMessage.error(e?.message || t('common.saveFailed'))
  } finally {
    saving.value = false
  }
}

async function loadBans() {
  bansLoading.value = true
  try {
    const res = await actions.globalFirewallBans()
    bans.value = res.items || []
    banTotal.value = res.total ?? 0
  } catch {
    /* 只读展示，拉不到不该打断整页 */
  } finally {
    bansLoading.value = false
  }
}

async function unban(ip: string) {
  try {
    await actions.clearGlobalFirewallBans(ip)
    ElMessage.success(t('gfw.banUnbanOk'))
    await loadBans()
  } catch (e: any) {
    ElMessage.error(e?.message || t('common.saveFailed'))
  }
}

async function clearBans() {
  try {
    await ElMessageBox.confirm(t('gfw.banClearConfirm'), '', {
      confirmButtonText: t('common.confirm'),
      cancelButtonText: t('common.cancel'),
      type: 'warning',
    })
  } catch {
    return
  }
  try {
    const res = await actions.clearGlobalFirewallBans()
    ElMessage.success(t('gfw.banClearOk', { n: res.cleared ?? 0 }))
    await loadBans()
  } catch (e: any) {
    ElMessage.error(e?.message || t('common.saveFailed'))
  }
}

// 切到「自动封禁」才去拉封禁名单：它是内存里随时在变的东西，要的是"打开时看到当下"，
// 而不是进页面时抓的那一眼。
watch(activeTab, (tab) => {
  if (tab === 'bans') loadBans()
})

// keep-alive 下 onActivated 首次挂载时也会触发，因此只挂它一个——与其余各模块页一致
// （Overview / WebServices / Certs … 都只写 onActivated）。再加一个 onMounted 的后果是
// 每次进页面都把 /api/global-firewall 与 /bans 各请求两遍。
onActivated(load)
</script>

<template>
  <PageCard :title="t('gfw.title')">
    <template #actions>
      <!-- 滑动开关 + 标签：放在 card-hd 右侧，与「设置」页的入站防护同一套交互。
           它是表单的一部分，改完需点「保存」才生效（见下方 saveHint）。 -->
      <div class="hd-switch">
        <el-switch v-model="cfg.enabled" />
        <span class="sw-label">{{ cfg.enabled ? t('gfw.enabled') : t('gfw.disabled') }}</span>
      </div>
    </template>

    <div v-loading="!loaded">
      <p class="brief">{{ t('gfw.brief') }}</p>

      <el-tabs v-model="activeTab">
        <el-tab-pane :label="t('gfw.tabSettings')" name="settings" />
        <el-tab-pane :label="t('gfw.tabAllow')" name="allow" />
        <el-tab-pane :label="t('gfw.tabDeny')" name="deny" />
        <el-tab-pane :label="t('gfw.tabBans')" name="bans" />
      </el-tabs>

      <!-- 设置 -->
      <div v-show="activeTab === 'settings'">
        <!-- 每个字段的结构都是 el-form-item > .field（纵向）> 控件 + .field-hint。
             灰色说明一律在控件**下方**：el-form-item 的内容区是 flex 行，直接塞一个 <p>
             会变成控件右边的一个 flex 兄弟，于是说明贴在输入框右侧、把整行撑高，
             标签也就跟着不齐平了。套一层纵向容器之后，标签始终对齐第一行控件。 -->
        <el-form :label-width="labelWidth" :label-position="labelPos">
          <el-form-item :label="t('gfw.level')">
            <div class="field">
              <el-radio-group v-model="cfg.level" @change="onLevelChange">
                <el-radio v-for="lv in limits.levels" :key="lv" :value="lv">{{ levelLabel(lv) }}</el-radio>
              </el-radio-group>
              <p class="field-hint">{{ t('gfw.levelHint') }}</p>
              <p class="field-hint">{{ levelDesc(cfg.level) }}</p>
            </div>
          </el-form-item>

          <el-form-item :label="t('gfw.autoBan')">
            <div class="field">
              <el-switch v-model="cfg.autoBan" />
              <p class="field-hint">{{ t('gfw.autoBanHint') }}</p>
            </div>
          </el-form-item>

          <el-form-item :label="t('gfw.window')">
            <div class="field">
              <div class="num-row">
                <el-input-number
                  v-model="cfg.windowSeconds"
                  :min="limits.minWindowSeconds"
                  :max="limits.maxWindowSeconds"
                  :step="1"
                  :disabled="!isCustom || !cfg.autoBan"
                  style="width: 120px"
                />
                <span class="unit">{{ t('gfw.windowJoin') }}</span>
                <el-input-number
                  v-model="cfg.windowLimit"
                  :min="limits.minLimit"
                  :max="limits.maxLimit"
                  :step="1"
                  :disabled="!isCustom || !cfg.autoBan"
                  style="width: 120px"
                />
                <span class="unit">{{ t('gfw.unitTimes') }}</span>
              </div>
              <!-- 这里不再重复"数值被服务端按档位锁定、要手填请切自定义"那句话：
                   上面档位那一行的 levelHint 已经把这件事连同受影响的三行一起说清了，
                   紧挨着再说一遍只是把同一句话摊到两处。 -->
              <p class="field-hint">{{ t('gfw.windowHint') }}</p>
            </div>
          </el-form-item>

          <el-form-item :label="t('gfw.burst')">
            <div class="field">
              <div class="num-row">
                <el-input-number
                  v-model="cfg.burstSeconds"
                  :min="limits.minWindowSeconds"
                  :max="limits.maxWindowSeconds"
                  :step="1"
                  :disabled="!isCustom || !cfg.autoBan"
                  style="width: 120px"
                />
                <span class="unit">{{ t('gfw.windowJoin') }}</span>
                <el-input-number
                  v-model="cfg.burstLimit"
                  :min="limits.minLimit"
                  :max="limits.maxLimit"
                  :step="1"
                  :disabled="!isCustom || !cfg.autoBan"
                  style="width: 120px"
                />
                <span class="unit">{{ t('gfw.unitTimes') }}</span>
              </div>
              <p class="field-hint">{{ t('gfw.burstHint') }}</p>
            </div>
          </el-form-item>

          <el-form-item :label="t('gfw.banMinutes')">
            <div class="field">
              <div class="num-row">
                <el-input-number
                  v-model="cfg.banMinutes"
                  :min="1"
                  :max="limits.maxBanMinutes"
                  :step="1"
                  :disabled="!isCustom || !cfg.autoBan"
                  style="width: 150px"
                />
                <span class="unit">{{ t('gfw.unitMinutes') }}</span>
              </div>
              <p class="field-hint">{{ t('gfw.banMinutesHint', { max: limits.maxBanMinutes }) }}</p>
            </div>
          </el-form-item>

          <el-form-item :label="t('gfw.memoryMB')">
            <div class="field">
              <div class="num-row">
                <el-input-number
                  v-model="cfg.memoryMB"
                  :min="1"
                  :max="limits.maxMemoryMB"
                  :step="1"
                  style="width: 130px"
                />
                <span class="unit">MB</span>
              </div>
              <p class="field-hint">{{ t('gfw.memoryHint') }}</p>
            </div>
          </el-form-item>
        </el-form>

        <!-- 保存行：缩进到与上面各输入框同一列（标签列宽度见 labelWidth），说明在按钮下方。
             不放进 el-form 里做一个空标签的 form-item：那会渲染出一个空的 <label>，
             读屏软件会念出一个没有内容的标签。 -->
        <div class="save-row" :style="{ paddingLeft: contentIndent }">
          <el-button type="primary" :loading="saving" @click="save">{{ t('common.save') }}</el-button>
          <p class="field-hint save-hint">{{ t('gfw.saveHint') }}</p>
        </div>
        <el-divider />

        <!-- 来源自检：复用实时封禁数据，作为「服务防护确实看到了真实来源 IP 并已在拦截」的信号。 -->
        <div class="selfcheck">
          <div class="sc-title">{{ t('gfw.selfCheck') }}</div>
          <p class="field-hint">{{ t('gfw.selfCheckHint') }}</p>
          <template v-if="banTotal > 0">
            <p class="field-hint">{{ t('gfw.selfCheckActive', { n: banTotal }) }}</p>
            <div class="sc-list">
              <div v-for="b in bans.slice(0, 5)" :key="b.ip" class="sc-item">
                <span class="sc-ip">{{ b.ip }}</span>
                <span class="field-hint">{{ t('gfw.banColBannedAt') }} {{ fmtTime(b.bannedAt) }}</span>
              </div>
            </div>
          </template>
          <p v-else class="field-hint">{{ t('gfw.selfCheckEmpty') }}</p>
        </div>
      </div>

      <!-- 白名单 -->
      <div v-show="activeTab === 'allow'">
        <el-form :label-width="labelWidth" :label-position="labelPos">
          <el-form-item :label="t('gfw.allowIps')">
            <div class="field">
              <el-input
                v-model="allowText"
                type="textarea"
                :rows="8"
                :placeholder="t('gfw.ipsPlaceholder')"
                style="width: 440px; max-width: 100%"
              />
              <p class="field-hint">{{ t('gfw.allowHint', { max: limits.maxIps }) }}</p>
            </div>
          </el-form-item>
        </el-form>
        <div class="save-row" :style="{ paddingLeft: contentIndent }">
          <el-button type="primary" :loading="saving" @click="save">{{ t('common.save') }}</el-button>
          <p class="field-hint save-hint">{{ t('gfw.saveHint') }}</p>
        </div>
      </div>

      <!-- 黑名单 -->
      <div v-show="activeTab === 'deny'">
        <el-form :label-width="labelWidth" :label-position="labelPos">
          <el-form-item :label="t('gfw.denyIps')">
            <div class="field">
              <el-input
                v-model="denyText"
                type="textarea"
                :rows="8"
                :placeholder="t('gfw.ipsPlaceholder')"
                style="width: 440px; max-width: 100%"
              />
              <p class="field-hint">{{ t('gfw.denyHint') }}</p>
            </div>
          </el-form-item>
        </el-form>
        <div class="save-row" :style="{ paddingLeft: contentIndent }">
          <el-button type="primary" :loading="saving" @click="save">{{ t('common.save') }}</el-button>
          <p class="field-hint save-hint">{{ t('gfw.saveHint') }}</p>
        </div>
      </div>

      <!-- 自动封禁 -->
      <div v-show="activeTab === 'bans'">
        <div class="metrics">
          <div class="metric"><b>{{ banTotal }}</b><span>{{ t('gfw.banActive') }}</span></div>
          <div class="metric"><b>{{ fmtBytes(memUsedBytes) }}</b><span>{{ t('gfw.banMemoryUsed') }}</span></div>
          <div class="metric"><b>{{ memLimitMB }} MB</b><span>{{ t('gfw.banMemoryLimit') }}</span></div>
        </div>
        <div class="storage-bar" style="margin: 14px 0">
          <el-button :loading="bansLoading" @click="loadBans">{{ t('common.refresh') }}</el-button>
          <el-button type="danger" :disabled="bans.length === 0" @click="clearBans">{{ t('gfw.banClearAll') }}</el-button>
          <span class="field-hint">
            {{ t('gfw.banTotal', { n: banTotal }) }}
            <template v-if="banTotal > bans.length">{{ t('gfw.banTruncated', { n: bans.length }) }}</template>
          </span>
        </div>
        <el-empty
          v-if="!bansLoading && bans.length === 0"
          :description="t('gfw.banEmpty')"
          :image-size="60"
        />
        <div v-else class="ban-list">
          <div v-for="b in bans" :key="b.ip" class="ban-row">
            <span class="ban-ip">{{ b.ip }}</span>
            <span class="field-hint">{{ t('gfw.banColBannedAt') }} {{ fmtTime(b.bannedAt) }}</span>
            <el-tag v-if="b.rounds > 1" size="small" type="warning" disable-transitions>
              {{ t('gfw.banColCount') }} {{ b.rounds }}
            </el-tag>
            <span class="field-hint">{{ t('gfw.banColUntil') }} {{ fmtTime(b.until) }}</span>
            <el-button link type="primary" @click="unban(b.ip)">{{ t('gfw.banUnban') }}</el-button>
          </div>
        </div>
      </div>

      <!-- 详细说明：始终可见，与所属标签页无关（与 mockup 一致，放在标签页内容之外）。 -->
      <el-divider />
      <div class="callout">
        <h4>{{ t('gfw.explainTitle') }}</h4>
        <ul>
          <li>{{ t('gfw.explainWhat') }}</li>
          <li>{{ t('gfw.explainModules') }}</li>
          <li>{{ t('gfw.explainVsPanel') }}</li>
          <li>{{ t('gfw.explainDefends') }}</li>
          <li>{{ t('gfw.explainNotDefends') }}</li>
          <li>{{ t('gfw.explainOrder') }}</li>
        </ul>
      </div>
    </div>
  </PageCard>
</template>

<style scoped>
.brief {
  color: var(--mt-text-soft);
  font-size: 13px;
  margin: 0 0 14px;
}
.hd-switch {
  display: flex;
  align-items: center;
  gap: 8px;
}
.sw-label {
  color: var(--mt-text-soft);
  font-size: 13px;
}
/* 字段容器：控件在上、灰色说明在下，纵向排列。
 *
 * 这一层是"说明不许贴在输入框右边"的实现：el-form-item 的内容区本身是
 * display:flex 的一行，说明直接放进去就成了控件右侧的兄弟节点，既把行撑高、
 * 让右置标签看起来与输入框错位，又在窄屏上把输入框挤成一条缝。
 * width:100% 让它吃满内容区，align-items:flex-start 保证控件不被拉伸。 */
.field {
  display: flex;
  flex-direction: column;
  align-items: flex-start;
  gap: 6px;
  width: 100%;
}
/* 灰色小字说明。统一用这一个类，不再用没有定义过的 .hint
 * （原先写的是 class="mt-subtle hint"，而 .hint 在本文件与全局样式里都不存在，
 * 于是说明与正文同样大小，看着像正文而不是注解）。 */
.field-hint {
  display: block;
  margin: 0;
  font-size: 12px;
  line-height: 1.6;
  color: var(--mt-text-subtle, #909399);
}
/* 数值行：输入框与单位同一行，纵向居中。 */
.num-row {
  display: flex;
  align-items: center;
  gap: 8px;
  flex-wrap: wrap;
}
.num-row .unit {
  color: var(--mt-text-soft);
  font-size: 13px;
}
/* 保存行：缩进到与上面各输入框同一列（内联样式给 padding-left = 标签列宽），
 * 说明在按钮下方而不是右边。 */
.save-row {
  margin-top: 4px;
  display: flex;
  flex-direction: column;
  align-items: flex-start;
  gap: 6px;
}
.save-hint {
  margin: 0;
}
.selfcheck {
  border: 1px dashed var(--mt-border, #dcdfe6);
  border-radius: var(--mt-card-radius, 14px);
  padding: 12px 14px;
  background: var(--mt-bg-soft, #fafafa);
}
.sc-title {
  font-weight: 600;
  margin-bottom: 4px;
}
.sc-list {
  margin-top: 8px;
  display: flex;
  flex-direction: column;
  gap: 6px;
}
.sc-item {
  display: flex;
  align-items: center;
  gap: 12px;
  font-size: 13px;
}
.sc-ip {
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  color: var(--mt-text);
}
.metrics {
  display: flex;
  gap: 12px;
  flex-wrap: wrap;
}
.metric {
  display: inline-flex;
  flex-direction: column;
  gap: 4px;
  border: 1px solid var(--mt-border, #ebeef5);
  border-radius: var(--mt-card-radius, 14px);
  padding: 14px 18px;
  min-width: 150px;
  background: var(--mt-bg-soft, #f5f7fa);
}
.metric b {
  font-size: 20px;
  color: var(--mt-text);
}
.metric span {
  font-size: 12px;
  color: var(--mt-text-soft);
}
.storage-bar {
  display: flex;
  align-items: center;
  gap: 10px;
  flex-wrap: wrap;
}
.ban-list {
  display: flex;
  flex-direction: column;
  gap: 8px;
}
.ban-row {
  display: flex;
  align-items: center;
  gap: 14px;
  flex-wrap: wrap;
  padding: 8px 12px;
  border: 1px solid var(--mt-border, #ebeef5);
  border-radius: var(--mt-card-radius, 14px);
}
.ban-ip {
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  color: var(--mt-text);
  font-weight: 600;
}
/* 详细说明卡片：与 mockup 一致的蓝色提示框。 */
.callout {
  border: 1px solid color-mix(in srgb, var(--mt-primary) 35%, transparent);
  background: color-mix(in srgb, var(--mt-primary) 8%, transparent);
  border-radius: var(--mt-card-radius, 14px);
  padding: 14px 16px;
}
.callout h4 {
  margin: 0 0 8px;
  color: var(--mt-primary);
  font-size: 14px;
}
.callout ul {
  margin: 6px 0 0;
  padding-left: 18px;
  color: var(--mt-text-soft);
  font-size: 13px;
}
.callout li {
  margin: 6px 0;
  line-height: 1.6;
}
</style>
