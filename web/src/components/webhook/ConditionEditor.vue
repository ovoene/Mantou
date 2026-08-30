<script setup lang="ts">
import { computed } from 'vue'
import { useI18n } from 'vue-i18n'
import { Plus, Delete } from '@element-plus/icons-vue'
import type { Condition } from '@/api/webhook'

// 条件编辑器：一条「取值路径 + 算子 + 比较值 + 取反」。
//
// 算子清单由后端下发（meta.operators），界面不自己维护一份：漏一个算子
// 用户就永远配不出那种条件，而这种缺失在界面上完全看不出来。

const props = defineProps<{
  modelValue: Condition[]
  operators: string[]
  // countOperators 比"取到几个值"的算子（如 数量大于）。比较值必须是数字，
  // 且要和值比较的「大于」分开摆——两者中文名只差两个字，混在一个列表里必然选错。
  countOperators?: string[]
  // paths 候选取值路径，来自样本载荷解析出的字段树；用于输入框的补全提示。
  paths?: string[]
  max: number
  disabled?: boolean
}>()
const emit = defineEmits<{ (e: 'update:modelValue', v: Condition[]): void }>()

const { t } = useI18n()

// 不需要比较值的算子：有没有值本身就是判断结果。
const NO_VALUE_OPS = ['exists', 'empty']
function needsValue(op: string): boolean {
  return !NO_VALUE_OPS.includes(op)
}

const countOps = computed(() => props.countOperators || [])
const valueOps = computed(() => props.operators.filter((op) => !countOps.value.includes(op)))
function isCount(op: string): boolean {
  return countOps.value.includes(op)
}
// 空路径的条件永远不成立（后端 lookupAll 对空路径不返回任何值），
// 而它看起来只是"还没填完"，所以必须当场标红——后端保存时也会拦。
const hasEmptyPath = computed(() => list.value.some((c) => !(c.path || '').trim()))

const list = computed(() => props.modelValue || [])
const full = computed(() => list.value.length >= props.max)

function opLabel(op: string): string {
  const key = `mroute.op.${op}`
  const s = t(key)
  return s === key ? op : s
}

function add() {
  if (full.value || props.disabled) return
  emit('update:modelValue', [...list.value, { path: '', op: 'eq', value: '', not: false }])
}
function removeAt(i: number) {
  if (props.disabled) return
  const next = list.value.slice()
  next.splice(i, 1)
  emit('update:modelValue', next)
}
function patch(i: number, key: keyof Condition, v: any) {
  const next = list.value.slice()
  next[i] = { ...next[i], [key]: v }
  emit('update:modelValue', next)
}

// el-autocomplete 的取词回调：按已输入片段过滤候选路径。
function suggest(q: string, cb: (items: { value: string }[]) => void) {
  const all = props.paths || []
  const kw = (q || '').toLowerCase()
  const hit = kw ? all.filter((p) => p.toLowerCase().includes(kw)) : all
  cb(hit.slice(0, 30).map((value) => ({ value })))
}
</script>

<template>
  <div class="cond-editor">
    <div v-for="(c, i) in list" :key="i" class="cond-row">
      <el-autocomplete
        :model-value="c.path"
        :fetch-suggestions="suggest"
        :placeholder="t('mroute.cond.pathPlaceholder')"
        :disabled="disabled"
        class="c-path"
        :class="{ 'is-bad': !(c.path || '').trim() }"
        @update:model-value="(v: string) => patch(i, 'path', v)"
      />
      <el-select
        :model-value="c.op"
        :disabled="disabled"
        class="c-op"
        @update:model-value="(v: string) => patch(i, 'op', v)"
      >
        <el-option-group v-if="countOps.length" :label="t('mroute.cond.groupValue')">
          <el-option v-for="op in valueOps" :key="op" :label="opLabel(op)" :value="op" />
        </el-option-group>
        <el-option-group v-if="countOps.length" :label="t('mroute.cond.groupCount')">
          <el-option v-for="op in countOps" :key="op" :label="opLabel(op)" :value="op" />
        </el-option-group>
        <el-option v-for="op in operators" v-else :key="op" :label="opLabel(op)" :value="op" />
      </el-select>
      <el-input
        v-if="needsValue(c.op)"
        :model-value="c.value"
        :type="isCount(c.op) ? 'number' : 'text'"
        :placeholder="
          isCount(c.op)
            ? t('mroute.cond.countPlaceholder')
            : c.op === 'in'
              ? t('mroute.cond.inPlaceholder')
              : t('mroute.cond.valuePlaceholder')
        "
        :disabled="disabled"
        class="c-val"
        @update:model-value="(v: string) => patch(i, 'value', v)"
      />
      <span v-else class="c-val mt-subtle no-val">{{ t('mroute.cond.noValueNeeded') }}</span>
      <el-tooltip :content="t('mroute.cond.notHint')" placement="top">
        <el-checkbox
          :model-value="c.not"
          :disabled="disabled"
          class="c-not"
          @update:model-value="(v: any) => patch(i, 'not', !!v)"
        >
          {{ t('mroute.cond.not') }}
        </el-checkbox>
      </el-tooltip>
      <el-button :icon="Delete" text type="danger" :disabled="disabled" @click="removeAt(i)" />
    </div>

    <div class="cond-foot">
      <el-button size="small" :icon="Plus" :disabled="disabled || full" @click="add">
        {{ t('mroute.cond.add') }}
      </el-button>
      <span v-if="!list.length" class="mt-subtle tip">{{ t('mroute.cond.emptyMeansAlways') }}</span>
      <span v-else-if="full" class="mt-subtle tip">{{ t('mroute.cond.limit', { n: max }) }}</span>
    </div>
    <div v-if="hasEmptyPath" class="mt-danger-text tip">{{ t('mroute.cond.pathRequired') }}</div>
    <div v-if="list.some((c) => isCount(c.op))" class="mt-subtle tip">{{ t('mroute.cond.countHint') }}</div>
  </div>
</template>

<style scoped>
.cond-row {
  display: grid;
  grid-template-columns: minmax(140px, 1.4fr) 130px minmax(120px, 1.2fr) auto auto;
  align-items: center;
  gap: 8px;
  margin-bottom: 8px;
}
.no-val {
  font-size: 12px;
  padding-left: 2px;
}
.c-not {
  margin-right: 0;
}
.cond-foot {
  display: flex;
  align-items: center;
  gap: 10px;
}
.tip {
  font-size: 12px;
}
/* 同样必须绕一层 .cond-row 再 :deep：is-bad 挂在 el-autocomplete 的根节点上，
 * 那个节点拿不到本组件的 scoped 标记，`.is-bad :deep(...)` 编译出来永不生效。 */
.cond-row :deep(.is-bad .el-input__wrapper) {
  box-shadow: 0 0 0 1px var(--el-color-danger) inset;
}
.mt-danger-text {
  color: var(--mt-danger, #f56c6c);
}

/* 窄屏：一行五格的硬下限约 500 像素（路径 140 + 算子 130 + 取值 120 + 取反 50
 * + 删除 32，再加四道 8 的间距），而弹窗最宽只有 94vw，600 像素上下就开始在弹窗里
 * 横向溢出。640 这一档改成三行：路径独占一行，算子与取值并排，取反与删除收在末行。 */
@media (max-width: 640px) {
  .cond-row {
    grid-template-columns: minmax(0, 1fr) minmax(0, 1fr);
  }
  /* 用 :deep 是必须的：el-autocomplete 的根节点是 el-tooltip 的触发元素，
   * 拿不到本组件的 scoped 标记，写成 .c-path 这条规则就成了永不生效的死样式。 */
  .cond-row > :deep(.c-path) {
    grid-column: 1 / -1;
  }
  /* 删除按钮在半格宽的格子里会被拉满，靠右收住。 */
  .cond-row > :last-child {
    justify-self: end;
  }
}
</style>
