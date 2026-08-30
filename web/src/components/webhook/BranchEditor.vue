<script setup lang="ts">
import { computed } from 'vue'
import { useI18n } from 'vue-i18n'
import { Plus, Delete, ArrowUp, ArrowDown, CopyDocument } from '@element-plus/icons-vue'
import ConditionEditor from './ConditionEditor.vue'
import type { MessageTemplate, NotifyTarget, RuleBranch } from '@/api/webhook'

// 输出分支编辑器：一条规则的多个出口。
//
// 两层条件的分工必须在界面上看得出来，否则用户会把规则条件在每个分支里重抄一遍：
//   规则条件 = 总条件，粗筛"这条消息与这条规则有关吗"
//   分支条件 = 在总条件之上再筛，决定"这一条走哪个出口"
// 所以分支标题旁写的是"在规则条件成立的前提下"，而不是只写"条件"。
//
// 顺序可调：选了「命中即停」之后，谁在前面谁优先。没做拖拽是刻意的——
// 10 条以内上下移动比拖拽更准，也不引入拖拽库。

const props = defineProps<{
  modelValue: RuleBranch[]
  operators: string[]
  countOperators?: string[]
  paths?: string[]
  templates: MessageTemplate[]
  targets: NotifyTarget[]
  // maxConditions 单个分支里的条件数上限，与规则本体同一个限额。
  maxConditions: number
  // max 分支数上限（后端 config.MaxWebhookBranches，经 meta.limits 下发）。
  max: number
  // fallbackNames 接收器的兜底目标名，用于"这个分支没选目标"时把话说全。
  fallbackNames: string
}>()
const emit = defineEmits<{ (e: 'update:modelValue', v: RuleBranch[]): void }>()

const { t } = useI18n()

const list = computed(() => props.modelValue || [])
const full = computed(() => list.value.length >= props.max)

function commit(next: RuleBranch[]) {
  emit('update:modelValue', next)
}
function patch(i: number, key: keyof RuleBranch, v: any) {
  const next = list.value.slice()
  next[i] = { ...next[i], [key]: v }
  commit(next)
}

// 新分支刻意**不带条件**：带条件的新分支一存就报"路径不能为空"，
// 而用户此刻想做的只是"先加一个出口，再想清楚它筛什么"。
function add() {
  if (full.value) return
  commit([
    ...list.value,
    { name: t('mroute.rule.branchNameN', { n: list.value.length + 1 }), match: 'all', conditions: [], templateRef: '', targets: [] },
  ])
}
// 复制一个分支：相邻分支往往只差一个条件值和一个目标，从空白重配一遍纯属重复劳动。
function dup(i: number) {
  if (full.value) return
  const src = JSON.parse(JSON.stringify(list.value[i])) as RuleBranch
  src.name = t('mroute.rule.copyName', { name: src.name || '' }).trim()
  const next = list.value.slice()
  next.splice(i + 1, 0, src)
  commit(next)
}
function removeAt(i: number) {
  const next = list.value.slice()
  next.splice(i, 1)
  commit(next)
}
function move(i: number, delta: number) {
  const j = i + delta
  if (j < 0 || j >= list.value.length) return
  const next = list.value.slice()
  ;[next[i], next[j]] = [next[j], next[i]]
  commit(next)
}

function targetLabel(id: string): string {
  const hit = props.targets.find((x) => x.id === id)
  if (!hit) return id
  return hit.enabled ? hit.name : `${hit.name}（${t('common.disabled')}）`
}

// ---- 就地校验：这三件事后端保存时都会拦，提前说出来省一次"保存失败"的往返 ----

const noName = computed(() => list.value.some((b) => !(b.name || '').trim()))
// 同名分支在执行历史里长得一模一样（都写成「规则名 / 分支名」），排查时分不出是哪个出口。
const dupNames = computed(() => {
  const seen = new Set<string>()
  const bad = new Set<string>()
  for (const b of list.value) {
    const n = (b.name || '').trim()
    if (!n) continue
    if (seen.has(n)) bad.add(n)
    seen.add(n)
  }
  return [...bad]
})
function isDupName(b: RuleBranch): boolean {
  return dupNames.value.includes((b.name || '').trim())
}
const noTemplate = computed(() => list.value.some((b) => !b.templateRef))

// 每个分支都带条件 = 这条规则没有兜底出口。消息可能命中了规则、却一个分支都不成立，
// 于是什么都发不出去（后端记成「命中了规则，但没有任何输出分支的条件成立」）。
// 这是多分支独有的一种"配好了却收不到"，必须在配的时候就说，而不是等上线后去翻历史。
const noCatchAll = computed(
  () => list.value.length > 0 && list.value.every((b) => (b.conditions || []).length > 0),
)
</script>

<template>
  <div class="branches">
    <div v-for="(b, i) in list" :key="i" class="branch">
      <div class="b-head">
        <span class="b-no">{{ i + 1 }}</span>
        <el-input
          :model-value="b.name"
          :placeholder="t('mroute.rule.branchNamePlaceholder')"
          class="b-name"
          :class="{ 'is-bad': !(b.name || '').trim() || isDupName(b) }"
          @update:model-value="(v: string) => patch(i, 'name', v)"
        />
        <el-radio-group
          :model-value="b.match || 'all'"
          size="small"
          @update:model-value="(v: any) => patch(i, 'match', v)"
        >
          <el-radio-button value="all">{{ t('mroute.rule.matchAll') }}</el-radio-button>
          <el-radio-button value="any">{{ t('mroute.rule.matchAny') }}</el-radio-button>
        </el-radio-group>
        <span class="grow" />
        <el-tooltip :content="t('mroute.rule.branchUp')" placement="top">
          <el-button :icon="ArrowUp" size="small" text :disabled="i === 0" @click="move(i, -1)" />
        </el-tooltip>
        <el-tooltip :content="t('mroute.rule.branchDown')" placement="top">
          <el-button
            :icon="ArrowDown"
            size="small"
            text
            :disabled="i === list.length - 1"
            @click="move(i, 1)"
          />
        </el-tooltip>
        <el-tooltip :content="t('mroute.rule.branchDup')" placement="top">
          <el-button :icon="CopyDocument" size="small" text :disabled="full" @click="dup(i)" />
        </el-tooltip>
        <el-tooltip :content="t('common.delete')" placement="top">
          <el-button :icon="Delete" size="small" text type="danger" @click="removeAt(i)" />
        </el-tooltip>
      </div>

      <div class="b-label">{{ t('mroute.rule.branchCond') }}</div>
      <ConditionEditor
        :model-value="b.conditions || []"
        :operators="operators"
        :count-operators="countOperators"
        :paths="paths"
        :max="maxConditions"
        @update:model-value="(v: any) => patch(i, 'conditions', v)"
      />
      <!-- 不带条件的分支在这一层永远成立，是这条规则的兜底出口。说清楚，
           别让人以为"忘了填条件"而去补一个把兜底堵死的条件。 -->
      <div v-if="!(b.conditions || []).length" class="mt-subtle tip">
        {{ t('mroute.rule.branchCatchAll') }}
      </div>

      <div class="b-grid">
        <div>
          <div class="b-label">{{ t('mroute.rule.template') }}</div>
          <el-select
            :model-value="b.templateRef"
            style="width: 100%"
            :class="{ 'is-bad': !b.templateRef }"
            :placeholder="t('mroute.rule.branchTemplatePlaceholder')"
            @update:model-value="(v: any) => patch(i, 'templateRef', v)"
          >
            <el-option v-for="tp in templates" :key="tp.id" :label="tp.name" :value="tp.id!" />
          </el-select>
        </div>
        <div>
          <div class="b-label">{{ t('mroute.rule.targets') }}</div>
          <el-select
            :model-value="b.targets || []"
            multiple
            collapse-tags
            collapse-tags-tooltip
            style="width: 100%"
            :placeholder="t('mroute.rule.targetsPlaceholder')"
            @update:model-value="(v: any) => patch(i, 'targets', v)"
          >
            <el-option v-for="tg in targets" :key="tg.id" :label="targetLabel(tg.id!)" :value="tg.id!" />
          </el-select>
        </div>
      </div>
      <!-- 与单输出同一个道理：留空不是"不发"，而是跟着接收器的兜底目标发。 -->
      <div v-if="!(b.targets || []).length && fallbackNames" class="mt-subtle tip">
        {{ t('mroute.rule.usingFallback', { names: fallbackNames }) }}
      </div>
      <div v-else-if="!(b.targets || []).length" class="mt-danger-text tip">
        {{ t('mroute.rule.noTargetWarn') }}
      </div>
    </div>

    <div class="b-foot">
      <el-button size="small" :icon="Plus" :disabled="full" @click="add">
        {{ t('mroute.rule.branchAdd') }}
      </el-button>
      <span v-if="full" class="mt-subtle tip">{{ t('mroute.rule.branchLimit', { n: max }) }}</span>
      <span v-else-if="!list.length" class="mt-subtle tip">{{ t('mroute.rule.branchEmpty') }}</span>
    </div>

    <div v-if="noName" class="mt-danger-text tip">{{ t('mroute.rule.branchNameRequired') }}</div>
    <div v-if="dupNames.length" class="mt-danger-text tip">
      {{ t('mroute.rule.branchNameDup', { names: dupNames.join('、') }) }}
    </div>
    <div v-if="noTemplate" class="mt-danger-text tip">{{ t('mroute.rule.branchTemplateRequired') }}</div>
    <div v-if="noCatchAll" class="mt-warn-text tip">{{ t('mroute.rule.branchNoCatchAll') }}</div>
  </div>
</template>

<style scoped>
.branch {
  border: 1px solid var(--mt-border, rgba(20, 27, 45, 0.12));
  border-radius: 8px;
  padding: 10px 12px 12px;
  margin-bottom: 12px;
}
.b-head {
  display: flex;
  align-items: center;
  gap: 8px;
  margin-bottom: 10px;
}
.grow {
  flex: 1;
}
/* 分支序号：选了「命中即停」之后这个数字就是优先级，得看得见。 */
.b-no {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  width: 20px;
  height: 20px;
  flex: none;
  border-radius: 50%;
  font-size: 11px;
  font-weight: 700;
  color: #fff;
  background: var(--mt-primary);
}
.b-name {
  width: 190px;
  flex: none;
}
.b-label {
  font-size: 12px;
  color: var(--el-text-color-regular);
  margin-bottom: 4px;
}
.b-grid {
  display: grid;
  grid-template-columns: minmax(0, 1fr) minmax(0, 1.2fr);
  gap: 12px;
  margin-top: 10px;
}
.b-foot {
  display: flex;
  align-items: center;
  gap: 10px;
}
.tip {
  font-size: 12px;
  margin-top: 4px;
  line-height: 1.6;
}
.mt-danger-text {
  color: var(--mt-danger, #f56c6c);
}
.is-bad :deep(.el-input__wrapper),
.is-bad :deep(.el-select__wrapper) {
  box-shadow: 0 0 0 1px var(--el-color-danger) inset;
}

/* 窄屏：两栏各不足 240 像素时，里面选择框的中文选项要被截断，改成上下排。
 * 560 这一档与「程序信息」页的三栏用的是同一个数。 */
@media (max-width: 560px) {
  .b-grid {
    grid-template-columns: minmax(0, 1fr);
  }
}
</style>
