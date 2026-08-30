<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import { ElMessage, ElMessageBox } from 'element-plus'
import ConditionEditor from './ConditionEditor.vue'
import BranchEditor from './BranchEditor.vue'
import FieldTree from './FieldTree.vue'
import { buildFieldTree, collectPaths, parseSample } from '@/composables/fieldPaths'
import type {
  MessageTemplate,
  NotifyTarget,
  RuleBranch,
  WebhookMeta,
  WebhookReceiver,
  WebhookRule,
} from '@/api/webhook'

// 一条发送规则的编辑器。
//
// 一条规则读起来就是「哪个入口进来的 → 什么情况 → 长什么样 → 发给谁」，
// 所以这里刻意不做页签、就是一条竖着往下走的表单，四段各自带序号：
// 用户从上读到下就是一次完整的决策，不需要在几个页签之间来回对照。
//
// 第 3、4 段有两种形态，由「多分支发送」开关切换：
//   关（默认，也是所有老规则的形态）  一个模板 + 一批目标
//   开                                若干个分支，各自「附加条件 + 模板 + 目标」
// 第 2 段的条件在两种形态下都是**总条件**：数据先过它，过了才进分支细分。
// 这个先后关系写在开关下面那句提示里——不说清楚，用户会把总条件在每个分支里重抄一遍。
//
// 右栏是字段树。它按**所选接收器**的解析设置解那份通用样本载荷（试运行抓到的那一条），
// 因为"有哪些字段可以判断"完全取决于消息从哪个入口进来、按什么类型解——
// 换一个接收器，能用的字段就是另一套。

const props = defineProps<{
  visible: boolean
  // model 编辑中的草稿：规则本体 + 它归哪个接收器。receiverId 是可改的，
  // 选错接收器之后的出路不该是"删掉、去另一个接收器下把条件重配一遍"。
  model: WebhookRule & { receiverId: string }
  isNew: boolean
  saving: boolean
  meta: WebhookMeta | null
  receivers: WebhookReceiver[]
  templates: MessageTemplate[]
  targets: NotifyTarget[]
  // sample 通用样本载荷（试运行抓到的最新一条，或用户自己贴的），用来列可用字段。
  sample: string
}>()
const emit = defineEmits<{
  (e: 'update:visible', v: boolean): void
  (e: 'save'): void
}>()

const { t } = useI18n()

const limits = computed(() => props.meta?.limits || {})
const operators = computed(() => props.meta?.operators || [])
const countOperators = computed(() => props.meta?.countOperators || [])

const receiver = computed(() => props.receivers.find((r) => r.id === props.model.receiverId) || null)
// 样本按所选接收器的设置解：同一段文本在 JSON 与键值文本两种类型下拆出的字段完全不同。
const nodes = computed(() => buildFieldTree(parseSample(props.sample, receiver.value || undefined)))
const paths = computed(() => collectPaths(nodes.value))

function targetLabel(id: string): string {
  const hit = props.targets.find((x) => x.id === id)
  if (!hit) return id
  return hit.enabled ? hit.name : `${hit.name}（${t('common.disabled')}）`
}

// 这条规则没选目标时会回落到接收器的兜底目标；两处都空就是一条永远发不出去的规则，
// 后端保存时会拦。这里提前把话说清楚，省一次"保存失败"的往返。
const fallback = computed(() => receiver.value?.defaultTargets || [])
const noTargetAtAll = computed(() => (props.model.targets || []).length === 0 && fallback.value.length === 0)
const fallbackNames = computed(() => fallback.value.map(targetLabel).join(' / '))

// 高级折叠区。弹窗关闭时并不销毁，不受控的 el-collapse 会把展开状态留到下一次打开，
// 于是"默认折叠"只在第一次成立。每次打开都归零。
const advOpen = ref<string[]>([])
watch(
  () => props.visible,
  (v) => {
    if (v) advOpen.value = []
  },
)

// ---- 多分支 ----
//
// 开关的真值就是"有没有分支"，不额外存一个布尔：多一个字段就多一种矛盾状态
// （开关开着但分支为空、或开关关着却存着分支），而运行期只看 branches 这一个东西。
const multi = computed(() => (props.model.branches || []).length > 0)

// toggleMulti 开 / 关多分支。
//
// 开：把当前这一组「模板 + 目标」原样搬成第一个分支，不带附加条件——
// 于是它在分支这一层永远成立，行为与开关之前**完全一致**（消息照旧按老样子发出去），
// 用户接着加第二个分支就行。这是"把当前输出转成第一个分支"那个一键动作，
// 直接挂在开关上：单独放一个按钮的话，用户开了开关先看到一片空白，
// 会以为原来配好的模板和目标被弄丢了。
//
// 关：要毁掉用户配的东西，所以必须先问。第一个分支的模板与目标搬回规则本体，
// 其余分支连同它们的条件一起丢掉——毕竟单输出装不下第二个出口。
async function toggleMulti(on: boolean) {
  if (on) {
    props.model.branches = [
      {
        name: t('mroute.rule.branchNameN', { n: 1 }),
        match: 'all',
        conditions: [],
        templateRef: props.model.templateRef || '',
        targets: [...(props.model.targets || [])],
      },
    ]
    return
  }
  const list = props.model.branches || []
  if (list.length > 1) {
    try {
      await ElMessageBox.confirm(
        t('mroute.rule.multiOffConfirm', { n: list.length - 1, name: list[0]?.name || '' }),
        t('mroute.rule.multiOffTitle'),
        { type: 'warning', confirmButtonText: t('common.confirm'), cancelButtonText: t('common.cancel') },
      )
    } catch {
      return // 用户取消：什么都不动，开关自己会弹回去（它绑的是 multi 这个计算值）
    }
  }
  const first = list[0]
  if (first) {
    props.model.templateRef = first.templateRef || ''
    props.model.targets = [...(first.targets || [])]
  }
  props.model.branches = []
  props.model.firstBranchOnly = false
}

function setBranches(v: RuleBranch[]) {
  props.model.branches = v
}

async function copy(text: string) {
  try {
    await navigator.clipboard.writeText(text)
    ElMessage.success(t('mroute.copied'))
  } catch {
    // 非 HTTPS 页面下 clipboard 不可用，此时提示用户手动复制而不是静默失败。
    ElMessage.warning(t('mroute.copyFail'))
  }
}
</script>

<template>
  <el-dialog
    :model-value="visible"
    :title="isNew ? t('mroute.rule.add') : t('mroute.rule.edit')"
    width="min(1040px, 94vw)"
    append-to-body
    :close-on-click-modal="false"
    @update:model-value="(v: boolean) => emit('update:visible', v)"
  >
    <div class="two-col">
      <el-form label-position="top">
        <div class="grid4">
          <el-form-item :label="t('mroute.rule.name')">
            <el-input v-model="model.name" :placeholder="t('mroute.rule.namePlaceholder')" />
          </el-form-item>
          <el-form-item :label="t('mroute.rule.priority')">
            <el-input-number v-model="model.priority" :min="0" :max="9999" style="width: 100%" />
          </el-form-item>
          <el-form-item :label="t('common.status')">
            <el-switch v-model="model.enabled" />
          </el-form-item>
        </div>
        <div class="mt-subtle pull-up hint">{{ t('mroute.rule.priorityHint') }}</div>

        <el-divider content-position="left">
          <span class="step">1</span>{{ t('mroute.rule.stepFrom') }}
        </el-divider>
        <el-form-item :label="t('mroute.rule.receiver')">
          <el-select v-model="model.receiverId" style="width: 100%">
            <el-option
              v-for="rc in receivers"
              :key="rc.id"
              :label="rc.enabled ? rc.name : `${rc.name}（${t('common.disabled')}）`"
              :value="rc.id!"
            />
          </el-select>
          <div class="mt-subtle hint">{{ t('mroute.rule.receiverHint') }}</div>
        </el-form-item>

        <el-divider content-position="left">
          <span class="step">2</span>{{ t('mroute.rule.stepWhen') }}
        </el-divider>
        <el-form-item :label="t('mroute.rule.match')">
          <el-radio-group v-model="model.match">
            <el-radio-button value="all">{{ t('mroute.rule.matchAll') }}</el-radio-button>
            <el-radio-button value="any">{{ t('mroute.rule.matchAny') }}</el-radio-button>
          </el-radio-group>
        </el-form-item>
        <el-form-item :label="t('mroute.rule.conditions')">
          <ConditionEditor
            v-model="model.conditions"
            :operators="operators"
            :count-operators="countOperators"
            :paths="paths"
            :max="limits.conditions || 20"
          />
          <div class="mt-subtle hint">
            {{ multi ? t('mroute.rule.conditionsHintMulti') : t('mroute.rule.conditionsHint') }}
          </div>
        </el-form-item>

        <el-divider content-position="left">
          <span class="step">3</span>{{ multi ? t('mroute.rule.stepBranch') : t('mroute.rule.stepRender') }}
        </el-divider>
        <el-form-item :label="t('mroute.rule.multi')">
          <el-switch :model-value="multi" @update:model-value="(v: any) => toggleMulti(!!v)" />
          <span class="mt-subtle hint inline">{{ t('mroute.rule.multiHint') }}</span>
        </el-form-item>

        <!-- 多分支：第 3、4 段合成这一块。分支自己带着模板与目标，
             再把「渲染成什么」「发给哪些目标」分成两段就得让用户在两处对照同一个分支。 -->
        <template v-if="multi">
          <el-alert type="info" :closable="false" class="two-layer">
            <div>{{ t('mroute.rule.twoLayer') }}</div>
          </el-alert>
          <BranchEditor
            :model-value="model.branches || []"
            :operators="operators"
            :count-operators="countOperators"
            :paths="paths"
            :templates="templates"
            :targets="targets"
            :max-conditions="limits.conditions || 20"
            :max="limits.branches || 10"
            :fallback-names="fallbackNames"
            @update:model-value="setBranches"
          />
          <!-- 用两个具名选项而不是开关：默认那一侧也有名字，省得人以为"没开=没配"。 -->
          <el-form-item :label="t('mroute.rule.firstBranchOnly')">
            <el-radio-group
              :model-value="!!model.firstBranchOnly"
              @update:model-value="(v: any) => (model.firstBranchOnly = !!v)"
            >
              <el-radio-button :value="false">{{ t('mroute.rule.firstBranchOnlyAll') }}</el-radio-button>
              <el-radio-button :value="true">{{ t('mroute.rule.firstBranchOnlyFirst') }}</el-radio-button>
            </el-radio-group>
            <span class="mt-subtle hint inline">
              {{
                model.firstBranchOnly
                  ? t('mroute.rule.firstBranchOnlyOn')
                  : t('mroute.rule.firstBranchOnlyOff')
              }}
            </span>
            <!-- 这句两种选法下都要在：它回答的正是"两句读起来都像我想要的，到底选哪个"。 -->
            <div class="mt-subtle hint full">{{ t('mroute.rule.firstBranchOnlySame') }}</div>
          </el-form-item>
        </template>

        <!-- 单输出：老形态，一个模板 + 一批目标。 -->
        <template v-else>
          <el-form-item :label="t('mroute.rule.template')">
            <el-select v-model="model.templateRef" style="width: 100%">
              <el-option v-for="tp in templates" :key="tp.id" :label="tp.name" :value="tp.id!" />
            </el-select>
            <div class="mt-subtle hint">{{ t('mroute.rule.templateHint') }}</div>
          </el-form-item>

          <el-divider content-position="left">
            <span class="step">4</span>{{ t('mroute.rule.stepSend') }}
          </el-divider>
          <el-form-item :label="t('mroute.rule.targets')">
            <el-select
              v-model="model.targets"
              multiple
              style="width: 100%"
              :placeholder="t('mroute.rule.targetsPlaceholder')"
            >
              <el-option v-for="tg in targets" :key="tg.id" :label="targetLabel(tg.id!)" :value="tg.id!" />
            </el-select>
            <!-- 留空不是"不发"，而是"跟着接收器的兜底目标发"。这两件事差别很大，
                 所以这里把接收器此刻的兜底目标直接写出来，而不是让用户去另一个弹窗里翻。 -->
            <div v-if="noTargetAtAll" class="mt-danger-text hint">{{ t('mroute.rule.noTargetWarn') }}</div>
            <div v-else-if="!model.targets.length" class="mt-subtle hint">
              {{ t('mroute.rule.usingFallback', { names: fallbackNames }) }}
            </div>
            <div v-else class="mt-subtle hint">{{ t('mroute.rule.targetsHint') }}</div>
          </el-form-item>
        </template>

        <!-- 折叠区默认收起：这一格只在同一个接收器里还有别的规则时才有意义，
             多数人配完目标就该直接保存了。 -->
        <el-collapse v-model="advOpen" class="adv">
          <el-collapse-item :title="t('common.advanced')" name="adv">
            <el-form-item :label="t('mroute.rule.continue')">
              <el-switch v-model="model.continue" />
              <span class="mt-subtle hint inline">{{ t('mroute.rule.continueHint') }}</span>
            </el-form-item>
          </el-collapse-item>
        </el-collapse>
      </el-form>

      <div class="side">
        <h4 class="side-h">{{ t('mroute.fields') }}</h4>
        <p class="mt-subtle side-tip">{{ t('mroute.rule.fieldsHint') }}</p>
        <FieldTree :nodes="nodes" :empty-hint="t('mroute.treeEmptyParse')" @pick="copy" />
      </div>
    </div>

    <template #footer>
      <el-button @click="emit('update:visible', false)">{{ t('common.cancel') }}</el-button>
      <el-button type="primary" :loading="saving" @click="emit('save')">{{ t('common.save') }}</el-button>
    </template>
  </el-dialog>
</template>

<style scoped>
/* minmax(0, 1fr)：1fr 的最小值是 min-content，左栏里的定宽输入框会把右栏挤出容器
 * （与 ReceiverDialog 同一个坑）。 */
.two-col {
  display: grid;
  grid-template-columns: minmax(0, 1fr) 300px;
  gap: 18px;
}
.two-col > * {
  min-width: 0;
}
.grid4 {
  display: grid;
  grid-template-columns: minmax(0, 1.6fr) 110px 80px;
  gap: 0 16px;
  align-items: start;
}
/* 步骤序号：让「哪个入口 → 什么情况 → 长什么样 → 发给谁」这个顺序看得见。 */
.step {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  width: 18px;
  height: 18px;
  margin-right: 6px;
  border-radius: 50%;
  font-size: 11px;
  font-weight: 700;
  color: #fff;
  background: var(--mt-primary);
}
.side {
  border-left: 1px solid var(--mt-border, rgba(20, 27, 45, 0.12));
  padding-left: 16px;
}
.side-h {
  margin: 0 0 6px;
  font-size: 13px;
  font-weight: 600;
}
.side-tip {
  font-size: 12px;
  margin: 0 0 8px;
  line-height: 1.6;
}
.hint {
  font-size: 12px;
  margin-top: 4px;
  line-height: 1.6;
}
.hint.inline {
  margin-left: 10px;
}
/* el-form-item 的内容区是 flex 容器：开关与它后面那句提示同处一行，
 * 再跟一段说明就必须自己占满一行，否则会被挤成一条竖着的窄柱。 */
.hint.full {
  flex: 0 0 100%;
}
.pull-up {
  margin: -10px 0 4px;
}
/* 两层条件的说明：它是这一段最该先被读到的东西，所以给足行距、别挤成一行小字。 */
.two-layer {
  margin-bottom: 12px;
  line-height: 1.7;
}
/* 高级折叠区：去掉 el-collapse 自带的上边框（上面那格表单已经有间隔了），
 * 并收掉展开区末尾的空白，否则展开后底下会空出一大块。 */
.adv {
  border-top: none;
  margin-bottom: 4px;
}
.adv :deep(.el-collapse-item__header) {
  font-size: 13px;
}
.adv :deep(.el-collapse-item__content) {
  padding-bottom: 0;
}
.adv :deep(.el-form-item) {
  margin-bottom: 8px;
}
/* 窄屏两档。
 * 900：侧栏定宽 300。弹窗宽 min(1040px, 94vw)，900 像素屏上是 846，去掉 32 的内边距
 * 与 18 的间距，主区只剩约 496——而主区里最挤的条件行硬下限约 500。侧栏落到下方。
 * 640：定宽 110 + 80 的三联排在一栏里也挤不下，改成上下排。 */
@media (max-width: 900px) {
  .two-col {
    grid-template-columns: minmax(0, 1fr);
  }
}
@media (max-width: 640px) {
  .grid4 {
    grid-template-columns: minmax(0, 1fr);
  }
}
</style>
