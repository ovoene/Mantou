<script setup lang="ts">
import { computed, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import { ArrowDown } from '@element-plus/icons-vue'
import { useNarrow } from '@/composables/useNarrow'

const props = defineProps<{
  title: string
  subtitle?: string
  // maxCount 本模块的条目数上限，来自后端（页面通常直接传 useResource 的 r.maxCount）。
  // 有值时在说明后面接一句「最多可添加 N 条」；0 或不传就什么都不加——
  // 上限还没拉回来时宁可少一句话，也不要先显示一个「最多 0 条」。
  maxCount?: number
  // collapseActions 窄屏时把 actions 插槽整个收进一个「更多」菜单。
  // 只有插槽里放的全是按钮时才该开：状态标签那类展示物收进菜单就等于藏起来了。
  collapseActions?: boolean
}>()

const { t } = useI18n()

// 窄屏时换的是 DOM 结构（菜单），光靠 CSS 做不到，所以这里要再判一次宽度。
const narrow = useNarrow()

const collapsed = computed(() => !!props.collapseActions && narrow.value)

// 菜单里点了按钮要顺手收起菜单：插槽里是页面自己的 el-button 而不是 el-dropdown-item，
// 而 el-dropdown 只认后者，不管的话菜单会一直挂在弹窗前面。
const moreRef = ref<{ handleClose?: () => void } | null>(null)
function closeMore() {
  moreRef.value?.handleClose?.()
}

// 拼在一句里而不是另起一行：这句是对上面那句说明的补充，单独占一行会让标题区显得
// 比它实际承载的信息更重。
//
// 用「·」隔开而不是空格：没有一条模块说明是以标点结尾的（各模块的 subtitle 都是短语），
// 空格接上去就变成「…更新 DNS 解析记录 最多可添加 100 条」——读起来像一句话说漏了。
const subLine = computed(() => {
  const cap = props.maxCount && props.maxCount > 0 ? t('common.maxEntries', { n: props.maxCount }) : ''
  if (!props.subtitle) return cap
  return cap ? `${props.subtitle} · ${cap}` : props.subtitle
})
</script>

<template>
  <section class="mt-glass page-card">
    <header class="page-head">
      <div class="page-head-main">
        <h2 class="mt-title">
          {{ title }}
          <slot name="title-extra" />
        </h2>
        <p v-if="subLine" class="mt-subtle sub">{{ subLine }}</p>
      </div>
      <div v-if="$slots.actions" class="page-actions">
        <el-dropdown v-if="collapsed" ref="moreRef" trigger="click" placement="bottom-end">
          <el-button>
            {{ t('common.more') }}
            <el-icon class="more-arrow"><ArrowDown /></el-icon>
          </el-button>
          <template #dropdown>
            <div class="actions-menu" @click="closeMore">
              <slot name="actions" />
            </div>
          </template>
        </el-dropdown>
        <slot v-else name="actions" />
      </div>
    </header>
    <div class="page-body">
      <slot />
    </div>
  </section>
</template>

<style scoped>
.page-card {
  padding: 22px 24px 24px;
}
.page-head {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: 16px;
  margin-bottom: 18px;
}
/* 让标题与 title-extra 插槽（图标等）排在同一行内，h2 默认 block 会换行。 */
.page-head-main h2 {
  display: inline-flex;
  align-items: center;
  flex-wrap: wrap;
  gap: 4px;
}
.sub {
  margin: 4px 0 0;
  font-size: 13px;
}
.page-actions {
  display: flex;
  gap: 10px;
  flex-shrink: 0;
}
.more-arrow {
  margin-left: 4px;
}
/* 「更多」菜单里的按钮竖排、各占满一行。
 * 这里的 :deep 是必须的：插槽内容在页面那边编译，带的是页面的 scoped 标记，
 * 写成 .actions-menu .el-button 这条规则永远匹配不到。 */
.actions-menu {
  display: flex;
  flex-direction: column;
  gap: 8px;
  padding: 4px;
  min-width: 132px;
}
.actions-menu :deep(.el-button) {
  width: 100%;
  margin-left: 0; /* el-button 相邻时自带左外边距，竖排下会歪出去一截 */
  justify-content: flex-start;
}
.page-body {
  min-height: 40px;
}

/* 窄屏：页头收成上下两行。操作区留在标题右边的话，标题会被挤到一行一两个字，
 * 而操作区自己是 flex-shrink: 0（按钮不能压），最后整页横向溢出。
 * 独占一行后仍然靠右，跟宽屏的位置一致。
 * 一行放不下的页面（如安全证书的两个按钮）再加 collapse-actions 收进「更多」。 */
@media (max-width: 640px) {
  .page-head {
    flex-wrap: wrap;
  }
  .page-actions {
    width: 100%;
    justify-content: flex-end;
    flex-shrink: 1;
    min-width: 0;
  }
}
</style>
