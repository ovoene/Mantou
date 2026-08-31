<script setup lang="ts">
import { ref } from 'vue'
import { useI18n } from 'vue-i18n'
import { ArrowDown } from '@element-plus/icons-vue'
import { useNarrow } from '@/composables/useNarrow'

// 列表行的操作按钮：窄屏收进一个「更多」下拉，宽屏原样平铺。
//
// 为什么必须收起来：一行操作往往是「立即运行 / 编辑 / 删除」三个按钮，平铺要 200 像素上下，
// 而窄屏整页可用宽度只有 200 出头。按钮是 nowrap、压不动，结果是表格横向滚动，
// 而「删除」在最右边——得先滚才点得到。
//
// 用法：把原来那几个 el-button 原样塞进默认插槽即可，不用改成 el-dropdown-item。
// 菜单里保留的就是页面自己那些按钮，type/loading/disabled 这些都照旧生效。
// 全站列表统一用它，菜单长相才是一样的（PageCard 页头那个「更多」也是同一套做法）。
const { t } = useI18n()

// 窄屏换的是 DOM 结构（菜单），CSS 做不到，所以这里要判宽度。
const narrow = useNarrow()

// 点完顺手收起菜单：插槽里是页面自己的 el-button 而不是 el-dropdown-item，
// 而 el-dropdown 只认后者，不管的话菜单会一直挂在弹窗前面。
const moreRef = ref<{ handleClose?: () => void } | null>(null)
function closeMore() {
  moreRef.value?.handleClose?.()
}
</script>

<template>
  <el-dropdown v-if="narrow" ref="moreRef" trigger="click" placement="bottom-end">
    <el-button size="small">
      {{ t('common.more') }}
      <el-icon class="more-arrow"><ArrowDown /></el-icon>
    </el-button>
    <template #dropdown>
      <div class="row-menu" @click="closeMore">
        <slot />
      </div>
    </template>
  </el-dropdown>
  <slot v-else />
</template>

<style scoped>
.more-arrow {
  margin-left: 4px;
}
/* 菜单里的按钮竖排、各占满一行。
 * 这里的 :deep 是必须的：插槽内容在页面那边编译，带的是页面的 scoped 标记，
 * 写成 .row-menu .el-button 这条规则永远匹配不到。 */
.row-menu {
  display: flex;
  flex-direction: column;
  gap: 8px;
  padding: 4px;
  min-width: 132px;
}
.row-menu :deep(.el-button) {
  width: 100%;
  margin-left: 0; /* el-button 相邻时自带左外边距，竖排下会歪出去一截 */
  justify-content: flex-start;
}
</style>
