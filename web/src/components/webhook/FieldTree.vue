<script setup lang="ts">
import { computed } from 'vue'
import { useI18n } from 'vue-i18n'
import type { FieldNode } from '@/composables/fieldPaths'

// 字段树：把样本载荷的结构摆出来，点任意一行把它的完整路径交给调用方
//（填进条件的取值路径，或以 {{.xxx}} 的形式插进模板）。

const props = defineProps<{
  nodes: FieldNode[]
  emptyHint?: string
}>()
const emit = defineEmits<{ (e: 'pick', path: string): void }>()

const { t } = useI18n()

// 只展开第一层：真实载荷常有几十个字段，全展开等于把面板铺满。
const topKeys = computed(() => props.nodes.map((n) => n.path))
</script>

<template>
  <div class="field-tree">
    <p v-if="!nodes.length" class="mt-subtle empty">{{ emptyHint || t('mroute.tree.empty') }}</p>
    <el-tree
      v-else
      :data="nodes"
      node-key="path"
      :props="{ label: 'label', children: 'children' }"
      :default-expanded-keys="topKeys"
      :expand-on-click-node="false"
    >
      <template #default="{ data }">
        <span class="ft-node" :title="data.path" @click="emit('pick', data.path)">
          <code class="ft-key" :class="{ 'is-arr': data.array }">{{ data.label }}</code>
          <!-- 数组要一眼看得出来：它是唯一"直接取值会出乱码、必须走循环"的字段，
               而这件事光看 [2] 这样的预览是看不出来的。点它插入的也不是取值而是
               整段循环（见 TemplateDialog 的 pickPayload）。 -->
          <el-tag v-if="data.array" size="small" type="warning" class="ft-arr">
            {{ t('mroute.tree.arrayTag') }}
          </el-tag>
          <span class="mt-subtle ft-prev">{{ data.preview }}</span>
        </span>
      </template>
    </el-tree>
  </div>
</template>

<style scoped>
.field-tree {
  max-height: 320px;
  overflow: auto;
}
.empty {
  font-size: 12px;
  margin: 8px 2px;
  line-height: 1.6;
}
.ft-node {
  display: inline-flex;
  align-items: center;
  gap: 8px;
  cursor: pointer;
  min-width: 0;
}
.ft-key {
  font-family: ui-monospace, Menlo, Consolas, monospace;
  font-size: 12px;
  padding: 1px 5px;
  border-radius: 4px;
  background: rgba(140, 150, 170, 0.14);
}
/* 数组那一行整体偏暖色，与普通字段拉开距离——用户扫一眼就知道"这一段要循环"。 */
.ft-key.is-arr {
  background: color-mix(in srgb, var(--mt-warning) 20%, transparent);
  color: color-mix(in srgb, var(--mt-warning) 72%, var(--mt-text));
}
.ft-arr {
  flex: 0 0 auto;
}
.ft-node:hover .ft-key {
  background: color-mix(in srgb, var(--mt-primary) 18%, transparent);
  color: var(--mt-primary);
}
.ft-prev {
  font-size: 12px;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
  max-width: 180px;
}
</style>
