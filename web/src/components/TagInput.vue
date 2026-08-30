<script setup lang="ts">
import { computed, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import { Plus } from '@element-plus/icons-vue'

const props = defineProps<{
  modelValue: string[]
  placeholder?: string
  disabled?: boolean
  addLabel?: string
}>()
const emit = defineEmits<{ (e: 'update:modelValue', v: string[]): void }>()

const { t } = useI18n()
const input = ref('')

// Go 的 nil 切片序列化成 null，而配置里没填过的列表就是 nil（新增字段对老配置更是如此）。
// 直接拿 modelValue 调 .includes 会在那种情况下抛错，表现为"输入框里加不进东西"。
const items = computed(() => props.modelValue ?? [])

function commit() {
  if (props.disabled) return
  const v = input.value.trim()
  if (!v) return
  if (!items.value.includes(v)) {
    emit('update:modelValue', [...items.value, v])
  }
  input.value = ''
}
function removeAt(i: number) {
  if (props.disabled) return
  const next = items.value.slice()
  next.splice(i, 1)
  emit('update:modelValue', next)
}
function onKey(e: KeyboardEvent) {
  if (props.disabled) return
  if (e.key === 'Enter') {
    e.preventDefault()
    commit()
  } else if (e.key === 'Backspace' && input.value === '' && items.value.length) {
    removeAt(items.value.length - 1)
  }
}
</script>

<template>
  <div class="ti-wrap">
    <div class="tag-input" :class="{ disabled: disabled }" @click="!disabled && (($event.currentTarget as HTMLElement).querySelector('input') as HTMLInputElement)?.focus()">
      <span v-for="(t, i) in items" :key="i" class="ti-chip">
        {{ t }}
        <button type="button" class="ti-x" :aria-label="'remove'" :disabled="disabled" @click.stop="removeAt(i)">×</button>
      </span>
      <input
        v-model="input"
        class="ti-field"
        :placeholder="placeholder"
        :disabled="disabled"
        @keydown="onKey"
        @blur="commit"
      />
    </div>
    <!-- 回车提交是给熟手的快捷方式，不能是唯一入口：没有一个看得见的「添加」，
         用户会以为这里根本加不了东西。 -->
    <el-button size="small" :icon="Plus" :disabled="disabled || !input.trim()" @click.stop="commit">
      {{ addLabel || t('common.add') }}
    </el-button>
  </div>
</template>

<style scoped>
.ti-wrap {
  display: flex;
  align-items: flex-start;
  gap: 8px;
  width: 100%;
}
.tag-input {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 6px;
  flex: 1 1 auto;
  min-width: 0;
  min-height: 36px;
  padding: 4px 8px;
  border: 1px solid var(--el-border-color, rgba(20, 27, 45, 0.22));
  border-radius: var(--mt-radius-sm, 10px);
  background: var(--mt-input-bg, #fff);
  cursor: text;
  transition: border-color 0.16s;
}
.tag-input:focus-within {
  border-color: var(--mt-primary);
}
.tag-input.disabled {
  background: var(--mt-disabled-bg, rgba(140, 150, 170, 0.1));
  cursor: not-allowed;
  opacity: 0.7;
}
.ti-chip {
  display: inline-flex;
  align-items: center;
  gap: 4px;
  padding: 2px 8px;
  font-size: 13px;
  line-height: 20px;
  border-radius: 8px;
  background: color-mix(in srgb, var(--mt-primary) 12%, transparent);
  color: var(--mt-primary);
  border: 1px solid color-mix(in srgb, var(--mt-primary) 28%, transparent);
}
.ti-x {
  border: none;
  background: transparent;
  color: inherit;
  font-size: 15px;
  line-height: 1;
  cursor: pointer;
  padding: 0 2px;
  opacity: 0.7;
}
.ti-x:hover {
  opacity: 1;
}
.ti-field {
  flex: 1;
  min-width: 120px;
  border: none;
  outline: none;
  background: transparent;
  font-size: 14px;
  font-family: inherit;
  color: var(--mt-text);
  padding: 2px 0;
}
</style>
