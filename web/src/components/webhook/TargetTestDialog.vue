<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import type { NotifyTarget, WebhookMeta } from '@/api/webhook'

// 通知目标的「测试发送」。
//
// 为什么不是点一下就发一句固定的话：调通道时真正要确认的往往不是"通不通"，
// 而是"这条消息在钉钉／企业微信里长什么样"——换行生效了吗、标题出来了吗、
// markdown 认不认。所以这里给一个和消息模板一样的 txt / markdown 输入框，
// 内容手填、原样发出，改一句再发一次也不用去动任何模板。
//
// 这里刻意没有字段与变量：测试发送不挂接收器，没有载荷可取，写 {{.xxx}} 只会
// 原样出现在消息里，看着更像 bug。要连着载荷一起试请用「接收器 → 试运行」。

const props = defineProps<{
  visible: boolean
  target: NotifyTarget | null
  sending: boolean
  meta: WebhookMeta | null
}>()
const emit = defineEmits<{
  (e: 'update:visible', v: boolean): void
  (e: 'send', payload: { message: string; format: string; title: string; titleStyle: string }): void
}>()

const { t } = useI18n()

// 取值由后端下发（config.MarkdownTitleStyles），与消息模板同一份下拉。
const titleStyles = computed(() => props.meta?.titleStyles || ['h1', 'h2', 'h3', 'bold', 'none'])

function blank() {
  return { format: 'text', title: '', titleStyle: 'h3', message: t('mroute.target.testDefault') }
}
const form = ref(blank())

// 每次打开都重置：上一次可能调的是另一个目标，留着上次的内容容易被当成
// "这个目标已经配好的东西"。正文预填一句现成的，一进来就能直接点发送。
watch(
  () => props.visible,
  (open) => {
    if (open) form.value = blank()
  },
)

const canSend = computed(() => form.value.message.trim() !== '')

function send() {
  emit('send', { ...form.value })
}
</script>

<template>
  <el-dialog
    :model-value="visible"
    :title="t('mroute.target.testTitle', { name: target?.name || '' })"
    width="min(620px, 94vw)"
    append-to-body
    :close-on-click-modal="false"
    @update:model-value="(v: boolean) => emit('update:visible', v)"
  >
    <el-form label-position="top">
      <el-form-item :label="t('mroute.tmpl.format')">
        <el-radio-group v-model="form.format">
          <el-radio-button value="text">{{ t('mroute.tmpl.text') }}</el-radio-button>
          <el-radio-button value="markdown">Markdown</el-radio-button>
        </el-radio-group>
        <div class="mt-subtle hint">{{ t('mroute.target.testFormatHint') }}</div>
      </el-form-item>

      <template v-if="form.format === 'markdown'">
        <el-form-item :label="t('mroute.tmpl.title')">
          <el-input v-model="form.title" :placeholder="t('mroute.target.testTitlePlaceholder')" />
        </el-form-item>
        <el-form-item :label="t('mroute.tmpl.titleStyle')">
          <el-select v-model="form.titleStyle" style="width: 220px">
            <el-option
              v-for="s in titleStyles"
              :key="s"
              :value="s"
              :label="t(`mroute.tmpl.style.${s}`)"
            />
          </el-select>
          <div class="mt-subtle hint">{{ t('mroute.tmpl.titleStyleHint') }}</div>
        </el-form-item>
      </template>

      <el-form-item :label="t('mroute.tmpl.body')">
        <el-input
          v-model="form.message"
          type="textarea"
          :rows="8"
          class="mono"
          :placeholder="t('mroute.target.testBodyPlaceholder')"
        />
        <div class="mt-subtle hint">{{ t('mroute.target.testNoVars') }}</div>
      </el-form-item>
    </el-form>

    <template #footer>
      <el-button @click="emit('update:visible', false)">{{ t('common.close') }}</el-button>
      <el-button type="primary" :loading="sending" :disabled="!canSend" @click="send">
        {{ t('mroute.target.testSend') }}
      </el-button>
    </template>
  </el-dialog>
</template>

<style scoped>
.hint {
  font-size: 12px;
  margin-top: 4px;
  line-height: 1.6;
}
.mono :deep(textarea) {
  font-family: ui-monospace, Menlo, Consolas, monospace;
  font-size: 13px;
}
</style>
