<script setup lang="ts">
import { ref, computed, onActivated } from 'vue'
import { useI18n } from 'vue-i18n'
import { actions, type GfwConfig } from '@/api/resources'
import { gfwRulesText, gfwListsText } from '@/composables/gfwText'

// 业务页（Web 服务 / 消息路由）顶部的只读状态组件：展示服务防护是否启用及其当前规则。
// 只读——不提供任何开关或跳转，用户要改去「服务防护」模块；这里只回答"现在处于什么状态"。
// 加载失败静默处理：状态展示挂了不该影响业务页本身的使用。
//
// 规则文本由 composables/gfwText 按结构化配置拼出，与模块页同一份函数：
// 后端不再下发拼好的摘要（那句话是硬编码中文，英文界面上会漏出中文），而两个业务页
// 各拼一份的话，同一份配置能在两个页面上写着不同的规则，且不会有任何报错。
const { t } = useI18n()
const cfg = ref<GfwConfig | null>(null)
const loaded = ref(false)

const enabled = computed(() => !!cfg.value?.enabled)
const rules = computed(() => gfwRulesText(t, cfg.value))
const lists = computed(() => gfwListsText(t, cfg.value))

async function load() {
  try {
    const res = await actions.globalFirewall()
    cfg.value = res.config
  } catch {
    /* 只读展示，加载失败不影响业务页 */
  } finally {
    loaded.value = true
  }
}

// 宿主页（Web 服务 / 消息路由）在 keep-alive 里，本组件作为其子节点同样会收到 activated，
// 且首次挂载时也会触发——所以只挂 onActivated 一个。再加一个 onMounted 的后果是
// 每次进业务页都把 /api/global-firewall 请求两遍。
onActivated(load)
</script>

<template>
  <div v-if="loaded" class="gfw-widget">
    <el-tag :type="enabled ? 'success' : 'info'" effect="light" size="small" class="chip">
      <span class="dot" :class="enabled ? 'on' : 'off'" />
      {{ enabled ? t('gfw.chipEnabled') : t('gfw.chipDisabled') }}
    </el-tag>
    <span v-if="rules" class="rules">
      <span class="k">{{ t('gfw.rulesLabel') }}</span>{{ rules }}
    </span>
    <span v-if="lists" class="rules">{{ lists }}</span>
  </div>
</template>

<style scoped>
.gfw-widget {
  display: flex;
  align-items: center;
  gap: 14px;
  flex-wrap: wrap;
  border: 1px solid var(--mt-border, #ebeef5);
  border-radius: var(--mt-card-radius, 14px);
  padding: 10px 14px;
  background: var(--mt-bg-soft, #f5f7fa);
  margin-bottom: 14px;
}
.chip {
  display: inline-flex;
  align-items: center;
  gap: 6px;
}
/* 状态点：开=绿、关=灰，跟随 el-tag 的 success/info 语义。 */
.dot {
  width: 8px;
  height: 8px;
  border-radius: 50%;
  display: inline-block;
}
.dot.on {
  background: var(--el-color-success, #67c23a);
}
.dot.off {
  background: var(--el-text-color-secondary, #909399);
}
.rules {
  font-size: 12px;
  color: var(--mt-text-soft, #606266);
}
.rules .k {
  color: var(--mt-text-soft, #909399);
  margin-right: 2px;
}
</style>
