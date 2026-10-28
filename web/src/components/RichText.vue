<script setup lang="ts">
import { computed } from 'vue'

// 带少量标记的一段说明文字：加粗、等宽、彩色小标签、彩色强调。
//
// 为什么不用 v-html：说明文案在语言包里，写成 HTML 就得开 v-html，而一个能渲染任意 HTML 的口子
// 只要哪天有一条文案拼进了用户数据就是 XSS。这里把文案切成片段、每段都按纯文本插值渲染，
// 标记只决定"套哪个标签"，内容永远不会被当成 HTML 解析。
//
// 也不用 vue-i18n 的 <i18n-t> 插槽：一句话里五六处加粗要写五六个具名插槽，两个语言包的
// 文案还得跟模板里的插槽名逐个对上——改一句说明要同时动三个文件。
//
// 标记语法只有一种：[类型:文字]。文字里不能再出现 ]，也不支持嵌套（说明文字用不到）。
//   b      加粗                 [b:Web 服务]
//   code   等宽（日志原文等）    [code:TLS handshake error from <ip>]
//   ok     绿色小标签            [ok:管]
//   no     红色小标签            [no:不管]
//   warn   橙色小标签            [warn:自动封禁]
//   info   灰色小标签            [info:局域网豁免]
//   red / green / orange   彩色加粗文字（一句话里最要紧的那个词）
// 认不出的类型原样当普通文字输出，不会吞字。
const props = defineProps<{ text: string }>()

type Seg = { kind: string; text: string }

const MARK = /\[(b|code|ok|no|warn|info|red|green|orange):([^\]]+)\]/g
const BADGES = new Set(['ok', 'no', 'warn', 'info'])

const segs = computed<Seg[]>(() => {
  const out: Seg[] = []
  const s = props.text || ''
  let last = 0
  for (const m of s.matchAll(MARK)) {
    const at = m.index ?? 0
    if (at > last) out.push({ kind: '', text: s.slice(last, at) })
    out.push({ kind: m[1], text: m[2] })
    last = at + m[0].length
  }
  if (last < s.length) out.push({ kind: '', text: s.slice(last) })
  return out
})
</script>

<template>
  <template v-for="(seg, i) in segs" :key="i">
    <template v-if="seg.kind === ''">{{ seg.text }}</template>
    <strong v-else-if="seg.kind === 'b'" class="rt-b">{{ seg.text }}</strong>
    <code v-else-if="seg.kind === 'code'" class="rt-code">{{ seg.text }}</code>
    <span v-else-if="BADGES.has(seg.kind)" :class="['rt-badge', `rt-badge-${seg.kind}`]">{{ seg.text }}</span>
    <strong v-else :class="['rt-em', `rt-em-${seg.kind}`]">{{ seg.text }}</strong>
  </template>
</template>

<style scoped>
.rt-b {
  font-weight: 600;
  color: var(--mt-text);
}
.rt-code {
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  font-size: 0.92em;
  padding: 1px 5px;
  border-radius: 4px;
  background: color-mix(in srgb, var(--mt-text) 8%, transparent);
  color: var(--mt-text);
  word-break: break-all;
}
/* 彩色小标签：底色取对应语义色的浅调、字取原色。color-mix 而不是 Element 的 -light-9 变量：
 * 那组变量只有浅色主题下是"浅"的，深色模式里会变成一块刺眼的亮底。 */
.rt-badge {
  display: inline-block;
  margin: 0 4px 0 2px;
  padding: 0 7px;
  border-radius: 4px;
  font-size: 0.9em;
  line-height: 1.6;
  font-weight: 500;
  white-space: nowrap;
  border: 1px solid transparent;
}
.rt-badge-ok {
  color: var(--el-color-success, #67c23a);
  background: color-mix(in srgb, var(--el-color-success, #67c23a) 14%, transparent);
  border-color: color-mix(in srgb, var(--el-color-success, #67c23a) 30%, transparent);
}
.rt-badge-no {
  color: var(--el-color-danger, #f56c6c);
  background: color-mix(in srgb, var(--el-color-danger, #f56c6c) 12%, transparent);
  border-color: color-mix(in srgb, var(--el-color-danger, #f56c6c) 28%, transparent);
}
.rt-badge-warn {
  color: var(--el-color-warning, #e6a23c);
  background: color-mix(in srgb, var(--el-color-warning, #e6a23c) 14%, transparent);
  border-color: color-mix(in srgb, var(--el-color-warning, #e6a23c) 30%, transparent);
}
.rt-badge-info {
  color: var(--mt-text-soft);
  background: color-mix(in srgb, var(--mt-text-soft) 12%, transparent);
  border-color: color-mix(in srgb, var(--mt-text-soft) 26%, transparent);
}
.rt-em {
  font-weight: 600;
}
.rt-em-red {
  color: var(--el-color-danger, #f56c6c);
}
.rt-em-green {
  color: var(--el-color-success, #67c23a);
}
.rt-em-orange {
  color: var(--el-color-warning, #e6a23c);
}
</style>
