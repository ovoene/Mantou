<script setup lang="ts">
import { useI18n } from 'vue-i18n'
import { setLocale, currentLocale } from '@/i18n'
import { computed } from 'vue'

const { locale } = useI18n()
const value = computed({
  get: () => currentLocale(),
  set: (v: 'zh-CN' | 'en-US') => {
    setLocale(v)
    locale.value = v
  },
})
</script>

<template>
  <!-- 收起时显示缩写「简 / EN」，展开后的选项仍是完整名字。
       两处文字不同是刻意的：这个控件摆在顶栏最右边，而顶栏中间要放居中的时间——
       右侧每宽一像素，时间就少一像素的居中余地，而写完整名字要占 108 像素。
       展开之后是纵向一列，不跟任何东西抢宽度，那里写全反而清楚。
       桌面、移动端、登录页共用这一份，没有按屏宽分叉。 -->
  <el-select v-model="value" size="small" class="lang-select">
    <el-option label="简" value="zh-CN">简体中文</el-option>
    <el-option label="EN" value="en-US">English</el-option>
  </el-select>
</template>

<style scoped>
/* 宽度得写死：el-select 默认撑满父级，而三处调用方（顶栏、登录页、初始化页）
 * 都是靠内容取宽的容器，不给宽度它会把那一行整个撑开。
 * 56 是按里面各部分量出来的：左内边距 8 + 文字 17（较宽的「EN」那一档，中文只 12）
 * + 文字与箭头间距 4 + 箭头 14 + 右内边距 8 = 51，多留 5 像素是给字体回退用的余量——
 * 差一点就会被 el-select 自己的省略号截成「E…」。 */
.lang-select {
  width: 56px;
}
</style>
