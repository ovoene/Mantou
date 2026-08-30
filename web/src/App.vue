<script setup lang="ts">
// 根组件：仅承载路由出口。全局背景与主题由 style.css 的 CSS 变量驱动，
// 由外观 store 在 :root 上动态写入变量实现「实时预览 + 持久化」。
import { elLocale } from '@/i18n'
</script>

<template>
  <el-config-provider :locale="elLocale">
    <router-view />
  </el-config-provider>
</template>
