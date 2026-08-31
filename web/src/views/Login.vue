<script setup lang="ts">
import { ref, reactive } from 'vue'
import { useRouter, useRoute } from 'vue-router'
import { useI18n } from 'vue-i18n'
import { ElMessage } from 'element-plus'
import { useAuthStore } from '@/stores/auth'
import AppBackdrop from '@/components/AppBackdrop.vue'
import LangSwitch from '@/components/LangSwitch.vue'

const { t } = useI18n()
const router = useRouter()
const route = useRoute()
const auth = useAuthStore()

const form = reactive({ username: '', password: '' })
const loading = ref(false)

async function submit() {
  if (!form.username || !form.password) return
  loading.value = true
  try {
    await auth.login(form.username, form.password)
    const redirect = (route.query.redirect as string) || '/overview'
    router.replace(redirect)
  } catch (e: any) {
    ElMessage.error(e?.message || t('login.failed'))
  } finally {
    loading.value = false
  }
}
</script>

<template>
  <AppBackdrop />
  <div class="auth-wrap">
    <div class="auth-top"><LangSwitch /></div>
    <div class="mt-glass auth-card">
      <div class="brand">
        <div class="logo">M</div>
        <div>
          <h1 class="mt-title">{{ t('app.name') }}</h1>
          <p class="mt-subtle">{{ t('app.tagline') }}</p>
        </div>
      </div>
      <h2 class="auth-h2">{{ t('login.title') }}</h2>
      <el-form label-position="top" @submit.prevent="submit">
        <el-form-item :label="t('login.username')">
          <el-input v-model="form.username" :placeholder="t('login.placeholderUser')" size="large" />
        </el-form-item>
        <el-form-item :label="t('login.password')">
          <el-input
            v-model="form.password"
            type="password"
            show-password
            :placeholder="t('login.placeholderPass')"
            size="large"
            @keyup.enter="submit"
          />
        </el-form-item>
        <el-button type="primary" size="large" class="submit" :loading="loading" @click="submit">
          {{ t('login.submit') }}
        </el-button>
      </el-form>
    </div>
  </div>
</template>

<style scoped>
.auth-wrap {
  min-height: 100vh;
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  padding: 24px;
}
.auth-top {
  position: fixed;
  top: 18px;
  right: 22px;
}
.auth-card {
  width: 100%;
  max-width: 400px;
  padding: 36px 34px 40px;
}
.brand {
  display: flex;
  align-items: center;
  gap: 14px;
  margin-bottom: 22px;
}
.logo {
  width: 52px;
  height: 52px;
  border-radius: 15px;
  display: grid;
  place-items: center;
  font-size: 26px;
  font-weight: 700;
  color: #fff;
  background: linear-gradient(135deg, var(--mt-primary), var(--mt-accent));
  box-shadow: 0 6px 18px rgba(79, 107, 237, 0.4);
}
.auth-h2 {
  font-size: 16px;
  font-weight: 600;
  margin: 0 0 14px;
  color: var(--mt-text-soft);
}
.submit {
  width: 100%;
  margin-top: 6px;
}
</style>
