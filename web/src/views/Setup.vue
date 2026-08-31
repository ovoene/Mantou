<script setup lang="ts">
import { reactive, ref, computed } from 'vue'
import { useRouter } from 'vue-router'
import { useI18n } from 'vue-i18n'
import { ElMessage } from 'element-plus'
import { useAuthStore } from '@/stores/auth'
import AppBackdrop from '@/components/AppBackdrop.vue'
import LangSwitch from '@/components/LangSwitch.vue'

const { t } = useI18n()
const router = useRouter()
const auth = useAuthStore()

const form = reactive({ username: '', password: '', confirm: '' })
const loading = ref(false)

const userError = computed(() =>
  form.username && form.username.length < 3 ? t('setup.hintUser') : '',
)
const passError = computed(() =>
  form.password && form.password.length < 6 ? t('setup.hintPass') : '',
)
const mismatch = computed(() =>
  form.confirm && form.confirm !== form.password ? t('setup.mismatch') : '',
)
const canSubmit = computed(
  () =>
    form.username.length >= 3 &&
    form.password.length >= 6 &&
    form.password === form.confirm,
)

async function submit() {
  if (!canSubmit.value) return
  loading.value = true
  try {
    await auth.setup(form.username, form.password)
    await auth.login(form.username, form.password)
    ElMessage.success(t('setup.done'))
    router.replace('/overview')
  } catch (e: any) {
    ElMessage.error(e?.message || t('common.failed'))
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
          <h1 class="mt-title">{{ t('setup.title') }}</h1>
          <p class="mt-subtle">{{ t('setup.subtitle') }}</p>
        </div>
      </div>
      <el-form label-position="top" @submit.prevent="submit">
        <el-form-item :label="t('setup.username')" :error="userError">
          <el-input v-model="form.username" size="large" />
        </el-form-item>
        <el-form-item :label="t('setup.password')" :error="passError">
          <el-input v-model="form.password" type="password" show-password size="large" />
        </el-form-item>
        <el-form-item :label="t('setup.confirmPassword')" :error="mismatch">
          <el-input
            v-model="form.confirm"
            type="password"
            show-password
            size="large"
            @keyup.enter="submit"
          />
        </el-form-item>
        <el-button
          type="primary"
          size="large"
          class="submit"
          :loading="loading"
          :disabled="!canSubmit"
          @click="submit"
        >
          {{ t('setup.submit') }}
        </el-button>
      </el-form>
    </div>
  </div>
</template>

<style scoped>
.auth-wrap {
  min-height: 100vh;
  display: flex;
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
  max-width: 420px;
  padding: 34px;
}
.brand {
  display: flex;
  align-items: center;
  gap: 14px;
  margin-bottom: 18px;
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
.submit {
  width: 100%;
  margin-top: 4px;
}
</style>
