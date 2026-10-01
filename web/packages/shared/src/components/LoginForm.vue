<script setup lang="ts">
import { reactive } from 'vue'
defineProps<{title: string; pending: boolean; error: string}>()
const emit = defineEmits<{submit: [username: string, password: string]}>()
const form = reactive({username: '', password: ''})
function submit() {emit('submit', form.username, form.password); form.password = ''}
</script>

<template>
  <main class="login-page">
    <section class="login-panel" aria-labelledby="login-title">
      <h1 id="login-title">{{ title }}</h1>
      <p class="page-description">使用管理员分配的账号登录。</p>
      <a-alert v-if="error" type="error" :message="error" show-icon class="section-gap" />
      <a-form layout="vertical" :model="form" @finish="submit">
        <a-form-item label="账号" name="username" :rules="[{required: true, message: '请输入账号'}]">
          <a-input v-model:value="form.username" autocomplete="username" :maxlength="64" :disabled="pending" />
        </a-form-item>
        <a-form-item label="密码" name="password" :rules="[{required: true, message: '请输入密码'}]">
          <a-input-password v-model:value="form.password" autocomplete="current-password" :disabled="pending" />
        </a-form-item>
        <a-button type="primary" html-type="submit" block :loading="pending">登录</a-button>
      </a-form>
    </section>
  </main>
</template>
