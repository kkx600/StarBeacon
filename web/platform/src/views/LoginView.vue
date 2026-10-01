<script setup lang="ts">
import { useRouter } from 'vue-router'
import LoginForm from '@starbeacon/shared/components/LoginForm.vue'
import { session } from '../session'
const router = useRouter()
async function submit(username: string, password: string) {if (await session.login(username, password)) await router.replace('/sensors')}
</script>
<template><LoginForm title="登录星烽 StarBeacon" :pending="session.pending.value" :error="session.error.value" @submit="submit" /></template>
