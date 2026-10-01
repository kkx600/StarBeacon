<script setup lang="ts">
import { h, watch } from 'vue'
import { RadarChartOutlined, AlertOutlined } from '@ant-design/icons-vue'
import { useRoute, useRouter } from 'vue-router'
import { message } from 'ant-design-vue'
import zhCN from 'ant-design-vue/es/locale/zh_CN'
import { appTheme } from '@starbeacon/shared/theme.ts'
import AppShell from '@starbeacon/shared/components/AppShell.vue'
import { session } from './session'
const route = useRoute(), router = useRouter()
const items = [{key: '/sensors', label: '探针管理', icon: () => h(RadarChartOutlined)}, {key: '/alerts', label: '告警管理', icon: () => h(AlertOutlined)}]
watch(session.current, user => {if (!user && route.path !== '/login') void router.replace('/login')})
async function logout() {try {await session.logout(); await router.replace('/login')} catch (e) {message.error(e instanceof Error ? e.message : '退出失败')}}
</script>
<template>
  <a-config-provider :theme="appTheme" :locale="zhCN">
    <RouterView v-if="route.path === '/login'" />
    <AppShell v-else title="态势感知系统" :username="session.current.value?.username ?? ''" :current="route.path" :items="items" @navigate="router.push($event)" @logout="logout"><RouterView /></AppShell>
  </a-config-provider>
</template>
