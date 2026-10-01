<script setup lang="ts">
import { h, watch } from 'vue'
import { ClusterOutlined } from '@ant-design/icons-vue'
import { useRoute,useRouter } from 'vue-router'
import { message } from 'ant-design-vue'
import zhCN from 'ant-design-vue/es/locale/zh_CN'
import { appTheme } from '@starbeacon/shared/theme.ts'
import AppShell from '@starbeacon/shared/components/AppShell.vue'
import { session } from './session'
const route=useRoute(),router=useRouter()
const items = [{key: '/network', label: '网络与采集', icon: () => h(ClusterOutlined)}]
watch(session.current, user => {if (!user && route.path !== '/login') void router.replace({path:'/login',query:{redirect:route.fullPath}})})
async function logout(){try{await session.logout();await router.replace('/login')}catch(e){message.error(e instanceof Error?e.message:'退出失败')}}
</script>
<template><a-config-provider :theme="appTheme" :locale="zhCN"><RouterView v-if="route.path === '/login'" /><AppShell v-else title="采集器本地管理" :username="session.current.value?.username ?? ''" :current="route.path" :items="items" @navigate="router.push($event)" @logout="logout"><RouterView /></AppShell></a-config-provider></template>
