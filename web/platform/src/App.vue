<script setup lang="ts">
import { computed,h, shallowRef,watch } from 'vue'
import { RadarChartOutlined, AlertOutlined, FileProtectOutlined,DatabaseOutlined,AuditOutlined,BellOutlined,RobotOutlined,DashboardOutlined } from '@ant-design/icons-vue'
import { useRoute, useRouter } from 'vue-router'
import { message } from 'ant-design-vue'
import zhCN from 'ant-design-vue/es/locale/zh_CN'
import { appTheme } from '@starbeacon/shared/theme.ts'
import AppShell from '@starbeacon/shared/components/AppShell.vue'
import { session } from './session'
import PasswordDialog from './features/users/PasswordDialog.vue'
const route = useRoute(), router = useRouter()
const passwordOpen=shallowRef(false)
const items = computed(()=>[{key:'/overview',label:'态势总览',icon:()=>h(DashboardOutlined)},{key: '/sensors', label: '探针管理', icon: () => h(RadarChartOutlined)}, {key: '/alerts', label: '告警管理', icon: () => h(AlertOutlined)}, {key:'/traffic',label:'流量检索',icon:()=>h(RadarChartOutlined)},{key:'/assets',label:'资产管理',icon:()=>h(DatabaseOutlined)},{key: '/rules', label: '规则管理', icon: () => h(FileProtectOutlined)},...(session.current.value?.role==='admin'?[{key:'/incidents',label:'事件调查',icon:()=>h(FileProtectOutlined)},{key:'/assistant',label:'智能助手',icon:()=>h(RobotOutlined)},{key:'/reports',label:'报告中心',icon:()=>h(FileProtectOutlined)},{key:'/models',label:'模型配置',icon:()=>h(RobotOutlined)},{key:'/notifications',label:'通知中心',icon:()=>h(BellOutlined)},{key:'/users',label:'用户管理',icon:()=>h(AuditOutlined)},{key:'/operations',label:'运行与审计',icon:()=>h(AuditOutlined)},{key:'/retention',label:'数据留存',icon:()=>h(DatabaseOutlined)}]:[])])
watch(session.current, user => {if (!user){passwordOpen.value=false;if(route.path !== '/login') void router.replace({path:'/login',query:{redirect:route.fullPath}})}})
async function logout() {try {await session.logout(); await router.replace('/login')} catch (e) {message.error(e instanceof Error ? e.message : '退出失败')}}
</script>
<template>
  <a-config-provider :theme="appTheme" :locale="zhCN">
    <RouterView v-if="route.path === '/login'" />
    <AppShell v-else title="态势感知系统" :username="session.current.value?.username ?? ''" :current="route.path==='/screen'?'/overview':route.path" :items="items" allow-password-change @password="passwordOpen=true" @navigate="router.push($event)" @logout="logout"><RouterView /></AppShell>
    <PasswordDialog v-if="passwordOpen" own @close="passwordOpen=false"/>
  </a-config-provider>
</template>
