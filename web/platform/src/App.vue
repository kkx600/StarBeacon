<script setup lang="ts">
import { computed,h, shallowRef,watch } from 'vue'
import {AlertOutlined,ApiOutlined,BarChartOutlined,BellOutlined,ClusterOutlined,DashboardOutlined,FileProtectOutlined,RadarChartOutlined,RobotOutlined,SafetyCertificateOutlined,SettingOutlined,ThunderboltOutlined} from '@ant-design/icons-vue'
import {navigationForRole} from './navigation'
import {navigationGroups,navigationWorkspaces} from '@starbeacon/shared/navigation.ts'
import { useRoute, useRouter } from 'vue-router'
import {App as AApp, message as antMessage} from 'ant-design-vue'
import zhCN from 'ant-design-vue/es/locale/zh_CN'
import { appTheme } from '@starbeacon/shared/theme.ts'
import AppShell from '@starbeacon/shared/components/AppShell.vue'
import { session } from './session'
import PasswordDialog from './features/users/PasswordDialog.vue'
const [message, MessageContextHolder]=antMessage.useMessage()
const route = useRoute(), router = useRouter()
const passwordOpen=shallowRef(false)
const icons={AlertOutlined,ApiOutlined,BarChartOutlined,BellOutlined,ClusterOutlined,DashboardOutlined,FileProtectOutlined,RadarChartOutlined,RobotOutlined,SafetyCertificateOutlined,SettingOutlined,ThunderboltOutlined}
const sections=computed(()=>navigationForRole(session.current.value?.role==='admin'))
const items=computed(()=>sections.value.map(group=>{
  const icon=()=>h(icons[group.icon as keyof typeof icons])
  const children=group.children.map(item=>({key:'workspace:'+item.key,label:item.label,title:item.available?item.label:item.label+'（当前版本未提供）'}))
  return children.length===1?{...children[0]!,icon}:{key:'group:'+group.key,label:group.label,icon,children}
}))
const breadcrumbs=computed(()=>{
  const group=navigationGroups.find(item=>item.id===route.meta.navGroup),workspace=navigationWorkspaces.find(item=>item.id===route.meta.navWorkspace)
  return [...(group?[{label:group.title}]:[]),...(workspace?[{label:workspace.title}]:[]),...(route.meta.title&&route.meta.title!==workspace?.title?[{label:String(route.meta.title)}]:[])].filter((item,index,all)=>!index||item.label!==all[index-1]!.label)
})
function navigate(key:string){const item=sections.value.flatMap(group=>group.children).find(item=>'workspace:'+item.key===key);void router.push(item?.path??key)}
watch(()=>route.meta.title,title=>{document.title=(title?String(title)+' · ':'')+'星烽 StarBeacon'},{immediate:true})
watch(session.current, user => {if (!user){passwordOpen.value=false;if(route.path !== '/login') void router.replace({path:'/login',query:{redirect:route.fullPath}})}else if(route.meta.admin&&user.role!=='admin'){passwordOpen.value=false;void router.replace('/sensors/list')}})
async function logout() {try {await session.logout(); await router.replace('/login')} catch (e) {message.error(e instanceof Error ? e.message : '退出失败')}}
</script>
<template>
  <a-config-provider :theme="appTheme" :locale="zhCN"><AApp><MessageContextHolder/>
    <RouterView v-if="route.path === '/login'" />
    <AppShell v-else title="态势感知系统" :username="session.current.value?.username ?? ''" :current="'workspace:'+String(route.meta.navWorkspace??'')" :breadcrumbs="breadcrumbs" :items="items" allow-password-change @password="passwordOpen=true" @navigate="navigate" @logout="logout"><RouterView :key="route.path" /></AppShell>
    <PasswordDialog v-if="passwordOpen" own @close="passwordOpen=false"/>
  </AApp></a-config-provider>
</template>
