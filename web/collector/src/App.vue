<script setup lang="ts">
import { computed,h, watch } from 'vue'
import { ApiOutlined,ClusterOutlined,DashboardOutlined,FileProtectOutlined,SafetyCertificateOutlined } from '@ant-design/icons-vue'
import { useRoute,useRouter } from 'vue-router'
import {App as AApp, message as antMessage} from 'ant-design-vue'
import zhCN from 'ant-design-vue/es/locale/zh_CN'
import { appTheme } from '@starbeacon/shared/theme.ts'
import AppShell from '@starbeacon/shared/components/AppShell.vue'
import {collectorNavigation,collectorWorkspaces} from './navigation'
import { session } from './session'
const [message, MessageContextHolder]=antMessage.useMessage()
const route=useRoute(),router=useRouter()
const icons={ApiOutlined,ClusterOutlined,DashboardOutlined,FileProtectOutlined,SafetyCertificateOutlined}
const sections=computed(()=>collectorNavigation(session.current.value?.role==='admin'))
const items=computed(()=>sections.value.map(item=>({key:'workspace:'+item.id,label:item.title,icon:()=>h(icons[item.icon])})))
const breadcrumbs=computed(()=>{
  const workspace=collectorWorkspaces.find(item=>item.id===route.meta.navWorkspace)
  return [...(workspace?[{label:workspace.title}]:[]),...(route.meta.title&&route.meta.title!==workspace?.title?[{label:String(route.meta.title)}]:[])]
})
function navigate(key:string){const item=sections.value.find(item=>'workspace:'+item.id===key);const {view:ignoredView,task:ignoredTask,...query}=route.query;void router.push({path:item?.path??key,query,hash:route.hash})}
watch(()=>route.meta.title,title=>{document.title=(title?String(title)+' · ':'')+'星烽 StarBeacon 采集器'},{immediate:true})
watch(session.current, user => {
  if(!user&&route.path!=='/login')void router.replace({path:'/login',query:{redirect:route.fullPath}})
  else if(user&&route.meta.admin&&user.role!=='admin')void router.replace({path:'/access-denied',query:{redirect:route.fullPath}})
})
async function logout(){try{await session.logout();await router.replace('/login')}catch(e){message.error(e instanceof Error?e.message:'退出失败')}}
</script>
<template><a-config-provider :theme="appTheme" :locale="zhCN"><AApp><MessageContextHolder/><RouterView v-if="route.path === '/login'" /><AppShell v-else title="采集器本地管理" :username="session.current.value?.username ?? ''" :current="'workspace:'+String(route.meta.navWorkspace??'')" :breadcrumbs="breadcrumbs" :items="items" @navigate="navigate" @logout="logout"><RouterView :key="route.path" /></AppShell></AApp></a-config-provider></template>
