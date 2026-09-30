<script setup lang="ts">
import {computed,ref,watch,onMounted,onBeforeUnmount} from 'vue'
import {useRoute,useRouter} from 'vue-router'
import {ApiOutlined,DashboardOutlined,DeploymentUnitOutlined,LinkOutlined,CloudSyncOutlined,SettingOutlined,MenuFoldOutlined,MenuUnfoldOutlined,AppstoreOutlined,SafetyCertificateOutlined} from '@ant-design/icons-vue'
import {collectorPages,collectorDevice} from '../data/collector'
import {states} from '../data/catalog'
import {usePreview} from '../composables/usePreview'
import type {PreviewState} from '../models'
const route=useRoute();const router=useRouter();const {state,setState}=usePreview()
const media=window.matchMedia('(max-width:899px)');const collapsed=ref(media.matches)
const current=computed(()=>collectorPages.find(page=>page.id===route.params.id))
const icons=[DashboardOutlined,DeploymentUnitOutlined,LinkOutlined,CloudSyncOutlined,SettingOutlined]
function viewport(event:MediaQueryListEvent){collapsed.value=event.matches}
onMounted(()=>media.addEventListener('change',viewport));onBeforeUnmount(()=>media.removeEventListener('change',viewport))
watch(current,page=>{document.title=`${page?.title??'采集器管理'} · 星烽 StarBeacon 采集器`},{immediate:true})
function navigate(id:string){void router.push(`/collector/${id}`);if(window.innerWidth<900)collapsed.value=true}
</script>
<template>
  <div class="console-shell collector-shell" :class="{'is-collapsed':collapsed}">
    <aside class="sidebar" aria-label="采集器导航">
      <button class="brand" aria-label="采集器运行状态" @click="navigate('overview')"><span class="brand-symbol"><SafetyCertificateOutlined/></span><span v-if="!collapsed" class="brand-copy"><b>星烽 <span>StarBeacon</span></b><small>采集器管理</small></span></button>
      <div v-if="!collapsed" class="collector-identity"><b>{{collectorDevice.name}}</b><small>{{collectorDevice.id}}</small><span>旁路镜像 · {{collectorDevice.site}}</span></div>
      <a-menu mode="inline" :inline-collapsed="collapsed" :selected-keys="[String(route.params.id)]" class="main-menu"><a-menu-item v-for="(page,index) in collectorPages" :key="page.id" @click="navigate(page.id)"><template #icon><component :is="icons[index]"/></template>{{page.title}}</a-menu-item></a-menu>
      <div class="sidebar-footer"><ApiOutlined/><span v-if="!collapsed">交互原型 · 合成数据</span></div>
    </aside>
    <div class="console-main">
      <header class="topbar"><div class="topbar-left"><a-button type="text" :aria-label="collapsed?'展开采集器导航':'收起采集器导航'" @click="collapsed=!collapsed"><MenuUnfoldOutlined v-if="collapsed"/><MenuFoldOutlined v-else/></a-button><a-breadcrumb><a-breadcrumb-item>采集器管理</a-breadcrumb-item><a-breadcrumb-item>{{current?.title}}</a-breadcrumb-item></a-breadcrumb></div><div class="topbar-actions">
        <a-dropdown trigger="click"><a-button size="small" class="preview-state-button" :aria-label="`原型状态：${states.find(item=>item.value===state)?.label}`">原型状态：{{states.find(item=>item.value===state)?.label}}</a-button><template #overlay><a-menu :selected-keys="[state]" @click="({key}:{key:string|number})=>setState(String(key) as PreviewState)"><a-menu-item v-for="item in states" :key="item.value">{{item.label}}</a-menu-item></a-menu></template></a-dropdown>
        <router-link to="/page/sensors" class="collector-platform-link"><a-button size="small">主控平台</a-button></router-link><router-link to="/catalog" aria-label="页面目录"><a-button type="text" aria-label="页面目录"><AppstoreOutlined/></a-button></router-link><router-link to="/collector/auth/login" class="collector-admin">本地管理员 · 退出</router-link>
      </div></header>
      <main class="content-area"><slot/></main><footer class="app-footer">星烽 StarBeacon 采集器 <span>合成数据仅用于界面评审</span></footer>
    </div>
  </div>
</template>
