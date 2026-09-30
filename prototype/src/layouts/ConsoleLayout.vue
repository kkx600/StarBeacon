<script setup lang="ts">
import { computed, ref, watch, onMounted, onBeforeUnmount } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { AlertOutlined,ApiOutlined,BarChartOutlined,BellOutlined,ClusterOutlined,DashboardOutlined,FileProtectOutlined,MenuFoldOutlined,MenuUnfoldOutlined,RadarChartOutlined,RobotOutlined,SafetyCertificateOutlined,SearchOutlined,SettingOutlined,ThunderboltOutlined,UserOutlined,AppstoreOutlined,QuestionCircleOutlined,LogoutOutlined,CheckOutlined } from '@ant-design/icons-vue'
import type {PreviewState} from '../models'
import { groups,pageById,pages,states } from '../data/catalog'
import { usePreview } from '../composables/usePreview'

const route=useRoute();const router=useRouter();const {state,setState}=usePreview()
const compact=window.matchMedia('(max-width:899px)');const collapsed=ref(compact.matches);const tenant=ref('总部安全中心');const searchOpen=ref(false);const search=ref('');const noticesOpen=ref(false);const read=ref(false)
function onViewportChange(event:MediaQueryListEvent){collapsed.value=event.matches}
onMounted(()=>compact.addEventListener('change',onViewportChange));onBeforeUnmount(()=>compact.removeEventListener('change',onViewportChange))
const iconMap={AlertOutlined,ApiOutlined,BarChartOutlined,BellOutlined,ClusterOutlined,DashboardOutlined,FileProtectOutlined,RadarChartOutlined,RobotOutlined,SafetyCertificateOutlined,SettingOutlined,ThunderboltOutlined} as Record<string,typeof AlertOutlined>
const current=computed(()=>pageById.get(String(route.params.id)))
const title=computed(()=>current.value?.title??(route.path==='/catalog'?'页面目录':'访问状态'))
const groupTitle=computed(()=>groups.find(g=>g.id===current.value?.group)?.title??'星烽 StarBeacon')
const menuOpen=ref<string[]>(['overview'])
const visited=ref<string[]>(['overview','alerts','search'])
watch(()=>route.params.id, id=>{if(typeof id==='string'&&pageById.has(id)){menuOpen.value=collapsed.value?[]:[pageById.get(id)!.group];if(!visited.value.includes(id)){visited.value.push(id);if(visited.value.length>8)visited.value.shift()}document.title=`${pageById.get(id)!.title} · 星烽 StarBeacon`}}, {immediate:true})
watch(collapsed,value=>{menuOpen.value=value?[]:[current.value?.group??'overview']})
const results=computed(()=>pages.filter(p=>`${p.title}${p.description}`.includes(search.value.trim())).slice(0,20))
function navigate(id:string){void router.push(`/page/${id}`);searchOpen.value=false;if(window.innerWidth<900)collapsed.value=true}
function profileAction(key:string){if(key==='account')navigate('my-account');if(key==='logout')void router.push('/auth/login')}
</script>

<template>
  <div class="console-shell" :class="{'is-collapsed':collapsed}">
    <aside class="sidebar" aria-label="主导航">
      <button class="brand" aria-label="星烽 StarBeacon 态势总览" @click="navigate('overview')">
        <span class="brand-symbol"><SafetyCertificateOutlined /></span><span v-if="!collapsed" class="brand-copy"><b>星烽 <span>StarBeacon</span></b><small>态势感知系统</small></span>
      </button>
      <div v-if="!collapsed" class="nav-section-label">安全运营</div>
      <a-menu mode="inline" :inline-collapsed="collapsed" :selected-keys="[String(route.params.id)]" v-model:openKeys="menuOpen" class="main-menu">
        <a-sub-menu v-for="group in groups" :key="group.id">
          <template #icon><component :is="iconMap[group.icon]" /></template><template #title>{{group.title}}</template>
          <a-menu-item v-for="page in pages.filter(p=>p.group===group.id)" :key="page.id" @click="navigate(page.id)">{{page.title}}</a-menu-item>
        </a-sub-menu>
      </a-menu>
      <div class="sidebar-footer"><span class="status-dot success"></span><span v-if="!collapsed">演示环境 · 合成数据</span></div>
    </aside>
    <div class="console-main">
      <header class="topbar">
        <div class="topbar-left"><a-button type="text" :aria-label="collapsed?'展开导航':'收起导航'" @click="collapsed=!collapsed"><MenuUnfoldOutlined v-if="collapsed"/><MenuFoldOutlined v-else/></a-button><a-breadcrumb><a-breadcrumb-item>工作空间</a-breadcrumb-item><a-breadcrumb-item>{{groupTitle}}</a-breadcrumb-item><a-breadcrumb-item>{{title}}</a-breadcrumb-item></a-breadcrumb></div>
        <div class="topbar-actions">
          <a-select aria-label="当前租户" v-model:value="tenant" class="tenant-select" :options="['总部安全中心','研发事业部','集团审计组织'].map(value=>({value,label:value}))" />
          <a-tooltip title="搜索页面"><a-button type="text" aria-label="搜索页面" @click="searchOpen=true"><SearchOutlined/></a-button></a-tooltip>
          <a-tooltip title="页面目录"><a-button type="text" aria-label="页面目录" @click="router.push('/catalog')"><AppstoreOutlined/></a-button></a-tooltip>
          <a-popover v-model:open="noticesOpen" trigger="click" placement="bottomRight" title="通知中心">
            <template #content><div class="notice-popover"><p><b>{{read?'暂无未读通知':'3 条未读通知'}}</b><a-button type="link" size="small" @click="read=true">全部标记已读</a-button></p><div class="notice-item"><span class="status-dot warning"></span><div>高危告警等待研判<small>总部网络域 · 3 分钟前</small></div></div><div class="notice-item"><span class="status-dot warning"></span><div>响应动作结果未知<small>需要回读设备配置</small></div></div><div class="notice-item"><span class="status-dot success"></span><div>安全日报等待审核<small>统计窗口 2026-09-29</small></div></div><a-button block @click="navigate('delivery-logs');noticesOpen=false">查看推送日志</a-button></div></template>
            <a-button type="text" aria-label="查看通知"><a-badge :dot="!read"><BellOutlined/></a-badge></a-button>
          </a-popover>
          <a-dropdown><button class="profile-button"><a-avatar :size="28"><template #icon><UserOutlined/></template></a-avatar><span>陈宁</span></button><template #overlay><a-menu @click="({key}:{key:string|number})=>profileAction(String(key))"><a-menu-item key="account"><UserOutlined/> 个人设置</a-menu-item><a-menu-item key="logout"><LogoutOutlined/> 退出登录</a-menu-item></a-menu></template></a-dropdown>
        </div>
      </header>
      <nav class="workspace-tabs" aria-label="已访问页面"><button v-for="id in visited" :key="id" :class="{active:id===route.params.id}" @click="navigate(id)"><span v-if="id===route.params.id" class="tab-dot"></span>{{pageById.get(id)?.title}}</button><button :class="{active:route.path==='/catalog'}" @click="router.push('/catalog')"><AppstoreOutlined/> 页面目录</button></nav>
      <div class="preview-bar"><span><span class="preview-dot"></span>交互原型 <span class="preview-caption">· 全部数据为合成示例</span></span><div v-if="current" class="preview-controls"><span class="preview-label">页面状态</span><a-segmented :value="state" :options="states.map(s=>({value:s.value,label:s.label}))" size="small" @change="(value:string|number)=>setState(value as PreviewState)"/></div><a-button v-else size="small" type="text" @click="navigate('overview')">返回态势总览</a-button></div>
      <main class="content-area"><slot/></main>
      <footer class="app-footer">星烽 StarBeacon <span>合成数据仅用于界面评审</span></footer>
    </div>
    <a-modal v-model:open="searchOpen" title="搜索页面" :footer="null" :width="650"><a-input v-model:value="search" placeholder="输入功能或页面名称" allow-clear autofocus><template #prefix><SearchOutlined/></template></a-input><div class="page-search-results"><button v-for="result in results" :key="result.id" @click="navigate(result.id)"><div><b>{{result.title}}</b><small>{{result.description}}</small></div><span>{{groups.find(g=>g.id===result.group)?.title}}</span></button><a-empty v-if="!results.length" description="没有匹配的页面，请尝试其他关键词。"/></div></a-modal>
  </div>
</template>
