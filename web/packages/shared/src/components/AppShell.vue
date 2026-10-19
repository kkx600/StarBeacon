<script setup lang="ts">
import { shallowRef, type VNode } from 'vue'
import { SafetyCertificateOutlined, MenuFoldOutlined, MenuUnfoldOutlined, LogoutOutlined } from '@ant-design/icons-vue'
import {Breadcrumb as ABreadcrumb} from 'ant-design-vue'
import NavigationMenu from './NavigationMenu.vue'
const ABreadcrumbItem=ABreadcrumb.Item
defineProps<{title: string; username: string; current: string; allowPasswordChange?:boolean; breadcrumbs?:{label:string;path?:string}[]; items: {key: string; label: string; icon?: () => VNode; title?:string;children?:{key:string;label:string;title?:string}[]}[]}>()
const emit = defineEmits<{navigate: [path: string]; logout: []; password:[]}>()
const collapsed = shallowRef(false)
const mobileMenu = shallowRef(false)
function toggleMenu() {if (window.matchMedia('(max-width: 550px)').matches) mobileMenu.value = true; else collapsed.value = !collapsed.value}
function navigate(path: string) {mobileMenu.value = false; emit('navigate', path)}
</script>

<template>
  <a-layout class="app-shell">
    <a-layout-sider :collapsed="collapsed" :width="220" theme="light" collapsible :trigger="null" breakpoint="lg" :collapsed-width="64" aria-label="主导航" @collapse="(value: boolean) => collapsed = value">
      <div class="brand"><SafetyCertificateOutlined class="brand-symbol" /><span v-if="!collapsed">星烽 <b>StarBeacon</b><small>{{ title }}</small></span></div>
      <NavigationMenu :current="current" :collapsed="collapsed" :items="items" @navigate="navigate"/>
    </a-layout-sider>
    <a-layout>
      <a-layout-header class="app-header">
        <a-button type="text" :aria-label="collapsed ? '展开导航' : '收起导航'" @click="toggleMenu"><MenuUnfoldOutlined v-if="collapsed" /><MenuFoldOutlined v-else /></a-button>
        <a-breadcrumb v-if="breadcrumbs?.length" class="shell-breadcrumb" aria-label="当前位置"><a-breadcrumb-item v-for="(item,index) in breadcrumbs" :key="index"><a-button v-if="item.path" type="link" @click="navigate(item.path)">{{item.label}}</a-button><span v-else>{{item.label}}</span></a-breadcrumb-item></a-breadcrumb><span v-else class="header-title">{{ title }}</span><span class="header-user">{{ username }}</span>
        <a-button v-if="allowPasswordChange" type="text" @click="emit('password')">修改密码</a-button>
        <a-button type="text" @click="emit('logout')"><LogoutOutlined />退出</a-button>
      </a-layout-header>
      <a-layout-content class="app-content"><slot /></a-layout-content>
    </a-layout>
  </a-layout>
  <a-drawer title="主导航" placement="left" :open="mobileMenu" :width="220" @close="mobileMenu = false"><NavigationMenu :current="current" :items="items" @navigate="navigate"/></a-drawer>
</template>
<style scoped>.shell-breadcrumb{min-width:0;flex:1}.shell-breadcrumb :deep(ol){flex-wrap:wrap;row-gap:0}.shell-breadcrumb :deep(.ant-btn){height:auto;padding:0;font-size:inherit}.shell-breadcrumb :deep(li){overflow-wrap:anywhere}@media(max-width:1000px){.shell-breadcrumb :deep(li:first-child){display:none}}</style>
