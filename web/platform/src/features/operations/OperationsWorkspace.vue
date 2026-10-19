<script setup lang="ts">
import {usePageTitle} from '@starbeacon/shared/utils/usePageTitle.ts'
const pageTitle=usePageTitle('运行与审计')
import WorkspaceTabs from '@starbeacon/shared/components/WorkspaceTabs.vue'
import {useWorkspaceView} from '@starbeacon/shared/utils/useWorkspaceView.ts'
import AuditWorkspace from './AuditWorkspace.vue'
import PlatformHealth from './PlatformHealth.vue'
const {view,change}=useWorkspaceView(['health','operations','logins'])
const items=[{key:'health',label:'运行状态'},{key:'operations',label:'操作日志'},{key:'logins',label:'登录日志'}]
</script>
<template><header class="page-header"><div><h1>{{pageTitle}}</h1><p class="page-description">核对平台运行资源、依赖可用性及当前租户的操作与登录记录。</p></div></header><WorkspaceTabs :active="view" :items="items" label="运行与审计功能" @change="change"/><PlatformHealth v-if="view==='health'"/><AuditWorkspace v-else :category="view==='operations'?'operations':'logins'"/></template>
