<script setup lang="ts">
import {defineAsyncComponent} from 'vue'
import WorkspaceTabs from '@starbeacon/shared/components/WorkspaceTabs.vue'
import AsyncWorkspaceState from '@starbeacon/shared/components/AsyncWorkspaceState.vue'
import {useWorkspaceView} from '@starbeacon/shared/utils/useWorkspaceView.ts'
import TrafficEvents from './TrafficEvents.vue'
import {session} from '../../session'
const PacketArchiveWorkspace=defineAsyncComponent({loader:()=>import('@starbeacon/shared/components/PacketArchiveWorkspace.vue'),loadingComponent:AsyncWorkspaceState,errorComponent:AsyncWorkspaceState,delay:150,timeout:30000})
const {view,change}=useWorkspaceView(['events','archives'])
const views=[{key:'events',label:'协议记录'},{key:'archives',label:'原包归档'}]
</script>
<template>
 <header class="page-header"><div><h1>流量检索</h1><p class="page-description">检索协议事件与会话摘要，读取旁路捕获的实际原包。</p></div></header>
 <WorkspaceTabs :active="view" :items="views" label="流量检索功能" @change="change"/>
 <TrafficEvents v-if="view==='events'"/>
 <PacketArchiveWorkspace v-else :api="session.api"/>
</template>
