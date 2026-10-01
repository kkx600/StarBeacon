<script setup lang="ts">
import { message } from 'ant-design-vue'
import { defineAsyncComponent } from 'vue'
import StatePanel from '@starbeacon/shared/components/StatePanel.vue'
import HealthSummary from './HealthSummary.vue'
import InterfaceTable from './InterfaceTable.vue'
import CaptureForm from './CaptureForm.vue'
import AsyncWorkspaceState from '@starbeacon/shared/components/AsyncWorkspaceState.vue'
import WorkspaceTabs from '@starbeacon/shared/components/WorkspaceTabs.vue'
import {useWorkspaceView} from '@starbeacon/shared/utils/useWorkspaceView.ts'
import { session } from '../../session'
import { useCollector } from './useCollector'
const ReplayWorkspace=defineAsyncComponent({loader:()=>import('@starbeacon/shared/components/ReplayWorkspace.vue'),loadingComponent:AsyncWorkspaceState,errorComponent:AsyncWorkspaceState,delay:150,timeout:30000})
const {view,change}=useWorkspaceView(['interfaces','capture','samples','tasks'])
const views=[{key:'interfaces',label:'网卡与状态'},{key:'capture',label:'采集配置'},{key:'samples',label:'重放样本'},{key:'tasks',label:'任务记录'}]
const {health,interfaces,capture,pending,saving,error,refresh,save}=useCollector()
async function submit(names:string[]){try{await save(names);message.success('采集目标保存成功，等待应用')}catch(e){message.error(e instanceof Error?e.message:'保存失败')}}
</script>
<template>
  <header class="page-header"><div><h1>网络与采集</h1><p class="page-description">读取本机接口、运行状态与采集目标，核对采集器的实际环境。</p></div><a-button v-if="['interfaces','capture'].includes(view)" :loading="pending" @click="refresh">刷新</a-button></header>
  <WorkspaceTabs :active="view" :items="views" label="网络与采集功能" @change="change" />
  <StatePanel v-if="['interfaces','capture'].includes(view)" :loading="pending" :error="error" @retry="refresh">
    <template v-if="view==='interfaces'"><HealthSummary v-if="health" :health="health" /><section class="panel"><div class="panel-header"><h2>网卡列表</h2><span>{{ interfaces.length }} 个接口</span></div><InterfaceTable :items="interfaces" /></section></template>
    <section v-else class="panel"><div class="panel-header"><h2>采集配置</h2></div><div class="panel-body"><CaptureForm :interfaces="interfaces" :capture="capture" :saving="saving" @save="submit" /></div></section>
  </StatePanel>
  <ReplayWorkspace v-else :api="session.api" local @tasks="change('tasks')" :view="view==='tasks'?'tasks':'samples'" />
</template>
