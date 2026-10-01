<script setup lang="ts">
import { message } from 'ant-design-vue'
import StatePanel from '@starbeacon/shared/components/StatePanel.vue'
import HealthSummary from './HealthSummary.vue'
import InterfaceTable from './InterfaceTable.vue'
import CaptureForm from './CaptureForm.vue'
import { useCollector } from './useCollector'
const {health,interfaces,capture,pending,saving,error,refresh,save}=useCollector()
async function submit(names:string[]){try{await save(names);message.success('采集目标保存成功，等待应用')}catch(e){message.error(e instanceof Error?e.message:'保存失败')}}
</script>
<template>
  <header class="page-header"><div><h1>网络与采集</h1><p class="page-description">读取本机接口、运行状态与采集目标，核对采集器的实际环境。</p></div><a-button :loading="pending" @click="refresh">刷新</a-button></header>
  <StatePanel :loading="pending" :error="error" @retry="refresh"><HealthSummary v-if="health" :health="health" /><section class="panel"><div class="panel-header"><h2>网卡列表</h2><span>{{ interfaces.length }} 个接口</span></div><InterfaceTable :items="interfaces" /></section><section class="panel"><div class="panel-header"><h2>采集配置</h2></div><div class="panel-body"><CaptureForm :interfaces="interfaces" :capture="capture" :saving="saving" @save="submit" /></div></section></StatePanel>
</template>
