<script setup lang="ts">
import { onMounted, onScopeDispose, shallowRef } from 'vue'
import { message } from 'ant-design-vue'
import type { SensorTask } from '@starbeacon/shared/types.ts'
import StatePanel from '@starbeacon/shared/components/StatePanel.vue'
import TaskTable from '@starbeacon/shared/components/TaskTable.vue'
import { session } from '../../session'
const props = defineProps<{sensorId?:string}>()
const items=shallowRef<SensorTask[]>([]),pending=shallowRef(true),error=shallowRef(''),saving=shallowRef(false)
let controller:AbortController|undefined
async function refresh(){controller?.abort();const current=new AbortController();controller=current;pending.value=true;error.value='';try{const result=await session.api.request<{items:SensorTask[]}>('/tasks'+(props.sensorId?'?sensor_id='+encodeURIComponent(props.sensorId):''),{signal:current.signal});if(!current.signal.aborted)items.value=result.items}catch(e){if(!current.signal.aborted)error.value=e instanceof Error?e.message:'读取失败'}finally{if(controller===current)pending.value=false}}
async function cancel(task:SensorTask){saving.value=true;try{await session.api.request(`/tasks/${encodeURIComponent(task.id)}/cancel`,{method:'POST',body:{}});message.success('任务已取消');await refresh()}catch(e){message.error(e instanceof Error?e.message:'取消失败')}finally{saving.value=false}}
onMounted(refresh);onScopeDispose(()=>controller?.abort());defineExpose({refresh})
</script>
<template>
  <section class="panel"><div class="panel-header"><h2>任务记录</h2><a-button :loading="pending" @click="refresh">刷新任务</a-button></div>
    <StatePanel :loading="pending" :error="error" :empty="items.length===0" description="暂无任务记录。可在探针详情中提交运行诊断，或在规则管理中提交装载检查与 PCAP 重放。" @retry="refresh"><TaskTable :items="items" cancellable :saving="saving" @cancel="cancel" /></StatePanel>
  </section>
</template>
