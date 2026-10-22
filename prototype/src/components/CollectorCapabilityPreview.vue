<script setup lang="ts">
import {computed,nextTick,onScopeDispose,shallowRef,watch} from 'vue'
import {useRoute,useRouter} from 'vue-router'
import type {CollectorView} from '../../../web/collector/src/navigation'
import type {CaptureConfig,CaptureSettings,HostHealth,NetworkInterface,SensorTask} from '../../../web/packages/shared/src/types'
import HealthSummary from '../../../web/collector/src/features/network/HealthSummary.vue'
import CollectorInterfacePanel from '../../../web/collector/src/features/network/CollectorInterfacePanel.vue'
import CaptureForm from '../../../web/packages/shared/src/components/CaptureForm.vue'
import ProbeIdentitySummary from '../../../web/packages/shared/src/components/ProbeIdentitySummary.vue'
import TaskTable from '../../../web/packages/shared/src/components/TaskTable.vue'
import StatePanel from '../../../web/packages/shared/src/components/StatePanel.vue'
import {useFeedback} from '../../../web/packages/shared/src/composables/useFeedback'
import type {PreviewState} from '../models'
import {engineHealthExample} from '../data/engineHealth'
const props=defineProps<{view:CollectorView;state:PreviewState}>(),emit=defineEmits<{state:[value:PreviewState]}>(),route=useRoute(),router=useRouter()
const at='2026-10-22T01:00:00Z'
const interfaces:NetworkInterface[]=[{name:'eth0',index:2,mac:'02:00:00:00:00:01',mtu:1500,up:true,loopback:false,addresses:[]},{name:'eth1',index:3,mac:'02:00:00:00:00:02',mtu:1500,up:true,loopback:false,addresses:['192.0.2.8/24','2001:db8::8/64']},{name:'lo',index:1,mac:'',mtu:65536,up:true,loopback:true,addresses:['127.0.0.1/8','::1/128']}]
const capture=shallowRef<CaptureConfig>({interfaces:['eth0'],threads:2,bpf_filter:'',promiscuous:true,managed:false,status:'not_applied',revision:1,observed_at:at})
const saved=shallowRef(false)
const health=computed<HostHealth>(()=>({version:'合成构建',hostname:'collector-example',observed_at:at,cpu_percent:22,memory_percent:35,disk_percent:48,rx_bytes:'60250000',tx_bytes:'12416',wal_pending:3,wal_bytes:8192,errors:[],capture_status:'not_applied',engine_health:engineHealthExample(route.query.engine)}))
const identity={mode:'managed' as const,sensor_id:'probe_office_01',registration_id:'reg_office_example',fingerprint_sha256:'34a890f1698b34dd865b8afea927fca870f8d7d9f71550affd7f6d3809573d99',not_before:'2026-10-22T00:00:00Z',renew_after:'2026-10-22T18:00:00Z',not_after:'2026-10-23T00:00:00Z'}
const tasks:SensorTask[]=['diagnostics','rules.apply','capture.configure','rules.replay'].map((kind,index)=>({id:`task_example_${index+1}`,sensor_id:'probe_office_01',kind,state:index===1?'unknown':'queued',created_by:'admin_example',created_at:at,expires_at:'2026-10-22T02:00:00Z',retain_until:'2027-04-20T01:00:00Z',retention_protected:true,delivery_count:index===1?1:0,updated_at:at,receipt:index===1?{state:'unknown',code:'execution_interrupted',result:{}}:{},origin:index===0?'local':'platform',acknowledged:false}))
const snapshots=shallowRef(tasks),taskPending=shallowRef(false),feedback=useFeedback(),refreshKey='collector-task-example-refresh'
let refreshEpoch=0
const hasTask=computed(()=>Object.hasOwn(route.query,'task')),taskID=computed(()=>typeof route.query.task==='string'?route.query.task:'')
const chosen=computed(()=>snapshots.value.find(row=>row.id===taskID.value)??(!hasTask.value&&props.state==='detail'?snapshots.value[0]:undefined))
const taskDetail=computed(()=>({open:hasTask.value||props.state==='detail',item:chosen.value??null,pending:taskPending.value,error:!taskPending.value&&hasTask.value&&!chosen.value?'任务不在当前合成示例范围内，请返回列表重新选择。':''}))
watch([()=>route.query.task,()=>props.state,()=>props.view],()=>{refreshEpoch++;taskPending.value=false;feedback.destroy(refreshKey)})
onScopeDispose(()=>{refreshEpoch++;feedback.destroy(refreshKey)})
async function refreshTask(){
 const current=++refreshEpoch;taskPending.value=true;feedback.destroy(refreshKey);await nextTick()
 if(current!==refreshEpoch)return
 snapshots.value=structuredClone(tasks);taskPending.value=false
 feedback.open({key:refreshKey,type:chosen.value?'info':'warning',content:chosen.value?`已重新读取合成任务 ${chosen.value.id}；记录来自固定示例，不代表设备状态已更新。`:'指定任务不在当前合成示例范围内，未读取其他任务。'})
}
function save(settings:CaptureSettings){capture.value={...capture.value,...structuredClone(settings),revision:(capture.value.revision??0)+1,status:'not_applied'};saved.value=true}
function inspect(row:SensorTask){void router.replace({query:{...route.query,task:row.id},hash:route.hash})}
function closeTask(){void router.replace({query:{...route.query,task:undefined,state:props.state==='detail'?'data':route.query.state},hash:route.hash});if(props.state==='detail')emit('state','data')}
</script>
<template>
 <div class="collector-capability"><StatePanel :loading="state==='loading'" :error="state==='error'?'合成观测来源暂时不可用，当前状态无法确认。':''" :empty="state==='empty'" description="当前示例范围内没有可读取的观测记录。" @retry="emit('state','data')">
  <HealthSummary v-if="view==='overview'" :health="health"/>
  <CollectorInterfacePanel v-else-if="view==='interfaces'" :interfaces="interfaces"/>
  <section v-else-if="view==='capture'" class="panel collector-capability-body"><a-alert v-if="saved" type="info" show-icon message="采集目标已保存在原型内存，实际采集尚未应用。" class="section-gap"/><CaptureForm :interfaces="interfaces" :capture="capture" :saving="false" @save="save"/></section>
  <section v-else-if="view==='identity'" class="panel collector-capability-body"><ProbeIdentitySummary :identity="identity" :now="Date.parse(at)"/><p class="muted">本页展示固定合成证书快照，不读取本机证书。刷新证书状态请在实际采集器中操作；本页不发起注册、续签或吊销。</p></section>
  <section v-else-if="view==='tasks'" class="panel"><TaskTable :items="snapshots" local :detail="taskDetail" @view="inspect" @close="closeTask" @refresh-detail="refreshTask"/></section>
 </StatePanel></div>
</template>
<style scoped>.collector-capability-body{padding:var(--panel-inset)}.collector-capability :deep(.metric-grid){display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:var(--related-gap);padding:var(--panel-inset)}.collector-capability :deep(.metric-grid>div){display:flex;flex-direction:column;gap:var(--label-gap);min-width:0}.collector-capability :deep(.metric-grid strong){font-size:24px;color:var(--text);font-variant-numeric:tabular-nums}.collector-capability :deep(.metric-grid small),.collector-capability :deep(.metric-grid span){color:var(--muted)}.collector-capability :deep(.panel-header){display:flex;align-items:center;justify-content:space-between;gap:var(--related-gap);padding:var(--panel-inset)}.collector-capability :deep(.panel-header h2){margin:0;font-size:16px}.collector-capability :deep(.panel-body){padding:0 var(--panel-inset) var(--panel-inset);overflow-wrap:anywhere}@media(max-width:900px){.collector-capability :deep(.metric-grid){grid-template-columns:repeat(2,minmax(0,1fr))}}</style>
