<script setup lang="ts">
import {useFeedback} from '@starbeacon/shared/composables/useFeedback.ts'
import { computed,inject,onMounted,onScopeDispose,reactive,shallowRef,watch } from 'vue'
import {routeLocationKey,routerKey} from 'vue-router'
import type { Sensor, SensorTask } from '@starbeacon/shared/types.ts'
import StatePanel from '@starbeacon/shared/components/StatePanel.vue'
import TaskTable from '@starbeacon/shared/components/TaskTable.vue'
import { session } from '../../session'
import {readSensorDirectory} from '@starbeacon/shared/sensors.ts'
import {readyConnector} from '@starbeacon/shared/response.ts'
import {useTaskDetail} from './useTaskDetail'
import {ApiError} from '@starbeacon/shared/api.ts'
import ResponseActionFilters from '@starbeacon/shared/components/ResponseActionFilters.vue'
import {defaultResponseFilters,linkedResponseFilters,responseQuery,readResponsePage,type ResponseQuery} from '@starbeacon/shared/responseCatalog.ts'
const message=useFeedback()
const props = defineProps<{sensorId?:string;responseOnly?:boolean}>()
const route=inject(routeLocationKey,undefined),router=inject(routerKey,undefined)
const {detail,refresh:refreshDetail}=useTaskDetail(computed(()=>route?.query.task),()=>props.sensorId,()=>!!props.responseOnly)
function viewTask(task:Pick<SensorTask,'id'>){if(route&&router)void router.push({path:route.path,query:{...route.query,task:task.id},hash:route.hash})}
function closeDetail(){if(route&&router)void router.replace({path:route.path,query:{...route.query,task:undefined},hash:route.hash})}
const items=shallowRef<SensorTask[]>([]),pending=shallowRef(true),error=shallowRef(''),saving=shallowRef(false)
let controller:AbortController|undefined,cancelController:AbortController|undefined,timer:ReturnType<typeof setTimeout>|undefined,stopped=false,failures=0
const reconcileKeys=new Map<string,{sha:string;key:string}>()
type ResponseAttempt={task:SensorTask;kind:'response.read'|'response.revoke';key:string;input:{kind:string;connector_id:string;config_sha256:string;original_task_id:string;reason:string}}
const responseAttempts=reactive(new Map<string,ResponseAttempt>())
const unconfirmedResponse=computed(()=>responseAttempts.values().next().value as ResponseAttempt|undefined)
const filters=reactive(defaultResponseFilters()),applied=shallowRef<ResponseQuery>(responseQuery(filters)),cursors=shallowRef(['']),nextCursor=shallowRef(''),filterError=shallowRef(''),linkedError=shallowRef(false)
function search(){try{applied.value=responseQuery(filters);linkedError.value=false;cursors.value=[''];items.value=[];nextCursor.value='';filterError.value='';void refresh()}catch(cause){filterError.value=(cause as Error).message}}
function reset(){Object.assign(filters,defaultResponseFilters());search()}
function applyLinkedFilters(){
 if(!props.responseOnly){void refresh();return}
 controller?.abort();if(timer)clearTimeout(timer);items.value=[];cursors.value=[''];nextCursor.value='';filterError.value='';linkedError.value=false
 try{Object.assign(filters,linkedResponseFilters(route?.query??{}));applied.value=responseQuery(filters);void refresh()}catch(cause){pending.value=false;linkedError.value=true;filterError.value=(cause as Error).message}
}
function page(next:boolean){if(pending.value||next&&!nextCursor.value||!next&&cursors.value.length<=1)return;cursors.value=next?[...cursors.value,nextCursor.value]:cursors.value.slice(0,-1);items.value=[];nextCursor.value='';void refresh()}
function schedule(){if(timer)clearTimeout(timer);if(stopped||failures>=3)return;if(error.value||items.value.some(task=>['queued','delivered','running'].includes(task.state)))timer=setTimeout(()=>refresh(false),error.value?5000*2**Math.max(0,failures-1):5000)}
async function refresh(showLoading=true){if(stopped||props.responseOnly&&linkedError.value)return;if(props.responseOnly&&session.current.value?.role!=='admin'){pending.value=false;return;}controller?.abort();const current=new AbortController();controller=current;if(showLoading){pending.value=true;failures=0}try{
 const query={...applied.value,cursor:cursors.value.at(-1)??''}
 const result=await session.api.request<{items:SensorTask[]}>(props.responseOnly?'/response-actions?'+new URLSearchParams(Object.entries(query).map(([k,v])=>[k,String(v)])):'/tasks'+(props.sensorId?'?sensor_id='+encodeURIComponent(props.sensorId):''),{signal:current.signal})
 const qualified=props.responseOnly?await readResponsePage(result,query):undefined
 if(!current.signal.aborted){items.value=qualified?.items??result.items;nextCursor.value=qualified?.next_cursor??'';error.value='';failures=0}
 }catch(e){if(!current.signal.aborted){error.value=e instanceof Error?e.message:'读取失败';failures++}}finally{if(controller===current){pending.value=false;schedule()}}}
async function cancel(task:SensorTask){if(saving.value||stopped)return;if(responseAttempts.size){message.error('请先核对原联动提交，再发起其他操作。');return;}saving.value=true;const current=new AbortController();cancelController=current;try{await session.api.request(`/tasks/${encodeURIComponent(task.id)}/cancel`,{method:'POST',body:{},signal:current.signal});if(current.signal.aborted)return;message.success('任务已取消');await refresh();void refreshDetail()}catch(e){if(!current.signal.aborted)message.error(e instanceof Error?e.message:'取消失败')}finally{if(!stopped&&cancelController===current)saving.value=false}}
async function reconcile(task:SensorTask){
  if(stopped||saving.value||session.current.value?.role!=='admin'||props.sensorId&&task.sensor_id!==props.sensorId||task.kind!=='rules.apply'||task.state!=='unknown'||task.rule_resolution)return
  if(responseAttempts.size){message.error('请先核对原联动提交，再发起其他操作。');return}
  saving.value=true;const current=new AbortController();cancelController=current
  try{
    const result=await readSensorDirectory(session.api,current.signal)
    if(current.signal.aborted)return
    const target=result.find(item=>item.id===task.sensor_id),sha=target?.health.registered_rules_sha256??''
    if(!target?.active||target.status!=='online'||!target.health.task_capabilities?.includes('rules.reconcile')||!/^[a-f0-9]{64}$/.test(sha))throw new Error('探针当前不可核实，请核对在线状态、规则摘要和部署授权')
    let entry=reconcileKeys.get(task.id)
    if(!entry||entry.sha!==sha){entry={sha,key:crypto.randomUUID()};reconcileKeys.set(task.id,entry)}
    await session.api.request(`/sensors/${encodeURIComponent(task.sensor_id)}/tasks`,{method:'POST',headers:{'Idempotency-Key':entry.key},body:{kind:'rules.reconcile',unknown_task_id:task.id,expected_rules_sha256:sha},signal:current.signal})
    if(current.signal.aborted)return
    message.success('规则核实任务已受理，请查看设备执行回执');await refresh();void refreshDetail()
  }catch(cause){if(!current.signal.aborted)message.error(cause instanceof Error?cause.message:'规则核实任务提交失败')}
  finally{if(!stopped&&cancelController===current)saving.value=false}
}
async function respond(task:SensorTask,kind:'response.read'|'response.revoke'){
 if(stopped||saving.value||session.current.value?.role!=='admin'||props.sensorId&&task.sensor_id!==props.sensorId||task.kind!=='response.block'||!task.response_action||task.delivery_count<=0||!['succeeded','unknown','failed'].includes(task.state))return
 saving.value=true;const current=new AbortController();cancelController=current
 const identity=task.id+'/'+kind
 try{
  let attempt=responseAttempts.get(identity)
  if(!attempt&&responseAttempts.size)throw new Error('请先核对原联动提交，再发起其他联动操作。')
  if(!attempt){const rows=await readSensorDirectory(session.api,current.signal);if(current.signal.aborted)return
  const target=rows.find(v=>v.id===task.sensor_id),binding=target?.health.response_connectors?.find(v=>v.connector_id===task.response_action!.connector_id)
  const seen=Date.parse(target?.last_seen??'')
  if(!target?.active||target.status!=='online'||!Number.isFinite(seen)||Date.now()-seen>35000||seen-Date.now()>30000||!target.health.task_capabilities?.includes(kind)||!binding||!readyConnector(binding)||binding.config_sha256!==task.response_action.config_sha256||binding.device_id!==task.response_action.device_id)throw new Error('执行采集器或原设备配置尚未就绪，请刷新核对。')
   attempt={task,kind,key:crypto.randomUUID(),input:{kind,connector_id:binding.connector_id,config_sha256:binding.config_sha256,original_task_id:task.id,reason:kind==='response.read'?'核对原封禁租约当前状态':'解除原封禁任务独立租约'}};responseAttempts.set(identity,attempt)
  }
  const result=await session.api.request<{id:string}>(`/sensors/${encodeURIComponent(attempt.task.sensor_id)}/response-tasks`,{method:'POST',headers:{'Idempotency-Key':attempt.key},body:attempt.input,signal:current.signal})
  if(current.signal.aborted)return
  if(!result||!/^task_[a-f0-9]{32}$/.test(result.id))throw new Error('提交回执不完整，请使用相同操作核对原提交。')
  responseAttempts.delete(identity);message.success('联动任务已受理，请核对独立设备回执');await refresh();if(props.responseOnly)viewTask({id:result.id});else void refreshDetail()
 }catch(cause){if(!current.signal.aborted){if(cause instanceof ApiError&&[400,401,403,404,409,413,422,429].includes(cause.status))responseAttempts.delete(identity);message.error(cause instanceof Error?cause.message:'联动任务提交失败')}}
 finally{if(!stopped&&cancelController===current)saving.value=false}
}
onMounted(applyLinkedFilters);watch(()=>[route?.query.sensor_id,route?.query.device_id],()=>{if(props.responseOnly)applyLinkedFilters()});watch(()=>[props.sensorId,props.responseOnly,session.current.value?.tenant_id,session.current.value?.id,session.current.value?.role],()=>{cancelController?.abort();cancelController=undefined;saving.value=false;items.value=[];reconcileKeys.clear();responseAttempts.clear();cursors.value=[''];nextCursor.value='';filterError.value='';Object.assign(filters,defaultResponseFilters());applied.value=responseQuery(filters);if(props.responseOnly)applyLinkedFilters();else void refresh()});onScopeDispose(()=>{stopped=true;controller?.abort();cancelController?.abort();if(timer)clearTimeout(timer)});defineExpose({refresh:()=>{void refresh();void refreshDetail()}})
</script>
<template>
  <ResponseActionFilters v-if="responseOnly" :model="filters" :pending="pending" @search="search" @reset="reset"/>
  <a-alert v-if="responseOnly&&filterError" type="error" show-icon :message="filterError" class="section-gap"/>
  <section class="panel"><div class="panel-header"><div><h2>{{responseOnly?'响应记录':'任务记录'}}</h2><p class="page-description">{{responseOnly?'按创建时间检索，每页 20 项，窗口最多 31 天。执行状态以读取时为准；设备回读与真实阻断效果分别核对。':'列表显示最近 200 项；历史任务可通过处置档案或任务链接查看。'}}</p></div><a-button :loading="pending" @click="refresh();refreshDetail()">刷新任务</a-button></div>
    <div v-if="unconfirmedResponse" class="panel-body"><a-alert type="warning" show-icon message="联动提交结果尚未确认" description="原请求键与输入保留在当前页面会话中。请核对原提交，避免重复操作；配置变化或设备离线不妨碍确认原受理回执。"><template #action><a-button :loading="saving" @click="respond(unconfirmedResponse.task,unconfirmedResponse.kind)">核对原联动提交</a-button></template></a-alert></div>
    <div v-if="error&&items.length" class="panel-body"><a-alert type="warning" show-icon message="任务状态更新失败" :description="`${error}。当前显示上次成功读取的状态，请刷新核实。`"/></div>
    <StatePanel :loading="pending&&items.length===0&&!detail.open" :error="items.length||detail.open?undefined:error" :empty="items.length===0&&!detail.open" :description="responseOnly?'当前条件下没有响应动作。请调整时间、目标或状态；限时封禁可从探针详情或研判处置确认提交。':'暂无任务记录。可在探针详情中提交运行诊断，或在规则管理中提交装载检查与 PCAP 重放。'" @retry="refresh()"><TaskTable :items="items" :detail="route?detail:undefined" :response-catalog="responseOnly" cancellable :reconcilable="!responseOnly&&session.current.value?.role==='admin'" :saving="saving" :responseable="session.current.value?.role==='admin'" @view="viewTask" @open-task="id=>viewTask({id})" @close="closeDetail" @refresh-detail="refreshDetail" @cancel="cancel" @reconcile="reconcile" @response="respond" /></StatePanel>
    <div v-if="responseOnly" class="response-pagination"><a-button :disabled="pending||cursors.length<=1" @click="page(false)">上一页</a-button><span>第 {{cursors.length}} 页 · 当前 {{items.length}} 项</span><a-button :disabled="pending||!nextCursor||!!error" @click="page(true)">下一页</a-button></div>
  </section>
</template>
<style scoped>.response-pagination{display:flex;justify-content:flex-end;align-items:center;flex-wrap:wrap;gap:var(--related-gap);padding:var(--panel-inset)}</style>
