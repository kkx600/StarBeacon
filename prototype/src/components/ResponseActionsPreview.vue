<script setup lang="ts">
import {computed,onScopeDispose,reactive,shallowRef,watch} from 'vue'
import {useRoute,useRouter} from 'vue-router'
import {useFeedback} from '../../../web/packages/shared/src/composables/useFeedback'
import TaskTable from '../../../web/packages/shared/src/components/TaskTable.vue'
import ResponseActionFilters from '../../../web/packages/shared/src/components/ResponseActionFilters.vue'
import {defaultResponseFilters,linkedResponseFilters} from '../../../web/packages/shared/src/responseCatalog'
import type {SensorTask,TaskDetailState} from '../../../web/packages/shared/src/types'
import type {PreviewState} from '../models'
import {goJSONDigest} from '../../../web/packages/shared/src/utils/goJSONDigest'
import {validResponseProtection,type ResponseProtection} from '../../../web/packages/shared/src/responseProtection'
import PageHeader from './PageHeader.vue'
import StatePanel from './StatePanel.vue'
const props=defineProps<{state:PreviewState}>(),emit=defineEmits<{state:[value:PreviewState]}>(),message=useFeedback()
const filters=reactive(defaultResponseFilters())
const route=useRoute(),router=useRouter()
watch(()=>[route.query.sensor_id,route.query.device_id],()=>{try{Object.assign(filters,linkedResponseFilters(route.query))}catch{message.error('关联动作条件无效，请核对探针与设备标识。')}},{immediate:true})
const rows=shallowRef<SensorTask[]>(['unknown','succeeded','queued'].map((state,i)=>{
 const id=['task_action_unknown','task_action_verified','task_action_pending'][i]!,at=Date.now()-(i===2?5000:3600000),created=new Date(at).toISOString(),leaseEnd=new Date(at+300000).toISOString(),finished=new Date(at+10000).toISOString()
 const action={schema_version:'response.action.v1' as const,connector_id:'connector_hq',config_sha256:'a'.repeat(64),device_id:'device_hq',lease_id:id,owner_sha256:'b'.repeat(64),target_ip:'198.51.100.'+(24+i),requested_at:created,expires_at:leaseEnd,reason:'合成限时处置示例'}
 const receipt=i===2?{}:{command_id:id,command_sha256:'c'.repeat(64),state,started_at:created,finished_at:finished,result:i===1?{schema_version:'response.result.v1',connector_id:action.connector_id,config_sha256:action.config_sha256,verified:true,traffic_effect:'not_observed',observation:{schema_version:'response.lease.v1',device_id:action.device_id,lease_id:id,owner_sha256:action.owner_sha256,target_ip:action.target_ip,expires_at:leaseEnd,state:'active',observed_at:finished}}:{}}
 return {id,sensor_id:'sensor_hq',kind:'response.block',state,created_by:'admin_example',created_at:created,updated_at:created,expires_at:new Date(at+60000).toISOString(),retain_until:new Date(at+180*86400000).toISOString(),delivery_count:i===2?0:1,response_action:action,receipt}
}))
let disposed=false
const proofError=shallowRef('')
const queued=rows.value.find(row=>row.id==='task_action_pending')!,check={schema_version:'watchlist-response-check.v1' as const,checked_at:queued.response_action!.requested_at,state_sha256:'e'.repeat(64),matches:[]}
void goJSONDigest(check).then(check_sha256=>{if(disposed)return;const proof:ResponseProtection={schema_version:'response.protection.v1',command_sha256:'c'.repeat(64),check_sha256,check};if(!validResponseProtection(proof,queued.kind,queued.response_action!.requested_at,queued.response_action!.expires_at))throw new Error('合成授权记录未通过工程字段与时间边界校验。');rows.value=rows.value.map(row=>row.id===queued.id?{...row,response_protection:proof}:row)}).catch(e=>{if(!disposed)proofError.value=e instanceof Error?e.message:'合成记录无法校验'})
onScopeDispose(()=>{disposed=true})
const items=computed(()=>props.state==='empty'?[]:rows.value.filter(row=>(!filters.target_ip||row.response_action?.target_ip===filters.target_ip)&&(!filters.sensor_id||row.sensor_id===filters.sensor_id)&&(!filters.device_id||row.response_action?.device_id===filters.device_id)&&(!filters.kind||row.kind===filters.kind)&&(!filters.state||row.state===filters.state)))
const detail=reactive<TaskDetailState>({open:false,item:null,pending:false,error:''})
watch([()=>props.state,()=>route.query.task,rows],([state,task])=>{const requested=task!==undefined;detail.open=!['empty','loading','error'].includes(state)&&(requested||['detail','action'].includes(state));detail.item=detail.open?(requested&&typeof task==='string'?rows.value.find(row=>row.id===task)??null:requested?null:rows.value[0]??null):null;detail.error=detail.open&&requested&&!detail.item?'所选任务不在当前合成示例范围内，请返回列表重新选择。':'';detail.pending=false},{immediate:true})
function view(id:string){void router.replace({query:{...route.query,task:id},hash:route.hash})}
function close(){detail.open=false;void router.replace({query:{...route.query,task:undefined,state:['detail','action'].includes(props.state)?'data':route.query.state},hash:route.hash});if(['detail','action'].includes(props.state))emit('state','data')}
function example(){message.info('以下为合成示例，未提交平台或设备任务。')}
</script>
<template>
 <PageHeader title="响应动作" description="集中核对限时封禁、租约回读与解除任务，追溯执行位置、目标和独立设备回执。"/>
 <a-alert type="info" show-icon message="以下为合成示例，展示工程端相同的筛选、任务列表和详情组件。名单核对记录也为合成材料，不构成真实授权，不连接设备或提交响应动作。" class="section-gap"/>
 <a-alert v-if="proofError" type="error" show-icon :message="proofError" class="section-gap"/>
 <ResponseActionFilters :model="filters" :pending="state==='loading'" @search="emit('state','data')" @reset="Object.assign(filters,defaultResponseFilters());emit('state','data')"/>
 <section class="panel"><div class="panel-header"><div><h2>响应记录</h2><p class="page-description">按创建时间检索，每页 20 项，窗口最多 31 天。执行状态以读取时为准；设备回读与真实阻断效果分别核对。</p></div><a-button @click="emit('state','data')">刷新任务</a-button></div>
  <StatePanel v-if="['empty','loading','error'].includes(state)" :state="state as 'empty'|'loading'|'error'" :description="state==='empty'?'当前条件下没有响应动作，请调整时间、目标或状态。':undefined" @action="emit('state','data')"/>
  <TaskTable v-else :items="items" :detail="detail" response-catalog responseable cancellable @view="view($event.id)" @open-task="view" @close="close" @refresh-detail="example" @response="example" @cancel="example"/>
  <div class="response-pagination"><a-button disabled>上一页</a-button><span>第 1 页 · 当前 {{items.length}} 项</span><a-button disabled>下一页</a-button></div>
 </section>
</template>
<style scoped>.panel-header{padding:var(--section-gap) var(--panel-inset);display:flex;align-items:center;justify-content:space-between;gap:var(--field-gap)}.panel-header h2{margin:0;font-size:16px}.page-description{margin:0;color:var(--muted);line-height:1.6;font-size:13px;max-width:72ch}.section-gap{margin-bottom:var(--section-gap)}.response-pagination{display:flex;justify-content:flex-end;align-items:center;flex-wrap:wrap;gap:var(--related-gap);padding:var(--panel-inset)}</style>
