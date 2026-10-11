<script setup lang="ts">
import {computed,onScopeDispose,reactive,ref,shallowRef,watch} from 'vue'
import {Modal as AModal,Select as ASelect,InputNumber as AInputNumber,Checkbox as ACheckbox,message} from 'ant-design-vue'
import {useRouter} from 'vue-router'
import type {Sensor} from '@starbeacon/shared/types.ts'
import {formatTime} from '@starbeacon/shared/types.ts'
import {readyConnector} from '@starbeacon/shared/response.ts'
import {readSensorDirectory} from '@starbeacon/shared/sensors.ts'
import StatePanel from '@starbeacon/shared/components/StatePanel.vue'
import {session} from '../../session'
import {validEvaluation,type EvaluationRecord} from './decisionEvaluations'
import {eligibleDecisionResponse,eligibleResponseSensor,validDecisionResponse,type DecisionResponseRecord,type DecisionResponseRequest} from './decisionResponses'
const props=defineProps<{record:EvaluationRecord}>()
const emit=defineEmits<{close:[]}>(),router=useRouter()
const sensors=shallowRef<Sensor[]>([]),existing=shallowRef<DecisionResponseRecord|null>(null),pending=ref(false),saving=ref(false),error=ref(''),unconfirmed=ref(false),now=ref(Date.now())
const form=reactive({sensor_id:'',connector_id:'',ttl_seconds:300,reason:'',confirmed:false})
const sensor=computed(()=>sensors.value.find(v=>v.id===form.sensor_id))
const connectors=computed(()=>(sensor.value?.health.response_connectors??[]).filter(v=>readyConnector(v,now.value)))
const connector=computed(()=>connectors.value.find(v=>v.connector_id===form.connector_id))
const locked=computed(()=>saving.value||unconfirmed.value)
const eligible=computed(()=>session.current.value?.role==='admin'&&eligibleDecisionResponse(props.record,now.value)&&!!sensor.value&&eligibleResponseSensor(sensor.value,now.value)&&!!connector.value)
let controller:AbortController|undefined,stopped=false,attempt:{key:string;body:DecisionResponseRequest;tenant:string;owner:string}|undefined
async function load(){
 if(locked.value||stopped)return
 controller?.abort();const read=new AbortController();controller=read;pending.value=true;error.value='';existing.value=null;sensors.value=[];form.sensor_id='';form.connector_id='';form.confirmed=false
 const u=session.current.value
 try{
  if(!u||u.role!=='admin'||!await validEvaluation(props.record,u.tenant_id,u.id))throw new Error('评估记录与当前账号不一致，无法确认处置。')
  const result=await session.api.request<unknown>('/decision-evaluations/'+encodeURIComponent(props.record.id)+'/response',{signal:read.signal});if(read.signal.aborted)return
  if(!result||typeof result!=='object'||Object.keys(result).length!==1||!('item' in result))throw new Error('处置记录读取不完整，请重试。')
  if(result.item!==null){if(!await validDecisionResponse(result.item,props.record,u.tenant_id,u.id))throw new Error('处置档案与原评估或内容摘要不一致。');if(!read.signal.aborted)existing.value=result.item as DecisionResponseRecord;return}
  if(!eligibleDecisionResponse(props.record,Date.now()))throw new Error('该评估没有有效的源 IP 封禁候选，请重新核对研判和策略。')
  const rows=await readSensorDirectory(session.api,read.signal);if(read.signal.aborted)return
  sensors.value=rows.filter(v=>eligibleResponseSensor(v));if(!sensors.value.length)throw new Error('没有具备就绪联动设备的在线探针，请核对采集器配置与设备身份。')
  if(sensors.value.length===1)form.sensor_id=sensors.value[0]!.id
 }catch(cause){if(!read.signal.aborted)error.value=cause instanceof Error?cause.message:'处置材料读取失败，请重试。'}finally{if(controller===read)pending.value=false}
}
async function submit(){
 if(stopped||saving.value||session.current.value?.role!=='admin')return
 if(!attempt){
  if(!eligible.value||!sensor.value||!connector.value||!form.confirmed||!Number.isSafeInteger(form.ttl_seconds)||form.ttl_seconds<30||form.ttl_seconds>connector.value.max_ttl_seconds||!form.reason.trim()||form.reason!==form.reason.trim()||[...form.reason].length>500||/\p{Cc}/u.test(form.reason)){error.value='请选择就绪探针和设备，填写期限与依据，并明确确认提交。';return}
  const u=session.current.value
  attempt={key:crypto.randomUUID(),tenant:u.tenant_id,owner:u.id,body:{evaluation_sha256:props.record.sha256,sensor_id:sensor.value.id,registration_id:sensor.value.registration_id,connector_id:connector.value.connector_id,config_sha256:connector.value.config_sha256,ttl_seconds:form.ttl_seconds,reason:form.reason,confirmed:true}}
 }
 const frozen=attempt,request=new AbortController();controller?.abort();controller=request;saving.value=true;error.value=''
 try{
  const result=await session.api.request<unknown>('/decision-evaluations/'+encodeURIComponent(props.record.id)+'/response',{method:'POST',headers:{'Idempotency-Key':frozen.key},body:frozen.body,signal:request.signal});if(request.signal.aborted)return
  if(!await validDecisionResponse(result,props.record,frozen.tenant,frozen.owner,frozen.body))throw new Error('平台授权回执与原评估或输入不一致，请核对原提交。')
  if(request.signal.aborted)return
  existing.value=result as DecisionResponseRecord;attempt=undefined;unconfirmed.value=false;message.success('处置任务已受理，请核对设备配置回执与实际流量效果')
 }catch(cause){if(!request.signal.aborted){error.value=cause instanceof Error?cause.message:'处置提交结果未确认，请核对原提交。';const status=typeof cause==='object'&&cause!==null&&'status' in cause?Number(cause.status):0
  if(status>=400&&status<500&&status!==408){attempt=undefined;unconfirmed.value=false}else unconfirmed.value=true
 }}finally{if(controller===request)saving.value=false}
}
watch(()=>form.sensor_id,()=>{form.connector_id=connectors.value[0]?.connector_id??'';form.confirmed=false})
watch(()=>form.connector_id,()=>{if(connector.value&&!locked.value){form.ttl_seconds=Math.min(form.ttl_seconds,connector.value.max_ttl_seconds);form.confirmed=false}})
watch(()=>[props.record.id,props.record.sha256,session.current.value?.tenant_id,session.current.value?.id,session.current.value?.role],()=>{controller?.abort();attempt=undefined;unconfirmed.value=false;saving.value=false;load()},{immediate:true})
const timer=setInterval(()=>{now.value=Date.now()},5000)
onScopeDispose(()=>{stopped=true;clearInterval(timer);controller?.abort()})
</script>
<template>
 <a-modal :open="true" title="处置确认" :width="720" :footer="null" :closable="!locked" :mask-closable="!locked" :keyboard="!locked" @cancel="emit('close')">
  <a-alert type="warning" show-icon message="影子评估没有执行授权。此操作由管理员独立确认并创建限时任务，模型自报分数不代表经校准的攻击概率。" class="section-gap"/>
  <dl class="decision-response-context"><dt>原评估</dt><dd class="technical">{{record.id}}</dd><dt>策略 / 修订</dt><dd>{{record.policy.name}} / {{record.policy.revision}}</dd><dt>源 IP / 自报分数</dt><dd>{{record.result.target_ip||'无'}} / {{record.result.confidence?.toFixed(3)??'未参与评估'}}</dd></dl>
  <StatePanel :loading="pending" :error="!sensors.length&&!existing?error:undefined" @retry="load">
   <template v-if="existing">
    <a-alert type="info" show-icon message="本评估已确认处置，不会创建第二个任务。原授权和原期限保持不变；任务受理不等于设备已阻断实际流量。" class="section-gap"/>
    <dl class="decision-response-context"><dt>签名任务</dt><dd class="technical">{{existing.task_id}}</dd><dt>探针 / 注册代次</dt><dd>{{existing.request.sensor_id}} / {{existing.request.registration_id}}</dd><dt>联动连接器</dt><dd>{{existing.request.connector_id}}</dd><dt>封禁期限</dt><dd>{{existing.request.ttl_seconds}} 秒，从任务签发时起计</dd><dt>确认 / 保留截止</dt><dd>{{formatTime(existing.created_at)}} / {{formatTime(existing.expires_at)}}</dd><dt>操作依据</dt><dd>{{existing.request.reason}}</dd><dt>授权 SHA-256</dt><dd class="technical">{{existing.sha256}}</dd></dl>
    <div class="filter-actions"><a-button type="primary" @click="router.push({path:'/sensors',query:{view:'tasks',task:existing.task_id}})">查看任务记录</a-button><a-button @click="emit('close')">返回</a-button></div>
   </template>
   <a-form v-else-if="sensors.length" :model="form" layout="vertical" @finish="submit">
    <a-alert v-if="error" type="error" show-icon :message="error" class="section-gap"/>
    <a-alert v-if="unconfirmed" type="warning" show-icon message="提交结果未确认，输入与请求键已保留。核对原提交不会更换探针、延长期限或创建第二个任务。" class="section-gap"/>
    <a-alert v-else-if="!eligible" type="info" show-icon message="请选择探针；已选观测过期时，请刷新后重新确认设备。" class="section-gap"/>
    <a-form-item label="执行探针" required><a-select v-model:value="form.sensor_id" aria-label="处置执行探针" show-search :option-filter-prop="'label'" :disabled="locked" :options="sensors.map(v=>({value:v.id,label:v.name+' · '+v.id}))" placeholder="选择可访问联动设备的在线探针"/></a-form-item>
    <div class="decision-response-grid"><a-form-item label="联动设备" required><a-select v-model:value="form.connector_id" aria-label="处置联动设备" :disabled="locked||!sensor" :options="connectors.map(v=>({value:v.connector_id,label:v.device_id+' · '+v.version}))"/></a-form-item><a-form-item label="封禁期限（秒）" required><a-input-number v-model:value="form.ttl_seconds" aria-label="处置封禁期限" :min="30" :max="connector?.max_ttl_seconds??30" :precision="0" :disabled="locked"/></a-form-item></div>
    <a-form-item label="操作依据" required><a-textarea v-model:value="form.reason" aria-label="处置操作依据" :auto-size="{minRows:2,maxRows:4}" :maxlength="500" :disabled="locked"/></a-form-item>
    <a-checkbox v-model:checked="form.confirmed" :disabled="locked">确认提交原评估源 IP 的限时封禁配置</a-checkbox>
    <p class="page-description section-gap">提交时重新核对当前策略、本人研判、告警来源、探针注册与设备配置。源 IP 不可更改，保护地址仍由采集器核验。</p>
    <div class="filter-actions"><a-button type="primary" html-type="submit" :loading="saving">{{unconfirmed?'核对原提交':'确认并提交'}}</a-button><a-button :disabled="locked" @click="load">刷新探针</a-button><a-button :disabled="locked" @click="emit('close')">返回</a-button></div>
   </a-form>
  </StatePanel>
 </a-modal>
</template>
<style scoped>.decision-response-context{display:grid;grid-template-columns:140px minmax(0,1fr);gap:8px;margin:12px 0}.decision-response-context dt{color:var(--text-secondary)}.decision-response-context dd{margin:0;overflow-wrap:anywhere}.decision-response-grid{display:grid;grid-template-columns:1fr 170px;gap:var(--related-gap)}.decision-response-grid .ant-input-number{width:100%}@media(max-width:600px){.decision-response-grid{grid-template-columns:1fr}}</style>
