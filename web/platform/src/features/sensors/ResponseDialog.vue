<script setup lang="ts">
import {computed,onScopeDispose,reactive,shallowRef,watch} from 'vue'
import {Modal as AModal,Select as ASelect,InputNumber as AInputNumber,Checkbox as ACheckbox,message} from 'ant-design-vue'
import type {Sensor} from '@starbeacon/shared/types.ts'
import type {ResponseConnector} from '@starbeacon/shared/response.ts'
import {readyConnector} from '@starbeacon/shared/response.ts'
import {readSensorDirectory} from '@starbeacon/shared/sensors.ts'
import StatePanel from '@starbeacon/shared/components/StatePanel.vue'
import {session} from '../../session'
const props=defineProps<{sensor:Sensor|null}>()
const emit=defineEmits<{close:[];submitted:[]}>()
const connectors=shallowRef<ResponseConnector[]>([]),pending=shallowRef(false),saving=shallowRef(false),error=shallowRef(''),unconfirmed=shallowRef(false)
const form=reactive({connector_id:'',target_ip:'',ttl_seconds:300,reason:'',confirmed:false})
const current=computed(()=>connectors.value.find(v=>v.connector_id===form.connector_id))
const locked=computed(()=>saving.value||unconfirmed.value)
let controller:AbortController|undefined,stopped=false,attempt:{key:string;body:Record<string,unknown>;sensor:string}|undefined
async function load(){controller?.abort();attempt=undefined;unconfirmed.value=false;saving.value=false;error.value='';connectors.value=[];form.connector_id='';form.target_ip='';form.reason='';form.confirmed=false
 if(!props.sensor||session.current.value?.role!=='admin'){pending.value=false;return}
 const original=props.sensor,currentRequest=new AbortController();controller=currentRequest;pending.value=true
 try{const rows=await readSensorDirectory(session.api,currentRequest.signal);if(currentRequest.signal.aborted)return;const row=rows.find(v=>v.id===original.id)
  const seen=Date.parse(row?.last_seen??'')
  if(!row?.active||row.status!=='online'||row.registration_id!==original.registration_id||!Number.isFinite(seen)||Date.now()-seen>35000||seen-Date.now()>30000||!row.health.task_capabilities?.includes('response.block'))throw new Error('探针未就绪或注册身份已变化，请刷新后核对。')
  connectors.value=(row.health.response_connectors??[]).filter(v=>readyConnector(v));if(!connectors.value.length)throw new Error('没有就绪的联动设备。请在采集器配置受信任的 HTTP 连接器，并核对设备身份。')
  form.connector_id=connectors.value[0]!.connector_id;form.ttl_seconds=Math.min(300,connectors.value[0]!.max_ttl_seconds)
 }catch(cause){if(!currentRequest.signal.aborted)error.value=cause instanceof Error?cause.message:'联动设备读取失败'}finally{if(controller===currentRequest)pending.value=false}
}
async function submit(){if(stopped||saving.value||session.current.value?.role!=='admin'||!props.sensor)return
 if(!attempt){
  if(!current.value||!readyConnector(current.value)||!form.confirmed||!form.target_ip||form.target_ip.trim()!==form.target_ip||!Number.isSafeInteger(form.ttl_seconds)||form.ttl_seconds<30||form.ttl_seconds>current.value.max_ttl_seconds||!form.reason.trim()||form.reason.trim()!==form.reason||[...form.reason].length>500||/[\u0000-\u001f\u007f]/.test(form.reason)){error.value='请选择就绪设备，填写单个规范 IP、允许的期限及操作依据，并确认提交。';return}
  attempt={key:crypto.randomUUID(),sensor:props.sensor.id,body:{kind:'response.block',connector_id:current.value.connector_id,config_sha256:current.value.config_sha256,target_ip:form.target_ip,ttl_seconds:form.ttl_seconds,reason:form.reason}}
 }
 const frozen=attempt,request=new AbortController();controller?.abort();controller=request;saving.value=true;error.value=''
 try{const result=await session.api.request<{id:string}>(`/sensors/${encodeURIComponent(frozen.sensor)}/response-tasks`,{method:'POST',headers:{'Idempotency-Key':frozen.key},body:frozen.body,signal:request.signal});if(request.signal.aborted)return
  if(!result||typeof result.id!=='string'||!/^task_[a-f0-9]{32}$/.test(result.id))throw new Error('平台提交回执不完整，请核对原提交。')
  attempt=undefined;unconfirmed.value=false;message.success('联动任务已受理，请在任务记录中核对设备配置状态');emit('submitted')
 }catch(cause){if(!request.signal.aborted){error.value=cause instanceof Error?cause.message:'联动任务提交失败';const status=typeof cause==='object'&&cause!==null&&'status' in cause?Number(cause.status):0
  if(status>=400&&status<500&&status!==408){attempt=undefined;unconfirmed.value=false}else unconfirmed.value=true
 }}finally{if(controller===request)saving.value=false}
}
watch(()=>[props.sensor?.id,props.sensor?.registration_id,session.current.value?.tenant_id,session.current.value?.id,session.current.value?.role],load,{immediate:true})
watch(()=>form.connector_id,()=>{if(current.value&&!locked.value)form.ttl_seconds=Math.min(form.ttl_seconds,current.value.max_ttl_seconds)})
onScopeDispose(()=>{stopped=true;controller?.abort()})
</script>
<template>
 <a-modal title="限时封禁" :open="sensor!==null" :width="660" :footer="null" :closable="!locked" :mask-closable="!locked" :keyboard="!locked" @cancel="emit('close')">
  <a-alert type="warning" show-icon message="本操作由指定采集器访问联动设备，提交限时封禁配置。配置回读与实际流量阻断效果分别核验。" class="section-gap"/>
  <StatePanel :loading="pending" :error="connectors.length?undefined:error" @retry="load">
   <a-alert v-if="error&&connectors.length" type="error" show-icon :message="error" class="section-gap"/>
   <a-alert v-if="unconfirmed" type="warning" show-icon message="提交结果未确认，输入与请求键已保留。核对原提交不会重新计时或创建第二个任务。" class="section-gap"/>
   <a-form v-if="connectors.length" :model="form" layout="vertical" @finish="submit">
    <a-form-item label="联动设备" required><a-select v-model:value="form.connector_id" aria-label="联动设备" :disabled="locked" :options="connectors.map(v=>({value:v.connector_id,label:v.device_id+' · '+v.version}))"/></a-form-item>
    <div class="response-form-grid"><a-form-item label="目标 IP" required><a-input v-model:value="form.target_ip" aria-label="封禁目标 IP" :maxlength="45" :disabled="locked" placeholder="单个 IPv4 或 IPv6 地址"/></a-form-item><a-form-item label="封禁期限（秒）" required><a-input-number v-model:value="form.ttl_seconds" aria-label="封禁期限" :min="30" :max="current?.max_ttl_seconds??30" :precision="0" :disabled="locked"/></a-form-item></div>
    <a-form-item label="操作依据" required><a-textarea v-model:value="form.reason" aria-label="联动操作依据" :maxlength="500" :auto-size="{minRows:2,maxRows:4}" :disabled="locked"/></a-form-item>
    <a-checkbox v-model:checked="form.confirmed" :disabled="locked">确认提交此 IP 的限时封禁配置</a-checkbox>
    <p class="page-description section-gap">设备保护范围由采集器再次校验。任务投递期限与设备封禁到期时间分别记录；旁路探针自身不阻断流量。</p>
    <div class="filter-actions"><a-button type="primary" html-type="submit" :loading="saving">{{unconfirmed?'核对原提交':'提交任务'}}</a-button><a-button :disabled="locked" @click="emit('close')">返回</a-button></div>
   </a-form>
  </StatePanel>
 </a-modal>
</template>
<style scoped>.response-form-grid{display:grid;grid-template-columns:1fr 170px;gap:var(--related-gap)}.response-form-grid .ant-input-number{width:100%}@media(max-width:600px){.response-form-grid{grid-template-columns:1fr}}</style>
