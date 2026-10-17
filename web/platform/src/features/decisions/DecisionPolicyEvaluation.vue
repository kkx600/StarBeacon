<script setup lang="ts">
import {onScopeDispose,ref,shallowRef,watch} from 'vue'
import {Modal as AModal} from 'ant-design-vue'
import {formatTime} from '@starbeacon/shared/types.ts'
import {session} from '../../session'
import {ApiError} from '@starbeacon/shared/api.ts'
import {validEvaluation,type EvaluationRecord} from './decisionEvaluations'
import {validTriageJob,type TriageJob} from '../alerts/triage'
import {policyID,policyActions,policyStatuses,policyReasons,validShadowResult,type PolicyRecord,type PolicyResult} from './decisionPolicies'
const props=defineProps<{record:PolicyRecord;triageId?:string}>(),emit=defineEmits<{close:[]}>()
const triageID=ref(props.triageId??''),pending=ref(false),unconfirmed=ref(false),error=ref(''),result=shallowRef<PolicyResult|null>(null),job=shallowRef<TriageJob|null>(null),archive=shallowRef<EvaluationRecord|null>(null)
let stopped=false,read:AbortController|undefined
let attempt:{input:{policy_id:string;expected_revision:number;triage_id:string};key:string;policy:PolicyRecord;job:TriageJob}|undefined
async function evaluate(){
 if(pending.value)return
 result.value=null;job.value=null;archive.value=null;error.value=''
 const id=triageID.value.trim()
 if(!policyID(id)){error.value='请输入本账号可访问的模型研判作业标识。';return}
 const controller=new AbortController();read=controller;pending.value=true;const timer=setTimeout(()=>controller.abort(),30000)
 try{
  if(!attempt){
   const source=await session.api.request<unknown>('/alert-triage/jobs/'+encodeURIComponent(id),{signal:controller.signal})
   if(stopped||controller.signal.aborted)return
   if(!validTriageJob(source)||source.id!==id)throw new Error('研判材料回执与所选作业不一致。')
   attempt={input:{policy_id:props.record.id,expected_revision:props.record.revision,triage_id:id},key:crypto.randomUUID(),policy:JSON.parse(JSON.stringify(props.record)) as PolicyRecord,job:source}
  }
  const frozen=attempt,tenant=session.current.value?.tenant_id??'',owner=session.current.value?.id??''
  const value=await session.api.request<unknown>('/decision-evaluations',{method:'POST',body:frozen.input,headers:{'Idempotency-Key':frozen.key},signal:controller.signal})
  if(stopped)return
  if(controller.signal.aborted||!await validEvaluation(value,tenant,owner)||!await validShadowResult((value as EvaluationRecord).result,frozen.policy,frozen.job))throw new Error('影子评估回执与策略、材料或档案摘要不一致，请核对原提交。')
  if(!stopped&&!controller.signal.aborted){job.value=frozen.job;archive.value=value as EvaluationRecord;result.value=archive.value.result;attempt=undefined;unconfirmed.value=false}
 }catch(e){if(!stopped&&read===controller){error.value=controller.signal.aborted?'评估结果尚未确认，请核对原提交。':e instanceof Error?e.message:'影子评估失败。';if(e instanceof ApiError&&e.status>=400&&e.status<500&&e.status!==408){attempt=undefined;unconfirmed.value=false}else unconfirmed.value=!!attempt}}finally{clearTimeout(timer);if(read===controller)pending.value=false}
}
function changed(){if(attempt)return;result.value=null;job.value=null;archive.value=null;error.value=''}
watch(()=>[session.current.value?.tenant_id,session.current.value?.id,session.current.value?.role].join('/'),()=>{read?.abort();read=undefined;attempt=undefined;unconfirmed.value=false;pending.value=false;changed();triageID.value=''})
onScopeDispose(()=>{stopped=true;read?.abort();attempt=undefined})
</script>
<template>
 <a-modal :open="true" title="影子评估" :width="820" :footer="null" :body-style="{maxHeight:'calc(100vh - 220px)',overflowY:'auto'}" @cancel="emit('close')">
  <a-alert type="info" show-icon message="复用本账号已有的模型研判材料，不再次调用模型；评估不会创建封禁或通知任务。" class="section-gap"/>
  <p><strong>{{record.name}}</strong> · 修订 {{record.revision}} · {{record.active?'启用':'停用'}}</p>
  <form class="policy-evaluation-input" @submit.prevent="evaluate"><label for="policy-triage-id">模型研判作业标识</label><a-input id="policy-triage-id" v-model:value="triageID" :maxlength="64" :disabled="pending||unconfirmed" placeholder="从告警详情的模型研判结果中获取" @input="changed"/><a-button type="primary" html-type="submit" :loading="pending" :disabled="pending">{{unconfirmed?'核对原提交':'执行影子评估'}}</a-button></form>
  <a-alert v-if="unconfirmed" type="warning" show-icon message="原评估提交结果尚未确认。核对会复用同一请求键和冻结材料；也可在评估记录中检查是否已保存。" class="section-gap"/>
  <a-alert v-if="error" type="error" show-icon :message="error" class="section-gap"/>
  <div v-if="result&&job" aria-label="影子评估结果">
   <a-alert :type="result.status==='matched'?'success':'info'" show-icon :message="policyStatuses[result.status]+' · 未授权执行'" class="section-gap"/>
   <dl class="policy-evaluation-detail">
    <template v-if="archive"><dt>评估档案</dt><dd class="technical">{{archive.id}}</dd><dt>保留截止</dt><dd>{{formatTime(archive.expires_at)}} · <a href="/models?view=evaluations">查看评估记录</a></dd></template>
    <dt>判断依据</dt><dd>{{result.reasons.map(r=>policyReasons[r]).join('；')}}</dd><dt>候选处置</dt><dd>{{policyActions[result.candidate_action]}}</dd>
    <dt>模型自报分数</dt><dd>{{result.confidence===null?'未参与评估':result.confidence.toFixed(3)}} · 未校准</dd><dt>候选源 IP</dt><dd>{{result.target_ip||'无'}}</dd>
    <dt>材料观测时间</dt><dd>{{formatTime(job.evidence.observed_at)}}</dd><dt>评估时间</dt><dd>{{formatTime(result.evaluated_at)}}</dd>
    <dt>模型 / 修订</dt><dd>{{result.provider_id}} / {{result.provider_revision}}</dd><dt>计算成本</dt><dd>{{result.cost===null?'未执行表达式':result.cost+' / 1000'}}</dd>
    <dt>告警标识</dt><dd class="technical">{{result.event_id}}</dd><dt>原始事件 SHA-256</dt><dd class="technical">{{result.raw_sha256}}</dd><dt>材料 SHA-256</dt><dd class="technical">{{result.evidence_sha256}}</dd><dt>策略 SHA-256</dt><dd class="technical">{{result.definition_sha256}}</dd>
   </dl>
   <h3>证据与执行限制</h3><ul><li v-for="item in result.limitations" :key="item">{{item}}</li></ul>
  </div>
 </a-modal>
</template>
<style scoped>.policy-evaluation-input{display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin-bottom:12px}.policy-evaluation-input .ant-input{flex:1;min-width:200px}.policy-evaluation-detail{display:grid;grid-template-columns:150px minmax(0,1fr);gap:8px}.policy-evaluation-detail dt{color:var(--muted)}.policy-evaluation-detail dd{margin:0;overflow-wrap:anywhere}</style>
