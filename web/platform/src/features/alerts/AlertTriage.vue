<script setup lang="ts">
import {useFeedback} from '@starbeacon/shared/composables/useFeedback.ts'
import {computed,onMounted,onScopeDispose,reactive,ref,shallowRef,watch} from 'vue'
import {Descriptions as ADescriptions,Select as ASelect,Checkbox as ACheckbox} from 'ant-design-vue'
import {formatTime} from '@starbeacon/shared/types.ts'
import StatePanel from '@starbeacon/shared/components/StatePanel.vue'
import {session} from '../../session'
import {router} from '../../router'
import {checkClass,resultNames} from '../models/models'
import {triageCodes,triageStates,triageVerdicts,triageOutcomes,triageRecommendations,triageWorking,validTriageProviders,type TriageProvider} from './triage'
import {useAlertTriage} from './useAlertTriage'
const message=useFeedback()
const ADescriptionsItem=ADescriptions.Item
const props=defineProps<{eventId:string;digest:string}>(),emit=defineEmits<{locked:[value:boolean]}>()
const state=useAlertTriage(props.eventId,props.digest)
const {items,next,pending,error,available,selected,loading,detailError,busy,actionError,unconfirmed}=state
const providers=shallowRef<TriageProvider[]>([]),providerPending=ref(false),providerError=ref(''),providerAvailable=ref(false),recordID=ref<string>(),formError=ref('')
const form=reactive({provider_id:'',note:'',allow_context:false})
let stopped=false,providerRead:AbortController|undefined,providerEpoch=0
const locked=computed(()=>busy.value||unconfirmed.value)
const provider=computed(()=>providers.value.find(row=>row.id===form.provider_id))
const canSubmit=computed(()=>!locked.value&&!pending.value&&!error.value&&available.value&&!providerPending.value&&!providerError.value&&providerAvailable.value&&provider.value?.enabled&&provider.value.has_key&&form.allow_context)
watch(locked,value=>emit('locked',value),{immediate:true})
watch(selected,job=>{if(job)recordID.value=job.id})
async function loadProviders(){
 const epoch=++providerEpoch;providerRead?.abort();const controller=new AbortController();providerRead=controller;providerPending.value=true;providerError.value=''
 try{const page=await session.api.request<unknown>('/models/providers',{signal:controller.signal});if(stopped||controller.signal.aborted||epoch!==providerEpoch)return;if(!validTriageProviders(page))throw new Error('模型配置未能完整返回');providers.value=page.items;providerAvailable.value=page.available;if(!providers.value.some(row=>row.id===form.provider_id))form.provider_id=''}
 catch(e){if(!controller.signal.aborted)providerError.value=e instanceof Error?e.message:'模型配置读取失败'}finally{if(!stopped&&epoch===providerEpoch)providerPending.value=false}
}
async function submit(){
 formError.value=''
 if(!canSubmit.value||!provider.value){formError.value='请选择可用模型并确认本次数据使用许可';return}
 if([...form.note].length>2000){formError.value='研判说明最多 2000 字符';return}
 if(await state.submit({event_id:props.eventId,raw_sha256:props.digest,provider_id:provider.value.id,provider_revision:provider.value.revision,note:form.note,allow_context:form.allow_context}))message.success('模型研判作业已提交')
}
function openPolicies(){const job=selected.value;if(job?.state==='succeeded'&&session.current.value?.role==='admin')void router.push({path:'/models',query:{view:'policies',triage_id:job.id}})}
async function confirm(){if(await state.confirm())message.success('研判提交结果已确认')}
async function selectRecord(value:unknown){if(typeof value==='string'){recordID.value=value;await state.load(value)}}
onMounted(()=>void loadProviders())
onScopeDispose(()=>{stopped=true;providerEpoch++;providerRead?.abort()})
</script>
<template>
 <div class="triage-content">
  <a-alert type="info" show-icon message="模型提供待复核建议。自评分未经校准，不能证明攻击成功，也不能单独授权封禁。" class="section-gap"/>
  <div class="triage-history section-gap">
   <a-select :value="recordID" aria-label="模型研判记录" placeholder="选择本账号的研判记录" :disabled="locked" :loading="pending" :options="items.map(row=>({value:row.id,label:`${formatTime(row.created_at)} · ${triageStates[row.state]}`}))" @update:value="selectRecord"/>
   <a-button :disabled="locked" :loading="pending" @click="state.refresh()">刷新记录</a-button>
   <a-button v-if="next" :disabled="locked" :loading="pending" @click="state.refresh(next)">加载更早记录</a-button>
  </div>
  <a-alert v-if="error" type="error" :message="error+(items.length?'。当前保留上次读取的记录。':'')" show-icon class="section-gap"/>
  <p v-if="!pending&&!error&&!items.length" class="muted">暂无模型研判记录，提交后可查看材料、判断依据和执行状态。</p>
  <a-alert v-if="!pending&&!error&&!available" type="warning" message="模型执行或材料检索服务暂不可用，可以查看已有记录，暂不能提交研判。" show-icon class="section-gap"/>
  <a-form :model="form" layout="vertical" @finish="submit">
   <div class="triage-model-row">
    <a-form-item label="研判模型" required>
     <a-select v-model:value="form.provider_id" aria-label="研判模型" :disabled="locked||providerPending||!!providerError" :loading="providerPending" placeholder="选择已配置凭据的模型" :options="providers.map(row=>({value:row.id,label:`${row.name} · 修订 ${row.revision}`,disabled:!row.enabled||!row.has_key}))"/>
    </a-form-item>
    <a-button :disabled="locked" :loading="providerPending" @click="loadProviders">刷新模型</a-button>
   </div>
   <a-alert v-if="providerError" type="error" :message="providerError" show-icon class="section-gap"/>
   <p v-else-if="!providerPending&&!providers.length" class="muted">尚无可用模型，请先在模型配置中登记模型与凭据。</p>
   <a-form-item label="研判说明" extra="可说明业务背景或调查问题，最多 2000 字符。说明会发送给选定模型，请勿填写密码或访问令牌。">
    <a-textarea v-model:value="form.note" aria-label="模型研判说明" :disabled="locked" :rows="2" :maxlength="2000" show-count placeholder="例如：核对请求是否符合规则条件，并指出还需要哪些证据。"/>
   </a-form-item>
   <a-checkbox v-model:checked="form.allow_context" :disabled="locked">允许本次向选定模型发送告警索引字段与研判说明，不含原始载荷</a-checkbox>
   <a-alert v-if="formError||actionError" type="error" :message="formError||actionError" show-icon class="section-gap"/>
   <a-alert v-if="unconfirmed" type="warning" message="提交结果尚未确认，原输入与请求标识已保留。请先确认原请求，避免重复调用和计费。" show-icon class="section-gap"/>
   <div class="filter-actions section-gap"><a-button v-if="unconfirmed" type="primary" :loading="busy" @click="confirm">确认提交结果</a-button><a-button v-else type="primary" html-type="submit" :disabled="!canSubmit" :loading="busy">提交模型研判</a-button></div>
  </a-form>
  <template v-if="recordID">
   <div class="filter-actions section-gap"><h2>研判结果</h2><a-button :disabled="locked" :loading="loading" @click="state.load(recordID)">刷新结果</a-button><a-button v-if="selected&&triageWorking(selected.state)" :disabled="locked||selected.cancel_requested" :loading="busy" @click="state.cancel(selected.id)">取消研判</a-button></div>
   <a-alert v-if="detailError&&selected" type="error" :message="`${detailError}。当前显示下方作业的上次读取结果。`" show-icon class="section-gap"/>
   <StatePanel :loading="loading&&!selected" :error="selected?'':detailError" :empty="!selected" description="选择记录后可查看本次研判结果。" @retry="state.load(recordID)">
    <template v-if="selected">
     <a-descriptions bordered size="small" :column="{xs:1,sm:2}">
      <a-descriptions-item label="作业状态"><span class="status" :class="checkClass(selected.state)">{{triageStates[selected.state]}}</span></a-descriptions-item>
      <a-descriptions-item label="模型修订">{{providers.find(row=>row.id===selected!.request.provider_id)?.name||selected.request.provider_id}} · {{selected.request.provider_revision}}</a-descriptions-item>
      <a-descriptions-item label="作业标识" :span="2"><span class="technical">{{selected.id}}</span></a-descriptions-item>
      <a-descriptions-item label="执行说明" :span="2">{{triageCodes[selected.result.code]||resultNames[selected.result.code]||'执行结果需核对（'+selected.result.code+'）'}}</a-descriptions-item>
      <a-descriptions-item label="创建 / 完成时间" :span="2">{{formatTime(selected.created_at)}} / {{formatTime(selected.finished_at)}}</a-descriptions-item>
      <a-descriptions-item label="模型调用耗时">{{selected.result.duration_ms===null?'未获得实际调用耗时':selected.result.duration_ms+' ms'}}</a-descriptions-item>
      <a-descriptions-item label="调用用量">{{selected.result.usage?`输入 ${selected.result.usage.input_tokens} / 输出 ${selected.result.usage.output_tokens} Token`:'提供方未返回用量'}}</a-descriptions-item>
     </a-descriptions>
     <a-alert v-if="selected.state==='uncertain'" type="warning" message="提供方是否完成调用无法确认，费用可能已产生。平台不会自动重试本次调用；请先核对提供方记录。" show-icon class="section-gap"/>
     <a-alert v-if="selected.cancel_requested&&triageWorking(selected.state)" type="warning" message="取消请求已登记。已发送的模型请求是否完成，需要等待作业记录或提供方记录确认。" show-icon class="section-gap"/>
     <div v-if="selected.answer" class="triage-answer section-gap">
      <a-button v-if="session.current.value?.role==='admin'" :disabled="locked||loading||!!detailError" @click="openPolicies">评估决策策略</a-button>
      <div class="triage-answer-heading"><strong>{{triageVerdicts[selected.answer.verdict]}}</strong><span>{{triageOutcomes[selected.answer.outcome]}}</span><span class="status status-unknown">模型自评分 {{(selected.answer.confidence*100).toFixed(1)}}%</span></div>
      <p class="triage-text">{{selected.answer.reason}}</p>
      <p><strong>处置建议：</strong>{{triageRecommendations[selected.answer.recommendation]}}，须人工复核及独立授权。</p>
      <h3>事实引用</h3><p v-if="!selected.answer.references.length" class="muted">未引用具体事实，当前结论为证据不足。</p>
      <dl class="triage-facts"><template v-for="fact in selected.evidence.facts.filter(row=>selected!.answer!.references.includes(row.id))" :key="fact.id"><dt>{{fact.label}}</dt><dd>{{fact.value}}</dd></template></dl>
      <h3>反证与约束</h3><ul v-if="selected.answer.counter_evidence.length"><li v-for="item in selected.answer.counter_evidence" :key="item">{{item}}</li></ul><p v-else class="muted">模型未提供反证讨论，请结合材料限制复核。</p>
      <h3>待补充信息</h3><ul v-if="selected.answer.missing.length"><li v-for="item in selected.answer.missing" :key="item">{{item}}</li></ul><p v-else class="muted">模型未列出补充信息，仍需核对完整会话与独立业务证据。</p>
     </div>
     <details class="triage-material section-gap"><summary>查看冻结材料与证据限制</summary><p v-if="selected.evidence.limited" class="muted">部分字段因格式或长度限制未完整提供给模型。</p><dl class="triage-facts"><template v-for="fact in selected.evidence.facts" :key="fact.id"><dt>{{fact.label}}</dt><dd>{{fact.value}}</dd></template></dl><ul><li v-for="item in selected.evidence.limitations" :key="item">{{item}}</li></ul><p class="technical">材料摘要：{{selected.evidence.sha256}}</p><p class="muted">模板：{{selected.template}} · 留存至 {{formatTime(selected.expires_at)}}</p></details>
    </template>
   </StatePanel>
  </template>
 </div>
</template>
<style scoped>
.triage-content{min-width:0}.triage-history,.triage-model-row,.triage-answer-heading{display:flex;align-items:center;gap:8px;flex-wrap:wrap}.triage-history .ant-select{flex:1 1 300px;min-width:0}.triage-model-row{align-items:flex-start}.triage-model-row .ant-form-item{flex:1 1 280px;min-width:0}.triage-model-row>.ant-btn{margin-top:30px}.triage-text{white-space:pre-wrap;overflow-wrap:anywhere;margin:12px 0}.triage-answer h3{font-size:14px;margin:12px 0 4px}.triage-facts{display:grid;grid-template-columns:minmax(85px,135px) minmax(0,1fr);margin:8px 0;gap:6px 12px}.triage-facts dt{color:var(--muted)}.triage-facts dd{margin:0;white-space:pre-wrap;overflow-wrap:anywhere}.triage-material summary{cursor:pointer;padding:8px 0;font-weight:600}.triage-content p,.triage-content li,.triage-content .technical{overflow-wrap:anywhere}.triage-answer-heading strong{font-size:16px}.filter-actions h2{font-size:16px;margin:0 auto 0 0}@media(max-width:680px){.triage-model-row>.ant-btn{margin-top:0}.triage-facts{grid-template-columns:85px minmax(0,1fr)}}
</style>
