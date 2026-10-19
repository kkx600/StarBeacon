<script setup lang="ts">
import {usePageTitle} from '@starbeacon/shared/utils/usePageTitle.ts'
const pageTitle=usePageTitle('评估记录')
import {onScopeDispose,reactive,ref,shallowRef,watch} from 'vue'
import {Table as ATable,Select as ASelect,Tag as ATag,Modal as AModal} from 'ant-design-vue'
import StatePanel from '@starbeacon/shared/components/StatePanel.vue'
import {formatTime} from '@starbeacon/shared/types.ts'
import {session} from '../../session'
import {policyStatuses} from './decisionPolicies'
import {validEvaluation,type EvaluationRecord} from './decisionEvaluations'
import {useDecisionEvaluations} from './useDecisionEvaluations'
import DecisionEvaluationDetail from './DecisionEvaluationDetail.vue'
import DecisionResponseDialog from './DecisionResponseDialog.vue'
const model=useDecisionEvaluations(),draft=reactive({policy_id:'',triage_id:'',status:''}),detail=shallowRef<EvaluationRecord|null>(null),detailTarget=ref(''),detailPending=ref(false),detailError=ref('')
const responseTarget=shallowRef<EvaluationRecord|null>(null)
let read:AbortController|undefined
const columns=[{title:'评估标识',key:'id',width:220},{title:'策略 / 修订',key:'policy',width:220},{title:'判断结果',key:'status',width:150},{title:'模型自报分数',key:'confidence',width:130},{title:'研判作业',key:'triage',width:230},{title:'评估时间',key:'time',width:190},{title:'操作',key:'actions',width:80}]
function close(){read?.abort();detailTarget.value='';detail.value=null;detailError.value='';detailPending.value=false;responseTarget.value=null}
function respond(record:EvaluationRecord){if(session.current.value?.role!=='admin')return;close();responseTarget.value=record}
async function inspect(id:string){
 close();detailTarget.value=id;const controller=new AbortController();read=controller;detailPending.value=true
 const tenant=session.current.value?.tenant_id??'',owner=session.current.value?.id??''
 try{const value=await session.api.request<unknown>('/decision-evaluations/'+encodeURIComponent(id),{signal:controller.signal});if(controller.signal.aborted)return;if(!await validEvaluation(value,tenant,owner)||(value as EvaluationRecord).id!==id)throw new Error('评估档案与所选记录或摘要不一致，请重试。');if(!controller.signal.aborted)detail.value=value as EvaluationRecord}
 catch(e){if(!controller.signal.aborted)detailError.value=e instanceof Error?e.message:'评估档案读取失败。'}finally{if(read===controller)detailPending.value=false}
}
function search(){close();model.search(draft)}
function refresh(){close();model.refresh()}
function page(direction:'next'|'previous'){close();model[direction]()}
watch(()=>[session.current.value?.id,session.current.value?.tenant_id,session.current.value?.role].join('/'),()=>{close();draft.policy_id='';draft.triage_id='';draft.status=''})
onScopeDispose(()=>read?.abort())
</script>
<template>
 <header class="page-header"><div><h1>{{pageTitle}}</h1><p class="page-description">查看本账号的评估档案与策略快照，核对判断依据和处置授权记录。</p></div></header>
 <a-alert type="info" show-icon message="仅显示本账号的评估记录。判断与持续决策授权独立留档，详情可核对自动任务或未授权原因；默认保留 180 天。" class="section-gap"/>
 <form class="evaluation-toolbar" @submit.prevent="search"><a-input v-model:value="draft.policy_id" aria-label="评估策略标识" placeholder="策略标识" :maxlength="64"/><a-input v-model:value="draft.triage_id" aria-label="评估研判作业标识" placeholder="研判作业标识" :maxlength="64"/><a-select v-model:value="draft.status" aria-label="评估判断结果" :options="[{value:'',label:'全部结果'},...Object.entries(policyStatuses).map(([value,label])=>({value,label}))]"/><a-button html-type="submit" :disabled="model.pending.value">检索</a-button><a-button :loading="model.pending.value" @click="refresh">刷新</a-button></form>
 <section class="panel"><div class="panel-header"><h2>评估记录</h2><span>当前页 {{model.page.value.items.length}} 条 · 持久提交倒序</span></div>
  <StatePanel :loading="model.pending.value" :error="model.error.value" :empty="!model.page.value.items.length" :description="Object.values(model.filter.value).some(Boolean)?'没有符合筛选条件的评估记录。请调整条件后重新检索。':'暂无评估记录。使用本人研判材料执行影子评估后，可在此查看判断快照。'" @retry="model.refresh">
   <a-table :data-source="model.page.value.items" :columns="columns" row-key="id" :pagination="false" size="small" :scroll="{x:1220}"><template #bodyCell="{column,record}">
    <template v-if="column.key==='id'"><span class="technical">{{record.id}}</span></template><template v-else-if="column.key==='policy'"><strong>{{record.policy.name}}</strong><div class="page-description">{{record.policy.id}} / {{record.policy.revision}}</div></template>
    <template v-else-if="column.key==='status'"><a-tag :color="record.result.status==='matched'?'green':record.result.status==='protected'?'gold':'default'">{{policyStatuses[record.result.status as keyof typeof policyStatuses]}}</a-tag><div class="page-description">{{record.policy.definition.mode==='shadow'?'未授权执行':'授权记录见详情'}}</div></template>
    <template v-else-if="column.key==='confidence'">{{record.result.confidence===null?'未参与评估':record.result.confidence.toFixed(3)}}<div class="page-description">未校准</div></template><template v-else-if="column.key==='triage'"><span class="technical">{{record.result.triage_id}}</span></template><template v-else-if="column.key==='time'">{{formatTime(record.result.evaluated_at)}}</template><template v-else-if="column.key==='actions'"><a-button type="link" size="small" @click="inspect(record.id)">查看</a-button></template>
   </template></a-table>
  </StatePanel>
  <div class="evaluation-pagination"><span class="page-description">到期记录不可访问。新记录在刷新首屏后出现；游标到期时请重新检索。</span><a-button :disabled="model.pending.value||model.cursors.value.length<2" @click="page('previous')">上一页</a-button><a-button :disabled="model.pending.value||!!model.error.value||!model.page.value.next_cursor" @click="page('next')">下一页</a-button></div>
 </section>
 <DecisionEvaluationDetail v-if="detail" :record="detail" :can-respond="session.current.value?.role==='admin'" @close="close" @respond="respond"/>
 <DecisionResponseDialog v-else-if="responseTarget" :record="responseTarget" @close="close"/>
 <a-modal v-else-if="detailTarget" :open="true" title="评估记录详情" :width="820" :footer="null" :body-style="{maxHeight:'calc(100vh - 220px)',overflowY:'auto'}" @cancel="close"><StatePanel :loading="detailPending" :error="detailError" @retry="inspect(detailTarget)"/></a-modal>
</template>
<style scoped>.evaluation-toolbar,.evaluation-pagination{display:flex;align-items:center;flex-wrap:wrap;gap:8px}.evaluation-toolbar{margin-bottom:12px}.evaluation-toolbar>.ant-input{width:220px}.evaluation-toolbar>.ant-select{width:160px}.evaluation-pagination{justify-content:flex-end;padding:12px}.evaluation-pagination>span{flex:1;min-width:200px}</style>
