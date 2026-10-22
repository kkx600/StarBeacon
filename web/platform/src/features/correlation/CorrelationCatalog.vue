<script setup lang="ts">
import {computed,onScopeDispose,ref,shallowRef} from 'vue'
import {useRouter} from 'vue-router'
import {Select as ASelect} from 'ant-design-vue'
import StatePanel from '@starbeacon/shared/components/StatePanel.vue'
import CorrelationRuleTable from '@starbeacon/shared/components/CorrelationRuleTable.vue'
import CorrelationRuleForm from '@starbeacon/shared/components/CorrelationRuleForm.vue'
import CorrelationRuleDetail from '@starbeacon/shared/components/CorrelationRuleDetail.vue'
import {readCorrelationRule,type CorrelationChange,type CorrelationRule} from '@starbeacon/shared/correlation.ts'
import {session} from '../../session'
import {useCorrelationRules} from './useCorrelationRules'
const model=useCorrelationRules(),router=useRouter(),canEdit=computed(()=>session.current.value?.role==='admin')
const keyword=ref(''),active=ref(''),editing=ref(false),editRecord=shallowRef<CorrelationRule|null>(null),detailTarget=shallowRef<CorrelationRule|null>(null),detail=shallowRef<CorrelationRule|null>(null),revision=ref(1),detailPending=ref(false),detailError=ref('')
let detailController:AbortController|undefined,stopped=false
function create(){if(!canEdit.value)return;editRecord.value=null;model.clearError();editing.value=true}
function edit(record:CorrelationRule){if(!canEdit.value||model.busy.value||model.unconfirmed.value)return;editRecord.value=record;model.clearError();editing.value=true}
async function save(input:CorrelationChange){if(await model.save(input)){editing.value=false;void model.refresh()}}
async function confirm(){if(await model.confirm()){editing.value=false;void model.refresh()}}
function backtest(record:CorrelationRule){if(!canEdit.value||!record.active)return;void router.push({path:'/detection/correlation/backtest',query:{rule_id:record.id,revision:String(record.revision)}})}
async function read(rev:number){
 const target=detailTarget.value;if(stopped||!target||!Number.isSafeInteger(rev)||rev<1||rev>target.revision)return
 detailController?.abort();const current=new AbortController();detailController=current;detailPending.value=true;detailError.value='';detail.value=null;revision.value=rev
 try{const value=await session.api.request<unknown>(`/correlation-rules/${target.id}/revisions/${rev}`,{signal:current.signal});if(current.signal.aborted)return;const record=await readCorrelationRule(value,session.current.value?.tenant_id??'');if(record.id!==target.id||record.revision!==rev)throw new Error('关联规则修订与所选记录不一致。');if(!current.signal.aborted)detail.value=record}catch(cause){if(!current.signal.aborted)detailError.value=cause instanceof Error?cause.message:'规则修订读取失败。'}finally{if(detailController===current)detailPending.value=false}
}
function inspect(record:CorrelationRule){detailTarget.value=record;void read(record.revision)}
function closeDetail(){detailController?.abort();detailTarget.value=null;detail.value=null;detailError.value=''}
onScopeDispose(()=>{stopped=true;detailController?.abort()})
</script>
<template>
 <header class="page-header"><div><h1>关联规则</h1><p class="page-description">按唯一告警、实体字段和固定时间窗口核对活动模式，保留规则修订。</p></div><a-button :loading="model.pending.value" @click="model.refresh">刷新目录</a-button></header>
 <a-alert type="info" show-icon message="当前提供固定修订的按需窗口回测。规则保存与阈值命中不启用实时关联，不生成告警或设备动作。" class="section-gap"/>
 <form class="correlation-toolbar panel-body panel" @submit.prevent="model.search(keyword,active)"><a-input v-model:value="keyword" aria-label="筛选关联规则名称" placeholder="规则名称" :maxlength="128" allow-clear/><a-select v-model:value="active" aria-label="筛选回测状态" :options="[{value:'',label:'全部状态'},{value:'true',label:'允许回测'},{value:'false',label:'停用'}]"/><a-button type="primary" html-type="submit" :loading="model.pending.value">查询</a-button><a-button :disabled="model.pending.value" @click="keyword='';active='';model.search('','')">重置</a-button><a-button v-if="canEdit" :disabled="model.busy.value" @click="create">{{model.unconfirmed.value?'核对原提交':'创建关联规则'}}</a-button></form>
 <section class="panel"><div class="panel-header"><h2>规则目录</h2><span>当前 {{model.page.value.items.length}} 项</span></div><StatePanel :loading="model.pending.value" :error="model.error.value" :empty="!model.page.value.items.length" description="当前条件下没有关联规则。管理员可创建规则，再选择固定修订执行窗口回测。" @retry="model.refresh"><CorrelationRuleTable :items="model.page.value.items" :can-edit="canEdit" :disabled="model.busy.value||model.unconfirmed.value" @inspect="inspect" @edit="edit" @backtest="backtest"/></StatePanel><div class="correlation-pagination"><span class="page-description">历史修订默认保留 180 天，当前配置受引用保护；最多 128 条规则。</span><a-button :disabled="model.pending.value||model.cursors.value.length<=1" @click="model.previous">上一页</a-button><span>第 {{model.cursors.value.length}} 页</span><a-button :disabled="model.pending.value||!!model.error.value||!model.page.value.next_cursor" @click="model.next">下一页</a-button></div></section>
 <CorrelationRuleForm v-if="editing" :record="editRecord" :draft="model.draft()" :busy="model.busy.value" :unconfirmed="model.unconfirmed.value" :error="model.mutationError.value" @save="save" @confirm="confirm" @close="editing=false"/>
 <CorrelationRuleDetail v-else-if="detailTarget" :record="detail" :pending="detailPending" :error="detailError" :revision="revision" :maximum="detailTarget.revision" @read="read" @close="closeDetail"/>
</template>
<style scoped>.correlation-toolbar{display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin-bottom:12px}.correlation-toolbar>.ant-input-affix-wrapper{width:240px}.correlation-toolbar>.ant-select{width:150px}.correlation-pagination{display:flex;gap:8px;align-items:center;justify-content:flex-end;flex-wrap:wrap;padding:12px}.correlation-pagination>.page-description{flex:1;min-width:200px}</style>
