<script setup lang="ts">
import {computed,onScopeDispose,reactive,shallowRef,watch} from 'vue'
import {Table as ATable,Modal as AModal,InputNumber as AInputNumber,Select as ASelect,Tag as ATag,message} from 'ant-design-vue'
import StatePanel from '@starbeacon/shared/components/StatePanel.vue'
import {formatTime} from '@starbeacon/shared/types.ts'
import {session} from '../../session'
import {applicationCategories,validRule,type AppChange,type AppRule} from './applicationRules'
import {useApplicationRules} from './useApplicationRules'
import ApplicationRuleForm from './ApplicationRuleForm.vue'
import ApplicationRuleTest from './ApplicationRuleTest.vue'
const model=useApplicationRules(),canEdit=computed(()=>session.current.value?.role==='admin'),filter=reactive({keyword:'',active:''})
const editing=shallowRef(false),editRecord=shallowRef<AppRule|null>(null),detail=shallowRef<AppRule|null>(null),detailTarget=shallowRef<AppRule|null>(null),detailError=shallowRef(''),detailPending=shallowRef(false),revision=shallowRef<number|null>(null)
const testing=shallowRef(false),testRecord=shallowRef<AppRule|null>(null)
let read:AbortController|undefined,stopped=false
const columns=[{title:'规则名称',key:'name',width:200},{title:'应用产品 / 类别',key:'product',width:200},{title:'协议范围',key:'protocols',width:135},{title:'修订',dataIndex:'revision',width:75},{title:'状态',key:'active',width:80},{title:'保存时间',key:'created',width:175},{title:'操作',key:'actions',width:180}]
function closeDetail(){read?.abort();read=undefined;detail.value=null;detailTarget.value=null;detailError.value='';detailPending.value=false}
function closeOverlays(){closeDetail();testing.value=false;testRecord.value=null}
function search(){closeOverlays();model.search(filter.keyword,filter.active)}
function refresh(){closeOverlays();void model.refresh()}
function page(direction:'next'|'previous'){closeOverlays();model[direction]()}
function edit(record:AppRule|null){if(model.busy.value||!canEdit.value)return;closeOverlays();editRecord.value=record;model.clearError();editing.value=true}
async function save(input:AppChange){const receipt=await model.save(input);if(receipt){editing.value=false;editRecord.value=null;message.success('应用识别规则已保存');await model.refresh()}}
async function confirm(){const receipt=await model.confirm();if(receipt){editing.value=false;editRecord.value=null;message.success('原提交已确认');await model.refresh()}}
function test(record:AppRule|null){if(model.busy.value)return;closeOverlays();editing.value=false;testRecord.value=record;testing.value=true}
async function loadDetail(){
 const target=detailTarget.value,value=revision.value
 if(stopped||!target||!Number.isSafeInteger(value)||value===null||value<1||value>target.revision||detailPending.value)return
 read?.abort();const controller=new AbortController();read=controller;detailPending.value=true;detailError.value='';detail.value=null
 const tenant=session.current.value?.tenant_id??''
 try{const response=await session.api.request<unknown>(`/application-rules/${encodeURIComponent(target.id)}/revisions/${value}`,{signal:controller.signal});if(controller.signal.aborted)return;if(!await validRule(response,tenant)||!(response&&typeof response==='object'&&'id' in response&&response.id===target.id&&'revision' in response&&response.revision===value))throw new Error('规则修订回执与所选对象不一致，请重试。');if(!controller.signal.aborted)detail.value=response as AppRule}
 catch(e){if(!controller.signal.aborted)detailError.value=e instanceof Error?e.message:'应用规则修订读取失败。'}finally{if(read===controller)detailPending.value=false}
}
function inspect(record:AppRule){closeOverlays();editing.value=false;detailTarget.value=record;revision.value=record.revision;void loadDetail()}
function setRevision(value:unknown){revision.value=typeof value==='number'&&Number.isSafeInteger(value)?value:null}
function inputRevision(value:unknown){const raw=typeof value==='string'?value:'';const number=/^[1-9]\d{0,6}$/.test(raw)?Number(raw):null;revision.value=number!==null&&Number.isSafeInteger(number)&&number<=1000000?number:null}
watch(()=>[session.current.value?.id,session.current.value?.tenant_id,session.current.value?.role].join('/'),()=>{closeOverlays();editing.value=false;editRecord.value=null;filter.keyword='';filter.active=''})
onScopeDispose(()=>{stopped=true;read?.abort()})
</script>
<template>
 <a-alert type="info" show-icon message="维护产品名称识别规则并验证可见元数据。当前规则用于输入验证；探针分发、真实流量归因与应用字节计量尚未提供。" class="section-gap"/>
 <form class="application-rule-toolbar" @submit.prevent="search"><a-input v-model:value="filter.keyword" aria-label="应用识别规则名称" placeholder="规则名称" :maxlength="128"/><a-select v-model:value="filter.active" aria-label="应用识别规则状态" :options="[{value:'',label:'全部状态'},{value:'true',label:'启用'},{value:'false',label:'停用'}]"/><a-button html-type="submit" :disabled="model.pending.value">检索</a-button><a-button :loading="model.pending.value" @click="refresh">刷新</a-button><a-button :disabled="model.pending.value" @click="test(null)">验证启用规则</a-button><a-button v-if="canEdit" type="primary" :disabled="model.busy.value" @click="edit(null)">{{model.unconfirmed.value?'核对原提交':'创建规则'}}</a-button></form>
 <section class="panel"><div class="panel-header"><h2>应用识别规则</h2><span>当前页 {{model.page.value.items.length}} 条</span></div>
  <StatePanel :loading="model.pending.value" :error="model.error.value" :empty="!model.page.value.items.length" :description="model.keyword.value||model.active.value?'没有符合筛选条件的应用识别规则。请调整条件后重新检索。':'暂无应用识别规则。管理员配置规则后可验证产品名称条件与排除依据。'" @retry="model.refresh">
   <a-table :data-source="model.page.value.items" :columns="columns" row-key="id" :pagination="false" size="small" :scroll="{x:1045}"><template #bodyCell="{column,record}">
    <template v-if="column.key==='name'"><strong>{{record.name}}</strong><div class="page-description technical">{{record.id}}</div></template>
    <template v-else-if="column.key==='product'">{{record.definition.product_name}}<div class="page-description">{{applicationCategories[record.definition.category_id as keyof typeof applicationCategories]}}</div></template>
    <template v-else-if="column.key==='protocols'"><a-tag v-for="protocol in record.definition.protocols" :key="protocol" color="blue">{{protocol.toUpperCase()}}</a-tag></template>
    <template v-else-if="column.key==='active'"><a-tag :color="record.active?'green':'default'">{{record.active?'启用':'停用'}}</a-tag></template>
    <template v-else-if="column.key==='created'">{{formatTime(record.created_at)}}</template>
    <template v-else-if="column.key==='actions'"><div class="application-row-actions"><a-button type="link" size="small" @click="inspect(record as AppRule)">查看</a-button><a-button v-if="canEdit" type="link" size="small" :disabled="model.busy.value||model.unconfirmed.value" @click="edit(record as AppRule)">编辑</a-button><a-button type="link" size="small" @click="test(record as AppRule)">验证</a-button></div></template>
   </template></a-table>
  </StatePanel>
  <div class="application-pagination"><span class="page-description">规则修订历史默认保留 180 天，当前配置持续保留；最多 128 条规则。</span><a-button :disabled="model.pending.value||model.cursors.value.length<2" @click="page('previous')">上一页</a-button><a-button :disabled="model.pending.value||!!model.error.value||!model.page.value.next_cursor" @click="page('next')">下一页</a-button></div>
 </section>
 <ApplicationRuleForm v-if="editing" :record="editRecord" :draft="model.draft()" :busy="model.busy.value" :unconfirmed="model.unconfirmed.value" :error="model.mutationError.value" @save="save" @confirm="confirm" @close="editing=false"/>
 <ApplicationRuleTest v-else-if="testing" :definition="testRecord?.definition" :name="testRecord?.name" :revision="testRecord?.revision" @close="testing=false;testRecord=null"/>
 <a-modal v-else-if="detailTarget" :open="true" title="应用识别规则详情" :width="800" :footer="null" :body-style="{maxHeight:'calc(100vh - 220px)',overflowY:'auto'}" @cancel="closeDetail">
  <div class="application-revision"><label for="application-revision">读取修订</label><a-input-number id="application-revision" :value="revision??''" :min="1" :max="detailTarget.revision" :precision="0" :disabled="detailPending" @input="inputRevision" @update:value="setRevision"/><a-button :loading="detailPending" :disabled="detailPending||revision===null" @click="loadDetail">读取</a-button></div>
  <StatePanel :loading="detailPending" :error="detailError" @retry="loadDetail"><template v-if="detail">
   <dl class="application-detail"><dt>规则 / 标识</dt><dd>{{detail.name}} · <span class="technical">{{detail.id}}</span></dd><dt>产品 / 类别</dt><dd>{{detail.definition.product_name}} / {{applicationCategories[detail.definition.category_id]}}</dd><dt>修订 / 状态</dt><dd>{{detail.revision}} / {{detail.active?'启用':'停用'}}</dd><dt>维护说明</dt><dd>{{detail.description||'未填写'}}</dd><dt>保存时间 / 操作者</dt><dd>{{formatTime(detail.created_at)}} / <span class="technical">{{detail.created_by}}</span></dd><dt>定义 SHA-256</dt><dd class="technical">{{detail.definition_sha256}}</dd><dt>历史保留截止</dt><dd>{{formatTime(detail.expires_at)}}；当前配置受引用保护。</dd></dl>
   <pre class="application-definition">{{JSON.stringify(detail.definition,null,2)}}</pre>
  </template></StatePanel>
 </a-modal>
</template>
<style scoped>.application-rule-toolbar{display:flex;flex-wrap:wrap;gap:8px;margin-bottom:12px}.application-rule-toolbar>.ant-input{width:220px}.application-rule-toolbar>.ant-select{width:130px}.application-row-actions,.application-pagination,.application-revision{display:flex;align-items:center;gap:8px;flex-wrap:wrap}.application-pagination{justify-content:flex-end;padding:12px}.application-pagination>span{flex:1;min-width:180px}.application-detail{display:grid;grid-template-columns:140px minmax(0,1fr);gap:8px}.application-detail dd{margin:0;overflow-wrap:anywhere}.application-detail dt{color:var(--text-secondary,#4b5563)}.application-definition{white-space:pre-wrap;overflow-wrap:anywhere;background:var(--surface-muted,#f8f9fa);padding:12px;border:1px solid var(--border-color,#e5e7eb);border-radius:8px}.application-revision{margin-bottom:12px}</style>
