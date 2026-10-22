<script setup lang="ts">
import {computed,shallowRef,toRaw,useTemplateRef,watch} from 'vue'
import {Modal as AModal,Table as ATable,Tag as ATag,Descriptions as ADescriptions,Timeline as ATimeline} from 'ant-design-vue'
import type {IncidentRecord} from '../../../web/platform/src/features/incidents/incident'
import {noteStatuses,noteSpecError,validNoteRecord,type IncidentNoteAttempt,type IncidentNoteInput,type IncidentNoteRecord} from '../../../web/platform/src/features/incidents/incidentNote'
import IncidentNoteForm from '../../../web/platform/src/features/incidents/IncidentNoteForm.vue'
import StatePanel from '../../../web/packages/shared/src/components/StatePanel.vue'
import {formatTime} from '../../../web/packages/shared/src/types'

const ADescriptionsItem=ADescriptions.Item,ATimelineItem=ATimeline.Item
const props=withDefaults(defineProps<{parent:IncidentRecord;scenario?:string;open?:boolean}>(),{open:true}),emit=defineEmits<{close:[]}>()
const mode=shallowRef<'list'|'detail'|'form'>('list'),records=shallowRef<IncidentNoteRecord[]>([]),selected=shallowRef<IncidentNoteRecord|null>(null),editing=shallowRef(false),historyOpen=shallowRef(false),error=shallowRef(''),unconfirmed=shallowRef(false),draft=shallowRef<IncidentNoteInput>()
const readRetried=shallowRef(false)
const form=useTemplateRef<InstanceType<typeof IncidentNoteForm>>('form'),epoch=shallowRef(0)
const versions=new Map<string,IncidentNoteRecord[]>()
const receipts=new Set<string>()
let attempt:(IncidentNoteAttempt&{key:string})|undefined
const actor='admin_example',canEdit=computed(()=>!!selected.value&&selected.value.author_id===actor&&props.parent.spec.status!=='closed'&&selected.value.revision<1000)
const history=computed(()=>versions.get(selected.value?.id??'')??[])
const columns=[{title:'笔记标题',key:'title',width:280},{title:'状态',key:'status',width:110},{title:'作者',dataIndex:'author_name',width:150},{title:'记录时间',key:'time',width:190},{title:'操作',key:'actions',width:80}]
function example():IncidentNoteRecord {
 const withdrawn=props.scenario==='withdrawn',foreign=props.scenario==='foreign'
 return {id:'note_example',incident_id:props.parent.id,incident_revision:props.parent.revision,revision:2,spec:{title:'核对请求与业务影响（示例）',body:'已观察：示例请求命中检测规则。\n待确认：应用端是否执行请求、是否产生实际影响。\n来源：合成告警与样本标识，不代表真实调查结论。',status:withdrawn?'withdrawn':'active',withdrawal_reason:withdrawn?'材料归属需要继续核对，撤回当前说明，保留原有历史。':''},author_id:foreign?'admin_other_example':actor,author_name:foreign?'另一分析员（示例）':'陈宁（示例）',reason:'补充原始材料与待确认问题。',actor_id:foreign?'admin_other_example':actor,actor_name:foreign?'另一分析员（示例）':'陈宁（示例）',created_at:'2026-10-18T01:00:00Z',recorded_at:'2026-10-22T01:00:00Z',expires_at:'2027-04-20T01:00:00Z'}
}
function initialize(){
 readRetried.value=false;const row=example();records.value=props.scenario==='empty'?[]:[row];versions.clear();receipts.clear();versions.set(row.id,[row,{...row,revision:1,spec:{...row.spec,status:'active',withdrawal_reason:''},reason:'建立调查笔记。',recorded_at:row.created_at}]);selected.value=null;editing.value=false;historyOpen.value=false;unconfirmed.value=false;draft.value=undefined;attempt=undefined;error.value='';mode.value='list'
 if(['detail','history'].includes(props.scenario??'')){selected.value=row;mode.value='detail';historyOpen.value=props.scenario==='history'}
 if(['form','conflict','unknown'].includes(props.scenario??'')){selected.value=row;editing.value=true;mode.value='form'}
 if(props.scenario==='unknown'){attempt={parent:structuredClone(toRaw(props.parent)),id:row.id,input:{incident_revision:props.parent.revision,expected_revision:row.revision,spec:structuredClone(row.spec),reason:'核对同一份合成提交。'},key:crypto.randomUUID()};draft.value=structuredClone(attempt.input);unconfirmed.value=true}
 epoch.value++
}
watch([()=>props.parent.id,()=>props.scenario],initialize,{immediate:true})
// 合成提交保留原目标、修订、材料和提交键；返回或关闭只改变视图。
function restore(){const original=attempt;if(!original)return;selected.value=records.value.find(row=>row.id===original.id)??null;editing.value=!!original.id;draft.value=structuredClone(original.input);epoch.value++;mode.value='form'}
function create(){if(unconfirmed.value){restore();return}if(props.parent.spec.status==='closed')return;selected.value=null;editing.value=false;draft.value=undefined;error.value='';epoch.value++;mode.value='form'}
function inspect(row:IncidentNoteRecord){selected.value=row;historyOpen.value=false;mode.value='detail';error.value=''}
function edit(){if(unconfirmed.value){restore();return}if(!canEdit.value)return;editing.value=true;draft.value=undefined;error.value='';epoch.value++;mode.value='form'}
function apply(input:IncidentNoteInput,id:string){
 if(props.parent.spec.status==='closed'||input.incident_revision!==props.parent.revision)throw new Error('事件状态或修订已变化，当前不能保存笔记。')
 const invalid=noteSpecError(input.spec);if(invalid)throw new Error(invalid)
 const current=id?records.value.find(row=>row.id===id):undefined
 if(id&&(!current||current.author_id!==actor||!('expected_revision' in input)||input.expected_revision!==current.revision))throw new Error('笔记修订或作者权限已变化，请返回列表重新读取。')
 const now=new Date().toISOString(),row:IncidentNoteRecord={id:current?.id??'note_'+crypto.randomUUID().replaceAll('-',''),incident_id:props.parent.id,incident_revision:input.incident_revision,revision:(current?.revision??0)+1,spec:structuredClone(input.spec),author_id:actor,author_name:'陈宁（示例）',reason:'reason' in input?input.reason:'建立调查笔记。',actor_id:actor,actor_name:'陈宁（示例）',created_at:current?.created_at??now,recorded_at:now,expires_at:new Date(Date.now()+180*86400000).toISOString()}
 if(!validNoteRecord(row,props.parent.id))throw new Error('合成笔记未通过工程记录校验。')
 records.value=[row,...records.value.filter(item=>item.id!==row.id)];versions.set(row.id,[row,...versions.get(row.id)??[]]);selected.value=row;return row
}
function save(input:IncidentNoteInput){
 if(unconfirmed.value)return
 try{if(props.scenario==='conflict')throw new Error('合成修订冲突示例：笔记已被其他操作修改，请返回列表重新核对。');if(editing.value&&!selected.value)throw new Error('当前笔记尚未读取，请返回列表重新核对。');apply(input,editing.value?selected.value!.id:'');error.value='';mode.value='list'}catch(e){error.value=e instanceof Error?e.message:'合成笔记未保存'}
}
function confirm(){const original=attempt;if(!original)return;try{if(original.parent.id!==props.parent.id)throw new Error('当前事件与原提交不一致，请返回原事件核对。');if(!receipts.has(original.key)){apply(original.input,original.id);receipts.add(original.key)}attempt=undefined;unconfirmed.value=false;draft.value=undefined;error.value='';mode.value='list'}catch(e){error.value=e instanceof Error?e.message:'原合成提交尚未核对'}}
function close(){emit('close')}
</script>
<template>
 <a-modal :open="open" :title="mode==='form'?(editing?'编辑调查笔记':'建立调查笔记'):'调查笔记'" :width="1000" :body-style="{maxHeight:'calc(100vh - 240px)',overflowY:'auto'}" :mask-closable="false" @cancel="close">
  <a-alert type="info" show-icon message="合成调查笔记示例" description="表单与记录校验复用工程实现；笔记与历史只保存在浏览器内存，不访问真实案件或提交API。" class="section-gap"/>
  <p class="note-parent"><strong>{{parent.spec.title}}</strong><span class="muted">事件修订 {{parent.revision}} · {{parent.id}}</span></p>
  <a-alert v-if="parent.spec.status==='closed'" type="info" show-icon message="事件已结案，调查笔记仅供查阅。需要继续记录时，请先重开事件。" class="section-gap"/>
  <a-alert v-if="unconfirmed" type="warning" show-icon message="上次笔记提交尚未确认。请核对原提交，避免重复建立或覆盖记录。" description="当前为合成回执未知示例，原提交仅保存在浏览器内存。" class="section-gap"><template #action><a-button size="small" @click="restore">核对原提交</a-button></template></a-alert>
  <a-alert v-if="error" type="error" show-icon :message="error" class="section-gap"/>
  <template v-if="mode==='list'"><div class="note-toolbar section-gap"><a-button type="primary" :disabled="parent.spec.status==='closed'" @click="create">建立笔记</a-button></div><StatePanel :loading="scenario==='loading'" :error="scenario==='error'&&!readRetried?'合成笔记来源暂时不可用，请核对后重试。':''" :empty="!records.length" description="当前示例范围内没有调查笔记。" @retry="readRetried=true"><a-table :data-source="records" :columns="columns" row-key="id" :pagination="false" :scroll="{x:810}"><template #bodyCell="{column,record}"><a-button v-if="column.key==='title'" type="link" class="note-title" @click="inspect(record as IncidentNoteRecord)">{{record.spec.title}}</a-button><a-tag v-else-if="column.key==='status'" :color="record.spec.status==='active'?'blue':undefined">{{noteStatuses[record.spec.status as keyof typeof noteStatuses]}}</a-tag><span v-else-if="column.key==='time'">{{formatTime(record.recorded_at)}}</span><a-button v-else-if="column.key==='actions'" type="link" @click="inspect(record as IncidentNoteRecord)">查看</a-button></template></a-table></StatePanel></template>
  <IncidentNoteForm v-else-if="mode==='form'" :key="epoch" ref="form" :parent="parent" :record="selected" :editing="editing" :draft="draft" :busy="false" :unconfirmed="unconfirmed" @save="save"/>
  <template v-else-if="selected"><h2 class="note-title">{{selected.spec.title}}</h2><p class="note-text">{{selected.spec.body}}</p><a-descriptions bordered :column="1" size="small"><a-descriptions-item label="笔记标识"><span class="technical">{{selected.id}}</span></a-descriptions-item><a-descriptions-item label="笔记状态"><a-tag :color="selected.spec.status==='active'?'blue':undefined">{{noteStatuses[selected.spec.status]}}</a-tag></a-descriptions-item><a-descriptions-item label="原始作者">{{selected.author_name}}</a-descriptions-item><a-descriptions-item label="建立时间">{{formatTime(selected.created_at)}}</a-descriptions-item><a-descriptions-item label="最近记录">{{selected.actor_name}} · {{formatTime(selected.recorded_at)}}</a-descriptions-item><a-descriptions-item label="修订">{{selected.revision}} · 基于事件修订 {{selected.incident_revision}}</a-descriptions-item><a-descriptions-item label="变更说明"><span class="note-text">{{selected.reason}}</span></a-descriptions-item><a-descriptions-item v-if="selected.spec.withdrawal_reason" label="撤回原因"><span class="note-text">{{selected.spec.withdrawal_reason}}</span></a-descriptions-item><a-descriptions-item label="当前修订保留期限">{{formatTime(selected.expires_at)}} · {{parent.spec.status==='closed'?'按固化期限保留':'活动事件的笔记及历史受保护'}}</a-descriptions-item></a-descriptions><div class="note-toolbar section-gap"><a-button type="primary" :disabled="!canEdit" @click="edit">编辑笔记</a-button><a-button @click="historyOpen=!historyOpen">{{historyOpen?'收起历史':'读取历史'}}</a-button></div><a-timeline v-if="historyOpen"><a-timeline-item v-for="row in history" :key="row.revision"><strong>修订 {{row.revision}} · {{noteStatuses[row.spec.status]}}</strong><p class="muted">{{row.actor_name}} · {{formatTime(row.recorded_at)}}</p><p class="note-text">{{row.reason}}</p><p class="note-text">{{row.spec.body}}</p><p v-if="row.spec.withdrawal_reason" class="note-text">撤回原因：{{row.spec.withdrawal_reason}}</p></a-timeline-item></a-timeline></template>
  <template #footer><a-button v-if="mode!=='list'" @click="mode='list'">返回笔记</a-button><a-button @click="close">关闭</a-button><a-button v-if="mode==='form'&&unconfirmed" type="primary" @click="confirm">核对原提交</a-button><a-button v-else-if="mode==='form'" type="primary" :disabled="parent.spec.status==='closed'" @click="form?.submit()">保存笔记</a-button></template>
 </a-modal>
</template>
<style scoped>
.note-parent{display:flex;flex-direction:column;gap:var(--label-gap);overflow-wrap:anywhere}
.note-toolbar{display:flex;align-items:center;flex-wrap:wrap;gap:var(--related-gap)}
.note-title{font-size:16px;overflow-wrap:anywhere;white-space:normal}
.note-text{white-space:pre-wrap;overflow-wrap:anywhere}
</style>
