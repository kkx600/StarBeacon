<script setup lang="ts">
import {computed,nextTick,ref,shallowRef,watch} from 'vue'
import {Modal as AModal,Table as ATable,Tag as ATag,Select as ASelect,Descriptions as ADescriptions,Timeline as ATimeline} from 'ant-design-vue'
import {formatTime} from '@starbeacon/shared/types.ts'
import {useFeedback} from '@starbeacon/shared/composables/useFeedback.ts'
import StatePanel from '@starbeacon/shared/components/StatePanel.vue'
import {session} from '../../session'
import type {IncidentRecord} from './incident'
import {noteStatuses,type IncidentNoteInput,type IncidentNoteRecord} from './incidentNote'
import IncidentNoteForm from './IncidentNoteForm.vue'
import type {IncidentNotesState} from './useIncidentNotes'

const ADescriptionsItem=ADescriptions.Item,ATimelineItem=ATimeline.Item
const props=defineProps<{parent:IncidentRecord;state:IncidentNotesState;parentPending:boolean;parentError:string}>()
const emit=defineEmits<{close:[];reloadParent:[]}>()
const {page,pending,error,cursors,status,selected,detailPending,detailError,history,historyNext,historyPending,historyError,historyLoaded,busy,unconfirmed,actionError}=props.state
const feedback=useFeedback(),mode=ref<'list'|'detail'|'form'>('list'),viewID=ref(''),editingID=ref('')
const editing=shallowRef<IncidentNoteRecord|null>(null),draft=shallowRef<IncidentNoteInput>(),form=ref<{submit:()=>void}|null>(null),formEpoch=ref(0),errorPanel=ref<HTMLDivElement|null>(null)
const canEdit=computed(()=>!!selected.value&&selected.value.author_id===session.current.value?.id&&props.parent.spec.status!=='closed'&&selected.value.revision<1000)
watch(actionError,value=>{if(value)void nextTick(()=>errorPanel.value?.focus())},{flush:'post'})
const columns=[{title:'笔记标题',key:'title',width:280},{title:'状态',key:'status',width:110},{title:'作者',dataIndex:'author_name',key:'author',width:150},{title:'记录时间',key:'recorded',width:190},{title:'操作',key:'actions',width:80}]
function restore(){const original=props.state.pendingInput();if(!original)return;editingID.value=original.id;editing.value=null;draft.value=original.input;formEpoch.value++;mode.value='form'}
function create(){if(unconfirmed.value){restore();return}editingID.value='';editing.value=null;draft.value=undefined;formEpoch.value++;props.state.clearActionError();mode.value='form'}
function show(id:string){viewID.value=id;mode.value='detail';void props.state.select(id)}
function edit(){if(unconfirmed.value){restore();return}if(!canEdit.value||!selected.value)return;editingID.value=selected.value.id;editing.value=selected.value;draft.value=undefined;formEpoch.value++;props.state.clearActionError();mode.value='form'}
async function save(input:IncidentNoteInput){if(await props.state.save(editingID.value,input)){draft.value=undefined;mode.value='list';emit('reloadParent');feedback.success('调查笔记已提交')}else if(!unconfirmed.value)draft.value=undefined}
async function confirm(){if(await props.state.confirm()){draft.value=undefined;mode.value='list';emit('reloadParent');feedback.success('笔记提交已确认')}}
if(unconfirmed.value)restore()
</script>
<template>
 <a-modal :open="true" :title="mode==='form'?(editingID?'编辑调查笔记':'建立调查笔记'):'调查笔记'" :width="1000" :closable="!busy" :keyboard="!busy" :mask-closable="false" @cancel="emit('close')">
  <div class="note-parent section-gap"><strong>{{parent.spec.title}}</strong><span class="muted">事件修订 {{parent.revision}} · {{parent.id}}</span></div>
  <a-alert v-if="parentError" type="error" show-icon :message="parentError" class="section-gap"/>
  <a-alert v-if="parent.spec.status==='closed'" type="info" show-icon message="事件已结案，调查笔记仅供查阅。需要继续记录时，请先重开事件。" class="section-gap"/>
  <a-alert v-if="unconfirmed" type="warning" show-icon message="上次笔记提交尚未确认。请核对原提交，避免重复建立或覆盖记录。" class="section-gap"><template #action><a-button size="small" :loading="busy" @click="restore">核对原提交</a-button></template></a-alert>
  <div v-if="actionError" ref="errorPanel" tabindex="-1" role="region" aria-label="笔记提交结果" class="section-gap"><a-alert type="error" show-icon :message="actionError"/></div>
  <template v-if="mode==='list'">
   <div class="note-toolbar section-gap"><a-select :value="status" aria-label="筛选调查笔记状态" :options="[{value:'',label:'全部状态'},...Object.entries(noteStatuses).map(([value,label])=>({value,label}))]" @change="value=>{if(typeof value==='string')props.state.search(value)}"/><a-button :loading="pending||parentPending" :disabled="busy" @click="emit('reloadParent')">刷新事件与笔记</a-button><a-button type="primary" :disabled="busy||parentPending||!!parentError||parent.spec.status==='closed'" @click="create">建立笔记</a-button></div>
   <StatePanel :loading="pending" :error="error" :empty="!page.items.length" description="当前条件下没有调查笔记。可记录已观察事实、来源及待核实的问题。" @retry="props.state.refresh">
    <a-table row-key="id" size="middle" :data-source="page.items" :columns="columns" :pagination="false" :scroll="{x:810}"><template #bodyCell="{column,record}"><template v-if="column.key==='title'"><a-button type="link" class="note-title" @click="show(record.id)">{{record.spec.title}}</a-button><div class="technical muted">{{record.id}}</div></template><a-tag v-else-if="column.key==='status'" :color="record.spec.status==='active'?'blue':'default'">{{noteStatuses[record.spec.status as keyof typeof noteStatuses]}}</a-tag><template v-else-if="column.key==='recorded'">{{formatTime(record.recorded_at)}}</template><a-button v-else-if="column.key==='actions'" type="link" @click="show(record.id)">查看</a-button></template></a-table>
   </StatePanel>
   <p class="muted note-policy">笔记对当前租户具备事件调查权限的管理员可见；仅作者本人可以修改或撤回，修订按事件留存策略管理。</p>
   <div class="note-pagination"><a-button :disabled="pending||cursors.length<=1" @click="props.state.previous">上一页</a-button><span>第 {{cursors.length}} 页</span><a-button :disabled="pending||!page.next_cursor" @click="props.state.next">下一页</a-button></div>
  </template>
  <IncidentNoteForm v-else-if="mode==='form'" :key="formEpoch" ref="form" :parent="parent" :record="editing" :editing="!!editingID" :draft="draft" :busy="busy||parentPending||!!parentError" :unconfirmed="unconfirmed" @save="save"/>
  <StatePanel v-else :loading="detailPending" :error="detailError" @retry="props.state.select(viewID)">
   <template v-if="selected">
    <h2 class="note-title">{{selected.spec.title}}</h2><p class="note-text">{{selected.spec.body}}</p>
    <a-descriptions bordered size="small" :column="1"><a-descriptions-item label="笔记标识"><span class="technical">{{selected.id}}</span></a-descriptions-item><a-descriptions-item label="笔记状态"><a-tag :color="selected.spec.status==='active'?'blue':'default'">{{noteStatuses[selected.spec.status]}}</a-tag></a-descriptions-item><a-descriptions-item label="原始作者">{{selected.author_name}}</a-descriptions-item><a-descriptions-item label="建立时间">{{formatTime(selected.created_at)}}</a-descriptions-item><a-descriptions-item label="最近记录">{{selected.actor_name}} · {{formatTime(selected.recorded_at)}}</a-descriptions-item><a-descriptions-item label="修订">{{selected.revision}} · 基于事件修订 {{selected.incident_revision}}</a-descriptions-item><a-descriptions-item label="变更说明"><span class="note-text">{{selected.reason}}</span></a-descriptions-item><a-descriptions-item v-if="selected.spec.withdrawal_reason" label="撤回原因"><span class="note-text">{{selected.spec.withdrawal_reason}}</span></a-descriptions-item><a-descriptions-item label="当前修订保留期限">{{formatTime(selected.expires_at)}} · {{parent.spec.status==='closed'?'按固化期限保留':'活动事件的笔记及历史受保护'}}</a-descriptions-item></a-descriptions>
    <div class="note-toolbar section-gap"><a-button type="primary" :disabled="busy||parentPending||!!parentError||!canEdit" @click="edit">编辑笔记</a-button><a-button :loading="historyPending" @click="props.state.loadHistory()">读取历史</a-button></div>
    <StatePanel v-if="historyLoaded||historyPending||historyError" :loading="historyPending" :error="historyError" :empty="!history.length" description="当前保留范围内没有笔记历史。" @retry="props.state.loadHistory()"><a-timeline><a-timeline-item v-for="row in history" :key="row.revision"><strong>修订 {{row.revision}} · {{noteStatuses[row.spec.status]}}</strong><p class="muted">{{row.actor_name}} · {{formatTime(row.recorded_at)}}</p><p class="note-text">{{row.reason}}</p><h3 class="note-history-title">{{row.spec.title}}</h3><p class="note-text">{{row.spec.body}}</p><p v-if="row.spec.withdrawal_reason" class="note-text">撤回原因：{{row.spec.withdrawal_reason}}</p></a-timeline-item></a-timeline></StatePanel><a-button v-if="historyNext" :loading="historyPending" @click="props.state.loadHistory(historyNext)">读取更早记录</a-button>
   </template>
  </StatePanel>
  <template #footer><a-button v-if="mode!=='list'" :disabled="busy" @click="mode='list'">返回笔记</a-button><a-button :disabled="busy" @click="emit('close')">关闭</a-button><a-button v-if="mode==='form'&&unconfirmed" type="primary" :loading="busy" @click="confirm">核对原提交</a-button><a-button v-else-if="mode==='form'" type="primary" :loading="busy" :disabled="parentPending||!!parentError||parent.spec.status==='closed'" @click="form?.submit()">保存笔记</a-button></template>
 </a-modal>
</template>
<style scoped>.note-parent{display:flex;flex-direction:column;gap:4px;overflow-wrap:anywhere}.note-toolbar,.note-pagination{display:flex;align-items:center;flex-wrap:wrap;gap:var(--related-gap)}.note-toolbar{margin-top:var(--related-gap)}.note-toolbar :deep(.ant-select){min-width:150px}.note-pagination{justify-content:flex-end;margin-top:var(--related-gap)}.note-text{white-space:pre-wrap;overflow-wrap:anywhere}.note-title{white-space:normal;overflow-wrap:anywhere}.note-title.ant-btn{padding:0;height:auto;text-align:left}.note-policy{margin:var(--related-gap) 0;overflow-wrap:anywhere}.note-history-title{font-size:14px;margin:var(--related-gap) 0}.technical{overflow-wrap:anywhere}</style>
