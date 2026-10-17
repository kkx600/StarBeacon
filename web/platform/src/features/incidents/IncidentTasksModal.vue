<script setup lang="ts">
import {nextTick,ref,shallowRef,watch} from 'vue'
import {Modal as AModal,Table as ATable,Tag as ATag,Select as ASelect,Descriptions as ADescriptions,Timeline as ATimeline} from 'ant-design-vue'
import {formatTime} from '@starbeacon/shared/types.ts'
import {useFeedback} from '@starbeacon/shared/composables/useFeedback.ts'
import StatePanel from '@starbeacon/shared/components/StatePanel.vue'
import type {IncidentAssignee,IncidentRecord} from './incident'
import {taskPriorities,taskStatuses,type IncidentTaskInput,type IncidentTaskRecord} from './incidentTask'
import IncidentTaskForm from './IncidentTaskForm.vue'
import type {IncidentTasksState} from './useIncidentTasks'

const ADescriptionsItem=ADescriptions.Item,ATimelineItem=ATimeline.Item
const props=defineProps<{parent:IncidentRecord;state:IncidentTasksState;assignees:readonly IncidentAssignee[];ownerPending:boolean;ownerError:string;parentPending:boolean;parentError:string}>()
const emit=defineEmits<{close:[];reloadParent:[];reloadOwners:[]}>()
const {page,pending,error,cursors,selected,detailPending,detailError,history,historyNext,historyPending,historyError,historyLoaded,busy,unconfirmed,actionError}=props.state
const errorPanel=ref<HTMLDivElement|null>(null)
watch(actionError,value=>{if(value)void nextTick(()=>errorPanel.value?.focus())},{flush:'post'})
const feedback=useFeedback(),mode=ref<'list'|'detail'|'form'>('list'),status=ref(''),viewID=ref(''),editingID=ref('')
const editing=shallowRef<IncidentTaskRecord|null>(null),draft=shallowRef<IncidentTaskInput>(),form=ref<{submit:()=>void}|null>(null),formEpoch=ref(0)
const colors={open:'orange',in_progress:'blue',completed:'green',cancelled:'default'} as const
const columns=[{title:'任务标题',key:'title',width:240},{title:'状态',key:'state',width:110},{title:'优先级',key:'priority',width:100},{title:'负责人',dataIndex:'assignee_name',key:'owner',width:150},{title:'截止时间',key:'due',width:185},{title:'操作',key:'actions',width:80}]
function restore(){const original=props.state.pendingInput();if(!original)return;editingID.value=original.id;editing.value=null;draft.value=original.input;formEpoch.value++;mode.value='form'}
function create(){if(unconfirmed.value){restore();return}editingID.value='';editing.value=null;draft.value=undefined;formEpoch.value++;props.state.clearActionError();mode.value='form'}
function show(id:string){viewID.value=id;mode.value='detail';void props.state.select(id)}
function edit(){if(unconfirmed.value){restore();return}if(!selected.value)return;editingID.value=selected.value.id;editing.value=selected.value;draft.value=undefined;formEpoch.value++;props.state.clearActionError();mode.value='form'}
async function save(input:IncidentTaskInput){const result=await props.state.save(editingID.value,input);if(result){draft.value=undefined;mode.value='list';emit('reloadParent');feedback.success('协作任务已提交')}else if(!unconfirmed.value)draft.value=undefined}
async function confirm(){if(await props.state.confirm()){draft.value=undefined;mode.value='list';emit('reloadParent');feedback.success('协作提交已确认')}}
if(unconfirmed.value)restore()
</script>
<template>
 <a-modal :open="true" :title="mode==='form'?(editingID?'记录协作任务':'建立协作任务'):'协作任务'" :width="1000" :closable="!busy" :keyboard="!busy" :mask-closable="false" @cancel="emit('close')">
  <div class="task-parent section-gap"><strong>{{parent.spec.title}}</strong><span class="muted">事件修订 {{parent.revision}} · {{parent.id}}</span></div>
  <a-alert v-if="parentError" type="error" show-icon :message="parentError" class="section-gap"/>
  <a-alert v-if="parent.spec.status==='closed'" type="info" show-icon message="事件已结案，协作任务仅供查阅。需要继续调查时，请先重开事件。" class="section-gap"/>
  <a-alert v-if="unconfirmed" type="warning" show-icon message="上次协作提交尚未确认。请使用原请求核对，避免重复建立或覆盖任务。" class="section-gap"><template #action><a-button size="small" :loading="busy" @click="restore">核对原提交</a-button></template></a-alert>
  <div v-if="actionError" ref="errorPanel" tabindex="-1" role="region" aria-label="任务提交结果" class="section-gap"><a-alert type="error" show-icon :message="actionError"/></div>
  <template v-if="mode==='list'">
   <div class="task-toolbar section-gap"><a-select v-model:value="status" aria-label="筛选协作任务状态" :options="[{value:'',label:'全部状态'},...Object.entries(taskStatuses).map(([value,label])=>({value,label}))]" @change="props.state.search(status)"/><a-button :loading="pending||parentPending" :disabled="busy" @click="emit('reloadParent')">刷新事件与任务</a-button><a-button type="primary" :disabled="busy||parentPending||!!parentError||parent.spec.status==='closed'" @click="create">建立任务</a-button></div>
   <StatePanel :loading="pending" :error="error" :empty="!page.items.length" description="当前条件下没有协作任务。可分派调查工作，记录处理进展与完成依据。" @retry="props.state.refresh">
    <a-table row-key="id" size="middle" :data-source="page.items" :columns="columns" :pagination="false" :scroll="{x:865}"><template #bodyCell="{column,record}"><template v-if="column.key==='title'"><a-button type="link" class="task-title" @click="show(record.id)">{{record.spec.title}}</a-button><div class="technical muted">{{record.id}}</div></template><a-tag v-else-if="column.key==='state'" :color="colors[record.spec.status as keyof typeof colors]">{{taskStatuses[record.spec.status as keyof typeof taskStatuses]}}</a-tag><a-tag v-else-if="column.key==='priority'" :color="record.spec.priority==='high'?'red':record.spec.priority==='medium'?'orange':'blue'">{{taskPriorities[record.spec.priority as keyof typeof taskPriorities]}}</a-tag><template v-else-if="column.key==='owner'">{{record.assignee_name||'待分派'}}</template><template v-else-if="column.key==='due'">{{record.spec.due_at?formatTime(record.spec.due_at):'未设置'}}</template><a-button v-else-if="column.key==='actions'" type="link" @click="show(record.id)">查看</a-button></template></a-table>
   </StatePanel>
   <div class="task-pagination"><a-button :disabled="pending||cursors.length<=1" @click="props.state.previous">上一页</a-button><span>第 {{cursors.length}} 页</span><a-button :disabled="pending||!page.next_cursor" @click="props.state.next">下一页</a-button></div>
  </template>
  <IncidentTaskForm v-else-if="mode==='form'" :key="formEpoch" ref="form" :parent="parent" :record="editing" :editing="!!editingID" :draft="draft" :assignees="assignees" :owner-pending="ownerPending" :owner-error="ownerError" :busy="busy||parentPending||!!parentError" :unconfirmed="unconfirmed" @save="save" @reload-owners="emit('reloadOwners')"/>
  <StatePanel v-else :loading="detailPending" :error="detailError" @retry="props.state.select(viewID)">
   <template v-if="selected">
    <h2 class="task-title">{{selected.spec.title}}</h2><p class="task-text">{{selected.spec.description}}</p>
    <a-descriptions bordered size="small" :column="1"><a-descriptions-item label="任务标识"><span class="technical">{{selected.id}}</span></a-descriptions-item><a-descriptions-item label="任务状态"><a-tag :color="colors[selected.spec.status]">{{taskStatuses[selected.spec.status]}}</a-tag></a-descriptions-item><a-descriptions-item label="优先级">{{taskPriorities[selected.spec.priority]}}</a-descriptions-item><a-descriptions-item label="负责人">{{selected.assignee_name||'待分派'}}</a-descriptions-item><a-descriptions-item label="截止时间">{{selected.spec.due_at?formatTime(selected.spec.due_at):'未设置'}}</a-descriptions-item><a-descriptions-item v-if="selected.spec.resolution" label="完成依据或取消原因"><span class="task-text">{{selected.spec.resolution}}</span></a-descriptions-item><a-descriptions-item label="建立时间">{{formatTime(selected.created_at)}}</a-descriptions-item><a-descriptions-item label="最近变更说明"><span class="task-text">{{selected.note}}</span></a-descriptions-item><a-descriptions-item label="任务修订">{{selected.revision}} · 基于事件修订 {{selected.incident_revision}}</a-descriptions-item><a-descriptions-item label="最近记录">{{selected.actor_name}} · {{formatTime(selected.recorded_at)}}</a-descriptions-item><a-descriptions-item label="记录保留截止">{{formatTime(selected.expires_at)}}</a-descriptions-item></a-descriptions>
    <div class="task-toolbar section-gap"><a-button :disabled="busy||parentPending||!!parentError||parent.spec.status==='closed'||selected.revision>=1000" type="primary" @click="edit">记录任务</a-button><a-button :loading="historyPending" @click="props.state.loadHistory()">读取历史</a-button></div>
    <StatePanel v-if="historyLoaded||historyPending||historyError" :loading="historyPending" :error="historyError" :empty="!history.length" description="当前保留范围内没有可读取的任务历史。" @retry="props.state.loadHistory()">
    <a-timeline v-if="history.length"><a-timeline-item v-for="row in history" :key="row.revision"><strong>修订 {{row.revision}} · {{taskStatuses[row.spec.status]}}</strong><p class="muted">{{row.actor_name}} · {{formatTime(row.recorded_at)}}</p><p class="task-text">{{row.note}}</p><p v-if="row.spec.resolution" class="task-text">{{row.spec.resolution}}</p></a-timeline-item></a-timeline></StatePanel><a-button v-if="historyNext" :loading="historyPending" @click="props.state.loadHistory(historyNext)">读取更早记录</a-button>
   </template>
  </StatePanel>
  <template #footer><a-button v-if="mode!=='list'" :disabled="busy" @click="mode='list'">返回任务</a-button><a-button :disabled="busy" @click="emit('close')">关闭</a-button><a-button v-if="mode==='form'&&unconfirmed" type="primary" :loading="busy" @click="confirm">核对原提交</a-button><a-button v-else-if="mode==='form'" type="primary" :loading="busy" :disabled="parentPending||!!parentError||parent.spec.status==='closed'" @click="form?.submit()">保存任务</a-button></template>
 </a-modal>
</template>
<style scoped>.task-parent{display:flex;flex-direction:column;gap:4px;overflow-wrap:anywhere}.task-toolbar,.task-pagination{display:flex;align-items:center;flex-wrap:wrap;gap:var(--related-gap)}.task-toolbar{margin-top:var(--related-gap)}.task-toolbar :deep(.ant-select){min-width:150px}.task-pagination{justify-content:flex-end;margin-top:var(--related-gap)}.task-text{white-space:pre-wrap;overflow-wrap:anywhere}.task-title{white-space:normal;overflow-wrap:anywhere}.task-title.ant-btn{padding:0;height:auto;text-align:left}.technical{overflow-wrap:anywhere}</style>
