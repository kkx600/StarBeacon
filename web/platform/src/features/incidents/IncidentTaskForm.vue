<script setup lang="ts">
import {computed,nextTick,ref,toRaw} from 'vue'
import {Select as ASelect} from 'ant-design-vue'
import type {IncidentAssignee,IncidentRecord} from './incident'
import {newTaskSpec,taskPriorities,taskSpecError,taskStatuses,type IncidentTaskInput,type IncidentTaskRecord} from './incidentTask'

const props=defineProps<{parent:IncidentRecord;record:IncidentTaskRecord|null;editing:boolean;draft?:IncidentTaskInput;assignees:readonly IncidentAssignee[];ownerPending:boolean;ownerError:string;busy:boolean;unconfirmed:boolean}>()
const emit=defineEmits<{save:[input:IncidentTaskInput];reloadOwners:[]}>()
const spec=ref(structuredClone(toRaw(props.draft?.spec??props.record?.spec??newTaskSpec())))
const errorPanel=ref<HTMLDivElement|null>(null)
function revealError(){void nextTick(()=>errorPanel.value?.focus())}
const note=ref(props.draft&&'note' in props.draft?props.draft.note:''),validation=ref('')
function localDate(value:string|null){if(!value)return '';const date=new Date(value);return new Date(date.getTime()-date.getTimezoneOffset()*60000).toISOString().slice(0,16)}
const originalDue=spec.value.due_at,initialDue=localDate(originalDue),due=ref(initialDue)
const disabled=computed(()=>props.busy||props.unconfirmed)
const owners=computed(()=>[{value:'',label:'待分派'},...(props.record?.spec.assignee_id&&!props.assignees.some(a=>a.id===props.record?.spec.assignee_id)?[{value:props.record.spec.assignee_id,label:props.record.assignee_name+'（历史负责人）',disabled:true}]:[]),...props.assignees.map(a=>({value:a.id,label:a.name}))])
function submit(){
 if(disabled.value)return
 const value=structuredClone(toRaw(spec.value))
 if(due.value&&!Number.isFinite(Date.parse(due.value))){validation.value='请填写有效截止时间，也可留空。';revealError();return}
 value.due_at=due.value===initialDue?originalDue:due.value?new Date(due.value).toISOString():null
 if(value.status!=='completed'&&value.status!=='cancelled')value.resolution=''
 validation.value=taskSpecError(value)
 if(!validation.value&&props.editing&&(!note.value.trim()||[...note.value.trim()].length>2048))validation.value='请填写本次变更说明，最多 2048 字符。'
 if(validation.value){revealError();return}
 const incident_revision=props.draft?.incident_revision??props.parent.revision
 if(props.editing){const expected_revision=props.draft&&'expected_revision' in props.draft?props.draft.expected_revision:props.record?.revision??0;emit('save',{incident_revision,expected_revision,spec:value,note:note.value.trim()})}
 else emit('save',{incident_revision,spec:value})
}
defineExpose({submit})
</script>
<template>
 <a-form :model="spec" layout="vertical" class="task-editor" @finish="submit">
  <div v-if="validation" ref="errorPanel" tabindex="-1" role="region" aria-label="任务表单校验信息" class="section-gap"><a-alert type="error" show-icon :message="validation"/></div>
  <a-form-item label="任务标题" required><a-input v-model:value="spec.title" :disabled="disabled" :maxlength="120" aria-label="任务标题" placeholder="填写需要完成的调查工作"/></a-form-item>
  <a-form-item label="任务说明" required><a-textarea v-model:value="spec.description" :disabled="disabled" :maxlength="4096" :rows="3" aria-label="任务说明" placeholder="说明核对范围、所需材料和预期结果"/></a-form-item>
  <div class="task-form-grid">
   <a-form-item label="任务状态" required><a-select v-model:value="spec.status" :disabled="disabled||!editing" @keydown.esc.stop aria-label="任务状态" :options="Object.entries(taskStatuses).map(([value,label])=>({value,label}))"/></a-form-item>
   <a-form-item label="优先级" required><a-select v-model:value="spec.priority" :disabled="disabled" @keydown.esc.stop aria-label="任务优先级" :options="Object.entries(taskPriorities).map(([value,label])=>({value,label}))"/></a-form-item>
   <a-form-item label="任务负责人"><a-select v-model:value="spec.assignee_id" :disabled="disabled" :loading="ownerPending" @keydown.esc.stop aria-label="任务负责人" :options="owners"/></a-form-item>
   <a-form-item label="截止时间"><a-input v-model:value="due" type="datetime-local" :disabled="disabled" aria-label="任务截止时间"/><div class="muted">按本地时间填写，可留空。</div></a-form-item>
  </div>
  <a-alert v-if="ownerError" type="error" show-icon :message="ownerError" class="section-gap"><template #action><a-button size="small" :disabled="disabled" @click="emit('reloadOwners')">重新读取负责人</a-button></template></a-alert>
  <a-form-item v-if="spec.status==='completed'||spec.status==='cancelled'" :label="spec.status==='completed'?'完成依据':'取消原因'" required><a-textarea v-model:value="spec.resolution" :disabled="disabled" :rows="3" :maxlength="2048" :aria-label="spec.status==='completed'?'完成依据':'取消原因'"/></a-form-item>
  <a-form-item v-if="editing" label="变更说明" required><a-textarea v-model:value="note" :disabled="disabled" :rows="2" :maxlength="2048" aria-label="任务变更说明"/></a-form-item>
 </a-form>
</template>
<style scoped>.task-form-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:0 var(--related-gap)}.task-editor :deep(.ant-form-item){min-width:0}@media(max-width:700px){.task-form-grid{grid-template-columns:minmax(0,1fr)}}</style>
