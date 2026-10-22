<script setup lang="ts">
import {computed,nextTick,ref,toRaw} from 'vue'
import {Select as ASelect} from 'ant-design-vue'
import type {IncidentRecord} from './incident'
import {newNoteSpec,noteSpecError,noteStatuses,type IncidentNoteInput,type IncidentNoteRecord} from './incidentNote'

const props=defineProps<{parent:IncidentRecord;record:IncidentNoteRecord|null;editing:boolean;draft?:IncidentNoteInput;busy:boolean;unconfirmed:boolean}>()
const emit=defineEmits<{save:[input:IncidentNoteInput]}>()
const spec=ref(structuredClone(toRaw(props.draft?.spec??props.record?.spec??newNoteSpec())))
const reason=ref(props.draft&&'reason' in props.draft?props.draft.reason:'')
const validation=ref(''),errorPanel=ref<HTMLDivElement|null>(null)
const disabled=computed(()=>props.busy||props.unconfirmed||props.parent.spec.status==='closed')
function submit(){
 if(disabled.value)return
 const value=structuredClone(toRaw(spec.value))
 if(value.status==='active')value.withdrawal_reason=''
 validation.value=noteSpecError(value)
 if(!validation.value&&props.editing&&(!reason.value.trim()||[...reason.value.trim()].length>2048||/\p{Cc}/u.test(reason.value.replace(/[\n\t]/g,''))))validation.value='请填写本次变更说明，最多 2048 字符。'
 if(validation.value){void nextTick(()=>errorPanel.value?.focus());return}
 const incident_revision=props.draft?.incident_revision??props.parent.revision
 if(props.editing)emit('save',{incident_revision,expected_revision:props.draft&&'expected_revision' in props.draft?props.draft.expected_revision:props.record?.revision??0,spec:value,reason:reason.value.trim()})
 else emit('save',{incident_revision,spec:value})
}
defineExpose({submit})
</script>
<template>
 <a-form :model="spec" layout="vertical" class="note-editor" @finish="submit">
  <div v-if="validation" ref="errorPanel" tabindex="-1" role="region" aria-label="笔记表单校验信息" class="section-gap"><a-alert type="error" show-icon :message="validation"/></div>
  <a-form-item label="笔记标题" required><a-input v-model:value="spec.title" :disabled="disabled" :maxlength="120" aria-label="笔记标题" placeholder="概括本次核对内容"/></a-form-item>
  <a-form-item label="笔记正文" required><a-textarea v-model:value="spec.body" :disabled="disabled" :maxlength="8192" :rows="7" aria-label="笔记正文" placeholder="记录已观察事实、来源标识及尚未确认的问题"/><div class="muted">仅保存纯文本。请勿填写口令、令牌或不必要的敏感信息。</div></a-form-item>
  <a-form-item label="笔记状态" required><a-select v-model:value="spec.status" :disabled="disabled||!editing" @keydown.esc.stop aria-label="笔记状态" :options="Object.entries(noteStatuses).map(([value,label])=>({value,label}))"/></a-form-item>
  <a-form-item v-if="spec.status==='withdrawn'" label="撤回原因" required><a-textarea v-model:value="spec.withdrawal_reason" :disabled="disabled" :rows="3" :maxlength="2048" aria-label="笔记撤回原因"/><div class="muted">撤回后仍保留原正文与修订历史。</div></a-form-item>
  <a-form-item v-if="editing" label="变更说明" required><a-textarea v-model:value="reason" :disabled="disabled" :rows="2" :maxlength="2048" aria-label="笔记变更说明"/></a-form-item>
 </a-form>
</template>
<style scoped>.note-editor :deep(.ant-form-item){min-width:0}.note-editor .muted{overflow-wrap:anywhere}</style>
