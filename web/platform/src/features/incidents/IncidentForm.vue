<script setup lang="ts">
import {computed,nextTick,reactive,ref,toRaw,watch} from 'vue'
import {Modal as AModal,Select as ASelect} from 'ant-design-vue'
import {incidentCategories,incidentSeverities,incidentStatuses,newIncidentSpec,incidentSpecError,validIncidentRef,type IncidentRecord,type IncidentAssignee,type IncidentInput,type IncidentSpec,type IncidentRef} from './incident'
const props=defineProps<{record:IncidentRecord|null;assignees:readonly IncidentAssignee[];assigneePending:boolean;assigneeError:string;busy:boolean;unconfirmed:boolean;error:string;linkedId?:string;draft?:IncidentInput;seed?:IncidentRef}>()
const emit=defineEmits<{save:[input:IncidentInput];confirm:[];close:[];reloadOwners:[];existing:[id:string]}>()
const errorPanel=ref<HTMLDivElement|null>(null)
function revealError(){void nextTick(()=>errorPanel.value?.focus())}
watch(()=>props.error,value=>{if(value)revealError()},{flush:'post'})
const spec=reactive<IncidentSpec>(structuredClone(toRaw(props.draft?.spec??props.record?.spec??newIncidentSpec())))
const change=props.draft&&'expected_revision' in props.draft?props.draft:undefined
const note=ref(change?.note??''),eventID=ref(props.seed?.event_id??''),rawSHA=ref(props.seed?.raw_sha256??''),localError=ref(''),evidence=ref(spec.closure?.evidence.join('\n')??'')
const frozenRefs=props.draft?('alerts' in props.draft?props.draft.alerts:props.draft.add_alerts):undefined
if(frozenRefs?.[0]){eventID.value=frozenRefs[0].event_id;rawSHA.value=frozenRefs[0].raw_sha256}
const locked=computed(()=>props.busy||props.unconfirmed),editing=computed(()=>props.record!==null||!!change)
const title=computed(()=>editing.value?'记录调查':'建立事件')
function setStatus(value:unknown){
 if(value==='closed')spec.closure??={reason:'resolved',root_cause:'',impact:'',remediation:'',verification:'',evidence:[]}
 else spec.closure=null
}
function submit(){
 const value=structuredClone(toRaw(spec));if(value.closure)value.closure.evidence=evidence.value.split('\n').map(v=>v.trim()).filter(Boolean)
 localError.value=incidentSpecError(value);if(localError.value){revealError();return}
 const refs:IncidentRef[]=eventID.value||rawSHA.value?[{event_id:eventID.value.trim(),raw_sha256:rawSHA.value.trim()}]:[]
 if(refs.some(v=>!validIncidentRef(v))){localError.value='关联告警必须同时提供有效标识和小写 SHA-256 摘要。';revealError();return}
 if(props.record?.alerts.some(a=>refs.some(r=>r.event_id===a.event_id))){localError.value='该告警已在当前事件中，请核对既有关联。';revealError();return}
 if(editing.value&&(!note.value.trim()||[...note.value.trim()].length>2048)){localError.value='请填写本次调查说明，最多 2048 字符。';revealError();return}
 const input:IncidentInput=editing.value?{expected_revision:change?.expected_revision??props.record!.revision,spec:value,note:note.value.trim(),add_alerts:refs}:{spec:value,alerts:refs}
 emit('save',input)
}
</script>
<template>
 <a-modal :open="true" :title="title" :width="880" :footer="null" :closable="!busy" :keyboard="!busy" :mask-closable="!busy" @cancel="emit('close')">
  <a-alert show-icon type="info" message="调查结论属于人工记录，不改写原始告警，也不代表设备已完成封禁。结案需保留可复核的材料。" class="section-gap"/>
  <a-alert v-if="unconfirmed" show-icon type="warning" message="上次提交结果尚未确认。字段已锁定，请使用原请求核对，避免重复建立或覆盖调查。" class="section-gap"/>
  <div v-if="localError||error" ref="errorPanel" tabindex="-1" role="region" aria-label="调查表单校验信息" class="section-gap"><a-alert show-icon type="error" :message="localError||error"/></div>
  <a-button v-if="linkedId" class="section-gap" @click="emit('existing',linkedId)">查看既有调查</a-button>
  <a-alert v-if="assigneeError" show-icon type="error" :message="assigneeError" class="section-gap"><template #action><a-button size="small" :disabled="locked" @click="emit('reloadOwners')">重试责任人</a-button></template></a-alert>
  <a-form :model="spec" layout="vertical" :disabled="locked" @finish="submit">
   <a-form-item label="事件标题" html-for="incident-title" required><a-input id="incident-title" v-model:value="spec.title" :maxlength="120"/></a-form-item>
   <div class="incident-form-grid">
    <a-form-item label="事件分类" html-for="incident-category" required><a-select id="incident-category" v-model:value="spec.category" :options="Object.entries(incidentCategories).map(([value,label])=>({value,label}))" @keydown.esc.stop/></a-form-item>
    <a-form-item label="严重度" html-for="incident-severity" required><a-select id="incident-severity" v-model:value="spec.severity" :options="Object.entries(incidentSeverities).map(([value,label])=>({value,label}))" @keydown.esc.stop/></a-form-item>
    <a-form-item label="调查状态" html-for="incident-status" required><a-select id="incident-status" v-model:value="spec.status" :disabled="!editing||locked" :options="Object.entries(incidentStatuses).filter(([value])=>record?.spec.status!=='closed'||value!=='open').map(([value,label])=>({value,label}))" @change="setStatus" @keydown.esc.stop/></a-form-item>
    <a-form-item label="责任人" html-for="incident-owner" :required="spec.status==='closed'"><a-select id="incident-owner" v-model:value="spec.owner_id" :loading="assigneePending" :disabled="locked||assigneePending||!!assigneeError" :options="[{value:'',label:'待分派'},...assignees.map(a=>({value:a.id,label:a.name}))]" @keydown.esc.stop/></a-form-item>
   </div>
   <a-form-item label="事件概述" html-for="incident-summary" required><a-textarea id="incident-summary" v-model:value="spec.summary" :maxlength="4096" :rows="3"/></a-form-item>
   <div class="incident-form-grid">
    <a-form-item :label="editing?'关联其他告警标识':'关联告警标识'" html-for="incident-event"><a-input id="incident-event" v-model:value="eventID" :maxlength="64" placeholder="可留空，建立人工线索调查"/></a-form-item>
    <a-form-item label="告警原始 SHA-256" html-for="incident-sha"><a-input id="incident-sha" v-model:value="rawSHA" :maxlength="64" placeholder="与实际告警摘要一致"/></a-form-item>
   </div>
   <p class="muted incident-hint">告警来源由服务端核验。同一告警只关联一份调查；界面每次可关联一条，单事件最多 16 条。</p>
   <a-form-item v-if="editing" label="本次调查说明" html-for="incident-note" required><a-textarea id="incident-note" v-model:value="note" :rows="3" :maxlength="2048"/></a-form-item>
   <template v-if="spec.closure">
    <h3>结案材料</h3>
    <a-form-item label="结案原因" html-for="incident-close-reason" required><a-select id="incident-close-reason" v-model:value="spec.closure.reason" :options="[{value:'resolved',label:'确认处置完成'},{value:'false_positive',label:'确认误报'}]" @keydown.esc.stop/></a-form-item>
    <div class="incident-form-grid">
     <a-form-item label="根因说明" html-for="incident-root" required><a-textarea id="incident-root" v-model:value="spec.closure.root_cause" :rows="3" :maxlength="2048"/></a-form-item>
     <a-form-item label="影响范围" html-for="incident-impact" required><a-textarea id="incident-impact" v-model:value="spec.closure.impact" :rows="3" :maxlength="2048"/></a-form-item>
     <a-form-item label="修复措施" html-for="incident-remediation" required><a-textarea id="incident-remediation" v-model:value="spec.closure.remediation" :rows="3" :maxlength="2048"/></a-form-item>
     <a-form-item label="复测说明" html-for="incident-verification" required><a-textarea id="incident-verification" v-model:value="spec.closure.verification" :rows="3" :maxlength="2048"/></a-form-item>
    </div>
    <a-form-item label="复测证据引用" html-for="incident-evidence" :required="spec.closure.reason==='resolved'"><a-textarea id="incident-evidence" v-model:value="evidence" :rows="3" :maxlength="2055" placeholder="每行一条，最多 8 条；填写可复核的测试或证据定位"/></a-form-item>
   </template>
   <div class="incident-form-actions"><a-button :disabled="busy" @click="emit('close')">关闭</a-button><a-button v-if="unconfirmed" type="primary" :loading="busy" :disabled="busy" @click="emit('confirm')">核对原提交</a-button><a-button v-else type="primary" html-type="submit" :loading="busy" :disabled="busy||assigneePending||!!assigneeError">{{editing?'提交调查':'建立事件'}}</a-button></div>
  </a-form>
 </a-modal>
</template>
<style scoped>.incident-form-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:0 var(--related-gap)}.incident-form-actions{display:flex;gap:var(--related-gap);justify-content:flex-end;flex-wrap:wrap}.incident-hint{font-size:12px;margin:-8px 0 12px;overflow-wrap:anywhere}@media(max-width:700px){.incident-form-grid{grid-template-columns:minmax(0,1fr)}}</style>
