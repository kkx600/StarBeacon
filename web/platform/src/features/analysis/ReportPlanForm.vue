<script setup lang="ts">
import {computed,reactive,watch} from 'vue'
import {Modal,Select,Switch,Checkbox} from 'ant-design-vue'
import type {ModelProvider} from '../models/models'
import {validPlanSpec,type ReportPlan,type ReportPlanSpec,type ReportPlanChange} from './plans'
const props=defineProps<{record:ReportPlan|null;providers:readonly ModelProvider[];available:boolean;modelsAvailable:boolean;busy:boolean;error:string;unconfirmed:boolean}>()
const emit=defineEmits<{save:[change:ReportPlanChange];close:[];confirm:[]}>()
const id=props.record?.id??'plan_'+crypto.randomUUID().replaceAll('-',''),revision=props.record?.revision??0
const draft=reactive<ReportPlanSpec>(props.record?{...props.record.spec,allow_context:false}:{name:'',kind:'daily',timezone:'Asia/Shanghai',at:'09:00',enabled:props.available,provider_id:'',provider_revision:0,allow_context:false})
const providers=computed(()=>props.providers.filter(p=>p.enabled)),current=computed(()=>providers.value.find(p=>p.id===draft.provider_id))
watch(()=>draft.provider_id,()=>{draft.allow_context=false;draft.provider_revision=current.value?.revision??0})
watch(()=>current.value?.revision,revision=>{draft.allow_context=false;draft.provider_revision=revision??0},{immediate:true})
const allowed=computed(()=>{const spec={...draft,provider_revision:draft.provider_id?current.value?.revision??0:0,allow_context:draft.provider_id?draft.allow_context:false};return validPlanSpec(spec)&&(!draft.enabled||props.available)&&(!draft.enabled||!draft.provider_id||props.modelsAvailable)})
function save(){if(props.busy||props.unconfirmed||!allowed.value)return;emit('save',{id,expected_revision:revision,spec:{...draft,provider_revision:draft.provider_id?current.value!.revision:0,allow_context:draft.provider_id?draft.allow_context:false}})}
</script>
<template>
 <Modal :open="true" :title="record?'配置报告计划':'创建报告计划'" :width="640" :footer="null" :closable="!busy&&!unconfirmed" :mask-closable="false" :keyboard="!busy&&!unconfirmed" @cancel="emit('close')">
  <a-alert v-if="error" type="error" :message="error" show-icon class="section-gap"/>
  <a-alert v-if="unconfirmed" type="warning" message="保存结果尚未确认，请确认原请求后继续。" show-icon class="section-gap"/>
  <a-alert v-if="!available" type="info" message="计划执行服务暂不可用，可保存停用计划。" show-icon class="section-gap"/>
  <a-form layout="vertical" :disabled="busy||unconfirmed" @finish="save">
   <a-form-item label="计划名称"><a-input v-model:value="draft.name" aria-label="计划名称" :maxlength="80" placeholder="例如：集团安全日报"/></a-form-item>
   <div class="plan-fields"><a-form-item label="报告类型"><Select v-model:value="draft.kind" aria-label="计划报告类型" :options="[{value:'daily',label:'安全日报'},{value:'weekly',label:'安全周报'},{value:'monthly',label:'安全月报'}]"/></a-form-item><a-form-item label="执行时间"><input v-model="draft.at" type="time" aria-label="计划执行时间" class="plan-clock" :disabled="busy||unconfirmed" step="60"></a-form-item></div>
   <a-form-item label="报告时区"><a-input v-model:value="draft.timezone" aria-label="计划报告时区" :maxlength="128" placeholder="Asia/Shanghai"/></a-form-item>
   <p class="muted section-gap">日报每天执行，周报在周一执行，月报在每月第一天执行，生成前一完整自然周期。夏令时重复时刻取首次，跳过时刻顺延至当日首个有效分钟。</p>
   <a-form-item label="智能总结"><Select v-model:value="draft.provider_id" aria-label="计划报告模型" :options="[{value:'',label:'仅生成统计报告'},...providers.map(p=>({value:p.id,label:`${p.name} · 修订 ${p.revision}`,disabled:!modelsAvailable&&draft.enabled}))]"/></a-form-item>
   <a-alert v-if="draft.provider_id&&!current" type="warning" message="计划绑定的模型当前不可用，请选择启用的模型或仅生成统计报告。" show-icon class="section-gap"/>
   <Checkbox v-if="draft.provider_id" v-model:checked="draft.allow_context" :disabled="busy||unconfirmed">允许该计划修订持续使用周期统计调用所选模型</Checkbox>
   <p v-if="draft.provider_id" class="muted section-gap">模型调用可能计费，使用固定模型修订及共享日额度。模型配置变化时暂停该周期调用，需重新配置计划并授权。</p>
   <a-form-item label="计划状态"><Switch v-model:checked="draft.enabled" aria-label="启用报告计划" :disabled="busy||unconfirmed||!available&&!draft.enabled" checked-children="启用" un-checked-children="停用"/></a-form-item>
   <p class="muted section-gap">停机恢复时只生成最近完整周期，错过的槽位范围可在运行记录中核对。停用计划不会取消已提交的报告；报告不会自动发布或通知他人。</p>
  </a-form>
  <div class="filter-actions plan-actions"><a-button :disabled="busy||unconfirmed" @click="emit('close')">取消</a-button><a-button type="primary" :loading="busy" :disabled="busy||!unconfirmed&&!allowed" @click="unconfirmed?emit('confirm'):save()">{{unconfirmed?'确认保存结果':'保存计划'}}</a-button></div>
 </Modal>
</template>
<style scoped>.plan-fields{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:var(--related-gap)}.plan-clock{width:100%;min-height:32px;border:1px solid var(--line);border-radius:6px;padding:4px 10px;background:var(--surface);color:var(--text);font:inherit}.plan-clock:focus{outline:2px solid var(--primary);outline-offset:2px}.plan-clock:disabled{background:var(--control-disabled);color:var(--muted)}.plan-actions{justify-content:flex-end;margin-top:var(--section-gap)}@media(max-width:640px){.plan-fields{grid-template-columns:1fr;gap:0}}</style>
