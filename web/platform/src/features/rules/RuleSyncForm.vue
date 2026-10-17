<script setup lang="ts">
import {computed,reactive,shallowRef,watch} from 'vue'
import {Modal as AModal,Select as ASelect,Switch as ASwitch,InputNumber as AInputNumber} from 'ant-design-vue'
import type {RulePackage,Sensor} from '@starbeacon/shared/types.ts'
import {syncInputError,type RuleSyncChange,type RuleSyncPlan} from './sync'
const props=defineProps<{plan:RuleSyncPlan|null;sensors:Sensor[];packages:RulePackage[];busy:boolean;locked:boolean;error:string;choicesError:string;choicesPending:boolean}>()
const emit=defineEmits<{save:[value:RuleSyncChange];close:[];confirm:[]}>()
const form=reactive<RuleSyncChange>(props.plan?{id:props.plan.id,expected_revision:props.plan.revision,spec:{...props.plan.spec}}:{id:'sync_'+crypto.randomUUID().replaceAll('-',''),expected_revision:0,spec:{name:'',enabled:false,sensor_id:'',registration_id:'',package_id:'',package_revision:1,positive_sample_id:'',negative_sample_id:'',interval_seconds:60}})
const localError=shallowRef('')
watch(form,()=>{localError.value=''})
const sensorOptions=computed(()=>props.sensors.map(s=>({value:s.id,label:`${s.name} · ${s.id}`,disabled:!s.active})))
const packageOptions=computed(()=>props.packages.map(p=>({value:p.id,label:`${p.name} · 最新修订 ${p.revision}`})))
const inFlight=computed(()=>props.plan?.run&&!props.plan.run.finished_at)
const currentSensor=computed(()=>props.sensors.find(s=>s.id===form.spec.sensor_id))
function chooseSensor(id:unknown){form.spec.registration_id=props.sensors.find(s=>s.id===id)?.registration_id??''}
function choosePackage(id:unknown){form.spec.package_revision=props.packages.find(p=>p.id===id)?.revision??1}
function submit(){if(props.busy||props.locked||props.choicesPending||props.choicesError)return;localError.value=syncInputError(form);if(!localError.value)emit('save',structuredClone({...form,spec:{...form.spec}}))}
</script>
<template>
 <a-modal open :title="plan?'规则同步计划':'创建规则同步计划'" :width="760" :closable="!busy" :keyboard="!busy" :mask-closable="false" @cancel="emit('close')">
  <a-alert type="info" show-icon message="授权仅适用于指定规则修订和探针注册代次。系统逐步执行装载检查、正反样本重放及发布，不跟随未批准修订。" class="section-gap" />
  <a-alert v-if="error||localError||choicesError" type="error" show-icon :message="error||localError||choicesError" role="alert" class="section-gap" />
  <a-alert v-if="inFlight" type="warning" show-icon message="存在在途任务。可停用原计划以停止后续步骤；已经下发的任务仍需等待独立回执。" class="section-gap" />
  <a-form layout="vertical" :disabled="busy||locked||choicesPending" @submit.prevent="submit">
   <div class="sync-form-grid">
    <a-form-item label="计划名称" required><a-input v-model:value="form.spec.name" :maxlength="128" :disabled="!!inFlight" aria-label="计划名称" /></a-form-item>
    <a-form-item label="计划状态"><a-switch v-model:checked="form.spec.enabled" checked-children="启用" un-checked-children="停用" :disabled="!!inFlight&&!plan?.spec.enabled" /></a-form-item>
    <a-form-item label="目标探针" required><a-select v-model:value="form.spec.sensor_id" :options="sensorOptions" :disabled="!!plan" show-search option-filter-prop="label" placeholder="选择目标探针" @change="chooseSensor" @keydown.esc.stop /></a-form-item>
    <a-form-item label="批准的注册代次"><div class="sync-identity"><a-input v-model:value="form.spec.registration_id" readonly aria-label="批准的注册代次" /><a-button v-if="plan&&!inFlight" :disabled="busy||locked||!currentSensor?.active" @click="chooseSensor(form.spec.sensor_id)">使用当前代次</a-button></div><p v-if="currentSensor&&currentSensor.registration_id!==form.spec.registration_id" class="field-hint">探针注册代次已变化，请核对设备身份后重新批准。旧任务与数据归属不会随本计划迁移。</p></a-form-item>
    <a-form-item label="规则包" required><a-select v-model:value="form.spec.package_id" :options="packageOptions" :disabled="!!inFlight" show-search option-filter-prop="label" placeholder="选择规则包" @change="choosePackage" @keydown.esc.stop /></a-form-item>
    <a-form-item label="批准的规则修订" required><a-input-number v-model:value="form.spec.package_revision" :min="1" :precision="0" :disabled="!!inFlight" aria-label="批准的规则修订" class="full-width" /></a-form-item>
    <a-form-item label="正样本标识" required><a-input v-model:value="form.spec.positive_sample_id" :disabled="!!inFlight" placeholder="填写已导入的正样本 ID" aria-label="正样本标识" /></a-form-item>
    <a-form-item label="反样本标识" required><a-input v-model:value="form.spec.negative_sample_id" :disabled="!!inFlight" placeholder="填写已导入的反样本 ID" aria-label="反样本标识" /></a-form-item>
    <a-form-item label="核对周期（秒）" required><a-input-number v-model:value="form.spec.interval_seconds" :min="30" :max="3600" :precision="0" :disabled="!!inFlight" aria-label="核对周期" class="full-width" /></a-form-item>
   </div>
   <p class="field-hint">从重放样本页复制样本标识。正样本需产生告警，反样本不得产生告警；两份样本的实际内容必须不同。核对周期不构成检测或发布时延承诺。</p>
  </a-form>
  <template #footer><div class="sync-form-actions"><a-button :disabled="busy" @click="emit('close')">关闭</a-button><a-button v-if="locked" type="primary" :loading="busy" @click="emit('confirm')">核对原提交</a-button><a-button v-else type="primary" :loading="busy" :disabled="choicesPending||!!choicesError" @click="submit">保存计划</a-button></div></template>
 </a-modal>
</template>
<style scoped>
.sync-form-grid{display:grid;grid-template-columns:minmax(0,1fr) minmax(0,1fr);column-gap:16px}.full-width{width:100%}.sync-identity{display:flex;gap:8px}.sync-identity>.ant-input{min-width:0}.sync-form-actions{display:flex;justify-content:flex-end;flex-wrap:wrap;gap:8px}@media(max-width:640px){.sync-form-grid{grid-template-columns:minmax(0,1fr)}}
</style>
