<script setup lang="ts">
import {computed,reactive,shallowRef,watch} from 'vue'
import {Modal as AModal,Select as ASelect,InputNumber as AInputNumber,Checkbox as ACheckbox} from 'ant-design-vue'
import type {RuleSyncPlan} from './sync'
import {rolloutInputError,type RolloutCreate} from './rollout'
const props=defineProps<{plans:RuleSyncPlan[];userId:string;busy:boolean;locked:boolean;error:string;plansPending:boolean;plansError:string;hasMore:boolean}>()
const emit=defineEmits<{save:[input:RolloutCreate];confirm:[];close:[];more:[];retry:[]}>()
const selected=shallowRef<string[]>([]),approved=shallowRef(false),localError=shallowRef('')
const form=reactive({id:'rollout_'+crypto.randomUUID().replaceAll('-',''),name:'',canary_count:1,batch_size:10,observation_seconds:60,timeout_seconds:3600})
const options=computed(()=>props.plans.map(p=>({value:p.id,label:`${p.spec.name} · ${p.spec.sensor_id} · 规则修订 ${p.spec.package_revision}`,disabled:p.created_by!==props.userId||p.spec.enabled||!!p.run&&!p.run.finished_at})))
const choices=computed(()=>selected.value.map(id=>props.plans.find(p=>p.id===id)).filter((p):p is RuleSyncPlan=>!!p))
const common=computed(()=>{const a=choices.value[0]?.spec;return !a||choices.value.every(p=>p.spec.package_id===a.package_id&&p.spec.package_revision===a.package_revision&&p.spec.positive_sample_id===a.positive_sample_id&&p.spec.negative_sample_id===a.negative_sample_id)})
watch([form,selected,approved],()=>{localError.value=''})
function submit(){
 if(props.busy||props.locked||props.plansPending||props.plansError)return
 const input:RolloutCreate={id:form.id,spec:{name:form.name,plans:choices.value.map(p=>({plan_id:p.id,revision:p.revision})),canary_count:form.canary_count,batch_size:form.batch_size,observation_seconds:form.observation_seconds,timeout_seconds:form.timeout_seconds}}
 localError.value=rolloutInputError(input)
 if(!localError.value&&!common.value)localError.value='所选计划必须使用相同规则包修订和正反样本'
 if(!localError.value&&!approved.value)localError.value='请确认固定范围的分批发布授权'
 if(!localError.value)emit('save',structuredClone(input))
}
</script>
<template>
 <a-modal open title="创建分批发布" :width="800" :closable="!busy" :keyboard="!busy" :mask-closable="false" @cancel="emit('close')">
  <a-alert type="info" show-icon message="先配置停用的单探针同步计划。每个目标独立完成装载、正反样本及发布；首批按选择顺序确定。" class="section-gap" />
  <a-alert v-if="error||localError||plansError" type="error" show-icon :message="error||localError||plansError" class="section-gap" role="alert"><template v-if="plansError" #action><a-button :disabled="busy||locked" @click="emit('retry')">重试读取</a-button></template></a-alert>
  <a-form layout="vertical" :disabled="busy||locked" @submit.prevent="submit">
   <a-form-item label="发布名称" required><a-input v-model:value="form.name" :maxlength="128" aria-label="发布名称" /></a-form-item>
   <a-form-item label="目标同步计划" html-for="rollout-target-plans" required><a-select id="rollout-target-plans" v-model:value="selected" mode="multiple" :max-tag-count="3" :options="options" :loading="plansPending" show-search option-filter-prop="label" placeholder="按执行顺序选择至少两个停用计划" aria-label="目标同步计划" @keydown.esc.stop /><div class="rollout-choice-footer"><span class="field-hint">已读取 {{plans.length}} 个计划，已选择 {{selected.length}} 个。仅可选择本人批准且没有在途任务的停用计划。</span><a-button v-if="hasMore" :loading="plansPending" :disabled="busy||locked" @click="emit('more')">加载更多计划</a-button></div></a-form-item>
   <a-alert v-if="!common" type="warning" show-icon message="所选计划的规则或正反样本不同，请统一后再提交。" class="section-gap" />
   <div class="rollout-form-grid">
    <a-form-item label="首批探针数" required><a-input-number v-model:value="form.canary_count" :min="1" :max="20" :precision="0" aria-label="首批探针数" /></a-form-item>
    <a-form-item label="后续每批探针数" required><a-input-number v-model:value="form.batch_size" :min="1" :max="20" :precision="0" aria-label="后续每批探针数" /></a-form-item>
    <a-form-item label="批次观察时间（秒）" required><a-input-number v-model:value="form.observation_seconds" :min="30" :max="3600" :precision="0" aria-label="批次观察时间" /></a-form-item>
    <a-form-item label="执行期限（秒）" required><a-input-number v-model:value="form.timeout_seconds" :min="300" :max="86400" :precision="0" aria-label="执行期限" /></a-form-item>
   </div>
   <div v-if="choices.length" class="rollout-order" aria-label="冻结目标顺序"><ol><li v-for="(p,index) in choices" :key="p.id"><span>{{p.spec.name}}</span><small>{{index<form.canary_count?'首批':'第 '+(2+Math.floor((index-form.canary_count)/form.batch_size))+' 批'}} · {{p.spec.sensor_id}} · 授权修订 {{p.revision}}</small></li></ol></div>
   <p class="field-hint">观察时间从该批发布回执完成后的新心跳开始，还需窗口结束后的心跳核对实际规则摘要。失败、结果未知或达到期限会停止后续提交；已执行规则不会自动回滚。</p>
   <a-checkbox v-model:checked="approved">批准所选固定计划修订按上述范围逐批验证与发布，允许平台启用对应计划。</a-checkbox>
  </a-form>
  <template #footer><a-button :disabled="busy" @click="emit('close')">关闭</a-button><a-button v-if="locked" type="primary" :loading="busy" @click="emit('confirm')">核对原提交</a-button><a-button v-else type="primary" :loading="busy" :disabled="plansPending||!!plansError" @click="submit">批准并启动</a-button></template>
 </a-modal>
</template>
<style scoped>
.rollout-form-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:0 16px}.rollout-form-grid .ant-input-number{width:100%}.rollout-choice-footer{display:flex;align-items:center;justify-content:space-between;gap:8px;flex-wrap:wrap;margin-top:8px}.rollout-order{max-height:160px;overflow:auto;border:1px solid var(--line);border-radius:8px;margin-bottom:12px;padding:8px 12px}.rollout-order ol{margin:0;padding-left:22px}.rollout-order li{padding:4px;overflow-wrap:anywhere}.rollout-order small{display:block;color:var(--muted)}@media(max-width:640px){.rollout-form-grid{grid-template-columns:minmax(0,1fr)}}
</style>
