<script setup lang="ts">
import {computed,nextTick,reactive,ref,watch} from 'vue'
import {Modal as AModal,Select as ASelect,InputNumber as AInputNumber} from 'ant-design-vue'
import {correlationChangeError,correlationFields,emptyCorrelationDefinition,definitionShape,type CorrelationChange,type CorrelationRule} from '../correlation'
const props=defineProps<{record:CorrelationRule|null;draft?:CorrelationChange;busy:boolean;unconfirmed:boolean;error:string}>()
const emit=defineEmits<{save:[input:CorrelationChange];confirm:[];close:[]}>()
const source=props.draft??props.record,identifier=source?.id??'corr_'+crypto.randomUUID().replaceAll('-','')
const expected=props.draft?.expected_revision??props.record?.revision??0
const form=reactive({name:source?.name??'',description:source?.description??'',active:source?.active??true,definition:definitionShape(source?.definition??emptyCorrelationDefinition())})
const localError=ref(''),errorPanel=ref<HTMLDivElement|null>(null),locked=computed(()=>props.busy||props.unconfirmed)
const groupOptions=['source.ip','destination.ip','rule.id'].map(value=>({value,label:correlationFields[value]}))
const distinctOptions=computed(()=>Object.entries(correlationFields).filter(([key])=>key!==form.definition.group_by).map(([value,label])=>({value,label})))
watch(()=>[form.definition.metric,form.definition.group_by],()=>{if(form.definition.metric==='count')form.definition.distinct_field='';else if(!distinctOptions.value.some(v=>v.value===form.definition.distinct_field))form.definition.distinct_field=distinctOptions.value[0]!.value})
async function submit(){
 if(locked.value)return
 const input:CorrelationChange={id:identifier,expected_revision:expected,name:form.name.trim(),description:form.description.trim(),active:form.active,definition:definitionShape(form.definition)}
 localError.value=correlationChangeError(input)
 if(localError.value){await nextTick();errorPanel.value?.focus();return}
 emit('save',input)
}
</script>
<template>
 <a-modal :open="true" :title="expected?'编辑关联规则':'创建关联规则'" :width="760" :body-style="{maxHeight:'calc(100vh - 240px)',overflowY:'auto'}" :mask-closable="false" :closable="!busy" :keyboard="!busy" @cancel="emit('close')">
  <a-alert type="info" show-icon message="规则用于已有告警的窗口回测。保存不会启用实时关联，不生成告警或设备动作。" class="section-gap"/>
  <a-alert v-if="unconfirmed" type="warning" show-icon message="上次提交结果尚未确认，字段已锁定，请核对原提交。" class="section-gap"/>
  <div v-if="localError||error" ref="errorPanel" role="region" aria-label="关联规则校验信息" tabindex="-1" class="section-gap"><a-alert type="error" show-icon :message="error||localError"/></div>
  <a-form layout="vertical" :disabled="locked" :model="form" @finish="submit">
   <div class="correlation-form-grid">
    <a-form-item label="规则名称" html-for="correlation-name" required><a-input id="correlation-name" v-model:value="form.name" :maxlength="128" autocomplete="off"/></a-form-item>
    <a-form-item label="回测状态" html-for="correlation-active"><a-select id="correlation-active" :value="String(form.active)" :options="[{value:'true',label:'允许回测'},{value:'false',label:'停用'}]" @update:value="form.active=$event==='true'" @keydown.esc.stop/></a-form-item>
    <a-form-item label="分组字段" html-for="correlation-group" required><a-select id="correlation-group" v-model:value="form.definition.group_by" :options="groupOptions" @keydown.esc.stop/></a-form-item>
    <a-form-item label="计量方式" html-for="correlation-metric"><a-select id="correlation-metric" v-model:value="form.definition.metric" :options="[{value:'count',label:'唯一告警条数'},{value:'distinct',label:'不同值数量'}]" @keydown.esc.stop/></a-form-item>
    <a-form-item v-if="form.definition.metric==='distinct'" label="不同值字段" html-for="correlation-distinct" required><a-select id="correlation-distinct" v-model:value="form.definition.distinct_field" :options="distinctOptions" @keydown.esc.stop/></a-form-item>
    <a-form-item label="窗口时长（秒）" html-for="correlation-window" required><a-input-number id="correlation-window" v-model:value="form.definition.window_seconds" :min="15" :max="3600" :precision="0" style="width:100%"/></a-form-item>
    <a-form-item label="触发阈值" html-for="correlation-threshold" required><a-input-number id="correlation-threshold" v-model:value="form.definition.threshold" :min="2" :max="5000" :precision="0" style="width:100%"/></a-form-item>
   </div>
   <a-form-item label="告警过滤条件" html-for="correlation-filter" extra="使用告警高级检索语法，例如 ip.src == 192.0.2.1；留空表示范围内全部告警。"><a-textarea id="correlation-filter" v-model:value="form.definition.filter" :maxlength="4096" :auto-size="{minRows:2,maxRows:5}" placeholder="例如 ip.src == 192.0.2.1" class="technical"/></a-form-item>
   <a-form-item label="维护说明" html-for="correlation-description"><a-textarea id="correlation-description" v-model:value="form.description" :maxlength="1000" :auto-size="{minRows:2,maxRows:4}" placeholder="说明使用场景、字段依据与阈值选择"/></a-form-item>
   <p class="page-description">分组始终隔离探针和注册代次。窗口按 UTC 固定边界划分，单次最多回测一小时、5000 条告警和 512 个分组；字段缺失及边界窗口单独标记。</p>
  </a-form>
  <template #footer><a-button :disabled="busy" @click="emit('close')">关闭</a-button><a-button v-if="unconfirmed" type="primary" :loading="busy" @click="emit('confirm')">核对原提交</a-button><a-button v-else type="primary" :loading="busy" :disabled="locked" @click="submit">保存规则</a-button></template>
 </a-modal>
</template>
<style scoped>.correlation-form-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));column-gap:12px}@media(max-width:700px){.correlation-form-grid{grid-template-columns:minmax(0,1fr)}}</style>
