<script setup lang="ts">
import { computed,reactive,ref,watch } from 'vue'
import { message } from 'ant-design-vue'
import type {FormInstance} from 'ant-design-vue'
import type {BusinessRecord,FieldSpec,PageSpec} from '../models'
import {formValueFor} from '../composables/formValues'
const props=defineProps<{open:boolean;page:PageSpec;record?:BusinessRecord}>()
const emit=defineEmits<{close:[];save:[values:Record<string,unknown>]}>()
const formRef=ref<FormInstance>();const values=reactive<Record<string,unknown>>({});const busy=ref(false)
const exportMode=computed(()=>props.page.actionMode==='export')
const fields=computed<FieldSpec[]>(()=>exportMode.value?[
  {key:'range',label:'导出范围',type:'select',required:true,value:'当前筛选快照',options:['当前筛选快照','已选记录']},
  {key:'format',label:'文件格式',type:'select',required:true,value:'CSV',options:['CSV','JSON']},
  {key:'reason',label:'使用目的',type:'textarea',required:true,value:'界面评审与业务核对'},
]:props.page.fields)
const title=computed(()=>exportMode.value?props.page.primary:props.record?`${props.page.rowAction} · ${props.record.name}`:props.page.primary)
watch(()=>props.open,open=>{if(open){Object.keys(values).forEach(k=>delete values[k]);fields.value.forEach(f=>values[f.key]=formValueFor(f,props.record));formRef.value?.clearValidate()}},{immediate:true})
const rules=computed(()=>Object.fromEntries(fields.value.map(f=>[f.key,[...(f.required?[{required:true,message:`请${f.type==='select'?'选择':'填写'}${f.label}`}]:[])]])))
function checkBusiness(){
  const ip=String(values.ip??values.target??'')
  if(ip&&!/^(?:\d{1,3}\.){3}\d{1,3}$/.test(ip)&&!ip.includes(':'))throw new Error('请输入有效的 IPv4 或 IPv6 地址。')
  if(ip.includes('.')&&ip.split('.').some(v=>Number(v)>255))throw new Error('IP 地址中的数字不能超过 255。')
  if(values.cidr&&!/^(?:\d{1,3}\.){3}\d{1,3}\/(?:[0-9]|[12][0-9]|3[0-2])$/.test(String(values.cidr)))throw new Error('请输入有效的 IPv4 CIDR 网段，例如 10.20.0.0/16。')
  if(values.confidence!==undefined&&(Number(values.confidence)<0||Number(values.confidence)>1))throw new Error('校准置信度门槛应在 0 与 1 之间。')
  if(props.page.family==='emergency'&&values.confirm!=='确认控制')throw new Error('请输入“确认控制”以确认控制范围。')
  if(props.page.family==='retention'&&!values.preview)throw new Error('请先核对影响预览。')
  if(props.page.family==='decision'&&values.mode==='自动'&&!String(values.calibration??'').trim())throw new Error('自动模式需要经过验收的校准与评测版本。')
}
async function submit(){
  try{await formRef.value?.validate();checkBusiness();busy.value=true;await new Promise(resolve=>setTimeout(resolve,180));emit('save',{...values})}
  catch(error){if(error instanceof Error)message.error(error.message)}finally{busy.value=false}
}
</script>

<template>
  <a-modal :open="open" :title="title" :width="720" :confirm-loading="busy" ok-text="提交" cancel-text="取消" destroy-on-close @cancel="emit('close')" @ok="submit" class="record-form-modal">
    <a-alert v-if="page.notice" :message="page.notice" type="info" show-icon class="modal-notice"/>
    <a-alert v-if="page.family==='action'||page.family==='emergency'" message="此原型仅创建本地示例任务，不连接设备。生产执行前需核对目标、授权、保护名单和撤销路径。" type="warning" show-icon class="modal-notice"/>
    <a-alert v-if="exportMode" message="导出内容仅包含当前有权限的示例记录；生产导出绑定查询快照、脱敏策略和下载期限。" type="info" show-icon class="modal-notice"/>
    <a-form ref="formRef" :model="values" :rules="rules" layout="vertical" class="operation-form">
      <div class="form-grid">
        <a-form-item v-for="field in fields" :key="field.key" :label="field.label" :name="field.key" :class="{'form-span-2':field.type==='textarea'}">
          <a-select v-if="field.type==='select'" v-model:value="values[field.key]" :options="field.options?.map(value=>({value,label:value}))" :placeholder="`请选择${field.label}`"/>
          <a-input-number v-else-if="field.type==='number'" v-model:value="values[field.key]" :min="field.key==='confidence'?0:field.min??1" :max="field.key==='confidence'?1:field.max" :step="field.key==='confidence'?0.01:1" style="width:100%"/>
          <a-switch v-else-if="field.type==='switch'" v-model:checked="values[field.key]" checked-children="开启" un-checked-children="关闭"/>
          <a-textarea v-else-if="field.type==='textarea'" v-model:value="values[field.key]" :rows="field.key==='rule'?5:3" :placeholder="`请输入${field.label}`"/>
          <a-input-password v-else-if="field.type==='password'" v-model:value="values[field.key]" autocomplete="new-password"/>
          <a-input v-else v-model:value="values[field.key]" :placeholder="`请输入${field.label}`"/>
          <small v-if="field.hint" class="field-hint">{{field.hint}}</small>
        </a-form-item>
      </div>
    </a-form>
    <div v-if="page.family==='decision'" class="policy-gates"><b>自动动作资格检查</b><div><a-tag>完整证据</a-tag><a-tag>校准版本有效</a-tag><a-tag>授权范围</a-tag><a-tag>保护名单</a-tag><a-tag>TTL 与预算</a-tag></div><small>本原型呈现配置路径，提交表单不会赋予实际执行权限。</small></div>
    <div class="modal-footnote">表单提交仅保存在当前原型会话中。</div>
  </a-modal>
</template>
