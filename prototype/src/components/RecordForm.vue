<script setup lang="ts">
import { computed,nextTick,reactive,ref,watch } from 'vue'
import type {FormInstance} from 'ant-design-vue'
import type {BusinessRecord,FieldSpec,PageSpec} from '../models'
import RuleEditor from '../../../web/packages/shared/src/components/RuleEditor.vue'
import {inspectRules} from '../../../web/packages/shared/src/utils/ruleSyntax'
import {formValueFor} from '../composables/formValues'
import {userInputError} from '../../../web/platform/src/features/users/user'
import {managementInputError} from '../../../web/platform/src/features/sensors/management'
const props=defineProps<{open:boolean;page:PageSpec;record?:BusinessRecord}>()
const emit=defineEmits<{close:[];save:[values:Record<string,unknown>]}>()
const formRef=ref<FormInstance>();const values=reactive<Record<string,unknown>>({});const busy=ref(false)
const formError=ref(''),errorRef=ref<HTMLElement>()
const exportMode=computed(()=>props.page.actionMode==='export')
const fields=computed<FieldSpec[]>(()=>exportMode.value?[
  {key:'range',label:'导出范围',type:'select',required:true,value:'当前筛选快照',options:['当前筛选快照','已选记录']},
  {key:'format',label:'文件格式',type:'select',required:true,value:'CSV',options:['CSV','JSON']},
  {key:'reason',label:'使用目的',type:'textarea',required:true,value:'界面评审与业务核对'},
]:props.page.family==='user'&&props.record?props.page.fields.filter(field=>field.key!=='password'):props.page.fields)
const title=computed(()=>exportMode.value?props.page.primary:props.record?`${props.page.rowAction} · ${props.record.name}`:props.page.primary)
watch(()=>props.open,open=>{if(open){formError.value='';Object.keys(values).forEach(k=>delete values[k]);fields.value.forEach(f=>values[f.key]=formValueFor(f,props.record));formRef.value?.clearValidate()}},{immediate:true})
const rules=computed(()=>Object.fromEntries(fields.value.map(f=>[f.key,[...(f.required?[{required:true,message:`请${f.type==='select'?'选择':'填写'}${f.label}`}]:[])]])))
function checkBusiness(){
  if(props.page.family==='sensor-group'){const error=managementInputError({id:'prototype_group',expected_revision:Number(props.record?.revision??0),name:String(values.name??''),description:String(values.description??''),active:Boolean(values.active)});if(error)throw new Error(error)}
  if(props.page.family==='sensor-group'&&props.record&&Number(props.record.memberCount)>0&&!values.active)throw new Error('分组内仍有探针，请先调整探针归属。')
  if(props.page.family==='user'&&!props.record){const error=userInputError({username:String(values.name??''),password:String(values.password??''),role:values.role==='管理员'?'admin':'viewer',active:Boolean(values.active)});if(error)throw new Error(error)}
  if(props.page.family==='rule'||props.page.family==='rule-studio'){const problems=inspectRules(String(values.rule??''));if(problems.length)throw new Error(`第 ${problems[0]!.line} 行：${problems[0]!.message}`)}
  const ip=String(values.ip??values.target??'')
  if(ip&&!/^(?:\d{1,3}\.){3}\d{1,3}$/.test(ip)&&!ip.includes(':'))throw new Error('请输入有效的 IPv4 或 IPv6 地址。')
  if(ip.includes('.')&&ip.split('.').some(v=>Number(v)>255))throw new Error('IP 地址中的数字不能超过 255。')
  if(values.cidr&&!/^(?:\d{1,3}\.){3}\d{1,3}\/(?:[0-9]|[12][0-9]|3[0-2])$/.test(String(values.cidr)))throw new Error('请输入有效的 IPv4 CIDR 网段，例如 10.20.0.0/16。')
  if(props.page.family==='decision'){
    if(!Number.isFinite(Number(values.confidence))||Number(values.confidence)<=0||Number(values.confidence)>1)throw new Error('模型自报分数阈值须大于 0 且不超过 1。')
    if(!Number.isInteger(Number(values.age))||Number(values.age)<60||Number(values.age)>86400)throw new Error('材料观测时限须为 60–86400 秒。')
    if(new TextEncoder().encode(String(values.expression??'')).length>2048)throw new Error('决策表达式不能超过 2048 字节。')
  }else if(values.confidence!==undefined&&(Number(values.confidence)<0||Number(values.confidence)>1))throw new Error('校准置信度门槛应在 0 与 1 之间。')
  if(props.page.family==='emergency'&&values.confirm!=='确认控制')throw new Error('请输入“确认控制”以确认控制范围。')
  if(props.page.family==='retention'&&!values.preview)throw new Error('请先核对影响预览。')
  if(props.page.family==='decision'&&values.mode==='自动'&&!String(values.calibration??'').trim())throw new Error('自动模式需要经过验收的校准与评测版本。')
}
async function submit(){
  try{formError.value='';await formRef.value?.validate();checkBusiness();busy.value=true;await new Promise(resolve=>setTimeout(resolve,180));const output={...values};if(props.page.family==='user'){delete output.password;output.status=values.active?'启用':'停用'}if(props.page.family==='sensor-group'){output.status=values.active?'启用':'停用';output.memberCount=props.record?.memberCount??0;output.revision=Number(props.record?.revision??0)+1}if(props.page.family==='sensor'){output.metadataRevision=Number(props.record?.metadataRevision??0)+1}emit('save',output)}
  catch(error){formError.value=error instanceof Error?error.message:'请核对必填字段与格式后提交。';await nextTick();errorRef.value?.focus()}finally{busy.value=false}
}
</script>

<template>
  <a-modal :open="open" :title="title" :width="720" :body-style="{maxHeight:'calc(100vh - 252px)',overflowY:'auto'}" :confirm-loading="busy" ok-text="提交" cancel-text="取消" destroy-on-close @cancel="emit('close')" @ok="submit" class="record-form-modal">
    <a-alert v-if="page.notice" :message="page.notice" type="info" show-icon class="modal-notice"/>
    <a-alert v-if="page.family==='action'||page.family==='emergency'" message="此原型仅创建本地示例任务，不连接设备。生产执行前需核对目标、授权、保护名单和撤销路径。" type="warning" show-icon class="modal-notice"/>
    <a-alert v-if="exportMode" message="导出内容仅包含当前有权限的示例记录；生产导出绑定查询快照、脱敏策略和下载期限。" type="info" show-icon class="modal-notice"/>
    <div v-if="formError" ref="errorRef" role="alert" tabindex="-1" aria-label="表单校验信息" class="form-validation-error"><a-alert type="error" show-icon :message="formError" /></div>
    <a-form ref="formRef" :model="values" :rules="rules" layout="vertical" class="operation-form">
      <div class="form-grid">
        <a-form-item v-for="field in fields" :key="field.key" :label="field.label" :name="field.key" :class="{'form-span-2':field.type==='textarea'}">
          <a-select v-if="field.type==='select'" v-model:value="values[field.key]" :options="field.options?.map(value=>({value,label:value}))" :placeholder="`请选择${field.label}`" @keydown.esc.stop/>
          <a-input-number v-else-if="field.type==='number'" v-model:value="values[field.key]" :min="field.key==='confidence'?0:field.min??1" :max="field.key==='confidence'?1:field.max" :step="field.key==='confidence'?0.01:1" style="width:100%"/>
          <a-switch v-else-if="field.type==='switch'" v-model:checked="values[field.key]" :disabled="page.family==='sensor-group'&&!record&&field.key==='active'" checked-children="开启" un-checked-children="关闭"/>
          <RuleEditor v-else-if="field.key==='rule'" :model-value="String(values[field.key]??'')" @update:model-value="values[field.key]=$event"/>
          <a-textarea v-else-if="field.type==='textarea'" v-model:value="values[field.key]" :rows="field.key==='rule'?5:3" :placeholder="`请输入${field.label}`"/>
          <a-input-password v-else-if="field.type==='password'" v-model:value="values[field.key]" autocomplete="new-password"/>
          <a-input v-else v-model:value="values[field.key]" :readonly="page.family==='user'&&!!record&&field.key==='name'" :placeholder="`请输入${field.label}`"/>
          <small v-if="field.hint" class="field-hint">{{field.hint}}</small>
        </a-form-item>
      </div>
    </a-form>
    <div v-if="page.family==='decision'" class="policy-gates"><b>影子评估条件</b><div><a-tag>本人研判</a-tag><a-tag>来源摘要</a-tag><a-tag>材料时限</a-tag><a-tag>保护网段</a-tag><a-tag>表达式预算</a-tag></div><small>本原型使用合成材料展示配置；影子结果没有设备执行授权。</small></div>
    <div class="modal-footnote">表单提交仅保存在当前原型会话中。</div>
  </a-modal>
</template>

<style scoped>.form-validation-error{margin-bottom:var(--section-gap)}.form-validation-error:focus-visible{outline:2px solid var(--primary);outline-offset:2px}</style>
