<script setup lang="ts">
import {computed,nextTick,onScopeDispose,reactive,ref,watch} from 'vue'
import {Modal as AModal,Select as ASelect,InputNumber as AInputNumber} from 'ant-design-vue'
import {session} from '../../session'
import {policyActions,policyChangeError,validPolicyValidation,type PolicyChange,type PolicyRecord} from './decisionPolicies'
const props=defineProps<{record:PolicyRecord|null;draft?:PolicyChange;busy:boolean;unconfirmed:boolean;error:string}>()
const emit=defineEmits<{save:[input:PolicyChange];confirm:[];close:[]}>()
const draft=props.draft,record=props.record,d=draft?.definition??record?.definition,id=draft?.id??record?.id??'policy_'+crypto.randomUUID().replaceAll('-','')
const form=reactive({name:draft?.name??record?.name??'',description:draft?.description??record?.description??'',active:String(draft?.active??record?.active??true),expression:d?.expression??'confidence >= threshold && verdict == "confirmed"',threshold:d?.threshold??.8,action:d?.candidate_action??'investigate',age:d?.max_age_seconds??3600,prefixes:d?.protected_prefixes.join('\n')??''})
const localError=ref(''),validation=ref(''),checking=ref(false),errorPanel=ref<HTMLDivElement|null>(null),locked=computed(()=>props.busy||props.unconfirmed||checking.value)
let stopped=false,read:AbortController|undefined
function input():PolicyChange{return {id,expected_revision:draft?.expected_revision??record?.revision??0,name:form.name.trim(),description:form.description.trim(),active:form.active==='true',definition:{schema_version:'decision-policy.v1',mode:'shadow',expression:form.expression.trim(),threshold:form.threshold,candidate_action:form.action,max_age_seconds:form.age,protected_prefixes:form.prefixes.split('\n').map(p=>p.trim()).filter(Boolean)}}}
function focusError(){void nextTick(()=>errorPanel.value?.focus())}
watch(()=>props.error,value=>{if(value)focusError()},{flush:'post'})
watch(()=>[form.expression,form.threshold,form.action,form.age,form.prefixes],()=>{validation.value='';read?.abort()})
async function validate(){
 if(locked.value)return
 const c=input();localError.value=policyChangeError(c);validation.value=''
 if(localError.value){focusError();return}
 const controller=new AbortController();read=controller;checking.value=true
 try{const value=await session.api.request<unknown>('/decision-policies/validate',{method:'POST',body:{definition:c.definition},signal:controller.signal});if(stopped||controller.signal.aborted)return;if(!await validPolicyValidation(value,c.definition))throw new Error('策略校验回执与当前定义不一致。');if(!stopped&&!controller.signal.aborted)validation.value='表达式与参数校验通过；尚未对研判材料执行评估。'}
 catch(e){if(!stopped&&!controller.signal.aborted){localError.value=e instanceof Error?e.message:'策略校验失败。';focusError()}}finally{if(read===controller)checking.value=false}
}
function submit(){
 if(locked.value)return
 const c=input();localError.value=policyChangeError(c)
 if(!localError.value&&record&&c.name===record.name&&c.description===record.description&&c.active===record.active&&JSON.stringify(c.definition)===JSON.stringify(record.definition))localError.value='没有可提交的策略变更。'
 if(localError.value){focusError();return};emit('save',c)
}
onScopeDispose(()=>{stopped=true;read?.abort()})
</script>
<template>
 <a-modal :open="true" :title="record||draft?.expected_revision?'编辑决策策略':'创建决策策略'" :width="820" :footer="null" :body-style="{maxHeight:'calc(100vh - 220px)',overflowY:'auto'}" :mask-closable="false" :closable="!busy" :keyboard="!busy" @cancel="emit('close')">
  <a-alert type="info" show-icon message="影子评估验证策略是否命中，不发送通知、不修改告警结论、不执行设备封禁。" class="section-gap"/>
  <a-alert v-if="unconfirmed" type="warning" show-icon message="原提交结果尚未确认，请先核对；字段暂不可编辑。" class="section-gap"/>
  <div v-if="localError||error" ref="errorPanel" role="region" aria-label="决策策略校验信息" tabindex="-1" class="section-gap"><a-alert type="error" show-icon :message="error||localError"/></div>
  <a-alert v-if="validation" type="success" show-icon :message="validation" class="section-gap"/>
  <a-form layout="vertical" :model="form" :disabled="locked" @finish="submit">
   <div class="policy-grid">
    <a-form-item label="策略名称" html-for="policy-name" required><a-input id="policy-name" v-model:value="form.name" :maxlength="128"/></a-form-item>
    <a-form-item label="策略状态" html-for="policy-active"><a-select id="policy-active" v-model:value="form.active" :disabled="locked||!record&&!draft?.expected_revision" :options="[{value:'true',label:'启用'},{value:'false',label:'停用'}]" @keydown.esc.stop/></a-form-item>
    <a-form-item label="运行模式"><a-select value="shadow" aria-label="决策运行模式" :options="[{value:'shadow',label:'影子评估'},{value:'approval',label:'审批执行（暂不可用）',disabled:true},{value:'automatic',label:'自动执行（暂不可用）',disabled:true}]"/></a-form-item>
    <a-form-item label="候选处置" html-for="policy-action"><a-select id="policy-action" v-model:value="form.action" :options="Object.entries(policyActions).map(([value,label])=>({value,label}))" @keydown.esc.stop/></a-form-item>
    <a-form-item label="模型自报分数阈值" html-for="policy-threshold" extra="取值大于 0 且不超过 1，不等同攻击概率或封禁授权。"><a-input-number id="policy-threshold" v-model:value="form.threshold" :min=".001" :max="1" :step=".01" :precision="3"/></a-form-item>
    <a-form-item label="材料观测时限（秒）" html-for="policy-age" extra="按告警进入平台的观测时间核对，范围 60–86400 秒。"><a-input-number id="policy-age" v-model:value="form.age" :min="60" :max="86400" :precision="0"/></a-form-item>
   </div>
   <a-form-item label="决策表达式" html-for="policy-expression" required extra="CEL 布尔表达式，最多 2048 字节。阈值只在表达式引用 threshold 时参与判断。"><a-textarea id="policy-expression" v-model:value="form.expression" :rows="3" :maxlength="2048" class="technical" spellcheck="false"/></a-form-item>
   <p class="page-description">可用变量：confidence、threshold、verdict、outcome、recommendation、protocol、reference_count、missing_count、evidence_limited、needs_review。未知变量、非布尔结果和循环宏不能保存。</p>
   <a-form-item label="保护网段" html-for="policy-prefixes" extra="每行一个规范 IPv4 / IPv6 CIDR，最多 32 个；仅在源 IP 封禁候选中排除匹配地址。"><a-textarea id="policy-prefixes" v-model:value="form.prefixes" :rows="2" :maxlength="4127" placeholder="192.0.2.0/24&#10;2001:db8::/32" spellcheck="false"/></a-form-item>
   <a-form-item label="维护说明" html-for="policy-description"><a-input id="policy-description" v-model:value="form.description" :maxlength="1000"/></a-form-item>
   <div class="policy-actions"><a-button :disabled="busy" @click="emit('close')">关闭</a-button><a-button v-if="unconfirmed" type="primary" :loading="busy" :disabled="busy" @click="emit('confirm')">核对原提交</a-button><template v-else><a-button :loading="checking" :disabled="locked" @click="validate">检查表达式</a-button><a-button type="primary" html-type="submit" :disabled="locked" :loading="busy">保存</a-button></template></div>
  </a-form>
 </a-modal>
</template>
<style scoped>.policy-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:0 12px}.policy-actions{display:flex;gap:8px;justify-content:flex-end}.ant-input-number{width:100%}@media(max-width:700px){.policy-grid{grid-template-columns:minmax(0,1fr)}}</style>
