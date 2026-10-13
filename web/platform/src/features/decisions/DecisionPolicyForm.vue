<script setup lang="ts">
import {computed,nextTick,onScopeDispose,reactive,ref,shallowRef,watch} from 'vue'
import {Modal as AModal,Select as ASelect,InputNumber as AInputNumber,Checkbox as ACheckbox} from 'ant-design-vue'
import {readSensorDirectory} from '@starbeacon/shared/sensors.ts'
import {readyConnector} from '@starbeacon/shared/response.ts'
import type {Sensor} from '@starbeacon/shared/types.ts'
import type {ModelProvider} from '../models/models'
import {eligibleResponseSensor} from './decisionResponses'
import {session} from '../../session'
import {policyActions,policyModes,policyChangeError,policyID,validPolicyValidation,type PolicyChange,type PolicyRecord} from './decisionPolicies'
const props=defineProps<{record:PolicyRecord|null;draft?:PolicyChange;busy:boolean;unconfirmed:boolean;error:string}>()
const emit=defineEmits<{save:[input:PolicyChange];confirm:[];close:[]}>()
const draft=props.draft,record=props.record,d=draft?.definition??record?.definition,id=draft?.id??record?.id??'policy_'+crypto.randomUUID().replaceAll('-','')
const form=reactive({name:draft?.name??record?.name??'',description:draft?.description??record?.description??'',active:String(draft?.active??record?.active??true),expression:d?.expression??'confidence >= threshold && verdict == "confirmed"',threshold:d?.threshold??.8,action:d?.candidate_action??'investigate',age:d?.max_age_seconds??3600,prefixes:d?.protected_prefixes.join('\n')??''})
const continuous=reactive({mode:d?.mode??'shadow',provider_id:d?.continuous?.provider_id??'',provider_revision:d?.continuous?.provider_revision??0,sensor_id:d?.continuous?.automatic?.sensor_id??'',registration_id:d?.continuous?.automatic?.registration_id??'',connector_id:d?.continuous?.automatic?.connector_id??'',config_sha256:d?.continuous?.automatic?.config_sha256??'',ttl_seconds:d?.continuous?.automatic?.ttl_seconds??300,cooldown_seconds:d?.continuous?.automatic?.cooldown_seconds??3600,max_hourly_actions:d?.continuous?.automatic?.max_hourly_actions??10,accept_uncalibrated_score:d?.continuous?.automatic?.accept_uncalibrated_score??false})
const trigger=reactive({enabled:!!d?.continuous?.trigger,severities:d?.continuous?.trigger?.severities.slice()??['critical','high'],max_daily_jobs:d?.continuous?.trigger?.max_daily_jobs??100,allow_model_context:d?.continuous?.trigger?.allow_model_context??false})
const providers=shallowRef<ModelProvider[]>([]),sensors=shallowRef<Sensor[]>([]),bindingsPending=ref(false),bindingsError=ref('')
const selectedSensor=computed(()=>sensors.value.find(v=>v.id===continuous.sensor_id)),connectors=computed(()=>(selectedSensor.value?.health.response_connectors??[]).filter(v=>readyConnector(v)))
let bindingRead:AbortController|undefined
const localError=ref(''),validation=ref(''),checking=ref(false),errorPanel=ref<HTMLDivElement|null>(null),locked=computed(()=>props.busy||props.unconfirmed||checking.value)
let stopped=false,read:AbortController|undefined
function input():PolicyChange{return {id,expected_revision:draft?.expected_revision??record?.revision??0,name:form.name.trim(),description:form.description.trim(),active:form.active==='true',definition:{schema_version:'decision-policy.v1',mode:continuous.mode,expression:form.expression.trim(),threshold:form.threshold,candidate_action:form.action,max_age_seconds:form.age,protected_prefixes:form.prefixes.split('\n').map(p=>p.trim()).filter(Boolean),...(continuous.mode==='shadow'?{}:{continuous:{provider_id:continuous.provider_id,provider_revision:continuous.provider_revision,...(continuous.mode==='automatic'?{automatic:{sensor_id:continuous.sensor_id,registration_id:continuous.registration_id,connector_id:continuous.connector_id,config_sha256:continuous.config_sha256,ttl_seconds:continuous.ttl_seconds,cooldown_seconds:continuous.cooldown_seconds,max_hourly_actions:continuous.max_hourly_actions,accept_uncalibrated_score:continuous.accept_uncalibrated_score},...(trigger.enabled?{trigger:{severities:[...trigger.severities],max_daily_jobs:trigger.max_daily_jobs,allow_model_context:trigger.allow_model_context as true}}:{})}:{})}})}}}
async function readBindings(){
 if(locked.value||bindingsPending.value||stopped)return
 bindingRead?.abort();const c=new AbortController();bindingRead=c;bindingsPending.value=true;bindingsError.value=''
 try{
  const value=await session.api.request<{items:ModelProvider[]}>('/models/providers',{signal:c.signal})
  if(c.signal.aborted)return
  if(!Array.isArray(value.items)||value.items.length>100||!value.items.every(v=>policyID(v.id)&&Number.isSafeInteger(v.revision)&&v.revision>0&&typeof v.enabled==='boolean'&&typeof v.name==='string'))throw new Error('模型目录不完整，请刷新后核对。')
  providers.value=value.items.filter(v=>v.enabled)
  if(continuous.mode==='automatic'){const rows=await readSensorDirectory(session.api,c.signal);if(c.signal.aborted)return;sensors.value=rows.filter(v=>eligibleResponseSensor(v))}
 }catch(e){if(!c.signal.aborted)bindingsError.value=e instanceof Error?e.message:'模型与探针目录读取失败。'}finally{if(bindingRead===c)bindingsPending.value=false}
}
function chooseProvider(value:unknown){const id=typeof value==='string'?value:'';continuous.provider_id=id;continuous.provider_revision=providers.value.find(v=>v.id===id)?.revision??0;continuous.accept_uncalibrated_score=false;trigger.allow_model_context=false}
function chooseSensor(value:unknown){const id=typeof value==='string'?value:'';const s=sensors.value.find(v=>v.id===id);continuous.sensor_id=id;continuous.registration_id=s?.registration_id??'';continuous.connector_id='';continuous.config_sha256='';continuous.accept_uncalibrated_score=false;trigger.allow_model_context=false}
function chooseConnector(value:unknown){const id=typeof value==='string'?value:'';const c=connectors.value.find(v=>v.connector_id===id);continuous.connector_id=id;continuous.config_sha256=c?.config_sha256??'';continuous.accept_uncalibrated_score=false;trigger.allow_model_context=false;if(c)continuous.ttl_seconds=Math.min(continuous.ttl_seconds,c.max_ttl_seconds)}
function focusError(){void nextTick(()=>errorPanel.value?.focus())}
watch(()=>props.error,value=>{if(value)focusError()},{flush:'post'})
watch(()=>[form.expression,form.threshold,form.action,form.age,form.prefixes],()=>{validation.value='';read?.abort()})
watch(continuous,()=>{validation.value='';read?.abort()})
watch(trigger,()=>{validation.value='';read?.abort()})
watch(()=>continuous.mode,mode=>{if(mode==='automatic')form.action='block_source';if(mode!=='shadow')void readBindings()},{immediate:true})
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
onScopeDispose(()=>{stopped=true;read?.abort();bindingRead?.abort()})
</script>
<template>
 <a-modal :open="true" :title="record||draft?.expected_revision?'编辑决策策略':'创建决策策略'" :width="820" :body-style="{maxHeight:'calc(100vh - 220px)',overflowY:'auto'}" :mask-closable="false" :closable="!busy" :keyboard="!busy" @cancel="emit('close')">
  <a-alert type="info" show-icon message="影子评估按需执行；持续模式处理本修订启用后的指定模型研判。自动研判默认关闭，启用后仅提交指定探针的新告警。自动授权不表示攻击成功或设备已阻断流量。" class="section-gap"/>
  <a-alert v-if="unconfirmed" type="warning" show-icon message="原提交结果尚未确认，请先核对；字段暂不可编辑。" class="section-gap"/>
  <div v-if="localError||error" ref="errorPanel" role="region" aria-label="决策策略校验信息" tabindex="-1" class="section-gap"><a-alert type="error" show-icon :message="error||localError"/></div>
  <a-alert v-if="validation" type="success" show-icon :message="validation" class="section-gap"/>
  <a-form layout="vertical" :model="form" :disabled="locked" @finish="submit">
   <div class="policy-grid">
    <h3 class="form-section-title">基本信息</h3>
    <a-form-item label="策略名称" html-for="policy-name" required><a-input id="policy-name" v-model:value="form.name" :maxlength="128"/></a-form-item>
    <a-form-item label="策略状态" html-for="policy-active"><a-select id="policy-active" v-model:value="form.active" :disabled="locked||!record&&!draft?.expected_revision" :options="[{value:'true',label:'启用'},{value:'false',label:'停用'}]" @keydown.esc.stop/></a-form-item>
    <a-form-item label="运行模式"><a-select v-model:value="continuous.mode" aria-label="决策运行模式" :options="Object.entries(policyModes).map(([value,label])=>({value,label}))" @keydown.esc.stop/></a-form-item>
    <a-form-item label="候选处置" html-for="policy-action"><a-select id="policy-action" v-model:value="form.action" :disabled="locked||continuous.mode==='automatic'" :options="Object.entries(policyActions).map(([value,label])=>({value,label}))" @keydown.esc.stop/></a-form-item>
    <h3 class="form-section-title">判断条件</h3>
    <a-form-item label="模型自报分数阈值" html-for="policy-threshold" extra="取值大于 0 且不超过 1，不等同攻击概率或封禁授权。"><a-input-number id="policy-threshold" v-model:value="form.threshold" :min=".001" :max="1" :step=".01" :precision="3"/></a-form-item>
    <a-form-item label="材料观测时限（秒）" html-for="policy-age" extra="按告警进入平台的观测时间核对，范围 60–86400 秒。"><a-input-number id="policy-age" v-model:value="form.age" :min="60" :max="86400" :precision="0"/></a-form-item>
   </div>
   <template v-if="continuous.mode!=='shadow'">
    <h3 class="form-section-title">模型与执行范围</h3>
    <a-alert v-if="bindingsError" type="error" show-icon :message="bindingsError" class="section-gap"/>
    <a-form-item label="指定模型" required extra="固定提供方修订。模型停用或修订变化后，本策略不再授权执行。"><a-select :value="continuous.provider_id||undefined" aria-label="持续决策指定模型" :loading="bindingsPending" :disabled="locked" :options="providers.map(v=>({value:v.id,label:v.name+' · 修订 '+v.revision}))" placeholder="选择已启用模型" @update:value="chooseProvider"/></a-form-item>
    <p class="policy-binding page-description">当前绑定：{{continuous.provider_id||'未选择'}} / {{continuous.provider_revision||'无'}}。<a-button size="small" :loading="bindingsPending" :disabled="locked" @click="readBindings">刷新模型与探针</a-button></p>
    <template v-if="continuous.mode==='automatic'">
     <a-form-item label="执行探针" required extra="仅授权该探针、该注册代次观测的告警；重新注册后需重新配置。"><a-select :value="continuous.sensor_id||undefined" aria-label="自动执行探针" :disabled="locked" :options="sensors.map(v=>({value:v.id,label:v.name+' · '+v.id}))" placeholder="选择具有就绪联动设备的在线探针" @update:value="chooseSensor"/></a-form-item>
     <a-form-item label="联动设备" required><a-select :value="continuous.connector_id||undefined" aria-label="自动执行联动设备" :disabled="locked||!selectedSensor" :options="connectors.map(v=>({value:v.connector_id,label:v.device_id+' · '+v.connector_id}))" placeholder="选择设备连接器" @update:value="chooseConnector"/></a-form-item>
     <div class="policy-grid"><a-form-item label="封禁期限（秒）" required><a-input-number v-model:value="continuous.ttl_seconds" aria-label="自动封禁期限" :min="30" :max="3600" :precision="0"/></a-form-item><a-form-item label="同一目标冷却时间（秒）" required extra="不短于封禁期限，跨策略共享目标冷却。"><a-input-number v-model:value="continuous.cooldown_seconds" aria-label="自动封禁冷却时间" :min="continuous.ttl_seconds" :max="86400" :precision="0"/></a-form-item><a-form-item label="每小时授权上限" required><a-input-number v-model:value="continuous.max_hourly_actions" aria-label="自动封禁每小时上限" :min="1" :max="100" :precision="0"/></a-form-item></div>
     <a-alert type="warning" show-icon message="模型分数未经领域校准。自动执行同时要求策略命中、达到分数阈值、确认攻击尝试、建议源 IP 封禁，以及源地址和规则的事实引用；不会把攻击尝试认定为入侵成功。" class="section-gap"/>
     <a-checkbox v-model:checked="continuous.accept_uncalibrated_score" :disabled="locked">授权在上述范围内使用模型自报分数自动提交限时封禁任务</a-checkbox>
     <div class="section-gap"><a-checkbox v-model:checked="trigger.enabled" aria-label="自动提交新告警研判" :disabled="locked">自动提交指定探针的新告警研判</a-checkbox></div>
     <template v-if="trigger.enabled">
      <div class="policy-grid"><a-form-item label="自动研判告警等级" required><a-select v-model:value="trigger.severities" mode="multiple" aria-label="自动研判告警等级" :disabled="locked" :options="[{value:'critical',label:'严重'},{value:'high',label:'高危'},{value:'medium',label:'中危'},{value:'low',label:'低危'}]"/></a-form-item><a-form-item label="每日自动研判上限" required extra="按 UTC 自然日计算，跨策略修订共享；同时受模型和租户额度约束。"><a-input-number v-model:value="trigger.max_daily_jobs" aria-label="每日自动研判上限" :min="1" :max="1000" :precision="0"/></a-form-item></div>
      <a-alert type="info" show-icon message="向指定模型发送告警白名单字段，不发送原始载荷或 PCAP；模型可能计费。同一触发只提交一次，历史告警和新注册代次不补做。停用或修订策略后，尚未执行的自动研判失去许可。" class="section-gap"/>
      <a-checkbox v-model:checked="trigger.allow_model_context" aria-label="自动研判数据使用许可" :disabled="locked">允许在上述范围和额度内向指定模型提交告警字段，并接受模型调用费用</a-checkbox>
     </template>
    </template>
   </template>
   <h3 class="form-section-title">表达式与保护范围</h3>
   <a-form-item label="决策表达式" html-for="policy-expression" required extra="CEL 布尔表达式，最多 2048 字节。自动执行始终额外核对分数阈值，表达式不能绕过固定门槛。"><a-textarea id="policy-expression" v-model:value="form.expression" :rows="3" :maxlength="2048" class="technical" spellcheck="false"/></a-form-item>
   <p class="page-description">可用变量：confidence、threshold、verdict、outcome、recommendation、protocol、reference_count、missing_count、evidence_limited、needs_review。未知变量、非布尔结果和循环宏不能保存。</p>
   <a-form-item label="保护网段" html-for="policy-prefixes" extra="每行一个规范 IPv4 / IPv6 CIDR，最多 32 个；仅在源 IP 封禁候选中排除匹配地址。"><a-textarea id="policy-prefixes" v-model:value="form.prefixes" :rows="2" :maxlength="4127" placeholder="192.0.2.0/24&#10;2001:db8::/32" spellcheck="false"/></a-form-item>
   <a-form-item label="维护说明" html-for="policy-description"><a-input id="policy-description" v-model:value="form.description" :maxlength="1000"/></a-form-item>

  </a-form>
  <template #footer>
   <div class="policy-actions"><a-button :disabled="busy" @click="emit('close')">关闭</a-button><a-button v-if="unconfirmed" type="primary" :loading="busy" :disabled="busy" @click="emit('confirm')">核对原提交</a-button><template v-else><a-button :loading="checking" :disabled="locked" @click="validate">检查表达式</a-button><a-button type="primary" @click="submit" :disabled="locked" :loading="busy">保存</a-button></template></div>
  </template>
 </a-modal>
</template>
<style scoped>.policy-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:0 12px}.policy-actions{display:flex;gap:8px;justify-content:flex-end;flex-wrap:wrap}.policy-binding{margin-bottom:16px;display:flex;align-items:center;justify-content:space-between;gap:8px;flex-wrap:wrap}.ant-input-number{width:100%}@media(max-width:700px){.policy-grid{grid-template-columns:minmax(0,1fr)}}</style>
