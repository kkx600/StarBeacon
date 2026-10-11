<script setup lang="ts">
import {reactive,shallowRef} from 'vue'
import {Modal,Select,Switch,InputNumber} from 'ant-design-vue'
import {providerNames,type ModelProvider,type ModelChange,type ProviderKind} from './models'
const props=defineProps<{record:ModelProvider|null;pending:boolean;error:string}>()
const emit=defineEmits<{save:[change:ModelChange];close:[]}>()
const id=props.record?.id??'model_'+crypto.randomUUID().replaceAll('-','')
const credential=shallowRef<'keep'|'replace'|'clear'>(props.record?'keep':'replace'),formError=shallowRef('')
const model=reactive({name:props.record?.name??'',kind:props.record?.kind??'openai_responses' as ProviderKind,baseURL:props.record?.base_url??'',model:props.record?.model??'',key:'',enabled:props.record?.enabled??true,external:props.record?.allow_external??false,tokens:props.record?.max_output_tokens??2048,timeout:props.record?.timeout_seconds??30,daily:props.record?.daily_requests??100})
function save(){
  if(props.pending)return
  formError.value=''
  let url:URL
  try{url=new URL(model.baseURL.trim())}catch{formError.value='请输入完整的模型 API 地址。';return}
  if(url.protocol!=='https:'||url.username||url.password||url.search||url.hash||url.pathname.includes('..')){formError.value='模型 API 地址需使用 HTTPS，且不能包含账号、查询参数或片段。';return}
  if(credential.value==='keep'&&props.record&&(props.record.base_url!==model.baseURL.trim()||props.record.kind!==model.kind)){formError.value='连接目标或协议已改变，请替换或清除原凭据。';return}
  if(!model.name.trim()||!model.model.trim()){formError.value='请填写提供方名称和模型标识。';return}
  if(model.tokens==null||model.timeout==null||model.daily==null){formError.value='请填写输出、超时和每日请求上限。';return}
  emit('save',{id,expected_revision:props.record?.revision??0,replace_key:credential.value!=='keep',config:{name:model.name.trim(),kind:model.kind,base_url:model.baseURL.trim(),model:model.model.trim(),api_key:credential.value==='replace'?model.key:'',enabled:model.enabled,allow_external:model.external,max_output_tokens:model.tokens,timeout_seconds:model.timeout,daily_requests:model.daily}})
}
</script>
<template>
  <Modal :open="true" :title="record?'配置模型提供方':'创建模型提供方'" :width="680" :footer="null" :mask-closable="false" :closable="!pending" :keyboard="!pending" @cancel="emit('close')">
    <a-alert v-if="error||formError" type="error" :message="error||formError" show-icon class="section-gap" />
    <a-form :model="model" layout="vertical" :disabled="pending" @finish="save">
      <div class="provider-fields"><a-form-item label="提供方名称" name="name" :rules="[{required:true,message:'请输入提供方名称'}]"><a-input v-model:value="model.name" :maxlength="128" /></a-form-item><a-form-item label="生成协议" html-for="provider-protocol"><Select id="provider-protocol" aria-label="生成协议" v-model:value="model.kind" :options="Object.entries(providerNames).map(([value,label])=>({value,label}))" /></a-form-item></div>
      <a-form-item label="API 基础地址" name="baseURL" :rules="[{required:true,message:'请输入模型 API 地址'}]"><a-input v-model:value="model.baseURL" :maxlength="4096" placeholder="https://models.example.com/v1" autocomplete="off" /></a-form-item>
      <a-form-item label="模型标识" name="model" :rules="[{required:true,message:'请输入提供方支持的模型标识'}]"><a-input v-model:value="model.model" :maxlength="128" placeholder="填写提供方实际支持的模型标识" /></a-form-item>
      <a-form-item v-if="record" label="API 凭据处理" html-for="provider-credential-mode"><Select id="provider-credential-mode" aria-label="API 凭据处理" v-model:value="credential" :options="[{value:'keep',label:record.has_key?'保留现有凭据':'保持无凭据'},{value:'replace',label:'替换凭据'},{value:'clear',label:'清除凭据'}]" /></a-form-item>
      <a-form-item v-if="credential==='replace'" label="API Key" html-for="provider-key"><a-input-password id="provider-key" aria-label="API Key" v-model:value="model.key" :maxlength="4096" autocomplete="new-password" placeholder="私有服务不要求认证时可留空" /></a-form-item>
      <p class="page-description section-gap">凭据加密保存，保存后不回显。修改连接目标时须重新配置凭据。</p>
      <div class="provider-fields"><a-form-item label="提供方状态" html-for="provider-enabled"><Switch id="provider-enabled" aria-label="提供方状态" v-model:checked="model.enabled" checked-children="启用" un-checked-children="停用" /></a-form-item><a-form-item label="允许连接公网模型" html-for="provider-external"><Switch id="provider-external" aria-label="允许连接公网模型" v-model:checked="model.external" checked-children="允许" un-checked-children="禁止" /></a-form-item></div>
      <p class="page-description section-gap">禁止公网连接时，只能访问部署管理员明确授权的内网地址。连接权限不等于业务数据外送授权。</p>
      <div class="provider-budgets"><a-form-item label="最大输出 Token" html-for="provider-tokens"><InputNumber id="provider-tokens" aria-label="最大输出 Token" v-model:value="model.tokens" :min="64" :max="8192" :precision="0" style="width:100%" /></a-form-item><a-form-item label="请求超时（秒）" html-for="provider-timeout"><InputNumber id="provider-timeout" aria-label="请求超时（秒）" v-model:value="model.timeout" :min="5" :max="120" :precision="0" style="width:100%" /></a-form-item><a-form-item label="每日请求上限" html-for="provider-daily"><InputNumber id="provider-daily" aria-label="每日请求上限" v-model:value="model.daily" :min="1" :max="10000" :precision="0" style="width:100%" /></a-form-item></div>
      <div class="filter-actions provider-actions"><a-button :disabled="pending" @click="emit('close')">取消</a-button><a-button type="primary" html-type="submit" :loading="pending">保存配置</a-button></div>
    </a-form>
  </Modal>
</template>
<style scoped>.provider-fields{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:var(--field-gap)}.provider-budgets{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:var(--field-gap)}.provider-actions{justify-content:flex-end;margin-top:var(--section-gap)}@media(max-width:640px){.provider-fields,.provider-budgets{grid-template-columns:minmax(0,1fr);gap:0}}</style>
