<script setup lang="ts">
import {reactive,shallowRef} from 'vue'
import {Modal,Select,Switch,InputNumber} from 'ant-design-vue'
import {scopeNames,type Scope,type Binding,type BindingChange} from './mcp'
const props=defineProps<{record:Binding|null;issuer:string;pending:boolean;error:string}>()
const emit=defineEmits<{save:[change:BindingChange];close:[]}>()
const id=props.record?.id??'mcp_'+crypto.randomUUID().replaceAll('-',''),validation=shallowRef('')
// 使用带时区的时间，避免浏览器与平台时区不同导致授权有效期偏移。
const model=reactive({name:props.record?.name??'',subject:props.record?.subject??'',client:props.record?.oauth_client_id??'',scopes:[...(props.record?.scopes??['alerts:read'])] as Scope[],enabled:props.record?.enabled??true,expires:props.record?.expires_at??new Date(Date.now()+180*86400000).toISOString(),budget:props.record?.requests_per_minute??60})
function save(){
  if(props.pending)return
  validation.value=''
  if(!model.name.trim()||!model.subject.trim()||!model.client.trim()){validation.value='请填写名称、授权主体和 OAuth 客户端标识。';return}
  if(!model.scopes.length){validation.value='请至少选择一个只读权限范围。';return}
  const expires=new Date(model.expires)
  if(!/(Z|[+-]\d{2}:\d{2})$/.test(model.expires)||!Number.isFinite(expires.getTime())||expires.getTime()<=Date.now()||expires.getTime()>Date.now()+3650*86400000){validation.value='请输入包含时区且未来 3650 天内的有效期。';return}
  if(model.budget==null||model.budget<1||model.budget>120){validation.value='每分钟调用上限应为 1–120 次。';return}
  emit('save',{id,expected_revision:props.record?.revision??0,name:model.name.trim(),subject:model.subject.trim(),oauth_client_id:model.client.trim(),scopes:[...model.scopes],enabled:model.enabled,expires_at:expires.toISOString(),requests_per_minute:model.budget})
}
</script>
<template>
  <Modal :open="true" :title="record?'配置服务身份':'登记服务身份'" :width="680" :footer="null" :mask-closable="false" :closable="!pending" :keyboard="!pending" @cancel="emit('close')">
    <a-alert v-if="error||validation" type="error" :message="error||validation" show-icon class="section-gap" />
    <p class="page-description section-gap">授权方：{{issuer}}。身份仅能查询当前租户；访问令牌由该授权方签发，平台不会生成 OAuth 令牌。</p>
    <a-form :model="model" layout="vertical" :disabled="pending" @finish="save">
      <a-form-item label="服务身份名称" name="name" :rules="[{required:true,message:'请输入服务身份名称'}]"><a-input v-model:value="model.name" :maxlength="80" /></a-form-item>
      <a-form-item label="授权主体（sub）" name="subject" :rules="[{required:true,message:'请输入授权方提供的主体标识'}]"><a-input v-model:value="model.subject" :disabled="!!record" :maxlength="512" autocomplete="off" /></a-form-item>
      <a-form-item label="OAuth 客户端标识（client_id）" name="client" :rules="[{required:true,message:'请输入调用方的 OAuth 客户端标识'}]"><a-input v-model:value="model.client" :disabled="!!record" :maxlength="512" autocomplete="off" /></a-form-item>
      <p class="page-description section-gap">主体和客户端登记后不能改绑。同一主体的其他客户端不会继承此权限。</p>
      <a-form-item label="只读权限范围" html-for="mcp-scopes"><Select id="mcp-scopes" aria-label="只读权限范围" v-model:value="model.scopes" mode="multiple" :options="Object.entries(scopeNames).map(([value,label])=>({value,label}))" /></a-form-item>
      <a-form-item label="授权到期时间" name="expires" :rules="[{required:true,message:'请输入包含时区的到期时间'}]"><a-input v-model:value="model.expires" :maxlength="40" placeholder="2027-04-01T00:00:00+08:00" /></a-form-item>
      <div class="binding-fields"><a-form-item label="每分钟调用上限" html-for="mcp-budget"><InputNumber id="mcp-budget" aria-label="每分钟调用上限" v-model:value="model.budget" :min="1" :max="120" :precision="0" style="width:100%" /></a-form-item><a-form-item label="服务身份状态" html-for="mcp-enabled"><Switch id="mcp-enabled" aria-label="服务身份状态" v-model:checked="model.enabled" checked-children="启用" un-checked-children="停用" /></a-form-item></div>
      <p class="page-description section-gap">默认有效期为 180 天。权限变更、停用及所属账号停用会使后续调用失效；当前只读工具不返回原始通信载荷。</p>
      <div class="filter-actions binding-actions"><a-button :disabled="pending" @click="emit('close')">取消</a-button><a-button type="primary" html-type="submit" :loading="pending">保存配置</a-button></div>
    </a-form>
  </Modal>
</template>
<style scoped>.binding-fields{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:var(--field-gap)}.binding-actions{justify-content:flex-end;margin-top:var(--section-gap)}@media(max-width:640px){.binding-fields{grid-template-columns:minmax(0,1fr);gap:0}}</style>
