<script setup lang="ts">
import {reactive,shallowRef,watch} from 'vue'
import {Modal as AModal,InputNumber as AInputNumber,InputPassword as AInputPassword,Descriptions as ADescriptions} from 'ant-design-vue'
import {formatTime} from '@starbeacon/shared/types.ts'
import {enrollmentError,type EnrollmentDraft,type Enrollment} from './pki'
const props=defineProps<{busy:boolean;locked:boolean;error:string;receipt:Enrollment|null;token:string;draft?:EnrollmentDraft|null}>()
const emit=defineEmits<{save:[value:EnrollmentDraft];confirm:[];close:[]}>()
const ADescriptionsItem=ADescriptions.Item
const form=reactive<EnrollmentDraft>(props.draft?{...props.draft}:{name:'',sensor_id:'',registration_id:'reg_'+crypto.randomUUID().replaceAll('-',''),ttl_seconds:3600})
const localError=shallowRef(''),downloadError=shallowRef('')
watch(form,()=>{localError.value=''})
function submit(){if(props.busy||props.locked||props.receipt)return;localError.value=enrollmentError(form);if(!localError.value)emit('save',{...form})}
function download(){
 downloadError.value=''
 if(!props.receipt||!props.token||props.receipt.revoked||Date.parse(props.receipt.expires_at)<=Date.now()){downloadError.value='注册凭据已不可用，请创建独立凭据。';return}
 try{const url=URL.createObjectURL(new Blob([props.token+'\n'],{type:'text/plain;charset=utf-8'}));const link=document.createElement('a');link.href=url;link.download='starbeacon-'+props.receipt.sensor_id+'.token';link.click();setTimeout(()=>URL.revokeObjectURL(url),1000)}catch{downloadError.value='文件保存未完成，请重试并核对浏览器下载权限。'}
}
</script>
<template>
 <a-modal open title="创建探针注册凭据" :width="700" :mask-closable="false" :closable="!busy" :keyboard="!busy&&!receipt" @cancel="emit('close')">
  <a-alert v-if="error||localError||downloadError" type="error" show-icon :message="error||localError||downloadError" role="alert" class="section-gap" />
  <template v-if="receipt">
   <a-alert type="success" show-icon message="注册凭据已创建。请保存令牌文件，再由采集器生成本机私钥并完成注册。此窗口关闭后不再提供令牌原文。" class="section-gap" />
   <a-descriptions bordered size="small" :column="1"><a-descriptions-item label="探针标识"><span class="technical">{{receipt.sensor_id}}</span></a-descriptions-item><a-descriptions-item label="注册身份"><span class="technical">{{receipt.registration_id}}</span></a-descriptions-item><a-descriptions-item label="注册截止时间">{{formatTime(receipt.expires_at)}}</a-descriptions-item></a-descriptions>
   <a-form layout="vertical" class="section-gap"><a-form-item label="一次性注册令牌"><a-input-password :value="token" readonly autocomplete="off" aria-label="一次性注册令牌" /></a-form-item></a-form>
   <p class="field-hint">令牌用于一个固定 CSR，不能跨探针或注册身份使用。请将文件存入仅部署人员可读的位置，在 Linux 采集器上将权限设为 600，再使用注册工具。平台不接收探针私钥。</p>
  </template>
  <template v-else>
   <a-alert type="info" show-icon message="创建独立生产探针身份，注册凭据默认一小时有效。现有探针的身份和历史数据不会被本操作覆盖。" class="section-gap" />
   <a-form layout="vertical" :disabled="busy||locked" @submit.prevent="submit">
    <div class="pki-form-grid">
     <a-form-item label="探针名称" required><a-input v-model:value="form.name" aria-label="探针名称" :maxlength="128" placeholder="例如：办公出口探针" /></a-form-item>
     <a-form-item label="探针标识" required><a-input v-model:value="form.sensor_id" aria-label="探针标识" :maxlength="64" placeholder="例如：probe_office_01" /></a-form-item>
     <a-form-item label="注册身份" required><a-input v-model:value="form.registration_id" aria-label="注册身份" :maxlength="64" /><small class="field-hint">新探针使用自动生成值。恢复现有探针时，填写目录中的同一注册身份，并保持探针名称一致。</small></a-form-item>
     <a-form-item label="凭据有效期（秒）" required><a-input-number v-model:value="form.ttl_seconds" :min="60" :max="86400" :precision="0" aria-label="凭据有效期" class="full-width" /></a-form-item>
    </div>
    <p class="field-hint">有效期只限制首次注册。已签发证书由采集器在到期前自动续签；撤销注册令牌不会吊销已签发证书。</p>
   </a-form>
  </template>
  <template #footer><div class="pki-actions"><a-button :disabled="busy" @click="emit('close')">{{receipt?'关闭窗口':'关闭'}}</a-button><a-button v-if="receipt" type="primary" @click="download">保存令牌文件</a-button><a-button v-else-if="locked" type="primary" :loading="busy" @click="emit('confirm')">核对原提交</a-button><a-button v-else type="primary" :loading="busy" @click="submit">创建注册凭据</a-button></div></template>
 </a-modal>
</template>
<style scoped>.pki-form-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));column-gap:16px}.full-width{width:100%}.pki-actions{display:flex;flex-wrap:wrap;justify-content:flex-end;gap:8px}@media(max-width:640px){.pki-form-grid{grid-template-columns:minmax(0,1fr)}}</style>
