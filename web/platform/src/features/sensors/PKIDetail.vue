<script setup lang="ts">
import {computed} from 'vue'
import {Modal as AModal,Descriptions as ADescriptions} from 'ant-design-vue'
import {formatTime} from '@starbeacon/shared/types.ts'
import {enrollmentStates,certificateStates,revocationStates,type Enrollment,type ProbeCertificate} from './pki'
const ADescriptionsItem=ADescriptions.Item
const props=defineProps<{record:Enrollment|ProbeCertificate|null}>()
const emit=defineEmits<{close:[]}>()
const certificate=computed(()=>props.record&&'fingerprint_sha256' in props.record?props.record:null)
const enrollment=computed(()=>props.record&&!('fingerprint_sha256' in props.record)?props.record:null)
</script>
<template>
 <a-modal :open="!!record" :title="certificate?'探针证书详情':'探针注册凭据详情'" :width="700" :footer="null" @cancel="emit('close')">
  <a-descriptions v-if="record" bordered size="small" :column="1">
   <a-descriptions-item label="记录标识"><span class="technical">{{record.id}}</span></a-descriptions-item><a-descriptions-item label="探针标识"><span class="technical">{{record.sensor_id}}</span></a-descriptions-item><a-descriptions-item label="注册身份"><span class="technical">{{record.registration_id}}</span></a-descriptions-item>
   <template v-if="certificate"><a-descriptions-item label="签发状态">{{certificateStates[certificate.state]}}</a-descriptions-item><a-descriptions-item label="证书指纹"><span class="technical pki-digest">{{certificate.fingerprint_sha256||'尚未取得签发回执'}}</span></a-descriptions-item><a-descriptions-item label="证书序列号"><span class="technical pki-digest">{{certificate.serial||'尚未取得'}}</span></a-descriptions-item><a-descriptions-item label="证书有效期">{{certificate.state==='issued'?formatTime(certificate.not_before)+' 至 '+formatTime(certificate.not_after):'尚未取得签发回执'}}</a-descriptions-item><a-descriptions-item label="平台吊销时间">{{certificate.revoked_at?formatTime(certificate.revoked_at):'未吊销'}}</a-descriptions-item><a-descriptions-item label="CA 吊销确认">{{revocationStates[certificate.ca_revocation]}}</a-descriptions-item></template>
   <template v-if="enrollment"><a-descriptions-item label="注册状态">{{enrollmentStates[enrollment.state]}}</a-descriptions-item><a-descriptions-item label="创建时间">{{formatTime(enrollment.created_at)}}</a-descriptions-item><a-descriptions-item label="注册截止时间">{{formatTime(enrollment.expires_at)}}</a-descriptions-item><a-descriptions-item label="令牌状态">{{enrollment.revoked?'已撤销':Date.parse(enrollment.expires_at)<=Date.now()?'已到期':'尚未撤销'}}</a-descriptions-item><a-descriptions-item label="签发记录"><span class="technical">{{enrollment.job_id||'尚未提交 CSR'}}</span></a-descriptions-item></template>
   <a-descriptions-item v-if="record.csr_sha256" label="CSR 摘要"><span class="technical pki-digest">{{record.csr_sha256}}</span></a-descriptions-item>
  </a-descriptions>
  <p class="field-hint section-gap">注册令牌原文和探针私钥不在目录中提供。签发记录不代表探针当前在线；证书是否允许通信还取决于注册代次、探针启用状态和平台吊销状态。</p>
 </a-modal>
</template>
<style scoped>.pki-digest{overflow-wrap:anywhere}</style>
