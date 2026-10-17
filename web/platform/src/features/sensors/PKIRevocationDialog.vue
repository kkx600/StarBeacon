<script setup lang="ts">
import {Modal as AModal} from 'ant-design-vue'
import type {ProbeCertificate} from './pki'
import type {RevocationTarget} from './useProbeRevocation'
const props=defineProps<{target:RevocationTarget|null;busy:boolean;locked:boolean;error:string;result:ProbeCertificate|'revoked'|null}>()
const emit=defineEmits<{close:[];submit:[]}>()
</script>
<template>
 <a-modal :open="!!target" :title="target?.kind==='certificate'?'吊销探针证书':'撤销注册令牌'" :width="620" :mask-closable="false" :closable="!busy" :keyboard="!busy" @cancel="emit('close')">
  <template v-if="target">
   <a-alert v-if="error" type="error" show-icon :message="error" role="alert" class="section-gap" />
   <a-alert v-if="result" :type="result==='revoked'||result.ca_revocation==='confirmed'?'success':'warning'" show-icon :message="result==='revoked'?'注册令牌已撤销。已有证书的状态保持独立。':result.ca_revocation==='confirmed'?'平台已拒绝此证书，CA 已确认吊销。':'平台已拒绝此证书；CA 吊销尚未取得可核实确认，请核查 CA 服务。'" />
   <template v-else><a-alert type="warning" show-icon :message="target.kind==='certificate'?'平台将拒绝此指纹的后续数据和任务请求，并定期复核已有控制连接。其他证书保持独立；如需停止整台探针，请在探针列表停用。':'令牌将不能继续注册或取得签发回执。已签发证书保持独立；需要停止通信时请吊销证书或停用探针。'" class="section-gap" /><p>探针：<span class="technical pki-digest">{{target.record.sensor_id}}</span></p><p>注册身份：<span class="technical pki-digest">{{target.record.registration_id}}</span></p><p v-if="target.kind==='certificate'">指纹：<span class="technical pki-digest">{{target.record.fingerprint_sha256}}</span></p></template>
  </template>
  <template #footer><a-button :disabled="busy" @click="emit('close')">关闭</a-button><a-button v-if="!result" danger type="primary" :loading="busy" @click="emit('submit')">{{locked?'核对原操作':target?.kind==='certificate'?'吊销证书':'撤销令牌'}}</a-button></template>
 </a-modal>
</template>
<style scoped>.pki-digest{overflow-wrap:anywhere}</style>
