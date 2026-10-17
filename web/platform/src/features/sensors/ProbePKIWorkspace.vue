<script setup lang="ts">
import {computed,shallowRef,watch} from 'vue'
import StatePanel from '@starbeacon/shared/components/StatePanel.vue'
import PKITable from './PKITable.vue'
import PKIDetail from './PKIDetail.vue'
import EnrollmentForm from './EnrollmentForm.vue'
import PKIRevocationDialog from './PKIRevocationDialog.vue'
import {useProbePKI} from './useProbePKI'
import {useProbeEnrollment} from './useProbeEnrollment'
import {useProbeRevocation} from './useProbeRevocation'
import type {Enrollment,ProbeCertificate} from './pki'
import {session} from '../../session'
const props=defineProps<{sensorId?:string}>()
const directory=useProbePKI(),creation=useProbeEnrollment(),revocation=useProbeRevocation()
const {mode,enrollments,certificates,pending,error,cursors}=directory
const {busy,unconfirmed,receipt,token,draft,error:creationError}=creation
const {target:revokeTarget,busy:revoking,unconfirmed:revokeUnconfirmed,error:revokeError,result}=revocation
const search=shallowRef(props.sensorId??''),formOpen=shallowRef(false),revokeOpen=shallowRef(false),detail=shallowRef<Enrollment|ProbeCertificate|null>(null)
const rows=computed(()=>mode.value==='enrollments'?enrollments.value.items:certificates.value.items)
const nextCursor=computed(()=>mode.value==='enrollments'?enrollments.value.next_cursor:certificates.value.next_cursor)
const locked=computed(()=>busy.value||revoking.value||unconfirmed.value||revokeUnconfirmed.value)
watch(()=>props.sensorId,id=>{if(id){search.value=id;directory.select('certificates',id)}else directory.select('enrollments')},{immediate:true})
watch(receipt,value=>{if(value)void directory.load('', [''])})
watch(result,value=>{if(value)void directory.load()})
watch(()=>[session.current.value?.tenant_id,session.current.value?.id,session.current.value?.role].join('/'),()=>{formOpen.value=false;revokeOpen.value=false;detail.value=null;search.value='';directory.select('enrollments')})
function changeMode(value:'enrollments'|'certificates'){if(locked.value)return;detail.value=null;directory.select(value,search.value)}
function create(){if(busy.value||revoking.value||revokeUnconfirmed.value)return;if(!unconfirmed.value)creation.reset();formOpen.value=true}
function closeCreation(){formOpen.value=false;if(!unconfirmed.value)creation.reset()}
function revoke(record:Enrollment|ProbeCertificate){const value='fingerprint_sha256' in record?{kind:'certificate' as const,record}:{kind:'enrollment' as const,record};if(revocation.choose(value))revokeOpen.value=true}
function closeRevocation(){revokeOpen.value=false;if(!revokeUnconfirmed.value)revocation.reset()}
function showCertificates(sensor:string){if(locked.value)return;search.value=sensor;directory.select('certificates',sensor)}
</script>
<template>
 <div class="panel pki-toolbar"><div class="pki-mode"><a-button :type="mode==='enrollments'?'primary':'default'" :disabled="locked" @click="changeMode('enrollments')">注册凭据</a-button><a-button :type="mode==='certificates'?'primary':'default'" :disabled="locked" @click="changeMode('certificates')">证书目录</a-button></div><a-button v-if="mode==='enrollments'" type="primary" :disabled="pending||revoking||revokeUnconfirmed||!enrollments.ca_configured" @click="create">{{unconfirmed?'核对注册提交':'创建注册凭据'}}</a-button></div>
 <a-alert v-if="unconfirmed||revokeUnconfirmed" type="warning" show-icon message="存在结果尚未确认的操作，请核对原提交后继续。关闭页面将清除浏览器中的令牌原文。" class="section-gap"><template #action><a-button v-if="unconfirmed" size="small" @click="formOpen=true">核对注册提交</a-button><a-button v-if="revokeUnconfirmed" size="small" @click="revokeOpen=true">核对撤销操作</a-button></template></a-alert>
 <a-alert v-if="mode==='enrollments'&&!pending&&!error&&!enrollments.ca_configured" type="info" show-icon message="独立 CA 尚未配置。请完成 CA 部署和平台签发授权后创建注册凭据。" class="section-gap" />
 <a-form v-if="mode==='certificates'" layout="inline" class="panel pki-search" @submit.prevent="directory.search(search)"><a-form-item label="探针标识" required><a-input v-model:value="search" aria-label="查询证书的探针标识" :maxlength="64" placeholder="填写完整探针标识" :disabled="locked" /></a-form-item><a-button type="primary" html-type="submit" :loading="pending" :disabled="locked">查询</a-button></a-form>
 <section class="panel"><div class="panel-header"><h2>{{mode==='enrollments'?'探针注册凭据':'探针证书目录'}}</h2><span v-if="mode==='certificates'&&directory.sensor.value" class="technical">{{directory.sensor.value}}</span><a-button :disabled="pending||locked||mode==='certificates'&&!directory.sensor.value" @click="directory.load()">刷新</a-button></div>
  <StatePanel :loading="pending" :error="error" :empty="!rows.length" :description="mode==='enrollments'?'暂无注册凭据。配置独立 CA 后可创建生产探针身份。':'请输入完整探针标识查询。开发证书不进入托管证书目录。'" @retry="directory.load()"><PKITable :mode="mode" :enrollments="enrollments.items" :certificates="certificates.items" :locked="locked" @view="detail=$event" @revoke="revoke" @certificates="showCertificates" /></StatePanel>
  <div class="pki-pagination"><a-button :disabled="pending||locked||cursors.length<=1" @click="directory.previous">上一页</a-button><span>第 {{cursors.length}} 页</span><a-button :disabled="pending||locked||!nextCursor" @click="directory.next">下一页</a-button></div>
 </section>
 <EnrollmentForm v-if="formOpen" :busy="busy" :locked="unconfirmed" :error="creationError" :receipt="receipt" :token="token" :draft="draft" @save="creation.submit" @confirm="creation.submit()" @close="closeCreation" />
 <PKIDetail :record="detail" @close="detail=null" />
 <PKIRevocationDialog :target="revokeOpen?revokeTarget:null" :busy="revoking" :locked="revokeUnconfirmed" :error="revokeError" :result="result" @submit="revocation.submit" @close="closeRevocation" />
</template>
<style scoped>.pki-toolbar,.pki-mode,.pki-search,.pki-pagination{display:flex;align-items:center;flex-wrap:wrap;gap:8px}.pki-toolbar{justify-content:space-between;padding:var(--panel-inset);margin-bottom:var(--section-gap)}.pki-search{padding:var(--panel-inset);margin-bottom:var(--section-gap)}.pki-search .ant-form-item{margin:0;min-width:0}.pki-pagination{justify-content:flex-end;padding:var(--panel-inset)}@media(max-width:640px){.pki-search .ant-form-item{flex:1 1 100%}}</style>
