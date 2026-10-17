<script setup lang="ts">
import {computed,shallowRef,watch} from 'vue'
import {useRoute,useRouter} from 'vue-router'
import type {PreviewState} from '../models'
import type {Enrollment,EnrollmentDraft,ProbeCertificate} from '../../../web/platform/src/features/sensors/pki'
import PKITable from '../../../web/platform/src/features/sensors/PKITable.vue'
import PKIDetail from '../../../web/platform/src/features/sensors/PKIDetail.vue'
import EnrollmentForm from '../../../web/platform/src/features/sensors/EnrollmentForm.vue'
import PKIRevocationDialog from '../../../web/platform/src/features/sensors/PKIRevocationDialog.vue'
import type {RevocationTarget} from '../../../web/platform/src/features/sensors/useProbeRevocation'
import PageHeader from './PageHeader.vue'
import StatePanel from './StatePanel.vue'
const props=defineProps<{state:PreviewState}>(),emit=defineEmits<{state:[value:PreviewState]}>()
const route=useRoute(),router=useRouter()
const mode=computed(()=>route.query.view==='certificates'?'certificates':'enrollments')
const enrollment:Enrollment={id:'enroll_example',sensor_id:'probe_office_01',registration_id:'reg_office_example',created_at:'2026-10-17T06:00:00Z',expires_at:'2027-04-15T06:00:00Z',revoked:false,state:'unused'}
const certificate:ProbeCertificate={id:'cert_example',sensor_id:enrollment.sensor_id,registration_id:enrollment.registration_id,fingerprint_sha256:'34a890f1698b34dd865b8afea927fca870f8d7d9f71550affd7f6d3809573d99',serial:'4756932874962873469287346',not_before:'2026-10-17T06:00:00Z',not_after:'2026-10-18T06:00:00Z',ca_revocation:'none',state:'issued',csr_sha256:'d'.repeat(64)}
const formOpen=shallowRef(false),detail=shallowRef<Enrollment|ProbeCertificate|null>(null),revoke=shallowRef<RevocationTarget|null>(null),receipt=shallowRef<Enrollment|null>(null),revokeResult=shallowRef<ProbeCertificate|'revoked'|null>(null)
watch(()=>[props.state,mode.value],()=>{formOpen.value=props.state==='action'&&mode.value==='enrollments';detail.value=props.state==='detail'?(mode.value==='enrollments'?enrollment:certificate):null;revoke.value=props.state==='action'&&mode.value==='certificates'?{kind:'certificate',record:certificate}:null;receipt.value=null;revokeResult.value=null},{immediate:true})
function select(value:string){void router.push({query:{...route.query,view:value==='certificates'?'certificates':undefined,state:'data'}})}
function save(draft:EnrollmentDraft){receipt.value={...enrollment,sensor_id:draft.sensor_id,registration_id:draft.registration_id}}
function choose(row:Enrollment|ProbeCertificate){revokeResult.value=null;revoke.value='fingerprint_sha256' in row?{kind:'certificate',record:row}:{kind:'enrollment',record:row}}
function revokeExample(){revokeResult.value=revoke.value?.kind==='certificate'?{...certificate,revoked_at:'2026-10-17T06:30:00Z',ca_revocation:'unknown'}:'revoked'}
</script>
<template>
 <PageHeader title="注册与证书" description="核对生产探针注册凭据、签发记录和证书吊销状态。"><a-button @click="emit('state','data')">刷新</a-button><a-button v-if="mode==='enrollments'" type="primary" @click="receipt=null;formOpen=true">创建注册凭据</a-button></PageHeader>
 <a-alert type="info" show-icon message="本页面为合成示例，复用工程表单和只读详情，不调用 CA 或真实探针。证书有效、平台允许通信与 CA 吊销确认分别核对。" class="section-gap" />
 <div class="panel pki-preview-toolbar"><a-button :type="mode==='enrollments'?'primary':'default'" @click="select('enrollments')">注册凭据</a-button><a-button :type="mode==='certificates'?'primary':'default'" @click="select('certificates')">证书目录</a-button><a-tag v-if="mode==='certificates'">{{certificate.sensor_id}}</a-tag></div>
 <section class="panel"><StatePanel v-if="['empty','error','loading'].includes(state)" :state="state as 'empty'|'error'|'loading'" :title="state==='empty'?'暂无'+(mode==='enrollments'?'注册凭据':'托管证书'):undefined" :description="state==='empty'?'核对当前探针和目录范围。开发证书不进入托管证书目录。':undefined" action="重新加载" @action="emit('state','data')" /><PKITable v-else :mode="mode" :enrollments="[enrollment]" :certificates="[certificate]" :locked="false" @view="detail=$event" @revoke="choose" @certificates="select('certificates')" /></section>
 <EnrollmentForm v-if="formOpen" :busy="false" :locked="false" error="" :receipt="receipt" :token="receipt?'合成示例，不能用于设备注册':''" @save="save" @close="formOpen=false;receipt=null" />
 <PKIDetail :record="detail" @close="detail=null" />
 <PKIRevocationDialog :target="revoke" :busy="false" :locked="false" error="" :result="revokeResult" @submit="revokeExample" @close="revoke=null" />
</template>
<style scoped>.pki-preview-toolbar{display:flex;align-items:center;flex-wrap:wrap;gap:8px;padding:var(--panel-inset);margin-bottom:var(--section-gap)}</style>
