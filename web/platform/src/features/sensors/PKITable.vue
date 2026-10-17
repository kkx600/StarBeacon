<script setup lang="ts">
import {computed} from 'vue'
import {Table as ATable,Tag as ATag} from 'ant-design-vue'
import {formatTime} from '@starbeacon/shared/types.ts'
import {enrollmentStates,certificateStates,revocationStates,type Enrollment,type ProbeCertificate} from './pki'
const props=defineProps<{mode:'enrollments'|'certificates';enrollments:Enrollment[];certificates:ProbeCertificate[];locked:boolean}>()
const emit=defineEmits<{view:[record:Enrollment|ProbeCertificate];revoke:[record:Enrollment|ProbeCertificate];certificates:[sensor:string]}>()
const columns=computed(()=>props.mode==='enrollments'?[{title:'探针标识',dataIndex:'sensor_id',width:200},{title:'注册身份',dataIndex:'registration_id',width:240},{title:'注册状态',key:'state',width:140},{title:'注册截止时间',dataIndex:'expires_at',width:180},{title:'操作',key:'action',width:220}]:[{title:'证书指纹',dataIndex:'fingerprint_sha256',width:240},{title:'注册身份',dataIndex:'registration_id',width:230},{title:'签发状态',key:'state',width:140},{title:'证书到期时间',dataIndex:'not_after',width:180},{title:'CA 吊销确认',dataIndex:'ca_revocation',width:140},{title:'操作',key:'action',width:140}])
function action(kind:'view'|'revoke',id:string){const item=(props.mode==='enrollments'?props.enrollments:props.certificates).find(v=>v.id===id);if(item){if(kind==='view')emit('view',item);else emit('revoke',item)}}
function canRevoke(id:string){if(props.mode==='enrollments'){const row=props.enrollments.find(v=>v.id===id);return !!row&&!row.revoked&&Date.parse(row.expires_at)>Date.now()}const row=props.certificates.find(v=>v.id===id);return !!row&&row.state==='issued'&&(!row.revoked_at||row.ca_revocation!=='confirmed')}
function field(row:Record<string,unknown>,key:unknown){return typeof key==='string'&&typeof row[key]==='string'?row[key]:'—'}
</script>
<template>
 <a-table row-key="id" :columns="columns" :data-source="mode==='enrollments'?enrollments:certificates" :pagination="false" :scroll="{x:mode==='enrollments'?980:1070}" size="small">
  <template #bodyCell="{column,record}">
   <template v-if="column.key==='action'"><div class="pki-row-actions"><a-button type="link" size="small" @click="action('view',record.id)">查看</a-button><a-button v-if="mode==='enrollments'" type="link" size="small" :disabled="locked" @click="emit('certificates',record.sensor_id)">查看证书</a-button><a-button v-if="canRevoke(record.id)" type="link" danger size="small" :disabled="locked" @click="action('revoke',record.id)">{{mode==='enrollments'?'撤销令牌':record.revoked_at?'重试 CA 吊销':'吊销'}}</a-button></div></template>
   <template v-else-if="column.key==='state'"><a-tag :color="mode==='certificates'&&record.revoked_at?'red':record.state==='unknown'?'orange':record.state==='issued'?'green':undefined">{{mode==='certificates'&&record.revoked_at?'平台已吊销':(mode==='enrollments'?enrollmentStates:certificateStates)[record.state]}}</a-tag></template>
   <template v-else-if="column.dataIndex==='expires_at'||column.dataIndex==='not_after'">{{mode==='certificates'&&record.state!=='issued'?'—':formatTime(record[column.dataIndex])}}</template>
   <template v-else-if="column.dataIndex==='ca_revocation'">{{revocationStates[record.ca_revocation]}}</template>
   <template v-else-if="column.dataIndex==='fingerprint_sha256'"><span class="technical pki-cell" :title="record.fingerprint_sha256">{{record.fingerprint_sha256||'尚未取得签发回执'}}</span></template>
   <template v-else><span class="technical pki-cell">{{field(record,column.dataIndex)}}</span></template>
  </template>
 </a-table>
</template>
<style scoped>.pki-row-actions{display:flex;flex-wrap:wrap;gap:2px}.pki-cell{display:block;overflow-wrap:anywhere;min-width:0}</style>
