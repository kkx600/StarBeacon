<script setup lang="ts">
import {computed} from 'vue'
import {Modal as AModal,Descriptions as ADescriptions} from 'ant-design-vue'
import type {AuditRecord} from '@starbeacon/shared/types.ts'
import {formatTime} from '@starbeacon/shared/types.ts'
import {actionLabel} from './audits'
const ADescriptionsItem=ADescriptions.Item
const props=defineProps<{record:AuditRecord|null}>()
const emit=defineEmits<{close:[]}>()
const fields=computed(()=>props.record?[{label:'时间',value:formatTime(props.record.created_at)},{label:'账号',value:props.record.username},{label:'操作',value:actionLabel(props.record.action)},{label:'操作标识',value:props.record.action},{label:'对象',value:props.record.object_id||'未提供'},{label:'来源 IP',value:props.record.source_ip||'未获取'},{label:'客户端',value:props.record.user_agent||'未获取'},{label:'请求标识',value:props.record.request_id||'未提供'},{label:'日志标识',value:props.record.id},...(props.record.reason?[{label:'操作原因',value:props.record.reason}]:[]),...(props.record.success!==undefined?[{label:'凭据验证结果',value:props.record.success?'验证通过':'验证失败'},{label:'验证阶段',value:props.record.phase==='password_verification'?'密码验证':'凭据验证'}]:[])]:[])
</script>
<template><a-modal title="审计日志详情" :open="record!==null" :width="760" :footer="null" @cancel="emit('close')"><a-alert v-if="record?.success!==undefined" type="info" message="凭据验证结果不代表会话一定创建成功。" show-icon class="section-gap"/><a-descriptions :column="1" bordered size="small"><a-descriptions-item v-for="field in fields" :key="field.label" :label="field.label"><span class="technical">{{field.value}}</span></a-descriptions-item></a-descriptions></a-modal></template>
