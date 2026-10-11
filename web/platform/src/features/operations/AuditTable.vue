<script setup lang="ts">
import {computed} from 'vue'
import {Table as ATable} from 'ant-design-vue'
import type {AuditRecord} from '@starbeacon/shared/types.ts'
import {formatTime} from '@starbeacon/shared/types.ts'
import {actionLabel} from './audits'
import type {AuditCategory} from './useAudits'
const props=defineProps<{category:AuditCategory;records:AuditRecord[]}>()
const emit=defineEmits<{view:[record:AuditRecord]}>()
const columns=computed(()=>[{title:'时间',key:'time',width:185},{title:'账号',dataIndex:'username',width:150},...(props.category==='operations'?[{title:'操作',key:'action',width:185},{title:'对象',dataIndex:'object_id',width:210}]:[{title:'凭据验证结果',key:'success',width:140}]),{title:'来源 IP',dataIndex:'source_ip',width:170},{title:'操作',key:'view',width:80}])
</script>
<template><div class="table-wrap"><a-table :columns="columns" :data-source="records" row-key="id" :pagination="false" :scroll="{x:1000}"><template #bodyCell="{column,record}"><span v-if="column.key==='time'">{{formatTime(record.created_at)}}</span><span v-else-if="column.key==='action'" :title="record.action">{{actionLabel(record.action)}}</span><span v-else-if="column.key==='success'" :class="['status',record.success===true?'status-online':record.success===false?'status-high':'status-unknown']">{{record.success===true?'验证通过':record.success===false?'验证失败':'未获取'}}</span><button v-else-if="column.key==='view'" class="link-button" @click="emit('view',record as AuditRecord)">查看</button><span v-else class="technical">{{record[String(column.dataIndex)]||'未获取'}}</span></template></a-table></div></template>
