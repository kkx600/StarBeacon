<script setup lang="ts">
import {Modal as AModal,Descriptions as ADescriptions,DescriptionsItem as ADescriptionsItem,Tag as ATag} from 'ant-design-vue'
import {formatTime} from '@starbeacon/shared/types.ts'
import StatePanel from '@starbeacon/shared/components/StatePanel.vue'
import {userRoles,type UserRecord} from './user'
defineProps<{record:UserRecord|null;pending:boolean;error:string;selfId:string}>()
const emit=defineEmits<{close:[];reload:[];edit:[];password:[]}>()
</script>
<template>
 <a-modal :open="true" title="用户详情" :width="720" :footer="null" @cancel="emit('close')">
  <StatePanel :loading="pending" :error="error" :empty="!record" description="用户详情暂不可用，请刷新后核对。" @retry="emit('reload')">
   <template v-if="record"><a-descriptions bordered size="small" :column="1"><a-descriptions-item label="账号名称">{{record.username}}</a-descriptions-item><a-descriptions-item label="用户标识"><span class="user-id">{{record.id}}</span></a-descriptions-item><a-descriptions-item label="用户角色">{{userRoles[record.role]}}</a-descriptions-item><a-descriptions-item label="账号状态"><a-tag :color="record.active?'green':'default'">{{record.active?'启用':'停用'}}</a-tag></a-descriptions-item><a-descriptions-item label="当前修订">{{record.revision}}</a-descriptions-item><a-descriptions-item label="创建时间">{{formatTime(record.created_at)}}</a-descriptions-item><a-descriptions-item label="变更时间">{{formatTime(record.updated_at)}}</a-descriptions-item></a-descriptions><p v-if="record.id===selfId" class="muted">当前登录账号受保护，权限变更需由其他管理员处理。</p><a-button type="primary" class="section-gap" :disabled="record.id===selfId||record.revision>=1000000" @click="emit('edit')">编辑用户</a-button><a-button v-if="record.id!==selfId" class="section-gap" :disabled="record.revision>=1000000" @click="emit('password')">重置密码</a-button></template>
  </StatePanel>
 </a-modal>
</template>
<style scoped>.user-id{overflow-wrap:anywhere}</style>
