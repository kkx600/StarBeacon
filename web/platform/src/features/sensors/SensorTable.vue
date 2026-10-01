<script setup lang="ts">
import { Table as ATable, Popconfirm as APopconfirm } from 'ant-design-vue'
import type { Sensor } from '@starbeacon/shared/types.ts'
import { formatTime, formatPercent } from '@starbeacon/shared/types.ts'
const props = defineProps<{items: readonly Sensor[]; admin: boolean; saving: boolean}>()
const emit = defineEmits<{view: [sensor: Sensor]; toggle: [sensor: Sensor]}>()
function action(kind: 'view' | 'toggle', id: string) {const sensor = props.items.find(item => item.id === id); if (sensor) {if (kind === 'view') emit('view',sensor); else emit('toggle',sensor)}}
const labels = {online: '在线', offline: '离线', disabled: '停用'}
const columns = [{title:'探针名称',key:'name',width:200},{title:'连接状态',key:'status',width:100},{title:'CPU',key:'cpu',width:100},{title:'内存',key:'memory',width:100},{title:'磁盘',key:'disk',width:100},{title:'版本',dataIndex:['health','version'],width:100},{title:'最后观测时间',key:'seen',width:190},{title:'操作',key:'action',width:150}]
</script>
<template>
  <div class="table-wrap"><a-table :columns="columns" :data-source="[...items]" row-key="id" :pagination="false" :scroll="{x:1040}">
    <template #bodyCell="{column, record}">
      <template v-if="column.key === 'name'"><button class="link-button" @click="action('view',record.id)">{{ record.name }}</button><small class="record-id technical">{{ record.id }}</small></template>
      <span v-else-if="column.key === 'status'" class="status" :class="'status-'+record.status">{{ labels[record.status as Sensor['status']] }}</span>
      <template v-else-if="column.key === 'cpu'">{{ formatPercent(record.health.cpu_percent) }}</template>
      <template v-else-if="column.key === 'memory'">{{ formatPercent(record.health.memory_percent) }}</template>
      <template v-else-if="column.key === 'disk'">{{ formatPercent(record.health.disk_percent) }}</template>
      <template v-else-if="column.key === 'seen'">{{ formatTime(record.last_seen) }}</template>
      <template v-else-if="column.key === 'action'"><a-space><a-button type="link" @click="action('view',record.id)">查看</a-button><a-popconfirm v-if="admin" :title="record.active ? '停用后将拒绝探针上报和控制连接，确认停用？' : '确认启用此探针？'" @confirm="action('toggle',record.id)"><a-button type="link" :disabled="saving">{{ record.active ? '停用' : '启用' }}</a-button></a-popconfirm></a-space></template>
    </template>
  </a-table></div>
</template>
