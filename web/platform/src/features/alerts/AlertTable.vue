<script setup lang="ts">
import type { Alert, SearchResult } from '@starbeacon/shared/types.ts'
import { Table as ATable, type TablePaginationConfig } from 'ant-design-vue'
import { formatTime } from '@starbeacon/shared/types.ts'
const props = defineProps<{result: SearchResult}>()
const emit = defineEmits<{view: [alert: Alert]; page: [value: number, size: number]}>()
function changePage(pagination: TablePaginationConfig) { emit('page', pagination.current ?? 1, pagination.pageSize ?? 20) }
function view(id: string) {const alert = props.result.items.find(item => item.event_id === id); if (alert) emit('view',alert)}
const labels = {high:'高危',medium:'中危',low:'低危',unknown:'未知'}
const columns = [{title:'告警名称',key:'name',width:240},{title:'严重级别',key:'severity',width:100},{title:'源 IP',dataIndex:['source','ip'],width:150},{title:'目的 IP',dataIndex:['destination','ip'],width:150},{title:'协议',key:'protocol',width:100},{title:'发生时间',key:'time',width:190},{title:'操作',key:'action',width:80}]
</script>
<template>
  <div class="table-wrap"><a-table :columns="columns" :data-source="result.items" row-key="event_id" :scroll="{x:1050}" :pagination="{current:result.page,pageSize:result.page_size,total:Math.min(result.total,10000),showSizeChanger:true,pageSizeOptions:['20','50','100'],showTotal:(total: number) => `共 ${total} 条`}" @change="changePage">
    <template #bodyCell="{column,record}">
      <template v-if="column.key === 'name'"><button class="link-button" @click="view(record.event_id)">{{ record.rule.name || '未命名检测规则' }}</button><small class="record-id">SID {{ record.rule.id || '未提供' }}</small></template>
      <span v-else-if="column.key === 'severity'" class="status" :class="'status-'+record.severity">{{ labels[record.severity as Alert['severity']] }}</span>
      <template v-else-if="column.key === 'protocol'">{{ record.network.protocol || record.network.transport || '未提供' }}</template>
      <template v-else-if="column.key === 'time'">{{ formatTime(record['@timestamp']) }}</template>
      <a-button v-else-if="column.key === 'action'" type="link" @click="view(record.event_id)">查看</a-button>
    </template>
  </a-table></div>
</template>
