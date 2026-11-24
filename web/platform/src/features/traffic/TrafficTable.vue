<script setup lang="ts">
import ListTable from '@starbeacon/shared/components/ListTable.vue';
import { formatBytes } from '@starbeacon/shared/utils/format.ts';
import { formatTime } from '@starbeacon/shared/types.ts';
import { applicationStatuses } from '@starbeacon/shared/application.ts';
import { endpoint, packetCountLabel, trafficKinds, type TrafficRecord, type TrafficResult } from './traffic';

defineProps<{ result: TrafficResult }>();
const emit = defineEmits<{ view: [record: TrafficRecord] }>();
const columns = [
  { title: '记录编号', dataIndex: 'event_id', width: 145, className: 'technical', ellipsis: true },
  { title: '记录类型', key: 'kind', width: 100 },
  { title: '协议', key: 'protocol', width: 100, ellipsis: true },
  { title: '源端点', key: 'source', width: 164, className: 'technical', ellipsis: true },
  { title: '目的端点', key: 'destination', width: 164, className: 'technical', ellipsis: true },
  { title: '事件时间', key: 'time', width: 170 },
  { title: '流编号', key: 'flow', width: 145, className: 'technical', ellipsis: true },
  { title: '探针编号', dataIndex: 'sensor_id', width: 145, className: 'technical', ellipsis: true },
  { title: '应用分类', key: 'application', width: 136, ellipsis: true },
  { title: '客户端→服务端', key: 'server', width: 180, ellipsis: true },
  { title: '服务端→客户端', key: 'client', width: 180, ellipsis: true },
  { title: '操作', key: 'action', width: 68, fixed: 'right' as const },
];
function applicationLabel(record: TrafficRecord) {
  const app = record.application;
  return app ? app.product_name || applicationStatuses[app.result.status] : '未提供分类';
}
function directionalCount(record: TrafficRecord, direction: 'server' | 'client') {
  const flow = record.details.flow;
  const volume = formatBytes(flow?.[`bytes_to_${direction}`]);
  return `${volume} · ${packetCountLabel(flow?.[`packets_to_${direction}`])}`;
}
</script>

<template>
  <ListTable :columns="columns" :data-source="result.items" row-key="event_id" :scroll="{ x: 1697 }">
    <template #bodyCell="{ column, record }">
      <template v-if="column.key === 'kind'">{{ trafficKinds[record.event.kind] }}</template>
      <template v-else-if="column.key === 'protocol'">
        {{ record.network.protocol || record.network.transport || '无数据' }}
      </template>
      <template v-else-if="column.key === 'source' || column.key === 'destination'">
        <span :title="endpoint(record[column.key].ip, record[column.key].port)">
          {{ endpoint(record[column.key].ip, record[column.key].port) }}
        </span>
      </template>
      <template v-else-if="column.key === 'flow'">{{ record.suricata.flow_id || '未提供' }}</template>
      <span v-else-if="column.key === 'application'" :title="applicationLabel(record)">{{
        applicationLabel(record)
      }}</span>
      <span
        v-else-if="column.key === 'server' || column.key === 'client'"
        :title="directionalCount(record, column.key)"
      >
        {{ directionalCount(record, column.key) }}
      </span>
      <template v-else-if="column.key === 'time'">{{ formatTime(record['@timestamp']) }}</template>
      <a-button v-else-if="column.key === 'action'" size="small" type="link" @click="emit('view', record)"
        >查看</a-button
      >
    </template>
  </ListTable>
</template>
