<script setup lang="ts">
import { computed } from 'vue';
import type { LogDocument } from '../syslog';
import { formatTime } from '../types';
import { statusTerms } from '../terms';
import ListTable from './ListTable.vue';
import StatusTag from './StatusTag.vue';
const props = defineProps<{ items: readonly LogDocument[] }>(),
  emit = defineEmits<{ view: [row: LogDocument] }>(),
  rows = computed(() => [...props.items]);
const columns = [
  { title: '日志编号', dataIndex: 'event_id', width: 145, className: 'technical', ellipsis: true },
  { title: '接收时间', key: 'time', width: 168 },
  {
    title: '来源编号',
    dataIndex: ['record', 'binding', 'source_id'],
    width: 145,
    className: 'technical',
    ellipsis: true,
  },
  { title: '来源名称', dataIndex: ['record', 'binding', 'source_name'], width: 142, ellipsis: true },
  { title: '网络域', dataIndex: ['record', 'binding', 'network_domain'], width: 115, ellipsis: true },
  { title: '探针编号', dataIndex: 'sensor_id', width: 145, className: 'technical', ellipsis: true },
  { title: '传输对端', dataIndex: ['record', 'peer', 'ip'], width: 150, className: 'technical', ellipsis: true },
  { title: '原文声明主机', key: 'host', width: 160, ellipsis: true },
  { title: '正文', key: 'message', width: 245, ellipsis: true },
  { title: '解析状态', key: 'state', width: 110 },
  { title: '操作', key: 'action', width: 93, fixed: 'right' as const },
];
function summary(record: LogDocument) {
  return record.parsed.state === 'quarantined'
    ? '原文未能按配置协议解析'
    : (record.parsed.message || '空正文') + (record.message_truncated ? '…（查看原文）' : '');
}
</script>
<template>
  <ListTable :columns="columns" :data-source="rows" row-key="event_id" :scroll="{ x: 1618 }"
    ><template #bodyCell="{ column, record }"
      ><template v-if="column.key === 'time'">{{ formatTime(record.received_at) }}</template
      ><template v-else-if="column.key === 'host'">{{ record.parsed.hostname || '未提供' }}</template
      ><span v-else-if="column.key === 'message'" :title="summary(record)">{{ summary(record) }}</span>
      <StatusTag
        v-else-if="column.key === 'state'"
        :value="record.parsed.state === 'parsed' ? '解析成功' : '解析隔离'"
        :tone="record.parsed.state === 'parsed' ? statusTerms.已完成 : statusTerms.不完整"
      /><a-button v-else-if="column.key === 'action'" size="small" type="link" @click="emit('view', record)"
        >查看原文</a-button
      ></template
    ></ListTable
  >
</template>
