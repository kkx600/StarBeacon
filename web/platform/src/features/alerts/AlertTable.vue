<script setup lang="ts">
import { formatTime, type Alert, type SearchResult } from '@starbeacon/shared/types.ts';
import ListTable from '@starbeacon/shared/components/ListTable.vue';
import ListPager from '@starbeacon/shared/components/ListPager.vue';
import StatusTag from '@starbeacon/shared/components/StatusTag.vue';
import { alertSeverityTones, statusTone } from '@starbeacon/shared/statusTones.ts';
defineProps<{ result: SearchResult }>();
const emit = defineEmits<{ view: [alert: Alert]; page: [value: number, size: number] }>();
const labels = { high: '高危', medium: '中危', low: '低危', unknown: '未知' };
const columns = [
  { title: '告警编号', dataIndex: 'event_id', width: 132, ellipsis: true, className: 'technical' },
  { title: '告警名称', key: 'name', width: 190, ellipsis: true },
  { title: '规则编号', dataIndex: ['rule', 'id'], width: 100, ellipsis: true, className: 'technical' },
  { title: '严重级别', key: 'severity', width: 92 },
  { title: '源 IP', dataIndex: ['source', 'ip'], width: 128, ellipsis: true, className: 'technical' },
  { title: '目的 IP', dataIndex: ['destination', 'ip'], width: 128, ellipsis: true, className: 'technical' },
  { title: '协议', key: 'protocol', width: 78, ellipsis: true },
  { title: '发生时间', key: 'time', width: 180, className: 'technical' },
  { title: '操作', key: 'action', width: 68, fixed: 'right' as const },
];
</script>
<template>
  <ListTable :columns="columns" :data-source="result.items" row-key="event_id" :scroll="{ x: 1096 }">
    <template #bodyCell="{ column, record }">
      <button
        v-if="column.key === 'name'"
        type="button"
        class="record-link"
        :title="record.rule.name || '未命名检测规则'"
        @click="emit('view', record)"
      >
        {{ record.rule.name || '未命名检测规则' }}
      </button>
      <StatusTag
        v-else-if="column.key === 'severity'"
        :tone="statusTone(alertSeverityTones, record.severity)"
        :value="labels[record.severity] || labels.unknown"
      />
      <template v-else-if="column.key === 'protocol'">{{
        record.network.protocol || record.network.transport || '未提供'
      }}</template>
      <template v-else-if="column.key === 'time'">{{ formatTime(record['@timestamp']) }}</template>
      <button v-else-if="column.key === 'action'" type="button" class="record-link" @click="emit('view', record)">
        查看
      </button>
    </template>
  </ListTable>
  <ListPager
    :page="result.page"
    :page-size="result.page_size"
    :total="Math.min(result.total, 10000)"
    @change="(page, size) => emit('page', page, size)"
  />
</template>
