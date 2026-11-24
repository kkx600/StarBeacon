<script setup lang="ts">
import { statusTerms } from '@starbeacon/shared/terms.ts';
import { Popconfirm } from 'ant-design-vue';
import { formatTime } from '@starbeacon/shared/types.ts';
import { tablePagination } from '@starbeacon/shared/pagination.ts';
import ListTable from '@starbeacon/shared/components/ListTable.vue';
import StatusTag from '@starbeacon/shared/components/StatusTag.vue';
import { channelNames, severityOptions, streamNames, type Channel, type LogStream } from './notifications';
defineProps<{ items: readonly Channel[]; busy: boolean; available: boolean }>();
const emit = defineEmits<{ edit: [record: Channel]; test: [record: Channel] }>();
const columns = [
  { title: '渠道编号', dataIndex: 'id', width: 148, className: 'technical', ellipsis: true },
  { title: '渠道名称', dataIndex: 'name', width: 150, ellipsis: true },
  { title: '类型', key: 'kind', width: 115 },
  { title: '修订', dataIndex: 'revision', width: 66 },
  { title: '状态', key: 'state', width: 82 },
  { title: '目标', dataIndex: 'target', width: 184, className: 'technical', ellipsis: true },
  { title: '订阅内容', key: 'streams', width: 150, ellipsis: true },
  { title: '告警级别', key: 'severities', width: 140, ellipsis: true },
  { title: '静默截止', key: 'muted', width: 172 },
  { title: '操作', key: 'actions', width: 116, fixed: 'right' as const },
];
function subscribed(record: Channel) {
  const streams: readonly LogStream[] = record.streams ?? ['alerts'];
  return streams.map(value => streamNames[value] ?? value).join('、');
}
function severities(record: Channel) {
  return (record.streams ?? ['alerts']).includes('alerts')
    ? record.severities.map(value => severityOptions.find(item => item.value === value)?.label ?? value).join('、')
    : '不订阅告警';
}
</script>

<template>
  <ListTable :columns="columns" :data-source="[...items]" :pagination="tablePagination()" :scroll="{ x: 1323 }">
    <template #bodyCell="{ column, record }">
      <template v-if="column.key === 'kind'">{{ channelNames[record.kind] }}</template>
      <StatusTag
        v-else-if="column.key === 'state'"
        :tone="record.enabled ? statusTerms.启用 : statusTerms.停用"
        :value="record.enabled ? '启用' : '停用'"
      />
      <span v-else-if="column.key === 'streams'" :title="subscribed(record)">{{ subscribed(record) }}</span>
      <span v-else-if="column.key === 'severities'" :title="severities(record)">{{ severities(record) }}</span>
      <template v-else-if="column.key === 'muted'">{{ formatTime(record.muted_until) }}</template>
      <div v-else-if="column.key === 'actions'" class="table-row-actions">
        <a-button type="link" size="small" :disabled="busy || !available" @click="emit('edit', record)">配置</a-button>
        <Popconfirm
          title="向该渠道发送一条测试摘要？"
          description="测试会发送到渠道当前配置的接收目标。"
          ok-text="发送测试"
          cancel-text="取消"
          :disabled="busy || !available"
          @confirm="emit('test', record)"
        >
          <a-button type="link" size="small" :disabled="busy || !available">测试</a-button>
        </Popconfirm>
      </div>
    </template>
  </ListTable>
</template>
