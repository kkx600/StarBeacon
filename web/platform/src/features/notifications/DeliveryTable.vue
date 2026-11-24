<script setup lang="ts">
import { formatTime } from '@starbeacon/shared/types.ts';
import { formatNumber } from '@starbeacon/shared/utils/format.ts';
import { statusTone } from '@starbeacon/shared/statusTones.ts';
import ListTable from '@starbeacon/shared/components/ListTable.vue';
import StatusTag from '@starbeacon/shared/components/StatusTag.vue';
import { channelNames, deliveryNames, deliveryTones, streamNames, type Delivery } from './notifications';
defineProps<{ items: readonly Delivery[] }>();
const emit = defineEmits<{ view: [record: Delivery] }>();
const columns = [
  { title: '投递编号', dataIndex: 'id', width: 148, className: 'technical', ellipsis: true },
  { title: '投递时间', key: 'created', width: 172 },
  { title: '渠道编号', dataIndex: 'channel_id', width: 132, className: 'technical', ellipsis: true },
  { title: '渠道', dataIndex: 'channel_name', width: 150, ellipsis: true },
  { title: '修订', dataIndex: 'channel_revision', width: 65 },
  { title: '类型', key: 'kind', width: 110 },
  { title: '接收目标', key: 'recipient', width: 180, className: 'technical', ellipsis: true },
  { title: '状态', key: 'state', width: 116 },
  { title: '内容类别', key: 'stream', width: 115 },
  { title: '记录数', key: 'count', width: 75 },
  { title: '尝试次数', dataIndex: 'attempts', width: 84 },
  { title: '操作', key: 'actions', width: 68, fixed: 'right' as const },
];
</script>

<template>
  <ListTable :columns="columns" :data-source="[...items]" :scroll="{ x: 1415 }">
    <template #bodyCell="{ column, record }">
      <template v-if="column.key === 'created'">{{ formatTime(record.created_at) }}</template>
      <template v-else-if="column.key === 'kind'">{{ channelNames[record.kind] }}</template>
      <span v-else-if="column.key === 'recipient'" :title="record.recipient">{{ record.recipient || '渠道目标' }}</span>
      <StatusTag
        v-else-if="column.key === 'state'"
        :tone="statusTone(deliveryTones, record.state)"
        :value="deliveryNames[record.state] ?? '其他处理状态'"
      />
      <template v-else-if="column.key === 'stream'">{{ streamNames[record.stream ?? 'alerts'] }}</template>
      <template v-else-if="column.key === 'count'">{{
        formatNumber(record.record_count ?? record.alert_count)
      }}</template>
      <button v-else-if="column.key === 'actions'" type="button" class="record-link" @click="emit('view', record)">
        查看
      </button>
    </template>
  </ListTable>
</template>
