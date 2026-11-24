<script setup lang="ts">
import { formatNumber } from '../utils/format';
import { onScopeDispose, shallowRef } from 'vue';
import type { ResponseDevice } from '../responseDevices';
import { deviceCondition, deviceConditions, deviceConditionTones, usableDevice } from '../responseDevices';
import { formatTime } from '../types';
import ListTable from './ListTable.vue';
import StatusTag from './StatusTag.vue';
defineProps<{ items: ResponseDevice[] }>();
const emit = defineEmits<{
  view: [device: ResponseDevice];
  actions: [device: ResponseDevice];
  respond: [device: ResponseDevice];
}>();
const now = shallowRef(Date.now()),
  timer = setInterval(() => {
    now.value = Date.now();
  }, 5000);
onScopeDispose(() => clearInterval(timer));
const columns = [
  { title: '设备编号', dataIndex: 'device_id', width: 150, className: 'technical', ellipsis: true },
  { title: '连接器编号', dataIndex: 'connector_id', width: 135, className: 'technical', ellipsis: true },
  { title: '探针编号', dataIndex: 'sensor_id', width: 145, className: 'technical', ellipsis: true },
  { title: '执行探针', dataIndex: 'sensor_name', width: 140, ellipsis: true },
  { title: '接口版本', dataIndex: 'version', width: 92, className: 'technical', ellipsis: true },
  { title: '当前条件', key: 'status', width: 156 },
  { title: '最长封禁', key: 'ttl', width: 100 },
  { title: '设备核验时间', key: 'observed', width: 174 },
  { title: '操作', key: 'actions', width: 206, fixed: 'right' as const },
];
function badge(device: ResponseDevice) {
  const condition = deviceCondition(device, now.value);
  return { tone: deviceConditionTones[condition], value: deviceConditions[condition] };
}
</script>
<template>
  <ListTable
    :columns="columns"
    :data-source="items"
    :row-key="(v: ResponseDevice) => v.sensor_id + '/' + v.connector_id"
    :scroll="{ x: 1298 }"
    ><template #bodyCell="{ column, record }"
      ><StatusTag v-if="column.key === 'status'" v-bind="badge(record)" />
      <template v-else-if="column.key === 'ttl'">{{ formatNumber(record.max_ttl_seconds) }} 秒</template
      ><template v-else-if="column.key === 'observed'">{{
        record.observation === 'pending' ? '无数据' : formatTime(record.observed_at)
      }}</template>
      <div v-else-if="column.key === 'actions'" class="table-row-actions">
        <a-button type="link" size="small" @click="emit('view', record)">查看</a-button
        ><a-button type="link" size="small" @click="emit('actions', record)">相关动作</a-button
        ><a-button type="link" size="small" :disabled="!usableDevice(record, now)" @click="emit('respond', record)"
          >限时封禁</a-button
        >
      </div></template
    ></ListTable
  >
</template>
