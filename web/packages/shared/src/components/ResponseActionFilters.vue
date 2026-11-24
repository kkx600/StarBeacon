<script setup lang="ts">
import { Select as ASelect } from 'ant-design-vue';
import { responseKinds, type ResponseFilters } from '../responseCatalog';
import { taskStates } from '../types';
import ListFilters from './ListFilters.vue';
import TimeRangeField from './TimeRangeField.vue';
defineProps<{ model: ResponseFilters; pending: boolean }>();
defineEmits<{ search: []; reset: [] }>();
const states = [
  { value: '', label: '全部执行状态' },
  ...Object.entries(taskStates).map(([value, label]) => ({ value, label })),
];
</script>
<template>
  <a-form :model="model" layout="horizontal" @finish="$emit('search')">
    <ListFilters label="响应动作筛选" :columns="3">
      <TimeRangeField v-model:start="model.start" v-model:end="model.end" id-prefix="response" required />
      <a-form-item label="目标 IP" html-for="response-target"
        ><a-input
          id="response-target"
          v-model:value="model.target_ip"
          aria-label="响应目标 IP"
          :maxlength="45"
          placeholder="精确 IPv4 或 IPv6"
          allow-clear
      /></a-form-item>
      <a-form-item label="执行探针" html-for="response-sensor"
        ><a-input
          id="response-sensor"
          v-model:value="model.sensor_id"
          aria-label="响应探针标识"
          :maxlength="64"
          placeholder="精确探针标识"
          allow-clear
      /></a-form-item>
      <a-form-item label="联动设备" html-for="response-device"
        ><a-input
          id="response-device"
          v-model:value="model.device_id"
          aria-label="响应设备标识"
          :maxlength="64"
          placeholder="精确设备标识"
          allow-clear
      /></a-form-item>
      <a-form-item label="动作类型" html-for="response-kind"
        ><a-select id="response-kind" v-model:value="model.kind" aria-label="响应动作类型" :options="responseKinds"
      /></a-form-item>
      <a-form-item label="执行状态" html-for="response-state"
        ><a-select id="response-state" v-model:value="model.state" aria-label="响应执行状态" :options="states"
      /></a-form-item>
      <template #actions>
        <a-button type="primary" html-type="submit" :loading="pending">查询</a-button
        ><a-button :disabled="pending" @click="$emit('reset')">重置</a-button>
      </template>
    </ListFilters>
  </a-form>
</template>
