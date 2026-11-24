<script setup lang="ts">
import { Select as ASelect } from 'ant-design-vue';
import { connectorStatuses, type DeviceQuery } from '../responseDevices';
import ListFilters from './ListFilters.vue';
defineProps<{ model: DeviceQuery; pending: boolean }>();
const emit = defineEmits<{ search: []; reset: [] }>();
</script>
<template>
  <a-form layout="horizontal" :model="model" @finish="emit('search')">
    <ListFilters label="联动设备筛选" :columns="4">
      <a-form-item label="执行探针" html-for="device-sensor">
        <a-input
          id="device-sensor"
          v-model:value="model.sensor_id"
          aria-label="设备执行探针"
          :maxlength="64"
          allow-clear
          placeholder="完整探针标识"
        />
      </a-form-item>
      <a-form-item label="设备标识" html-for="device-id">
        <a-input
          id="device-id"
          v-model:value="model.device_id"
          aria-label="联动设备标识"
          :maxlength="64"
          allow-clear
          placeholder="完整设备标识"
        />
      </a-form-item>
      <a-form-item label="设备核验状态" html-for="device-status">
        <a-select id="device-status" v-model:value="model.status" :options="connectorStatuses" />
      </a-form-item>
      <template #actions>
        <a-button type="primary" html-type="submit" :loading="pending">查询</a-button>
        <a-button :disabled="pending" @click="emit('reset')">重置</a-button>
      </template>
    </ListFilters>
  </a-form>
</template>
