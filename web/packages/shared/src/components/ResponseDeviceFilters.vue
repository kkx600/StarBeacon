<script setup lang="ts">
import {Select as ASelect} from 'ant-design-vue'
import {connectorStatuses,type DeviceQuery} from '../responseDevices'
defineProps<{model:DeviceQuery;pending:boolean}>()
const emit=defineEmits<{search:[];reset:[]}>()
</script>
<template><section class="panel"><div class="panel-body"><a-form layout="vertical" :model="model" @finish="emit('search')"><div class="device-filter-grid"><a-form-item label="执行探针" html-for="device-sensor"><a-input id="device-sensor" v-model:value="model.sensor_id" aria-label="设备执行探针" :maxlength="64" allow-clear placeholder="完整探针标识"/></a-form-item><a-form-item label="设备标识" html-for="device-id"><a-input id="device-id" v-model:value="model.device_id" aria-label="联动设备标识" :maxlength="64" allow-clear placeholder="完整设备标识"/></a-form-item><a-form-item label="设备核验状态" html-for="device-status"><a-select id="device-status" v-model:value="model.status" :options="connectorStatuses"/></a-form-item><div class="filter-actions"><a-button type="primary" html-type="submit" :loading="pending">查询</a-button><a-button :disabled="pending" @click="emit('reset')">重置</a-button></div></div></a-form></div></section></template>
<style scoped>.device-filter-grid{display:grid;grid-template-columns:repeat(3,minmax(150px,1fr)) auto;gap:var(--related-gap);align-items:end}.ant-form-item{margin-bottom:0}.filter-actions{padding-bottom:1px}@media(max-width:1100px){.device-filter-grid{grid-template-columns:repeat(2,minmax(0,1fr))}}@media(max-width:600px){.device-filter-grid{grid-template-columns:1fr}}</style>
