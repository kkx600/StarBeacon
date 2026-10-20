<script setup lang="ts">
import {Select as ASelect} from 'ant-design-vue'
import {responseKinds,type ResponseFilters} from '../responseCatalog'
import {taskStates} from '../types'
defineProps<{model:ResponseFilters;pending:boolean}>()
defineEmits<{search:[];reset:[]}>()
const states=[{value:'',label:'全部执行状态'},...Object.entries(taskStates).map(([value,label])=>({value,label}))]
</script>
<template>
 <a-form :model="model" layout="inline" class="panel response-filters" @finish="$emit('search')">
  <a-form-item label="开始时间（本地）" html-for="response-start"><a-input id="response-start" v-model:value="model.start" aria-label="响应开始时间" type="datetime-local" step="1"/></a-form-item>
  <a-form-item label="结束时间（本地）" html-for="response-end"><a-input id="response-end" v-model:value="model.end" aria-label="响应结束时间" type="datetime-local" step="1"/></a-form-item>
  <a-form-item label="目标 IP" html-for="response-target"><a-input id="response-target" v-model:value="model.target_ip" aria-label="响应目标 IP" :maxlength="45" placeholder="精确 IPv4 或 IPv6" allow-clear/></a-form-item>
  <a-form-item label="执行探针" html-for="response-sensor"><a-input id="response-sensor" v-model:value="model.sensor_id" aria-label="响应探针标识" :maxlength="64" placeholder="精确探针标识" allow-clear/></a-form-item>
  <a-form-item label="联动设备" html-for="response-device"><a-input id="response-device" v-model:value="model.device_id" aria-label="响应设备标识" :maxlength="64" placeholder="精确设备标识" allow-clear/></a-form-item>
  <a-form-item label="动作类型" html-for="response-kind"><a-select id="response-kind" v-model:value="model.kind" aria-label="响应动作类型" :options="responseKinds"/></a-form-item>
  <a-form-item label="执行状态" html-for="response-state"><a-select id="response-state" v-model:value="model.state" aria-label="响应执行状态" :options="states"/></a-form-item>
  <div class="filter-actions"><a-button type="primary" html-type="submit" :loading="pending">查询</a-button><a-button :disabled="pending" @click="$emit('reset')">重置</a-button></div>
 </a-form>
</template>
<style scoped>
.response-filters{display:flex;flex-wrap:wrap;align-items:center;gap:var(--related-gap);padding:var(--panel-inset);margin-bottom:var(--section-gap)}.response-filters .ant-form-item{margin:0;min-width:0;flex:1 1 240px}.response-filters :deep(.ant-form-item-control){min-width:100px}.response-filters :deep(.ant-select){min-width:150px;width:100%}.response-filters .filter-actions{flex:1 1 160px}
</style>
