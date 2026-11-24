<script setup lang="ts">
import type { SourceQuery } from '../syslog';
import ListFilters from './ListFilters.vue';
defineProps<{ model: SourceQuery; pending: boolean }>();
const emit = defineEmits<{ search: []; reset: [] }>();
</script>
<template>
  <form aria-label="Syslog 来源筛选" @submit.prevent="emit('search')">
    <ListFilters label="Syslog 来源条件" :columns="2">
      <label
        ><span>接入探针</span
        ><a-input v-model:value="model.sensor_id" aria-label="日志接入探针" allow-clear :maxlength="64" /></label
      ><label
        ><span>来源标识</span
        ><a-input v-model:value="model.source_id" aria-label="Syslog 来源标识" allow-clear :maxlength="64"
      /></label>
      <template #actions>
        <a-button html-type="submit" type="primary" :disabled="pending">查询</a-button
        ><a-button :disabled="pending" @click="emit('reset')">重置</a-button>
      </template>
    </ListFilters>
  </form>
</template>
