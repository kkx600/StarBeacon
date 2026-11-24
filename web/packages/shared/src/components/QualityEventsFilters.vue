<script setup lang="ts">
import { Select as ASelect } from 'ant-design-vue';
import { qualityEventNames, type QualityFilters } from '../qualityEvents';
import TimeRangeField from './TimeRangeField.vue';
import ListFilters from './ListFilters.vue';
const model = defineModel<QualityFilters>({ required: true });
defineProps<{ pending: boolean }>();
const emit = defineEmits<{ query: []; cancel: []; reset: [] }>();
</script>
<template>
  <a-form :model="model" layout="horizontal" @finish="emit('query')">
    <ListFilters label="质量事件筛选" :columns="3">
      <TimeRangeField
        v-model:start="model.start"
        v-model:end="model.end"
        id-prefix="quality"
        required
        end-hint="结束时刻不包含在查询内，窗口最多 31 天。"
      />
      <a-form-item label="事件类型" html-for="quality-kind"
        ><a-select
          id="quality-kind"
          v-model:value="model.kind"
          aria-label="质量事件类型"
          :options="[
            { value: '', label: '全部类型' },
            ...Object.entries(qualityEventNames).map(([value, label]) => ({ value, label })),
          ]"
      /></a-form-item>
      <a-form-item label="探针标识" html-for="quality-sensor"
        ><a-input id="quality-sensor" v-model:value="model.sensor" :maxlength="64" placeholder="留空查询全部探针"
      /></a-form-item>
      <a-form-item label="注册代次" html-for="quality-registration" extra="可核对历史注册；填写时须同时指定探针。"
        ><a-input
          id="quality-registration"
          v-model:value="model.registration"
          :maxlength="64"
          placeholder="留空包含全部注册代次"
      /></a-form-item>
      <template #actions>
        <a-button type="primary" html-type="submit" :loading="pending">查询</a-button
        ><a-button v-if="pending" @click="emit('cancel')">取消查询</a-button
        ><a-button :disabled="pending" @click="emit('reset')">重置</a-button>
      </template>
    </ListFilters>
  </a-form>
</template>
