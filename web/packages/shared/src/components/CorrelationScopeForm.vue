<script setup lang="ts">
import { reactive, ref } from 'vue';
import { correlationRequestError, type CorrelationRequest } from '../correlation';
import ListFilters from './ListFilters.vue';
import PageHelp from './PageHelp.vue';
const props = defineProps<{
  revision: number;
  windowSeconds: number;
  initial?: CorrelationRequest;
  pending: boolean;
  disabled?: boolean;
  error?: string;
}>();
const emit = defineEmits<{ run: [query: CorrelationRequest]; cancel: []; change: [] }>();
function local(value: number) {
  const d = new Date(value);
  return new Date(d.getTime() - d.getTimezoneOffset() * 60000).toISOString().slice(0, 19);
}
const step = props.windowSeconds * 1000,
  end = Math.floor(Date.now() / step) * step,
  start = end - Math.floor(Math.min(3600, Math.max(900, props.windowSeconds * 3)) / props.windowSeconds) * step;
const scope = reactive({
    start: local(props.initial ? Date.parse(props.initial.start) : start),
    end: local(props.initial ? Date.parse(props.initial.end) : end),
  }),
  localError = ref('');
function run() {
  if (props.pending || props.disabled) return;
  const start = Date.parse(scope.start),
    end = Date.parse(scope.end);
  if (
    !Number.isFinite(start) ||
    !Number.isFinite(end) ||
    local(start) !== (scope.start.length === 16 ? scope.start + ':00' : scope.start) ||
    local(end) !== (scope.end.length === 16 ? scope.end + ':00' : scope.end)
  ) {
    localError.value = '请选择有效的本机起止时间，精确到秒。';
    return;
  }
  const query: CorrelationRequest = {
    expected_revision: props.revision,
    start: new Date(start).toISOString(),
    end: new Date(end).toISOString(),
  };
  localError.value = correlationRequestError(query);
  if (!localError.value) emit('run', query);
}
function change(key: 'start' | 'end', value: string) {
  scope[key] = value;
  localError.value = '';
  emit('change');
}
</script>
<template>
  <a-form :model="scope" layout="horizontal" :disabled="pending || disabled" @finish="run">
    <ListFilters label="回测时间筛选" :columns="3">
      <a-form-item label="回测开始时间" html-for="correlation-start" required
        ><a-input
          id="correlation-start"
          :value="scope.start"
          type="datetime-local"
          step="1"
          @update:value="change('start', $event)" /></a-form-item
      ><a-form-item label="回测结束时间" html-for="correlation-end" required
        ><a-input
          id="correlation-end"
          :value="scope.end"
          type="datetime-local"
          step="1"
          @update:value="change('end', $event)"
      /></a-form-item>
      <template #actions>
        <PageHelp title="回测时间"
          ><p>
            单次范围最多一小时。输入采用本机时区，查询结束时刻不计入。{{ windowSeconds }} 秒窗口以 UTC
            对齐，阈值只按完整窗口计算。
          </p></PageHelp
        >
        <a-button type="primary" html-type="submit" :loading="pending" :disabled="disabled || pending"
          >运行回测</a-button
        ><a-button v-if="pending" :disabled="false" @click="emit('cancel')">停止等待</a-button>
      </template>
    </ListFilters>
  </a-form>
  <a-alert v-if="localError || error" type="error" show-icon :message="error || localError" class="section-gap" />
</template>
