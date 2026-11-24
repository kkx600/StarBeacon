<script setup lang="ts">
import { computed, shallowRef, watch } from 'vue';
import { Modal as AModal, Descriptions as ADescriptions, DescriptionsItem as ADescriptionsItem } from 'ant-design-vue';
import {
  correlationFields,
  correlationStates,
  type CorrelationDefinition,
  type CorrelationResult,
  type CorrelationWindow,
} from '../correlation';
import { formatTime } from '../types';
import ListTable from './ListTable.vue';
import MetricBar from './MetricBar.vue';
import StatusTag from './StatusTag.vue';
import { tablePagination } from '../pagination';
import { statusTone, type StatusToneMap } from '../statusTones';
const props = defineProps<{ result: CorrelationResult; definition: CorrelationDefinition; detailID?: string }>(),
  emit = defineEmits<{ close: [] }>();
const selected = shallowRef<CorrelationWindow | null>(null),
  copyError = shallowRef('');
watch(
  () => [props.result, props.detailID],
  () => {
    selected.value = props.result.windows.find(w => w.detection_id === props.detailID) ?? null;
    copyError.value = '';
  },
  { immediate: true },
);
const rows = computed(() => props.result.windows),
  columns = [
    { title: '窗口编号', dataIndex: 'detection_id', width: 150, ellipsis: true, className: 'technical' },
    { title: '窗口开始', key: 'start', width: 172, className: 'technical' },
    { title: '窗口结束', key: 'end', width: 172, className: 'technical' },
    { title: '探针编号', dataIndex: 'sensor_id', width: 142, ellipsis: true, className: 'technical' },
    { title: '注册代次', dataIndex: 'sensor_registration_id', width: 142, ellipsis: true, className: 'technical' },
    { title: '分组值', dataIndex: 'group_value', width: 160, ellipsis: true, className: 'technical' },
    { title: '告警条数', dataIndex: 'count', width: 100 },
    { title: '计量值 / 阈值', key: 'metric', width: 145 },
    { title: '计量缺失', dataIndex: 'missing_metric', width: 92 },
    { title: '窗口状态', key: 'status', width: 150 },
    { title: '操作', key: 'action', width: 100, fixed: 'right' as const },
  ];
const windowTones = {
  threshold_observed: 'warning',
  threshold_not_observed: 'neutral',
  partial_window: 'info',
} as const satisfies StatusToneMap;
function close() {
  selected.value = null;
  copyError.value = '';
  emit('close');
}
async function copy(value: string) {
  copyError.value = '';
  try {
    if (!navigator.clipboard) throw new Error();
    await navigator.clipboard.writeText(value);
  } catch {
    copyError.value = '无法访问剪贴板，请手动选择并复制事件标识。';
  }
}
</script>
<template>
  <MetricBar
    embedded
    :items="[
      { label: '唯一告警', value: result.unique_events },
      { label: '回测输入去重', value: result.duplicate_events },
      { label: '分组字段缺失', value: result.missing_group },
      { label: '观察到阈值的窗口', value: result.threshold_windows, tone: 'warning' },
      { label: '边界窗口', value: result.partial_windows },
    ]"
  />
  <ListTable
    :columns="columns"
    :data-source="rows"
    row-key="detection_id"
    :pagination="tablePagination()"
    :scroll="{ x: 1525 }"
    ><template #bodyCell="{ column, record }"
      ><template v-if="column.key === 'start'">{{ formatTime(record.start) }}</template>
      <template v-else-if="column.key === 'end'">{{ formatTime(record.end) }}</template>
      <template v-else-if="column.key === 'metric'">{{ record.metric_value }} / {{ definition.threshold }}</template>
      <StatusTag
        v-else-if="column.key === 'status'"
        :tone="statusTone(windowTones, record.status)"
        :value="correlationStates[record.status]"
      />
      <button
        v-else-if="column.key === 'action'"
        type="button"
        class="record-link"
        @click="
          selected = record;
          copyError = '';
        "
      >
        查看证据
      </button></template
    ><template #emptyText><span>快照中没有可计入窗口的告警，此结果不代表流量安全。</span></template></ListTable
  >
  <a-modal
    v-if="selected"
    :open="true"
    title="窗口证据"
    :width="820"
    :body-style="{ maxHeight: 'calc(100vh - 240px)', overflowY: 'auto' }"
    @cancel="close"
    ><a-alert
      type="info"
      show-icon
      message="窗口只描述检索快照中已观察到的事实；来源覆盖未经证明，不据此认定攻击成功或授予处置权限。"
      class="section-gap"
    /><a-descriptions bordered :column="1" size="small"
      ><a-descriptions-item label="窗口状态"
        ><StatusTag
          :tone="statusTone(windowTones, selected.status)"
          :value="correlationStates[selected.status]" /></a-descriptions-item
      ><a-descriptions-item label="探针 / 注册代次"
        >{{ selected.sensor_id }} / {{ selected.sensor_registration_id }}</a-descriptions-item
      ><a-descriptions-item :label="correlationFields[definition.group_by]">{{
        selected.group_value
      }}</a-descriptions-item
      ><a-descriptions-item label="时间区间"
        >{{ formatTime(selected.start) }} — {{ formatTime(selected.end) }}，结束时间不计入</a-descriptions-item
      ><a-descriptions-item label="计量 / 阈值"
        >{{ selected.metric_value }} / {{ definition.threshold }}；{{ selected.count }} 条唯一告警，{{
          selected.missing_metric
        }}
        条计量值未知</a-descriptions-item
      ><a-descriptions-item label="窗口标识"
        ><span class="technical correlation-wrap">{{ selected.detection_id }}</span></a-descriptions-item
      ><a-descriptions-item label="完整证据集合摘要"
        ><span class="technical correlation-wrap">{{ selected.evidence_sha256 }}</span></a-descriptions-item
      ></a-descriptions
    >
    <h3 class="correlation-evidence-title">证据样本 · {{ selected.evidence.length }} / {{ selected.count }}</h3>
    <p class="page-description">
      {{
        selected.evidence_truncated
          ? '当前展示按事件标识排序的前 8 条证据；计量和摘要包含全部窗口事实。'
          : '当前展示全部窗口证据。'
      }}
      相同标识的补证据不形成新的窗口身份。
    </p>
    <a-alert v-if="copyError" type="warning" show-icon :message="copyError" class="section-gap" />
    <ol class="correlation-evidence">
      <li v-for="item in selected.evidence" :key="item.event_id">
        <div class="correlation-evidence-header">
          <strong class="technical correlation-wrap">{{ item.event_id }}</strong><a-button
            size="small"
            @click="copy(item.event_id)"
            >复制事件标识</a-button
          >
        </div>
        <span>{{ formatTime(item.timestamp) }}</span>
        <div class="page-description technical correlation-wrap">原文 SHA-256：{{ item.raw_sha256 }}</div>
      </li>
    </ol>
    <template #footer><a-button @click="close">关闭</a-button></template></a-modal
  >
</template>
<style scoped>
:deep(.ant-descriptions-item-content) {
  overflow-wrap: anywhere;
}
.correlation-wrap {
  overflow-wrap: anywhere;
}
.correlation-evidence-title {
  font-size: 14px;
  margin: 14px 0 8px;
}
.correlation-evidence {
  padding-left: 20px;
  margin: 8px 0;
}
.correlation-evidence li {
  padding: 10px 0;
  border-bottom: 1px solid var(--line);
}
.correlation-evidence-header {
  display: flex;
  gap: 8px;
  align-items: flex-start;
  justify-content: space-between;
}
.correlation-evidence-header > strong {
  min-width: 0;
}
.correlation-evidence-header > .ant-btn {
  flex-shrink: 0;
}
</style>
