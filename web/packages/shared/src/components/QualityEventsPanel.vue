<script setup lang="ts">
import { formatNumber } from '../utils/format';
import { shallowRef, watch } from 'vue';
import { Modal as AModal } from 'ant-design-vue';
import { qualityCounters } from '../detectionQuality';
import { qualityEventNames, type QualityEvent, type QualityPage } from '../qualityEvents';
import { formatTime } from '../types';
import StatePanel from './StatePanel.vue';
import DetectionQuality from './DetectionQuality.vue';
import ListTable from './ListTable.vue';
import ListPager from './ListPager.vue';
import MetricBar from './MetricBar.vue';
import PageHelp from './PageHelp.vue';
import StatusTag from './StatusTag.vue';
const props = defineProps<{
  result: QualityPage | null;
  pending: boolean;
  error: string;
  attempted: boolean;
  initialID?: string;
}>();
const emit = defineEmits<{ retry: []; page: [value: number, size: number] }>();
const selected = shallowRef<QualityEvent | null>(null);
watch(
  () => [props.result, props.initialID],
  () => {
    selected.value = props.result?.items.find(row => row.id === props.initialID) ?? null;
  },
  { immediate: true },
);
const columns = [
  { title: '事件编号', dataIndex: 'id', width: 142, className: 'technical', ellipsis: true },
  { title: '记录时间', key: 'created', width: 175, className: 'technical' },
  { title: '探针编号', dataIndex: 'sensor_id', width: 130, className: 'technical', ellipsis: true },
  { title: '注册代次', dataIndex: 'sensor_registration_id', width: 130, className: 'technical', ellipsis: true },
  { title: '事件类型', key: 'kind', width: 165 },
  { title: '持续提醒', key: 'reminder', width: 110 },
  { title: '区间原因', key: 'reasons', width: 225, ellipsis: true },
  { title: '操作', key: 'actions', width: 70, fixed: 'right' as const },
];
const kindTones = {
  limitation: 'warning',
  policy: 'info',
  uncertain: 'warning',
  interval_clear: 'neutral',
  observation_resumed: 'neutral',
} as const satisfies Record<QualityEvent['signal']['kind'], import('../terms').StatusTone>;
const reason = (key: string) =>
  Object.hasOwn(qualityCounters, key)
    ? qualityCounters[key as keyof typeof qualityCounters][0]
    : ((
        {
          counter_reset: '计数器复位',
          sample_gap: '采样中断',
          stale: '观测过期',
          stopped: '引擎未运行',
          continuous_interval: '建立连续观测区间',
        } as Record<string, string>
      )[key] ?? key);
</script>
<template>
  <section v-if="!selected" class="panel table-panel quality-history">
    <div class="table-toolbar">
      <div class="heading-with-help">
        <h2>质量事件</h2>
        <PageHelp title="质量事件"
          ><p>记录托管引擎的区间质量变化和持续提醒。事件异步入库，最多检索前 10,000 条。</p>
          <p>采样缺失、计数器复位和外部 EVE 的检测覆盖需要独立核对。</p></PageHelp
        >
      </div>
      <MetricBar v-if="result" embedded :items="[{ label: '匹配事件', value: formatNumber(BigInt(result.total)) }]" />
    </div>
    <StatePanel
      :loading="pending"
      :error="error"
      :empty="!result || !result.items.length"
      :description="
        attempted
          ? '当前范围没有可列出的质量事件。请核对探针管理模式、时间窗口及索引状态；空结果不证明检测完整。'
          : '选择时间窗口与筛选条件后查询。'
      "
      @retry="emit('retry')"
    >
      <ListTable :columns="columns" :data-source="result?.items ?? []" :scroll="{ x: 1147 }"
        ><template #bodyCell="{ column, record }">
          <time v-if="column.key === 'created'" :datetime="record.created_at">{{ formatTime(record.created_at) }}</time>
          <StatusTag
            v-else-if="column.key === 'kind'"
            :tone="kindTones[record.signal.kind]"
            :value="qualityEventNames[record.signal.kind]"
          />
          <template v-else-if="column.key === 'reminder'">{{ record.signal.reminder ? '持续状态提醒' : '—' }}</template>
          <span v-else-if="column.key === 'reasons'" :title="record.signal.reasons.map(reason).join('、')">{{
            record.signal.reasons.map(reason).join('、')
          }}</span>
          <button v-else-if="column.key === 'actions'" type="button" class="record-link" @click="selected = record">
            详情
          </button>
        </template></ListTable
      >
      <ListPager
        v-if="result"
        :page="result.page"
        :page-size="result.page_size"
        :total="Math.min(Number(result.total), 10000)"
        @change="(page, size) => emit('page', page, size)"
      />
    </StatePanel>
  </section>
  <a-modal v-if="selected" open title="质量事件详情" :width="920" @cancel="selected = null">
    <a-alert
      type="info"
      show-icon
      message="历史区间快照"
      description="详情保留当时的统计区间，不代表探针当前状态。原限制未再报告增量不等于补回丢包或恢复全部检测能力。"
      class="section-gap"
    />
    <dl class="quality-event-facts">
      <dt>事件类型</dt>
      <dd>
        <StatusTag :tone="kindTones[selected.signal.kind]" :value="qualityEventNames[selected.signal.kind]" />
        <span v-if="selected.signal.reminder">持续状态提醒</span>
      </dd>
      <dt>区间原因</dt>
      <dd>{{ selected.signal.reasons.map(reason).join('、') }}</dd>
      <dt>事件标识</dt>
      <dd>
        <code>{{ selected.id }}</code>
      </dd>
      <dt>探针 / 注册代次</dt>
      <dd>{{ selected.sensor_id }} / {{ selected.sensor_registration_id }}</dd>
      <dt>平台记录时间</dt>
      <dd>
        <time :datetime="selected.created_at">{{ formatTime(selected.created_at) }}</time>
      </dd>
      <dt>平台接收时的观测时间</dt>
      <dd>
        <time :datetime="selected.report.evaluated_at">{{ formatTime(selected.report.evaluated_at) }}</time>
      </dd>
      <dt v-if="selected.signal.prior_event_id">关联先前事件</dt>
      <dd v-if="selected.signal.prior_event_id">
        <code>{{ selected.signal.prior_event_id }}</code>
      </dd>
    </dl>
    <DetectionQuality
      :capture="{ status: 'running', config_sha256: selected.report.config_sha256, quality: selected.report }"
      historical
    />
    <template #footer
      ><div class="filter-actions quality-close"><a-button @click="selected = null">返回列表</a-button></div></template
    >
  </a-modal>
</template>
<style scoped>
.quality-event-facts {
  display: grid;
  grid-template-columns: 155px minmax(0, 1fr);
  gap: 8px 12px;
  margin: 12px 0;
}
.quality-event-facts dt {
  color: var(--muted);
}
.quality-event-facts dd {
  margin: 0;
  overflow-wrap: anywhere;
}
.quality-close {
  justify-content: flex-end;
}
</style>
