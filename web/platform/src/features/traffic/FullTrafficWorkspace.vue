<script setup lang="ts">
import { computed, onScopeDispose, reactive, shallowRef, watch } from 'vue';
import { DownloadOutlined, SearchOutlined } from '@ant-design/icons-vue';
import { Select as ASelect } from 'ant-design-vue';
import { RouterLink } from 'vue-router';
import PageHeader from '@starbeacon/shared/components/PageHeader.vue';
import ListFilters from '@starbeacon/shared/components/ListFilters.vue';
import ListTable from '@starbeacon/shared/components/ListTable.vue';
import ListPager from '@starbeacon/shared/components/ListPager.vue';
import MetricBar from '@starbeacon/shared/components/MetricBar.vue';
import PacketInspector from '@starbeacon/shared/components/PacketInspector.vue';
import StatePanel from '@starbeacon/shared/components/StatePanel.vue';
import StatusTag from '@starbeacon/shared/components/StatusTag.vue';
import TimeRangeField from '@starbeacon/shared/components/TimeRangeField.vue';
import { defaultPageSize, pageSizeOptions } from '@starbeacon/shared/pagination.ts';
import { segmentRetentionLabels, retentionModes } from '@starbeacon/shared/packetRetention.ts';
import { formatTime, type MetricSpec } from '@starbeacon/shared/types.ts';
import { formatBytes } from '@starbeacon/shared/utils/format.ts';
import type { SegmentFlowSource } from '@starbeacon/shared/packetInspection.ts';
import { session } from '../../session';
import { usePacketStorage } from '../settings/usePacketStorage';
import { endpoint } from './traffic';
import {
  defaultFlowFilters,
  flowCSV,
  flowQuery,
  flowSource,
  flowWindows,
  validPacketFlowPage,
  type PacketFlowPage,
  type PacketFlowRow,
} from './packetFlows';

const fields = reactive(defaultFlowFilters());
const applied = shallowRef(flowQuery(fields, Date.now(), defaultPageSize));
const result = shallowRef<PacketFlowPage>({ items: [], page: 1, page_size: defaultPageSize, total: 0 });
const pending = shallowRef(true);
const error = shallowRef('');
const validation = shallowRef('');
const selected = shallowRef<SegmentFlowSource | null>(null);
const activeDownload = shallowRef('');
const downloadError = shallowRef('');
let downloader: AbortController | undefined;
let downloadURL = '';
let release: ReturnType<typeof setTimeout> | undefined;
const { settings, error: storageError } = usePacketStorage();
const choices = computed(() =>
  (settings.value?.sensors ?? []).map(item => ({ value: item.id, label: `${item.name} · ${item.id}` })),
);
const names = computed(() => new Map((settings.value?.sensors ?? []).map(row => [row.id, row.name])));
const policy = computed(() => {
  if (storageError.value) return '无近期观测';
  const sensors = (settings.value?.sensors ?? []).filter(
    row => !applied.value.sensor_id || row.id === applied.value.sensor_id,
  );
  const modes = new Set(
    sensors.flatMap(row => (row.fresh && row.status?.configuration ? [row.status.configuration.policy.mode] : [])),
  );
  if (modes.size === 0) return '无近期观测';
  if (modes.size > 1 || sensors.some(row => !row.fresh || !row.status?.configuration)) return '按采集器配置';
  return retentionModes[modes.values().next().value!];
});
const settingsLink = computed(() => ({
  path: '/system/settings',
  query: { section: 'traffic', ...(applied.value.sensor_id ? { sensor: applied.value.sensor_id } : {}) },
}));
const metrics = computed<MetricSpec[]>(() => {
  const { items, total } = result.value;
  const original = items.reduce((sum, item) => sum + BigInt(item.details.segment.original_bytes), 0n);
  const retained = items.reduce((sum, item) => sum + BigInt(item.details.segment.retained_bytes), 0n);
  return [
    { label: '匹配会话分段', value: total },
    { label: '本页观测字节', value: formatBytes(original, true) },
    { label: '本页留存字节', value: formatBytes(retained, true) },
    {
      label: '本页留存比例',
      value: original === 0n ? null : `${(Number((retained * 1000n) / original) / 10).toFixed(1)}%`,
      missingReason: '当前页暂无观测字节',
    },
  ];
});
const columns = [
  { title: '编号', dataIndex: 'event_id', width: 86, className: 'technical', ellipsis: true },
  { title: '首包时间', key: 'start', width: 154 },
  { title: '原包留存', key: 'retention', width: 134 },
  { title: '端点 A', key: 'source', width: 142, className: 'technical', ellipsis: true },
  { title: '端点 B', key: 'destination', width: 142, className: 'technical', ellipsis: true },
  { title: '协议', key: 'protocol', width: 58 },
  { title: '采集器', key: 'sensor', width: 100, ellipsis: true },
  { title: '观测字节', key: 'original', width: 84 },
  { title: '留存字节', key: 'retained', width: 84 },
  { title: '操作', key: 'action', width: 184, fixed: 'right' as const },
];
const retentions = Object.entries(segmentRetentionLabels).map(([value, label]) => ({ value, label }));
const tones = { retained: 'success', policy_truncated: 'warning', metadata_only: 'neutral' } as const;
const identity = computed(() =>
  [session.current.value?.id, session.current.value?.tenant_id, session.current.value?.role].join('/'),
);

watch(identity, () => reset());
watch(
  applied,
  async (query, _old, onCleanup) => {
    const operation = new AbortController();
    onCleanup(() => operation.abort());
    selected.value = null;
    stopDownload();
    pending.value = true;
    error.value = '';
    downloadError.value = '';
    result.value = { items: [], page: query.page, page_size: query.page_size, total: 0 };
    try {
      const value = await session.api.request<unknown>('/traffic/search', {
        method: 'POST',
        body: query,
        signal: operation.signal,
      });
      if (operation.signal.aborted) return;
      if (!validPacketFlowPage(value, query, session.current.value?.tenant_id ?? ''))
        throw new Error('会话分段与检索条件或归档来源不一致，请重试');
      result.value = value;
    } catch (e) {
      if (!operation.signal.aborted) error.value = e instanceof Error ? e.message : '会话分段检索失败';
    } finally {
      if (!operation.signal.aborted) pending.value = false;
    }
  },
  { immediate: true },
);

function search() {
  validation.value = '';
  try {
    applied.value = flowQuery(fields, Date.now(), applied.value.page_size);
  } catch (e) {
    validation.value = e instanceof Error ? e.message : '会话检索条件无效';
  }
}
function reset() {
  Object.assign(fields, defaultFlowFilters(), { sensor: undefined, retention: undefined });
  validation.value = '';
  applied.value = flowQuery(fields, Date.now(), defaultPageSize);
}
function changePage(page: number, size: number) {
  if (
    page >= 1 &&
    Number.isSafeInteger(page) &&
    pageSizeOptions.some(option => option === size) &&
    page * size <= 10000
  )
    applied.value = { ...applied.value, page, page_size: size };
}
function revokeFile() {
  if (downloadURL) URL.revokeObjectURL(downloadURL);
  downloadURL = '';
  clearTimeout(release);
}
function saveFile(blob: Blob, name: string) {
  revokeFile();
  downloadURL = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = downloadURL;
  link.download = name;
  link.click();
  release = setTimeout(revokeFile, 1000);
}
function stopDownload() {
  downloader?.abort();
  downloader = undefined;
  activeDownload.value = '';
  revokeFile();
}
async function download(row: PacketFlowRow) {
  const source = flowSource(row);
  if (!source || activeDownload.value) return;
  downloadError.value = '';
  const operation = new AbortController();
  downloader = operation;
  activeDownload.value = row.event_id;
  try {
    const blob = await session.api.downloadPacket(
      `/packet-archives/${source.archiveID}/flow-snapshot`,
      operation.signal,
      source,
    );
    if (!operation.signal.aborted) {
      const suffix = source.retention === 'policy_truncated' ? '-partial' : '';
      saveFile(blob, `snapshot-${row.event_id}${suffix}.pcapng`);
    }
  } catch (e) {
    if (!operation.signal.aborted) downloadError.value = e instanceof Error ? e.message : '会话快照下载失败';
  } finally {
    if (!operation.signal.aborted) activeDownload.value = '';
  }
}
function exportPage() {
  if (!pending.value && !error.value && result.value.items.length)
    saveFile(
      new Blob(['\uFEFF', flowCSV(result.value.items)], { type: 'text/csv;charset=utf-8' }),
      'starbeacon-session-segments.csv',
    );
}
onScopeDispose(stopDownload);
</script>

<template>
  <PageHeader
    title="全流量回溯"
    description="按时间和双向五元组查找会话分段。端点 A 与 B 采用固定排序，流向没有经过核验。"
    notice="每行对应一个采集窗口。查询使用分段末包时间，留存状态表示窗口内捕获字节的策略结果。快照下载仅包含该分段实际留存的报文。"
  >
    <span class="muted">当前留存策略 {{ policy }}</span>
    <RouterLink :to="settingsLink">全流量存储</RouterLink>
    <a-button :disabled="pending || !!error || !result.items.length" @click="exportPage"
      ><DownloadOutlined />导出本页</a-button
    >
  </PageHeader>
  <MetricBar v-if="!pending && !error" :items="metrics" />

  <ListFilters label="会话检索" wide>
    <TimeRangeField v-model:preset="fields.hours" :preset-options="flowWindows" label="时间" />
    <label
      ><span>端点 A</span
      ><a-input
        v-model:value="fields.a"
        aria-label="端点 A"
        placeholder="IP、网段或 IP:端口"
        :maxlength="80"
        allow-clear
        @press-enter="search"
    /></label>
    <label
      ><span>端点 B</span
      ><a-input
        v-model:value="fields.b"
        aria-label="端点 B"
        placeholder="IP、网段或 IP:端口"
        :maxlength="80"
        allow-clear
        @press-enter="search"
    /></label>
    <label
      ><span>原包留存</span
      ><ASelect
        v-model:value="fields.retention"
        aria-label="原包留存"
        placeholder="全部"
        :options="retentions"
        allow-clear
    /></label>
    <template #actions>
      <a-button type="primary" :loading="pending" @click="search"><SearchOutlined />查询</a-button>
      <a-button @click="reset">重置</a-button>
    </template>
    <template #advanced>
      <TimeRangeField v-if="fields.hours === 0" v-model:start="fields.start" v-model:end="fields.end" required />
      <label v-if="choices.length"
        ><span>采集器</span
        ><ASelect v-model:value="fields.sensor" aria-label="采集器" placeholder="全部" :options="choices" allow-clear
      /></label>
    </template>
  </ListFilters>
  <a-alert
    v-if="validation || downloadError"
    class="section-gap"
    type="error"
    show-icon
    :message="validation || downloadError"
  />
  <a-alert
    v-if="result.total > 10000"
    type="info"
    class="section-gap"
    message="列表可浏览前 10,000 条。请缩小范围后检索。"
    show-icon
  />
  <section class="panel">
    <div class="panel-header"><h2>会话分段</h2></div>
    <StatePanel
      :loading="pending"
      :error="error"
      :empty="!result.items.length"
      title="没有找到会话分段"
      description="请确认采集器已上传原包，或调整检索条件。"
      @retry="applied = { ...applied }"
    >
      <ListTable :columns="columns" :data-source="result.items" row-key="event_id" :scroll="{ x: 1168 }">
        <template #bodyCell="{ column, record }">
          <template v-if="column.key === 'start'">{{ formatTime(record.details.segment.first_observed) }}</template>
          <template v-else-if="column.key === 'source' || column.key === 'destination'">
            <span :title="endpoint(record[column.key].ip, record[column.key].port)">{{
              endpoint(record[column.key].ip, record[column.key].port)
            }}</span>
          </template>
          <template v-else-if="column.key === 'protocol'">{{ record.network.transport?.toUpperCase() }}</template>
          <span v-else-if="column.key === 'sensor'" :title="record.sensor_id">{{
            names.get(record.sensor_id) ?? record.sensor_id
          }}</span>
          <template v-else-if="column.key === 'original'">{{
            formatBytes(record.details.segment.original_bytes, true)
          }}</template>
          <template v-else-if="column.key === 'retained'">{{
            formatBytes(record.details.segment.retained_bytes, true)
          }}</template>
          <StatusTag
            v-else-if="column.key === 'retention'"
            :value="segmentRetentionLabels[record.details.segment.retention]"
            :tone="tones[record.details.segment.retention]"
          />
          <template v-else-if="column.key === 'action'">
            <span v-if="record.details.segment.retention === 'metadata_only'" class="muted">无留存报文</span>
            <span v-else class="row-actions">
              <a-button size="small" type="link" @click="selected = flowSource(record)">逐包查看</a-button>
              <a-button
                size="small"
                type="link"
                :loading="activeDownload === record.event_id"
                :disabled="!!activeDownload"
                @click="download(record)"
              >
                {{ record.details.segment.retention === 'policy_truncated' ? '下载留存报文' : '下载快照' }}
              </a-button>
            </span>
          </template>
        </template>
      </ListTable>
    </StatePanel>
    <ListPager
      :page="result.page"
      :page-size="result.page_size"
      :total="Math.min(result.total, 10000)"
      :disabled="pending || !!error"
      @change="changePage"
    />
  </section>
  <PacketInspector :api="session.api" :record="null" :flow="selected" @close="selected = null">
    <template #notice>
      <a-alert
        v-if="selected?.retention === 'policy_truncated'"
        type="warning"
        message="此会话按策略截断，逐包查看仅包含实际留存的报文。"
        show-icon
        class="section-gap"
      />
    </template>
  </PacketInspector>
</template>
