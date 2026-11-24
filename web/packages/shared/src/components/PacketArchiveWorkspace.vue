<script setup lang="ts">
import { useFeedback } from '../composables/useFeedback';
import { computed, onScopeDispose, ref, shallowRef, watch } from 'vue';
import type { TableRowSelection } from 'ant-design-vue/es/table/interface';
import type { ApiClient } from '../api';
import { tablePagination } from '../pagination';
import { statusTone } from '../statusTones';
import {
  packetCapture,
  packetUnsealed,
  packetStates,
  packetTones,
  packetCodes,
  canDownloadPacket,
  type PacketRecord,
} from '../packetArchives';
import { usePacketArchives } from '../usePacketArchives';
import { formatNumber, formatBytes } from '../utils/format';
import { formatTime } from '../types';
import StatePanel from './StatePanel.vue';
import PageHelp from './PageHelp.vue';
import ListFilters from './ListFilters.vue';
import ListTable from './ListTable.vue';
import ListPager from './ListPager.vue';
import StatusTag from './StatusTag.vue';
import MetricBar from './MetricBar.vue';
import PacketArchiveDetail from './PacketArchiveDetail.vue';
import SessionExportDialog from './SessionExportDialog.vue';
import PacketInspector from './PacketInspector.vue';
const message = useFeedback();
const props = defineProps<{ api: ApiClient; local?: boolean }>();
const {
  page,
  pending,
  error,
  selected,
  detailPending,
  detailError,
  cursors,
  pageSize,
  changePageSize,
  view,
  close,
  refresh,
  filter,
  next,
  previous,
} = usePacketArchives(props.api, props.local);
const sensor = ref(''),
  downloading = shallowRef(''),
  downloadError = shallowRef('');
const exportIDs = shallowRef<string[]>([]),
  exportOpen = shallowRef(false);
const inspecting = shallowRef<PacketRecord | null>(null);
const exportArchives = computed(() => page.value.items.filter(row => exportIDs.value.includes(row.id)));
const rowSelection = computed<TableRowSelection<PacketRecord> | undefined>(() =>
  props.local
    ? undefined
    : {
        selectedRowKeys: exportIDs.value,
        hideSelectAll: true,
        getCheckboxProps: row => ({
          disabled: row.state !== 'ready' || (exportIDs.value.length >= 16 && !exportIDs.value.includes(row.id)),
        }),
        onChange: keys => {
          exportIDs.value = keys.map(String).slice(0, 16);
        },
      },
);
watch(
  () => page.value.items,
  () => {
    exportIDs.value = [];
    exportOpen.value = false;
    inspecting.value = null;
  },
);
let downloadController: AbortController | undefined,
  downloadURL = '',
  revokeTimer: ReturnType<typeof setTimeout> | undefined;
function revoke() {
  if (revokeTimer) clearTimeout(revokeTimer);
  if (downloadURL) URL.revokeObjectURL(downloadURL);
  downloadURL = '';
}
async function download(row: PacketRecord) {
  if (downloading.value || !canDownloadPacket(row)) return;
  downloadError.value = '';
  downloading.value = row.id;
  const controller = new AbortController();
  downloadController = controller;
  try {
    const blob = await props.api.downloadPacket(
      '/packet-archives/' + encodeURIComponent(row.id) + '/download',
      controller.signal,
    );
    if (controller.signal.aborted) return;
    revoke();
    downloadURL = URL.createObjectURL(blob);
    const anchor = document.createElement('a');
    anchor.href = downloadURL;
    anchor.download = row.id + '.pcapng';
    document.body.append(anchor);
    anchor.click();
    anchor.remove();
    revokeTimer = setTimeout(revoke, 1000);
    message.success('原包已通过摘要校验，下载已开始');
  } catch (e) {
    if (!controller.signal.aborted) downloadError.value = e instanceof Error ? e.message : '原包下载失败，请稍后重试';
  } finally {
    if (!controller.signal.aborted) downloading.value = '';
  }
}
onScopeDispose(() => {
  downloadController?.abort();
  revoke();
});
const columns = [
  { title: '归档编号', dataIndex: 'id', width: 145, className: 'technical', ellipsis: true },
  { title: '归档状态', key: 'state', width: 127 },
  { title: '探针编号', key: 'sensor', width: 140, className: 'technical', ellipsis: true },
  { title: '网卡', key: 'interface', width: 125, ellipsis: true },
  { title: '捕获开始', key: 'time', width: 170 },
  { title: '包数', key: 'packets', width: 103, ellipsis: true },
  { title: '截断包数', key: 'truncated', width: 108, ellipsis: true },
  { title: props.local ? '暂存预留' : '原始大小', key: 'size', width: 106 },
  ...(!props.local ? [{ title: '存储大小', key: 'stored', width: 140, ellipsis: true }] : []),
  { title: '操作', key: 'actions', width: 200, fixed: 'right' as const },
];
function inspect(row: PacketRecord) {
  if (canDownloadPacket(row) && packetCapture(row).packets) {
    close();
    exportOpen.value = false;
    inspecting.value = row;
  }
}
</script>
<template>
  <form v-if="!local" @submit.prevent="filter(sensor)">
    <ListFilters label="原包筛选" :columns="2">
      <label
        ><span>接入探针</span
        ><a-input
          v-model:value="sensor"
          placeholder="按探针标识筛选"
          aria-label="原包探针标识"
          :maxlength="64"
          :disabled="pending"
          allow-clear
      /></label>
      <template #actions>
        <a-button type="primary" html-type="submit" :disabled="pending">筛选</a-button
        ><a-button
          :disabled="pending"
          @click="
            sensor = '';
            filter('');
          "
          >重置</a-button
        >
      </template>
    </ListFilters>
  </form>
  <a-alert v-if="downloadError" type="error" show-icon :message="downloadError" class="section-gap" />
  <a-alert
    v-if="!pending && !error && !page.available"
    type="info"
    show-icon
    message="原包归档未配置。请核对平台对象存储与采集器的独立原包捕获配置。"
    class="section-gap"
  />
  <a-alert
    v-else-if="local && page.health?.code"
    type="warning"
    show-icon
    :message="packetCodes[page.health.code] ?? '原包捕获状态需要核查，请保留本机原件。'"
    class="section-gap"
  />
  <section class="panel">
    <div class="table-toolbar">
      <div>
        <h2>归档记录</h2>
        <PageHelp title="归档记录">
          <p v-if="local">本机展示最近 200 条捕获与确认记录。平台持久确认后本机回收原件，已归档数据可在主平台查询。</p>
          <p v-else>默认留存 180 天，具体到期时间按归档时生效的留存策略确定。</p>
          <p>单个切片只覆盖实际捕获的时间段，完整连接可能跨多个切片。</p>
        </PageHelp>
        <StatusTag
          v-if="local && page.health"
          :value="packetStates[page.health.state] ?? '状态待核查'"
          :tone="statusTone(packetTones, page.health.state)"
        />
      </div>
      <div class="table-row-actions">
        <a-button v-if="!local" :disabled="pending || !!error || !exportArchives.length" @click="exportOpen = true"
          >会话导出{{ exportArchives.length ? `（${exportArchives.length}）` : '' }}</a-button
        >
        <a-button :loading="pending" @click="refresh">刷新原包</a-button>
      </div>
    </div>
    <MetricBar
      v-if="local && page.health"
      embedded
      :items="[
        { label: '已预留', value: formatBytes(page.health.reserved_bytes) },
        { label: '暂存额度', value: formatBytes(page.health.quota_bytes) },
      ]"
    />
    <StatePanel
      :loading="pending"
      :error="error"
      :empty="!page.items.length"
      description="暂无原包归档。请核对网卡、捕获过滤器、暂存额度和平台连接状态。"
      @retry="refresh"
    >
      <ListTable
        :columns="columns"
        :data-source="page.items"
        :row-selection="rowSelection"
        row-key="id"
        :pagination="local ? tablePagination() : false"
        :scroll="{ x: local ? 1224 : 1400 }"
        ><template #bodyCell="{ column, record }">
          <StatusTag
            v-if="column.key === 'state'"
            :value="packetStates[record.state]"
            :tone="statusTone(packetTones, record.state)"
          />
          <template v-else-if="column.key === 'sensor'">{{ packetCapture(record).sensor_id }}</template>
          <span v-else-if="column.key === 'interface'" :title="packetCapture(record).interface_mac">
            {{ packetCapture(record).interface }}
          </span>
          <template v-else-if="column.key === 'packets'"
            ><span v-if="packetUnsealed(record)" title="包数与完整性尚未冻结">待封存 · 包数与完整性尚未冻结</span>
            <template v-else>{{ formatNumber(packetCapture(record).packets) }} 包</template>
          </template>
          <template v-else-if="column.key === 'truncated'">{{
            packetUnsealed(record) ? '—' : formatNumber(packetCapture(record).truncated_packets)
          }}</template>
          <template v-else-if="column.key === 'size'">{{
            formatBytes(local ? record.reserved_bytes : record.raw_bytes)
          }}</template>
          <template v-else-if="column.key === 'stored'"
            >{{ formatBytes(record.stored_bytes) }} · {{ record.codec }}</template
          >
          <template v-else-if="column.key === 'time'">{{ formatTime(packetCapture(record).started_at) }}</template>
          <div v-else-if="column.key === 'actions'" class="table-row-actions">
            <a-button type="link" size="small" @click="view(record)">查看</a-button
            ><a-button
              type="link"
              size="small"
              :disabled="!canDownloadPacket(record) || !packetCapture(record).packets"
              @click="inspect(record)"
              >协议查看</a-button
            ><a-button
              type="link"
              size="small"
              :disabled="!canDownloadPacket(record) || !!downloading"
              :loading="downloading === record.id"
              @click="download(record)"
              >下载</a-button
            >
          </div>
        </template></ListTable
      >
    </StatePanel>
    <ListPager
      v-if="!local"
      mode="cursor"
      :page="cursors.length"
      :page-size="pageSize"
      :count="error ? undefined : page.items.length"
      :has-previous="cursors.length > 1"
      :has-next="!error && !!page.next"
      :disabled="pending"
      @previous="previous"
      @next="next"
      @update:page-size="changePageSize"
    />
  </section>
  <PacketArchiveDetail
    :record="selected"
    :local="local"
    :pending="detailPending"
    :error="detailError"
    @close="close"
    @retry="selected && view(selected)"
  />
  <SessionExportDialog
    v-if="!local"
    :api="api"
    :archives="exportArchives"
    :open="exportOpen"
    @close="exportOpen = false"
  />
  <PacketInspector :api="api" :record="inspecting" @close="inspecting = null" />
</template>
