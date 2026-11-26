<script setup lang="ts">
import { computed, onScopeDispose, shallowRef } from 'vue';
import { RouterLink } from 'vue-router';
import { Button as AButton, Descriptions as ADescriptions, Modal as AModal, Table as ATable } from 'ant-design-vue';
import ListPager from '@starbeacon/shared/components/ListPager.vue';
import MetricBar from '@starbeacon/shared/components/MetricBar.vue';
import PageHeader from '@starbeacon/shared/components/PageHeader.vue';
import StatePanel from '@starbeacon/shared/components/StatePanel.vue';
import StatusTag from '@starbeacon/shared/components/StatusTag.vue';
import type { StatusTone } from '@starbeacon/shared/terms.ts';
import { formatTime, taskStates, type MetricSpec } from '@starbeacon/shared/types.ts';
import {
  formatGatewayFlow,
  gatewayCodes,
  readGatewayRecord,
  readGatewayRecords,
  type GatewayRecord,
} from '../features/gateway/gatewayBlocks';
import { useGatewayPage } from '../features/gateway/useGatewayPage';

const { data, cursors, loading, error, pageSize, changePageSize, next, previous, reload } =
  useGatewayPage(readGatewayRecords);
const items = computed(() => data.value?.items ?? []);
const current = computed(() => (loading.value || error.value ? undefined : data.value));
const metrics = computed<MetricSpec[]>(() => [
  { label: '近 24 小时请求', value: current.value?.last_day.total ?? '—' },
  { label: '流量暂停', value: current.value?.last_day.paused ?? '—' },
  { label: '仍有流量', value: current.value?.last_day.continued ?? '—', tone: 'warning' },
  { label: '结果未知', value: current.value?.last_day.unknown ?? '—' },
  { label: '保护名单命中', value: current.value?.last_day.protected ?? '—' },
]);
const columns = [
  { key: 'time', title: '登记时间', width: 160 },
  { key: 'flow', title: '连接', width: 285 },
  { key: 'policy', title: '策略与触发', width: 185 },
  { key: 'firewall', title: '防火墙回读', width: 115 },
  { key: 'observation', title: '流量观察', width: 105 },
  { key: 'followUp', title: '联动封禁', width: 125 },
  { key: 'view', title: '操作', width: 75 },
];
const observationStatus: Record<string, { value: string; tone: StatusTone }> = {
  paused: { value: '流量暂停', tone: 'success' },
  continued: { value: '仍有流量', tone: 'warning' },
  unknown: { value: '结果未知', tone: 'warning' },
  '': { value: '暂无观察', tone: 'neutral' },
};
const followUpStatus: Record<GatewayRecord['follow_up_state'], { value: string; tone: StatusTone }> = {
  none: { value: '未预授权', tone: 'neutral' },
  pending: { value: '复核中', tone: 'info' },
  issued: { value: '任务已签发', tone: 'info' },
  skipped: { value: '未签发', tone: 'warning' },
};
const triggers = { rule: '规则即时触发', review: '研判后触发' };

function firewall(record: GatewayRecord): { value: string; tone: StatusTone } {
  if (record.gateway_result) return { value: '已回读', tone: 'success' };
  if (record.state === 'denied') return { value: '已拒绝', tone: 'warning' };
  if (record.state === 'pending') return { value: '待授权', tone: 'info' };
  return { value: taskStates[record.task_state ?? ''] ?? '暂无回读', tone: 'neutral' };
}
function observation(record: GatewayRecord) {
  return observationStatus[record.gateway_result?.observation?.state ?? '']!;
}

const detailID = shallowRef('');
const detail = shallowRef<GatewayRecord>();
const detailPending = shallowRef(false);
const detailError = shallowRef('');
const result = computed(() => detail.value?.gateway_result);
const inspected = computed(() => result.value?.observation);
let detailRequest: AbortController | undefined;
async function openDetail(id: string) {
  detailRequest?.abort();
  const current = new AbortController();
  detailRequest = current;
  detailID.value = id;
  detail.value = undefined;
  detailPending.value = true;
  detailError.value = '';
  try {
    const record = await readGatewayRecord(id, current.signal);
    if (!current.signal.aborted) detail.value = record;
  } catch (err) {
    if (!current.signal.aborted) detailError.value = err instanceof Error ? err.message : '记录读取失败。';
  } finally {
    if (detailRequest === current) detailPending.value = false;
  }
}
function closeDetail() {
  detailRequest?.abort();
  detailID.value = '';
}
onScopeDispose(() => detailRequest?.abort());
</script>

<template>
  <PageHeader title="网关阻断" description="核对连接阻断、防火墙条目回读、出侧流量观察和后续设备任务。">
    <RouterLink to="/response/actions">响应动作</RouterLink>
    <RouterLink :to="{ path: '/system/settings', query: { section: 'gateway-block' } }">网关阻断设置</RouterLink>
    <AButton :loading="loading" @click="reload">刷新记录</AButton>
  </PageHeader>
  <MetricBar :items="metrics" />
  <section class="panel table-panel">
    <div class="table-toolbar">
      <h2>阻断记录</h2>
      <div v-if="current" class="gateway-status">
        <StatusTag :value="current.enabled ? '已启用' : '已停用'" :tone="current.enabled ? 'success' : 'neutral'" />
        <span>可用网关 {{ current.online_gateways }} 台</span>
      </div>
    </div>
    <StatePanel
      :loading="loading"
      :error="error"
      :empty="!items.length"
      description="当前没有网关阻断请求。"
      @retry="reload"
    >
      <ATable
        :columns="columns"
        :data-source="items"
        row-key="id"
        :pagination="false"
        :scroll="{ x: 1050 }"
        size="small"
      >
        <template #bodyCell="{ column, record }">
          <span v-if="column.key === 'time'" class="mono">{{ formatTime(record.created_at) }}</span>
          <template v-else-if="column.key === 'flow'">
            <div class="mono">{{ formatGatewayFlow(record.flow) }}</div>
            <small>{{ record.flow.transport.toUpperCase() }} · {{ record.sensor_id }}</small>
          </template>
          <template v-else-if="column.key === 'policy'">
            <div class="mono">{{ record.policy_id }} · v{{ record.policy_revision }}</div>
            <small>{{ triggers[record.trigger as keyof typeof triggers] }}</small>
          </template>
          <StatusTag v-else-if="column.key === 'firewall'" v-bind="firewall(record as GatewayRecord)" />
          <StatusTag v-else-if="column.key === 'observation'" v-bind="observation(record as GatewayRecord)" />
          <StatusTag
            v-else-if="column.key === 'followUp'"
            v-bind="followUpStatus[record.follow_up_state as GatewayRecord['follow_up_state']]"
          />
          <AButton v-else-if="column.key === 'view'" type="link" size="small" @click="openDetail(record.id)"
            >详情</AButton
          >
        </template>
      </ATable>
    </StatePanel>
    <ListPager
      mode="cursor"
      :page="cursors.length"
      :page-size="pageSize"
      :count="items.length"
      :disabled="loading"
      :has-previous="cursors.length > 1"
      :has-next="!error && !!data?.next_cursor"
      @update:page-size="changePageSize"
      @previous="previous"
      @next="next"
    />
  </section>

  <AModal :open="!!detailID" title="网关阻断详情" :footer="null" width="680px" @cancel="closeDetail">
    <StatePanel :loading="detailPending" :error="detailError" @retry="openDetail(detailID)">
      <ADescriptions v-if="detail" size="small" bordered :column="1">
        <ADescriptions.Item label="告警事件"
          ><span class="gateway-identity mono">{{ detail.event_id }}</span></ADescriptions.Item
        >
        <ADescriptions.Item label="请求"
          ><span class="gateway-identity mono">{{ detail.id }}</span></ADescriptions.Item
        >
        <ADescriptions.Item label="采集器与注册">
          <span class="gateway-identity mono">{{ detail.sensor_id }} · {{ detail.registration_id }}</span>
        </ADescriptions.Item>
        <ADescriptions.Item label="观测连接">
          {{ formatGatewayFlow(detail.flow) }} · {{ formatTime(detail.observed_at, { fraction: 'milliseconds' }) }}
        </ADescriptions.Item>
        <ADescriptions.Item label="策略">
          {{ detail.policy_id }} · v{{ detail.policy_revision }} · {{ triggers[detail.trigger] }}
          <template v-if="detail.assessment_revision"> · 研判 v{{ detail.assessment_revision }}</template>
        </ADescriptions.Item>
        <ADescriptions.Item label="防火墙回读">
          <StatusTag v-bind="firewall(detail)" />
          <div v-if="detail.task_id">
            <RouterLink :to="{ path: '/sensors/tasks', query: { task: detail.task_id } }">核对网关任务</RouterLink>
          </div>
          <div v-if="result">
            回读 {{ formatTime(result.verified_at, { fraction: 'milliseconds' }) }} · 租约截至
            {{ formatTime(result.lease_until) }}
          </div>
          <div v-if="detail.code">{{ gatewayCodes[detail.code] ?? detail.code }}</div>
        </ADescriptions.Item>
        <ADescriptions.Item label="流量观察">
          <StatusTag v-bind="observation(detail)" />
          <template v-if="inspected">
            <div>
              {{ inspected.interface || '观察口不可用' }} · 出侧 {{ inspected.egress_packets }} 包 · 原连接
              {{ inspected.original_packets }} 包
            </div>
            <div>
              {{ formatTime(inspected.started_at, { fraction: 'milliseconds' }) }} 至
              {{ formatTime(inspected.finished_at, { fraction: 'milliseconds' }) }}
            </div>
            <div v-if="inspected.reconnect">重连 {{ formatGatewayFlow(inspected.reconnect) }}</div>
            <div v-if="inspected.code">{{ gatewayCodes[inspected.code] ?? inspected.code }}</div>
          </template>
        </ADescriptions.Item>
        <ADescriptions.Item label="联动封禁">
          <StatusTag v-bind="followUpStatus[detail.follow_up_state]" />
          <div v-if="detail.follow_up_code">{{ gatewayCodes[detail.follow_up_code] ?? detail.follow_up_code }}</div>
          <div v-if="detail.follow_up_task_id">
            <RouterLink :to="{ path: '/response/actions', query: { task: detail.follow_up_task_id } }"
              >核对设备任务</RouterLink
            >
            · {{ taskStates[detail.follow_up_task_state ?? ''] ?? '等待任务回执' }}
          </div>
        </ADescriptions.Item>
      </ADescriptions>
    </StatePanel>
  </AModal>
</template>

<style scoped>
.gateway-status {
  display: flex;
  align-items: center;
  gap: var(--related-gap);
}
.gateway-identity {
  overflow-wrap: anywhere;
}
</style>
