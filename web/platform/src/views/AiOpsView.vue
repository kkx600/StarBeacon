<script setup lang="ts">
import { computed, onMounted, onScopeDispose, shallowRef, watch } from 'vue';
import { Alert, Button, Segmented, type TableColumnType } from 'ant-design-vue';
import { PauseCircleOutlined } from '@ant-design/icons-vue';
import { RouterLink } from 'vue-router';
import { useFeedback } from '@starbeacon/shared/composables/useFeedback.ts';
import { useCursorPageSize } from '@starbeacon/shared/composables/useCursorPageSize.ts';
import PageHeader from '@starbeacon/shared/components/PageHeader.vue';
import MetricBar from '@starbeacon/shared/components/MetricBar.vue';
import ListTable from '@starbeacon/shared/components/ListTable.vue';
import ListPager from '@starbeacon/shared/components/ListPager.vue';
import StatusTag from '@starbeacon/shared/components/StatusTag.vue';
import StatePanel from '@starbeacon/shared/components/StatePanel.vue';
import { formatTime, modelJobStates, type MetricSpec } from '@starbeacon/shared/types.ts';
import { session } from '../session';
import { automationLevels } from '../features/decisions/decisionPolicies';
import { continuousCodes, continuousStates, type ContinuousRecord } from '../features/decisions/continuousDecisions';
import {
  activityKinds,
  automationLocation,
  effectiveCeiling,
  planDeadline,
  readActivity,
  readAutomation,
  readMetrics,
  readPlans,
  validSettings,
  type AutomationSettings,
  type CursorPage,
  type PlanActivity,
  type PlanMetrics,
  type PlanRow,
} from '../features/decisions/automation';
import PlanReviewDialog from '../features/decisions/PlanReviewDialog.vue';

type View = 'pending' | 'activity';
const options: { value: View; label: string }[] = [
  { value: 'pending', label: '待确认' },
  { value: 'activity', label: '处置流水' },
];
const feedback = useFeedback();
const view = shallowRef<View>('pending');
const settings = shallowRef<AutomationSettings>();
const metrics = shallowRef<PlanMetrics>();
const statsFailure = shallowRef('');
const settingsFailure = shallowRef('');
const pausing = shallowRef(false);
const planError = shallowRef('');
const pending = shallowRef(true);
const plans = shallowRef<CursorPage<PlanRow>>();
const activity = shallowRef<CursorPage<PlanActivity>>();
const cursors = shallowRef(['']);
const { pageSize, changePageSize } = useCursorPageSize(cursors, pending, loadRows);
const selected = shallowRef<ContinuousRecord>();
const current = computed(() => (view.value === 'pending' ? plans.value : activity.value));
const isAdmin = computed(() => session.current.value?.role === 'admin');
let rowRequest: AbortController | undefined;
let summaryRequest: AbortController | undefined;
let pauseRequest: AbortController | undefined;
const metricItems = computed<MetricSpec[]>(() => [
  {
    label: '今日完成研判',
    value: metrics.value?.triage_count ?? '—',
    note:
      metrics.value?.triage_mean_ms != null
        ? '平均 ' + (metrics.value.triage_mean_ms / 1000).toFixed(2) + ' 秒'
        : undefined,
  },
  { label: '待确认', value: metrics.value?.pending ?? '—', tone: 'warning' },
  {
    label: '已执行处置',
    value: metrics.value?.executed ?? '—',
    note: metrics.value ? '自动执行 ' + metrics.value.automatic : undefined,
  },
  { label: '人工驳回', value: metrics.value?.rejected ?? '—' },
  { label: '保护名单拦截', value: metrics.value?.protected ?? '—' },
]);
const planColumns: TableColumnType<PlanRow>[] = [
  { key: 'event', title: '告警 / 场景', width: 211, ellipsis: true },
  { key: 'target', title: '处置对象', width: 166 },
  { key: 'confidence', title: '模型自报分数', width: 118 },
  { key: 'level', title: '有效级别', width: 118 },
  { key: 'deadline', title: '确认截止', width: 172 },
  { key: 'action', title: '操作', width: 90, fixed: 'right' },
];
const activityColumns: TableColumnType<PlanActivity>[] = [
  { key: 'time', title: '时间', width: 172 },
  { key: 'kind', title: '动作', width: 122 },
  { key: 'object', title: '对象', width: 184, ellipsis: true },
  { key: 'state', title: '结果', width: 100 },
  { key: 'code', title: '说明', ellipsis: true },
  { key: 'action', title: '操作', width: 90, fixed: 'right' },
];
const stateNames: Record<string, string> = {
  ...modelJobStates,
  ...continuousStates,
  rejected: '已驳回',
  expired: '已到期',
  revoked: '已解除',
  delivered: '已送达',
  unknown: '结果未知',
};
function activityState(item: PlanActivity) {
  if (item.kind === 'manual' || item.kind === 'automatic') {
    if (item.state === 'succeeded') return '设备已回读';
    if (item.state === 'queued') return '等待下发';
  }
  return stateNames[item.state] ?? item.state;
}
function explainCode(item: PlanActivity) {
  if (item.kind === 'review') return item.code || '超过方案确认时限';
  if (item.kind === 'release') return '设备回读确认';
  return continuousCodes[item.code as keyof typeof continuousCodes] ?? (item.code || '—');
}
async function loadRows() {
  rowRequest?.abort();
  const request = new AbortController();
  rowRequest = request;
  pending.value = true;
  planError.value = '';
  try {
    const cursor = cursors.value.at(-1) ?? '';
    if (view.value === 'pending') {
      const result = await readPlans(cursor, pageSize.value, request.signal);
      if (!request.signal.aborted) plans.value = result;
    } else {
      const result = await readActivity(cursor, pageSize.value, request.signal);
      if (!request.signal.aborted) activity.value = result;
    }
  } catch (cause) {
    if (!request.signal.aborted) planError.value = cause instanceof Error ? cause.message : '读取处置记录失败。';
  } finally {
    if (rowRequest === request) pending.value = false;
  }
}
async function loadSummary() {
  summaryRequest?.abort();
  const request = new AbortController();
  summaryRequest = request;
  settingsFailure.value = '';
  statsFailure.value = '';
  const [a, b] = await Promise.allSettled([readAutomation(request.signal), readMetrics(request.signal)]);
  if (request.signal.aborted) return;
  if (a.status === 'fulfilled') settings.value = a.value.settings;
  else {
    settings.value = undefined;
    settingsFailure.value = a.reason instanceof Error ? a.reason.message : '读取自动化级别失败。';
  }
  if (b.status === 'fulfilled') metrics.value = b.value;
  else {
    metrics.value = undefined;
    statsFailure.value = b.reason instanceof Error ? b.reason.message : '读取处置指标失败。';
  }
}
function first() {
  cursors.value = [''];
  void loadRows();
}
function refresh() {
  first();
  void loadSummary();
}
function goPage(delta: -1 | 1) {
  if (pending.value) return;
  const next = current.value?.next_cursor;
  if (delta === 1 && next && !planError.value) cursors.value = [...cursors.value, next];
  else if (delta === -1 && cursors.value.length > 1) cursors.value = cursors.value.slice(0, -1);
  else return;
  void loadRows();
}
async function pause() {
  if (!isAdmin.value || settings.value?.paused || pausing.value) return;
  summaryRequest?.abort();
  const request = new AbortController();
  pauseRequest = request;
  settingsFailure.value = '';
  pausing.value = true;
  try {
    const result = await session.api.request<unknown>('/decision-automation/pause', {
      method: 'POST',
      signal: request.signal,
    });
    if (request.signal.aborted) return;
    if (!validSettings(result) || !result.paused) throw new Error('暂停回执待核对，请重新刷新。');
    settings.value = result;
    feedback.success('自动处置已暂停');
    refresh();
  } catch (cause) {
    if (!request.signal.aborted) settingsFailure.value = cause instanceof Error ? cause.message : '暂停状态待核对。';
  } finally {
    if (pauseRequest === request) pausing.value = false;
  }
}
watch(view, first);
onMounted(refresh);
onScopeDispose(() => {
  rowRequest?.abort();
  summaryRequest?.abort();
  pauseRequest?.abort();
});
</script>

<template>
  <PageHeader title="AI 值守" description="核对待确认的处置方案、研判证据与设备回读。">
    <div class="ai-ops-controls">
      <span v-if="settings"
        >当前有效上限 <strong>{{ automationLevels[effectiveCeiling(settings)] }}</strong></span
      >
      <RouterLink v-if="isAdmin" :to="automationLocation">自动处置设置</RouterLink>
      <Button v-if="isAdmin && !settings?.paused" danger :loading="pausing" @click="pause">
        <PauseCircleOutlined aria-hidden="true" />暂停自动处置
      </Button>
      <Button :disabled="pausing" @click="refresh">刷新</Button>
    </div>
  </PageHeader>
  <Alert
    v-if="settings?.paused"
    show-icon
    type="warning"
    class="section-gap"
    message="自动处置已暂停。研判继续，可到系统设置恢复自动处置。"
  />
  <Alert
    v-if="settingsFailure || statsFailure"
    show-icon
    type="error"
    class="section-gap"
    :message="[settingsFailure, statsFailure].filter(Boolean).join(' ')"
  />
  <MetricBar :items="metricItems" />
  <section class="panel table-panel">
    <div class="table-toolbar">
      <Segmented v-model:value="view" :options="options" aria-label="值守记录类型" />
      <span v-if="metrics" class="muted">今日统计时区 {{ metrics.timezone }}</span>
    </div>
    <StatePanel
      :loading="pending"
      :error="planError"
      :empty="!current?.items.length"
      :title="view === 'pending' ? '没有待确认的方案' : '没有处置流水'"
      :description="
        view === 'pending' ? '等待人工确认的方案按截止时间排列。' : '研判、授权及设备回读记录将在这里显示。'
      "
      :action="view === 'pending' && !planError ? '查看处置流水' : undefined"
      @action="view = 'activity'"
      @retry="loadRows"
    >
      <ListTable
        v-if="view === 'pending'"
        :columns="planColumns"
        :data-source="plans?.items ?? []"
        :row-key="row => row.run.id"
        :scroll="{ x: 875 }"
      >
        <template #bodyCell="{ column, record }">
          <template v-if="column.key === 'event'">
            <div class="technical">{{ record.run.event_id }}</div>
            <small>{{ record.run.policy_id }} · v{{ record.run.policy_revision }}</small>
          </template>
          <template v-else-if="column.key === 'target'">
            <div>{{ record.run.target_ip }}</div>
            <small>限时封禁来源</small>
          </template>
          <template v-else-if="column.key === 'confidence'">{{
            record.run.plan?.confidence.toFixed(3) ?? '—'
          }}</template>
          <template v-else-if="column.key === 'level'">{{
            automationLevels[record.run.plan?.level ?? 'approval']
          }}</template>
          <template v-else-if="column.key === 'deadline'">{{ formatTime(planDeadline(record.run)) }}</template>
          <Button v-else-if="column.key === 'action'" type="link" size="small" @click="selected = record.run"
            >查看方案</Button
          >
        </template>
      </ListTable>
      <ListTable v-else :columns="activityColumns" :data-source="activity?.items ?? []" :scroll="{ x: 845 }">
        <template #bodyCell="{ column, record }">
          <template v-if="column.key === 'time'">{{ formatTime(record.at) }}</template>
          <template v-else-if="column.key === 'kind'">{{ activityKinds[record.kind] }}</template>
          <span v-else-if="column.key === 'object'" class="technical">{{ record.object || '—' }}</span>
          <StatusTag
            v-else-if="column.key === 'state'"
            :value="activityState(record)"
            :tone="record.state === 'succeeded' || record.state === 'revoked' ? 'success' : 'neutral'"
          />
          <template v-else-if="column.key === 'code'">{{ explainCode(record) }}</template>
          <RouterLink
            v-else-if="column.key === 'action' && isAdmin && record.task_id"
            :to="{ path: '/sensors/tasks', query: { task: record.task_id } }"
            >查看任务</RouterLink
          >
        </template>
      </ListTable>
    </StatePanel>
    <ListPager
      mode="cursor"
      :page="cursors.length"
      :page-size="pageSize"
      :count="current?.items.length ?? 0"
      :disabled="pending"
      :has-previous="cursors.length > 1"
      :has-next="!!current?.next_cursor && !planError"
      @update:page-size="changePageSize"
      @previous="goPage(-1)"
      @next="goPage(1)"
    />
  </section>
  <PlanReviewDialog v-if="selected" :key="selected.id" :run="selected" @close="selected = undefined" @saved="refresh" />
</template>

<style scoped>
.ai-ops-controls {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: var(--field-gap);
}
.ai-ops-controls strong {
  margin-inline-start: var(--label-gap);
}
@media (max-width: 670px) {
  .table-toolbar .muted {
    display: none;
  }
}
</style>
