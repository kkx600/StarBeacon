<script setup lang="ts">
import { statusTerms } from '@starbeacon/shared/terms.ts';
import { usePageTitle } from '@starbeacon/shared/utils/usePageTitle.ts';
const pageTitle = usePageTitle('报告计划');
import { useFeedback } from '@starbeacon/shared/composables/useFeedback.ts';
import { shallowRef } from 'vue';
import { Popconfirm } from 'ant-design-vue';
import StatePanel from '@starbeacon/shared/components/StatePanel.vue';
import PageHeader from '@starbeacon/shared/components/PageHeader.vue';
import ListTable from '@starbeacon/shared/components/ListTable.vue';
import ListPager from '@starbeacon/shared/components/ListPager.vue';
import MetricBar from '@starbeacon/shared/components/MetricBar.vue';
import StatusTag from '@starbeacon/shared/components/StatusTag.vue';
import { tablePagination } from '@starbeacon/shared/pagination.ts';
import { formatTime } from '@starbeacon/shared/types.ts';
import { useModels } from '../models/useModels';
import { kindNames } from './analysis';
import { useAnalysis } from './useAnalysis';
import { useReportPlans } from './useReportPlans';
import { planCodes, planRunState, planRunTone, type ReportPlan, type ReportPlanChange } from './plans';
import ReportPlanForm from './ReportPlanForm.vue';
import AnalysisDetail from './AnalysisDetail.vue';
const message = useFeedback();
const state = useReportPlans(),
  models = useModels(),
  analysis = useAnalysis('reports');
const {
  items,
  available,
  modelsAvailable,
  pending,
  error,
  busy,
  actionError,
  unconfirmed,
  runs,
  next,
  cursors,
  pageSize,
  runsPending,
  runsError,
} = state;
const editing = shallowRef<ReportPlan | null>(null),
  editorOpen = shallowRef(false),
  selected = shallowRef<ReportPlan | null>(null),
  detailOpen = shallowRef(false),
  viewing = shallowRef('');
const columns = [
  { title: '计划编号', dataIndex: 'id', width: 142, className: 'technical', ellipsis: true },
  { title: '计划名称', dataIndex: ['spec', 'name'], width: 160, ellipsis: true },
  { title: '修订', dataIndex: 'revision', width: 65 },
  { title: '报告周期', key: 'kind', width: 106 },
  { title: '时区', dataIndex: ['spec', 'timezone'], width: 150, ellipsis: true },
  { title: '执行时间', dataIndex: ['spec', 'at'], width: 85 },
  { title: '智能总结', key: 'provider', width: 134, ellipsis: true },
  { title: '模型修订', key: 'providerRevision', width: 82 },
  { title: '状态', key: 'state', width: 86 },
  { title: '下次计划时间', key: 'next', width: 172 },
  { title: '操作', key: 'actions', width: 174, fixed: 'right' as const },
];
const runColumns = [
  { title: '运行编号', dataIndex: 'id', width: 142, className: 'technical', ellipsis: true },
  { title: '报告周期', key: 'period', width: 156, ellipsis: true },
  { title: '计划修订', dataIndex: 'plan_revision', width: 76 },
  { title: '状态', key: 'state', width: 140 },
  { title: '计划槽位', key: 'due', width: 172 },
  { title: '实际槽位', key: 'effective', width: 172 },
  { title: '处理说明', key: 'reason', width: 235, ellipsis: true },
  { title: '错过槽位范围', key: 'skipped', width: 346, ellipsis: true },
  { title: '操作', key: 'action', width: 100, fixed: 'right' as const },
];
function edit(record: ReportPlan | null) {
  if (busy.value || unconfirmed.value) return;
  state.clearAction();
  editing.value = record;
  editorOpen.value = true;
}
async function save(change: ReportPlanChange) {
  if (await state.save(change)) {
    editorOpen.value = false;
    message.success('报告计划已保存');
  }
}
async function confirm() {
  if (await state.confirm()) {
    editorOpen.value = false;
    message.success('报告计划保存结果已确认');
  }
}
async function disable(record: ReportPlan) {
  if (await state.save({ id: record.id, expected_revision: record.revision, spec: { ...record.spec, enabled: false } }))
    message.success('报告计划已设为停用');
}
async function showRuns(record: ReportPlan) {
  selected.value = record;
  await state.loadRuns(record.id);
}
function closeRuns() {
  selected.value = null;
  state.closeRuns();
  detailOpen.value = false;
  analysis.clear();
  void state.refresh();
}
async function showReport(id: string) {
  analysis.clear();
  viewing.value = id;
  detailOpen.value = true;
  await analysis.loadJob(id);
}
</script>
<template>
  <PageHeader
    :title="pageTitle"
    :description="
      selected
        ? selected.spec.name + '的运行记录。错过槽位范围不含结束时刻，只生成最近完整周期。'
        : '按时区定时生成安全日报、周报与月报，管理持续模型授权和运行记录。每租户最多 32 个计划。'
    "
  >
    <template v-if="selected">
      <a-button @click="closeRuns">返回计划</a-button>
      <a-button :loading="runsPending" @click="state.loadRuns()">刷新记录</a-button>
    </template>
    <template v-else>
      <a-button :loading="pending" @click="state.refresh">刷新</a-button>
      <a-button
        type="primary"
        :disabled="pending || busy || unconfirmed || !!error || items.length >= 32"
        @click="edit(null)"
        >创建计划</a-button
      >
    </template>
  </PageHeader>
  <a-alert v-if="actionError && !editorOpen" type="error" :message="actionError" show-icon class="section-gap" />
  <a-alert
    v-if="unconfirmed && !editorOpen"
    type="warning"
    message="计划操作结果尚未确认，请确认原请求后继续。"
    show-icon
    class="section-gap"
    ><template #action><a-button :loading="busy" @click="confirm">确认保存结果</a-button></template></a-alert
  >
  <a-alert
    v-if="!selected && !pending && !available && !error"
    type="info"
    message="报告计划执行服务异常。可核对已有计划或保存停用配置。"
    show-icon
    class="section-gap"
  />
  <a-alert
    v-if="!selected && models.error.value"
    type="warning"
    :message="models.error.value + '。可使用统计报告计划。'"
    show-icon
    class="section-gap"
  />
  <section v-if="!selected" class="panel table-panel">
    <div class="table-toolbar">
      <h2>报告计划</h2>
      <MetricBar
        v-if="!pending && !error"
        embedded
        :items="[{ label: '当前账号计划', value: items.length, suffix: '个' }]"
      />
    </div>
    <a-alert
      v-if="error && items.length"
      type="error"
      :message="error + '。当前显示上次成功读取的计划。'"
      show-icon
      class="section-gap"
      ><template #action><a-button @click="state.refresh">重试</a-button></template></a-alert
    >
    <StatePanel
      :loading="pending && !items.length"
      :error="items.length ? '' : error"
      :empty="!items.length"
      description="暂无报告计划，可配置周期、时区与执行时间生成统计报告。"
      @retry="state.refresh"
    >
      <ListTable :columns="columns" :data-source="[...items]" :pagination="tablePagination()" :scroll="{ x: 1356 }">
        <template #bodyCell="{ column, record }">
          <template v-if="column.key === 'kind'">{{ kindNames[record.spec.kind] }}</template>
          <template v-else-if="column.key === 'provider'">
            {{
              record.spec.provider_id
                ? (models.items.value.find(p => p.id === record.spec.provider_id)?.name ?? '固定模型修订')
                : '统计报告'
            }}
          </template>
          <template v-else-if="column.key === 'providerRevision'">{{
            record.spec.provider_id ? record.spec.provider_revision : '—'
          }}</template>
          <StatusTag
            v-else-if="column.key === 'state'"
            :tone="record.spec.enabled ? statusTerms.启用 : statusTerms.停用"
            :value="record.spec.enabled ? '启用' : '停用'"
          />
          <template v-else-if="column.key === 'next'">{{
            record.next_at ? formatTime(record.next_at) : '未安排执行'
          }}</template>
          <div v-else-if="column.key === 'actions'" class="table-row-actions">
            <a-button type="link" size="small" :disabled="busy || unconfirmed || pending" @click="edit(record)"
              >配置</a-button
            >
            <a-button type="link" size="small" :disabled="busy || unconfirmed" @click="showRuns(record)"
              >运行记录</a-button
            >
            <Popconfirm
              v-if="record.spec.enabled"
              title="停用报告计划？"
              description="后续周期不再生成，已提交的报告继续处理。"
              ok-text="停用计划"
              cancel-text="取消"
              :disabled="busy || unconfirmed"
              @confirm="disable(record)"
              ><a-button type="link" size="small" :disabled="busy || unconfirmed">停用</a-button></Popconfirm
            >
          </div>
        </template>
      </ListTable>
    </StatePanel>
  </section>
  <section v-else class="panel table-panel">
    <div class="table-toolbar">
      <h2>计划运行记录</h2>
      <span>计划修订 {{ selected.revision }}</span>
    </div>
    <a-alert
      v-if="runsError && runs.length"
      type="error"
      :message="runsError + '。当前显示上次成功读取的运行记录。'"
      show-icon
      class="section-gap"
      ><template #action><a-button @click="state.loadRuns()">重试</a-button></template></a-alert
    >
    <StatePanel
      :loading="runsPending && !runs.length"
      :error="runs.length ? '' : runsError"
      :empty="!runs.length"
      description="暂无运行记录，计划到期后可核对生成结果。"
      @retry="state.loadRuns()"
    >
      <ListTable :columns="runColumns" :data-source="[...runs]" :scroll="{ x: 1539 }">
        <template #bodyCell="{ column, record }">
          <template v-if="column.key === 'period'"
            >{{ kindNames[record.request.kind] }} · {{ record.request.period }}</template
          >
          <StatusTag v-else-if="column.key === 'state'" :tone="planRunTone(record)" :value="planRunState(record)" />
          <template v-else-if="column.key === 'due'">{{ formatTime(record.due_at) }}</template>
          <template v-else-if="column.key === 'effective'">{{ formatTime(record.effective_at) }}</template>
          <span v-else-if="column.key === 'reason'" :title="planCodes[record.code]">
            {{ planCodes[record.code] ?? (record.state === 'preparing' ? '统计正在准备' : '请核对运行状态') }}
          </span>
          <template v-else-if="column.key === 'skipped'">
            {{
              record.skipped_from ? formatTime(record.skipped_from) + ' 至 ' + formatTime(record.skipped_until) : '—'
            }}
          </template>
          <div v-else-if="column.key === 'action'" class="table-row-actions">
            <a-button
              type="link"
              size="small"
              :disabled="!record.analysis_id || !record.analysis_state"
              @click="showReport(record.analysis_id)"
              >查看报告</a-button
            >
          </div>
        </template>
      </ListTable>
    </StatePanel>
    <ListPager
      mode="cursor"
      :page="cursors.length"
      :page-size="pageSize"
      :count="runsPending || runsError ? undefined : runs.length"
      :has-previous="cursors.length > 1"
      :has-next="!runsError && !!next"
      :disabled="runsPending"
      @previous="state.previousPage"
      @next="state.nextPage"
      @update:page-size="state.changePageSize"
    />
  </section>
  <ReportPlanForm
    v-if="editorOpen"
    :record="editing"
    :providers="models.items.value"
    :available="available"
    :models-available="modelsAvailable"
    :busy="busy"
    :error="actionError"
    :unconfirmed="unconfirmed"
    @save="save"
    @confirm="confirm"
    @close="editorOpen = false"
  />
  <AnalysisDetail
    :open="detailOpen"
    :job="analysis.selected.value"
    :loading="analysis.loading.value"
    :error="analysis.detailError.value"
    :busy="analysis.busy.value"
    @close="
      detailOpen = false;
      analysis.clear();
    "
    @retry="analysis.loadJob(viewing)"
    @cancel="analysis.cancel"
  />
</template>
