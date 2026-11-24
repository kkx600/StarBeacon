<script setup lang="ts">
import { usePageTitle } from '@starbeacon/shared/utils/usePageTitle.ts';
const pageTitle = usePageTitle('评估记录');
import { onScopeDispose, reactive, ref, shallowRef, watch } from 'vue';
import { Select as ASelect, Modal as AModal } from 'ant-design-vue';
import StatePanel from '@starbeacon/shared/components/StatePanel.vue';
import PageHeader from '@starbeacon/shared/components/PageHeader.vue';
import ListFilters from '@starbeacon/shared/components/ListFilters.vue';
import ListTable from '@starbeacon/shared/components/ListTable.vue';
import ListPager from '@starbeacon/shared/components/ListPager.vue';
import StatusTag from '@starbeacon/shared/components/StatusTag.vue';
import { formatTime } from '@starbeacon/shared/types.ts';
import { session } from '../../session';
import { policyStatuses, policyStatusTones } from './decisionPolicies';
import { validEvaluation, type EvaluationRecord } from './decisionEvaluations';
import { useDecisionEvaluations } from './useDecisionEvaluations';
import DecisionEvaluationDetail from './DecisionEvaluationDetail.vue';
import DecisionResponseDialog from './DecisionResponseDialog.vue';
const model = useDecisionEvaluations(),
  draft = reactive({ policy_id: '', triage_id: '', status: '' }),
  detail = shallowRef<EvaluationRecord | null>(null),
  detailTarget = ref(''),
  detailPending = ref(false),
  detailError = ref('');
const responseTarget = shallowRef<EvaluationRecord | null>(null);
let read: AbortController | undefined;
const columns = [
  { title: '评估编号', dataIndex: 'id', width: 145, className: 'technical', ellipsis: true },
  { title: '策略编号', dataIndex: ['policy', 'id'], width: 145, className: 'technical', ellipsis: true },
  { title: '策略名称', dataIndex: ['policy', 'name'], width: 156, ellipsis: true },
  { title: '修订', dataIndex: ['policy', 'revision'], width: 65 },
  { title: '判断结果', key: 'status', width: 150 },
  { title: '处置授权', key: 'authorization', width: 132 },
  { title: '模型自报分数', key: 'confidence', width: 130 },
  { title: '研判作业编号', dataIndex: ['result', 'triage_id'], width: 156, className: 'technical', ellipsis: true },
  { title: '评估时间', key: 'time', width: 172 },
  { title: '操作', key: 'actions', width: 68, fixed: 'right' as const },
];
function close() {
  read?.abort();
  detailTarget.value = '';
  detail.value = null;
  detailError.value = '';
  detailPending.value = false;
  responseTarget.value = null;
}
function respond(record: EvaluationRecord) {
  if (session.current.value?.role !== 'admin') return;
  close();
  responseTarget.value = record;
}
async function inspect(id: string) {
  close();
  detailTarget.value = id;
  const controller = new AbortController();
  read = controller;
  detailPending.value = true;
  const tenant = session.current.value?.tenant_id ?? '',
    owner = session.current.value?.id ?? '';
  try {
    const value = await session.api.request<unknown>('/decision-evaluations/' + encodeURIComponent(id), {
      signal: controller.signal,
    });
    if (controller.signal.aborted) return;
    if (!(await validEvaluation(value, tenant, owner)) || (value as EvaluationRecord).id !== id)
      throw new Error('评估档案与所选记录或摘要不一致，请重试。');
    if (!controller.signal.aborted) detail.value = value as EvaluationRecord;
  } catch (e) {
    if (!controller.signal.aborted) detailError.value = e instanceof Error ? e.message : '评估档案读取失败。';
  } finally {
    if (read === controller) detailPending.value = false;
  }
}
function search() {
  close();
  model.search(draft);
}
function refresh() {
  close();
  model.refresh();
}
function resize(size: number) {
  close();
  model.changePageSize(size);
}
function page(direction: 'next' | 'previous') {
  close();
  model[direction]();
}
watch(
  () => [session.current.value?.id, session.current.value?.tenant_id, session.current.value?.role].join('/'),
  () => {
    close();
    draft.policy_id = '';
    draft.triage_id = '';
    draft.status = '';
  },
);
onScopeDispose(() => read?.abort());
</script>
<template>
  <PageHeader
    :title="pageTitle"
    description="按持久提交倒序查看本账号的评估档案。判断与持续决策授权独立留档，详情可核对自动任务或未授权原因。模型自报分数未经校准。"
    notice="记录默认保留 180 天。刷新首屏可读取新记录，游标到期时请重新检索。"
  >
    <a-button :loading="model.pending.value" @click="refresh">刷新</a-button>
  </PageHeader>
  <form @submit.prevent="search">
    <ListFilters label="评估记录筛选" :columns="4">
      <label
        ><span>策略编号</span
        ><a-input v-model:value="draft.policy_id" aria-label="评估策略标识" placeholder="策略标识" :maxlength="64"
      /></label>
      <label
        ><span>研判作业编号</span
        ><a-input
          v-model:value="draft.triage_id"
          aria-label="评估研判作业标识"
          placeholder="研判作业标识"
          :maxlength="64"
      /></label>
      <div class="filter-field">
        <label for="evaluation-status">判断结果</label>
        <ASelect
          id="evaluation-status"
          v-model:value="draft.status"
          aria-label="评估判断结果"
          :options="[
            { value: '', label: '全部结果' },
            ...Object.entries(policyStatuses).map(([value, label]) => ({ value, label })),
          ]"
        />
      </div>
      <template #actions
        ><a-button type="primary" html-type="submit" :disabled="model.pending.value">检索</a-button></template
      >
    </ListFilters>
  </form>
  <section class="panel table-panel">
    <div class="table-toolbar"><h2>评估记录</h2></div>
    <StatePanel
      :loading="model.pending.value"
      :error="model.error.value"
      :empty="!model.page.value.items.length"
      :description="
        Object.values(model.filter.value).some(Boolean)
          ? '没有符合筛选条件的评估记录。请调整条件后重新检索。'
          : '暂无评估记录。使用本人研判材料执行影子评估后，可在此查看判断快照。'
      "
      @retry="model.refresh"
    >
      <ListTable :data-source="model.page.value.items" :columns="columns" :scroll="{ x: 1319 }">
        <template #bodyCell="{ column, record }">
          <StatusTag
            v-if="column.key === 'status'"
            :tone="policyStatusTones[record.result.status]"
            :value="policyStatuses[record.result.status]"
          />
          <template v-else-if="column.key === 'authorization'">{{
            record.policy.definition.mode === 'shadow' ? '未授权执行' : '授权记录见详情'
          }}</template>
          <template v-else-if="column.key === 'confidence'">{{
            record.result.confidence === null ? '未参与评估' : record.result.confidence.toFixed(3)
          }}</template>
          <template v-else-if="column.key === 'time'">{{ formatTime(record.result.evaluated_at) }}</template>
          <button v-else-if="column.key === 'actions'" type="button" class="record-link" @click="inspect(record.id)">
            查看
          </button>
        </template>
      </ListTable>
    </StatePanel>
    <ListPager
      mode="cursor"
      :page="model.cursors.value.length"
      :page-size="model.pageSize.value"
      :count="model.pending.value || model.error.value ? undefined : model.page.value.items.length"
      :has-previous="model.cursors.value.length > 1"
      :has-next="!model.error.value && !!model.page.value.next_cursor"
      :disabled="model.pending.value"
      @previous="page('previous')"
      @next="page('next')"
      @update:page-size="resize"
    />
  </section>
  <DecisionEvaluationDetail
    v-if="detail"
    :record="detail"
    :can-respond="session.current.value?.role === 'admin'"
    @close="close"
    @respond="respond"
  />
  <DecisionResponseDialog v-else-if="responseTarget" :record="responseTarget" @close="close" />
  <a-modal
    v-else-if="detailTarget"
    :open="true"
    title="评估记录详情"
    :width="820"
    :footer="null"
    :body-style="{ maxHeight: 'calc(100vh - 220px)', overflowY: 'auto' }"
    @cancel="close"
    ><StatePanel :loading="detailPending" :error="detailError" @retry="inspect(detailTarget)"
  /></a-modal>
</template>
