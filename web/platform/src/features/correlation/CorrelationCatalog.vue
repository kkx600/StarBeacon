<script setup lang="ts">
import { computed, onScopeDispose, ref, shallowRef } from 'vue';
import { useRouter } from 'vue-router';
import { Select as ASelect } from 'ant-design-vue';
import StatePanel from '@starbeacon/shared/components/StatePanel.vue';
import PageHeader from '@starbeacon/shared/components/PageHeader.vue';
import ListFilters from '@starbeacon/shared/components/ListFilters.vue';
import ListPager from '@starbeacon/shared/components/ListPager.vue';
import MetricBar from '@starbeacon/shared/components/MetricBar.vue';
import CorrelationRuleTable from '@starbeacon/shared/components/CorrelationRuleTable.vue';
import CorrelationRuleForm from '@starbeacon/shared/components/CorrelationRuleForm.vue';
import CorrelationRuleDetail from '@starbeacon/shared/components/CorrelationRuleDetail.vue';
import { readCorrelationRule, type CorrelationChange, type CorrelationRule } from '@starbeacon/shared/correlation.ts';
import { session } from '../../session';
import { useCorrelationRules } from './useCorrelationRules';
const model = useCorrelationRules(),
  router = useRouter(),
  canEdit = computed(() => session.current.value?.role === 'admin');
const keyword = ref(''),
  active = ref(''),
  editing = ref(false),
  editRecord = shallowRef<CorrelationRule | null>(null),
  detailTarget = shallowRef<CorrelationRule | null>(null),
  detail = shallowRef<CorrelationRule | null>(null),
  revision = ref(1),
  detailPending = ref(false),
  detailError = ref('');
let detailController: AbortController | undefined,
  stopped = false;
function create() {
  if (!canEdit.value) return;
  editRecord.value = null;
  model.clearError();
  editing.value = true;
}
function edit(record: CorrelationRule) {
  if (!canEdit.value || model.busy.value || model.unconfirmed.value) return;
  editRecord.value = record;
  model.clearError();
  editing.value = true;
}
async function save(input: CorrelationChange) {
  if (await model.save(input)) {
    editing.value = false;
    void model.refresh();
  }
}
async function confirm() {
  if (await model.confirm()) {
    editing.value = false;
    void model.refresh();
  }
}
function backtest(record: CorrelationRule) {
  if (!canEdit.value || !record.active) return;
  void router.push({
    path: '/detection/correlation/backtest',
    query: { rule_id: record.id, revision: String(record.revision) },
  });
}
async function read(rev: number) {
  const target = detailTarget.value;
  if (stopped || !target || !Number.isSafeInteger(rev) || rev < 1 || rev > target.revision) return;
  detailController?.abort();
  const current = new AbortController();
  detailController = current;
  detailPending.value = true;
  detailError.value = '';
  detail.value = null;
  revision.value = rev;
  try {
    const value = await session.api.request<unknown>(`/correlation-rules/${target.id}/revisions/${rev}`, {
      signal: current.signal,
    });
    if (current.signal.aborted) return;
    const record = await readCorrelationRule(value, session.current.value?.tenant_id ?? '');
    if (record.id !== target.id || record.revision !== rev) throw new Error('关联规则修订与所选记录不一致。');
    if (!current.signal.aborted) detail.value = record;
  } catch (cause) {
    if (!current.signal.aborted) detailError.value = cause instanceof Error ? cause.message : '规则修订读取失败。';
  } finally {
    if (detailController === current) detailPending.value = false;
  }
}
function inspect(record: CorrelationRule) {
  detailTarget.value = record;
  void read(record.revision);
}
function closeDetail() {
  detailController?.abort();
  detailTarget.value = null;
  detail.value = null;
  detailError.value = '';
}
onScopeDispose(() => {
  stopped = true;
  detailController?.abort();
});
</script>
<template>
  <PageHeader
    title="关联规则"
    description="按唯一告警、实体字段和固定时间窗口核对活动模式。"
    notice="按需回测使用固定修订。最多 128 条规则，历史修订默认保留 180 天，当前配置受引用保护。"
  >
    <a-button :loading="model.pending.value" @click="model.refresh">刷新目录</a-button>
  </PageHeader>
  <form @submit.prevent="model.search(keyword, active)">
    <ListFilters label="关联规则筛选" :columns="3">
      <label
        ><span>规则名称</span>
        <a-input
          v-model:value="keyword"
          aria-label="筛选关联规则名称"
          placeholder="规则名称"
          :maxlength="128"
          allow-clear
      /></label>
      <div class="filter-field">
        <label for="correlation-catalog-status">回测状态</label
        ><a-select
          id="correlation-catalog-status"
          v-model:value="active"
          aria-label="筛选回测状态"
          :options="[
            { value: '', label: '全部状态' },
            { value: 'true', label: '允许回测' },
            { value: 'false', label: '停用' },
          ]"
        />
      </div>
      <template #actions>
        <a-button type="primary" html-type="submit" :loading="model.pending.value">查询</a-button
        ><a-button
          :disabled="model.pending.value"
          @click="
            keyword = '';
            active = '';
            model.search('', '');
          "
          >重置</a-button
        ><a-button v-if="canEdit" :disabled="model.busy.value" @click="create">{{
          model.unconfirmed.value ? '核对原提交' : '创建关联规则'
        }}</a-button>
      </template>
    </ListFilters>
  </form>
  <section class="panel table-panel">
    <div class="table-toolbar">
      <h2>规则目录</h2>
      <MetricBar
        v-if="!model.pending.value && !model.error.value"
        embedded
        :items="[{ label: '本页规则', value: model.page.value.items.length }]"
      />
    </div>
    <StatePanel
      :loading="model.pending.value"
      :error="model.error.value"
      :empty="!model.page.value.items.length"
      description="当前条件下没有关联规则。管理员可创建规则，再选择固定修订执行窗口回测。"
      @retry="model.refresh"
      ><CorrelationRuleTable
        :items="model.page.value.items"
        :can-edit="canEdit"
        :disabled="model.busy.value || model.unconfirmed.value"
        @inspect="inspect"
        @edit="edit"
        @backtest="backtest"
    /></StatePanel>
    <ListPager
      mode="cursor"
      :page="model.cursors.value.length"
      :page-size="model.pageSize.value"
      :count="model.pending.value || model.error.value ? undefined : model.page.value.items.length"
      :has-previous="model.cursors.value.length > 1"
      :has-next="!model.error.value && !!model.page.value.next_cursor"
      :disabled="model.pending.value"
      @previous="model.previous"
      @next="model.next"
      @update:page-size="model.changePageSize"
    />
  </section>
  <CorrelationRuleForm
    v-if="editing"
    :record="editRecord"
    :draft="model.draft()"
    :busy="model.busy.value"
    :unconfirmed="model.unconfirmed.value"
    :error="model.mutationError.value"
    @save="save"
    @confirm="confirm"
    @close="editing = false"
  />
  <CorrelationRuleDetail
    v-else-if="detailTarget"
    :record="detail"
    :pending="detailPending"
    :error="detailError"
    :revision="revision"
    :maximum="detailTarget.revision"
    @read="read"
    @close="closeDetail"
  />
</template>
