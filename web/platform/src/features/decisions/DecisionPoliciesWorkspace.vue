<script setup lang="ts">
import { usePageTitle } from '@starbeacon/shared/utils/usePageTitle.ts';
const pageTitle = usePageTitle('决策策略');
import { useFeedback } from '@starbeacon/shared/composables/useFeedback.ts';
import { computed, onScopeDispose, reactive, shallowRef, watch } from 'vue';
import { useRoute } from 'vue-router';
import {
  Modal as AModal,
  InputNumber as AInputNumber,
  Select as ASelect,
  Dropdown as ADropdown,
  Menu as AMenu,
} from 'ant-design-vue';
import StatePanel from '@starbeacon/shared/components/StatePanel.vue';
import PageHeader from '@starbeacon/shared/components/PageHeader.vue';
import ListFilters from '@starbeacon/shared/components/ListFilters.vue';
import ListTable from '@starbeacon/shared/components/ListTable.vue';
import ListPager from '@starbeacon/shared/components/ListPager.vue';
import StatusTag from '@starbeacon/shared/components/StatusTag.vue';
import { formatTime } from '@starbeacon/shared/types.ts';
import { session } from '../../session';
import { policyActions, policyModes, validPolicy, type PolicyChange, type PolicyRecord } from './decisionPolicies';
import { useDecisionPolicies } from './useDecisionPolicies';
import DecisionPolicyForm from './DecisionPolicyForm.vue';
import DecisionPolicyEvaluation from './DecisionPolicyEvaluation.vue';
import AutomaticTriagePanel from './AutomaticTriagePanel.vue';
const message = useFeedback();
const AMenuItem = AMenu.Item;
const triggerTarget = shallowRef<PolicyRecord | null>(null);
const model = useDecisionPolicies(),
  route = useRoute(),
  canEdit = computed(() => session.current.value?.role === 'admin'),
  filter = reactive({ keyword: '', active: '' });
const editing = shallowRef(false),
  editRecord = shallowRef<PolicyRecord | null>(null),
  detail = shallowRef<PolicyRecord | null>(null),
  detailTarget = shallowRef<PolicyRecord | null>(null),
  detailError = shallowRef(''),
  detailPending = shallowRef(false),
  revision = shallowRef<number | null>(null),
  evaluation = shallowRef<PolicyRecord | null>(null);
const triageID = computed(() => (typeof route.query.triage_id === 'string' ? route.query.triage_id : ''));
let read: AbortController | undefined,
  stopped = false;
const columns = [
  { title: '策略编号', dataIndex: 'id', width: 144, className: 'technical', ellipsis: true },
  { title: '策略名称', key: 'name', width: 198, ellipsis: true },
  { title: '运行模式', key: 'mode', width: 180 },
  { title: '候选处置', key: 'action', width: 185 },
  { title: '自报分数阈值', key: 'threshold', width: 110 },
  { title: '材料时限', key: 'age', width: 100 },
  { title: '修订', dataIndex: 'revision', width: 75 },
  { title: '状态', key: 'active', width: 80 },
  { title: '保存时间', key: 'created', width: 175 },
  { title: '操作', key: 'actions', width: 184, fixed: 'right' as const },
];
function closeDetail() {
  read?.abort();
  read = undefined;
  detail.value = null;
  detailTarget.value = null;
  detailError.value = '';
  detailPending.value = false;
}
function closeOverlays() {
  closeDetail();
  evaluation.value = null;
  triggerTarget.value = null;
}
function search() {
  closeOverlays();
  model.search(filter.keyword, filter.active);
}
function refresh() {
  closeOverlays();
  void model.refresh();
}
function page(direction: 'next' | 'previous') {
  closeOverlays();
  model[direction]();
}
function resize(size: number) {
  closeOverlays();
  model.changePageSize(size);
}
function canReadTriggers(record: PolicyRecord) {
  return canEdit.value && record.created_by === session.current.value?.id && !!record.definition.continuous?.trigger;
}
function showTriggers(record: PolicyRecord) {
  closeOverlays();
  triggerTarget.value = record;
}
function edit(record: PolicyRecord | null) {
  if (model.busy.value || !canEdit.value) return;
  closeOverlays();
  editRecord.value = record;
  model.clearError();
  editing.value = true;
}
async function saved(receipt: PolicyRecord | undefined) {
  if (receipt) {
    editing.value = false;
    editRecord.value = null;
    message.success('决策策略已保存');
    await model.refresh();
  }
}
async function save(input: PolicyChange) {
  await saved(await model.save(input));
}
async function confirm() {
  await saved(await model.confirm());
}
function evaluate(record: PolicyRecord) {
  if (model.busy.value || model.unconfirmed.value || !canEdit.value) return;
  closeOverlays();
  editing.value = false;
  evaluation.value = record;
}
async function loadDetail() {
  const target = detailTarget.value,
    value = revision.value;
  if (
    stopped ||
    !target ||
    value === null ||
    !Number.isSafeInteger(value) ||
    value < 1 ||
    value > target.revision ||
    detailPending.value
  )
    return;
  read?.abort();
  const controller = new AbortController();
  read = controller;
  detailPending.value = true;
  detailError.value = '';
  detail.value = null;
  const tenant = session.current.value?.tenant_id ?? '';
  try {
    const response = await session.api.request<unknown>(
      `/decision-policies/${encodeURIComponent(target.id)}/revisions/${value}`,
      { signal: controller.signal },
    );
    if (controller.signal.aborted) return;
    if (
      !(await validPolicy(response, tenant)) ||
      !(
        response &&
        typeof response === 'object' &&
        'id' in response &&
        response.id === target.id &&
        'revision' in response &&
        response.revision === value
      )
    )
      throw new Error('策略修订回执与所选对象不一致，请重试。');
    if (!controller.signal.aborted) detail.value = response as PolicyRecord;
  } catch (e) {
    if (!controller.signal.aborted) detailError.value = e instanceof Error ? e.message : '策略修订读取失败。';
  } finally {
    if (read === controller) detailPending.value = false;
  }
}
function inspect(record: PolicyRecord) {
  closeOverlays();
  editing.value = false;
  detailTarget.value = record;
  revision.value = record.revision;
  void loadDetail();
}
function setRevision(value: unknown) {
  revision.value = typeof value === 'number' && Number.isSafeInteger(value) ? value : null;
}
function inputRevision(value: unknown) {
  const raw = typeof value === 'string' ? value : '';
  revision.value = /^[1-9]\d{0,6}$/.test(raw) && Number(raw) <= 1000000 ? Number(raw) : null;
}
watch(
  () => [session.current.value?.id, session.current.value?.tenant_id, session.current.value?.role].join('/'),
  () => {
    closeOverlays();
    editing.value = false;
    editRecord.value = null;
    filter.keyword = '';
    filter.active = '';
  },
);
onScopeDispose(() => {
  stopped = true;
  read?.abort();
});
</script>
<template>
  <PageHeader
    :title="pageTitle"
    description="维护决策条件与材料时限，核对当前策略及历史修订。最多 64 个策略，历史修订默认保留 180 天。"
    notice="持续模式处理指定模型的新研判。取得自动研判许可后，指定探针的新告警进入队列，后续限时任务按策略授权。模型分数、设备配置回读与实际流量效果分别核对。"
  >
    <a-button :loading="model.pending.value" @click="refresh">刷新</a-button>
    <a-button v-if="canEdit" type="primary" :disabled="model.busy.value" @click="edit(null)">{{
      model.unconfirmed.value ? '核对原提交' : '创建策略'
    }}</a-button>
  </PageHeader>
  <p v-if="triageID" class="page-description">
    已带入研判作业 <span class="technical">{{ triageID }}</span>，选择策略的“影子评估”后确认执行。
  </p>
  <form @submit.prevent="search">
    <ListFilters label="决策策略筛选" :columns="3">
      <label>
        <span>策略名称</span>
        <a-input v-model:value="filter.keyword" aria-label="决策策略名称" placeholder="策略名称" :maxlength="128" />
      </label>
      <div class="filter-field">
        <label for="policy-status">状态</label>
        <ASelect
          id="policy-status"
          v-model:value="filter.active"
          aria-label="决策策略状态"
          :options="[
            { value: '', label: '全部状态' },
            { value: 'true', label: '启用' },
            { value: 'false', label: '停用' },
          ]"
        />
      </div>
      <template #actions>
        <a-button type="primary" html-type="submit" :disabled="model.pending.value">检索</a-button>
      </template>
    </ListFilters>
  </form>
  <section class="panel table-panel">
    <div class="table-toolbar"><h2>决策策略</h2></div>
    <StatePanel
      :loading="model.pending.value"
      :error="model.error.value"
      :empty="!model.page.value.items.length"
      :description="
        model.keyword.value || model.active.value
          ? '没有符合筛选条件的决策策略。请调整条件后重新检索。'
          : '暂无决策策略。配置判断条件后，可使用本人研判材料执行影子评估。'
      "
      @retry="model.refresh"
    >
      <ListTable :data-source="model.page.value.items" :columns="columns" :scroll="{ x: 1431 }">
        <template #bodyCell="{ column, record }">
          <button
            v-if="column.key === 'name'"
            type="button"
            class="record-link"
            :title="record.name"
            @click="inspect(record)"
          >
            {{ record.name }}
          </button>
          <template v-else-if="column.key === 'mode'">{{ policyModes[record.definition.mode] }}</template>
          <template v-else-if="column.key === 'action'">{{
            policyActions[record.definition.candidate_action]
          }}</template>
          <template v-else-if="column.key === 'threshold'">{{ record.definition.threshold.toFixed(3) }}</template>
          <template v-else-if="column.key === 'age'">{{ record.definition.max_age_seconds }} 秒</template>
          <StatusTag
            v-else-if="column.key === 'active'"
            :tone="record.active ? 'success' : 'neutral'"
            :value="record.active ? '启用' : '停用'"
          />
          <template v-else-if="column.key === 'created'">{{ formatTime(record.created_at) }}</template>
          <div v-else-if="column.key === 'actions'" class="table-row-actions">
            <a-button type="link" size="small" @click="inspect(record)">查看</a-button>
            <a-button
              v-if="canEdit"
              type="link"
              size="small"
              :disabled="model.busy.value || model.unconfirmed.value"
              @click="edit(record)"
              >编辑</a-button
            >
            <ADropdown v-if="canReadTriggers(record)" :trigger="['click']">
              <a-button type="link" size="small" aria-haspopup="menu">更多</a-button>
              <template #overlay>
                <AMenu :selectable="false">
                  <AMenuItem
                    key="evaluation"
                    :disabled="model.busy.value || model.unconfirmed.value"
                    @click="evaluate(record)"
                    >影子评估</AMenuItem
                  >
                  <AMenuItem key="triggers" @click="showTriggers(record)">自动研判记录</AMenuItem>
                </AMenu>
              </template>
            </ADropdown>
            <a-button
              v-else-if="canEdit"
              type="link"
              size="small"
              :disabled="model.busy.value || model.unconfirmed.value"
              @click="evaluate(record)"
              >影子评估</a-button
            >
          </div>
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
  <DecisionPolicyForm
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
  <DecisionPolicyEvaluation
    v-else-if="evaluation"
    :record="evaluation"
    :triage-id="triageID"
    @close="evaluation = null"
  />
  <a-modal
    v-else-if="detailTarget"
    :open="true"
    title="决策策略详情"
    :width="800"
    :footer="null"
    :body-style="{ maxHeight: 'calc(100vh - 220px)', overflowY: 'auto' }"
    @cancel="closeDetail"
  >
    <div class="policy-revision">
      <label for="policy-revision">读取修订</label
      ><a-input-number
        id="policy-revision"
        :value="revision ?? ''"
        :min="1"
        :max="detailTarget.revision"
        :precision="0"
        :disabled="detailPending"
        @input="inputRevision"
        @update:value="setRevision"
      /><a-button :loading="detailPending" :disabled="detailPending || revision === null" @click="loadDetail"
        >读取</a-button
      >
    </div>
    <StatePanel :loading="detailPending" :error="detailError" @retry="loadDetail"
      ><template v-if="detail"
        ><dl class="policy-detail">
          <dt>策略 / 修订</dt>
          <dd>{{ detail.name }} / {{ detail.revision }}</dd>
          <dt>维护说明</dt>
          <dd>{{ detail.description || '未填写' }}</dd>
          <dt>保存时间 / 操作者</dt>
          <dd>{{ formatTime(detail.created_at) }} / {{ detail.created_by }}</dd>
          <dt>定义 SHA-256</dt>
          <dd class="technical">{{ detail.definition_sha256 }}</dd>
          <dt>历史保留截止</dt>
          <dd>{{ formatTime(detail.expires_at) }}；当前配置受引用保护。</dd>
        </dl>
        <pre class="policy-definition">{{ JSON.stringify(detail.definition, null, 2) }}</pre>
      </template></StatePanel
    >
  </a-modal>
  <a-modal
    :open="!!triggerTarget"
    title="自动研判记录"
    :width="1100"
    :footer="null"
    :body-style="{ maxHeight: 'calc(100vh - 220px)', overflowY: 'auto' }"
    @cancel="triggerTarget = null"
    ><AutomaticTriagePanel v-if="triggerTarget" :record="triggerTarget"
  /></a-modal>
</template>
<style scoped>
.policy-revision {
  display: flex;
  align-items: center;
  gap: var(--related-gap);
  flex-wrap: wrap;
}
.policy-detail {
  display: grid;
  grid-template-columns: 140px minmax(0, 1fr);
  gap: 8px;
}
.policy-detail dd {
  margin: 0;
  overflow-wrap: anywhere;
}
.policy-detail dt {
  color: var(--muted);
}
.policy-definition {
  white-space: pre-wrap;
  overflow-wrap: anywhere;
  background: var(--table-header);
  padding: 12px;
  border: 1px solid var(--line);
  border-radius: 8px;
}
.policy-revision {
  margin-bottom: 12px;
}
</style>
