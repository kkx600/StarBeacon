<script setup lang="ts">
import { statusTerms } from '@starbeacon/shared/terms.ts';
import { useFeedback } from '@starbeacon/shared/composables/useFeedback.ts';
import { computed, onScopeDispose, reactive, shallowRef, watch } from 'vue';
import { Modal as AModal, InputNumber as AInputNumber, Select as ASelect } from 'ant-design-vue';
import StatePanel from '@starbeacon/shared/components/StatePanel.vue';
import ListFilters from '@starbeacon/shared/components/ListFilters.vue';
import ListPager from '@starbeacon/shared/components/ListPager.vue';
import ListTable from '@starbeacon/shared/components/ListTable.vue';
import PageHelp from '@starbeacon/shared/components/PageHelp.vue';
import StatusTag from '@starbeacon/shared/components/StatusTag.vue';
import { formatTime } from '@starbeacon/shared/types.ts';
import { session } from '../../session';
import { applicationCategories, validRule, type AppChange, type AppRule } from './applicationRules';
import { useApplicationRules } from './useApplicationRules';
import ApplicationRuleForm from './ApplicationRuleForm.vue';
import ApplicationRuleTest from './ApplicationRuleTest.vue';
import ApplicationDeploymentForm from './ApplicationDeploymentForm.vue';
import { useApplicationDeployment } from './useApplicationDeployment';
import { router } from '../../router';
const message = useFeedback();
const model = useApplicationRules(),
  canEdit = computed(() => session.current.value?.role === 'admin'),
  filter = reactive({ keyword: '', active: '' });
const editing = shallowRef(false),
  editRecord = shallowRef<AppRule | null>(null),
  detail = shallowRef<AppRule | null>(null),
  detailTarget = shallowRef<AppRule | null>(null),
  detailError = shallowRef(''),
  detailPending = shallowRef(false),
  revision = shallowRef<number | null>(null);
const testing = shallowRef(false),
  testRecord = shallowRef<AppRule | null>(null);
const deployment = useApplicationDeployment();
let read: AbortController | undefined,
  stopped = false;
const columns = [
  { title: '规则编号', dataIndex: 'id', width: 140, className: 'technical', ellipsis: true },
  { title: '规则名称', key: 'name', width: 175, ellipsis: true },
  { title: '应用产品', dataIndex: ['definition', 'product_name'], width: 160, ellipsis: true },
  { title: '类别', key: 'category', width: 100 },
  { title: '协议范围', key: 'protocols', width: 135 },
  { title: '修订', dataIndex: 'revision', width: 75, className: 'technical' },
  { title: '状态', key: 'active', width: 80 },
  { title: '保存时间', key: 'created', width: 175, className: 'technical' },
  { title: '操作', key: 'actions', width: 155, fixed: 'right' as const },
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
  testing.value = false;
  testRecord.value = null;
  deployment.hide();
}
function deploy() {
  if (deployment.busy.value) return;
  closeOverlays();
  editing.value = false;
  deployment.show();
}
function viewDeploymentTask(id: string) {
  deployment.hide();
  void router.push({ path: '/sensors/tasks', query: { task: id } });
}
function search() {
  closeOverlays();
  model.search(filter.keyword, filter.active);
}
function refresh() {
  closeOverlays();
  void model.refresh();
}
function changePageSize(size: number) {
  closeOverlays();
  model.changePageSize(size);
}
function page(direction: 'next' | 'previous') {
  closeOverlays();
  model[direction]();
}
function edit(record: AppRule | null) {
  if (model.busy.value || !canEdit.value) return;
  closeOverlays();
  editRecord.value = record;
  model.clearError();
  editing.value = true;
}
async function save(input: AppChange) {
  const receipt = await model.save(input);
  if (receipt) {
    editing.value = false;
    editRecord.value = null;
    message.success('应用识别规则已保存');
    await model.refresh();
  }
}
async function confirm() {
  const receipt = await model.confirm();
  if (receipt) {
    editing.value = false;
    editRecord.value = null;
    message.success('原提交已确认');
    await model.refresh();
  }
}
function test(record: AppRule | null) {
  if (model.busy.value) return;
  closeOverlays();
  editing.value = false;
  testRecord.value = record;
  testing.value = true;
}
async function loadDetail() {
  const target = detailTarget.value,
    value = revision.value;
  if (
    stopped ||
    !target ||
    !Number.isSafeInteger(value) ||
    value === null ||
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
      `/application-rules/${encodeURIComponent(target.id)}/revisions/${value}`,
      { signal: controller.signal },
    );
    if (controller.signal.aborted) return;
    if (
      !(await validRule(response, tenant)) ||
      !(
        response &&
        typeof response === 'object' &&
        'id' in response &&
        response.id === target.id &&
        'revision' in response &&
        response.revision === value
      )
    )
      throw new Error('规则修订回执与所选对象不一致，请重试。');
    if (!controller.signal.aborted) detail.value = response as AppRule;
  } catch (e) {
    if (!controller.signal.aborted) detailError.value = e instanceof Error ? e.message : '应用规则修订读取失败。';
  } finally {
    if (read === controller) detailPending.value = false;
  }
}
function inspect(record: AppRule) {
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
  const number = /^[1-9]\d{0,6}$/.test(raw) ? Number(raw) : null;
  revision.value = number !== null && Number.isSafeInteger(number) && number <= 1000000 ? number : null;
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
  <form @submit.prevent="search">
    <ListFilters label="应用识别规则筛选" :columns="3">
      <label
        ><span>规则名称</span>
        <a-input v-model:value="filter.keyword" aria-label="应用识别规则名称" placeholder="规则名称" :maxlength="128"
      /></label>
      <div class="filter-field">
        <label for="application-rule-status">状态</label
        ><a-select
          id="application-rule-status"
          v-model:value="filter.active"
          aria-label="应用识别规则状态"
          :options="[
            { value: '', label: '全部状态' },
            { value: 'true', label: '启用' },
            { value: 'false', label: '停用' },
          ]"
        />
      </div>
      <template #actions>
        <a-button type="primary" html-type="submit" :disabled="model.pending.value">检索</a-button>
        <a-button :loading="model.pending.value" @click="refresh">刷新</a-button>
      </template>
    </ListFilters>
  </form>
  <section class="panel table-panel">
    <div class="table-toolbar">
      <div class="heading-with-help">
        <h2>应用识别规则</h2>
        <PageHelp title="应用识别规则">
          <p>编辑或停用后，通过签名任务部署到指定探针。应用字节计量来自流计量关联，产品匹配提供分类依据。</p>
          <p>最多支持 128 条规则，历史修订默认保留 180 天，当前配置持续保留。</p>
        </PageHelp>
      </div>
      <div class="filter-actions">
        <a-button :disabled="model.pending.value" @click="test(null)">验证启用规则</a-button>
        <a-button v-if="canEdit" :disabled="deployment.busy.value || model.busy.value" @click="deploy">{{
          deployment.unconfirmed.value ? '核对应用部署' : '部署到探针'
        }}</a-button>
        <a-button v-if="canEdit" type="primary" :disabled="model.busy.value" @click="edit(null)">{{
          model.unconfirmed.value ? '核对原提交' : '创建规则'
        }}</a-button>
      </div>
    </div>
    <StatePanel
      :loading="model.pending.value"
      :error="model.error.value"
      :empty="!model.page.value.items.length"
      :description="
        model.keyword.value || model.active.value
          ? '没有符合筛选条件的应用识别规则。请调整条件后重新检索。'
          : '暂无应用识别规则。管理员配置规则后可验证产品名称条件与排除依据。'
      "
      @retry="model.refresh"
    >
      <ListTable :data-source="model.page.value.items" :columns="columns" :scroll="{ x: 1195 }"
        ><template #bodyCell="{ column, record }">
          <button
            v-if="column.key === 'name'"
            type="button"
            class="record-link"
            :title="record.name"
            @click="inspect(record)"
          >
            {{ record.name }}
          </button>
          <template v-else-if="column.key === 'category'">{{
            applicationCategories[record.definition.category_id as keyof typeof applicationCategories]
          }}</template>
          <span v-else-if="column.key === 'protocols'" class="technical">{{
            record.definition.protocols.map(protocol => protocol.toUpperCase()).join('、')
          }}</span>
          <StatusTag
            v-else-if="column.key === 'active'"
            :tone="record.active ? statusTerms.启用 : statusTerms.停用"
            :value="record.active ? '启用' : '停用'"
          />
          <template v-else-if="column.key === 'created'">{{ formatTime(record.created_at) }}</template>
          <template v-else-if="column.key === 'actions'"
            ><div class="table-row-actions">
              <a-button type="link" size="small" @click="inspect(record)">查看</a-button
              ><a-button
                v-if="canEdit"
                type="link"
                size="small"
                :disabled="model.busy.value || model.unconfirmed.value"
                @click="edit(record)"
                >编辑</a-button
              ><a-button type="link" size="small" @click="test(record)">验证</a-button>
            </div></template
          >
        </template></ListTable
      >
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
      @update:page-size="changePageSize"
    />
  </section>
  <ApplicationRuleForm
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
  <ApplicationRuleTest
    v-else-if="testing"
    :definition="testRecord?.definition"
    :name="testRecord?.name"
    :revision="testRecord?.revision"
    @close="
      testing = false;
      testRecord = null;
    "
  />
  <ApplicationDeploymentForm
    v-else-if="deployment.open.value"
    :pending="deployment.pending.value"
    :busy="deployment.busy.value"
    :unconfirmed="deployment.unconfirmed.value"
    :error="deployment.error.value"
    :targets="deployment.targets.value"
    :snapshot="deployment.snapshot.value"
    :selected="deployment.selected.value"
    :task-id="deployment.taskID.value"
    @close="deployment.hide"
    @refresh="deployment.refresh"
    @choose="deployment.choose"
    @submit="deployment.submit"
    @confirm="deployment.confirm"
    @task="viewDeploymentTask"
  />
  <a-modal
    v-else-if="detailTarget"
    :open="true"
    title="应用识别规则详情"
    :width="800"
    :footer="null"
    :body-style="{ maxHeight: 'calc(100vh - 220px)', overflowY: 'auto' }"
    @cancel="closeDetail"
  >
    <div class="application-revision">
      <label for="application-revision">读取修订</label
      ><a-input-number
        id="application-revision"
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
      ><template v-if="detail">
        <dl class="application-detail">
          <dt>规则 / 标识</dt>
          <dd>
            {{ detail.name }} · <span class="technical">{{ detail.id }}</span>
          </dd>
          <dt>产品 / 类别</dt>
          <dd>{{ detail.definition.product_name }} / {{ applicationCategories[detail.definition.category_id] }}</dd>
          <dt>修订 / 状态</dt>
          <dd>{{ detail.revision }} / {{ detail.active ? '启用' : '停用' }}</dd>
          <dt>维护说明</dt>
          <dd>{{ detail.description || '未填写' }}</dd>
          <dt>保存时间 / 操作者</dt>
          <dd>
            {{ formatTime(detail.created_at) }} / <span class="technical">{{ detail.created_by }}</span>
          </dd>
          <dt>定义 SHA-256</dt>
          <dd class="technical">{{ detail.definition_sha256 }}</dd>
          <dt>历史保留截止</dt>
          <dd>{{ formatTime(detail.expires_at) }}；当前配置受引用保护。</dd>
        </dl>
        <pre class="application-definition">{{ JSON.stringify(detail.definition, null, 2) }}</pre>
      </template></StatePanel
    >
  </a-modal>
</template>
<style scoped>
.application-revision {
  display: flex;
  align-items: center;
  gap: 8px;
  flex-wrap: wrap;
}
.application-detail {
  display: grid;
  grid-template-columns: 140px minmax(0, 1fr);
  gap: 8px;
}
.application-detail dd {
  margin: 0;
  overflow-wrap: anywhere;
}
.application-detail dt {
  color: var(--muted);
}
.application-definition {
  white-space: pre-wrap;
  overflow-wrap: anywhere;
  background: var(--table-header);
  padding: 12px;
  border: 1px solid var(--line);
  border-radius: 8px;
}
.application-revision {
  margin-bottom: 12px;
}
</style>
