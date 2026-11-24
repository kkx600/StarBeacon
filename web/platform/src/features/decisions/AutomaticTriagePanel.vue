<script setup lang="ts">
import { onScopeDispose, ref, shallowRef, watch } from 'vue';
import { useRouter } from 'vue-router';
import { session } from '../../session';
import { formatTime } from '@starbeacon/shared/types.ts';
import StatePanel from '@starbeacon/shared/components/StatePanel.vue';
import PageHelp from '@starbeacon/shared/components/PageHelp.vue';
import ListTable from '@starbeacon/shared/components/ListTable.vue';
import ListPager from '@starbeacon/shared/components/ListPager.vue';
import StatusTag from '@starbeacon/shared/components/StatusTag.vue';
import { useCursorPageSize } from '@starbeacon/shared/composables/useCursorPageSize.ts';
import { defaultPageSize } from '@starbeacon/shared/pagination.ts';
import type { PolicyRecord } from './decisionPolicies';
import {
  triggerStates,
  triggerTones,
  triggerCodes,
  validAutomaticTriagePage,
  type AutomaticTriagePage,
} from './automaticTriage';
const props = defineProps<{ record: PolicyRecord }>(),
  router = useRouter(),
  page = shallowRef<AutomaticTriagePage>({ items: [], next_cursor: '' }),
  pending = ref(false),
  error = ref(''),
  cursors = shallowRef(['']);
const { pageSize, changePageSize } = useCursorPageSize(cursors, pending, load);
const columns = [
  { title: '登记编号', dataIndex: 'id', width: 150, className: 'technical', ellipsis: true },
  { title: '告警编号', dataIndex: 'event_id', width: 160, className: 'technical', ellipsis: true },
  { title: '状态', key: 'state', width: 150 },
  { title: '核对结果', key: 'code', width: 260 },
  { title: '登记时间', key: 'created', width: 180 },
  { title: '操作', key: 'actions', width: 130, fixed: 'right' as const },
];
let read: AbortController | undefined,
  stopped = false;
async function load() {
  if (stopped) return;
  read?.abort();
  const c = new AbortController();
  read = c;
  pending.value = true;
  error.value = '';
  page.value = { items: [], next_cursor: '' };
  const p = props.record,
    u = session.current.value,
    before = cursors.value.at(-1) ?? '',
    limit = pageSize.value;
  try {
    if (!u || u.role !== 'admin' || u.id !== p.created_by || u.tenant_id !== p.tenant_id)
      throw new Error('当前账号没有该策略自动研判记录的查看权限。');
    const query = new URLSearchParams();
    if (before) query.set('before', before);
    if (limit !== defaultPageSize) query.set('limit', String(limit));
    const result = await session.api.request<unknown>(
      `/decision-policies/${encodeURIComponent(p.id)}/revisions/${p.revision}/triggers` +
        (query.size ? '?' + query : ''),
      { signal: c.signal },
    );
    if (c.signal.aborted) return;
    if (!validAutomaticTriagePage(result, p, before, limit))
      throw new Error('自动研判记录与所选策略、探针或修订不一致，请重试。');
    if (!c.signal.aborted) page.value = result;
  } catch (e) {
    if (!c.signal.aborted) error.value = e instanceof Error ? e.message : '自动研判记录读取失败。';
  } finally {
    if (read === c) pending.value = false;
  }
}
function next() {
  if (pending.value || error.value || !page.value.next_cursor) return;
  cursors.value = [...cursors.value, page.value.next_cursor];
  void load();
}
function previous() {
  if (pending.value || cursors.value.length <= 1) return;
  cursors.value = cursors.value.slice(0, -1);
  void load();
}
function refresh() {
  cursors.value = [''];
  void load();
}
watch(
  () => [
    props.record.id,
    props.record.revision,
    props.record.definition_sha256,
    session.current.value?.id,
    session.current.value?.tenant_id,
    session.current.value?.role,
  ],
  () => {
    pageSize.value = defaultPageSize;
    refresh();
  },
  { immediate: true },
);
onScopeDispose(() => {
  stopped = true;
  read?.abort();
});
</script>
<template>
  <section class="panel table-panel">
    <div class="table-toolbar">
      <div class="heading-with-help">
        <h2>{{ record.name }} · 修订 {{ record.revision }}</h2>
        <PageHelp title="自动研判记录">
          <p>登记和提交状态不代表模型研判或设备处置已完成。登记范围和每日额度取自当前策略修订。</p>
        </PageHelp>
      </div>
      <a-button :loading="pending" @click="refresh">刷新记录</a-button>
    </div>
    <StatePanel
      :loading="pending"
      :error="error"
      :empty="!page.items.length"
      description="本策略修订暂无自动研判登记。"
      @retry="load"
    >
      <ListTable :data-source="page.items" :columns="columns" :scroll="{ x: 1030 }">
        <template #bodyCell="{ column, record: row }">
          <StatusTag v-if="column.key === 'state'" :tone="triggerTones[row.state]" :value="triggerStates[row.state]" />
          <template v-else-if="column.key === 'code'">{{ triggerCodes[row.code] }}</template>
          <template v-else-if="column.key === 'created'">{{ formatTime(row.created_at) }}</template>
          <template v-else-if="column.key === 'actions'">
            <button
              v-if="row.triage_id"
              type="button"
              class="record-link"
              @click="router.push({ path: '/response/evaluations', query: { triage_id: row.triage_id } })"
            >
              查看决策记录
            </button>
            <span v-else>尚无研判作业</span>
          </template>
        </template>
      </ListTable>
    </StatePanel>
    <ListPager
      mode="cursor"
      :page="cursors.length"
      :page-size="pageSize"
      :count="pending || error ? undefined : page.items.length"
      :has-previous="cursors.length > 1"
      :has-next="!error && !!page.next_cursor"
      :disabled="pending"
      @previous="previous"
      @next="next"
      @update:page-size="changePageSize"
    />
  </section>
</template>
