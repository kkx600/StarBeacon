<script setup lang="ts">
import { computed, onMounted, onScopeDispose, shallowRef, watch } from 'vue';
import { RouterLink, useRoute, useRouter } from 'vue-router';
import { Button } from 'ant-design-vue';
import PageHeader from '@starbeacon/shared/components/PageHeader.vue';
import StatePanel from '@starbeacon/shared/components/StatePanel.vue';
import ListTable from '@starbeacon/shared/components/ListTable.vue';
import ListPager from '@starbeacon/shared/components/ListPager.vue';
import StatusTag from '@starbeacon/shared/components/StatusTag.vue';
import { formatTime } from '@starbeacon/shared/types.ts';
import { useCursorPageSize } from '@starbeacon/shared/composables/useCursorPageSize.ts';
import { session } from '../session';
import { errorText, runStates, type Page, type PlaybookRun } from '../features/playbooks/playbooks';
import PlaybookRunDetails from '../features/playbooks/PlaybookRunDetails.vue';

const route = useRoute(),
  router = useRouter();
const page = shallowRef<Page<PlaybookRun>>();
const chosen = shallowRef<PlaybookRun>();
const cursors = shallowRef(['']),
  pending = shallowRef(true),
  error = shallowRef(''),
  detailError = shallowRef('');
const { pageSize, changePageSize } = useCursorPageSize(cursors, pending, load);
let read: AbortController | undefined, detail: AbortController | undefined;
const id = computed(() =>
  typeof route.query.run === 'string' && /^pbr_[a-f0-9]{32}$/.test(route.query.run) ? route.query.run : '',
);
const columns = [
  { title: '运行标识', dataIndex: 'id', width: 280, className: 'technical' },
  { title: '编排', key: 'name', ellipsis: true },
  { title: '发布修订', dataIndex: 'revision', width: 92 },
  { title: '进度', key: 'progress', width: 100 },
  { title: '状态', key: 'state', width: 100 },
  { title: '启动时间', key: 'created', width: 165 },
  { title: '操作', key: 'action', width: 90, fixed: 'right' as const },
];
async function load() {
  read?.abort();
  const control = new AbortController();
  read = control;
  pending.value = true;
  error.value = '';
  try {
    const q = new URLSearchParams({ limit: String(pageSize.value), cursor: cursors.value.at(-1) ?? '' });
    const value = await session.api.request<Page<PlaybookRun>>('/playbook-runs?' + q, { signal: control.signal });
    if (!control.signal.aborted) page.value = value;
  } catch (cause) {
    if (!control.signal.aborted) error.value = errorText(cause);
  } finally {
    if (read === control) pending.value = false;
  }
}
async function loadDetail() {
  detail?.abort();
  detailError.value = '';
  if (!id.value) {
    chosen.value = undefined;
    return;
  }
  const control = new AbortController();
  detail = control;
  const requested = id.value;
  if (chosen.value?.id !== requested) chosen.value = undefined;
  try {
    const value = await session.api.request<PlaybookRun>('/playbook-runs/' + requested, { signal: control.signal });
    if (!control.signal.aborted) chosen.value = value;
  } catch (cause) {
    if (!control.signal.aborted) detailError.value = errorText(cause);
  }
}
function pageBy(delta: -1 | 1) {
  if (pending.value) return;
  if (delta === 1 && page.value?.next_cursor) cursors.value = [...cursors.value, page.value.next_cursor];
  else if (delta === -1 && cursors.value.length > 1) cursors.value = cursors.value.slice(0, -1);
  else return;
  void load();
}
function update(run: PlaybookRun) {
  detail?.abort();
  chosen.value = run;
  if (page.value) page.value = { ...page.value, items: page.value.items.map(row => (row.id === run.id ? run : row)) };
}
function open(run: PlaybookRun) {
  chosen.value = run;
  void router.push({ path: '/response/playbook-runs', query: { run: run.id } });
}
watch(id, loadDetail, { immediate: true });
onMounted(load);
onScopeDispose(() => {
  read?.abort();
  detail?.abort();
});
</script>

<template>
  <PageHeader title="编排运行记录" description="核对本人启动的运行、授权和设备回执。">
    <RouterLink to="/response/playbooks">编排工作台</RouterLink>
    <Button
      @click="
        load();
        loadDetail();
      "
      >刷新</Button
    >
  </PageHeader>
  <StatePanel v-if="detailError" :error="detailError" @retry="loadDetail" />
  <PlaybookRunDetails v-if="chosen" :key="chosen.id" :run="chosen" @updated="update" />
  <StatePanel
    v-if="pending || error || !page?.items?.length"
    :loading="pending"
    :error="error"
    :empty="!pending && !error && !page?.items?.length"
    title="暂无编排运行"
    @retry="load"
  />
  <section v-else-if="page" class="panel">
    <ListTable :columns="columns" :data-source="page.items" row-key="id">
      <template #bodyCell="{ column, record }">
        <span v-if="column.key === 'name'">{{ record.definition.name }}</span>
        <span v-else-if="column.key === 'progress'"
          >{{ record.results.length }} / {{ record.definition.steps.length }}</span
        >
        <StatusTag
          v-else-if="column.key === 'state'"
          :value="runStates[record.state as PlaybookRun['state']]"
          :tone="record.state === 'completed' ? 'success' : record.state === 'stopped' ? 'warning' : 'neutral'"
        />
        <span v-else-if="column.key === 'created'">{{ formatTime(record.created_at) }}</span>
        <Button v-else-if="column.key === 'action'" type="link" @click="open(record)">查看</Button>
      </template>
    </ListTable>
    <ListPager
      mode="cursor"
      :page="cursors.length"
      :page-size="pageSize"
      :count="page.items.length"
      :has-previous="cursors.length > 1"
      :has-next="!!page.next_cursor"
      :disabled="pending"
      @previous="pageBy(-1)"
      @next="pageBy(1)"
      @update:page-size="changePageSize"
    />
  </section>
</template>
