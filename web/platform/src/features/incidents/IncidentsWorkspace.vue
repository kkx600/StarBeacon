<script setup lang="ts">
import { useFeedback } from '@starbeacon/shared/composables/useFeedback.ts';
import { ref, shallowRef, watch } from 'vue';
import { session } from '../../session';
import { useRoute, useRouter } from 'vue-router';
import { Select as ASelect } from 'ant-design-vue';
import StatePanel from '@starbeacon/shared/components/StatePanel.vue';
import PageHeader from '@starbeacon/shared/components/PageHeader.vue';
import ListFilters from '@starbeacon/shared/components/ListFilters.vue';
import ListPager from '@starbeacon/shared/components/ListPager.vue';
import ListTable from '@starbeacon/shared/components/ListTable.vue';
import MetricBar from '@starbeacon/shared/components/MetricBar.vue';
import StatusTag from '@starbeacon/shared/components/StatusTag.vue';
import { alertSeverityTones } from '@starbeacon/shared/statusTones.ts';
import { formatTime } from '@starbeacon/shared/types.ts';
import IncidentForm from './IncidentForm.vue';
import IncidentDetail from './IncidentDetail.vue';
import IncidentTasksModal from './IncidentTasksModal.vue';
import IncidentNotesModal from './IncidentNotesModal.vue';
import { useIncidentNotes } from './useIncidentNotes';
import { useIncidentTasks } from './useIncidentTasks';
import {
  validIncidentRef,
  incidentStatuses,
  incidentStatusTones,
  incidentCategories,
  incidentSeverities,
  type IncidentRecord,
  type IncidentRef,
  type IncidentInput,
} from './incident';
import { useIncidents } from './useIncidents';
const message = useFeedback();
const route = useRoute(),
  router = useRouter(),
  state = useIncidents();
const {
  page,
  pending,
  error,
  cursors,
  pageSize,
  selected,
  detailPending,
  detailError,
  history,
  historyNext,
  historyPending,
  historyError,
  assignees,
  assigneePending,
  assigneeError,
  busy,
  unconfirmed,
  actionError,
  linkedID,
} = state;
const status = ref(''),
  severity = ref(''),
  detailOpen = ref(false),
  editorOpen = ref(false),
  editing = shallowRef<IncidentRecord | null>(null),
  draft = shallowRef<IncidentInput | undefined>(),
  seed = shallowRef<IncidentRef | undefined>();
const taskParent = shallowRef<IncidentRecord | null>(null),
  tasks = useIncidentTasks(taskParent),
  tasksOpen = ref(false);
const { unconfirmed: taskUnconfirmed } = tasks;
const noteParent = shallowRef<IncidentRecord | null>(null),
  notes = useIncidentNotes(noteParent),
  notesOpen = ref(false);
const { unconfirmed: noteUnconfirmed } = notes;
watch(notesOpen, open => {
  if (open) notes.open();
  else notes.close();
});
watch(
  () =>
    `${session.current.value?.tenant_id ?? ''}/${session.current.value?.id ?? ''}/${session.current.value?.role ?? ''}`,
  () => {
    tasksOpen.value = false;
    taskParent.value = null;
    notesOpen.value = false;
    noteParent.value = null;
  },
);
function openTasks() {
  if (tasks.busy.value) return;
  notesOpen.value = false;
  const original = tasks.pendingInput();
  const parent = original?.parent ?? selected.value;
  if (!parent) return;
  taskParent.value = parent;
  state.clearSelection();
  detailOpen.value = false;
  editorOpen.value = false;
  tasksOpen.value = true;
  void state.loadAssignees();
}
async function reloadTaskParent() {
  if (!taskParent.value || tasks.busy.value) return;
  const id = taskParent.value.id;
  await state.select(id);
  if (taskParent.value?.id === id && selected.value?.id === id) {
    taskParent.value = selected.value;
    await tasks.refresh();
  }
}
const columns = [
  { title: '事件编号', dataIndex: 'id', width: 132, ellipsis: true, className: 'technical' },
  { title: '事件标题', key: 'title', width: 190, ellipsis: true },
  { title: '状态', key: 'state', width: 90 },
  { title: '分类', key: 'category', width: 110 },
  { title: '严重度', key: 'severity', width: 80 },
  { title: '责任人', key: 'owner', width: 115, ellipsis: true },
  { title: '建立时间', key: 'created', width: 175, className: 'technical' },
  { title: '操作', key: 'actions', width: 68, fixed: 'right' as const },
];
function openNotes() {
  if (notes.busy.value) return;
  const original = notes.pendingInput();
  const parent = original?.parent ?? selected.value;
  if (!parent) return;
  noteParent.value = parent;
  state.clearSelection();
  detailOpen.value = false;
  editorOpen.value = false;
  tasksOpen.value = false;
  notesOpen.value = true;
}
async function reloadNoteParent() {
  if (!noteParent.value || notes.busy.value) return;
  const id = noteParent.value.id;
  await state.select(id);
  if (noteParent.value?.id === id && selected.value?.id === id) {
    noteParent.value = selected.value;
    await notes.refresh();
  }
}
function openEditor(record: IncidentRecord | null) {
  if (unconfirmed.value) {
    restoreAttempt();
    return;
  }
  tasksOpen.value = false;
  notesOpen.value = false;
  editing.value = record;
  draft.value = undefined;
  state.clearActionError();
  detailOpen.value = false;
  editorOpen.value = true;
  void state.loadAssignees();
}
function restoreAttempt() {
  const pending = state.pendingInput();
  if (!pending) return;
  tasksOpen.value = false;
  notesOpen.value = false;
  draft.value = pending.input;
  editing.value = pending.id && selected.value?.id === pending.id ? selected.value : null;
  detailOpen.value = false;
  editorOpen.value = true;
  void state.loadAssignees();
}
function showDetail(id: string) {
  tasksOpen.value = false;
  notesOpen.value = false;
  editorOpen.value = false;
  detailOpen.value = true;
  void state.select(id);
}
async function save(input: IncidentInput) {
  const id = state.pendingInput()?.id ?? editing.value?.id ?? '';
  if (await state.save(id, input)) {
    editorOpen.value = false;
    seed.value = undefined;
    draft.value = undefined;
    message.success(id ? '调查记录已提交' : '事件已建立');
    if (route.query.alert_id) void router.replace({ path: '/incidents' });
    detailOpen.value = true;
  }
}
async function confirm() {
  const id = state.pendingInput()?.id ?? '';
  if (await state.confirm()) {
    editorOpen.value = false;
    seed.value = undefined;
    draft.value = undefined;
    message.success(id ? '调查记录已确认' : '事件已确认');
    if (route.query.alert_id) void router.replace({ path: '/incidents' });
    detailOpen.value = true;
  }
}
const initial = { event_id: route.query.alert_id, raw_sha256: route.query.sha256 };
if (validIncidentRef(initial)) {
  seed.value = initial;
  openEditor(null);
}
</script>
<template>
  <PageHeader title="事件调查" description="关联检测事实与人工线索，记录责任分派、调查笔记、协作任务和结案依据。">
    <a-button :loading="pending" @click="state.refresh">刷新</a-button
    ><a-button v-if="noteUnconfirmed" @click="openNotes">核对笔记提交</a-button
    ><a-button v-if="taskUnconfirmed" @click="openTasks">核对任务提交</a-button
    ><a-button v-if="unconfirmed" type="primary" @click="restoreAttempt">核对原提交</a-button
    ><a-button
      v-else
      type="primary"
      @click="
        seed = undefined;
        openEditor(null);
      "
      >建立事件</a-button
    >
  </PageHeader>
  <a-form
    :model="{ status, severity }"
    :disabled="pending"
    layout="horizontal"
    @finish="state.search(status, severity)"
  >
    <ListFilters label="事件筛选" :columns="3">
      <a-form-item label="调查状态" html-for="incident-list-status"
        ><a-select
          id="incident-list-status"
          v-model:value="status"
          :options="[
            { value: '', label: '全部状态' },
            ...Object.entries(incidentStatuses).map(([value, label]) => ({ value, label })),
          ]" /></a-form-item
      ><a-form-item label="严重度" html-for="incident-list-severity"
        ><a-select
          id="incident-list-severity"
          v-model:value="severity"
          :options="[
            { value: '', label: '全部严重度' },
            ...Object.entries(incidentSeverities).map(([value, label]) => ({ value, label })),
          ]"
      /></a-form-item>
      <template #actions>
        <a-button type="primary" html-type="submit" :loading="pending">查询</a-button>
        <a-button
          :disabled="pending"
          @click="
            status = '';
            severity = '';
            state.search('', '');
          "
          >重置</a-button
        >
      </template>
    </ListFilters>
  </a-form>
  <section class="panel table-panel">
    <div class="table-toolbar">
      <h2>安全事件</h2>
      <MetricBar v-if="!pending && !error" embedded :items="[{ label: '本页事件', value: page.items.length }]" />
    </div>
    <StatePanel
      :loading="pending"
      :error="error"
      :empty="!page.items.length"
      description="当前条件下没有安全事件。可关联告警建立调查，或登记人工线索。"
      @retry="state.refresh"
    >
      <ListTable :data-source="page.items" :columns="columns" :scroll="{ x: 960 }">
        <template #bodyCell="{ column, record }">
          <button
            v-if="column.key === 'title'"
            type="button"
            class="record-link"
            :title="record.spec.title"
            @click="showDetail(record.id)"
          >
            {{ record.spec.title }}
          </button>
          <StatusTag
            v-else-if="column.key === 'state'"
            :tone="incidentStatusTones[record.spec.status]"
            :value="incidentStatuses[record.spec.status]"
          />
          <template v-else-if="column.key === 'category'">{{ incidentCategories[record.spec.category] }}</template>
          <StatusTag
            v-else-if="column.key === 'severity'"
            :tone="alertSeverityTones[record.spec.severity]"
            :value="incidentSeverities[record.spec.severity]"
          />
          <span v-else-if="column.key === 'owner'" :title="record.owner_name || undefined">{{
            record.owner_name || '待分派'
          }}</span>
          <template v-else-if="column.key === 'created'">{{ formatTime(record.created_at) }}</template>
          <button v-else-if="column.key === 'actions'" type="button" class="record-link" @click="showDetail(record.id)">
            查看
          </button>
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
      @previous="state.previous"
      @next="state.next"
      @update:page-size="state.changePageSize"
    />
  </section>
  <IncidentDetail
    v-if="detailOpen"
    :record="selected"
    :pending="detailPending"
    :error="detailError"
    :history="history"
    :history-pending="historyPending"
    :history-error="historyError"
    :next="historyNext"
    @close="
      detailOpen = false;
      state.clearSelection();
    "
    @edit="openEditor(selected)"
    @tasks="openTasks"
    @notes="openNotes"
    @reload="state.reloadDetail"
    @history="state.loadHistory"
  />
  <IncidentTasksModal
    v-if="tasksOpen && taskParent"
    :parent="taskParent"
    :state="tasks"
    :assignees="assignees"
    :owner-pending="assigneePending"
    :owner-error="assigneeError"
    :parent-pending="detailPending"
    :parent-error="detailError"
    @close="tasksOpen = false"
    @reload-parent="reloadTaskParent"
    @reload-owners="state.loadAssignees"
  />
  <IncidentNotesModal
    v-if="notesOpen && noteParent"
    :parent="noteParent"
    :state="notes"
    :parent-pending="detailPending"
    :parent-error="detailError"
    @close="notesOpen = false"
    @reload-parent="reloadNoteParent"
  />
  <IncidentForm
    v-if="editorOpen"
    :key="(draft ? 'frozen_' : '') + (editing?.id ?? 'create')"
    :record="editing"
    :draft="draft"
    :seed="seed"
    :assignees="assignees"
    :assignee-pending="assigneePending"
    :assignee-error="assigneeError"
    :busy="busy"
    :unconfirmed="unconfirmed"
    :error="actionError"
    :linked-id="linkedID"
    @save="save"
    @confirm="confirm"
    @close="editorOpen = false"
    @reload-owners="state.loadAssignees"
    @existing="showDetail"
  />
</template>
