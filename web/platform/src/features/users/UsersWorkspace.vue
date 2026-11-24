<script setup lang="ts">
import { useFeedback } from '@starbeacon/shared/composables/useFeedback.ts';
import { ref, shallowRef } from 'vue';
import { Select as ASelect } from 'ant-design-vue';
import { formatTime } from '@starbeacon/shared/types.ts';
import StatePanel from '@starbeacon/shared/components/StatePanel.vue';
import PageHeader from '@starbeacon/shared/components/PageHeader.vue';
import ListTable from '@starbeacon/shared/components/ListTable.vue';
import ListFilters from '@starbeacon/shared/components/ListFilters.vue';
import ListPager from '@starbeacon/shared/components/ListPager.vue';
import StatusTag from '@starbeacon/shared/components/StatusTag.vue';
import { statusTerms } from '@starbeacon/shared/terms.ts';
import { session } from '../../session';
import { useUsers } from './useUsers';
import { userRoles, type UserInput, type UserRecord } from './user';
import UserForm from './UserForm.vue';
import UserDetail from './UserDetail.vue';
import PasswordDialog from './PasswordDialog.vue';
const message = useFeedback();
const passwordRecord = shallowRef<UserRecord | null>(null);
const state = useUsers();
const {
  page,
  pending,
  error,
  cursors,
  pageSize,
  selected,
  detailPending,
  detailError,
  busy,
  unconfirmed,
  actionError,
} = state;
const role = ref(''),
  active = ref(''),
  detailOpen = ref(false),
  editorOpen = ref(false),
  editing = shallowRef<UserRecord | null>(null),
  draft = shallowRef<UserInput | undefined>();
const columns = [
  { title: '用户编号', dataIndex: 'id', width: 146, className: 'technical', ellipsis: true },
  { title: '账号名称', dataIndex: 'username', width: 186, ellipsis: true },
  { title: '用户角色', key: 'role', width: 130 },
  { title: '账号状态', key: 'active', width: 110 },
  { title: '创建时间', key: 'created', width: 190 },
  { title: '变更时间', key: 'updated', width: 190 },
  { title: '操作', key: 'actions', width: 68, fixed: 'right' as const },
];
function restoreAttempt() {
  const frozen = state.pendingInput();
  if (!frozen) return;
  draft.value = frozen.input;
  editing.value = frozen.id && selected.value?.id === frozen.id ? selected.value : null;
  detailOpen.value = false;
  editorOpen.value = true;
}
function openEditor(record: UserRecord | null) {
  if (unconfirmed.value) {
    restoreAttempt();
    return;
  }
  editing.value = record;
  draft.value = undefined;
  state.clearActionError();
  detailOpen.value = false;
  editorOpen.value = true;
}
function showDetail(id: string) {
  editorOpen.value = false;
  detailOpen.value = true;
  void state.select(id);
}
async function saved(result: UserRecord | undefined) {
  if (!result) return;
  editorOpen.value = false;
  draft.value = undefined;
  editing.value = null;
  message.success('用户操作已确认');
  showDetail(result.id);
}
async function save(input: UserInput) {
  await saved(await state.save(state.pendingInput()?.id ?? editing.value?.id ?? '', input));
}
async function confirm() {
  await saved(await state.confirm());
}
</script>
<template>
  <PageHeader title="用户管理" description="维护本租户的账号、角色与启用状态，权限变更同步撤销目标用户的既有会话。">
    <a-button :loading="pending" @click="state.refresh">刷新</a-button
    ><a-button v-if="unconfirmed" type="primary" @click="restoreAttempt">核对原提交</a-button
    ><a-button v-else type="primary" @click="openEditor(null)">创建用户</a-button>
  </PageHeader>
  <a-form :model="{ role, active }" layout="horizontal" @finish="state.search(role, active)">
    <ListFilters :columns="2" label="用户管理筛选">
      <a-form-item label="用户角色" html-for="user-role"
        ><a-select
          id="user-role"
          v-model:value="role"
          aria-label="筛选用户角色"
          :options="[
            { value: '', label: '全部角色' },
            ...Object.entries(userRoles).map(([value, label]) => ({ value, label })),
          ]" /></a-form-item
      ><a-form-item label="账号状态" html-for="user-active"
        ><a-select
          id="user-active"
          v-model:value="active"
          aria-label="筛选账号状态"
          :options="[
            { value: '', label: '全部状态' },
            { value: 'true', label: '启用' },
            { value: 'false', label: '停用' },
          ]"
      /></a-form-item>
      <template #actions>
        <a-button type="primary" html-type="submit" :loading="pending">查询</a-button
        ><a-button
          :disabled="pending"
          @click="
            role = '';
            active = '';
            state.search('', '');
          "
          >重置</a-button
        >
      </template>
    </ListFilters>
  </a-form>
  <section class="panel">
    <div class="panel-header">
      <h2>租户用户</h2>
    </div>
    <StatePanel
      :loading="pending"
      :error="error"
      :empty="!page.items.length"
      description="当前条件下没有用户。请调整筛选条件，或创建本租户账号。"
      @retry="state.refresh"
      ><ListTable :data-source="page.items" :columns="columns" :scroll="{ x: 1020 }"
        ><template #bodyCell="{ column, record }"
          ><template v-if="column.key === 'role'">{{ userRoles[record.role] }}</template
          ><StatusTag
            v-else-if="column.key === 'active'"
            :value="record.active ? '启用' : '停用'"
            :tone="record.active ? statusTerms.启用 : statusTerms.停用"
          /><template v-else-if="column.key === 'created'">{{ formatTime(record.created_at) }}</template
          ><template v-else-if="column.key === 'updated'">{{ formatTime(record.updated_at) }}</template
          ><a-button v-else-if="column.key === 'actions'" size="small" type="link" @click="showDetail(record.id)"
            >查看</a-button
          ></template
        ></ListTable
      ></StatePanel
    >
    <ListPager
      mode="cursor"
      :page="cursors.length"
      :page-size="pageSize"
      :count="error ? undefined : page.items.length"
      :has-previous="cursors.length > 1"
      :has-next="!error && !!page.next_cursor"
      :disabled="pending"
      @previous="state.previous"
      @next="state.next"
      @update:page-size="state.changePageSize"
    />
  </section>
  <UserDetail
    v-if="detailOpen"
    :record="selected"
    :pending="detailPending"
    :error="detailError"
    :self-id="session.current.value?.id ?? ''"
    @close="
      detailOpen = false;
      state.clearSelection();
    "
    @reload="state.reloadDetail"
    @edit="openEditor(selected)"
    @password="
      passwordRecord = selected;
      detailOpen = false;
    "
  />
  <PasswordDialog
    v-if="passwordRecord"
    :record="passwordRecord"
    :own="false"
    @close="passwordRecord = null"
    @changed="
      state.refresh();
      state.reloadDetail();
    "
  />
  <UserForm
    v-if="editorOpen"
    :key="(draft ? 'frozen_' : '') + (editing?.id ?? 'create')"
    :record="editing"
    :draft="draft"
    :self-id="session.current.value?.id ?? ''"
    :busy="busy"
    :unconfirmed="unconfirmed"
    :error="actionError"
    @close="editorOpen = false"
    @save="save"
    @confirm="confirm"
  />
</template>
