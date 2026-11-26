<script setup lang="ts">
import { computed, onMounted, onScopeDispose, shallowRef } from 'vue';
import { RouterLink } from 'vue-router';
import { Alert, Button, Select, Checkbox, type TableColumnType } from 'ant-design-vue';
import { useFeedback } from '@starbeacon/shared/composables/useFeedback.ts';
import ListTable from '@starbeacon/shared/components/ListTable.vue';
import StatusTag from '@starbeacon/shared/components/StatusTag.vue';
import StatePanel from '@starbeacon/shared/components/StatePanel.vue';
import { session } from '../../session';
import DecisionPolicyForm from '../decisions/DecisionPolicyForm.vue';
import {
  automationLevels,
  validPolicy,
  type AutomationLevel,
  type PolicyChange,
  type PolicyRecord,
} from '../decisions/decisionPolicies';
import { useDecisionPolicies } from '../decisions/useDecisionPolicies';
import {
  levelOptions,
  readAutomation,
  validSettings,
  type AutomationScene,
  type AutomationState,
} from '../decisions/automation';

const feedback = useFeedback();
const state = shallowRef<AutomationState>();
const loading = shallowRef(true);
const error = shallowRef('');
const saveError = shallowRef('');
const sceneError = shallowRef('');
const saving = shallowRef(false);
const ceiling = shallowRef<AutomationLevel>('approval');
const paused = shallowRef(false);
const editor = shallowRef<PolicyRecord>();
const opening = shallowRef('');
const policies = useDecisionPolicies(false);
let reader: AbortController | undefined;
let writer: AbortController | undefined;
let sceneReader: AbortController | undefined;
const dirty = computed(
  () => state.value && (state.value.settings.ceiling !== ceiling.value || state.value.settings.paused !== paused.value),
);
const columns: TableColumnType<AutomationScene>[] = [
  { key: 'scene', title: '场景', width: 210 },
  { key: 'active', title: '状态', width: 90 },
  { dataIndex: 'level', key: 'level', title: '配置级别', width: 108 },
  { dataIndex: 'effective', key: 'effective', title: '有效级别', width: 108 },
  { key: 'limit', title: '小影响上限', width: 125 },
  { key: 'action', title: '操作', width: 76, fixed: 'right' },
];

async function load() {
  reader?.abort();
  const request = new AbortController();
  reader = request;
  loading.value = true;
  error.value = '';
  saveError.value = '';
  try {
    const data = await readAutomation(request.signal);
    if (request.signal.aborted) return;
    state.value = data;
    ceiling.value = data.settings.ceiling;
    paused.value = data.settings.paused;
  } catch (cause) {
    if (!request.signal.aborted) error.value = cause instanceof Error ? cause.message : '读取自动处置设置失败。';
  } finally {
    if (reader === request) loading.value = false;
  }
}
async function save() {
  if (!state.value || !dirty.value || saving.value || loading.value) return;
  const request = new AbortController();
  writer = request;
  saving.value = true;
  saveError.value = '';
  try {
    const result = await session.api.request<unknown>('/decision-automation', {
      method: 'PUT',
      body: { expected_revision: state.value.settings.revision, ceiling: ceiling.value, paused: paused.value },
      signal: request.signal,
    });
    if (request.signal.aborted) return;
    if (!validSettings(result) || result.ceiling !== ceiling.value || result.paused !== paused.value)
      throw new Error('设置回执不一致，请刷新核对。');
    feedback.success('自动处置设置已保存');
    await load();
  } catch (cause) {
    if (!request.signal.aborted)
      saveError.value = cause instanceof Error ? cause.message : '提交结果待核对，请刷新设置。';
  } finally {
    if (writer === request) saving.value = false;
  }
}
async function openScene(scene: AutomationScene) {
  const user = session.current.value;
  if (user?.role !== 'admin' || policies.busy.value || policies.unconfirmed.value) return;
  sceneReader?.abort();
  const request = new AbortController();
  sceneReader = request;
  sceneError.value = '';
  opening.value = scene.id;
  policies.clearError();
  try {
    const row = await session.api.request<PolicyRecord>(
      '/decision-policies/' + encodeURIComponent(scene.id) + '/revisions/' + scene.revision,
      { signal: request.signal },
    );
    if (!(await validPolicy(row, user.tenant_id)) || row.id !== scene.id || row.revision !== scene.revision)
      throw new Error('策略修订与所选场景不一致，请刷新后重试。');
    if (!request.signal.aborted) editor.value = row;
  } catch (cause) {
    if (!request.signal.aborted) sceneError.value = cause instanceof Error ? cause.message : '场景读取失败。';
  } finally {
    if (sceneReader === request) opening.value = '';
  }
}
async function saveScene(change?: PolicyChange) {
  const row = change ? await policies.save(change) : await policies.confirm();
  if (!row) return;
  editor.value = undefined;
  feedback.success('场景配置已保存');
  await load();
}
onMounted(load);
onScopeDispose(() => {
  reader?.abort();
  writer?.abort();
  sceneReader?.abort();
});
</script>

<template>
  <section class="panel table-panel">
    <div class="table-toolbar">
      <h2>自动处置</h2>
      <RouterLink to="/ai/ai-ops">查看 AI 值守</RouterLink>
    </div>
    <StatePanel :loading="loading" :error="error" @retry="load">
      <form v-if="state" class="panel-body automation-fields" @submit.prevent="save">
        <Alert v-if="saveError" show-icon type="error" :message="saveError" />
        <div class="automation-controls">
          <label for="automation-ceiling">全局自动化上限</label>
          <Select id="automation-ceiling" v-model:value="ceiling" :options="levelOptions" :disabled="saving" />
          <Checkbox v-model:checked="paused" :disabled="saving">暂停自动处置</Checkbox>
          <Button type="primary" html-type="submit" :disabled="!dirty" :loading="saving">保存设置</Button>
          <Button :disabled="saving" @click="load">刷新设置</Button>
        </div>
        <p class="muted">全局上限约束所有场景。取消暂停并保存后，具备原授权的场景按有效级别处理新告警。</p>
      </form>
    </StatePanel>
  </section>
  <section class="panel table-panel">
    <div class="table-toolbar">
      <h2>场景自动化级别</h2>
      <Button v-if="policies.unconfirmed.value && !editor" :loading="policies.busy.value" @click="saveScene()"
        >核对原提交</Button
      >
      <RouterLink v-else to="/response/policies">决策策略</RouterLink>
    </div>
    <Alert v-if="sceneError" show-icon type="error" :message="sceneError" class="scene-error" />
    <StatePanel
      :loading="loading"
      :error="error"
      :empty="!state?.scenes.length"
      description="当前没有决策场景。"
      @retry="load"
    >
      <ListTable :columns="columns" :data-source="state?.scenes ?? []" :scroll="{ x: 717 }">
        <template #bodyCell="{ column, record }">
          <template v-if="column.key === 'scene'">
            <div>{{ record.name }}</div>
            <small class="technical">{{ record.id }} · v{{ record.revision }}</small>
          </template>
          <StatusTag
            v-else-if="column.key === 'active'"
            :value="record.active ? '启用' : '停用'"
            :tone="record.active ? 'success' : 'neutral'"
          />
          <template v-else-if="column.key === 'level'">{{ automationLevels[record.level] }}</template>
          <template v-else-if="column.key === 'effective'">{{ automationLevels[record.effective] }}</template>
          <template v-else-if="column.key === 'limit'">{{ record.small_block_max_seconds }} 秒</template>
          <Button
            v-else-if="column.key === 'action'"
            type="link"
            size="small"
            :loading="opening === record.id"
            :disabled="policies.busy.value || policies.unconfirmed.value"
            @click="openScene(record)"
            >编辑</Button
          >
        </template>
      </ListTable>
    </StatePanel>
  </section>
  <DecisionPolicyForm
    v-if="editor"
    :key="editor.id + '/' + editor.revision"
    :record="editor"
    :draft="policies.draft()"
    :busy="policies.busy.value"
    :unconfirmed="policies.unconfirmed.value"
    :error="policies.mutationError.value"
    automation
    @save="saveScene"
    @confirm="saveScene()"
    @close="editor = undefined"
  />
</template>

<style scoped>
.automation-fields {
  display: grid;
  gap: var(--related-gap);
}
.automation-controls {
  display: flex;
  align-items: center;
  flex-wrap: wrap;
  gap: var(--field-gap);
}
.automation-controls :deep(.ant-select) {
  min-width: 124px;
}
.automation-fields p {
  margin: 0;
}
.scene-error {
  margin: 0 var(--panel-inset) var(--related-gap);
}
</style>
