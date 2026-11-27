<script setup lang="ts">
import { computed, onMounted, onScopeDispose, ref, shallowRef, watch } from 'vue';
import { RouterLink, useRoute, useRouter } from 'vue-router';
import { Alert, Button, Input, Modal, Select } from 'ant-design-vue';
import { PlusOutlined, RobotOutlined } from '@ant-design/icons-vue';
import PageHeader from '@starbeacon/shared/components/PageHeader.vue';
import StatusTag from '@starbeacon/shared/components/StatusTag.vue';
import { useFeedback } from '@starbeacon/shared/composables/useFeedback.ts';
import { session } from '../session';
import CopilotAnalysis from '../features/copilot/CopilotAnalysis.vue';
import type { DraftStep } from '../features/analysis/analysis';
import PlaybookEditor from '../features/playbooks/PlaybookEditor.vue';
import {
  adoptDraft,
  errorText,
  isDigest,
  issueNames,
  newDefinition,
  request,
  stepNames,
  type AlertIdentity,
  type Page,
  type Playbook,
  type PlaybookIssue,
  type PlaybookRun,
} from '../features/playbooks/playbooks';

const route = useRoute(),
  router = useRouter(),
  feedback = useFeedback();
const catalog = shallowRef<Playbook[]>([]);
const selected = ref<string>();
const definition = ref(newDefinition());
const issues = shallowRef<PlaybookIssue[]>();
const busy = ref(false),
  loading = ref(false),
  failure = ref(''),
  catalogError = ref('');
const aiOpen = ref(false),
  rehearsal = ref(false),
  startOpen = ref(false);
const source = ref<AlertIdentity>({ event_id: '', raw_sha256: '' });
let read: AbortController | undefined;
let mutation: AbortController | undefined;
let saveAttempt: { stamp: string; key: string } | undefined;
let startAttempt: { stamp: string; key: string } | undefined;
const saved = computed(() => catalog.value.find(item => item.id === selected.value));
const dirty = computed(
  () => !saved.value || JSON.stringify(saved.value.definition) !== JSON.stringify(definition.value),
);
const mine = computed(() => !saved.value || saved.value.owner_id === session.current.value?.id);
const options = computed(() =>
  catalog.value.map(item => ({
    value: item.id,
    label: item.definition.name + (item.published_revision ? ' · 已发布 ' + item.published_revision : ' · 草稿'),
  })),
);
const routeAlert = computed(() =>
  isDigest(route.query.event_id) && isDigest(route.query.sha256)
    ? { event_id: route.query.event_id, raw_sha256: route.query.sha256 }
    : undefined,
);
const sourceValid = computed(() => isDigest(source.value.event_id) && isDigest(source.value.raw_sha256));

async function load() {
  read?.abort();
  const control = new AbortController();
  read = control;
  loading.value = true;
  catalogError.value = '';
  try {
    const page = await session.api.request<Page<Playbook>>('/playbooks?limit=100', { signal: control.signal });
    if (control.signal.aborted) return;
    catalog.value = page.items ?? [];
    if (!selected.value && catalog.value[0] && !definition.value.name.trim()) select(catalog.value[0].id);
  } catch (cause) {
    if (!control.signal.aborted) catalogError.value = errorText(cause);
  } finally {
    if (read === control) loading.value = false;
  }
}
function select(id?: string) {
  const item = catalog.value.find(row => row.id === id);
  selected.value = item?.id;
  definition.value = item ? structuredClone(item.definition) : newDefinition();
  issues.value = undefined;
  failure.value = '';
}
watch(
  definition,
  () => {
    issues.value = undefined;
  },
  { deep: true, flush: 'sync' },
);
async function perform(fn: (signal: AbortSignal) => Promise<unknown>) {
  if (busy.value) return;
  const control = new AbortController();
  mutation = control;
  busy.value = true;
  failure.value = '';
  try {
    await fn(control.signal);
  } catch (cause) {
    if (!control.signal.aborted) failure.value = errorText(cause);
  } finally {
    if (mutation === control) busy.value = false;
  }
}
async function validate(signal: AbortSignal) {
  const result = await request<{ issues: PlaybookIssue[] }>(
    '/playbooks/validate',
    'POST',
    definition.value,
    undefined,
    signal,
  );
  if (!signal.aborted) issues.value = result.issues;
  return result.issues.length === 0;
}
function update(item: Playbook) {
  catalog.value = [...catalog.value.filter(row => row.id !== item.id), item].sort((a, b) => a.id.localeCompare(b.id));
  select(item.id);
}
function save() {
  void perform(async signal => {
    await validate(signal);
    if (signal.aborted) return;
    const existing = saved.value;
    const input = { expected_revision: existing?.revision ?? 0, definition: definition.value };
    const stamp = (existing?.id ?? '') + JSON.stringify(input);
    if (saveAttempt?.stamp !== stamp) saveAttempt = { stamp, key: crypto.randomUUID() };
    const result = await request<Playbook>(
      existing ? '/playbooks/' + existing.id : '/playbooks',
      existing ? 'PUT' : 'POST',
      input,
      saveAttempt.key,
      signal,
    );
    if (signal.aborted) return;
    const validation = issues.value;
    update(result);
    issues.value = validation;
    saveAttempt = undefined;
    feedback.success('草稿已保存');
  });
}
function publish() {
  const item = saved.value;
  if (!item || dirty.value || !mine.value) return;
  void perform(async signal => {
    if (!(await validate(signal)) || signal.aborted) return;
    const result = await request<Playbook>(
      '/playbooks/' + item.id + '/publish',
      'POST',
      { revision: item.revision, sha256: item.sha256 },
      undefined,
      signal,
    );
    if (signal.aborted) return;
    update(result);
    feedback.success('编排修订已发布');
  });
}
function importSteps(steps: DraftStep[]) {
  definition.value.steps = adoptDraft(steps);
  aiOpen.value = false;
}
function openStart() {
  source.value = routeAlert.value ? { ...routeAlert.value } : { event_id: '', raw_sha256: '' };
  failure.value = '';
  startOpen.value = true;
}
function start() {
  const item = saved.value;
  if (!item?.published_revision || !item.published_sha256 || !sourceValid.value) return;
  void perform(async signal => {
    const input = { ...source.value, revision: item.published_revision, sha256: item.published_sha256 };
    const stamp = item.id + JSON.stringify(input);
    if (startAttempt?.stamp !== stamp) startAttempt = { stamp, key: crypto.randomUUID() };
    const result = await request<PlaybookRun>(
      '/playbooks/' + item.id + '/runs',
      'POST',
      input,
      startAttempt.key,
      signal,
    );
    if (signal.aborted) return;
    startAttempt = undefined;
    startOpen.value = false;
    await router.push({ path: '/response/playbook-runs', query: { run: result.id } });
  });
}
onMounted(load);
onScopeDispose(() => {
  read?.abort();
  mutation?.abort();
});
</script>

<template>
  <PageHeader title="自动化编排" description="编辑顺序步骤，校验并发布固定修订。运行时由操作员逐步确认。">
    <RouterLink to="/response/playbook-runs">运行记录</RouterLink>
    <Button :disabled="busy" @click="select()"><PlusOutlined aria-hidden="true" /> 新建编排</Button>
    <Button :disabled="busy || !mine" @click="aiOpen = true"><RobotOutlined aria-hidden="true" /> AI 生成编排</Button>
  </PageHeader>
  <div class="playbook-toolbar">
    <Select
      aria-label="选择编排"
      :value="selected"
      :options="options"
      placeholder="选择已保存的编排"
      :loading="loading"
      :disabled="busy"
      @update:value="v => select(String(v))"
    />
    <StatusTag
      v-if="saved"
      :value="'修订 ' + saved.revision + (saved.revision === saved.published_revision ? ' · 已发布' : ' · 草稿')"
      :tone="saved.revision === saved.published_revision ? 'success' : 'neutral'"
    />
    <Button :disabled="busy" @click="rehearsal = true">演练路径</Button>
    <Button :disabled="busy || !definition.name.trim()" @click="perform(validate)">校验</Button>
    <Button :disabled="busy || !mine || !dirty || !definition.name.trim()" @click="save">保存草稿</Button>
    <Button
      type="primary"
      :disabled="busy || !mine || !saved || dirty || saved.published_revision === saved.revision"
      @click="publish"
      >发布修订</Button
    >
    <Button
      v-if="saved?.published_revision"
      :type="routeAlert ? 'primary' : 'default'"
      :disabled="busy"
      @click="openStart"
      >从告警运行</Button
    >
  </div>
  <Alert v-if="routeAlert" type="info" show-icon message="已带入原告警。选择已发布的编排后可核对并启动。" />
  <Alert v-if="catalogError" type="error" show-icon :message="catalogError">
    <template #action><Button size="small" @click="load">重试</Button></template>
  </Alert>
  <Alert v-if="failure && !startOpen" type="error" show-icon :message="failure" />
  <Alert
    v-if="issues"
    :type="issues.length ? 'warning' : 'success'"
    show-icon
    :message="issues.length ? '发布前需要核对这些步骤' : '编排校验通过'"
  >
    <template v-if="issues.length" #description>
      <ul class="issues">
        <li v-for="item in issues" :key="item.step + item.code">
          第 {{ item.step + 1 }} 步 {{ issueNames[item.code] ?? '步骤配置待核对。' }}
        </li>
      </ul>
    </template>
  </Alert>
  <PlaybookEditor :key="selected ?? 'draft'" v-model="definition" :disabled="busy || !mine" />
  <Modal v-model:open="aiOpen" title="AI 生成编排" :footer="null" :width="680" destroy-on-close>
    <CopilotAnalysis v-if="aiOpen" draft adoptable context="自动化编排" @adopt="importSteps" />
  </Modal>
  <Modal v-model:open="rehearsal" title="演练路径" :footer="null" :width="640">
    <ol class="rehearsal">
      <li v-for="(step, index) in definition.steps" :key="index">
        <strong>{{ step.name || stepNames[step.kind] }}</strong>
        <p v-if="step.description" class="muted">{{ step.description }}</p>
      </li>
    </ol>
    <p class="muted">此处预览步骤顺序。实际运行需要已发布修订和真实告警。</p>
  </Modal>
  <Modal
    v-model:open="startOpen"
    title="从告警运行"
    ok-text="启动编排"
    cancel-text="取消"
    :confirm-loading="busy"
    :ok-button-props="{ disabled: !sourceValid }"
    :closable="!busy"
    :mask-closable="!busy"
    @ok="start"
  >
    <div class="start-form">
      <p>{{ saved?.definition.name }} · 已发布修订 {{ saved?.published_revision }}</p>
      <label for="playbook-event">告警标识</label>
      <Input id="playbook-event" v-model:value="source.event_id" :maxlength="64" :disabled="busy" />
      <label for="playbook-sha">告警原文摘要</label>
      <Input id="playbook-sha" v-model:value="source.raw_sha256" :maxlength="64" :disabled="busy" />
      <Alert v-if="failure" type="error" show-icon :message="failure" />
    </div>
  </Modal>
</template>

<style scoped>
.playbook-toolbar {
  display: flex;
  align-items: center;
  gap: var(--related-gap);
  flex-wrap: wrap;
}
.playbook-toolbar :deep(.ant-select) {
  min-width: 220px;
}
.start-form {
  display: grid;
  gap: var(--related-gap);
}
.issues,
.rehearsal p {
  margin-block: 0;
}
.rehearsal li + li {
  margin-top: var(--related-gap);
}
</style>
