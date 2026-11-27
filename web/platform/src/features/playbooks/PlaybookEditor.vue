<script setup lang="ts">
import { computed, onMounted, onScopeDispose, ref, shallowRef } from 'vue';
import { Alert, Button, Input, InputNumber, Select } from 'ant-design-vue';
import { ArrowDownOutlined, PlusOutlined } from '@ant-design/icons-vue';
import StatusTag from '@starbeacon/shared/components/StatusTag.vue';
import { emptyDeviceQuery, readDevicePage, type ResponseDevice } from '@starbeacon/shared/responseDevices.ts';
import { session } from '../../session';
import { useModels } from '../models/useModels';
import type { PolicyPage, PolicyRecord } from '../decisions/decisionPolicies';
import type { GatewayPage, GatewayPolicy } from '../gateway/gatewayBlocks';
import {
  actionSteps,
  bindingValue,
  deviceValue,
  errorText,
  maxSteps,
  stepNames,
  type ModelBinding,
  type PlaybookDefinition,
  type PluginBinding,
  type StepKind,
} from './playbooks';

const definition = defineModel<PlaybookDefinition>({ required: true });
const props = defineProps<{ disabled?: boolean }>();
const modelState = useModels();
const selected = ref(0);
const kind = ref<StepKind>();
const loading = ref(false);
const error = ref('');
const policies = shallowRef<PolicyRecord[]>([]);
const gateways = shallowRef<GatewayPolicy[]>([]);
const devices = shallowRef<ResponseDevice[]>([]);
const options = Object.entries(stepNames)
  .filter(([key]) => key !== 'trigger')
  .map(([value, label]) => ({ value, label }));
const severities = [
  { value: '', label: '全部严重级别' },
  { value: 'low', label: '低危及以上' },
  { value: 'medium', label: '中危及以上' },
  { value: 'high', label: '高危及以上' },
  { value: 'critical', label: '严重' },
];
const current = computed(() => definition.value.steps[selected.value] ?? definition.value.steps[0]);
const usableModels = computed(() => modelState.items.value.filter(m => m.enabled && m.has_key));
const modelOptions = computed(() =>
  usableModels.value.map(m => ({ value: bindingValue(m)!, label: m.name + ' · 修订 ' + m.revision })),
);
const policyOptions = computed(() =>
  policies.value
    .filter(
      p =>
        p.active &&
        p.definition.mode === 'approval' &&
        p.definition.automation_level !== 'observe' &&
        p.definition.candidate_action === 'block_source',
    )
    .map(p => ({ value: bindingValue(p)!, label: p.name + ' · 修订 ' + p.revision })),
);
const gatewayOptions = computed(() =>
  gateways.value
    .filter(
      p =>
        p.definition.enabled &&
        p.definition.trigger === 'review' &&
        !p.definition.follow_up &&
        Date.parse(p.definition.valid_until) > Date.now(),
    )
    .map(p => ({ value: bindingValue(p)!, label: p.definition.name + ' · 修订 ' + p.revision })),
);
const deviceOptions = computed(() =>
  devices.value
    .filter(d => d.sensor_status !== 'disabled' && d.task_supported)
    .map(d => ({ value: deviceValue(d)!, label: d.sensor_name + ' / ' + d.device_id })),
);
const maximumTTL = computed(
  () => devices.value.find(d => deviceValue(d) === deviceValue(current.value?.plugin))?.max_ttl_seconds ?? 3600,
);
let read: AbortController | undefined;

async function loadResources() {
  read?.abort();
  const control = new AbortController();
  read = control;
  const signal = control.signal;
  loading.value = true;
  error.value = '';
  const q = { ...emptyDeviceQuery(), limit: 100 };
  const query = new URLSearchParams(Object.entries(q).map(([key, value]) => [key, String(value)]));
  const [a, b, c] = await Promise.allSettled([
    session.api.request<PolicyPage>('/decision-policies?limit=100', { signal }),
    session.api.request<GatewayPage<GatewayPolicy>>('/gateway-block/policies?limit=100', { signal }),
    session.api.request('/response-connectors?' + query.toString(), { signal }).then(v => readDevicePage(v, q)),
  ]);
  if (signal.aborted) return;
  if (a.status === 'fulfilled') policies.value = a.value.items ?? [];
  if (b.status === 'fulfilled') gateways.value = b.value.items ?? [];
  if (c.status === 'fulfilled') devices.value = c.value.items;
  const failure = [a, b, c].find(result => result.status === 'rejected');
  if (failure?.status === 'rejected') error.value = errorText(failure.reason);
  loading.value = false;
}
onMounted(loadResources);
onScopeDispose(() => read?.abort());

function setModel(value?: string) {
  if (!current.value) return;
  const candidate = usableModels.value.find(item => bindingValue(item) === value);
  const next: ModelBinding | undefined = candidate
    ? {
        id: candidate.id,
        revision: candidate.revision,
        minimum_confidence: current.value.model?.minimum_confidence ?? 0.9,
      }
    : undefined;
  current.value.model = next;
}
function setPolicy(value?: string) {
  if (!current.value) return;
  const candidate = policies.value.find(item => bindingValue(item) === value);
  if (!candidate) return;
  const previous = current.value.plugin;
  const binding: PluginBinding = {
    policy: { id: candidate.id, revision: candidate.revision },
    sensor_id: previous?.sensor_id ?? '',
    registration_id: previous?.registration_id ?? '',
    connector_id: previous?.connector_id ?? '',
    config_sha256: previous?.config_sha256 ?? '',
    ttl_seconds: previous?.ttl_seconds ?? 60,
  };
  current.value.plugin = binding;
}
function setDevice(value?: string) {
  const binding = current.value?.plugin;
  const candidate = devices.value.find(d => deviceValue(d) === value);
  if (!binding || !candidate) return;
  binding.sensor_id = candidate.sensor_id;
  binding.registration_id = candidate.registration_id;
  binding.connector_id = candidate.connector_id;
  binding.config_sha256 = candidate.config_sha256;
  binding.ttl_seconds = Math.min(binding.ttl_seconds, candidate.max_ttl_seconds);
}
function setGateway(value?: string) {
  if (!current.value) return;
  const candidate = gateways.value.find(p => bindingValue(p) === value);
  current.value.gateway = candidate ? { id: candidate.id, revision: candidate.revision } : undefined;
}
function add() {
  if (!kind.value || props.disabled) return;
  const steps = actionSteps(kind.value);
  if (steps.length + definition.value.steps.length > maxSteps) return;
  selected.value = definition.value.steps.length + (steps.length > 1 ? 2 : 0);
  definition.value.steps.push(...steps);
  kind.value = undefined;
}
function move(delta: -1 | 1) {
  const from = selected.value,
    to = from + delta,
    steps = definition.value.steps;
  if (from < 1 || to < 1 || to >= steps.length) return;
  [steps[from], steps[to]] = [steps[to]!, steps[from]!];
  selected.value = to;
}
function remove() {
  if (selected.value < 1) return;
  definition.value.steps.splice(selected.value, 1);
  selected.value = Math.min(selected.value, definition.value.steps.length - 1);
}
</script>

<template>
  <div class="playbook-grid">
    <section class="panel flow-panel">
      <label for="playbook-name">编排名</label>
      <Input
        id="playbook-name"
        v-model:value="definition.name"
        :maxlength="128"
        :disabled="disabled"
        placeholder="输入编排名"
      />
      <ol class="flow-list" aria-label="编排步骤">
        <li v-for="(step, index) in definition.steps" :key="index">
          <button type="button" class="flow-step" :aria-pressed="current === step" @click="selected = index">
            <span class="step-number technical">{{ String(index + 1).padStart(2, '0') }}</span>
            <span>
              <strong>{{ step.name || stepNames[step.kind] }}</strong>
              <small>{{ stepNames[step.kind] }}</small>
            </span>
            <ArrowDownOutlined v-if="index < definition.steps.length - 1" aria-hidden="true" />
          </button>
        </li>
      </ol>
      <div class="flow-add">
        <Select
          v-model:value="kind"
          aria-label="步骤类型"
          :options="options"
          placeholder="选择步骤类型"
          :disabled="disabled || definition.steps.length >= maxSteps"
        />
        <Button
          :disabled="disabled || !kind || actionSteps(kind).length + definition.steps.length > maxSteps"
          @click="add"
          ><PlusOutlined aria-hidden="true" /> 添加步骤</Button
        >
      </div>
    </section>
    <section v-if="current" class="panel step-panel">
      <div class="inspector-heading">
        <h2>步骤配置</h2>
        <StatusTag :value="stepNames[current.kind]" tone="neutral" />
      </div>
      <label for="playbook-step-name">步骤名称</label>
      <Input id="playbook-step-name" v-model:value="current.name" :maxlength="128" :disabled="disabled" />
      <label for="playbook-description">说明</label>
      <Input id="playbook-description" v-model:value="current.description" :maxlength="240" :disabled="disabled" />
      <template v-if="current.kind === 'trigger'">
        <label for="playbook-severity">最低严重级别</label>
        <Select
          id="playbook-severity"
          v-model:value="current.minimum_severity"
          :options="severities"
          placeholder="全部严重级别"
          :disabled="disabled"
        />
      </template>
      <template v-else-if="current.kind === 'triage'">
        <label for="playbook-provider">研判模型</label>
        <Select
          id="playbook-provider"
          :value="bindingValue(current.model)"
          :options="modelOptions"
          placeholder="请选择已启用的模型"
          :loading="modelState.pending.value"
          :disabled="disabled"
          @update:value="v => setModel(String(v))"
        />
        <template v-if="current.model">
          <label for="playbook-confidence">最低模型自报置信度</label>
          <InputNumber
            id="playbook-confidence"
            v-model:value="current.model.minimum_confidence"
            :min="0.01"
            :max="1"
            :step="0.05"
            :disabled="disabled"
          />
        </template>
      </template>
      <template v-else-if="current.kind === 'plugin'">
        <label for="playbook-policy">人机协同策略</label>
        <Select
          id="playbook-policy"
          :value="bindingValue(current.plugin?.policy)"
          :options="policyOptions"
          placeholder="请选择策略"
          :loading="loading"
          :disabled="disabled"
          @update:value="v => setPolicy(String(v))"
        />
        <template v-if="current.plugin">
          <label for="playbook-device">联动设备</label>
          <Select
            id="playbook-device"
            :value="deviceValue(current.plugin)"
            :options="deviceOptions"
            placeholder="请选择登记的联动设备"
            :loading="loading"
            :disabled="disabled"
            @update:value="v => setDevice(String(v))"
          />
          <label for="playbook-ttl">封禁源地址时长（秒）</label>
          <InputNumber
            id="playbook-ttl"
            v-model:value="current.plugin.ttl_seconds"
            :min="30"
            :max="maximumTTL"
            :disabled="disabled"
          />
        </template>
      </template>
      <template v-else-if="current.kind === 'gateway'">
        <label for="playbook-gateway">网关策略</label>
        <Select
          id="playbook-gateway"
          :value="bindingValue(current.gateway)"
          :options="gatewayOptions"
          placeholder="请选择人工研判触发的网关策略"
          :loading="loading"
          :disabled="disabled"
          @update:value="v => setGateway(String(v))"
        />
      </template>
      <template v-else>
        <Alert
          type="info"
          show-icon
          :message="
            {
              condition: '只有已确认的研判结论才能继续。',
              protection: '检查原告警的源和目的地址，签发动作时再次核对。',
              approval: '操作员确认冻结的动作范围，确认有效期为 15 分钟。',
              verify: '从原任务的设备回执核验。网关有出侧观察时同时记录实际结果。',
              compensate: '沿用原授权的到期解除，保存租约期限供后续回读。',
              notify: '操作员完成通知后登记。',
            }[current.kind]
          "
        />
      </template>
      <Alert v-if="error" type="warning" show-icon :message="error">
        <template #action><Button size="small" @click="loadResources">重试</Button></template>
      </Alert>
      <div class="step-buttons">
        <Button :disabled="disabled || selected <= 1" @click="move(-1)">上移</Button>
        <Button :disabled="disabled || selected === 0 || selected >= definition.steps.length - 1" @click="move(1)"
          >下移</Button
        >
        <Button danger :disabled="disabled || selected === 0" @click="remove">删除</Button>
      </div>
    </section>
  </div>
</template>

<style scoped>
.playbook-grid {
  display: grid;
  grid-template-columns: minmax(0, 1.35fr) minmax(300px, 1fr);
  gap: var(--section-gap);
  align-items: start;
}
.flow-panel,
.step-panel {
  display: grid;
  gap: var(--related-gap);
  min-width: 0;
}
.flow-list {
  list-style: none;
  margin: 0;
  padding: 0;
  display: grid;
  gap: var(--related-gap);
}
.flow-step {
  width: 100%;
  display: grid;
  align-items: center;
  grid-template-columns: 28px 1fr 18px;
  gap: var(--related-gap);
  padding: 8px 12px;
  border: 1px solid var(--line);
  border-radius: 8px;
  background: var(--surface);
  color: inherit;
  text-align: start;
  cursor: pointer;
}
.flow-step[aria-pressed='true'] {
  border-color: var(--primary);
}
.flow-step small {
  display: block;
  color: var(--muted);
}
.inspector-heading,
.flow-add,
.step-buttons {
  display: flex;
  align-items: center;
  gap: var(--related-gap);
  flex-wrap: wrap;
}
.inspector-heading h2 {
  margin: 0;
}
.flow-add :deep(.ant-select) {
  flex: 1;
  min-width: 150px;
}
@media (max-width: 920px) {
  .playbook-grid {
    grid-template-columns: minmax(0, 1fr);
  }
}
</style>
