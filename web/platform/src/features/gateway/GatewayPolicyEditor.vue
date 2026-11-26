<script setup lang="ts">
import { computed, onMounted, onScopeDispose, ref, shallowRef, watch } from 'vue';
import { Alert as AAlert, Button as AButton, Modal as AModal } from 'ant-design-vue';
import { readSensorDirectory } from '@starbeacon/shared/sensors.ts';
import type { Sensor } from '@starbeacon/shared/types.ts';
import { session } from '../../session';
import {
  gatewayID,
  readGatewayDevices,
  saveGatewayPolicy,
  type GatewayDefinition,
  type GatewayDevice,
  type GatewayFollowUp,
  type GatewayPolicy,
} from './gatewayBlocks';

const props = defineProps<{ policy?: GatewayPolicy }>();
const emit = defineEmits<{ close: []; saved: [] }>();
const d = props.policy?.definition;
const prior = d?.follow_up;
const pluginKey = (device: Pick<GatewayFollowUp, 'plugin_id' | 'generation' | 'connector_id' | 'config_sha256'>) =>
  [device.plugin_id, device.generation, device.connector_id, device.config_sha256].join('/');
const priorPlugin = prior ? pluginKey(prior) : '';
const defaultTime = new Date(Date.now() + 3600000);
const deadline = d ? new Date(d.valid_until) : defaultTime;
const localTime = new Date(deadline.getTime() - deadline.getTimezoneOffset() * 60000).toISOString().slice(0, 16);
const draft = ref({
  id: props.policy?.id ?? '',
  name: d?.name ?? '',
  enabled: d?.enabled ?? false,
  trigger: d?.trigger ?? 'rule',
  registration: d ? d.sensor_id + '/' + d.registration_id : '',
  rule: d?.rule_id ?? '',
  revision: d?.rule_revision ?? '',
  sources: d?.scope.sources.join('\n') ?? '',
  destinations: d?.scope.destinations.join('\n') ?? '',
  lease: d?.lease_seconds ?? 15,
  expires: localTime,
  followUp: !!prior,
  plugin: priorPlugin,
  side: prior?.target_side ?? 'source',
  ttl: prior?.ttl_seconds ?? 60,
});
const sensors = shallowRef<Sensor[]>([]);
const sensorPending = shallowRef(true);
const sensorError = shallowRef('');
const devices = shallowRef<GatewayDevice[]>([]);
const devicePending = shallowRef(false);
const deviceError = shallowRef('');
const saving = shallowRef(false);
const error = shallowRef('');
const current = computed(() => devices.value.find(device => pluginKey(device) === draft.value.plugin));
const registrationOf = (sensor: Sensor) => sensor.id + '/' + sensor.registration_id;
const fallbackRegistration = computed(
  () => d && !sensors.value.some(sensor => registrationOf(sensor) === d.sensor_id + '/' + d.registration_id),
);
let directory: AbortController | undefined;
let catalog: AbortController | undefined;
let write: AbortController | undefined;

async function loadSensors() {
  directory?.abort();
  const controller = new AbortController();
  directory = controller;
  sensorPending.value = true;
  sensorError.value = '';
  try {
    const result = await readSensorDirectory(session.api, controller.signal);
    if (!controller.signal.aborted) sensors.value = result.filter(sensor => sensor.active);
  } catch (err) {
    if (!controller.signal.aborted) sensorError.value = err instanceof Error ? err.message : '采集器目录不可用。';
  } finally {
    if (directory === controller) sensorPending.value = false;
  }
}
async function loadDevices(registration: string, followUp: boolean) {
  catalog?.abort();
  devices.value = [];
  deviceError.value = '';
  devicePending.value = false;
  if (!registration || !followUp) return;
  const [sensor, id] = registration.split('/');
  if (!gatewayID(sensor) || !gatewayID(id)) return;
  const controller = new AbortController();
  catalog = controller;
  devicePending.value = true;
  try {
    const result = await readGatewayDevices(sensor, id, controller.signal);
    if (!controller.signal.aborted) devices.value = result;
  } catch (err) {
    if (!controller.signal.aborted) deviceError.value = err instanceof Error ? err.message : '插件目录不可用。';
  } finally {
    if (catalog === controller) devicePending.value = false;
  }
}
function changeRegistration() {
  draft.value.plugin = '';
}
watch(
  [() => draft.value.registration, () => draft.value.followUp],
  ([registration, followUp]) => {
    void loadDevices(registration, followUp);
  },
  { immediate: true },
);
onMounted(loadSensors);
onScopeDispose(() => {
  directory?.abort();
  catalog?.abort();
  write?.abort();
});

const words = (value: string) =>
  value
    .trim()
    .split(/[\s,，]+/)
    .filter(Boolean);
function toDefinition(): GatewayDefinition {
  const input = draft.value;
  const [sensor, registration] = input.registration.split('/');
  if (!gatewayID(input.id) || !input.name.trim() || !gatewayID(sensor) || !gatewayID(registration))
    throw new Error('请填写策略标识、名称并选择已注册的采集器。');
  if (![input.rule, input.revision].every(value => /^[1-9]\d{0,9}$/.test(value) && Number(value) <= 4294967295))
    throw new Error('规则编号和修订必须是 1 至 4294967295 的整数。');
  const sources = words(input.sources);
  const destinations = words(input.destinations);
  if (
    ![sources, destinations].every(
      list => list.length && list.length <= 16 && list.every(prefix => prefix.includes('/')),
    )
  )
    throw new Error('源侧和目的侧各填写 1 至 16 个 CIDR。');
  const lease = Number(input.lease);
  if (!Number.isInteger(lease) || lease < (input.followUp ? 8 : 5) || lease > 60)
    throw new Error(input.followUp ? '预授权策略的网关租约须为 8 至 60 秒。' : '网关租约须为 5 至 60 秒。');
  const expires = new Date(input.expires).getTime();
  const now = Date.now();
  if (!Number.isFinite(expires) || (input.enabled && (expires <= now || expires > now + 86400000)))
    throw new Error('启用时，授权截止时间须在未来 24 小时内。');
  const definition: GatewayDefinition = {
    enabled: input.enabled,
    name: input.name.trim(),
    trigger: input.trigger,
    sensor_id: sensor,
    registration_id: registration,
    rule_id: input.rule,
    rule_revision: input.revision,
    scope: { sources, destinations },
    lease_seconds: lease,
    valid_until: d && input.expires === localTime ? d.valid_until : new Date(expires).toISOString(),
  };
  if (input.followUp) {
    const selected = current.value;
    const ttl = Number(input.ttl);
    if (selected) {
      if (!Number.isInteger(ttl) || ttl < 30 || ttl > selected.max_ttl_seconds)
        throw new Error('封禁时长须为 30 秒至设备限额。');
      definition.follow_up = {
        plugin_id: selected.plugin_id,
        generation: selected.generation,
        connector_id: selected.connector_id,
        config_sha256: selected.config_sha256,
        target_side: input.side,
        ttl_seconds: ttl,
      };
    } else if (
      !input.enabled &&
      prior &&
      input.registration === d?.sensor_id + '/' + d?.registration_id &&
      input.plugin === priorPlugin &&
      input.side === prior.target_side &&
      ttl === prior.ttl_seconds
    ) {
      definition.follow_up = prior;
    } else {
      throw new Error('请核对设备心跳并选择当前部署的联动插件。');
    }
  }
  return definition;
}
async function submit() {
  if (saving.value) return;
  error.value = '';
  const controller = new AbortController();
  write = controller;
  try {
    const definition = toDefinition();
    saving.value = true;
    await saveGatewayPolicy(draft.value.id, props.policy?.revision ?? 0, definition, controller.signal);
    if (!controller.signal.aborted) emit('saved');
  } catch (err) {
    if (!controller.signal.aborted) error.value = err instanceof Error ? err.message : '保存失败，请刷新后核对。';
  } finally {
    if (!controller.signal.aborted) saving.value = false;
  }
}
</script>

<template>
  <AModal
    :open="true"
    :title="policy ? '编辑网关策略' : '新建网关策略'"
    width="680px"
    :footer="null"
    :closable="!saving"
    :keyboard="!saving"
    :mask-closable="false"
    @cancel="emit('close')"
  >
    <form @submit.prevent="submit">
      <AAlert v-if="error" type="error" show-icon :message="error" class="section-gap" />
      <fieldset :disabled="saving" class="policy-fields">
        <label
          >策略标识<input v-model.trim="draft.id" class="ant-input" maxlength="64" :readonly="!!policy" required
        /></label>
        <label>名称<input v-model.trim="draft.name" class="ant-input" maxlength="120" required /></label>
        <label
          >触发方式
          <select v-model="draft.trigger" class="ant-input">
            <option value="rule">规则即时触发</option>
            <option value="review">研判后触发</option>
          </select>
        </label>
        <label
          >采集器注册
          <select v-model="draft.registration" class="ant-input" required @change="changeRegistration">
            <option value="" disabled>{{ sensorPending ? '读取采集器目录中' : '选择采集器' }}</option>
            <option v-if="fallbackRegistration && d" :value="d.sensor_id + '/' + d.registration_id">
              {{ d.sensor_id }} · {{ d.registration_id }}（原绑定）
            </option>
            <option v-for="sensor in sensors" :key="sensor.id" :value="registrationOf(sensor)">
              {{ sensor.name }} · {{ registrationOf(sensor) }}
            </option>
          </select>
        </label>
        <div v-if="sensorError" class="wide policy-message" role="alert">
          {{ sensorError }} <AButton size="small" @click="loadSensors">重读目录</AButton>
        </div>
        <label>规则编号<input v-model.trim="draft.rule" class="ant-input" inputmode="numeric" required /></label>
        <label>规则修订<input v-model.trim="draft.revision" class="ant-input" inputmode="numeric" required /></label>
        <label
          >源侧 CIDR<textarea v-model="draft.sources" class="ant-input" rows="2" placeholder="每行一个 CIDR" required />
        </label>
        <label
          >目的侧 CIDR<textarea
            v-model="draft.destinations"
            class="ant-input"
            rows="2"
            placeholder="每行一个 CIDR"
            required
          />
        </label>
        <label
          >网关租约（秒）<input
            v-model.number="draft.lease"
            type="number"
            class="ant-input"
            :min="draft.followUp ? 8 : 5"
            max="60"
            required
        /></label>
        <label>授权截止时间<input v-model="draft.expires" type="datetime-local" class="ant-input" required /></label>
        <label class="wide policy-check"><input v-model="draft.enabled" type="checkbox" />启用策略</label>
        <label class="wide policy-check"
          ><input v-model="draft.followUp" type="checkbox" />流量暂停后允许自动签发联动封禁</label
        >
        <template v-if="draft.followUp">
          <label class="wide"
            >联动插件及设备
            <select v-model="draft.plugin" class="ant-input">
              <option value="" disabled>{{ devicePending ? '读取插件目录中' : '选择当前部署' }}</option>
              <option v-if="prior && !devices.some(device => pluginKey(device) === priorPlugin)" :value="priorPlugin">
                {{ prior.plugin_id }}（原绑定）
              </option>
              <option v-for="device in devices" :key="device.plugin_id" :value="pluginKey(device)">
                {{ device.plugin_id }} · v{{ device.version }} · {{ device.device_id }} · 代次 {{ device.generation }}
              </option>
            </select>
          </label>
          <div v-if="!devicePending && draft.registration && !devices.length" class="wide policy-message" role="status">
            {{ deviceError || '当前采集器暂无通过心跳核对的联动插件。' }}
            <AButton size="small" @click="loadDevices(draft.registration, true)">重读插件</AButton>
          </div>
          <label
            >封禁方向
            <select v-model="draft.side" class="ant-input">
              <option value="source">告警源地址</option>
              <option value="destination">告警目的地址</option>
            </select>
          </label>
          <label
            >联动封禁时长（秒）
            <input
              v-model.number="draft.ttl"
              type="number"
              class="ant-input"
              min="30"
              :max="current?.max_ttl_seconds ?? 3600"
              required
            />
          </label>
        </template>
      </fieldset>
      <div class="policy-actions">
        <AButton :disabled="saving" @click="emit('close')">取消</AButton>
        <AButton type="primary" html-type="submit" :loading="saving">保存策略</AButton>
      </div>
    </form>
  </AModal>
</template>

<style scoped>
.policy-fields {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: var(--field-gap);
  border: 0;
  margin: 0;
  padding: 0;
}
.policy-fields label {
  display: grid;
  gap: var(--label-gap);
}
.policy-fields .policy-check,
.policy-actions,
.policy-message {
  display: flex;
  align-items: center;
  gap: var(--related-gap);
}
.wide {
  grid-column: 1 / -1;
}
.policy-actions {
  justify-content: flex-end;
  margin-top: var(--field-gap);
}
@media (max-width: 560px) {
  .policy-fields {
    grid-template-columns: minmax(0, 1fr);
  }
}
</style>
