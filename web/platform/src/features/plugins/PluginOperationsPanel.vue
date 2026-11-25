<script setup lang="ts">
import { computed, onScopeDispose, shallowRef, toRef, watch } from 'vue';
import { Modal as AModal, Popconfirm as APopconfirm, Select as ASelect } from 'ant-design-vue';
import StatusTag from '@starbeacon/shared/components/StatusTag.vue';
import { readSensorDirectory } from '@starbeacon/shared/sensors.ts';
import { formatTime, type Sensor } from '@starbeacon/shared/types.ts';
import {
  pluginEntries,
  pluginOperationLabels,
  trialResult,
  trialStages,
  type PluginOperationResult,
  type PluginVersion,
} from '@starbeacon/shared/responsePlugins.ts';
import { session } from '../../session';
import { usePluginOperations } from './usePluginOperations';

const props = defineProps<{ version: PluginVersion }>();
const emit = defineEmits<{ close: []; changed: [] }>();
const sensors = shallowRef<Sensor[]>([]);
const sensorId = shallowRef('');
const sensorError = shallowRef('');
const sensorLoading = shallowRef(false);
let sensorCall: AbortController | undefined;
const { state, loading, posting, error, writeError, can, refresh, submit } = usePluginOperations(
  toRef(props, 'version'),
  sensorId,
);
const choices = computed(() =>
  sensors.value.map(s => ({
    value: s.id,
    label: s.name + (s.status === 'online' ? '' : ' · 离线'),
  })),
);
const entries = computed(() => pluginEntries(props.version));
const hasBlock = computed(() => entries.value.includes('block'));
const hasIsolation = computed(() => entries.value.includes('isolate'));
const capabilityDescription = computed(() => {
  if (hasBlock.value && hasIsolation.value) return '验证保留 IP 与登记测试终端的限时动作及解除。';
  if (hasBlock.value) return '对采集器登记的保留 IP 完成封禁、回读、解封和复核。';
  if (hasIsolation.value) return '对采集器登记的测试终端完成隔离、回读、解除和复核。';
  return '核对只读插件对设备变更请求的限制。';
});
const status: Record<
  PluginOperationResult['state'],
  { text: string; tone: 'success' | 'neutral' | 'warning' | 'danger' | 'info' }
> = {
  queued: { text: '排队中', tone: 'info' },
  delivered: { text: '排队中', tone: 'info' },
  running: { text: '运行中', tone: 'info' },
  succeeded: { text: '已验证', tone: 'success' },
  failed: { text: '失败', tone: 'danger' },
  unknown: { text: '结果未知', tone: 'warning' },
  expired: { text: '已过期', tone: 'neutral' },
  cancelled: { text: '已取消', tone: 'neutral' },
};
const checks: Record<string, string> = {
  health: '健康检查',
  pull_alerts: '拉取告警',
  verify: '只读核验',
  writes_denied: '写入受限',
  block: '测试封禁',
  verify_blocked: '回读封禁',
  unblock: '解除封禁',
  verify_unblocked: '回读解封',
  isolate: '测试隔离',
  verify_isolated: '回读隔离',
  release: '解除隔离',
  verify_released: '回读解除',
};
const stages = computed(() =>
  trialStages.map(item => ({
    ...item,
    result: trialResult(state.value, props.version.version, item.key),
  })),
);

async function loadSensors() {
  sensorCall?.abort();
  const call = new AbortController();
  sensorCall = call;
  sensorLoading.value = true;
  sensorError.value = '';
  try {
    const list = await readSensorDirectory(session.api, call.signal);
    if (call.signal.aborted) return;
    sensors.value = list.filter(s => s.active && s.health.plugin_bindings?.some(b => b.plugin_id === props.version.id));
    sensorId.value =
      sensors.value.find(s => s.id === sensorId.value)?.id ??
      sensors.value.find(s => s.status === 'online')?.id ??
      sensors.value[0]?.id ??
      '';
  } catch (cause) {
    if (!call.signal.aborted) sensorError.value = cause instanceof Error ? cause.message : '采集器目录读取失败';
  } finally {
    if (sensorCall === call) sensorLoading.value = false;
  }
}
watch(() => props.version.id, loadSensors, { immediate: true });
watch(
  () => [state.value?.deployment.sensor_id, state.value?.deployment.generation],
  ([sensor, generation], [oldSensor, oldGeneration]) => {
    if (sensor && generation !== undefined && (sensor !== oldSensor || generation !== oldGeneration)) emit('changed');
  },
);
onScopeDispose(() => sensorCall?.abort());
</script>

<template>
  <a-modal
    :open="true"
    :title="version.name + ' · 版本 ' + version.version"
    :width="800"
    :footer="null"
    :mask-closable="false"
    :closable="!posting"
    :keyboard="!posting"
    @cancel="!posting && emit('close')"
  >
    <a-form layout="vertical">
      <a-form-item label="运行采集器">
        <a-select
          v-model:value="sensorId"
          aria-label="运行采集器"
          show-search
          option-filter-prop="label"
          :options="choices"
          :disabled="posting"
          :loading="sensorLoading"
          placeholder="选择已登记此插件的采集器"
        />
      </a-form-item>
    </a-form>
    <a-alert v-if="sensorError" type="error" show-icon :message="sensorError" class="section-gap">
      <template #action><a-button size="small" @click="loadSensors">重试</a-button></template>
    </a-alert>
    <a-alert
      v-else-if="!sensorLoading && !choices.length"
      type="warning"
      show-icon
      message="采集器尚未登记该插件的本地绑定"
      class="section-gap"
    >
      <template #action><a-button size="small" @click="loadSensors">刷新</a-button></template>
    </a-alert>
    <a-alert v-if="error || writeError" type="error" show-icon :message="error || writeError" class="section-gap" />
    <div v-if="sensorId" class="deployment-toolbar">
      <span>启用版本 {{ state?.deployment.version || '—' }}</span>
      <span>可回退版本 {{ state?.deployment.previous_version || '—' }}</span>
      <StatusTag
        v-if="state?.deployment.version && state.deployment.unavailable"
        value="设备异常，等待重试"
        tone="warning"
      />
      <a-button :loading="loading" :disabled="posting" @click="refresh">刷新回执</a-button>
    </div>
    <section aria-label="试运行" class="plugin-trials">
      <div v-for="stage in stages" :key="stage.key" class="plugin-stage">
        <div>
          <strong>{{ stage.label }}</strong>
          <p v-if="stage.key === 'capability'">{{ capabilityDescription }}</p>
        </div>
        <StatusTag
          :value="stage.result ? status[stage.result.state].text : '待验证'"
          :tone="stage.result ? status[stage.result.state].tone : 'neutral'"
        />
        <a-popconfirm
          v-if="stage.key === 'capability' && (hasBlock || hasIsolation)"
          title="执行本地登记的测试目标？"
          ok-text="执行试运行"
          cancel-text="取消"
          @confirm="submit(stage.key)"
        >
          <a-button size="small" :disabled="!can(stage.key)">试运行</a-button>
        </a-popconfirm>
        <a-button v-else size="small" :disabled="!can(stage.key)" @click="submit(stage.key)">试运行</a-button>
      </div>
    </section>
    <div class="plugin-actions">
      <a-popconfirm title="签名并下发此版本？" ok-text="签名并下发" cancel-text="取消" @confirm="submit('publish')">
        <a-button type="primary" :disabled="!can('publish')">签名并下发</a-button>
      </a-popconfirm>
      <a-popconfirm title="回退到上一个已签名版本？" ok-text="回退" cancel-text="取消" @confirm="submit('rollback')">
        <a-button :disabled="!can('rollback')">回退</a-button>
      </a-popconfirm>
      <a-popconfirm title="停用当前版本？" ok-text="停用" cancel-text="取消" @confirm="submit('disable')">
        <a-button :disabled="!can('disable')">停用</a-button>
      </a-popconfirm>
    </div>
    <section v-if="state?.operations.length" aria-label="最近执行" class="plugin-history">
      <h3>最近执行</h3>
      <div v-for="operation in state.operations" :key="operation.task_id" class="plugin-receipt">
        <div class="receipt-heading">
          <span>{{ pluginOperationLabels[operation.action] }} · 版本 {{ operation.version }}</span>
          <StatusTag
            :value="operation.state === 'succeeded' && !operation.trial ? '已完成' : status[operation.state].text"
            :tone="status[operation.state].tone"
          />
          <span>{{ formatTime(operation.updated_at) }}</span>
        </div>
        <span v-if="operation.code" class="technical">{{ operation.code }}</span>
        <ul v-if="operation.trial?.events.length" class="plugin-checks">
          <li v-for="(event, index) in operation.trial.events" :key="event.entry + index">
            {{ checks[event.entry] ?? event.entry }} · {{ event.code === 'ok' ? '已验证' : event.code }} ·
            {{ event.duration_ms }} ms
            <span v-for="(request, number) in event.requests" :key="number" class="technical">
              · {{ request.method }} {{ request.status || '无响应' }}
            </span>
          </li>
        </ul>
      </div>
    </section>
  </a-modal>
</template>

<style scoped>
.deployment-toolbar,
.plugin-actions,
.receipt-heading {
  display: flex;
  align-items: center;
  flex-wrap: wrap;
  gap: var(--related-gap);
}
.deployment-toolbar {
  margin-bottom: var(--related-gap);
}
.plugin-stage {
  display: grid;
  grid-template-columns: minmax(0, 1fr) auto auto;
  align-items: center;
  gap: var(--related-gap);
  padding: 8px 0;
  border-top: 1px solid var(--line);
}
.plugin-stage p {
  margin: 2px 0 0;
  color: var(--muted);
  font-size: 12px;
}
.plugin-actions {
  justify-content: flex-end;
  padding: var(--related-gap) 0;
}
.plugin-history {
  max-height: 230px;
  overflow: auto;
}
.plugin-receipt {
  padding: 6px 0;
  border-top: 1px solid var(--line);
}
.plugin-checks {
  margin: 4px 0;
  padding-inline-start: 20px;
}
</style>
