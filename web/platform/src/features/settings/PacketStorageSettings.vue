<script setup lang="ts">
import { computed, onMounted, onScopeDispose, shallowRef, watch } from 'vue';
import { Select as ASelect } from 'ant-design-vue';
import { RouterLink, useRoute } from 'vue-router';
import MetricBar from '@starbeacon/shared/components/MetricBar.vue';
import PacketRetentionEditor from '@starbeacon/shared/components/PacketRetentionEditor.vue';
import StatePanel from '@starbeacon/shared/components/StatePanel.vue';
import { formatBytes } from '@starbeacon/shared/utils/format.ts';
import { formatTime, taskStates, type MetricSpec } from '@starbeacon/shared/types.ts';
import {
  packetID,
  packetObject,
  sameRetentionPolicy,
  validRetentionObservation,
  type PacketRetentionChange,
  type PacketRetentionPolicy,
} from '@starbeacon/shared/packetRetention.ts';
import { session } from '../../session';
import { usePacketStorage } from './usePacketStorage';

const route = useRoute();
const { settings, pending, error, refresh } = usePacketStorage();
const selected = shallowRef(packetID(route.query.sensor) ? route.query.sensor : '');
const sensors = computed(() => settings.value?.sensors ?? []);
const sensor = computed(() => sensors.value.find(item => item.id === selected.value));
const choice = computed(() => sensors.value.map(item => ({ value: item.id, label: `${item.name} · ${item.id}` })));
const saving = shallowRef(false);
const saveError = shallowRef('');
const notice = shallowRef('');
const taskState = shallowRef('');
const tracked = shallowRef<{ id: string; sensor: string; policy: PacketRetentionPolicy } | null>(null);
const lastTask = shallowRef('');
let submission: AbortController | undefined;
let poll: AbortController | undefined;
let timer: ReturnType<typeof setInterval> | undefined;
let taskEnded = Number.POSITIVE_INFINITY;
let idempotency = { key: '', fingerprint: '' };

watch(sensors, values => {
  if (!values.some(item => item.id === selected.value))
    selected.value = values.find(item => item.can_apply)?.id ?? values[0]?.id ?? '';
});

const metrics = computed<MetricSpec[]>(() => {
  const current = sensor.value;
  const hot = current?.fresh ? current.status : null;
  const warm = settings.value?.warm;
  return [
    {
      label: '热层 · 所选采集器已预留',
      value: hot?.reserved_bytes === null || !hot ? null : formatBytes(hot.reserved_bytes, true),
      note: hot ? `暂存配额 ${formatBytes(hot.quota_bytes, true)}` : '',
      missingReason: '缺少可用的暂存观测',
    },
    {
      label: '温层 · 本租户原包',
      value: warm ? formatBytes(warm.stored_bytes, true) : null,
      note: warm ? `保留期上限 ${warm.retention_days} 天` : '',
      missingReason: settings.value?.warm_state === 'not_configured' ? '平台未配置原包存储' : '存储统计无数据',
    },
    { label: '冷层 · 使用量', value: null, missingReason: '平台未纳管冷层用量' },
  ];
});

function finish(message: string) {
  notice.value = message;
  taskState.value = '';
  tracked.value = null;
}

function checkObservation() {
  const active = tracked.value;
  if (!active || error.value) return;
  const row = sensors.value.find(item => item.id === active.sensor);
  const status = row?.fresh ? row.status : null;
  const observed = status?.configuration;
  if (observed?.task_id === active.id && sameRetentionPolicy(observed.policy, active.policy))
    finish(`采集器已回读修订 ${observed.policy.revision}，后续封段使用该策略。`);
  else if (observed && taskState.value === 'succeeded' && observed.policy.revision > active.policy.revision)
    finish(`任务已应用修订 ${active.policy.revision}。采集器随后更新至修订 ${observed.policy.revision}。`);
  else if (observed && status && taskState.value === 'unknown' && Date.parse(status.observed_at) >= taskEnded) {
    saveError.value = `任务结果待核对。采集器上报的当前修订为 ${observed.policy.revision}，请核对后重新提交。`;
    tracked.value = null;
  }
}
watch(settings, checkObservation);

async function checkTask() {
  const active = tracked.value;
  if (!active || poll) return;
  checkObservation();
  if (!tracked.value) return;
  const control = new AbortController();
  poll = control;
  try {
    const value = await session.api.request<unknown>(`/tasks/${active.id}`, { signal: control.signal });
    if (control.signal.aborted || tracked.value !== active) return;
    if (
      !packetObject(value) ||
      value.id !== active.id ||
      value.sensor_id !== active.sensor ||
      value.kind !== 'packet.retention.configure' ||
      typeof value.state !== 'string' ||
      !Object.hasOwn(taskStates, value.state)
    )
      throw new Error('任务回执与所选采集器不一致');
    taskState.value = value.state;
    if (value.state === 'succeeded') {
      const received = packetObject(value.receipt) ? value.receipt.result : null;
      if (
        !validRetentionObservation(received) ||
        received.task_id !== active.id ||
        !sameRetentionPolicy(received.policy, active.policy)
      )
        throw new Error('采集器返回的策略与下发内容不一致');
      await refresh();
      checkObservation();
    } else if (value.state === 'unknown') {
      const ended = packetObject(value.receipt) ? value.receipt.finished_at : undefined;
      if (typeof ended === 'string') taskEnded = Date.parse(ended);
      await refresh();
      checkObservation();
    } else if (['failed', 'cancelled', 'expired'].includes(value.state)) {
      saveError.value =
        packetObject(value.receipt) && value.receipt.code === 'packet_retention_changed'
          ? '采集器策略已有变更，请刷新后核对并重新提交。'
          : `留存任务${taskStates[value.state]}，请核对任务记录。`;
      tracked.value = null;
      await refresh();
    }
  } catch (e) {
    if (!control.signal.aborted && tracked.value === active)
      taskState.value = e instanceof Error ? e.message : '任务回执读取异常';
  } finally {
    if (poll === control) poll = undefined;
  }
}

async function apply(change: PacketRetentionChange) {
  const target = sensor.value;
  if (saving.value || tracked.value || !target?.can_apply || error.value) return;
  const active = new AbortController();
  submission = active;
  saving.value = true;
  saveError.value = '';
  notice.value = '';
  const fingerprint = JSON.stringify([target.id, change]);
  if (idempotency.fingerprint !== fingerprint) idempotency = { key: crypto.randomUUID(), fingerprint };
  try {
    const value = await session.api.request<unknown>(`/sensors/${target.id}/packet-retention`, {
      method: 'POST',
      body: change,
      headers: { 'Idempotency-Key': idempotency.key },
      signal: active.signal,
    });
    if (active.signal.aborted) return;
    if (!packetObject(value) || !packetID(value.task_id)) throw new Error('平台未返回签名任务标识');
    lastTask.value = value.task_id;
    tracked.value = { id: value.task_id, sensor: target.id, policy: change.policy };
    taskEnded = Number.POSITIVE_INFINITY;
    taskState.value = 'queued';
    idempotency = { key: '', fingerprint: '' };
    void checkTask();
  } catch (e) {
    if (!active.signal.aborted) {
      saveError.value = e instanceof Error ? e.message : '留存策略下发失败';
      void refresh();
    }
  } finally {
    if (!active.signal.aborted) saving.value = false;
  }
}

const taskLabel = computed(() => {
  if (taskState.value === 'succeeded') return '设备任务已应用，等待最新配置同步。';
  if (taskState.value === 'unknown') return '任务结果待核对，等待采集器回读。';
  return `留存下发 · ${taskStates[taskState.value] ?? taskState.value}`;
});
onMounted(() => {
  timer = setInterval(checkTask, 4000);
});
onScopeDispose(() => {
  clearInterval(timer);
  submission?.abort();
  poll?.abort();
});
</script>

<template>
  <section class="panel">
    <div class="panel-header">
      <h2>全流量存储</h2>
      <a-button :loading="pending" @click="refresh">刷新</a-button>
    </div>
    <StatePanel v-if="!settings" :loading="pending" :error="error" @retry="refresh" />
    <div v-if="settings" class="panel-body">
      <a-alert v-if="error" class="section-gap" type="error" :message="error" show-icon />
      <div class="sensor-picker section-gap">
        <label for="storage-sensor">采集器</label>
        <ASelect
          id="storage-sensor"
          v-model:value="selected"
          :options="choice"
          :disabled="saving || !!tracked"
          placeholder="选择采集器"
        />
      </div>
      <MetricBar :items="metrics" />
      <p v-if="settings.sensors_limited" class="muted">当前展示前 500 台上报原包状态的采集器。</p>
      <p v-if="settings.warm?.oldest_created_at" class="muted">
        温层最早归档 {{ formatTime(settings.warm.oldest_created_at) }}
      </p>
      <p v-if="sensor?.status?.rotate_seconds" class="muted">
        采集器封段条件 {{ formatBytes(sensor.status.segment_bytes, true) }} 或 {{ sensor.status.rotate_seconds }} 秒。
      </p>
      <a-alert
        v-if="saveError || notice || tracked"
        class="section-gap"
        :type="saveError ? 'error' : notice ? 'success' : 'info'"
        :message="saveError || notice || taskLabel"
        show-icon
      >
        <template v-if="lastTask" #action
          ><RouterLink :to="{ path: '/sensors/tasks', query: { task: lastTask } }">查看任务</RouterLink></template
        >
      </a-alert>
      <PacketRetentionEditor
        v-if="sensor?.status?.configuration"
        :key="sensor.id"
        :observation="sensor.status.configuration"
        :disabled="!sensor.can_apply || !!tracked || !!error"
        :saving="saving"
        remote
        @save="apply"
      />
      <p v-if="sensor && !sensor.can_apply" class="muted">
        {{ sensor.fresh ? '当前留存配置或平台签名能力未就绪。' : '采集器尚未上报近期留存观测。' }}
      </p>
      <p v-else-if="!sensor" class="muted">当前租户暂无上报原包状态的采集器。</p>
    </div>
  </section>
</template>

<style scoped>
.sensor-picker {
  display: flex;
  align-items: center;
  gap: var(--related-gap);
}
.sensor-picker :deep(.ant-select) {
  width: min(350px, 80%);
}
</style>
