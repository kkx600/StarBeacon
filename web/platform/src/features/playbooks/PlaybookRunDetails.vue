<script setup lang="ts">
import { computed, onScopeDispose, ref, watch } from 'vue';
import { Alert, Button, Checkbox, Modal } from 'ant-design-vue';
import { RouterLink } from 'vue-router';
import { formatTime } from '@starbeacon/shared/types.ts';
import StatusTag from '@starbeacon/shared/components/StatusTag.vue';
import AlertAssessment from '../alerts/AlertAssessment.vue';
import {
  authorizeGateway,
  authorizePlugin,
  beginTriage,
  errorText,
  outcomeNames,
  request,
  runStates,
  stepNames,
  type PlaybookRun,
} from './playbooks';

const props = defineProps<{ run: PlaybookRun }>();
const emit = defineEmits<{ updated: [value: PlaybookRun] }>();
const index = computed(() => props.run.results.length);
const step = computed(() => (props.run.state === 'running' ? props.run.definition.steps[index.value] : undefined));
const confirmed = ref(false),
  busy = ref(false),
  error = ref(''),
  submission = ref('');
const assessmentOpen = ref(false),
  assessmentLocked = ref(false);
const execution = computed(() => step.value && ['triage', 'plugin', 'gateway'].includes(step.value.kind));
const currentAction = computed(() =>
  step.value?.kind === 'approval' ? props.run.definition.steps[index.value + 1] : step.value,
);
const needsConfirmation = computed(
  () => execution.value || step.value?.kind === 'approval' || step.value?.kind === 'notify',
);
let active: AbortController | undefined;
watch(
  () => [props.run.id, index.value],
  () => {
    confirmed.value = false;
    error.value = '';
    submission.value = '';
  },
);
async function perform(fn: (signal: AbortSignal) => Promise<void>) {
  if (busy.value) return;
  const control = new AbortController();
  active = control;
  busy.value = true;
  error.value = '';
  try {
    await fn(control.signal);
  } catch (cause) {
    if (!control.signal.aborted) error.value = errorText(cause);
  } finally {
    if (active === control) busy.value = false;
  }
}
function submitStep() {
  const s = step.value;
  if (!confirmed.value || !s || !props.run.step_key) return;
  void perform(async signal => {
    if (s.kind === 'triage' && s.model) {
      const job = await beginTriage(props.run, s.model, signal);
      if (!signal.aborted) submission.value = '研判已受理 · ' + job.id;
    } else if (s.kind === 'plugin' && s.plugin) {
      const receipt = await authorizePlugin(props.run, s.plugin, signal);
      if (!signal.aborted) submission.value = '联动任务已签发 · ' + receipt.task_id;
    } else if (s.kind === 'gateway' && s.gateway) {
      const result = await authorizeGateway(props.run, s.gateway, signal);
      if (!signal.aborted) submission.value = '已登记网关请求 · ' + result.id;
    }
    confirmed.value = false;
  });
}
function advance() {
  if (!step.value || (!execution.value && needsConfirmation.value && !confirmed.value)) return;
  void perform(async signal => {
    const run = await request<PlaybookRun>(
      '/playbook-runs/' + props.run.id + '/steps',
      'POST',
      { step: index.value, confirmed: true },
      undefined,
      signal,
    );
    if (!signal.aborted) emit('updated', run);
  });
}
onScopeDispose(() => active?.abort());
</script>

<template>
  <section class="panel run-detail">
    <header class="run-title">
      <h2>{{ run.definition.name }}</h2>
      <StatusTag
        :value="runStates[run.state]"
        :tone="run.state === 'completed' ? 'success' : run.state === 'stopped' ? 'warning' : 'neutral'"
      />
    </header>
    <div class="run-source">
      <span>已发布修订 {{ run.revision }}</span>
      <span> {{ run.alert.source_ip || '—' }} → {{ run.alert.destination_ip || '—' }}</span>
      <span class="technical">告警 {{ run.alert.event_id }}</span>
    </div>
    <div class="run-grid">
      <ol class="run-timeline" aria-label="编排运行步骤">
        <li v-for="(s, i) in run.definition.steps" :key="i" :class="{ 'current-step': step && index === i }">
          <strong>{{ s.name }}</strong>
          <div v-if="run.results[i]" class="run-result">
            <span>{{ outcomeNames[run.results[i]!.outcome] ?? '已记录' }}</span>
            <span class="muted">{{ formatTime(run.results[i]!.at) }}</span>
            <span v-if="run.results[i]!.reference" class="technical">{{ run.results[i]!.reference }}</span>
            <RouterLink
              v-if="run.results[i]!.task_id && s.kind !== 'gateway'"
              :to="{ path: '/response/actions', query: { task: run.results[i]!.task_id } }"
              >原设备任务</RouterLink
            >
            <RouterLink v-if="s.kind === 'gateway'" to="/response/gateway-blocks">网关记录</RouterLink>
            <span v-if="run.results[i]!.lease_until">租约期限 {{ formatTime(run.results[i]!.lease_until) }}</span>
          </div>
          <small v-else class="muted">{{ step && index === i ? '当前步骤' : '未运行' }}</small>
        </li>
      </ol>
      <div v-if="step" class="run-step">
        <h3>{{ stepNames[step.kind] }}</h3>
        <p v-if="step.description">{{ step.description }}</p>
        <template v-if="currentAction?.plugin">
          <p class="technical">{{ currentAction.plugin.sensor_id }} / {{ currentAction.plugin.connector_id }}</p>
          <p>源地址限时封禁 {{ currentAction.plugin.ttl_seconds }} 秒</p>
        </template>
        <p v-if="currentAction?.gateway" class="technical">
          网关策略 {{ currentAction.gateway.id }} · 修订 {{ currentAction.gateway.revision }}
        </p>
        <p v-if="step.kind === 'verify'" class="muted">以原任务回执为准，等待期间可以再次核对。</p>
        <p v-if="step.kind === 'compensate'" class="muted">记录原授权租约的到期时间。实际解除状态可在原任务核对。</p>
        <Button v-if="step.kind === 'gateway'" :disabled="busy" @click="assessmentOpen = true">查看人工研判</Button>
        <Checkbox v-if="needsConfirmation" v-model:checked="confirmed" :disabled="busy">
          {{
            step.kind === 'triage'
              ? '允许把本次告警的白名单材料发送给所选模型'
              : step.kind === 'notify'
                ? '我已通知相关人员'
                : '我已核对原告警与本步骤的处置范围'
          }}
        </Checkbox>
        <Alert v-if="submission" type="info" show-icon :message="submission" />
        <Alert v-if="error" type="error" show-icon :message="error" />
        <div class="run-buttons">
          <Button v-if="execution" type="primary" :loading="busy" :disabled="!confirmed" @click="submitStep">
            {{ step.kind === 'triage' ? '发起研判' : '提交授权确认' }}
          </Button>
          <Button
            :type="execution ? 'default' : 'primary'"
            :loading="busy"
            :disabled="!execution && needsConfirmation && !confirmed"
            @click="advance"
          >
            {{
              execution || step.kind === 'verify'
                ? '核对结果'
                : step.kind === 'protection'
                  ? '检查保护名单'
                  : '确认本步'
            }}
          </Button>
        </div>
      </div>
    </div>
    <Modal
      v-model:open="assessmentOpen"
      title="原告警人工研判"
      :width="800"
      :footer="null"
      :closable="!assessmentLocked"
      :keyboard="!assessmentLocked"
      :mask-closable="!assessmentLocked"
    >
      <AlertAssessment
        v-if="assessmentOpen"
        :key="run.id"
        :event-id="run.alert.event_id"
        :digest="run.alert.raw_sha256"
        @locked="assessmentLocked = $event"
      />
    </Modal>
  </section>
</template>

<style scoped>
.run-detail,
.run-step {
  display: grid;
  gap: var(--related-gap);
  min-width: 0;
}
.run-title,
.run-source,
.run-buttons {
  display: flex;
  align-items: center;
  flex-wrap: wrap;
  gap: var(--related-gap);
}
.run-title h2,
.run-step :is(h3, p) {
  margin: 0;
}
.run-grid {
  display: grid;
  grid-template-columns: minmax(0, 1.25fr) minmax(270px, 1fr);
  gap: var(--section-gap);
  align-items: start;
}
.run-timeline {
  display: grid;
  gap: var(--related-gap);
  margin: 0;
  padding-inline-start: 1.5rem;
}
.run-timeline li {
  padding: 8px 12px;
  border: 1px solid var(--line);
  border-radius: 8px;
}
.run-timeline li.current-step {
  border-color: var(--primary);
}
.run-result {
  display: flex;
  flex-wrap: wrap;
  gap: 4px var(--related-gap);
}
.run-source {
  overflow-wrap: anywhere;
}
@media (max-width: 920px) {
  .run-grid {
    grid-template-columns: minmax(0, 1fr);
  }
}
</style>
