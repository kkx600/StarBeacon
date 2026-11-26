<script setup lang="ts">
import { computed, onMounted, onScopeDispose, shallowRef } from 'vue';
import { Alert, Button, Input, Modal } from 'ant-design-vue';
import { formatTime } from '@starbeacon/shared/types.ts';
import { useFeedback } from '@starbeacon/shared/composables/useFeedback.ts';
import StatePanel from '@starbeacon/shared/components/StatePanel.vue';
import { session } from '../../session';
import { automationLevels } from './decisionPolicies';
import { validContinuousRecord, type ContinuousRecord } from './continuousDecisions';
import { validEvaluation, type EvaluationRecord } from './decisionEvaluations';
import { planDeadline, record } from './automation';
import DecisionResponseDialog from './DecisionResponseDialog.vue';

const props = defineProps<{ run: ContinuousRecord }>();
const emit = defineEmits<{ close: []; saved: [] }>();
const message = useFeedback();
const evaluation = shallowRef<EvaluationRecord>();
const pending = shallowRef(true);
const failure = shallowRef('');
const actionFailure = shallowRef('');
const rejecting = shallowRef(false);
const posting = shallowRef(false);
const confirming = shallowRef(false);
const reason = shallowRef('');
const reasonValid = computed(
  () =>
    reason.value.trim().length > 0 && [...reason.value.trim()].length <= 500 && !/\p{Cc}/u.test(reason.value.trim()),
);
const deadline = computed(() => planDeadline(props.run));
const isAdmin = computed(() => session.current.value?.role === 'admin');
let controller: AbortController | undefined;
async function load() {
  controller?.abort();
  const read = new AbortController();
  controller = read;
  const user = session.current.value;
  pending.value = true;
  failure.value = '';
  try {
    const row = await session.api.request<EvaluationRecord>(
      '/decision-evaluations/' + encodeURIComponent(props.run.evaluation_id),
      {
        signal: read.signal,
      },
    );
    if (
      !user ||
      !(await validEvaluation(row, user.tenant_id, user.id)) ||
      !(await validContinuousRecord(props.run, row, user.tenant_id, user.id))
    )
      throw new Error('原评估与方案的证据摘要不一致，请刷新待确认目录。');
    if (!read.signal.aborted) evaluation.value = row;
  } catch (cause) {
    if (!read.signal.aborted) failure.value = cause instanceof Error ? cause.message : '读取方案失败。';
  } finally {
    if (controller === read) pending.value = false;
  }
}
async function reject() {
  if (!isAdmin.value || !evaluation.value || posting.value || !reasonValid.value) return;
  const request = new AbortController();
  controller = request;
  posting.value = true;
  actionFailure.value = '';
  try {
    const input = { plan_sha256: props.run.sha256, reason: reason.value.trim() };
    const out = await session.api.request<unknown>(
      '/decision-evaluations/' + encodeURIComponent(props.run.evaluation_id) + '/response/reject',
      { method: 'POST', body: input, signal: request.signal },
    );
    if (request.signal.aborted) return;
    if (
      !record(out) ||
      out.state !== 'rejected' ||
      out.plan_sha256 !== input.plan_sha256 ||
      out.reason !== input.reason ||
      out.actor_id !== session.current.value?.id
    )
      throw new Error('驳回回执尚未确认，请重试原请求。');
    message.success('方案已驳回，理由已进入评测记录');
    emit('saved');
    emit('close');
  } catch (cause) {
    if (!request.signal.aborted) actionFailure.value = cause instanceof Error ? cause.message : '驳回结果待核对。';
  } finally {
    if (controller === request) posting.value = false;
  }
}
onMounted(load);
onScopeDispose(() => controller?.abort());
</script>

<template>
  <DecisionResponseDialog
    v-if="confirming && evaluation"
    :record="evaluation"
    :plan="run"
    @saved="emit('saved')"
    @close="emit('close')"
  />
  <Modal
    v-else
    :open="true"
    title="处置方案"
    :width="720"
    :footer="null"
    :closable="!posting"
    :keyboard="!posting"
    :mask-closable="!posting"
    @cancel="!posting && emit('close')"
  >
    <StatePanel :loading="pending" :error="failure" @retry="load">
      <template v-if="evaluation">
        <dl class="plan-evidence">
          <dt>场景</dt>
          <dd>{{ evaluation.policy.name }} · v{{ run.policy_revision }}</dd>
          <dt>处置对象</dt>
          <dd>{{ run.target_ip }} · 限时封禁来源</dd>
          <dt>有效级别</dt>
          <dd>{{ automationLevels[run.plan?.level ?? 'approval'] }}</dd>
          <dt>模型自报分数</dt>
          <dd>{{ (run.plan?.confidence ?? evaluation.result.confidence)?.toFixed(3) ?? '—' }}</dd>
          <dt>确认截止</dt>
          <dd>{{ formatTime(deadline) }}</dd>
          <dt>执行通道</dt>
          <dd>
            {{
              run.config.automatic
                ? run.config.automatic.connector_id + ' · ' + run.config.automatic.ttl_seconds + ' 秒'
                : '确认时选择就绪设备与期限'
            }}
          </dd>
          <dt>告警证据</dt>
          <dd class="technical">{{ run.event_id }}</dd>
          <dt>材料摘要</dt>
          <dd class="technical">{{ evaluation.result.evidence_sha256 }}</dd>
          <template v-if="run.plan">
            <dt>证据字段</dt>
            <dd>{{ run.plan.references.join('、') || '无引用' }}</dd>
            <dt>缺失材料</dt>
            <dd>{{ run.plan.missing.join('、') || '未报告缺失项' }}</dd>
          </template>
        </dl>
        <Alert v-if="actionFailure" show-icon type="error" :message="actionFailure" class="section-gap" />
        <form v-if="rejecting" @submit.prevent="reject">
          <label for="reject-reason">驳回原因</label>
          <Input.TextArea
            id="reject-reason"
            v-model:value="reason"
            show-count
            :maxlength="500"
            :rows="3"
            :disabled="posting"
          />
          <div class="filter-actions">
            <Button danger html-type="submit" :loading="posting" :disabled="!reasonValid">提交驳回</Button>
            <Button :disabled="posting" @click="rejecting = false">返回方案</Button>
          </div>
        </form>
        <div v-else class="filter-actions">
          <Button v-if="isAdmin" type="primary" @click="confirming = true">确认处置</Button>
          <Button v-if="isAdmin" danger @click="rejecting = true">驳回方案</Button>
          <Button @click="emit('close')">返回</Button>
        </div>
      </template>
    </StatePanel>
  </Modal>
</template>

<style scoped>
.plan-evidence {
  display: grid;
  grid-template-columns: 110px minmax(0, 1fr);
  gap: var(--related-gap);
}
.plan-evidence dt {
  color: var(--muted);
}
.plan-evidence dd {
  margin: 0;
  overflow-wrap: anywhere;
}
</style>
