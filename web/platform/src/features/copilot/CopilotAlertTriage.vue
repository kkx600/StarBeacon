<script setup lang="ts">
import { computed, shallowRef } from 'vue';
import { Alert, Button, Checkbox, Select } from 'ant-design-vue';
import { useAlertTriage } from '../alerts/useAlertTriage';
import { triageCodes, triageOutcomes, triageVerdicts, triageWorking } from '../alerts/triage';
import { useModels } from '../models/useModels';
import type { CopilotAlert } from './context';

const props = defineProps<{ alert: CopilotAlert }>();
const triage = useAlertTriage(props.alert.eventID, props.alert.digest);
const models = useModels();
const provider = shallowRef<string>();
const allow = shallowRef(false);
const job = triage.selected;
const working = computed(() => triage.busy.value || (!!job.value && triageWorking(job.value.state)));
const options = computed(() =>
  models.items.value
    .filter(item => item.enabled && item.has_key)
    .map(item => ({ label: item.name + ' · ' + item.model, value: item.id })),
);
const canSend = computed(
  () =>
    !working.value &&
    (triage.unconfirmed.value ||
      (triage.available.value &&
        models.available.value &&
        options.value.some(item => item.value === provider.value) &&
        allow.value)),
);

async function send() {
  if (!canSend.value) return;
  if (triage.unconfirmed.value) {
    await triage.confirm();
    return;
  }
  const item = models.items.value.find(row => row.id === provider.value);
  if (!item) return;
  const submitted = await triage.submit({
    event_id: props.alert.eventID,
    raw_sha256: props.alert.digest,
    provider_id: item.id,
    provider_revision: item.revision,
    note: '',
    allow_context: allow.value,
    observation_only: true,
  });
  if (submitted) allow.value = false;
}
</script>

<template>
  <form class="copilot-triage" @submit.prevent="send">
    <label for="copilot-triage-model">研判模型</label>
    <Select
      id="copilot-triage-model"
      v-model:value="provider"
      :options="options"
      :loading="models.pending.value"
      placeholder="选择模型"
      :disabled="working || triage.unconfirmed.value"
    />
    <Alert
      v-if="models.error.value || triage.error.value || (!models.pending.value && !options.length)"
      type="warning"
      show-icon
      :message="models.error.value || triage.error.value || '暂无可用模型，请在模型提供方配置。'"
    />
    <Checkbox v-model:checked="allow" :disabled="working || triage.unconfirmed.value">
      允许把当前告警的研判材料发给所选模型
    </Checkbox>
    <p class="muted">助手研判仅用于观察。处置需在值守或响应动作页授权。</p>
    <Alert v-if="triage.actionError.value" type="error" show-icon :message="triage.actionError.value" />
    <Button type="primary" html-type="submit" :disabled="!canSend" :loading="working">
      {{ triage.unconfirmed.value ? '核对原提交' : '开始研判' }}
    </Button>
  </form>
  <section v-if="job" class="copilot-triage" aria-live="polite">
    <Alert v-if="triage.detailError.value" show-icon type="error" :message="triage.detailError.value">
      <template #action><Button size="small" @click="triage.load(job.id)">重试</Button></template>
    </Alert>
    <template v-if="job.answer">
      <h3>{{ triageVerdicts[job.answer.verdict] }}</h3>
      <p>{{ triageOutcomes[job.answer.outcome] }} · 模型自报分数 {{ job.answer.confidence.toFixed(3) }}</p>
      <p>{{ job.answer.reason }}</p>
      <dl v-if="job.answer.references.length">
        <template
          v-for="fact in job.evidence.facts.filter(item => job!.answer!.references.includes(item.id))"
          :key="fact.id"
        >
          <dt>{{ fact.label }}</dt>
          <dd>{{ fact.value }}</dd>
        </template>
      </dl>
    </template>
    <p v-else>{{ triageCodes[job.result.code as keyof typeof triageCodes] ?? '请核对研判记录。' }}</p>
  </section>
</template>

<style scoped>
.copilot-triage {
  display: grid;
  gap: var(--related-gap);
  overflow-wrap: anywhere;
}
.copilot-triage :is(h3, p, dl, dd) {
  margin: 0;
}
.copilot-triage :deep(.ant-btn) {
  justify-self: end;
}
.copilot-triage dl {
  display: grid;
  grid-template-columns: minmax(100px, 1fr) minmax(0, 2fr);
  gap: var(--label-gap);
}
</style>
