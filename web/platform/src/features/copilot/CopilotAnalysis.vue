<script setup lang="ts">
import { computed, shallowRef } from 'vue';
import { Alert, Button, Checkbox, Input, Select } from 'ant-design-vue';
import { SendOutlined } from '@ant-design/icons-vue';
import { formatTime } from '@starbeacon/shared/types.ts';
import { useAnalysis } from '../analysis/useAnalysis';
import { analysisCodes, blankRequest, draftStepNames, stateNames, working } from '../analysis/analysis';
import { useModels } from '../models/useModels';

const props = defineProps<{ draft: boolean; context: string; question?: string }>();
const analysis = useAnalysis('chat');
const models = useModels();
const provider = shallowRef<string>();
const input = shallowRef(props.question ?? '');
const allow = shallowRef(false);
const job = analysis.selected;
const busy = computed(() => analysis.busy.value || (!!job.value && working(job.value.state)));
const options = computed(() =>
  models.items.value
    .filter(item => item.enabled && item.has_key)
    .map(item => ({ label: item.name + ' · ' + item.model, value: item.id })),
);
const timeWindow = computed(() => job.value?.request.window);
const canSend = computed(
  () =>
    !busy.value &&
    (analysis.unconfirmed.value ||
      (models.available.value &&
        options.value.some(item => item.value === provider.value) &&
        !!input.value.trim() &&
        allow.value)),
);

async function send() {
  if (!canSend.value) return;
  if (analysis.unconfirmed.value) {
    await analysis.confirm();
    return;
  }
  const model = models.items.value.find(item => item.id === provider.value);
  if (!model) return;
  const request = blankRequest('chat');
  const now = new Date();
  request.window = { start: new Date(now.getTime() - 86400000).toISOString(), end: now.toISOString() };
  request.provider_id = model.id;
  request.provider_revision = model.revision;
  request.allow_context = allow.value;
  request.question = props.draft ? input.value.trim() : '当前页面为「' + props.context + '」。' + input.value.trim();
  if (props.draft) request.purpose = 'playbook_draft';
  if (await analysis.submit(request)) allow.value = false;
}
</script>

<template>
  <form class="copilot-form" @submit.prevent="send">
    <label for="copilot-model">{{ draft ? '编排草稿模型' : '统计分析模型' }}</label>
    <Select
      id="copilot-model"
      v-model:value="provider"
      placeholder="选择模型"
      :options="options"
      :disabled="busy || analysis.unconfirmed.value"
      :loading="models.pending.value"
    />
    <Alert
      v-if="models.error.value || (!models.pending.value && !options.length)"
      type="warning"
      show-icon
      :message="models.error.value || '暂无可用模型，请在模型提供方配置。'"
    />
    <label for="copilot-question">{{ draft ? '用一句话描述处置场景' : '输入统计问题' }}</label>
    <Input.TextArea
      id="copilot-question"
      v-model:value="input"
      :rows="3"
      :maxlength="draft ? 800 : 1500"
      :placeholder="draft ? '例如高危告警先研判和核验，再通知值班人' : '例如过去一天哪些规则触发较多'"
      :disabled="busy || analysis.unconfirmed.value"
    />
    <Checkbox v-model:checked="allow" :disabled="busy || analysis.unconfirmed.value">
      {{ draft ? '允许把本次描述发给所选模型' : '允许把本次问题和最近 24 小时的授权统计发给所选模型' }}
    </Checkbox>
    <Alert v-if="analysis.actionError.value" show-icon type="error" :message="analysis.actionError.value" />
    <Button type="primary" html-type="submit" :disabled="!canSend" :loading="analysis.busy.value">
      <SendOutlined aria-hidden="true" />{{ analysis.unconfirmed.value ? '核对原提交' : '发送' }}
    </Button>
  </form>
  <section v-if="job" class="copilot-answer" aria-live="polite">
    <p class="muted">{{ stateNames[job.state] }}</p>
    <Alert v-if="analysis.detailError.value" show-icon type="error" :message="analysis.detailError.value">
      <template #action><Button size="small" @click="analysis.loadJob(job.id)">重试</Button></template>
    </Alert>
    <template v-if="job.answer">
      <h3>{{ draft ? '处置编排草稿' : '统计分析' }}</h3>
      <p>{{ job.answer.summary }}</p>
      <ol v-if="job.answer.steps">
        <li v-for="(step, index) in job.answer.steps" :key="index">
          <strong>{{ draftStepNames[step.kind] }}</strong> {{ step.description }}
        </li>
      </ol>
      <template v-else>
        <p v-if="timeWindow" class="muted">{{ formatTime(timeWindow.start) }} 至 {{ formatTime(timeWindow.end) }}</p>
        <div v-for="(row, index) in [...job.answer.observations, ...job.answer.recommendations]" :key="index">
          <p>{{ row.text }}</p>
          <small class="muted">{{ row.sources.join('、') }}</small>
        </div>
      </template>
    </template>
    <p v-else-if="!working(job.state)">{{ analysisCodes[job.result.code] ?? '模型未返回可用结果。' }}</p>
  </section>
</template>

<style scoped>
.copilot-form,
.copilot-answer {
  display: grid;
  gap: var(--related-gap);
}
.copilot-form :deep(.ant-btn) {
  justify-self: end;
}
.copilot-answer {
  border-top: 1px solid var(--line);
  padding-top: var(--field-gap);
  overflow-wrap: anywhere;
}
.copilot-answer :is(h3, p, ol) {
  margin: 0;
}
.copilot-answer ol {
  padding-inline-start: 1.5em;
}
</style>
