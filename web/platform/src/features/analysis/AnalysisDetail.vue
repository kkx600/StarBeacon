<script setup lang="ts">
import { useFeedback } from '@starbeacon/shared/composables/useFeedback.ts';
import { computed, ref, watch, onScopeDispose } from 'vue';
import { Modal } from 'ant-design-vue';
import StatePanel from '@starbeacon/shared/components/StatePanel.vue';
import ListTable from '@starbeacon/shared/components/ListTable.vue';
import PageHelp from '@starbeacon/shared/components/PageHelp.vue';
import MetricBar from '@starbeacon/shared/components/MetricBar.vue';
import StatusTag from '@starbeacon/shared/components/StatusTag.vue';
import { tablePagination } from '@starbeacon/shared/pagination.ts';
import { modelJobTones, statusTone } from '@starbeacon/shared/statusTones.ts';
import { formatTime } from '@starbeacon/shared/types.ts';
import { resultNames } from '../models/models';
import { countText } from '../overview/overview';
import {
  analysisCodes,
  analysisFacts,
  kindNames,
  stateNames,
  totalAlerts,
  working,
  type AnalysisJob,
} from './analysis';
import { session } from '../../session';
const message = useFeedback();
const props = defineProps<{ open: boolean; job: AnalysisJob | null; loading: boolean; error: string; busy: boolean }>();
const emit = defineEmits<{ close: []; retry: []; cancel: [id: string] }>();
const exporting = ref(false);
let downloadControl: AbortController | undefined;
watch(
  () => props.open,
  open => {
    if (!open) downloadControl?.abort();
  },
);
onScopeDispose(() => downloadControl?.abort());
const facts = computed(() => (props.job ? analysisFacts(props.job) : []));
const factColumns = [
  { title: '来源编号', dataIndex: 'id', width: 192, className: 'technical', ellipsis: true },
  { title: '统计项', dataIndex: 'label', width: 218, ellipsis: true },
  { title: '统计值', dataIndex: 'value', width: 300, ellipsis: true },
];
const metrics = computed(() => {
  const job = props.job;
  if (!job) return [];
  const inventory = job.evidence.segments.at(-1)?.inventory;
  return [
    { label: '已索引告警', value: countText(totalAlerts(job)) },
    { label: '登记资产（生成时）', value: inventory ? countText(inventory.assets) : '—' },
    { label: '在线探针（生成时）', value: inventory ? countText(inventory.online) : '—' },
  ];
});
async function download() {
  if (!props.job || exporting.value) return;
  const control = new AbortController();
  downloadControl = control;
  exporting.value = true;
  try {
    const job = props.job,
      blob = await session.api.download('/analysis/jobs/' + encodeURIComponent(job.id) + '/report', control.signal);
    if (control.signal.aborted) return;
    const url = URL.createObjectURL(blob),
      link = document.createElement('a'),
      revoke = URL.revokeObjectURL.bind(URL);
    link.href = url;
    link.download = `starbeacon-${job.request.kind}-${job.request.period}-${job.id}.html`;
    link.click();
    setTimeout(() => revoke(url), 1000);
  } catch (e) {
    if (!control.signal.aborted) message.error(e instanceof Error ? e.message : '报告导出失败');
  } finally {
    exporting.value = false;
  }
}
</script>
<template>
  <Modal
    :open="open"
    :title="
      job
        ? `${kindNames[job.request.kind]} · ${job.request.kind === 'chat' ? '分析记录' : job.request.period}`
        : '分析结果'
    "
    :width="880"
    :footer="null"
    @cancel="emit('close')"
  >
    <StatePanel :loading="loading && !job" :error="!job ? error : ''" :empty="false" @retry="emit('retry')"
      ><template v-if="job">
        <a-alert
          v-if="error"
          type="error"
          :message="`${error}。当前显示上次成功读取的结果。`"
          show-icon
          class="section-gap"
        />
        <div class="filter-actions section-gap">
          <StatusTag
            :tone="statusTone(modelJobTones, job.state)"
            :value="stateNames[job.state] ?? '其他处理状态'"
          /><span class="muted">修订 {{ job.revision }} · {{ formatTime(job.created_at) }}</span
          ><a-button :loading="loading" :disabled="busy || loading" @click="emit('retry')">刷新结果</a-button
          ><a-button
            v-if="working(job.state)"
            danger
            :disabled="busy || job.cancel_requested"
            @click="emit('cancel', job.id)"
            >{{ job.cancel_requested ? '取消请求已提交' : '取消分析' }}</a-button
          ><a-button v-if="job.request.kind !== 'chat' && !working(job.state)" :loading="exporting" @click="download"
            >导出 HTML</a-button
          >
        </div>
        <p class="page-description section-gap">
          {{
            analysisCodes[job.result.code] ?? resultNames[job.result.code] ?? '未提供处理说明'
          }}。提供方受理和用量以实际返回为准。
        </p>
        <a-alert
          v-if="job.state === 'uncertain' || (job.cancel_requested && working(job.state))"
          type="warning"
          message="请求可能已由提供方执行，取消不保证停止计费；未确认结果不会自动重试。"
          show-icon
          class="section-gap"
        />
        <MetricBar :items="metrics" />
        <p class="muted">
          统计范围：{{ formatTime(job.evidence.window.start) }} — {{ formatTime(job.evidence.window.end) }} ·
          {{ job.request.timezone || 'UTC' }}
        </p>
        <section v-if="job.answer" class="analysis-narrative">
          <h2>模型概述</h2>
          <p>{{ job.answer.summary }}</p>
          <template
            v-for="group in [
              { label: '统计观察', items: job.answer.observations },
              { label: '调查建议', items: job.answer.recommendations },
            ]"
            :key="group.label"
            ><h2>{{ group.label }}</h2>
            <p v-if="!group.items.length" class="muted">暂无内容</p>
            <div v-for="(item, index) in group.items" :key="index">
              <p>{{ item.text }}</p>
              <small class="muted">来源：{{ item.sources.join('、') }}</small>
            </div></template
          >
        </section>
        <a-alert
          v-else-if="!working(job.state)"
          type="info"
          message="智能总结未返回，完整统计来源仍可复核。"
          show-icon
          class="section-gap"
        />
        <div class="heading-with-help">
          <h2>统计来源</h2>
          <PageHelp title="统计来源">
            <p>统计快照仅记录已索引告警。检测结论与周期覆盖率需独立核对，模型建议需人工复核。</p>
          </PageHelp>
        </div>
        <ListTable :data-source="facts" :columns="factColumns" :pagination="tablePagination()" :scroll="{ x: 710 }" />
        <dl class="analysis-metadata">
          <dt>分析标识</dt>
          <dd>{{ job.id }}</dd>
          <dt>输入 Token / 输出 Token / 总 Token</dt>
          <dd>
            {{
              job.result.usage
                ? `${job.result.usage.input_tokens} / ${job.result.usage.output_tokens} / ${job.result.usage.total_tokens}`
                : '无数据'
            }}
          </dd>
          <dt>模型处理耗时</dt>
          <dd>{{ job.result.duration_ms == null ? '无数据' : `${job.result.duration_ms} ms` }}</dd>
          <dt>模型标识</dt>
          <dd>{{ job.result.returned_model ?? (job.request.provider_id || '未调用模型') }}</dd>
          <dt>快照 SHA-256</dt>
          <dd>{{ job.evidence.sha256 }}</dd>
          <dt>保留至</dt>
          <dd>{{ formatTime(job.expires_at) }}</dd>
        </dl>
        <p v-for="limit in job.evidence.segments[0]?.limitations ?? []" :key="limit" class="muted">{{ limit }}</p>
      </template></StatePanel
    >
  </Modal>
</template>
<style scoped>
.analysis-narrative p {
  white-space: pre-wrap;
  overflow-wrap: anywhere;
}
.analysis-narrative > div {
  padding: 8px 0;
  border-bottom: 1px solid var(--line);
}
h2 {
  font-size: 16px;
  margin: 12px 0 8px;
}
.analysis-metadata {
  display: grid;
  grid-template-columns: minmax(150px, 1fr) minmax(0, 2fr);
  gap: 8px;
  margin: 12px 0;
}
.analysis-metadata dt {
  color: var(--muted);
}
.analysis-metadata dd {
  margin: 0;
  overflow-wrap: anywhere;
}
</style>
