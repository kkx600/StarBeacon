<script setup lang="ts">
import { usePageTitle } from '@starbeacon/shared/utils/usePageTitle.ts';
const pageTitle = usePageTitle('报告中心');
import { computed, ref, watch } from 'vue';
import { Modal, Select, Checkbox } from 'ant-design-vue';
import StatePanel from '@starbeacon/shared/components/StatePanel.vue';
import PageHeader from '@starbeacon/shared/components/PageHeader.vue';
import ListTable from '@starbeacon/shared/components/ListTable.vue';
import ListPager from '@starbeacon/shared/components/ListPager.vue';
import StatusTag from '@starbeacon/shared/components/StatusTag.vue';
import { modelJobTones, statusTone } from '@starbeacon/shared/statusTones.ts';
import { formatTime } from '@starbeacon/shared/types.ts';
import { useModels } from '../models/useModels';
import { blankRequest, kindNames, stateNames } from './analysis';
import { useAnalysis } from './useAnalysis';
import AnalysisDetail from './AnalysisDetail.vue';
const models = useModels(),
  state = useAnalysis('reports'),
  { items, next, cursors, pageSize, pending, error, busy, actionError, unconfirmed, selected, loading, detailError } =
    state;
const open = ref(false),
  detailOpen = ref(false),
  kind = ref<'daily' | 'weekly' | 'monthly'>('daily'),
  period = ref(new Date(Date.now() - 86400000).toLocaleDateString('en-CA', { timeZone: 'Asia/Shanghai' })),
  timezone = ref('Asia/Shanghai'),
  provider = ref(''),
  allowed = ref(false),
  viewing = ref('');
const providers = computed(() => models.items.value.filter(p => p.enabled));
watch(
  () => [
    kind.value,
    period.value,
    timezone.value,
    provider.value,
    providers.value.find(p => p.id === provider.value)?.revision,
  ],
  () => {
    allowed.value = false;
  },
);
const columns = [
  { title: '报告编号', dataIndex: 'id', width: 150, className: 'technical', ellipsis: true },
  { title: '报告类型', key: 'kind', width: 108 },
  { title: '报告名称', key: 'name', width: 180, ellipsis: true },
  { title: '修订', dataIndex: 'revision', width: 62 },
  { title: '状态', key: 'state', width: 122 },
  { title: '统计开始时间', key: 'start', width: 172 },
  { title: '统计结束时间', key: 'end', width: 172 },
  { title: '生成时间', key: 'time', width: 172 },
  { title: '操作', key: 'action', width: 68, fixed: 'right' as const },
];
async function generate() {
  if (busy.value) return;
  let job;
  if (unconfirmed.value) job = await state.confirm();
  else {
    const r = blankRequest(kind.value);
    r.period = period.value;
    r.timezone = timezone.value;
    if (provider.value) {
      const p = providers.value.find(row => row.id === provider.value);
      if (!p) return;
      r.provider_id = p.id;
      r.provider_revision = p.revision;
      r.allow_context = allowed.value;
    }
    job = await state.submit(r);
  }
  if (job) {
    open.value = false;
    detailOpen.value = true;
    viewing.value = job.id;
    allowed.value = false;
  }
}
async function show(id: string) {
  state.clear();
  viewing.value = id;
  detailOpen.value = true;
  await state.loadJob(id);
}
function closeDetail() {
  detailOpen.value = false;
  state.clear();
}
</script>
<template>
  <PageHeader
    :title="pageTitle"
    description="生成安全日报、周报与月报，复核冻结的统计来源和模型调查建议。不同运行保留独立修订。"
  >
    <a-button :loading="pending" @click="state.refresh">刷新</a-button>
    <a-button type="primary" :disabled="busy" @click="open = true">生成报告</a-button>
  </PageHeader>
  <a-alert
    v-if="models.error.value"
    type="warning"
    :message="`${models.error.value}。可生成统计报告。`"
    show-icon
    class="section-gap"
  />
  <section class="panel table-panel">
    <div class="table-toolbar"><h2>报告记录</h2></div>
    <a-alert
      v-if="error && items.length"
      type="error"
      :message="error + '。当前显示上次成功读取的报告。'"
      show-icon
      class="section-gap"
      ><template #action><a-button @click="state.refresh">重试</a-button></template></a-alert
    >
    <StatePanel
      :loading="pending && !items.length"
      :error="items.length ? '' : error"
      :empty="items.length === 0"
      description="暂无报告记录，可选择自然日、完整周或自然月生成报告。"
      @retry="state.refresh"
    >
      <ListTable :columns="columns" :data-source="[...items]" :scroll="{ x: 1206 }">
        <template #bodyCell="{ column, record }">
          <template v-if="column.key === 'kind'">{{ kindNames[record.kind] }}</template>
          <button
            v-else-if="column.key === 'name'"
            type="button"
            class="record-link"
            :title="record.title"
            @click="show(record.id)"
          >
            {{ record.title }}
          </button>
          <StatusTag
            v-else-if="column.key === 'state'"
            :tone="statusTone(modelJobTones, record.state)"
            :value="stateNames[record.state] ?? '其他处理状态'"
          />
          <template v-else-if="column.key === 'start'">{{ formatTime(record.window.start) }}</template>
          <template v-else-if="column.key === 'end'">{{ formatTime(record.window.end) }}</template>
          <template v-else-if="column.key === 'time'">{{ formatTime(record.created_at) }}</template>
          <button v-else-if="column.key === 'action'" type="button" class="record-link" @click="show(record.id)">
            查看
          </button>
        </template>
      </ListTable>
    </StatePanel>
    <ListPager
      mode="cursor"
      :page="cursors.length"
      :page-size="pageSize"
      :count="pending || error ? undefined : items.length"
      :has-previous="cursors.length > 1"
      :has-next="!error && !!next"
      :disabled="pending"
      @previous="state.previousPage"
      @next="state.nextPage"
      @update:page-size="state.changePageSize"
    />
  </section>
  <Modal
    :open="open"
    title="生成安全报告"
    :width="640"
    :footer="null"
    :mask-closable="false"
    :closable="!busy && !unconfirmed"
    :keyboard="!busy && !unconfirmed"
    @cancel="open = false"
    ><a-alert v-if="actionError" type="error" :message="actionError" show-icon class="section-gap" /><a-alert
      v-if="unconfirmed"
      type="warning"
      message="提交结果尚未确认，请确认原请求后继续。"
      show-icon
      class="section-gap"
    /><a-form
      :model="{ kind, period, timezone, provider, allowed }"
      layout="vertical"
      :disabled="busy || unconfirmed"
      @finish="generate"
      ><div class="report-fields">
        <a-form-item label="报告类型"
          ><Select
            v-model:value="kind"
            aria-label="报告类型"
            :options="[
              { value: 'daily', label: '安全日报' },
              { value: 'weekly', label: '安全周报' },
              { value: 'monthly', label: '安全月报' },
            ]" /></a-form-item
        ><a-form-item label="周期内日期"
          ><input
            v-model="period"
            type="date"
            class="report-date"
            aria-label="周期内日期"
            required
            :disabled="busy || unconfirmed"
        /></a-form-item>
      </div>
      <a-form-item label="报告时区"
        ><a-input v-model:value="timezone" aria-label="报告时区" :maxlength="128" placeholder="Asia/Shanghai"
      /></a-form-item>
      <p class="muted section-gap">
        日报使用所选自然日；周报使用该日期所在的完整周（周一至周日）；月报使用该日期所在自然月。仅生成已经结束的周期，夏令时按报告时区计算。
      </p>
      <a-form-item label="智能总结" html-for="report-model"
        ><Select
          id="report-model"
          v-model:value="provider"
          aria-label="报告模型"
          :options="[
            { value: '', label: '仅生成统计报告' },
            ...providers.map(p => ({ value: p.id, label: `${p.name} · ${p.model}`, disabled: !state.available.value })),
          ]" /></a-form-item
      ><Checkbox v-if="provider" v-model:checked="allowed">允许本次模型调用使用周期统计</Checkbox>
      <p class="muted section-gap">
        模型调用可能计费。未启用智能总结或模型失败时，统计来源仍可复核；生成报告不会自动发布或通知他人。
      </p></a-form
    >
    <div class="filter-actions report-actions">
      <a-button :disabled="busy || unconfirmed" @click="open = false">取消</a-button
      ><a-button
        type="primary"
        :loading="busy"
        :disabled="busy || (!unconfirmed && (!period || !timezone || (!!provider && !allowed)))"
        @click="generate"
        >{{ unconfirmed ? '确认提交结果' : '开始生成' }}</a-button
      >
    </div></Modal
  >
  <AnalysisDetail
    :open="detailOpen"
    :job="selected"
    :loading="loading"
    :error="detailError"
    :busy="busy"
    @close="closeDetail"
    @retry="state.loadJob(viewing)"
    @cancel="state.cancel"
  />
</template>
<style scoped>
.report-fields {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 12px;
}
.report-date {
  width: 100%;
  min-height: 32px;
  border: 1px solid var(--line);
  border-radius: 6px;
  padding: 4px 10px;
  background: var(--surface);
  color: var(--text);
  font: inherit;
}
.report-date:focus {
  outline: 2px solid var(--primary);
  outline-offset: 2px;
}
.report-date:disabled {
  background: var(--control-disabled);
  color: var(--muted);
}
.report-actions {
  justify-content: flex-end;
  margin-top: 12px;
}
</style>
