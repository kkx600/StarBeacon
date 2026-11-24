<script setup lang="ts">
import { useFeedback } from '@starbeacon/shared/composables/useFeedback.ts';
import { computed, onMounted, reactive, ref, watch } from 'vue';
import { Popover as APopover, Select as ASelect, Checkbox as ACheckbox } from 'ant-design-vue';
import { formatTime } from '@starbeacon/shared/types.ts';
import StatePanel from '@starbeacon/shared/components/StatePanel.vue';
import ListTable from '@starbeacon/shared/components/ListTable.vue';
import PageHelp from '@starbeacon/shared/components/PageHelp.vue';
import StatusTag from '@starbeacon/shared/components/StatusTag.vue';
import { alertWorkflowTones } from '@starbeacon/shared/statusTones.ts';
import type { StatusTone } from '@starbeacon/shared/terms.ts';
import {
  assessmentStatuses,
  assessmentVerdicts,
  assessmentOutcomes,
  initialAssessment,
  assessmentInputError,
  type AssessmentSpec,
} from './assessment';
import { useAssessment } from './useAssessment';
const message = useFeedback();
const props = defineProps<{ eventId: string; digest: string }>();
const emit = defineEmits<{ locked: [value: boolean] }>();
const state = useAssessment(props.eventId, props.digest);
const { current, pending, error, busy, unconfirmed, actionError, history, historyPending, historyError, next } = state;
const form = reactive({ ...initialAssessment(), claim: false, refs: '' }),
  historyOpen = ref(false),
  formError = ref('');
watch(current, record => {
  if (record) {
    Object.assign(form, record.spec, { claim: false, refs: record.spec.evidence.join('\n') });
    formError.value = '';
  }
});
watch([busy, unconfirmed], () => emit('locked', busy.value || unconfirmed.value), { immediate: true });
watch(
  () => form.verdict,
  verdict => {
    if (verdict !== 'confirmed') form.outcome = 'unknown';
  },
);
const disabled = computed(() => pending.value || busy.value || unconfirmed.value || !!error.value || !current.value);
const verdictTones = {
  unreviewed: 'neutral',
  suspicious: 'warning',
  false_positive: 'neutral',
  confirmed: 'danger',
} as const satisfies Record<AssessmentSpec['verdict'], StatusTone>;
const columns = [
  { title: '修订', dataIndex: 'revision', width: 64, className: 'technical' },
  { title: '记录时间', key: 'updated', width: 176, className: 'technical' },
  { title: '处理状态', key: 'status', width: 96 },
  { title: '研判结论', key: 'verdict', width: 96 },
  { title: '攻击结果', key: 'outcome', width: 144 },
  { title: '操作人', dataIndex: 'analyst', width: 110, ellipsis: true },
  { title: '认领人', key: 'owner', width: 110, ellipsis: true },
  { title: '操作', key: 'note', width: 114, fixed: 'right' as const },
];
async function save() {
  if (disabled.value || !current.value) return;
  const spec: AssessmentSpec = {
    status: form.status,
    verdict: form.verdict,
    outcome: form.outcome,
    note: form.note.trim(),
    evidence: form.refs.trim() ? form.refs.split('\n').map(v => v.trim()) : [],
  };
  formError.value = assessmentInputError(spec);
  if (formError.value) return;
  if (await state.save({ expected_revision: current.value.revision, spec, claim: form.claim }))
    message.success('告警研判已保存');
}
async function confirm() {
  if (await state.confirm()) message.success('研判保存结果已确认');
}
async function showHistory() {
  historyOpen.value = true;
  await state.loadHistory();
}
function back() {
  historyOpen.value = false;
  void state.refresh();
}
onMounted(() => {
  void state.refresh();
});
</script>
<template>
  <template v-if="historyOpen">
    <div class="filter-actions section-gap">
      <a-button @click="back">返回研判</a-button
      ><a-button :loading="historyPending" @click="state.loadHistory()">刷新记录</a-button>
    </div>
    <a-alert
      v-if="historyError && history.length"
      type="error"
      :message="`${historyError}。当前显示上次成功读取的记录。`"
      show-icon
      class="section-gap"
    />
    <StatePanel
      :loading="historyPending && !history.length"
      :error="history.length ? '' : historyError"
      :empty="!history.length"
      description="暂无研判记录，保存后可查看每次操作的结论和依据。"
      @retry="state.loadHistory()"
    >
      <ListTable :columns="columns" :data-source="history" row-key="revision" :scroll="{ x: 910 }">
        <template #bodyCell="{ column, record }">
          <template v-if="column.key === 'updated'">{{ formatTime(record.updated_at) }}</template>
          <StatusTag
            v-else-if="column.key === 'status'"
            :tone="alertWorkflowTones[record.spec.status]"
            :value="assessmentStatuses[record.spec.status]"
          />
          <StatusTag
            v-else-if="column.key === 'verdict'"
            :tone="verdictTones[record.spec.verdict]"
            :value="assessmentVerdicts[record.spec.verdict]"
          />
          <template v-else-if="column.key === 'outcome'">{{ assessmentOutcomes[record.spec.outcome] }}</template>
          <span v-else-if="column.key === 'owner'" :title="record.owner_name || undefined">{{
            record.owner_name || '未认领'
          }}</span>
          <a-popover v-else-if="column.key === 'note'" trigger="click" placement="left" title="研判说明与证据">
            <template #content>
              <div class="assessment-evidence">
                <p class="assessment-note">{{ record.spec.note }}</p>
                <ul v-if="record.spec.evidence.length" class="technical">
                  <li v-for="reference in record.spec.evidence" :key="reference">{{ reference }}</li>
                </ul>
              </div>
            </template>
            <button type="button" class="record-link">说明与证据</button>
          </a-popover>
        </template>
      </ListTable>
      <a-button v-if="next" :loading="historyPending" class="section-gap" @click="state.loadHistory(next)"
        >加载更早记录</a-button
      >
    </StatePanel>
  </template>
  <template v-else>
    <div class="filter-actions section-gap">
      <a-button :loading="pending" :disabled="busy || unconfirmed" @click="state.refresh">刷新研判</a-button
      ><a-button :disabled="busy || unconfirmed || pending || !!error" @click="showHistory">查看研判记录</a-button
      ><span class="muted">{{
        current?.revision
          ? `修订 ${current.revision} · ${formatTime(current.updated_at)} · ${current.analyst}`
          : '尚未保存研判'
      }}</span>
      <PageHelp title="告警研判">
        <p>人工研判记录保存人工判断、证据引用和认领情况。攻击结果须依据独立证据确认。</p>
      </PageHelp>
    </div>
    <a-alert
      v-if="error && current"
      type="error"
      :message="`${error}。当前显示上次成功读取的研判，恢复读取后才能保存。`"
      show-icon
      class="section-gap"
    />
    <StatePanel :loading="pending && !current" :error="current ? '' : error" :empty="false" @retry="state.refresh">
      <template v-if="current">
        <p class="muted">
          认领人：{{ current.owner_name || '未认领' }} ·
          {{ current.expires_at ? '记录保留至 ' + formatTime(current.expires_at) : '留存期限在首次保存时固化' }}
        </p>
        <a-form :model="form" layout="vertical" @finish="save">
          <div class="assessment-fields">
            <a-form-item label="处理状态"
              ><a-select
                v-model:value="form.status"
                aria-label="处理状态"
                :disabled="disabled"
                :options="
                  Object.entries(assessmentStatuses).map(([value, label]) => ({
                    value,
                    label,
                    disabled: value === 'closed' && !['false_positive', 'confirmed'].includes(form.verdict),
                  }))
                "
            /></a-form-item>
            <a-form-item label="研判结论"
              ><a-select
                v-model:value="form.verdict"
                aria-label="研判结论"
                :disabled="disabled"
                :options="Object.entries(assessmentVerdicts).map(([value, label]) => ({ value, label }))"
            /></a-form-item>
            <a-form-item label="攻击结果"
              ><a-select
                v-model:value="form.outcome"
                aria-label="攻击结果"
                :disabled="disabled || form.verdict !== 'confirmed'"
                :options="Object.entries(assessmentOutcomes).map(([value, label]) => ({ value, label }))"
            /></a-form-item>
          </div>
          <a-form-item label="研判说明" required
            ><a-textarea
              v-model:value="form.note"
              aria-label="研判说明"
              :disabled="disabled"
              :rows="4"
              :maxlength="2048"
              show-count
              placeholder="说明调查范围、判断依据、尚未确认的内容和后续处理。"
          /></a-form-item>
          <a-form-item
            label="证据引用"
            extra="每行一条，最多 8 条。确认攻击成功或已阻止时必填，可填写案件、终端或设备回执标识。"
            ><a-textarea
              v-model:value="form.refs"
              aria-label="证据引用"
              :disabled="disabled"
              :rows="2"
              :maxlength="2055"
              placeholder="填写可以复核的证据标识；请勿填写密码或访问令牌。"
          /></a-form-item>
          <a-checkbox v-model:checked="form.claim" :disabled="disabled"
            >认领给当前账号{{ current.owner_name ? '，替换当前认领人' : '' }}</a-checkbox
          >
          <a-alert
            v-if="formError || actionError"
            type="error"
            :message="formError || actionError"
            show-icon
            class="section-gap"
          />
          <a-alert
            v-if="unconfirmed"
            type="warning"
            message="保存结果尚未确认，原输入和请求标识已保留。请先确认原请求，避免覆盖其他人的研判。"
            show-icon
            class="section-gap"
          />
          <div class="filter-actions section-gap">
            <a-button v-if="unconfirmed" type="primary" :loading="busy" @click="confirm">确认保存结果</a-button
            ><a-button v-else type="primary" html-type="submit" :disabled="disabled" :loading="busy">保存研判</a-button>
          </div>
        </a-form>
      </template>
    </StatePanel>
  </template>
</template>
<style scoped>
.assessment-fields {
  display: grid;
  grid-template-columns: repeat(3, minmax(0, 1fr));
  gap: 12px;
}
.assessment-note {
  white-space: pre-wrap;
  overflow-wrap: anywhere;
  margin: 0;
}
.assessment-evidence {
  max-width: min(400px, 70vw);
  max-height: 40vh;
  overflow: auto;
}
</style>
