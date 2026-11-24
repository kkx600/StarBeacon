<script setup lang="ts">
import { shallowRef } from 'vue';
import { Modal as AModal } from 'ant-design-vue';
import { formatTime } from '@starbeacon/shared/types.ts';
import StatePanel from '@starbeacon/shared/components/StatePanel.vue';
import ListPager from '@starbeacon/shared/components/ListPager.vue';
import ListTable from '@starbeacon/shared/components/ListTable.vue';
import PageHelp from '@starbeacon/shared/components/PageHelp.vue';
import StatusTag from '@starbeacon/shared/components/StatusTag.vue';
import { statusTone } from '@starbeacon/shared/statusTones.ts';
import { session } from '../../session';
import { useRuleRollouts } from './useRuleRollouts';
import { rolloutStates, rolloutCodes, rolloutStateTones, rolloutTerminal, stopReasonError } from './rollout';
import RuleRolloutForm from './RuleRolloutForm.vue';
import RuleRolloutDetail from './RuleRolloutDetail.vue';
const state = useRuleRollouts(),
  reason = shallowRef(''),
  reasonError = shallowRef('');
const columns = [
  { title: '发布编号', dataIndex: 'id', width: 140, className: 'technical', ellipsis: true },
  { title: '发布任务', key: 'name', width: 175, ellipsis: true },
  { title: '目标与批次', key: 'scope', width: 210 },
  { title: '执行状态', key: 'state', width: 168 },
  { title: '执行说明', key: 'note', width: 178, ellipsis: true },
  { title: '创建时间', key: 'time', width: 175, className: 'technical' },
  { title: '操作', key: 'action', width: 70, fixed: 'right' as const },
];
function stop() {
  reasonError.value = stopReasonError(reason.value);
  if (!reasonError.value) void state.stop(reason.value);
}
function openStop() {
  reason.value = '';
  reasonError.value = '';
  state.openStop();
}
</script>
<template>
  <div class="panel table-toolbar section-gap">
    <div class="heading-with-help">
      <h2>{{ state.detailID.value ? '分批发布详情' : '分批发布' }}</h2>
      <PageHelp title="分批发布"
        ><p>每个目标独立验证。前一批心跳与观察窗口核对通过后启用下一批，回滚需单独发起。</p></PageHelp
      >
    </div>
    <a-space wrap
      ><template v-if="state.detailID.value"
        ><a-button @click="state.back">返回列表</a-button
        ><a-button :loading="state.detailPending.value" @click="state.show(state.detailID.value)">刷新执行状态</a-button
        ><a-button
          v-if="
            state.detail.value && !rolloutTerminal(state.detail.value.state) && state.detail.value.state !== 'stopping'
          "
          danger
          :disabled="state.saving.value || !!state.unconfirmed.value"
          @click="openStop"
          >停止后续发布</a-button
        ></template
      ><template v-else
        ><a-button :loading="state.pending.value" @click="state.refresh">刷新</a-button
        ><a-button type="primary" :disabled="state.saving.value || !!state.unconfirmed.value" @click="state.open"
          >创建分批发布</a-button
        ></template
      ></a-space
    >
  </div>
  <a-alert
    v-if="state.unconfirmed.value && !state.creating.value && !state.stopping.value"
    type="warning"
    show-icon
    message="上次操作结果尚未确认，请核对原提交。"
    class="section-gap"
    ><template #action
      ><a-button :loading="state.saving.value" @click="state.confirm">核对原提交</a-button></template
    ></a-alert
  >
  <section class="panel table-panel">
    <StatePanel
      v-if="state.detailID.value"
      :loading="state.detailPending.value"
      :error="state.detailError.value"
      :empty="false"
      @retry="state.show(state.detailID.value)"
      ><RuleRolloutDetail v-if="state.detail.value" :rollout="state.detail.value"
    /></StatePanel>
    <template v-else>
      <StatePanel
        :loading="state.pending.value"
        :error="state.error.value"
        :empty="state.page.value.items.length === 0"
        description="暂无分批发布。先创建停用的单探针同步计划，再选择固定修订并批准发布范围。"
        @retry="state.refresh"
      >
        <ListTable :columns="columns" :data-source="state.page.value.items" :scroll="{ x: 1116 }"
          ><template #bodyCell="{ column, record }">
            <button
              v-if="column.key === 'name'"
              type="button"
              class="record-link"
              :title="record.spec.name"
              @click="state.show(record.id)"
            >
              {{ record.spec.name }}
            </button>
            <template v-else-if="column.key === 'scope'"
              >{{ record.spec.plans.length }} 台 · 首批 {{ record.spec.canary_count }} · 每批
              {{ record.spec.batch_size }}</template
            >
            <StatusTag
              v-else-if="column.key === 'state'"
              :tone="statusTone(rolloutStateTones, record.state)"
              :value="rolloutStates[record.state]"
            />
            <span v-else-if="column.key === 'note'" :title="rolloutCodes[record.code] ?? record.code">{{
              rolloutCodes[record.code] ?? record.code
            }}</span>
            <template v-else-if="column.key === 'time'">{{ formatTime(record.created_at) }}</template>
            <template v-else-if="column.key === 'action'"
              ><button type="button" class="record-link" @click="state.show(record.id)">查看</button></template
            >
          </template></ListTable
        >
      </StatePanel>
      <ListPager
        mode="cursor"
        :page="state.cursors.value.length"
        :page-size="state.pageSize.value"
        :count="state.pending.value || state.error.value ? undefined : state.page.value.items.length"
        :has-previous="state.cursors.value.length > 1"
        :has-next="!state.error.value && !!state.page.value.next_cursor"
        :disabled="state.pending.value"
        @previous="state.previous"
        @next="state.next"
        @update:page-size="state.changePageSize"
      />
    </template>
  </section>
  <RuleRolloutForm
    v-if="session.current.value?.role === 'admin'"
    :key="state.draftEpoch.value"
    :open="state.creating.value"
    :plans="state.plans.value"
    :user-id="session.current.value?.id ?? ''"
    :busy="state.saving.value"
    :locked="!!state.unconfirmed.value"
    :error="state.formError.value"
    :plans-pending="state.plansPending.value"
    :plans-error="state.plansError.value"
    :has-more="!!state.plansCursor.value"
    @save="state.create"
    @confirm="state.confirm"
    @close="state.close"
    @more="state.loadPlans(true)"
    @retry="state.loadPlans()"
  />
  <a-modal
    v-if="state.stopping.value"
    open
    title="停止后续发布"
    :width="560"
    :mask-closable="false"
    :closable="!state.saving.value"
    :keyboard="!state.saving.value"
    @cancel="state.close"
  >
    <a-alert
      type="warning"
      show-icon
      message="停止提交后续任务，并等待已下发任务的独立回执。已经生效的规则继续保留，回退需要另行验证与授权。"
      class="section-gap"
    />
    <a-alert
      v-if="state.formError.value || reasonError"
      type="error"
      show-icon
      :message="state.formError.value || reasonError"
      class="section-gap"
    />
    <a-form layout="vertical"
      ><a-form-item label="停止原因" required
        ><a-textarea
          v-model:value="reason"
          :maxlength="512"
          :disabled="state.saving.value || !!state.unconfirmed.value"
          :auto-size="{ minRows: 3, maxRows: 6 }"
          aria-label="停止原因"
          @input="reasonError = ''" /></a-form-item
    ></a-form>
    <template #footer
      ><a-button :disabled="state.saving.value" @click="state.close">关闭</a-button
      ><a-button v-if="state.unconfirmed.value" type="primary" :loading="state.saving.value" @click="state.confirm"
        >核对原提交</a-button
      ><a-button v-else danger :loading="state.saving.value" @click="stop">确认停止后续发布</a-button></template
    >
  </a-modal>
</template>
