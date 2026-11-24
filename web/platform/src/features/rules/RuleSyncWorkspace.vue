<script setup lang="ts">
import { statusTerms } from '@starbeacon/shared/terms.ts';
import { shallowRef } from 'vue';
import { Modal as AModal, Descriptions as ADescriptions, DescriptionsItem as ADescriptionsItem } from 'ant-design-vue';
import { formatTime } from '@starbeacon/shared/types.ts';
import StatePanel from '@starbeacon/shared/components/StatePanel.vue';
import ListPager from '@starbeacon/shared/components/ListPager.vue';
import ListTable from '@starbeacon/shared/components/ListTable.vue';
import PageHelp from '@starbeacon/shared/components/PageHelp.vue';
import StatusTag from '@starbeacon/shared/components/StatusTag.vue';
import { statusTone } from '@starbeacon/shared/statusTones.ts';
import { useRuleSync } from './useRuleSync';
import RuleSyncForm from './RuleSyncForm.vue';
import { syncStates, syncStateTones, syncCodes, type RuleSyncPlan } from './sync';
const state = useRuleSync(),
  detail = shallowRef<RuleSyncPlan>();
const columns = [
  { title: '计划编号', dataIndex: 'id', width: 140, className: 'technical', ellipsis: true },
  { title: '计划名称', key: 'name', width: 178, ellipsis: true },
  { title: '探针编号', dataIndex: ['spec', 'sensor_id'], width: 140, className: 'technical', ellipsis: true },
  { title: '规则包编号', dataIndex: ['spec', 'package_id'], width: 138, className: 'technical', ellipsis: true },
  { title: '规则修订', dataIndex: ['spec', 'package_revision'], width: 88, className: 'technical' },
  { title: '授权修订', dataIndex: 'revision', width: 85, className: 'technical' },
  { title: '配置状态', key: 'state', width: 85 },
  { title: '执行阶段', key: 'run', width: 145 },
  { title: '最近更新', key: 'time', width: 175, className: 'technical' },
  { title: '操作', key: 'action', width: 125, fixed: 'right' as const },
];
const stages = ['装载检查', '正样本重放', '反样本重放', '规则发布'];
function showDetail(id: string) {
  detail.value = state.page.value.items.find(p => p.id === id);
}
function configure(id: string) {
  const p = state.page.value.items.find(p => p.id === id);
  if (p) void state.open(p);
}
</script>
<template>
  <div class="panel table-toolbar section-gap">
    <div class="heading-with-help">
      <h2>规则自动同步</h2>
      <PageHelp title="规则自动同步"
        ><p>平台持续核对获批的固定修订，再由采集器执行。已下发的任务须独立核对结果。</p></PageHelp
      >
    </div>
    <a-space
      ><a-button :loading="state.pending.value" @click="state.refresh">刷新</a-button
      ><a-button type="primary" :disabled="state.saving.value || !!state.unconfirmed.value" @click="state.open(null)"
        >创建同步计划</a-button
      ></a-space
    >
  </div>
  <a-alert
    v-if="state.unconfirmed.value && state.editing.value === undefined"
    type="warning"
    show-icon
    message="上次保存结果尚未确认，请核对原提交。"
    class="section-gap"
    ><template #action
      ><a-button :loading="state.saving.value" @click="state.confirm">核对原提交</a-button></template
    ></a-alert
  >
  <section class="panel table-panel">
    <StatePanel
      :loading="state.pending.value"
      :error="state.error.value"
      :empty="state.page.value.items.length === 0"
      description="暂无规则同步计划。创建计划前，请导入正反样本并核对探针执行能力。"
      @retry="state.refresh"
    >
      <ListTable :columns="columns" :data-source="state.page.value.items" :scroll="{ x: 1299 }"
        ><template #bodyCell="{ column, record }">
          <button
            v-if="column.key === 'name'"
            type="button"
            class="record-link"
            :title="record.spec.name"
            @click="showDetail(record.id)"
          >
            {{ record.spec.name }}
          </button>
          <StatusTag
            v-else-if="column.key === 'state'"
            :tone="record.spec.enabled ? statusTerms.启用 : statusTerms.停用"
            :value="record.spec.enabled ? '启用' : '停用'"
          />
          <StatusTag
            v-else-if="column.key === 'run'"
            :tone="
              record.run
                ? statusTone(syncStateTones, record.run.state)
                : record.processed_revision
                  ? statusTerms.已过期
                  : statusTerms.排队中
            "
            :value="record.run ? syncStates[record.run.state] : record.processed_revision ? '运行档案已到期' : '排队中'"
          />
          <template v-else-if="column.key === 'time'">{{ formatTime(record.updated_at) }}</template>
          <div v-else-if="column.key === 'action'" class="table-row-actions">
            <a-button type="link" size="small" @click="showDetail(record.id)">查看</a-button
            ><a-button
              type="link"
              size="small"
              :disabled="state.saving.value || !!state.unconfirmed.value"
              @click="configure(record.id)"
              >配置</a-button
            >
          </div>
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
  </section>
  <RuleSyncForm
    v-if="state.editing.value !== undefined"
    :key="state.editing.value?.id ?? 'create'"
    :plan="state.editing.value"
    :sensors="state.sensors.value"
    :packages="state.packages.value"
    :busy="state.saving.value"
    :locked="!!state.unconfirmed.value"
    :error="state.formError.value"
    :choices-error="state.choicesError.value"
    :choices-pending="state.choicesPending.value"
    @save="state.save"
    @confirm="state.confirm"
    @close="state.close"
  />
  <a-modal v-if="detail" open title="规则同步详情" :width="780" :footer="null" @cancel="detail = undefined">
    <a-descriptions bordered :column="1"
      ><a-descriptions-item label="计划">{{ detail.spec.name }} · 授权修订 {{ detail.revision }}</a-descriptions-item
      ><a-descriptions-item label="探针">{{ detail.spec.sensor_id }}</a-descriptions-item
      ><a-descriptions-item label="注册代次"
        ><span class="technical">{{ detail.spec.registration_id }}</span></a-descriptions-item
      ><a-descriptions-item label="批准规则"
        >{{ detail.spec.package_id }} · 修订 {{ detail.spec.package_revision }}</a-descriptions-item
      ><a-descriptions-item label="核对周期">{{ detail.spec.interval_seconds }} 秒</a-descriptions-item></a-descriptions
    >
    <template v-if="detail.run"
      ><p>
        本次批准规则：{{ detail.run.spec.package_id }} · 修订 {{ detail.run.spec.package_revision }}；批准人：{{
          detail.run.created_by
        }}
      </p>
      <p>
        {{ syncStates[detail.run.state] }} · {{ syncCodes[detail.run.code] ?? detail.run.code }}（授权修订
        {{ detail.run.plan_revision }}）
      </p>
      <ol class="sync-steps">
        <li v-for="(title, index) in stages" :key="title">
          <span>{{ title }}</span><RouterLink
            v-if="detail.run.tasks[index]"
            :to="{ path: '/sensors/tasks', query: { task: detail.run.tasks[index] } }"
            >查看独立任务</RouterLink
          ><span v-else class="field-hint">尚未提交</span>
        </li>
      </ol>
      <p class="field-hint">
        运行档案到期：{{
          formatTime(detail.run.expires_at)
        }}。生效回执反映执行时的状态，不代表此后规则未被其他授权操作改变。
      </p></template
    >
    <p v-else class="field-hint">
      {{
        detail.processed_revision
          ? '本授权已处理，运行档案已超过保留期限。'
          : '尚无运行记录。启用后会核对目标身份和执行条件。'
      }}
    </p>
  </a-modal>
</template>
<style scoped>
.sync-steps {
  padding-left: 24px;
}
.sync-steps li {
  padding: 10px 0;
}
.sync-steps li > span:first-child {
  display: inline-block;
  min-width: 130px;
}
</style>
