<script setup lang="ts">
import { shallowRef, watch } from 'vue';
import { Modal as AModal, Descriptions as ADescriptions, DescriptionsItem as ADescriptionsItem } from 'ant-design-vue';
import { formatTime } from '@starbeacon/shared/types.ts';
import ListTable from '@starbeacon/shared/components/ListTable.vue';
import StatusTag from '@starbeacon/shared/components/StatusTag.vue';
import { tablePagination } from '@starbeacon/shared/pagination.ts';
import { statusTone } from '@starbeacon/shared/statusTones.ts';
import {
  rolloutStates,
  rolloutCodes,
  rolloutTargetTones,
  targetStates,
  type RuleRollout,
  type RolloutTarget,
} from './rollout';
import { syncStates, syncCodes } from './sync';
const props = defineProps<{ rollout: RuleRollout; taskPath?: string }>();
const target = shallowRef<RolloutTarget>();
watch(
  () => props.rollout,
  () => {
    target.value = undefined;
  },
);
const columns = [
  { title: '探针编号', dataIndex: ['spec', 'sensor_id'], width: 145, ellipsis: true, className: 'technical' },
  { title: '批次', key: 'batch', width: 76 },
  { title: '计划编号', dataIndex: 'plan_id', width: 140, ellipsis: true, className: 'technical' },
  { title: '冻结计划', dataIndex: ['spec', 'name'], width: 140, ellipsis: true },
  { title: '批准修订', dataIndex: 'authorized_revision', width: 84, className: 'technical' },
  { title: '规则包编号', dataIndex: ['spec', 'package_id'], width: 130, ellipsis: true, className: 'technical' },
  { title: '规则修订', dataIndex: ['spec', 'package_revision'], width: 84, className: 'technical' },
  { title: '执行状态', key: 'state', width: 128 },
  { title: '执行说明', key: 'note', width: 195, ellipsis: true },
  { title: '操作', key: 'action', width: 110, fixed: 'right' as const },
];
const stages = ['装载检查', '正样本重放', '反样本重放', '规则发布'];
function targetNote(row: RolloutTarget) {
  return row.run && !row.run.finished_at
    ? syncStates[row.run.state]
    : (rolloutCodes[row.code] ?? syncCodes[row.code] ?? row.code);
}
function inspect(ordinal: number) {
  target.value = props.rollout.targets?.find(t => t.ordinal === ordinal);
}
</script>
<template>
  <a-alert
    :type="rollout.state === 'blocked' ? 'error' : rollout.state === 'succeeded' ? 'success' : 'info'"
    show-icon
    :message="rolloutStates[rollout.state]"
    :description="(rolloutCodes[rollout.code] ?? rollout.code) || '每个目标独立核对，不使用其他探针的验证结果。'"
    class="section-gap"
  />
  <a-descriptions bordered :column="2" class="section-gap rollout-summary">
    <a-descriptions-item label="发布名称">{{ rollout.spec.name }}</a-descriptions-item><a-descriptions-item
      label="当前批次"
      >第 {{ rollout.current_batch + 1 }} 批 · 共 {{ rollout.targets?.length }} 台探针</a-descriptions-item
    >
    <a-descriptions-item label="发布规则摘要" :span="2"
      ><span class="technical">{{ rollout.package_sha256 }}</span></a-descriptions-item
    >
    <a-descriptions-item label="批次设置"
      >首批 {{ rollout.spec.canary_count }} 台，之后每批 {{ rollout.spec.batch_size }} 台</a-descriptions-item
    ><a-descriptions-item label="观察时间">每批 {{ rollout.spec.observation_seconds }} 秒</a-descriptions-item>
    <a-descriptions-item label="执行截止">{{ formatTime(rollout.deadline) }}</a-descriptions-item><a-descriptions-item
      label="档案到期"
      >{{ formatTime(rollout.expires_at) }}</a-descriptions-item
    >
    <a-descriptions-item v-if="rollout.observation_started_at" label="当前观察起点" :span="2">{{
      formatTime(rollout.observation_started_at)
    }}</a-descriptions-item>
    <a-descriptions-item v-if="rollout.stop_reason" label="停止原因" :span="2">{{
      rollout.stop_reason
    }}</a-descriptions-item>
  </a-descriptions>
  <ListTable
    v-if="!target"
    :columns="columns"
    :data-source="rollout.targets ?? []"
    :pagination="tablePagination()"
    row-key="ordinal"
    :scroll="{ x: 1232 }"
    ><template #bodyCell="{ column, record }">
      <template v-if="column.key === 'batch'">{{
        record.batch === 0 ? '首批' : '第 ' + (record.batch + 1) + ' 批'
      }}</template>
      <StatusTag
        v-else-if="column.key === 'state'"
        :tone="statusTone(rolloutTargetTones, record.state)"
        :value="targetStates[record.state]"
      />
      <span v-else-if="column.key === 'note'" :title="targetNote(record)">{{ targetNote(record) }}</span>
      <button v-else-if="column.key === 'action'" type="button" class="record-link" @click="inspect(record.ordinal)">
        验证证据
      </button>
    </template></ListTable
  >
  <a-modal v-if="target" open title="目标验证证据" :width="760" :footer="null" @cancel="target = undefined">
    <a-descriptions bordered :column="1"
      ><a-descriptions-item label="目标探针">{{ target.spec.sensor_id }}</a-descriptions-item
      ><a-descriptions-item label="注册代次"
        ><span class="technical">{{ target.spec.registration_id }}</span></a-descriptions-item
      ><a-descriptions-item label="批准计划"
        >{{ target.plan_id }} · 修订 {{ target.authorized_revision }}</a-descriptions-item
      ><a-descriptions-item label="执行授权修订">{{ target.execution_revision || '尚未启用' }}</a-descriptions-item
      ><a-descriptions-item label="规则修订"
        >{{ target.spec.package_id }} · {{ target.spec.package_revision }}</a-descriptions-item
      ><a-descriptions-item label="正反样本"
        ><span>{{ target.spec.positive_sample_id }}</span
        ><br />{{ target.spec.negative_sample_id }}</a-descriptions-item
      ></a-descriptions
    >
    <ol class="rollout-proof">
      <li v-for="(title, index) in stages" :key="title">
        <span>{{ title }}</span><RouterLink
          v-if="target.run?.tasks[index]"
          :to="{ path: taskPath ?? '/sensors/tasks', query: { task: target.run.tasks[index] } }"
          >查看独立任务</RouterLink
        ><span v-else class="field-hint">尚未提交</span>
      </li>
    </ol>
    <p class="field-hint">
      验证记录绑定该设备和检测配置。发布回执及心跳核对不代表检测准确率、加密可见性或持续大流量性能通过。
    </p>
  </a-modal>
</template>
<style scoped>
.rollout-summary :deep(.ant-descriptions-item-content) {
  overflow-wrap: anywhere;
  word-break: break-word;
}
.record-id {
  display: block;
  margin-top: 4px;
  color: var(--muted);
  overflow-wrap: anywhere;
}
.rollout-proof {
  padding-left: 24px;
  margin: 12px 0;
}
.rollout-proof li {
  padding: 8px 0;
  display: flex;
  gap: 20px;
  flex-wrap: wrap;
}
.rollout-proof li > span:first-child {
  min-width: 110px;
}
</style>
