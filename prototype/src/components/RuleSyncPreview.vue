<script setup lang="ts">
import StatusTag from '../../../web/packages/shared/src/components/StatusTag.vue';
import { statusTerms } from '../../../web/packages/shared/src/terms.ts';
import ListTable from '../../../web/packages/shared/src/components/ListTable.vue';
import HelpNote from './HelpNote.vue';
import { tablePagination } from '../../../web/packages/shared/src/pagination';
import { statusTone } from '../../../web/packages/shared/src/statusTones.ts';
import { useFeedback } from '../../../web/packages/shared/src/composables/useFeedback';
import { computed, shallowRef, watch } from 'vue';
import type { Sensor } from '../../../web/packages/shared/src/types';
import type { PreviewState } from '../models';
import type { RuleSyncChange, RuleSyncPlan } from '../../../web/platform/src/features/rules/sync';
import { syncStates, syncCodes, syncStateTones } from '../../../web/platform/src/features/rules/sync';
import RuleSyncForm from '../../../web/platform/src/features/rules/RuleSyncForm.vue';
import PageHeader from '../../../web/packages/shared/src/components/PageHeader.vue';
import { helpEntries } from '../composables/pageHelp';
import StatePanel from '../../../web/packages/shared/src/components/StatePanel.vue';
import { prototypePath } from '../data/navigation';
const message = useFeedback();
const props = defineProps<{ state: PreviewState }>(),
  emit = defineEmits<{ state: [value: PreviewState] }>();
const at = '2026-10-17T01:00:00Z';
const example: RuleSyncPlan = {
  id: 'sync_example',
  revision: 2,
  spec: {
    name: '办公网规则同步（示例）',
    enabled: true,
    sensor_id: 'sensor_example',
    registration_id: 'registration_example',
    package_id: 'rules_example',
    package_revision: 3,
    positive_sample_id: 'sample_positive',
    negative_sample_id: 'sample_negative',
    interval_seconds: 60,
  },
  created_by: 'admin_example',
  updated_at: at,
  next_at: at,
  processed_revision: 1,
  run: {
    id: 'sync_run_example',
    plan_revision: 2,
    spec: {
      name: '办公网规则同步（示例）',
      enabled: true,
      sensor_id: 'sensor_example',
      registration_id: 'registration_example',
      package_id: 'rules_example',
      package_revision: 3,
      positive_sample_id: 'sample_positive',
      negative_sample_id: 'sample_negative',
      interval_seconds: 60,
    },
    created_by: 'admin_example',
    state: 'positive_replay',
    code: '',
    stage: 1,
    tasks: ['task_validation', 'task_positive', '', ''],
    expected_sha256: 'a'.repeat(64),
    created_at: at,
    expires_at: '2027-04-15T01:00:00Z',
  },
};
const records = shallowRef<RuleSyncPlan[]>([example]),
  editing = shallowRef<RuleSyncPlan | null | undefined>(),
  detail = shallowRef<RuleSyncPlan>();
const sensors = [
  {
    id: 'sensor_example',
    name: '办公网探针（示例）',
    registration_id: 'registration_example',
    active: true,
    status: 'online',
    health: {},
    created_at: at,
    last_seen: at,
  },
] as Sensor[];
const packages = [
  {
    id: 'rules_example',
    name: '办公网检测规则（示例）',
    revision: 3,
    engine_version: '8.0.7',
    sha256: 'b'.repeat(64),
    created_at: at,
  },
];
const items = computed(() => (props.state === 'empty' ? [] : records.value));
const columns = [
  { title: '计划编号', dataIndex: 'id', width: 135, ellipsis: true, className: 'mono' },
  { title: '计划名称', key: 'name', width: 220 },
  { title: '探针编号', dataIndex: ['spec', 'sensor_id'], width: 148, ellipsis: true, className: 'mono' },
  { title: '批准规则', key: 'package', width: 220 },
  { title: '配置状态', key: 'enabled', width: 90 },
  { title: '运行状态', key: 'state', width: 120 },
  { title: '最近更新', key: 'time', width: 162 },
  { title: '操作', key: 'action', width: 125, fixed: 'right' as const },
];
watch(
  () => props.state,
  state => {
    editing.value = state === 'action' ? null : undefined;
    detail.value = state === 'detail' ? records.value[0] : undefined;
  },
  { immediate: true },
);
function save(c: RuleSyncChange) {
  records.value = [
    {
      id: c.id,
      revision: c.expected_revision + 1,
      spec: c.spec,
      created_by: 'admin_example',
      updated_at: at,
      next_at: at,
      processed_revision: 0,
    },
  ];
  editing.value = undefined;
  emit('state', 'data');
  message.success('计划已保存为本地示例，未提交设备任务');
}
</script>
<template>
  <PageHeader
    :help-entries="helpEntries"
    title="规则自动同步"
    description="管理批准规则修订的同步计划，核对各阶段独立任务与实际执行结果。"
    ><router-link :to="{ path: prototypePath('rule-rollouts'), query: { state: 'data' } }"
      ><a-button>分批发布</a-button></router-link
    ><a-button @click="emit('state', 'data')">刷新</a-button
    ><a-button type="primary" @click="editing = null">创建同步计划</a-button></PageHeader
  >
  <HelpNote
    message="本页面为合成示例。计划绑定指定规则修订、样本和探针注册代次，不跟随未批准修订；原型不向真实设备下发任务。"
  />
  <section class="panel">
    <StatePanel
      v-if="['empty', 'error', 'loading'].includes(state)"
      :loading="state === 'loading'"
      :error="state === 'error'"
      empty
      :title="state === 'empty' ? '暂无规则同步计划' : undefined"
      :description="state === 'empty' ? '创建计划前，请导入正反样本并核对探针执行能力。' : undefined"
      :action="state === 'empty' ? '创建同步计划' : '重新加载'"
      @action="editing = null"
      @retry="emit('state', 'data')"
    />
    <ListTable
      v-else
      :columns="columns"
      :data-source="items"
      row-key="id"
      :pagination="tablePagination()"
      :scroll="{ x: 1220 }"
      ><template #bodyCell="{ column, record }"
        ><button
          v-if="column.key === 'name'"
          type="button"
          class="record-link"
          :title="record.spec.name"
          @click="detail = record"
        >
          {{ record.spec.name }}</button
        ><template v-else-if="column.key === 'package'"
          >{{ record.spec.package_id }} · 修订 {{ record.spec.package_revision }}</template
        ><StatusTag
          v-else-if="column.key === 'enabled'"
          :value="record.spec.enabled ? '启用' : '停用'"
          :tone="record.spec.enabled ? statusTerms.启用 : statusTerms.停用"
        /><StatusTag
          v-else-if="column.key === 'state'"
          :value="record.run ? syncStates[record.run.state] : record.processed_revision ? '已过期' : '排队中'"
          :tone="
            record.run
              ? statusTone(syncStateTones, record.run.state)
              : record.processed_revision
                ? statusTerms.已过期
                : statusTerms.排队中
          "
        /><template v-else-if="column.key === 'time'">2026-10-17 09:00:00</template
        ><template v-else-if="column.key === 'action'"
          ><a-button type="link" size="small" @click="detail = record">查看</a-button
          ><a-button type="link" size="small" @click="editing = record">配置</a-button></template
        ></template
      ></ListTable
    >
  </section>
  <RuleSyncForm
    v-if="editing !== undefined"
    :key="editing?.id ?? 'create'"
    :plan="editing"
    :sensors="sensors"
    :packages="packages"
    :busy="false"
    :locked="false"
    error=""
    choices-error=""
    :choices-pending="false"
    @save="save"
    @close="editing = undefined"
  />
  <a-modal v-if="detail" open title="规则同步详情" :footer="null" :width="780" @cancel="detail = undefined"
    ><HelpNote message="执行记录为合成示例，真实引擎的验证与应用状态以设备回执为准。" /><a-descriptions
      bordered
      :column="1"
      ><a-descriptions-item label="计划">{{ detail.spec.name }} · 授权修订 {{ detail.revision }}</a-descriptions-item
      ><a-descriptions-item label="探针">{{ detail.spec.sensor_id }}</a-descriptions-item
      ><a-descriptions-item label="注册代次">{{ detail.spec.registration_id }}</a-descriptions-item
      ><a-descriptions-item label="批准规则"
        >{{ detail.spec.package_id }} · 修订 {{ detail.spec.package_revision }}</a-descriptions-item
      ><a-descriptions-item label="核对周期">{{ detail.spec.interval_seconds }} 秒</a-descriptions-item></a-descriptions
    ><template v-if="detail.run"
      ><p>
        本次批准规则：{{ detail.run.spec.package_id }} · 修订 {{ detail.run.spec.package_revision }}；批准人：{{
          detail.run.created_by
        }}
      </p>
      <p>{{ syncStates[detail.run.state] }} · {{ syncCodes[detail.run.code] ?? '等待独立任务回执' }}</p>
      <ol class="plain-list">
        <li v-for="(label, index) in ['装载检查', '正样本重放', '反样本重放', '规则发布']" :key="label">
          {{ label }}：{{ detail.run.tasks[index] || '尚未提交' }}
        </li>
      </ol>
      <p class="field-hint">
        停用计划停止后续步骤，已经下发的任务仍要单独核对结果。运行档案默认保留 180 天。
      </p></template
    ></a-modal
  >
</template>
