<script setup lang="ts">
import { statusTerms } from '@starbeacon/shared/terms.ts';
import { usePageTitle } from '@starbeacon/shared/utils/usePageTitle.ts';
const pageTitle = usePageTitle('模型配置');
import { useFeedback } from '@starbeacon/shared/composables/useFeedback.ts';
import { computed, shallowRef } from 'vue';
import { Popconfirm } from 'ant-design-vue';
import StatePanel from '@starbeacon/shared/components/StatePanel.vue';
import PageHeader from '@starbeacon/shared/components/PageHeader.vue';
import ListTable from '@starbeacon/shared/components/ListTable.vue';
import MetricBar from '@starbeacon/shared/components/MetricBar.vue';
import StatusTag from '@starbeacon/shared/components/StatusTag.vue';
import { tablePagination } from '@starbeacon/shared/pagination.ts';
import { statusTone } from '@starbeacon/shared/statusTones.ts';
import { useModels } from './useModels';
import { providerNames, checkNames, checkTones, type ModelProvider, type ModelChange } from './models';
import ProviderForm from './ProviderForm.vue';
import CheckDetail from './CheckDetail.vue';
const message = useFeedback();
const state = useModels();
const { items, available, pending, error, busy, actionError } = state;
const editing = shallowRef<ModelProvider | null>(null),
  editorOpen = shallowRef(false),
  selectedID = shallowRef('');
const selected = computed(() => items.value.find(item => item.id === selectedID.value) ?? null);
const columns = [
  { title: '提供方编号', dataIndex: 'id', width: 148, className: 'technical', ellipsis: true },
  { title: '提供方', dataIndex: 'name', width: 150, ellipsis: true },
  { title: '修订', dataIndex: 'revision', width: 65 },
  { title: '生成协议', key: 'kind', width: 166, ellipsis: true },
  { title: '模型标识', dataIndex: 'model', width: 188, className: 'technical', ellipsis: true },
  { title: '状态', key: 'enabled', width: 82 },
  { title: '公网连接', key: 'external', width: 82 },
  { title: '连接验证', key: 'check', width: 135 },
  { title: '操作', key: 'actions', width: 186, fixed: 'right' as const },
];
function edit(record: ModelProvider | null) {
  state.clearActionError();
  editing.value = record;
  editorOpen.value = true;
}
async function save(change: ModelChange) {
  if (await state.save(change)) {
    editorOpen.value = false;
    message.success('模型配置已保存');
  }
}
async function test(record: ModelProvider) {
  const result = await state.test(record);
  if (result) {
    selectedID.value = record.id;
    if (result.state === 'succeeded') message.success('模型连接已验证');
  }
}
</script>
<template>
  <PageHeader
    :title="pageTitle"
    description="管理生成接口、连接范围和调用预算，核对模型连接验证结果。最多可配置 50 个提供方。"
  >
    <a-button :loading="pending" @click="state.refresh">刷新</a-button>
    <a-button type="primary" :disabled="pending || !available || busy || items.length >= 50" @click="edit(null)"
      >创建提供方</a-button
    >
  </PageHeader>
  <a-alert v-if="actionError && !editorOpen" type="error" :message="actionError" show-icon class="section-gap" />
  <a-alert
    v-if="!pending && !available && !error"
    type="info"
    message="模型凭据服务未启用。"
    show-icon
    class="section-gap"
  />
  <section class="panel table-panel">
    <div class="table-toolbar">
      <h2>模型提供方</h2>
      <MetricBar
        v-if="!pending && !error"
        embedded
        :items="[{ label: '已配置提供方', value: items.length, suffix: '/ 50' }]"
      />
    </div>
    <StatePanel
      :loading="pending"
      :error="error"
      :empty="items.length === 0"
      description="暂无模型提供方，可创建配置并验证生成接口连接。"
      @retry="state.refresh"
    >
      <ListTable :columns="columns" :data-source="[...items]" :pagination="tablePagination()" :scroll="{ x: 1202 }">
        <template #bodyCell="{ column, record }">
          <template v-if="column.key === 'kind'">{{ providerNames[record.kind] }}</template>
          <StatusTag
            v-else-if="column.key === 'enabled'"
            :tone="record.enabled ? statusTerms.启用 : statusTerms.停用"
            :value="record.enabled ? '启用' : '停用'"
          />
          <template v-else-if="column.key === 'external'">{{ record.allow_external ? '允许' : '禁止' }}</template>
          <template v-else-if="column.key === 'check'">
            <StatusTag
              v-if="record.check && record.check.provider_revision === record.revision"
              :tone="statusTone(checkTones, record.check.state)"
              :value="checkNames[record.check.state] ?? '其他处理状态'"
            />
            <StatusTag v-else :tone="statusTerms.待验证" value="待验证" />
          </template>
          <div v-else-if="column.key === 'actions'" class="table-row-actions">
            <a-button type="link" size="small" :disabled="busy || !available" @click="edit(record)">配置</a-button>
            <Popconfirm
              title="验证该模型的生成接口连接？"
              description="将发送固定短文本，提供方可能按调用计费。"
              ok-text="开始验证"
              cancel-text="取消"
              :disabled="busy || !available || !record.enabled"
              @confirm="test(record)"
              ><a-button type="link" size="small" :disabled="busy || !available || !record.enabled"
                >连接验证</a-button
              ></Popconfirm
            >
            <a-button type="link" size="small" @click="selectedID = record.id">结果</a-button>
          </div>
        </template>
      </ListTable>
    </StatePanel>
  </section>
  <ProviderForm
    v-if="editorOpen"
    :record="editing"
    :pending="busy"
    :error="actionError"
    @save="save"
    @close="editorOpen = false"
  />
  <CheckDetail :record="selected" @close="selectedID = ''" />
</template>
