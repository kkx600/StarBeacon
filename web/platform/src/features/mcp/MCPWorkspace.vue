<script setup lang="ts">
import { usePageTitle } from '@starbeacon/shared/utils/usePageTitle.ts';
const pageTitle = usePageTitle('MCP 服务');
import { useFeedback } from '@starbeacon/shared/composables/useFeedback.ts';
import { shallowRef } from 'vue';
import { Modal, Popconfirm, Tabs } from 'ant-design-vue';
import StatePanel from '@starbeacon/shared/components/StatePanel.vue';
import PageHeader from '@starbeacon/shared/components/PageHeader.vue';
import PageHelp from '@starbeacon/shared/components/PageHelp.vue';
import ListTable from '@starbeacon/shared/components/ListTable.vue';
import MetricBar from '@starbeacon/shared/components/MetricBar.vue';
import StatusTag from '@starbeacon/shared/components/StatusTag.vue';
import { tablePagination } from '@starbeacon/shared/pagination.ts';
import { formatTime } from '@starbeacon/shared/types.ts';
import { useMCP } from './useMCP';
import { bindingBadge, scopeNames, type Binding, type BindingChange } from './mcp';
import BindingForm from './BindingForm.vue';
import MCPResourceGuide from './MCPResourceGuide.vue';
const TabPane = Tabs.TabPane;
const message = useFeedback();
const state = useMCP(),
  { items, info, pending, error, busy, actionError } = state;
const editing = shallowRef<Binding | null>(null),
  editorOpen = shallowRef(false),
  toolsOpen = shallowRef(false);
const directoryTab = shallowRef('tools');
const columns = [
  { title: '身份编号', dataIndex: 'id', width: 142, className: 'technical', ellipsis: true },
  { title: '服务身份', dataIndex: 'name', width: 142, ellipsis: true },
  { title: '修订', dataIndex: 'revision', width: 62 },
  { title: '授权主体', dataIndex: 'subject', width: 155, className: 'technical', ellipsis: true },
  { title: 'OAuth 客户端', dataIndex: 'oauth_client_id', width: 158, className: 'technical', ellipsis: true },
  { title: '只读权限', key: 'scopes', width: 160, ellipsis: true },
  { title: '状态', key: 'state', width: 90 },
  { title: '到期时间', key: 'expiry', width: 172 },
  { title: '调用上限', key: 'budget', width: 110 },
  { title: '操作', key: 'actions', fixed: 'right' as const, width: 115 },
];
function scopes(record: Binding) {
  return record.scopes.map(scope => scopeNames[scope] ?? scope).join('、');
}
function edit(record: Binding | null) {
  state.clearActionError();
  editing.value = record;
  editorOpen.value = true;
}
async function save(change: BindingChange) {
  if (await state.save(change)) {
    editorOpen.value = false;
    message.success('服务身份配置已保存');
  }
}
async function remove(record: Binding) {
  if (await state.remove(record)) message.success('服务身份已删除');
}
function openDirectory() {
  directoryTab.value = 'tools';
  toolsOpen.value = true;
}
</script>
<template>
  <PageHeader
    :title="pageTitle"
    description="管理其他 Agent 的只读数据分析接入、租户授权及调用预算。最多可登记 100 个服务身份。"
    :notice="
      info?.enabled
        ? 'HTTP POST · Bearer 认证 · 无持久协议会话。支持协议：' + info.protocol_versions.join('、') + '。'
        : undefined
    "
  >
    <a-button :loading="pending" @click="state.refresh">刷新</a-button>
    <a-button @click="openDirectory">工具与资源</a-button>
    <a-button type="primary" :disabled="pending || busy || !info?.enabled || items.length >= 100" @click="edit(null)"
      >登记服务身份</a-button
    >
  </PageHeader>
  <a-alert v-if="actionError && !editorOpen" type="error" :message="actionError" show-icon class="section-gap" />
  <a-alert
    v-if="!pending && !error && !info?.enabled"
    type="info"
    message="MCP 服务尚未启用。部署管理员需配置 HTTPS 公开来源、OAuth 授权方与受限令牌内省凭据。"
    show-icon
    class="section-gap"
  />
  <section v-if="info?.enabled" class="panel mcp-connection">
    <div>
      <span class="muted">接入地址</span><code>{{ info.resource }}</code>
    </div>
    <div>
      <span class="muted">授权方</span><code>{{ info.issuer }}</code>
    </div>
    <div>
      <span class="muted">资源发现</span><code>{{ info.metadata_url }}</code>
    </div>
  </section>
  <section class="panel table-panel">
    <div class="table-toolbar">
      <h2>MCP 服务身份</h2>
      <MetricBar
        v-if="!pending && !error"
        embedded
        :items="[{ label: '已登记身份', value: items.length, suffix: '/ 100' }]"
      />
    </div>
    <StatePanel
      :loading="pending"
      :error="error"
      :empty="items.length === 0"
      description="暂无服务身份。启用 MCP 后，可登记调用方的主体与客户端，并授予只读权限。"
      @retry="state.refresh"
    >
      <ListTable :columns="columns" :data-source="[...items]" :pagination="tablePagination()" :scroll="{ x: 1306 }">
        <template #bodyCell="{ column, record }">
          <span v-if="column.key === 'scopes'" :title="scopes(record)">{{ scopes(record) }}</span>
          <StatusTag v-else-if="column.key === 'state'" v-bind="bindingBadge(record)" />
          <template v-else-if="column.key === 'expiry'">{{ formatTime(record.expires_at) }}</template>
          <template v-else-if="column.key === 'budget'">{{ record.requests_per_minute }} 次 / 分钟</template>
          <div v-else-if="column.key === 'actions'" class="table-row-actions">
            <a-button type="link" size="small" :disabled="busy || !info?.enabled" @click="edit(record)">配置</a-button>
            <Popconfirm
              title="删除此服务身份？"
              description="该身份的后续调用会被拒绝，已有操作日志仍按保留策略保存。"
              ok-text="删除身份"
              cancel-text="取消"
              :disabled="busy"
              @confirm="remove(record)"
              ><a-button type="link" size="small" danger :disabled="busy">删除</a-button></Popconfirm
            >
          </div>
        </template>
      </ListTable>
    </StatePanel>
  </section>
  <BindingForm
    v-if="editorOpen && info"
    :record="editing"
    :issuer="info.issuer"
    :pending="busy"
    :error="actionError"
    @save="save"
    @close="editorOpen = false"
  />
  <Modal
    v-if="toolsOpen"
    :open="true"
    title="MCP 工具与资源"
    :width="760"
    :footer="null"
    :body-style="{ maxHeight: 'calc(100vh - 240px)', overflowY: 'auto' }"
    @cancel="toolsOpen = false"
  >
    <Tabs v-model:activeKey="directoryTab" :animated="false" destroy-inactive-tab-pane>
      <TabPane key="tools" tab="工具目录">
        <div class="heading-with-help section-gap">
          <h2>工具目录</h2>
          <PageHelp title="工具目录">
            <p>实际可调用的范围以当前令牌发现结果为准。工具只执行有界只读查询，调用结果与错误写入操作日志。</p>
          </PageHelp>
        </div>
        <StatePanel
          :loading="pending"
          :error="error"
          :empty="!info?.tools.length"
          description="尚未取得工具目录，请核对服务部署状态后刷新。"
          @retry="state.refresh"
          ><ul class="mcp-tools">
            <li v-for="tool in info?.tools ?? []" :key="tool.name">
              <strong>{{ tool.title }}</strong><code>{{ tool.name }}</code>
              <p>{{ tool.description }}</p>
              <span class="muted">需要权限：{{ scopeNames[tool.scope] ?? tool.scope }}</span>
            </li>
          </ul></StatePanel
        >
      </TabPane>
      <TabPane key="resources" tab="元数据资源"><MCPResourceGuide /></TabPane>
    </Tabs>
  </Modal>
</template>
<style scoped>
.mcp-connection {
  display: grid;
  gap: var(--related-gap);
  padding: var(--panel-inset);
  margin-bottom: var(--section-gap);
}
.mcp-connection > div {
  display: grid;
  grid-template-columns: 80px minmax(0, 1fr);
  gap: var(--related-gap);
}
.mcp-connection code {
  overflow-wrap: anywhere;
  word-break: break-word;
}
.mcp-tools {
  padding-left: 20px;
}
.mcp-tools li {
  margin-bottom: var(--section-gap);
}
.mcp-tools code {
  display: block;
  color: var(--muted);
  overflow-wrap: anywhere;
}
.mcp-tools p {
  margin: var(--related-gap) 0;
}
</style>
