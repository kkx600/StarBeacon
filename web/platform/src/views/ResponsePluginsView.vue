<script setup lang="ts">
import { computed, shallowRef, watch } from 'vue';
import { EditOutlined, PlayCircleOutlined, PlusOutlined } from '@ant-design/icons-vue';
import type { TableColumnType } from 'ant-design-vue';
import ListPager from '@starbeacon/shared/components/ListPager.vue';
import ListTable from '@starbeacon/shared/components/ListTable.vue';
import PageHeader from '@starbeacon/shared/components/PageHeader.vue';
import StatePanel from '@starbeacon/shared/components/StatePanel.vue';
import StatusTag from '@starbeacon/shared/components/StatusTag.vue';
import { entryLabels, pluginEntries, type PluginVersion } from '@starbeacon/shared/responsePlugins.ts';
import { formatTime } from '@starbeacon/shared/types.ts';
import PluginWorkspaceTabs from '../features/plugins/PluginWorkspaceTabs.vue';
import PluginEditor from '../features/plugins/PluginEditor.vue';
import PluginOperationsPanel from '../features/plugins/PluginOperationsPanel.vue';
import { usePluginCatalog } from '../features/plugins/usePluginCatalog';

const { page, cursors, pageSize, loading, error, scope, refresh, move, resize } = usePluginCatalog();
const editor = shallowRef<{ version?: PluginVersion } | null>(null);
const operations = shallowRef<PluginVersion | null>(null);
const columns: TableColumnType<PluginVersion>[] = [
  { title: '编号', dataIndex: 'id', key: 'id', width: 120, ellipsis: true },
  { title: '插件名称', dataIndex: 'name', key: 'name', width: 160, ellipsis: true },
  { title: '形式', key: 'kind', width: 62 },
  { title: '适配设备', dataIndex: 'device', key: 'device', width: 140, ellipsis: true },
  { title: '能力', key: 'entries', width: 188, ellipsis: true },
  { title: '运行采集器', key: 'sensor', width: 136, ellipsis: true },
  { title: '状态', key: 'state', width: 92 },
  { title: '最近执行', key: 'updated', width: 152 },
  { title: '操作', key: 'actions', width: 126, fixed: 'right' },
];
const summary = computed(() => {
  const byPlugin = new Map<string, NonNullable<typeof page.value.deployments>>();
  const executedAt = new Map(page.value.executions?.map(item => [item.plugin_id, item.updated_at]));
  for (const deployment of page.value.deployments ?? []) {
    const values = byPlugin.get(deployment.plugin_id) ?? [];
    values.push(deployment);
    byPlugin.set(deployment.plugin_id, values);
  }
  return new Map(
    page.value.items.map(({ id }) => {
      const deployments = byPlugin.get(id) ?? [];
      const active = deployments.filter(d => d.version > 0);
      const failed = active.some(d => d.unavailable);
      const label = failed ? '设备异常' : active.length ? '启用' : deployments.length ? '停用' : '草稿';
      const tone = failed ? 'warning' : active.length ? 'success' : 'neutral';
      const time = executedAt.get(id);
      return [
        id,
        { label, tone, sensors: active.map(d => d.sensor_name).join('、'), time: time ? formatTime(time) : '—' },
      ] as const;
    }),
  );
});
function saved() {
  editor.value = null;
  void refresh();
}
watch(scope, () => {
  editor.value = null;
  operations.value = null;
});
</script>

<template>
  <PluginWorkspaceTabs active="plugins" />
  <PageHeader title="联动插件" description="插件通过模拟、真实设备只读和能力验收后，可签名下发到指定采集器。">
    <a-button :loading="loading" @click="refresh">刷新</a-button>
    <a-button type="primary" @click="editor = {}"><PlusOutlined /> 新建插件</a-button>
  </PageHeader>
  <section class="panel table-panel">
    <StatePanel v-if="error" :error="error" title="联动插件读取失败" @retry="refresh" />
    <ListTable v-else :columns="columns" :data-source="page.items" :loading="loading" :scroll="{ x: 1176 }">
      <template #bodyCell="{ column, record }">
        <code v-if="column.key === 'id'" :title="record.id">{{ record.id }}</code>
        <template v-else-if="column.key === 'kind'">{{ record.kind === 'template' ? '模板' : '脚本' }}</template>
        <span
          v-else-if="column.key === 'entries'"
          :title="
            pluginEntries(record)
              .map(e => entryLabels[e])
              .join('、')
          "
        >
          {{
            pluginEntries(record)
              .map(e => entryLabels[e])
              .join('、')
          }}
        </span>
        <span v-else-if="column.key === 'sensor'" :title="summary.get(record.id)?.sensors">{{
          summary.get(record.id)?.sensors || '—'
        }}</span>
        <StatusTag
          v-else-if="column.key === 'state'"
          :value="summary.get(record.id)?.label ?? '草稿'"
          :tone="summary.get(record.id)?.tone ?? 'neutral'"
        />
        <span v-else-if="column.key === 'updated'">{{ summary.get(record.id)?.time }}</span>
        <a-space v-else-if="column.key === 'actions'" :size="4">
          <a-button type="link" size="small" @click="editor = { version: record }"><EditOutlined /> 编辑</a-button>
          <a-button type="link" size="small" @click="operations = record"><PlayCircleOutlined /> 试运行</a-button>
        </a-space>
      </template>
      <template #emptyText><StatePanel empty title="暂无联动插件" action="新建插件" @action="editor = {}" /></template>
    </ListTable>
    <ListPager
      mode="cursor"
      :page="cursors.length"
      :page-size="pageSize"
      :count="page.items.length"
      :has-previous="cursors.length > 1"
      :has-next="!!page.next_after"
      :disabled="loading || !!error"
      @previous="move(false)"
      @next="move(true)"
      @change="resize"
    />
  </section>
  <PluginEditor v-if="editor" :version="editor.version" @close="editor = null" @saved="saved" />
  <PluginOperationsPanel v-if="operations" :version="operations" @close="operations = null" @changed="refresh" />
</template>
