<script setup lang="ts">
import { usePageTitle } from '@starbeacon/shared/utils/usePageTitle.ts';
const pageTitle = usePageTitle('资产管理');
import { computed } from 'vue';
import WorkspaceTabs from '@starbeacon/shared/components/WorkspaceTabs.vue';
import PageHeader from '@starbeacon/shared/components/PageHeader.vue';
import { useWorkspaceView } from '@starbeacon/shared/utils/useWorkspaceView.ts';
import { session } from '../../session';
import InventoryCatalog from './InventoryCatalog.vue';
import DiscoveryWorkspace from './DiscoveryWorkspace.vue';
import { inventoryNames, type InventoryKind } from './inventory';
const editable = computed(() => session.current.value?.role === 'admin');
const identity = computed(() => {
  const user = session.current.value;
  return user ? `${user.tenant_id}:${user.id}:${user.role}:${user.csrf_token}` : '';
});
const { view, change } = useWorkspaceView(['assets', 'groups', 'networks', 'discovery']);
const items = computed(() => [
  ...Object.entries(inventoryNames).map(([key, label]) => ({ key, label })),
  ...(editable.value ? [{ key: 'discovery', label: '被动发现' }] : []),
]);
</script>
<template>
  <WorkspaceTabs :active="view" :items="items" label="资产管理视图" @change="change" />
  <template v-if="view === 'discovery'">
    <PageHeader
      :title="pageTitle"
      description="按探针与网段核对流量地址观测，确认身份后登记资产。"
      notice="按已有流记录发现地址，源、目的方向分别计数。结果仅覆盖可检索的流记录，不代表设备数或独立会话数。" />
    <DiscoveryWorkspace v-if="editable" :key="identity" /><a-alert
      v-else
      type="warning"
      show-icon
      message="被动发现查询需要管理员权限。"
  /></template>
  <InventoryCatalog v-else :key="identity" :kind="view as InventoryKind" />
</template>
