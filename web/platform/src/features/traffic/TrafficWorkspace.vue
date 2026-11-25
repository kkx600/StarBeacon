<script setup lang="ts">
import { usePageTitle } from '@starbeacon/shared/utils/usePageTitle.ts';
const pageTitle = usePageTitle('流量检索');
import { computed, defineAsyncComponent } from 'vue';
import WorkspaceTabs from '@starbeacon/shared/components/WorkspaceTabs.vue';
import PageHeader from '@starbeacon/shared/components/PageHeader.vue';
import AsyncWorkspaceState from '@starbeacon/shared/components/AsyncWorkspaceState.vue';
import { useWorkspaceView } from '@starbeacon/shared/utils/useWorkspaceView.ts';
import TrafficEvents from './TrafficEvents.vue';
import { session } from '../../session';
const PacketArchiveWorkspace = defineAsyncComponent({
  loader: () => import('@starbeacon/shared/components/PacketArchiveWorkspace.vue'),
  loadingComponent: AsyncWorkspaceState,
  errorComponent: AsyncWorkspaceState,
  delay: 150,
  timeout: 30000,
});
const FullTrafficWorkspace = defineAsyncComponent({
  loader: () => import('./FullTrafficWorkspace.vue'),
  loadingComponent: AsyncWorkspaceState,
  errorComponent: AsyncWorkspaceState,
  delay: 150,
  timeout: 30000,
});
const { view, change } = useWorkspaceView(['events', 'full-traffic', 'archives']);
const views = computed(() => [
  { key: 'events', label: '协议记录' },
  ...(session.current.value?.role === 'admin' ? [{ key: 'full-traffic', label: '全流量回溯' }] : []),
  { key: 'archives', label: '原包归档' },
]);
</script>
<template>
  <WorkspaceTabs :active="view" :items="views" label="流量检索功能" @change="change" />
  <TrafficEvents v-if="view === 'events'" />
  <FullTrafficWorkspace v-else-if="view === 'full-traffic'" />
  <template v-else>
    <PageHeader :title="pageTitle" description="检索和读取探针旁路捕获的实际原包。" />
    <PacketArchiveWorkspace :api="session.api" />
  </template>
</template>
