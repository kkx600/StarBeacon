<script setup lang="ts">
import { computed, h, watch } from 'vue';
import { useRoute, useRouter } from 'vue-router';
import {
  ApiOutlined,
  AppstoreOutlined,
  ClusterOutlined,
  DashboardOutlined,
  FileProtectOutlined,
  SafetyCertificateOutlined,
} from '@ant-design/icons-vue';
import AppShell, { type ShellWorkspace } from '@starbeacon/shared/components/AppShell.vue';
import PreviewStateMenu from '../components/PreviewStateMenu.vue';
import { collectorPages, collectorDevice } from '../data/collector';
import {
  collectorPrototypeScreens,
  collectorWorkspaces,
  collectorPreviewScreen,
  collectorPreviewWorkspace,
  collectorPreviewDestination,
} from '../data/collectorNavigation';

const route = useRoute();
const router = useRouter();
const screen = computed(() => collectorPreviewScreen(route.path, String(route.params.id ?? ''), route.query));
const current = computed(() => screen.value ?? collectorPages.find(page => page.id === route.params.id));
const workspace = computed(() => collectorPreviewWorkspace(String(route.params.id ?? ''), screen.value));
const icons = { DashboardOutlined, ClusterOutlined, ApiOutlined, FileProtectOutlined, SafetyCertificateOutlined };
const items = collectorWorkspaces.map(item => ({
  key: item.id,
  label: item.title,
  icon: () => h(icons[item.icon]),
}));
const activeWorkspace = computed<ShellWorkspace | undefined>(() => {
  const item = collectorWorkspaces.find(item => item.id === workspace.value);
  if (item) return { key: item.id, label: item.title, path: screen.value?.path ?? route.path };
});
const breadcrumbs = computed(() => [{ label: '采集器管理' }, { label: current.value?.title ?? '运行状态' }]);
watch(
  current,
  page => {
    document.title = `${page?.title ?? '采集器管理'} · 星烽 StarBeacon 采集器`;
  },
  { immediate: true },
);
function navigate(key: string) {
  const target = key.startsWith('/') ? key : collectorPrototypeScreens.find(item => item.workspace === key)?.path;
  if (target) void router.push(collectorPreviewDestination(target, route.query, route.hash));
}
</script>

<template>
  <AppShell
    class="collector-shell"
    title="采集器管理"
    username="本地管理员"
    navigation-label="采集器导航"
    brand-target="/collector/overview/status"
    :current="workspace"
    :breadcrumbs="breadcrumbs"
    :items="items"
    :active-workspace="activeWorkspace"
    @navigate="navigate"
    @logout="router.push('/collector/auth/login')"
  >
    <template #sidebar-top="{ collapsed }">
      <div v-if="!collapsed" class="collector-identity">
        <b>{{ collectorDevice.name }}</b><small>{{ collectorDevice.id }}</small>
        <span>旁路镜像 · {{ collectorDevice.site }}</span>
      </div>
    </template>
    <template #sidebar-footer="{ collapsed }">
      <ApiOutlined /><span v-if="!collapsed">交互原型 · 合成数据</span>
    </template>
    <template #header-before-actions><PreviewStateMenu /></template>
    <template #header-actions>
      <a-button size="small" @click="router.push('/page/sensors')">主控平台</a-button>
      <a-button type="text" aria-label="页面目录" @click="router.push('/catalog')"><AppstoreOutlined /></a-button>
    </template>
    <template #workspace-actions>
      <button type="button" @click="router.push('/catalog')"><AppstoreOutlined aria-hidden="true" />页面目录</button>
    </template>
    <slot />
    <template #footer>星烽 StarBeacon 采集器 <span>合成数据仅用于界面评审</span></template>
  </AppShell>
</template>
