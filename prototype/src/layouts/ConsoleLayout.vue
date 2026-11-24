<script setup lang="ts">
import { computed, h, ref, watch, type Component } from 'vue';
import { useRoute, useRouter } from 'vue-router';
import {
  AlertOutlined,
  ApiOutlined,
  BarChartOutlined,
  BellOutlined,
  ClusterOutlined,
  DashboardOutlined,
  FileProtectOutlined,
  RadarChartOutlined,
  RobotOutlined,
  SafetyCertificateOutlined,
  SearchOutlined,
  SettingOutlined,
  ThunderboltOutlined,
  UserOutlined,
  AppstoreOutlined,
} from '@ant-design/icons-vue';
import { groups, pageById, pages } from '../data/catalog';
import { platformScreens } from '../../../web/packages/shared/src/navigation';
import {
  workspaces,
  workspaceById,
  workspaceForPage,
  workspaceTitleForPage,
  pageIdForRoute,
  prototypePath,
} from '../data/navigation';
import AppShell, { type ShellWorkspace } from '@starbeacon/shared/components/AppShell.vue';
import PreviewStateMenu from '../components/PreviewStateMenu.vue';
import CopilotDrawer from '../components/CopilotDrawer.vue';

const route = useRoute();
const router = useRouter();
const copilotOpen = ref(false);
const tenant = ref('总部安全中心');
const searchOpen = ref(false);
const search = ref('');
const noticesOpen = ref(false);
const read = ref(false);
const iconMap = {
  AlertOutlined,
  ApiOutlined,
  BarChartOutlined,
  BellOutlined,
  ClusterOutlined,
  DashboardOutlined,
  FileProtectOutlined,
  RadarChartOutlined,
  RobotOutlined,
  SafetyCertificateOutlined,
  SettingOutlined,
  ThunderboltOutlined,
} as Record<string, Component>;
const pageId = computed(() => pageIdForRoute(route));
const current = computed(() => pageById.get(pageId.value));
const title = computed(() => current.value?.title ?? (route.path === '/catalog' ? '页面目录' : '访问状态'));
const groupTitle = computed(() => groups.find(group => group.id === current.value?.group)?.title ?? '星烽 StarBeacon');
const workspace = computed(() => workspaceForPage.get(pageId.value));
const breadcrumbs = computed(() =>
  [groupTitle.value, workspace.value?.title, title.value]
    .filter((title, index, titles): title is string => !!title && title !== titles[index - 1])
    .map(label => ({ label })),
);
const items = groups.map(group => {
  const icon = () => h(iconMap[group.icon]!);
  const children = workspaces
    .filter(item => item.group === group.id)
    .map(item => ({
      key: `workspace:${item.id}`,
      label: item.title,
    }));
  return children.length === 1
    ? { ...children[0]!, icon }
    : { key: `group:${group.id}`, label: group.title, icon, children };
});
const lastViews = new Map<string, string>();
const activeWorkspace = computed<ShellWorkspace | undefined>(() => {
  const item = workspace.value;
  if (item) return { key: item.id, label: item.title, path: prototypePath(pageId.value) };
});
const initialWorkspaces = ['overview', 'alerts', 'search'].flatMap(id => {
  const item = workspaceById.get(id);
  return item ? [{ key: item.id, label: item.title, path: defaultWorkspacePath(item) }] : [];
});
watch(
  activeWorkspace,
  item => {
    if (item) lastViews.set(item.key, item.path);
  },
  { immediate: true },
);
watch(
  title,
  value => {
    document.title = `${value} · 星烽 StarBeacon`;
  },
  { immediate: true },
);
const results = computed(() =>
  pages.filter(p => `${p.title}${p.description}`.includes(search.value.trim())).slice(0, 20),
);
function defaultWorkspacePath(item: (typeof workspaces)[number]) {
  return prototypePath(platformScreens.find(screen => screen.workspace === item.id)?.id ?? item.pages[0]!);
}
function navigate(path: string) {
  if (path.startsWith('workspace:')) {
    const item = workspaceById.get(path.slice('workspace:'.length));
    if (!item) return;
    path = lastViews.get(item.id) ?? defaultWorkspacePath(item);
  }
  void router.push(path);
  searchOpen.value = false;
}
</script>

<template>
  <AppShell
    title="态势感知系统"
    username="陈宁"
    :current="`workspace:${workspace?.id ?? pageId}`"
    :brand-target="prototypePath('overview')"
    :breadcrumbs="breadcrumbs"
    :items="items"
    :active-workspace="activeWorkspace"
    :initial-workspaces="initialWorkspaces"
    show-assistant
    @assistant="copilotOpen = true"
    @navigate="navigate"
    @logout="router.push('/auth/login')"
  >
    <template #sidebar-top="{ collapsed }">
      <div v-if="!collapsed" class="nav-section-label">安全运营</div>
    </template>
    <template #sidebar-footer="{ collapsed }">
      <span class="status-dot success" aria-hidden="true"></span><span v-if="!collapsed">交互原型 · 合成数据</span>
    </template>
    <template #header-before-actions>
      <PreviewStateMenu v-if="current" />
      <a-select
        v-model:value="tenant"
        aria-label="当前租户"
        class="tenant-select"
        :options="['总部安全中心', '研发事业部', '集团审计组织'].map(value => ({ value, label: value }))"
      />
    </template>
    <template #header-actions>
      <a-tooltip title="搜索页面"
        ><a-button type="text" aria-label="搜索页面" @click="searchOpen = true"><SearchOutlined /></a-button
      ></a-tooltip>
      <a-tooltip title="页面目录"
        ><a-button type="text" aria-label="页面目录" @click="router.push('/catalog')"><AppstoreOutlined /></a-button
      ></a-tooltip>
      <a-popover v-model:open="noticesOpen" trigger="click" placement="bottomRight" title="通知中心">
        <template #content
          ><div class="notice-popover">
            <p>
              <b>{{ read ? '暂无未读通知' : '3 条未读通知' }}</b><a-button type="link" size="small" @click="read = true"
                >全部标记已读</a-button
              >
            </p>
            <div class="notice-item">
              <span class="status-dot warning"></span>
              <div>高危告警等待研判<small>总部网络域 · 3 分钟前</small></div>
            </div>
            <div class="notice-item">
              <span class="status-dot warning"></span>
              <div>响应动作结果未知<small>需要回读设备配置</small></div>
            </div>
            <div class="notice-item">
              <span class="status-dot success"></span>
              <div>安全日报等待审核<small>统计窗口 2026-09-29</small></div>
            </div>
            <a-button
              block
              @click="
                navigate(prototypePath('delivery-logs'));
                noticesOpen = false;
              "
              >查看推送日志</a-button
            >
          </div></template
        >
        <a-button type="text" aria-label="查看通知"
          ><a-badge :dot="!read"><BellOutlined /></a-badge
        ></a-button>
      </a-popover>
    </template>
    <template #account-actions>
      <a-menu-item key="account" @click="navigate(prototypePath('my-account'))">
        <UserOutlined aria-hidden="true" /> 个人设置
      </a-menu-item>
    </template>
    <template #workspace-actions>
      <button
        type="button"
        :aria-current="route.path === '/catalog' ? 'page' : undefined"
        @click="navigate('/catalog')"
      >
        <AppstoreOutlined aria-hidden="true" />页面目录
      </button>
    </template>
    <slot />
    <template #footer>星烽 StarBeacon <span>合成数据仅用于界面评审</span></template>
  </AppShell>
  <CopilotDrawer v-model:open="copilotOpen" :context="title" />
  <a-modal v-model:open="searchOpen" title="搜索页面" :footer="null" :width="650"
    ><a-input v-model:value="search" placeholder="输入功能或页面名称" allow-clear autofocus
      ><template #prefix><SearchOutlined /></template
    ></a-input>
    <div class="page-search-results">
      <button v-for="result in results" :key="result.id" @click="navigate(prototypePath(result.id))">
        <div>
          <b>{{ result.title }}</b><small>{{ result.description }}</small>
        </div>
        <span>{{ workspaceTitleForPage(result.id) }}</span></button
      ><a-empty v-if="!results.length" description="没有匹配的页面，请尝试其他关键词。" /></div
  ></a-modal>
</template>
