<script setup lang="ts">
import { shallowRef, watch } from 'vue';
import {
  LogoutOutlined,
  MenuFoldOutlined,
  MenuUnfoldOutlined,
  RobotOutlined,
  SafetyCertificateOutlined,
  UserOutlined,
} from '@ant-design/icons-vue';
import { Avatar as AAvatar, Breadcrumb as ABreadcrumb, Dropdown as ADropdown, Menu as AMenu } from 'ant-design-vue';
import NavigationMenu, { type NavigationItem } from './NavigationMenu.vue';

export interface ShellWorkspace {
  key: string;
  label: string;
  path: string;
}

const ABreadcrumbItem = ABreadcrumb.Item;
const AMenuItem = AMenu.Item;
const props = withDefaults(
  defineProps<{
    title: string;
    username: string;
    current: string;
    items: NavigationItem[];
    brandTarget?: string;
    navigationLabel?: string;
    allowPasswordChange?: boolean;
    showAssistant?: boolean;
    breadcrumbs?: { label: string; path?: string }[];
    activeWorkspace?: ShellWorkspace;
    initialWorkspaces?: ShellWorkspace[];
  }>(),
  { navigationLabel: '主导航', initialWorkspaces: () => [] },
);
const emit = defineEmits<{ navigate: [path: string]; logout: []; password: []; assistant: [] }>();
const collapsed = shallowRef(false);
const accountOpen = shallowRef(false);
const workspaceLimit = 5;
const visited = shallowRef(props.initialWorkspaces.slice(-workspaceLimit));

watch(
  () => props.activeWorkspace,
  workspace => {
    if (!workspace) return;
    const existing = visited.value.some(item => item.key === workspace.key);
    visited.value = existing
      ? visited.value.map(item => (item.key === workspace.key ? workspace : item))
      : [...visited.value, workspace].slice(-workspaceLimit);
  },
  { immediate: true },
);
</script>

<template>
  <a-layout class="app-shell" :class="{ 'is-collapsed': collapsed }">
    <a-layout-sider
      class="shell-sidebar"
      :collapsed="collapsed"
      :width="220"
      theme="light"
      collapsible
      :trigger="null"
      :collapsed-width="64"
      :aria-label="navigationLabel"
      @collapse="(value: boolean) => (collapsed = value)"
    >
      <component
        :is="brandTarget ? 'button' : 'div'"
        class="brand"
        :type="brandTarget ? 'button' : undefined"
        :aria-label="brandTarget ? `星烽 StarBeacon · ${title}` : undefined"
        @click="brandTarget && emit('navigate', brandTarget)"
      >
        <span class="brand-symbol" aria-hidden="true"><SafetyCertificateOutlined /></span>
        <span v-if="!collapsed" class="brand-copy"
          ><b>星烽 <span>StarBeacon</span></b
          ><small>{{ title }}</small></span
        >
      </component>
      <slot name="sidebar-top" :collapsed="collapsed" />
      <NavigationMenu
        class="main-menu"
        :current="current"
        :collapsed="collapsed"
        :items="items"
        @navigate="emit('navigate', $event)"
      />
      <div v-if="$slots['sidebar-footer']" class="sidebar-footer">
        <slot name="sidebar-footer" :collapsed="collapsed" />
      </div>
    </a-layout-sider>
    <a-layout class="shell-main">
      <a-layout-header class="app-header">
        <div class="topbar-left">
          <a-button type="text" :aria-label="collapsed ? '展开导航' : '收起导航'" @click="collapsed = !collapsed">
            <MenuUnfoldOutlined v-if="collapsed" /><MenuFoldOutlined v-else />
          </a-button>
          <a-breadcrumb v-if="breadcrumbs?.length" class="shell-breadcrumb" aria-label="当前位置">
            <a-breadcrumb-item v-for="(item, index) in breadcrumbs" :key="index">
              <a-button v-if="item.path" type="link" @click="emit('navigate', item.path)">{{ item.label }}</a-button>
              <span v-else :aria-current="index === breadcrumbs.length - 1 ? 'page' : undefined">{{ item.label }}</span>
            </a-breadcrumb-item>
          </a-breadcrumb>
          <span v-else class="header-title">{{ title }}</span>
        </div>
        <div class="topbar-actions">
          <slot name="header-before-actions" />
          <a-button v-if="showAssistant" class="copilot-entry" @click="emit('assistant')">
            <RobotOutlined aria-hidden="true" />AI 助手
          </a-button>
          <slot name="header-actions" />
          <a-dropdown v-model:open="accountOpen" :trigger="['click']">
            <button
              type="button"
              class="profile-button"
              :aria-label="username ? `账号菜单 · ${username}` : '账号菜单'"
              aria-haspopup="menu"
              :aria-expanded="accountOpen"
              :title="username"
            >
              <a-avatar :size="28"
                ><template #icon><UserOutlined /></template
              ></a-avatar>
              <span v-if="username" class="header-user">{{ username }}</span>
            </button>
            <template #overlay>
              <a-menu class="shell-account-menu" :selectable="false">
                <slot name="account-actions" />
                <a-menu-item v-if="allowPasswordChange" key="password" @click="emit('password')">修改密码</a-menu-item>
                <a-menu-item key="logout" @click="emit('logout')"
                  ><LogoutOutlined aria-hidden="true" /> 退出登录</a-menu-item
                >
              </a-menu>
            </template>
          </a-dropdown>
        </div>
      </a-layout-header>
      <nav v-if="visited.length || $slots['workspace-actions']" class="workspace-tabs" aria-label="已访问工作区">
        <button
          v-for="workspace in visited"
          :key="workspace.key"
          type="button"
          :aria-current="workspace.key === activeWorkspace?.key ? 'page' : undefined"
          @click="emit('navigate', workspace.path)"
        >
          <span v-if="workspace.key === activeWorkspace?.key" class="tab-dot" aria-hidden="true"></span>
          {{ workspace.label }}
        </button>
        <slot name="workspace-actions" />
      </nav>
      <a-layout-content class="app-content content-area"><slot /></a-layout-content>
      <footer v-if="$slots.footer" class="app-footer"><slot name="footer" /></footer>
    </a-layout>
  </a-layout>
</template>

<style scoped>
.app-shell {
  min-width: 1024px;
  min-height: 100vh;
  background: var(--workspace);
}
.shell-sidebar {
  position: sticky;
  top: 0;
  height: 100vh;
  background: var(--surface);
  border-right: 1px solid var(--line);
  z-index: 30;
}
.shell-sidebar :deep(.ant-layout-sider-children) {
  display: flex;
  flex-direction: column;
}
.shell-main {
  min-width: 0;
  background: var(--workspace);
}
.main-menu {
  flex: 1;
  min-height: 0;
  overflow: hidden auto;
  border-inline-end: 0;
  padding: 0 5px;
}
.main-menu :deep(.ant-menu-submenu-title),
.main-menu :deep(.ant-menu-item) {
  height: 41px;
  line-height: 41px;
}
.main-menu :deep(.ant-menu-sub .ant-menu-item) {
  font-size: 13px;
}
.main-menu :deep(.ant-menu-item-selected) {
  background: var(--nav-selected);
  color: var(--link);
}
.is-collapsed .main-menu {
  padding: 0;
  align-content: start;
}
.is-collapsed .brand {
  padding: 15px;
}
.sidebar-footer {
  height: 49px;
  border-top: 1px solid var(--line);
  display: flex;
  gap: var(--related-gap);
  align-items: center;
  padding: 0 23px;
  color: var(--muted);
  font-size: 12px;
  flex-shrink: 0;
}
.is-collapsed .sidebar-footer {
  justify-content: center;
  padding: 0;
}
.app-header {
  height: 56px;
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: var(--field-gap);
  line-height: normal;
  padding: 0 var(--panel-inset);
  background: var(--surface);
  border-bottom: 1px solid var(--line);
  position: sticky;
  top: 0;
  z-index: 15;
}
.topbar-left,
.topbar-actions {
  display: flex;
  align-items: center;
  gap: var(--related-gap);
}
.topbar-left,
.shell-breadcrumb {
  flex: 1;
  min-width: 0;
}
.topbar-actions {
  flex: none;
  white-space: nowrap;
}
.shell-breadcrumb {
  font-size: 12px;
  overflow: hidden;
}
.shell-breadcrumb :deep(ol) {
  flex-wrap: nowrap;
}
.shell-breadcrumb :deep(li) {
  flex: none;
  white-space: nowrap;
}
.shell-breadcrumb :deep(li:last-child),
.header-title,
.header-user {
  min-width: 0;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.shell-breadcrumb :deep(li:last-child) {
  flex: 0 1 auto;
}
.shell-breadcrumb :deep(.ant-btn) {
  height: auto;
  padding: 0;
  font-size: inherit;
}
.header-title {
  color: var(--muted);
}
.profile-button {
  border: 0;
  background: transparent;
  display: flex;
  align-items: center;
  gap: var(--related-gap);
  color: var(--record-text);
  padding: 3px;
  cursor: pointer;
}
.profile-button :deep(.ant-avatar) {
  flex: none;
  background: var(--status-surface);
  color: var(--primary);
}
.header-user {
  max-width: 160px;
  font-size: 13px;
}
.workspace-tabs {
  height: 44px;
  background: var(--surface);
  border-bottom: 1px solid var(--line);
  display: flex;
  align-items: flex-end;
  padding: 0 var(--page-inset);
  gap: var(--label-gap);
  overflow-x: auto;
  position: sticky;
  top: 56px;
  z-index: 14;
  white-space: nowrap;
}
.workspace-tabs > button,
.workspace-tabs > :slotted(button) {
  height: 36px;
  flex: none;
  background: transparent;
  border: 0;
  border-radius: 6px 6px 0 0;
  padding: 0 15px;
  color: var(--muted);
  display: flex;
  align-items: center;
  gap: 7px;
  font-size: 13px;
  cursor: pointer;
}
.workspace-tabs > button:hover,
.workspace-tabs > :slotted(button:hover) {
  background: var(--table-header);
}
.workspace-tabs > button[aria-current='page'],
.workspace-tabs > :slotted(button[aria-current='page']) {
  background: var(--tab-selected);
  color: var(--link);
  box-shadow: inset 0 -2px 0 var(--primary);
}
.tab-dot {
  height: 5px;
  width: 5px;
  background: var(--primary);
  border-radius: 4px;
}
.app-content {
  padding: var(--page-inset);
  min-width: 0;
  max-width: 1920px;
  width: 100%;
  margin: 0 auto;
}
.app-footer {
  min-height: 43px;
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 0 24px;
  color: var(--muted);
  font-size: 12px;
  border-top: 1px solid var(--line);
}
@media (max-width: 1180px) {
  .shell-breadcrumb :deep(li:not(:last-child)) {
    display: none;
  }
  .header-user {
    max-width: 104px;
  }
}
</style>
