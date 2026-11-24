<script setup lang="ts">
import { computed, h, shallowRef, watch } from 'vue';
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
  SettingOutlined,
  ThunderboltOutlined,
} from '@ant-design/icons-vue';
import { navigationForRole } from './navigation';
import { navigationGroups, navigationWorkspaces, platformScreens } from '@starbeacon/shared/navigation.ts';
import { useRoute, useRouter } from 'vue-router';
import { App as AApp, message as antMessage } from 'ant-design-vue';
import zhCN from 'ant-design-vue/es/locale/zh_CN';
import { appTheme } from '@starbeacon/shared/theme.ts';
import AppShell from '@starbeacon/shared/components/AppShell.vue';
import { session } from './session';
import PasswordDialog from './features/users/PasswordDialog.vue';
const [message, MessageContextHolder] = antMessage.useMessage();
const route = useRoute(),
  router = useRouter();
const passwordOpen = shallowRef(false);
const user = session.current;
const shellKey = computed(() => JSON.stringify([user.value?.tenant_id, user.value?.id, user.value?.role]));
const icons = {
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
};
const sections = computed(() => navigationForRole(user.value?.role === 'admin'));
const items = computed(() =>
  sections.value.map(group => {
    const icon = () => h(icons[group.icon as keyof typeof icons]);
    const children = group.children.map(item => ({
      key: 'workspace:' + item.key,
      label: item.label,
      title: item.available ? item.label : item.label + '（当前版本未提供）',
    }));
    return children.length === 1
      ? { ...children[0]!, icon }
      : { key: 'group:' + group.key, label: group.label, icon, children };
  }),
);
const workspace = computed(() => navigationWorkspaces.find(item => item.id === route.meta.navWorkspace));
const activeWorkspace = computed(() => {
  const item = workspace.value;
  if (!item || (route.meta.admin && user.value?.role !== 'admin')) return;
  return { key: item.id, label: item.title, path: route.path };
});
const assistantPath = computed(
  () => platformScreens.find(screen => screen.id === 'chat' && (!screen.admin || user.value?.role === 'admin'))?.path,
);
const breadcrumbs = computed(() => {
  const group = navigationGroups.find(item => item.id === route.meta.navGroup);
  const item = workspace.value;
  return [
    ...(group ? [{ label: group.title }] : []),
    ...(item ? [{ label: item.title }] : []),
    ...(route.meta.title && route.meta.title !== item?.title ? [{ label: String(route.meta.title) }] : []),
  ].filter((item, index, all) => !index || item.label !== all[index - 1]!.label);
});
function navigate(key: string) {
  const item = sections.value.flatMap(group => group.children).find(item => 'workspace:' + item.key === key);
  void router.push(item?.path ?? key);
}
watch(
  () => route.meta.title,
  title => {
    document.title = (title ? String(title) + ' · ' : '') + '星烽 StarBeacon';
  },
  { immediate: true },
);
watch(session.current, user => {
  if (!user) {
    passwordOpen.value = false;
    if (route.path !== '/login') void router.replace({ path: '/login', query: { redirect: route.fullPath } });
  } else if (route.meta.admin && user.role !== 'admin') {
    passwordOpen.value = false;
    void router.replace('/sensors/list');
  }
});
async function logout() {
  try {
    await session.logout();
    await router.replace('/login');
  } catch (e) {
    message.error(e instanceof Error ? e.message : '退出失败');
  }
}
</script>
<template>
  <a-config-provider :theme="appTheme" :locale="zhCN"
    ><AApp
      ><MessageContextHolder />
      <RouterView v-if="route.path === '/login'" />
      <AppShell
        v-else
        :key="shellKey"
        title="态势感知系统"
        brand-target="/overview/dashboard"
        :username="user?.username ?? ''"
        :current="'workspace:' + String(route.meta.navWorkspace ?? '')"
        :breadcrumbs="breadcrumbs"
        :items="items"
        :active-workspace="activeWorkspace"
        :show-assistant="!!assistantPath"
        allow-password-change
        @assistant="assistantPath && navigate(assistantPath)"
        @password="passwordOpen = true"
        @navigate="navigate"
        @logout="logout"
        ><RouterView :key="route.path"
      /></AppShell>
      <PasswordDialog v-if="passwordOpen" own @close="passwordOpen = false" /> </AApp
  ></a-config-provider>
</template>
