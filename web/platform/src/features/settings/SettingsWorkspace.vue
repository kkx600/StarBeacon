<script setup lang="ts">
import { computed } from 'vue';
import { RouterLink, useRoute } from 'vue-router';
import { AppstoreOutlined, TeamOutlined } from '@ant-design/icons-vue';
import PageHeader from '@starbeacon/shared/components/PageHeader.vue';
import UsersWorkspace from '../users/UsersWorkspace.vue';
import FeatureDirectory from './FeatureDirectory.vue';

const route = useRoute();
const sections = [
  { key: 'users', title: '用户管理', to: '/system/settings/users', icon: TeamOutlined },
  {
    key: 'features',
    title: '功能目录',
    to: { path: '/system/settings', query: { section: 'features' } },
    icon: AppstoreOutlined,
  },
];
const section = computed(() =>
  route.meta.workspaceView !== 'users' && route.query.section === 'features' ? 'features' : 'users',
);
</script>

<template>
  <PageHeader title="系统设置" description="管理本租户的用户账号，查找当前版本的功能入口。" />
  <div class="settings-layout">
    <nav class="panel settings-nav" aria-label="设置分类">
      <RouterLink v-for="item in sections" :key="item.key" :to="item.to" custom v-slot="{ href, navigate }">
        <a :href="href" :aria-current="section === item.key ? 'page' : undefined" @click="navigate">
          <component :is="item.icon" aria-hidden="true" />
          {{ item.title }}
        </a>
      </RouterLink>
    </nav>
    <section class="settings-section" aria-label="当前设置分类">
      <UsersWorkspace v-if="section === 'users'" />
      <FeatureDirectory v-else />
    </section>
  </div>
</template>

<style scoped>
.settings-layout {
  display: grid;
  grid-template-columns: 184px minmax(0, 1fr);
  align-items: start;
  gap: var(--section-gap);
}
.settings-nav {
  display: flex;
  flex-direction: column;
  gap: var(--label-gap);
  padding: var(--related-gap);
  margin-bottom: 0;
}
.settings-nav a {
  display: flex;
  align-items: center;
  gap: var(--related-gap);
  min-height: 38px;
  padding: 0 var(--field-gap);
  border-radius: 6px;
  color: var(--text);
  font-size: 14px;
}
.settings-nav a:hover {
  background: var(--row-hover);
}
.settings-nav a[aria-current='page'] {
  background: var(--progress-surface);
  color: var(--link);
  font-weight: 600;
}
.settings-section {
  min-width: 0;
}
@media (max-width: 1180px) {
  .settings-layout {
    grid-template-columns: 146px minmax(0, 1fr);
  }
}
@media (max-width: 670px) {
  .settings-layout {
    grid-template-columns: minmax(0, 1fr);
  }
  .settings-nav {
    flex-direction: row;
    flex-wrap: wrap;
  }
}
</style>
