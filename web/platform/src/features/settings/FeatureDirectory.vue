<script setup lang="ts">
import { computed, shallowRef } from 'vue';
import { useRouter } from 'vue-router';
import { Select as ASelect } from 'ant-design-vue';
import PageHelp from '@starbeacon/shared/components/PageHelp.vue';
import ListFilters from '@starbeacon/shared/components/ListFilters.vue';
import ListTable from '@starbeacon/shared/components/ListTable.vue';
import StatusTag from '@starbeacon/shared/components/StatusTag.vue';
import { statusTerms } from '@starbeacon/shared/terms.ts';
import {
  navigationGroups,
  navigationWorkspaces,
  platformScreens,
  workspacePath,
} from '@starbeacon/shared/navigation.ts';
defineProps<{ embedded?: boolean }>();
const router = useRouter(),
  keyword = shallowRef(''),
  scope = shallowRef('system');
const rows = computed(() =>
  navigationWorkspaces
    .filter(
      item =>
        item.id !== 'settings' &&
        (scope.value === 'all' || item.group === 'system') &&
        `${item.title}${navigationGroups.find(group => group.id === item.group)?.title}`.includes(keyword.value.trim()),
    )
    .map(item => ({
      ...item,
      groupTitle: navigationGroups.find(group => group.id === item.group)!.title,
      available: platformScreens.some(screen => screen.workspace === item.id),
      path: workspacePath(item),
    })),
);
const columns = [
  { title: '功能编号', dataIndex: 'id', width: 150, className: 'technical', ellipsis: true },
  { title: '功能分组', dataIndex: 'groupTitle', width: 160 },
  { title: '功能名称', dataIndex: 'title', width: 180 },
  { title: '可用范围', key: 'scope' },
  { title: '操作', key: 'action', width: 110, fixed: 'right' as const },
];
</script>
<template>
  <section class="panel table-panel" aria-label="功能目录">
    <header v-if="!embedded" class="table-toolbar">
      <div>
        <h2>功能目录</h2>
        <PageHelp title="功能目录"
          ><p>按名称查找工作区并查看交付范围。进入功能页面可核对权限和实际服务状态。</p></PageHelp
        >
      </div>
    </header>
    <a-form layout="horizontal" :model="{ keyword, scope }">
      <ListFilters :columns="2" label="功能目录筛选" embedded>
        <a-form-item label="功能名称" html-for="settings-keyword">
          <a-input id="settings-keyword" v-model:value="keyword" placeholder="查找设置项" allow-clear />
        </a-form-item>
        <a-form-item label="目录范围" html-for="settings-scope"
          ><a-select
            id="settings-scope"
            v-model:value="scope"
            :options="[
              { value: 'system', label: '系统管理' },
              { value: 'all', label: '全部功能' },
            ]"
        /></a-form-item>
      </ListFilters>
    </a-form>
    <ListTable :columns="columns" :data-source="rows" :scroll="{ x: 792 }"
      ><template #bodyCell="{ column, record }"
        ><StatusTag
          v-if="column.key === 'scope'"
          :value="record.available ? '提供功能入口' : '当前版本未提供'"
          :tone="record.available ? 'info' : statusTerms.未提供"
        />
        <template v-else-if="column.key === 'action'"
          ><a-button type="link" size="small" :disabled="!record.available" @click="router.push(record.path)"
            >进入管理</a-button
          ></template
        ></template
      >
      <template #emptyText>没有匹配的功能，请调整查找条件。</template>
    </ListTable>
  </section>
</template>
