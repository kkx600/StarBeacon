<script setup lang="ts">
import { RouterLink } from 'vue-router';
import TaskWorkspace from '../features/sensors/TaskWorkspace.vue';
import { usePageTitle } from '@starbeacon/shared/utils/usePageTitle.ts';
import PageHeader from '@starbeacon/shared/components/PageHeader.vue';
const title = usePageTitle('响应动作');
</script>
<template>
  <PageHeader :title="title" description="集中核对限时封禁、租约回读与解除任务，追溯执行位置、目标和独立设备回执。">
    <RouterLink to="/response/gateway-blocks">网关阻断</RouterLink>
  </PageHeader>
  <TaskWorkspace response-only />
</template>
