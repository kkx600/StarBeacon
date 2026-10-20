<script setup lang="ts">
import TaskWorkspace from '../features/sensors/TaskWorkspace.vue'
import {usePageTitle} from '@starbeacon/shared/utils/usePageTitle.ts'
const title=usePageTitle('响应动作')
</script>
<template><header class="page-header"><div><h1>{{title}}</h1><p class="page-description">集中核对限时封禁、租约回读与解除任务，追溯执行位置、目标和独立设备回执。</p></div></header><TaskWorkspace response-only/></template>
