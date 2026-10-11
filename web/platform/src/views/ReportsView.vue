<script setup lang="ts">
import ReportsWorkspace from '../features/analysis/ReportsWorkspace.vue'
import ReportPlansWorkspace from '../features/analysis/ReportPlansWorkspace.vue'
import WorkspaceTabs from '@starbeacon/shared/components/WorkspaceTabs.vue'
import {useWorkspaceView} from '@starbeacon/shared/utils/useWorkspaceView.ts'
const {view,change}=useWorkspaceView(['records','plans'])
</script>
<template><WorkspaceTabs :active="view" :items="[{key:'records',label:'报告记录'},{key:'plans',label:'报告计划'}]" label="报告中心功能" @change="change"/><ReportsWorkspace v-if="view==='records'"/><ReportPlansWorkspace v-else/></template>
