<script setup lang="ts">
import ModelsWorkspace from '../features/models/ModelsWorkspace.vue'
import MCPWorkspace from '../features/mcp/MCPWorkspace.vue'
import DecisionPoliciesWorkspace from '../features/decisions/DecisionPoliciesWorkspace.vue'
import DecisionEvaluationsWorkspace from '../features/decisions/DecisionEvaluationsWorkspace.vue'
import WorkspaceTabs from '@starbeacon/shared/components/WorkspaceTabs.vue'
import {useWorkspaceView} from '@starbeacon/shared/utils/useWorkspaceView.ts'
const {view,change}=useWorkspaceView(['providers','policies','evaluations','mcp'])
</script>
<template><WorkspaceTabs :active="view" :items="[{key:'providers',label:'模型提供方'},{key:'policies',label:'决策策略'},{key:'evaluations',label:'评估记录'},{key:'mcp',label:'MCP 服务'}]" label="模型配置功能" @change="change" /><ModelsWorkspace v-if="view==='providers'" /><DecisionPoliciesWorkspace v-else-if="view==='policies'" /><DecisionEvaluationsWorkspace v-else-if="view==='evaluations'" /><MCPWorkspace v-else /></template>
