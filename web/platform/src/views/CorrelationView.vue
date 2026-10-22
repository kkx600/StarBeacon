<script setup lang="ts">
import {computed} from 'vue'
import RuleWorkspaceNavigation from '../features/rules/RuleWorkspaceNavigation.vue'
import {useWorkspaceView} from '@starbeacon/shared/utils/useWorkspaceView.ts'
import CorrelationCatalog from '../features/correlation/CorrelationCatalog.vue'
import CorrelationBacktest from '../features/correlation/CorrelationBacktest.vue'
import {session} from '../session'
const {view}=useWorkspaceView(['rules','backtest'])
const identity=computed(()=>{const u=session.current.value;return u?[u.tenant_id,u.id,u.role,u.csrf_token].join(':'):''})
</script>
<template><RuleWorkspaceNavigation :can-manage="session.current.value?.role==='admin'"/><CorrelationBacktest v-if="view==='backtest'&&session.current.value?.role==='admin'" :key="identity+'/backtest'"/><CorrelationCatalog v-else :key="identity+'/rules'"/></template>
