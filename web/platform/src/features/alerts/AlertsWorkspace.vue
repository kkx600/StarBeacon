<script setup lang="ts">
import { shallowRef } from 'vue'
import type { Alert } from '@starbeacon/shared/types.ts'
import StatePanel from '@starbeacon/shared/components/StatePanel.vue'
import AlertFilters from './AlertFilters.vue'
import AlertTable from './AlertTable.vue'
import AlertDetail from './AlertDetail.vue'
import { useAlerts } from './useAlerts'
const {result,pending,error,search,page,refresh} = useAlerts()
const selected = shallowRef<Alert | null>(null)
</script>
<template>
  <header class="page-header"><div><h1>告警管理</h1><p class="page-description">检索已入库的原始检测事件，核对来源、时间和通信元数据。</p></div><a-button :loading="pending" @click="refresh">刷新</a-button></header>
  <AlertFilters :pending="pending" @search="search" />
  <a-alert v-if="result.total > 10000" type="info" message="当前列表最多浏览前 10,000 条，请缩小时间范围或增加检索条件。" show-icon class="section-gap" />
  <section class="panel"><div class="panel-header"><h2>告警列表</h2><span>{{ result.total }} 条</span></div>
    <StatePanel :loading="pending" :error="error" :empty="result.items.length === 0" description="当前条件下没有告警，可调整时间范围或检索条件。" @retry="refresh"><AlertTable :result="result" @view="selected = $event" @page="page" /></StatePanel>
  </section>
  <AlertDetail :alert="selected" @close="selected = null" />
</template>
