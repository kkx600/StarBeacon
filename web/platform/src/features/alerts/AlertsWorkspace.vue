<script setup lang="ts">
import { shallowRef,watch } from 'vue'
import type { Alert } from '@starbeacon/shared/types.ts'
import {formatTime} from '@starbeacon/shared/types.ts'
import StatePanel from '@starbeacon/shared/components/StatePanel.vue'
import AlertFilters from './AlertFilters.vue'
import AlertTable from './AlertTable.vue'
import AlertDetail from './AlertDetail.vue'
import { useAlerts } from './useAlerts'
import {session} from '../../session'
import SavedSearchTools from '../search/SavedSearchTools.vue'
import SearchExportButton from '../search/SearchExportButton.vue'
import type {SavedDefinition,SavedResolution} from '../search/savedSearch'
const props=defineProps<{window?:{start?:string;end?:string}}>()
const {result,pending,error,appliedQuery,inherited,range,definition,search,page,refresh,applyQuery} = useAlerts(props.window)
const selected = shallowRef<Alert | null>(null)
const applied=shallowRef<SavedDefinition>()
function apply(value:SavedResolution){applied.value=value.definition;applyQuery(value.query,value.definition.window.mode==='relative'?value.definition.window.hours:0)}
watch(()=>[session.current.value?.tenant_id,session.current.value?.id,session.current.value?.role].join('/'),()=>{selected.value=null;applied.value=undefined})
</script>
<template>
  <header class="page-header"><div><h1>告警管理</h1><p class="page-description">检索已入库的原始检测事件，核对来源、时间和通信元数据。</p></div><div class="query-toolbar"><SavedSearchTools dataset="alerts" :current="definition" :disabled="pending" @apply="apply"/><SearchExportButton dataset="alerts" :query="appliedQuery" :disabled="pending||!!error"/><a-button :loading="pending" @click="refresh">刷新</a-button></div></header>
  <AlertFilters :key="[session.current.value?.tenant_id,session.current.value?.id,session.current.value?.role].join('/')" :pending="pending" :inherited="inherited" :applied="applied" @search="search" />
  <a-alert v-if="result.total > 10000" type="info" message="当前列表最多浏览前 10,000 条，请缩小时间范围或增加检索条件。" show-icon class="section-gap" />
  <section class="panel"><div class="panel-header"><h2>告警列表</h2><span>{{ result.total }} 条</span></div><p class="muted alert-window">{{formatTime(range.start)}} — {{formatTime(range.end)}}</p>
    <StatePanel :loading="pending" :error="error" :empty="result.items.length === 0" description="当前条件下没有告警，可调整时间范围或检索条件。" @retry="refresh"><AlertTable :result="result" @view="selected = $event" @page="page" /></StatePanel>
  </section>
  <AlertDetail :alert="selected" @close="selected = null" />
</template>
<style scoped>.alert-window{font-size:12px;margin:0 0 8px;overflow-wrap:anywhere}.query-toolbar{display:flex;flex-wrap:wrap;justify-content:flex-end;gap:var(--related-gap,8px)}</style>
