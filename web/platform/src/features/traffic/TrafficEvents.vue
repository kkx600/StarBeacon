<script setup lang="ts">
import {shallowRef,watch} from 'vue'
import StatePanel from '@starbeacon/shared/components/StatePanel.vue'
import {formatTime} from '@starbeacon/shared/types.ts'
import TrafficFilters from './TrafficFilters.vue'
import TrafficTable from './TrafficTable.vue'
import TrafficDetail from './TrafficDetail.vue'
import {useTraffic} from './useTraffic'
import type {TrafficQuery,TrafficRecord} from './traffic'
import {session} from '../../session'
import SavedSearchTools from '../search/SavedSearchTools.vue'
import SearchExportButton from '../search/SearchExportButton.vue'
import type {SavedDefinition,SavedResolution} from '../search/savedSearch'
const {result,pending,error,appliedQuery,range,definition,fixed,search,page,refresh,applyQuery}=useTraffic(),selected=shallowRef<TrafficRecord|null>(null),applied=shallowRef<SavedDefinition>()
function apply(value:SavedResolution){applied.value=value.definition;applyQuery(value.query as TrafficQuery,value.definition.window.mode==='absolute'?0:value.definition.window.hours)}
watch(()=>[session.current.value?.tenant_id,session.current.value?.id,session.current.value?.role].join('/'),()=>{selected.value=null;applied.value=undefined})
</script>
<template>
 <div class="traffic-toolbar"><SavedSearchTools dataset="context" :current="definition" :disabled="pending" @apply="apply"/><SearchExportButton dataset="context" :query="appliedQuery" :disabled="pending||!!error"/><a-button :loading="pending" @click="refresh">刷新</a-button></div>
 <TrafficFilters :key="[session.current.value?.tenant_id,session.current.value?.id,session.current.value?.role].join('/')" :pending="pending" :applied="applied" :fixed="fixed" @search="search"/>
 <a-alert v-if="result.total>10000" type="info" message="当前列表最多浏览前 10,000 条，请缩小时间范围或增加检索条件。" show-icon class="section-gap"/>
 <section class="panel"><div class="panel-header"><h2>流量记录</h2><span>{{result.total.toLocaleString('zh-CN')}} 条</span></div><p v-if="range" class="muted traffic-window">{{formatTime(range.start)}} — {{formatTime(range.end)}} · 记录数不等于独立会话数或数据包数</p>
 <StatePanel :loading="pending" :error="error" :empty="!result.items.length" description="当前条件下没有协议记录。请核对探针采集状态、协议日志配置、时间范围和检索条件。" @retry="refresh"><TrafficTable :result="result" @view="selected=$event" @page="page"/></StatePanel></section>
 <TrafficDetail :record="selected" @close="selected=null"/>
</template>
<style scoped>.traffic-toolbar{display:flex;justify-content:flex-end;gap:8px;flex-wrap:wrap;margin-bottom:var(--section-gap)}.traffic-window{font-size:12px;margin:0 0 8px;overflow-wrap:anywhere}</style>
