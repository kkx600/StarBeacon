<script setup lang="ts">
import {onMounted,onScopeDispose,reactive,shallowRef,watch} from 'vue'
import StatePanel from '@starbeacon/shared/components/StatePanel.vue'
import SyslogSourceFilters from '@starbeacon/shared/components/SyslogSourceFilters.vue'
import SyslogSources from '@starbeacon/shared/components/SyslogSources.vue'
import {emptySourceQuery,sourceQuery,readSourcePage,type SyslogSource} from '@starbeacon/shared/syslog.ts'
import {session} from '../session'
const filters=reactive(emptySourceQuery()),applied=shallowRef(emptySourceQuery()),items=shallowRef<SyslogSource[]>([]),pending=shallowRef(false),error=shallowRef(''),filterError=shallowRef(''),cursors=shallowRef(['']),nextCursor=shallowRef('')
let controller:AbortController|undefined,stopped=false
async function refresh(){if(stopped)return;controller?.abort();const current=new AbortController();controller=current;pending.value=true
 try{const q={...applied.value,cursor:cursors.value.at(-1)??''},result=readSourcePage(await session.api.request('/syslog/sources?'+new URLSearchParams(Object.entries(q).map(([k,v])=>[k,String(v)])),{signal:current.signal}),q);if(current.signal.aborted)return;items.value=result.items;nextCursor.value=result.next_cursor;error.value=''}catch(cause){if(!current.signal.aborted)error.value=(cause as Error).message}finally{if(controller===current)pending.value=false}}
function search(){try{applied.value=sourceQuery(filters);filterError.value='';items.value=[];nextCursor.value='';cursors.value=[''];void refresh()}catch(cause){filterError.value=(cause as Error).message}}
function reset(){Object.assign(filters,emptySourceQuery());search()}
function page(next:boolean){if(pending.value||next&&!nextCursor.value||!next&&cursors.value.length<=1)return;cursors.value=next?[...cursors.value,nextCursor.value]:cursors.value.slice(0,-1);items.value=[];nextCursor.value='';void refresh()}
watch(()=>[session.current.value?.id,session.current.value?.tenant_id,session.current.value?.role],()=>{controller?.abort();items.value=[];Object.assign(filters,emptySourceQuery());applied.value=emptySourceQuery();cursors.value=[''];nextCursor.value='';if(session.current.value?.role==='admin')void refresh()})
onMounted(()=>{if(session.current.value?.role==='admin')void refresh()});onScopeDispose(()=>{stopped=true;controller?.abort()})
</script>
<template><header class="page-header"><div><h1>Syslog 接收</h1><p class="page-description">核对采集器的固定日志来源、接收状态与持久缓冲，不以日志正文声明设备或租户身份。</p></div><a-button :loading="pending" @click="refresh">刷新来源</a-button></header><SyslogSourceFilters :model="filters" :pending="pending" @search="search" @reset="reset"/><a-alert v-if="filterError" type="error" show-icon :message="filterError" class="section-gap"/><a-alert type="info" show-icon message="TLS 来源校验客户端证书与指纹；TCP、UDP 来源使用明确授权的网段限制。来源配置由采集器私有文件管理，配置内容与监听地址不通过心跳公开。" class="section-gap"/><section class="panel"><div class="panel-header"><h2>日志来源</h2><span>当前 {{items.length}} 项</span></div><div v-if="error&&items.length" class="panel-body"><a-alert type="warning" show-icon message="来源更新失败，当前显示上次成功读取的目录" :description="error"/></div><StatePanel :loading="pending&&!items.length" :error="items.length?undefined:error" :empty="!items.length" description="当前条件下没有 Syslog 来源。请调整筛选，或配置采集器来源文件后核对心跳。" @retry="refresh"><SyslogSources :items="items"/></StatePanel><div class="source-pagination"><a-button :disabled="pending||cursors.length<=1" @click="page(false)">上一页</a-button><span>第 {{cursors.length}} 页</span><a-button :disabled="pending||!nextCursor||!!error" @click="page(true)">下一页</a-button></div></section></template>
<style scoped>.source-pagination{display:flex;justify-content:flex-end;align-items:center;flex-wrap:wrap;gap:var(--related-gap);padding:var(--panel-inset)}</style>
