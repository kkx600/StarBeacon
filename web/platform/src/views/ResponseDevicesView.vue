<script setup lang="ts">
import {onMounted,onScopeDispose,reactive,shallowRef,watch} from 'vue'
import {useRouter} from 'vue-router'
import {emptyDeviceQuery,deviceQuery,readDevicePage,usableDevice,type ResponseDevice,type DeviceQuery} from '@starbeacon/shared/responseDevices.ts'
import type {Sensor} from '@starbeacon/shared/types.ts'
import StatePanel from '@starbeacon/shared/components/StatePanel.vue'
import ResponseDeviceFilters from '@starbeacon/shared/components/ResponseDeviceFilters.vue'
import ResponseDeviceTable from '@starbeacon/shared/components/ResponseDeviceTable.vue'
import ResponseDeviceDetail from '@starbeacon/shared/components/ResponseDeviceDetail.vue'
import ResponseDialog from '../features/sensors/ResponseDialog.vue'
import {session} from '../session'
const router=useRouter(),filters=reactive(emptyDeviceQuery()),applied=shallowRef<DeviceQuery>(emptyDeviceQuery())
const items=shallowRef<ResponseDevice[]>([]),pending=shallowRef(false),error=shallowRef(''),filterError=shallowRef(''),observedAt=shallowRef(''),cursors=shallowRef(['']),nextCursor=shallowRef(''),selected=shallowRef<ResponseDevice|null>(null),responseDevice=shallowRef<ResponseDevice|null>(null),responseSensor=shallowRef<Sensor|null>(null)
let controller:AbortController|undefined,stopped=false
async function refresh(){if(stopped)return;controller?.abort();const current=new AbortController();controller=current;pending.value=true
 try{const q={...applied.value,cursor:cursors.value.at(-1)??''},page=await readDevicePage(await session.api.request('/response-connectors?'+new URLSearchParams(Object.entries(q).map(([key,value])=>[key,String(value)])),{signal:current.signal}),q)
  if(current.signal.aborted)return;items.value=page.items;nextCursor.value=page.next_cursor;observedAt.value=page.observed_at;error.value='';if(selected.value)selected.value=page.items.find(v=>v.sensor_id===selected.value?.sensor_id&&v.connector_id===selected.value?.connector_id)??null
 }catch(cause){if(!current.signal.aborted)error.value=cause instanceof Error?cause.message:'联动设备读取失败'}finally{if(controller===current)pending.value=false}
}
function search(){try{applied.value=deviceQuery(filters);filterError.value='';items.value=[];selected.value=null;cursors.value=[''];nextCursor.value='';void refresh()}catch(cause){filterError.value=(cause as Error).message}}
function reset(){Object.assign(filters,emptyDeviceQuery());search()}
function page(next:boolean){if(pending.value||next&&!nextCursor.value||!next&&cursors.value.length<=1)return;cursors.value=next?[...cursors.value,nextCursor.value]:cursors.value.slice(0,-1);items.value=[];selected.value=null;nextCursor.value='';void refresh()}
function actions(v:ResponseDevice){void router.push({path:'/response/actions',query:{sensor_id:v.sensor_id,device_id:v.device_id}})}
function respond(v:ResponseDevice){if(!usableDevice(v)||session.current.value?.role!=='admin')return;selected.value=null;responseDevice.value=v;responseSensor.value={id:v.sensor_id,name:v.sensor_name,registration_id:v.registration_id,active:true,status:'online',last_seen:v.last_seen,created_at:'',health:{}} as Sensor}
function closeResponse(){responseSensor.value=null;responseDevice.value=null}
function submitted(id:string){const target=responseDevice.value;closeResponse();if(target)void router.push({path:'/response/actions',query:{sensor_id:target.sensor_id,device_id:target.device_id,task:id}})}
watch(()=>[session.current.value?.tenant_id,session.current.value?.id,session.current.value?.role],()=>{controller?.abort();closeResponse();selected.value=null;items.value=[];Object.assign(filters,emptyDeviceQuery());applied.value=emptyDeviceQuery();cursors.value=[''];nextCursor.value='';error.value='';filterError.value='';if(session.current.value?.role==='admin')void refresh()})
onMounted(()=>{if(session.current.value?.role==='admin')void refresh()});onScopeDispose(()=>{stopped=true;controller?.abort()})
</script>
<template>
 <header class="page-header"><div><h1>联动设备</h1><p class="page-description">按执行探针检索 HTTP 连接器，核对设备身份、配置绑定、观测时效和响应动作。</p></div><a-button :loading="pending" @click="refresh">刷新设备</a-button></header>
 <ResponseDeviceFilters :model="filters" :pending="pending" @search="search" @reset="reset"/>
 <a-alert v-if="filterError" type="error" show-icon :message="filterError" class="section-gap"/>
 <section class="panel"><div class="panel-header"><div><h2>设备目录</h2><p class="page-description">每页 20 项；设备核验状态来自最近一次探针上报，过期、离线与停用状态分别核对。</p></div><span>当前 {{items.length}} 项</span></div>
  <div v-if="error&&items.length" class="panel-body"><a-alert type="warning" show-icon message="设备目录更新失败" :description="error+'。当前显示上次成功读取的目录，请刷新核对。'"/></div>
  <StatePanel :loading="pending&&!items.length" :error="items.length?undefined:error" :empty="!items.length" description="当前条件下没有联动设备。请调整筛选，或在执行采集器配置本地 HTTP 连接器后核对心跳上报。" @retry="refresh"><ResponseDeviceTable :items="items" @view="selected=$event" @actions="actions" @respond="respond"/></StatePanel>
  <div class="device-pagination"><a-button :disabled="pending||cursors.length<=1" @click="page(false)">上一页</a-button><span>第 {{cursors.length}} 页 · 当前 {{items.length}} 项</span><a-button :disabled="pending||!nextCursor||!!error" @click="page(true)">下一页</a-button></div>
 </section>
 <ResponseDeviceDetail :device="selected" :observed-at="observedAt" @close="selected=null" @actions="actions" @respond="respond"/>
 <ResponseDialog :sensor="responseSensor" :binding="responseDevice" @close="closeResponse" @submitted="submitted"/>
</template>
<style scoped>.device-pagination{display:flex;justify-content:flex-end;align-items:center;flex-wrap:wrap;gap:var(--related-gap);padding:var(--panel-inset)}</style>
