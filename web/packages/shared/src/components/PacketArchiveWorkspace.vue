<script setup lang="ts">
import {Table as ATable,message} from 'ant-design-vue'
import {computed,onScopeDispose,ref,shallowRef,watch} from 'vue'
import type {TableRowSelection} from 'ant-design-vue/es/table/interface'
import type {ApiClient} from '../api'
import {packetCapture,packetUnsealed,packetStates,packetCodes,canDownloadPacket,type PacketRecord} from '../packetArchives'
import {usePacketArchives} from '../usePacketArchives'
import {formatBytes} from '../utils/format'
import {formatTime} from '../types'
import StatePanel from './StatePanel.vue'
import PacketArchiveDetail from './PacketArchiveDetail.vue'
import SessionExportDialog from './SessionExportDialog.vue'
import PacketInspector from './PacketInspector.vue'
const props=defineProps<{api:ApiClient;local?:boolean}>()
const {page,pending,error,selected,detailPending,detailError,history,view,close,refresh,filter,next,previous}=usePacketArchives(props.api,props.local)
const sensor=ref(''),downloading=shallowRef(''),downloadError=shallowRef('')
const exportIDs=shallowRef<string[]>([]),exportOpen=shallowRef(false)
const inspecting=shallowRef<PacketRecord|null>(null)
const exportArchives=computed(()=>page.value.items.filter(row=>exportIDs.value.includes(row.id)))
const rowSelection=computed<TableRowSelection<PacketRecord>|undefined>(()=>props.local?undefined:({selectedRowKeys:exportIDs.value,hideSelectAll:true,getCheckboxProps:row=>({disabled:row.state!=='ready'||exportIDs.value.length>=16&&!exportIDs.value.includes(row.id)}),onChange:keys=>{exportIDs.value=keys.map(String).slice(0,16)}}))
watch(()=>page.value.items,()=>{exportIDs.value=[];exportOpen.value=false;inspecting.value=null})
let downloadController:AbortController|undefined,downloadURL='',revokeTimer:ReturnType<typeof setTimeout>|undefined
function revoke(){if(revokeTimer)clearTimeout(revokeTimer);if(downloadURL)URL.revokeObjectURL(downloadURL);downloadURL=''}
async function download(row:PacketRecord){
 if(downloading.value||!canDownloadPacket(row))return
 downloadError.value='';downloading.value=row.id
 const controller=new AbortController();downloadController=controller
 try{
  const blob=await props.api.downloadPacket('/packet-archives/'+encodeURIComponent(row.id)+'/download',controller.signal)
  if(controller.signal.aborted)return
  revoke();downloadURL=URL.createObjectURL(blob)
  const anchor=document.createElement('a');anchor.href=downloadURL;anchor.download=row.id+'.pcapng';document.body.append(anchor);anchor.click();anchor.remove();revokeTimer=setTimeout(revoke,1000)
  message.success('原包已通过摘要校验，下载已开始')
 }catch(e){if(!controller.signal.aborted)downloadError.value=e instanceof Error?e.message:'原包下载失败，请稍后重试'}
 finally{if(!controller.signal.aborted)downloading.value=''}
}
onScopeDispose(()=>{downloadController?.abort();revoke()})
const columns=[{title:'归档 / 状态',key:'identity',width:220},{title:'探针 / 网卡',key:'source',width:190},{title:'包数 / 截断',key:'packets',width:140},{title:props.local?'暂存预留':'原始 / 存储大小',key:'size',width:180},{title:'捕获开始',key:'time',width:185},{title:'操作',key:'actions',width:230}]
function choose(id:string){const row=page.value.items.find(row=>row.id===id);if(row)void view(row)}
function inspect(row:PacketRecord){if(canDownloadPacket(row)&&packetCapture(row).packets){close();exportOpen.value=false;inspecting.value=row}}
</script>
<template>
 <div class="packet-toolbar"><form v-if="!local" @submit.prevent="filter(sensor)"><a-input v-model:value="sensor" placeholder="按探针标识筛选" aria-label="原包探针标识" :maxlength="64" :disabled="pending" allow-clear/><a-button html-type="submit" :disabled="pending" >筛选</a-button><a-button :disabled="pending" @click="sensor='';filter('')">重置</a-button></form><a-button v-if="!local" :disabled="pending||!!error||!exportArchives.length" @click="exportOpen=true">会话导出{{exportArchives.length?`（${exportArchives.length}）`:''}}</a-button><a-button :loading="pending" @click="refresh">刷新原包</a-button></div>
 <a-alert v-if="downloadError" type="error" show-icon :message="downloadError" class="section-gap"/>
 <a-alert v-if="!pending&&!error&&!page.available" type="info" show-icon message="原包归档未配置。请核对平台对象存储与采集器的独立原包捕获配置。" class="section-gap"/>
 <a-alert v-else-if="local&&page.health?.code" type="warning" show-icon :message="packetCodes[page.health.code]??'原包捕获状态需要核查，请保留本机原件。'" class="section-gap"/>
 <section class="panel"><div class="panel-header"><h2>原包归档</h2><span v-if="local&&page.health">{{packetStates[page.health.state]??'状态待核查'}} · {{formatBytes(page.health.reserved_bytes)}} / {{formatBytes(page.health.quota_bytes)}}</span></div>
  <p class="muted packet-note">{{local?'本机展示最近 200 条捕获与确认记录。平台持久确认后本机回收原件；已归档数据请在主平台查询。':'每页展示 50 条原包切片。默认留存 180 天，具体到期时间按归档时生效的留存策略确定。'}} 单个切片不保证包含完整连接。</p>
  <StatePanel :loading="pending" :error="error" :empty="!page.items.length" description="暂无原包归档。请核对网卡、捕获过滤器、暂存额度和平台连接状态。" @retry="refresh">
   <div class="table-wrap"><a-table :columns="columns" :data-source="page.items" :row-selection="rowSelection" row-key="id" :pagination="local?{pageSize:20,showSizeChanger:false}:false" :scroll="{x:1145}"><template #bodyCell="{column,record}">
    <template v-if="column.key==='identity'"><span class="technical">{{record.id}}</span><small class="packet-sub">{{packetStates[record.state]}}</small></template>
    <template v-else-if="column.key==='source'"><span class="technical">{{packetCapture(record as PacketRecord).sensor_id}}</span><small class="packet-sub">{{packetCapture(record as PacketRecord).interface}} · {{packetCapture(record as PacketRecord).interface_mac}}</small></template>
    <template v-else-if="column.key==='packets'"><template v-if="packetUnsealed(record as PacketRecord)">待封存<small class="packet-sub">包数与完整性尚未冻结</small></template><template v-else>{{packetCapture(record as PacketRecord).packets.toLocaleString('zh-CN')}} 包<small class="packet-sub">截断 {{packetCapture(record as PacketRecord).truncated_packets.toLocaleString('zh-CN')}} 包</small></template></template>
    <template v-else-if="column.key==='size'">{{formatBytes(local?record.reserved_bytes:record.raw_bytes)}}<small v-if="!local" class="packet-sub">{{formatBytes(record.stored_bytes)}} · {{record.codec}}</small></template>
    <template v-else-if="column.key==='time'">{{formatTime(packetCapture(record as PacketRecord).started_at)}}</template>
    <template v-else-if="column.key==='actions'"><a-button type="link" @click="choose(record.id)">查看</a-button><a-button type="link" :disabled="!canDownloadPacket(record as PacketRecord)||!packetCapture(record as PacketRecord).packets" @click="inspect(record as PacketRecord)">协议查看</a-button><a-button type="link" :disabled="!canDownloadPacket(record as PacketRecord)||!!downloading" :loading="downloading===record.id" @click="download(record as PacketRecord)">下载</a-button></template>
   </template></a-table></div>
  </StatePanel>
  <div v-if="!local&&!pending&&!error" class="packet-pagination"><span class="muted">第 {{history.length+1}} 页 · {{page.items.length}} 条</span><a-button :disabled="!history.length" @click="previous">上一页</a-button><a-button :disabled="!page.next" @click="next">下一页</a-button></div>
 </section>
 <PacketArchiveDetail :record="selected" :local="local" :pending="detailPending" :error="detailError" @close="close" @retry="selected&&view(selected)"/>
 <SessionExportDialog v-if="!local" :api="api" :archives="exportArchives" :open="exportOpen" @close="exportOpen=false"/>
 <PacketInspector :api="api" :record="inspecting" @close="inspecting=null"/>
</template>
<style scoped>.packet-toolbar,.packet-toolbar form,.packet-pagination{display:flex;align-items:center;gap:8px;flex-wrap:wrap}.packet-toolbar{justify-content:space-between;margin-bottom:var(--section-gap)}.packet-toolbar form{min-width:0;flex:1}.packet-toolbar form .ant-input-affix-wrapper{width:260px;max-width:100%}.packet-sub{display:block;color:var(--muted);margin-top:4px;overflow-wrap:anywhere}.technical{overflow-wrap:anywhere}.packet-note{font-size:12px;margin:0 0 8px}.packet-pagination{justify-content:flex-end;margin-top:10px}</style>
