<script setup lang="ts">
import {computed,onScopeDispose,shallowRef,watch} from 'vue'
import {Modal as AModal} from 'ant-design-vue'
import type {SearchRequest} from '@starbeacon/shared/types.ts'
import {formatTime} from '@starbeacon/shared/types.ts'
import {session} from '../../session'
import {trafficKinds,type TrafficQuery} from '../traffic/traffic'
const props=defineProps<{dataset:'alerts'|'context';query:SearchRequest;disabled:boolean}>()
const frozen=shallowRef<SearchRequest|null>(null),pending=shallowRef(false),error=shallowRef(''),success=shallowRef('')
const conditionFields=[['keyword','关键词'],['source_ip','源 IP'],['destination_ip','目的 IP'],['protocol','协议'],['method','HTTP 方法'],['path','HTTP 路径'],['severity','严重级别'],['event_kind','记录类型'],['sensor_id','探针'],['sensor_registration_id','注册代次'],['source_generation_id','来源代次'],['flow_id','会话标识'],['filter','高级表达式']] as const
const severityLabels:Record<string,string>={high:'高',medium:'中',low:'低',unknown:'未知'}
const conditions=computed(()=>{
 const q=frozen.value as (SearchRequest&Partial<TrafficQuery>)|null
 if(!q)return []
 return conditionFields.flatMap(([key,label])=>{
  const value=q[key]
  if(!value?.trim())return []
  return [{key,label,value:key==='severity'?severityLabels[value]??value:key==='event_kind'?trafficKinds[value]??value:value}]
 })
})
let controller:AbortController|undefined,url='',timer:ReturnType<typeof setTimeout>|undefined
function revoke(){if(timer!==undefined)clearTimeout(timer);timer=undefined;if(url)URL.revokeObjectURL(url);url=''}
function cancel(){controller?.abort();controller=undefined;pending.value=false;frozen.value=null;error.value='';success.value='';revoke()}
function open(){if(props.disabled||pending.value)return;frozen.value={...props.query};error.value='';success.value=''}
async function submit(){
 if(!frozen.value||pending.value)return
 const query={...frozen.value},active=new AbortController();controller=active;pending.value=true;error.value='';success.value=''
 try{
  const result=await session.api.downloadSearch(props.dataset,query,active.signal)
  if(active.signal.aborted)return
  revoke();url=URL.createObjectURL(result.blob)
  const link=document.createElement('a');link.href=url;link.download=`starbeacon-${props.dataset}-${query.start.replace(/[^0-9TZ]/g,'')}.csv`;document.body.append(link);link.click();link.remove();timer=setTimeout(revoke,1000)
  success.value=`导出文件已准备，包含 ${result.rows.toLocaleString('zh-CN')} 条记录。`
 }catch(value){if(!active.signal.aborted)error.value=value instanceof Error?value.message:'检索导出未完成，请稍后重试'}
 finally{if(controller===active){controller=undefined;pending.value=false}}
}
watch(()=>[session.current.value?.tenant_id,session.current.value?.id,session.current.value?.role,props.dataset].join('/'),cancel,{flush:'sync'})
watch(()=>props.query,()=>{if(frozen.value&&!pending.value)cancel()},{flush:'sync'})
onScopeDispose(cancel)
</script>
<template>
 <a-button :disabled="disabled" @click="open">导出</a-button>
 <a-modal :open="!!frozen" title="导出检索结果" :width="640" :footer="null" :mask-closable="false" @cancel="cancel">
  <template v-if="frozen">
   <p class="export-window">{{dataset==='alerts'?'告警记录':'协议记录'}} · {{formatTime(frozen.start)}} — {{formatTime(frozen.end)}}</p>
   <dl v-if="conditions.length" class="export-conditions" aria-label="导出筛选条件"><div v-for="condition in conditions" :key="condition.key"><dt>{{condition.label}}</dt><dd>{{condition.value}}</dd></div></dl>
   <p v-else class="export-notice">未设置其他筛选条件，导出范围为上述时间窗口内的全部记录。</p>
   <a-alert type="info" show-icon message="导出当前已提交条件下的全部命中，最多 10,000 条或 8 MiB。只包含元数据，不含原始载荷和原包；超限或不完整结果不会生成部分文件。"/>
   <p class="export-notice">CSV 使用 UTF-8；公式前缀和超过 15 位的整数字段以文本形式保存。文件基于导出时的固定快照，记录数量可能与此前列表不同。</p>
   <a-alert v-if="error" type="error" show-icon :message="error" class="section-gap"/>
   <a-alert v-if="success" type="success" show-icon :message="success" class="section-gap"/>
   <div class="export-actions"><a-button @click="cancel">{{pending?'取消导出':'关闭'}}</a-button><a-button type="primary" :loading="pending" :disabled="pending" @click="submit">导出 CSV</a-button></div>
  </template>
 </a-modal>
</template>
<style scoped>.export-window,.export-notice{overflow-wrap:anywhere;font-size:12px;line-height:1.7}.export-notice{color:var(--muted);margin:12px 0}.export-conditions{max-height:180px;overflow:auto;margin:12px 0;font-size:12px;line-height:1.7}.export-conditions>div{display:grid;grid-template-columns:96px minmax(0,1fr);gap:8px;padding:3px 0}.export-conditions dt{color:var(--muted)}.export-conditions dd{margin:0;white-space:pre-wrap;overflow-wrap:anywhere}.export-actions{display:flex;flex-wrap:wrap;justify-content:flex-end;gap:8px;margin-top:12px}</style>
