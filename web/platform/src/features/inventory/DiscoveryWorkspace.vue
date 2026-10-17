<script setup lang="ts">
import {computed,onScopeDispose,reactive,shallowRef,watch} from 'vue'
import {Select as ASelect} from 'ant-design-vue'
import {readSensorDirectory} from '@starbeacon/shared/sensors.ts'
import type {Sensor} from '@starbeacon/shared/types.ts'
import {readDiscovery,type DiscoveryQuery,type DiscoveryResult,type DiscoveryAddress} from '@starbeacon/shared/discovery.ts'
import DiscoveryPanel from '@starbeacon/shared/components/DiscoveryPanel.vue'
import {session} from '../../session'
import InventoryForm from './InventoryForm.vue'
import {createDraft,type InventoryRecord,type InventoryData,type InventoryPage} from './inventory'

const networks=shallowRef<InventoryRecord[]>([]),sensors=shallowRef<Sensor[]>([]),directoryPending=shallowRef(false),directoryError=shallowRef('')
const result=shallowRef<DiscoveryResult|null>(null),pending=shallowRef(false),error=shallowRef(''),attempted=shallowRef(false)
const localTime=(date:Date)=>new Date(date.getTime()-date.getTimezoneOffset()*60000).toISOString().slice(0,19)
const form=reactive({network:'',sensor:'',prefix:'',start:localTime(new Date(Date.now()-3600000)),end:localTime(new Date())})
const draft=shallowRef<InventoryData|null>(null),saving=shallowRef(false),saveError=shallowRef(''),saved=shallowRef('')
let directoryController:AbortController|undefined,queryController:AbortController|undefined,saveController:AbortController|undefined
const network=computed(()=>networks.value.find(row=>row.id===form.network))
const sensor=computed(()=>sensors.value.find(row=>row.id===form.sensor))
watch(()=>form.network,()=>{form.prefix=network.value?.data.prefix??''},{flush:'sync'})
function invalidate(){queryController?.abort();pending.value=false;result.value=null;error.value='';attempted.value=false}
watch(form,invalidate,{flush:'sync'})
async function loadDirectory(){
 directoryController?.abort();invalidate();networks.value=[];sensors.value=[];directoryPending.value=true;directoryError.value=''
 const controller=new AbortController();directoryController=controller
 const timer=setTimeout(()=>controller.abort('timeout'),12000)
 try {
  const networkRequest=async()=>{
   const rows:InventoryRecord[]=[],seen=new Set<string>();let cursor=''
   for(let round=0;round<101;round++){
    const page=await session.api.request<InventoryPage>('/inventory/networks?'+new URLSearchParams({limit:'100',cursor}),{signal:controller.signal})
    if(controller.signal.aborted)throw new DOMException('目录读取已取消','AbortError')
    if(!Array.isArray(page.items)||page.items.length>100||typeof page.next_cursor!=='string'||page.next_cursor&&(!/^[a-z0-9][a-z0-9_-]{0,63}$/.test(page.next_cursor)||page.items.at(-1)?.id!==page.next_cursor||page.next_cursor<=cursor))throw new Error('网段目录分页不完整，请刷新后重试。')
    for(const row of page.items){if(!row||row.kind!=='networks'||!/^[a-z0-9][a-z0-9_-]{0,63}$/.test(row.id)||seen.has(row.id)||!Number.isSafeInteger(row.revision)||row.revision<1||!row.data||typeof row.data.active!=='boolean'||typeof row.data.name!=='string'||!row.data.name||typeof row.data.prefix!=='string'||!row.data.prefix||typeof row.data.network_domain!=='string'||!row.data.network_domain)throw new Error('网段目录内容不完整，请核对配置。');seen.add(row.id);rows.push(row)}
    if(rows.length>10000)throw new Error('网段超过单次目录读取上限，请缩小管理范围。')
    if(!page.next_cursor)return rows
    cursor=page.next_cursor
   }
   throw new Error('网段目录分页未结束，请刷新后重试。')
  }
  const [nets,probes]=await Promise.all([networkRequest(),readSensorDirectory(session.api,controller.signal)])
  if(!controller.signal.aborted){networks.value=nets.filter(row=>row.data.active);sensors.value=probes;form.network='';form.sensor='';form.prefix=''}
 } catch(e){if(directoryController===controller)directoryError.value=controller.signal.reason==='timeout'?'探针或网段目录读取超时，请重试。':e instanceof Error?e.message:'目录读取失败。';if(!controller.signal.aborted)controller.abort()}finally{clearTimeout(timer);if(directoryController===controller)directoryPending.value=false}
}
async function discover(){
 if(pending.value||directoryPending.value)return
 result.value=null;error.value='';attempted.value=true
 const selectedNetwork=network.value,selectedSensor=sensor.value,start=new Date(form.start),end=new Date(form.end)
 if(!selectedNetwork||!selectedSensor||!form.prefix||!Number.isFinite(start.getTime())||!Number.isFinite(end.getTime())||end.getTime()<=start.getTime()||end.getTime()-start.getTime()>86400000){error.value='请选择探针、使用中的网段和有效前缀，时间窗口须大于 0 且不超过 24 小时。';return}
 const query:DiscoveryQuery={network_id:selectedNetwork.id,network_revision:selectedNetwork.revision,sensor_id:selectedSensor.id,registration_id:selectedSensor.registration_id,prefix:form.prefix.trim(),start:start.toISOString(),end:end.toISOString()}
 const controller=new AbortController();queryController=controller;pending.value=true
 const timer=setTimeout(()=>controller.abort('timeout'),12000)
 try{const response=await session.api.request<unknown>('/inventory/discovery',{method:'POST',body:query,signal:controller.signal});if(!controller.signal.aborted)result.value=readDiscovery(response,query)}
 catch(e){if(!controller.signal.aborted||controller.signal.reason==='timeout')error.value=controller.signal.reason==='timeout'?'发现查询超时，本次未交付结果。请缩小范围后重试。':e instanceof Error?e.message:'发现查询失败。'}finally{clearTimeout(timer);if(queryController===controller)pending.value=false}
}
function cancel(){queryController?.abort();pending.value=false;error.value='查询已取消，本次未交付结果。'}
function register(row:DiscoveryAddress,observed:DiscoveryResult){saved.value='';saveError.value='';draft.value={...createDraft('assets'),network_domain:observed.scope.network_domain,interfaces:[{name:'',mac:'',ips:[row.ip]}]}}
async function save(data:InventoryData,id:string){
 if(saving.value)return
 saving.value=true;saveError.value='';const controller=new AbortController();saveController=controller
 const timer=setTimeout(()=>controller.abort('timeout'),12000)
 try{await session.api.request('/inventory/assets',{method:'POST',body:{id,expected_revision:0,data},signal:controller.signal});if(!controller.signal.aborted){saved.value=`资产“${data.name}”已登记，可在资产目录查看。`;draft.value=null}}
 catch(e){saveError.value=controller.signal.reason==='timeout'?'保存结果尚未确认，请先在资产目录核对；再次提交将沿用相同对象标识。':e instanceof Error?e.message:'保存结果尚未确认，请先在资产目录核对。'}finally{clearTimeout(timer);saving.value=false}
}
onScopeDispose(()=>{directoryController?.abort();queryController?.abort();saveController?.abort()})
void loadDirectory()
</script>
<template>
 <a-alert type="info" show-icon message="按已有流记录发现地址，源、目的方向分别计数；不等于设备数或独立会话数，也不证明该网段已被完整捕获。" class="section-gap"/>
 <a-alert v-if="saved" type="success" show-icon :message="saved" class="section-gap"/>
 <a-alert v-if="directoryError" type="error" show-icon :message="directoryError" class="section-gap"><template #action><a-button size="small" :loading="directoryPending" @click="loadDirectory">刷新目录</a-button></template></a-alert>
 <a-form :model="form" layout="vertical" class="panel discovery-form" @finish="discover">
  <div class="discovery-query-fields">
   <a-form-item label="探针" html-for="discovery-sensor" required><a-select id="discovery-sensor" aria-label="发现探针" v-model:value="form.sensor" show-search option-filter-prop="label" :loading="directoryPending" :disabled="directoryPending||!!directoryError" placeholder="选择流量观测探针" :options="sensors.map(row=>({value:row.id,label:`${row.name} · ${row.id}`}))"/></a-form-item>
   <a-form-item label="网段" html-for="discovery-network" required><a-select id="discovery-network" aria-label="发现网段" v-model:value="form.network" show-search option-filter-prop="label" :loading="directoryPending" :disabled="directoryPending||!!directoryError" placeholder="选择使用中的网段" :options="networks.map(row=>({value:row.id,label:`${row.data.name} · ${row.data.prefix} · ${row.data.network_domain}`}))"/></a-form-item>
   <a-form-item label="查询前缀" html-for="discovery-prefix" required extra="可缩小到已选网段的子网段，使用标准 CIDR。"><a-input id="discovery-prefix" v-model:value="form.prefix" :maxlength="49" placeholder="192.0.2.0/24"/></a-form-item>
   <a-form-item label="开始时间（本地时间）" html-for="discovery-start" required><a-input id="discovery-start" v-model:value="form.start" type="datetime-local" step="1"/></a-form-item>
   <a-form-item label="结束时间（本地时间）" html-for="discovery-end" required extra="结束时刻不包含在查询内，窗口最多 24 小时。"><a-input id="discovery-end" v-model:value="form.end" type="datetime-local" step="1"/></a-form-item>
  </div>
  <div class="filter-actions"><a-button type="primary" html-type="submit" :loading="pending" :disabled="directoryPending||!!directoryError">执行发现</a-button><a-button v-if="pending" @click="cancel">取消查询</a-button><a-button :loading="directoryPending" :disabled="pending||saving" @click="loadDirectory">刷新目录</a-button><span v-if="!directoryPending&&!directoryError" class="page-description">{{sensors.length}} 个探针 / {{networks.length}} 个使用中网段 · 每次最多 512 个地址</span></div>
 </a-form>
 <DiscoveryPanel :result="result" :pending="pending" :error="error" :attempted="attempted" can-register @retry="discover" @register="register"/>
 <InventoryForm v-if="draft" kind="assets" :record="null" :draft="draft" :pending="saving" :error="saveError" @close="draft=null" @save="save"/>
</template>
<style scoped>.discovery-form{padding:var(--panel-inset);margin-bottom:var(--section-gap)}.discovery-query-fields{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:0 var(--field-gap)}.discovery-query-fields .ant-form-item{min-width:0}.discovery-query-fields .ant-select{width:100%}@media(max-width:1200px){.discovery-query-fields{grid-template-columns:repeat(2,minmax(0,1fr))}}@media(max-width:700px){.discovery-query-fields{grid-template-columns:minmax(0,1fr)}}</style>
