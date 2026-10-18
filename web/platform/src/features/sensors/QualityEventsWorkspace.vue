<script setup lang="ts">
import {onScopeDispose,ref,shallowRef,watch} from 'vue'
import QualityEventsFilters from '@starbeacon/shared/components/QualityEventsFilters.vue'
import QualityEventsPanel from '@starbeacon/shared/components/QualityEventsPanel.vue'
import {localQualityTime,qualityQuery,readQualityPage,type QualityPage} from '@starbeacon/shared/qualityEvents.ts'
import {session} from '../../session'
const defaults=()=>({start:localQualityTime(new Date(Date.now()-86400000)),end:localQualityTime(new Date()),sensor:'',registration:'',kind:''})
const form=ref(defaults()),result=shallowRef<QualityPage|null>(null),pending=shallowRef(false),error=shallowRef(''),attempted=shallowRef(false)
let controller:AbortController|undefined
function invalidate(){controller?.abort();pending.value=false;result.value=null;error.value='';attempted.value=false}
watch(form,invalidate,{deep:true,flush:'sync'})
async function load(page=1){
 if(pending.value)return
 result.value=null;error.value='';attempted.value=true
 let query;try{query=qualityQuery(form.value,page)}catch(e){error.value=(e as Error).message;return}
 const tenant=session.current.value?.tenant_id;if(!tenant){error.value='登录状态已失效，请重新登录。';return}
 const active=new AbortController();controller=active;pending.value=true
 const timer=setTimeout(()=>active.abort('timeout'),12000)
 try{const value=await session.api.request<unknown>('/sensors/quality-events?'+new URLSearchParams(Object.entries(query)),{signal:active.signal});if(!active.signal.aborted)result.value=readQualityPage(value,query,tenant)}
 catch(e){if(!active.signal.aborted||active.signal.reason==='timeout')error.value=active.signal.reason==='timeout'?'质量事件读取超时，本次未交付结果，请稍后重试。':e instanceof Error?e.message:'质量事件读取失败。'}
 finally{clearTimeout(timer);if(controller===active)pending.value=false}
}
function cancel(){invalidate();attempted.value=true;error.value='查询已取消，本次未交付结果。'}
function reset(){form.value=defaults();void load()}
watch(()=>[session.current.value?.tenant_id,session.current.value?.id,session.current.value?.role,session.current.value?.csrf_token].join('/'),()=>{invalidate();form.value=defaults();void load()},{immediate:true,flush:'sync'})
onScopeDispose(invalidate)
</script>
<template>
 <a-alert type="info" show-icon message="仅记录托管引擎的区间质量变化与持续状态提醒。采样缺失、计数器复位及外部 EVE 不提供完整检测覆盖结论。事件异步写入；空结果不代表不存在质量问题。" class="section-gap"/>
 <QualityEventsFilters v-model="form" :pending="pending" @query="load()" @cancel="cancel" @reset="reset"/>
 <QualityEventsPanel :result="result" :pending="pending" :error="error" :attempted="attempted" @retry="load()" @page="load"/>
</template>
