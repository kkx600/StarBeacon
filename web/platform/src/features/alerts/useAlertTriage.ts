import {onMounted,onScopeDispose,shallowReadonly,shallowRef} from 'vue'
import {ApiError} from '@starbeacon/shared/api.ts'
import {session} from '../../session'
import {sameTriageRequest,triageWorking,validTriageJob,validTriagePage,validTriageRequest,type TriageJob,type TriageRequest,type TriageSummary} from './triage'

export function useAlertTriage(eventID:string,digest:string){
 const items=shallowRef<TriageSummary[]>([]),next=shallowRef(''),pending=shallowRef(false),error=shallowRef(''),available=shallowRef(false)
 const selected=shallowRef<TriageJob|null>(null),loading=shallowRef(false),detailError=shallowRef(''),busy=shallowRef(false),actionError=shallowRef(''),unconfirmed=shallowRef(false)
 const path='/alerts/'+encodeURIComponent(eventID)+'/triage?sha256='+encodeURIComponent(digest)
 let stopped=false,listEpoch=0,detailEpoch=0,failures=0,listRead:AbortController|undefined,detailRead:AbortController|undefined,mutation:AbortController|undefined,timer:ReturnType<typeof setTimeout>|undefined
 let attempt:{key:string;input:TriageRequest}|undefined
 const matches=(job:TriageJob)=>job.request.event_id===eventID&&job.request.raw_sha256===digest
 function schedule(failed=false){
  if(timer)clearTimeout(timer)
  if(stopped||failed&&++failures>=3)return
  if(!failed)failures=0
  if(!failed&&!items.value.some(row=>triageWorking(row.state))&&!(selected.value&&triageWorking(selected.value.state)))return
  timer=setTimeout(async()=>{if(document.visibilityState!=='visible'){schedule();return}await refresh('',true);if(!error.value&&selected.value&&triageWorking(selected.value.state))await load(selected.value.id,true);schedule(!!error.value||!!detailError.value)},failed?5000*2**Math.max(0,failures-1):3000)
 }
 async function refresh(before='',poll=false){
  if(stopped)return
  const epoch=++listEpoch;listRead?.abort();const controller=new AbortController();listRead=controller;pending.value=true;error.value='';let failed=false
  try{const page=await session.api.request<unknown>(path+(before?'&before='+encodeURIComponent(before):''),{signal:controller.signal});if(stopped||controller.signal.aborted||epoch!==listEpoch)return;if(!validTriagePage(page))throw new Error('研判记录未能完整返回');items.value=before?[...items.value,...page.items.filter(row=>!items.value.some(old=>old.id===row.id))].slice(0,100):page.items;next.value=items.value.length>=100?'':page.next_cursor;available.value=page.model_execution_available}
  catch(e){if(!controller.signal.aborted){failed=true;error.value=e instanceof Error?e.message:'研判记录读取失败'}}finally{if(!stopped&&epoch===listEpoch){pending.value=false;if(!poll)schedule(failed)}}
 }
 async function load(id:string,poll=false){
  if(stopped)return
  const epoch=++detailEpoch;detailRead?.abort();const controller=new AbortController();detailRead=controller;loading.value=true;detailError.value=''
  try{const job=await session.api.request<unknown>('/alert-triage/jobs/'+encodeURIComponent(id),{signal:controller.signal});if(stopped||controller.signal.aborted||epoch!==detailEpoch)return;if(!validTriageJob(job)||job.id!==id||!matches(job))throw new Error('研判结果与当前告警无法核对');selected.value=job;items.value=items.value.map(row=>row.id===job.id?{...row,state:job.state}:row)}
  catch(e){if(!controller.signal.aborted)detailError.value=e instanceof Error?e.message:'研判结果读取失败'}finally{if(!stopped&&epoch===detailEpoch){loading.value=false;if(!poll)schedule(!!detailError.value)}}
 }
 async function submit(input:TriageRequest):Promise<TriageJob|undefined>{
  if(stopped||busy.value)return undefined
  if(!validTriageRequest(input)||input.event_id!==eventID||input.raw_sha256!==digest){actionError.value='请核对告警、模型修订、说明及本次数据使用许可';return undefined}
  if(attempt&&!sameTriageRequest(attempt.input,input)){actionError.value='上次提交结果尚未确认，请先确认原请求';return undefined}
  attempt??={key:crypto.randomUUID().replaceAll('-',''),input:structuredClone(input)}
  const controller=new AbortController();mutation=controller;busy.value=true;actionError.value=''
  try{const job=await session.api.request<unknown>(path,{method:'POST',body:attempt.input,headers:{'Idempotency-Key':attempt.key},signal:controller.signal});if(stopped||controller.signal.aborted)return undefined;if(!validTriageJob(job)||!sameTriageRequest(job.request,attempt.input))throw new Error('提交结果未能完整返回，请确认原请求');selected.value=job;attempt=undefined;unconfirmed.value=false;void refresh();return job}
  catch(e){if(!controller.signal.aborted){actionError.value=e instanceof Error?e.message:'研判提交结果尚未确认';if(e instanceof ApiError&&e.status>=400&&e.status<500&&e.status!==408){attempt=undefined;unconfirmed.value=false}else unconfirmed.value=true}return undefined}
  finally{if(mutation===controller){mutation=undefined;busy.value=false}}
 }
 async function cancel(id:string){
  if(stopped||busy.value||unconfirmed.value)return
  const controller=new AbortController();mutation=controller;busy.value=true;actionError.value=''
  try{const job=await session.api.request<unknown>('/alert-triage/jobs/'+encodeURIComponent(id)+'/cancel',{method:'POST',body:{},signal:controller.signal});if(stopped||controller.signal.aborted)return;if(!validTriageJob(job)||job.id!==id||!matches(job))throw new Error('取消结果未能核对，请刷新记录确认');selected.value=job;void refresh()}
  catch(e){if(!controller.signal.aborted)actionError.value=e instanceof Error?e.message:'取消请求未确认'}finally{if(mutation===controller){mutation=undefined;busy.value=false}}
 }
 onMounted(()=>void refresh())
 onScopeDispose(()=>{stopped=true;listEpoch++;detailEpoch++;listRead?.abort();detailRead?.abort();mutation?.abort();if(timer)clearTimeout(timer)})
 return{items:shallowReadonly(items),next:shallowReadonly(next),pending:shallowReadonly(pending),error:shallowReadonly(error),available:shallowReadonly(available),selected:shallowReadonly(selected),loading:shallowReadonly(loading),detailError:shallowReadonly(detailError),busy:shallowReadonly(busy),actionError:shallowReadonly(actionError),unconfirmed:shallowReadonly(unconfirmed),refresh,load,submit,confirm:()=>attempt?submit(attempt.input):Promise.resolve(undefined),cancel}
}
