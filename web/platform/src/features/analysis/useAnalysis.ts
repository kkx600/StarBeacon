import {onMounted,onScopeDispose,shallowReadonly,shallowRef} from 'vue'
import {ApiError} from '@starbeacon/shared/api.ts'
import {session} from '../../session'
import {validJob,validPage,validThreads,validConversation,working,type AnalysisJob,type AnalysisPage,type ThreadPage,type AnalysisRequest,type AnalysisSummary,type AnalysisThread,type Conversation} from './analysis'

export function useAnalysis(group:'chat'|'reports'){
 const items=shallowRef<AnalysisSummary[]>([]),threads=shallowRef<AnalysisThread[]>([]),next=shallowRef(''),pending=shallowRef(false),error=shallowRef(''),available=shallowRef(false)
 const selected=shallowRef<AnalysisJob|null>(null),conversation=shallowRef<Conversation|null>(null),loading=shallowRef(false),detailError=shallowRef(''),busy=shallowRef(false),actionError=shallowRef(''),unconfirmed=shallowRef(false)
 let stopped=false,listEpoch=0,detailEpoch=0,listController:AbortController|undefined,detailController:AbortController|undefined,mutation:AbortController|undefined,timer:ReturnType<typeof setInterval>|undefined
 let attempt:{key:string;input:AnalysisRequest}|undefined
 async function refresh(before='',append=false){
  if(stopped)return
  const epoch=++listEpoch;listController?.abort();const control=new AbortController();listController=control;pending.value=true;error.value=''
  try{
   const status=await session.api.request<AnalysisPage>(`/analysis/jobs?group=${group}&limit=20${before?'&before='+encodeURIComponent(before):''}`,{signal:control.signal})
   if(epoch!==listEpoch||stopped)return
   if(!validPage(status))throw new Error('分析记录未能完整返回')
   available.value=status.model_execution_available
   if(group==='reports'){items.value=append?[...items.value,...status.items]:status.items;next.value=status.next_cursor}
   else {const page=await session.api.request<ThreadPage>(`/analysis/threads${before?'?before='+encodeURIComponent(before):''}`,{signal:control.signal});if(epoch!==listEpoch||stopped)return;if(!validThreads(page))throw new Error('对话记录未能完整返回');threads.value=append?[...threads.value,...page.items]:page.items;next.value=page.next_cursor}
  }catch(e){if(!control.signal.aborted)error.value=e instanceof Error?e.message:'分析记录读取失败'}finally{if(epoch===listEpoch&&!stopped)pending.value=false}
 }
 async function loadJob(id:string){
  if(stopped)return
  const epoch=++detailEpoch;detailController?.abort();const control=new AbortController();detailController=control;loading.value=true;detailError.value=''
  try{const job=await session.api.request<AnalysisJob>('/analysis/jobs/'+encodeURIComponent(id),{signal:control.signal});if(epoch!==detailEpoch||stopped)return;if(!validJob(job))throw new Error('分析结果未能完整返回');selected.value=job;items.value=items.value.map(row=>row.id===job.id?{...row,state:job.state,cancel_requested:job.cancel_requested}:row);if(conversation.value?.id===job.request.thread_id)conversation.value={...conversation.value,jobs:conversation.value.jobs.map(row=>row.id===job.id?job:row)}}catch(e){if(!control.signal.aborted)detailError.value=e instanceof Error?e.message:'分析结果读取失败'}finally{if(epoch===detailEpoch&&!stopped)loading.value=false}
 }
 async function loadThread(id:string,before=''){
  if(stopped)return
  const epoch=++detailEpoch;detailController?.abort();const control=new AbortController();detailController=control;loading.value=true;detailError.value=''
  try{const page=await session.api.request<Conversation>('/analysis/threads/'+encodeURIComponent(id)+(before?'?before='+encodeURIComponent(before):''),{signal:control.signal});if(epoch!==detailEpoch||stopped)return;if(!validConversation(page,id))throw new Error('对话内容未能完整返回');if(before&&conversation.value?.id===id){const known=new Set(conversation.value.jobs.map(job=>job.id));conversation.value={...page,jobs:[...page.jobs.filter(job=>!known.has(job.id)),...conversation.value.jobs]}}else{conversation.value=page;selected.value=page.jobs.at(-1)??null}}catch(e){if(!control.signal.aborted)detailError.value=e instanceof Error?e.message:'对话记录读取失败'}finally{if(epoch===detailEpoch&&!stopped)loading.value=false}
 }
 async function submit(input:AnalysisRequest){
  if(stopped||busy.value)return undefined
  if(attempt&&JSON.stringify(attempt.input)!==JSON.stringify(input)){actionError.value='上次提交结果尚未确认，请先确认原请求。';return undefined}
  if(!attempt)attempt={key:crypto.randomUUID().replaceAll('-',''),input:structuredClone(input)}
  const control=new AbortController();mutation=control;busy.value=true;actionError.value=''
  try{const job=await session.api.request<AnalysisJob>('/analysis/jobs',{method:'POST',body:attempt.input,headers:{'Idempotency-Key':attempt.key},signal:control.signal});if(stopped||control.signal.aborted)return undefined;if(!validJob(job))throw new Error('提交结果未能完整返回，请确认原请求');attempt=undefined;unconfirmed.value=false;selected.value=job;if(group==='chat')await loadThread(job.request.thread_id);void refresh();return job}
  catch(e){if(!control.signal.aborted){actionError.value=e instanceof Error?e.message:'分析提交结果未确认';if(e instanceof ApiError&&e.status>=400&&e.status<500&&e.status!==408){attempt=undefined;unconfirmed.value=false}else unconfirmed.value=true}return undefined}
  finally{if(mutation===control){mutation=undefined;busy.value=false}}
 }
 async function confirm(){if(attempt)return submit(attempt.input);return undefined}
 async function cancel(id:string){
  if(stopped||busy.value)return undefined
  const control=new AbortController();mutation=control;busy.value=true;actionError.value=''
  try{const job=await session.api.request<AnalysisJob>('/analysis/jobs/'+encodeURIComponent(id)+'/cancel',{method:'POST',body:{},signal:control.signal});if(stopped||control.signal.aborted)return undefined;if(!validJob(job))throw new Error('取消结果未能完整返回，请刷新记录核对');selected.value=job;if(conversation.value?.id===job.request.thread_id)conversation.value={...conversation.value,jobs:conversation.value.jobs.map(row=>row.id===job.id?job:row)};void refresh();return job}catch(e){if(!control.signal.aborted)actionError.value=e instanceof Error?e.message:'取消请求未确认';return undefined}finally{if(mutation===control){mutation=undefined;busy.value=false}}
 }
 function clear(){detailEpoch++;detailController?.abort();conversation.value=null;selected.value=null;loading.value=false;detailError.value='';actionError.value=''}
 onMounted(()=>{void refresh();timer=setInterval(()=>{if(selected.value&&working(selected.value.state)&&!loading.value&&document.visibilityState==='visible')void loadJob(selected.value.id)},1000)})
 onScopeDispose(()=>{stopped=true;listEpoch++;detailEpoch++;listController?.abort();detailController?.abort();mutation?.abort();if(timer)clearInterval(timer)})
 return{items:shallowReadonly(items),threads:shallowReadonly(threads),next:shallowReadonly(next),pending:shallowReadonly(pending),error:shallowReadonly(error),available:shallowReadonly(available),selected:shallowReadonly(selected),conversation:shallowReadonly(conversation),loading:shallowReadonly(loading),detailError:shallowReadonly(detailError),busy:shallowReadonly(busy),actionError:shallowReadonly(actionError),unconfirmed:shallowReadonly(unconfirmed),refresh,loadJob,loadThread,submit,confirm,cancel,clear}
}
