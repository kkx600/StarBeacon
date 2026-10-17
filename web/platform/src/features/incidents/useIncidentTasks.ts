import {onScopeDispose,shallowReadonly,shallowRef,watch,type ShallowRef} from 'vue'
import {ApiError} from '@starbeacon/shared/api.ts'
import {session} from '../../session'
import type {IncidentRecord} from './incident'
import {sameTaskSpec,validTaskHistory,validTaskPage,validTaskRecord,type IncidentTaskAttempt,type IncidentTaskInput,type IncidentTaskPage,type IncidentTaskRecord} from './incidentTask'

export function useIncidentTasks(parent:ShallowRef<IncidentRecord|null>){
 const page=shallowRef<IncidentTaskPage>({items:[],next_cursor:''}),pending=shallowRef(false),error=shallowRef(''),cursors=shallowRef([''])
 const selected=shallowRef<IncidentTaskRecord|null>(null),detailPending=shallowRef(false),detailError=shallowRef('')
 const history=shallowRef<IncidentTaskRecord[]>([]),historyNext=shallowRef(''),historyPending=shallowRef(false),historyError=shallowRef(''),historyLoaded=shallowRef(false)
 const busy=shallowRef(false),unconfirmed=shallowRef(false),actionError=shallowRef('')
 let stopped=false,epoch=0,detailEpoch=0,historyEpoch=0,status=''
 let listRead:AbortController|undefined,detailRead:AbortController|undefined,historyRead:AbortController|undefined,mutation:AbortController|undefined
 let attempt:(IncidentTaskAttempt&{key:string})|undefined
 const path=(caseID:string)=>'/incidents/'+encodeURIComponent(caseID)+'/tasks'
 async function refresh(){
  if(stopped||!parent.value)return
  const id=parent.value.id,token=++epoch;listRead?.abort();const controller=new AbortController();listRead=controller;pending.value=true;error.value=''
  try{const result=await session.api.request<unknown>(path(id)+'?'+new URLSearchParams({status,before:cursors.value.at(-1)??''}),{signal:controller.signal});if(stopped||token!==epoch)return;if(!validTaskPage(result,id))throw new Error('协作任务列表未能完整返回');page.value=result}
  catch(e){if(!controller.signal.aborted)error.value=e instanceof Error?e.message:'协作任务读取失败'}finally{if(!stopped&&token===epoch)pending.value=false}
 }
 function search(value:string){status=value;cursors.value=[''];void refresh()}
 function next(){if(!pending.value&&page.value.next_cursor){cursors.value=[...cursors.value,page.value.next_cursor];void refresh()}}
 function previous(){if(!pending.value&&cursors.value.length>1){cursors.value=cursors.value.slice(0,-1);void refresh()}}
 function clearSelection(){detailEpoch++;historyEpoch++;detailRead?.abort();historyRead?.abort();selected.value=null;detailPending.value=false;detailError.value='';history.value=[];historyNext.value='';historyPending.value=false;historyError.value='';historyLoaded.value=false}
 async function select(id:string){
  if(stopped||!parent.value)return
  clearSelection();const caseID=parent.value.id,token=++detailEpoch,controller=new AbortController();detailRead=controller;detailPending.value=true
  try{const result=await session.api.request<unknown>(path(caseID)+'/'+encodeURIComponent(id),{signal:controller.signal});if(stopped||token!==detailEpoch)return;if(!validTaskRecord(result,caseID)||result.id!==id)throw new Error('协作任务详情未能完整返回');selected.value=result}
  catch(e){if(!controller.signal.aborted)detailError.value=e instanceof Error?e.message:'协作任务详情读取失败'}finally{if(!stopped&&token===detailEpoch)detailPending.value=false}
 }
 async function loadHistory(before=''){
  if(stopped||!parent.value||!selected.value)return
  const caseID=parent.value.id,id=selected.value.id,token=++historyEpoch;historyRead?.abort();const controller=new AbortController();historyRead=controller;historyPending.value=true;historyError.value=''
  try{const result=await session.api.request<unknown>(path(caseID)+'/'+encodeURIComponent(id)+'/history?'+new URLSearchParams({before}),{signal:controller.signal});if(stopped||token!==historyEpoch)return;if(!validTaskHistory(result,caseID,id)||(before&&result.items.some(r=>r.revision>=Number(before))))throw new Error('协作任务历史未能完整返回');history.value=before?[...history.value,...result.items.filter(r=>!history.value.some(old=>old.revision===r.revision))]:result.items;historyNext.value=result.next_cursor;historyLoaded.value=true}
  catch(e){if(!controller.signal.aborted)historyError.value=e instanceof Error?e.message:'协作任务历史读取失败'}finally{if(!stopped&&token===historyEpoch)historyPending.value=false}
 }
 async function save(id:string,input:IncidentTaskInput){
  if(stopped||busy.value||!parent.value)return undefined
  if(attempt&&(attempt.id!==id||attempt.parent.id!==parent.value.id||JSON.stringify(attempt.input)!==JSON.stringify(input))){actionError.value='上次协作操作尚未确认，请先核对原提交。';return undefined}
  if(!attempt)attempt={parent:structuredClone(parent.value),id,input:structuredClone(input),key:crypto.randomUUID()}
  const frozen=attempt,controller=new AbortController();mutation=controller;busy.value=true;actionError.value=''
  const timeout=setTimeout(()=>controller.abort(),30000)
  try{
   const result=await session.api.request<unknown>(path(frozen.parent.id)+(id?'/'+encodeURIComponent(id):''),{method:'POST',body:frozen.input,headers:{'Idempotency-Key':frozen.key},signal:controller.signal})
   if(stopped||mutation!==controller)return undefined
   if(controller.signal.aborted)throw new Error('协作提交结果尚未确认，请核对原提交。')
   const wanted='expected_revision' in frozen.input?frozen.input.expected_revision+1:1
   if(!validTaskRecord(result,frozen.parent.id)||(id&&result.id!==id)||result.revision!==wanted||result.incident_revision!==frozen.input.incident_revision||result.actor_id!==session.current.value?.id||!sameTaskSpec(result.spec,frozen.input.spec)||('note' in frozen.input&&result.note!==frozen.input.note))throw new Error('协作提交回执不完整，请核对原提交。')
   attempt=undefined;unconfirmed.value=false;void refresh();return result
  }catch(e){if(!stopped&&mutation===controller){actionError.value=controller.signal.aborted?'协作提交结果尚未确认，请核对原提交。':e instanceof Error?e.message:'协作提交结果尚未确认';if(e instanceof ApiError&&e.status>=400&&e.status<500&&e.status!==408){attempt=undefined;unconfirmed.value=false}else unconfirmed.value=true}return undefined}
  finally{clearTimeout(timeout);if(mutation===controller){mutation=undefined;busy.value=false}}
 }
 function pendingInput():IncidentTaskAttempt|undefined{return attempt?structuredClone({parent:attempt.parent,id:attempt.id,input:attempt.input}):undefined}
 function confirm(){return attempt?save(attempt.id,attempt.input):Promise.resolve(undefined)}
 function clearActionError(){if(!attempt)actionError.value=''}
 watch(()=>`${parent.value?.id??''}/${parent.value?.revision??''}`,()=>{epoch++;listRead?.abort();page.value={items:[],next_cursor:''};cursors.value=[''];pending.value=false;error.value='';clearSelection();if(parent.value)void refresh()},{immediate:true})
 watch(()=>`${session.current.value?.tenant_id??''}/${session.current.value?.id??''}/${session.current.value?.role??''}`,()=>{epoch++;listRead?.abort();mutation?.abort();mutation=undefined;attempt=undefined;page.value={items:[],next_cursor:''};pending.value=false;busy.value=false;unconfirmed.value=false;actionError.value='';error.value='';clearSelection()})
 onScopeDispose(()=>{stopped=true;epoch++;detailEpoch++;historyEpoch++;[listRead,detailRead,historyRead,mutation].forEach(c=>c?.abort())})
 return{page:shallowReadonly(page),pending:shallowReadonly(pending),error:shallowReadonly(error),cursors:shallowReadonly(cursors),selected:shallowReadonly(selected),detailPending:shallowReadonly(detailPending),detailError:shallowReadonly(detailError),history:shallowReadonly(history),historyNext:shallowReadonly(historyNext),historyPending:shallowReadonly(historyPending),historyError:shallowReadonly(historyError),historyLoaded:shallowReadonly(historyLoaded),busy:shallowReadonly(busy),unconfirmed:shallowReadonly(unconfirmed),actionError:shallowReadonly(actionError),refresh,search,next,previous,select,clearSelection,loadHistory,save,pendingInput,confirm,clearActionError}
}
export type IncidentTasksState=ReturnType<typeof useIncidentTasks>
