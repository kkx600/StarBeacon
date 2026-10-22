import {onScopeDispose,shallowReadonly,shallowRef,watch,type ShallowRef} from 'vue'
import {ApiError} from '@starbeacon/shared/api.ts'
import {session} from '../../session'
import type {IncidentRecord} from './incident'
import {sameNoteSpec,validNoteHistory,validNotePage,validNoteRecord,type IncidentNoteAttempt,type IncidentNoteInput,type IncidentNotePage,type IncidentNoteRecord} from './incidentNote'

export function useIncidentNotes(parent:ShallowRef<IncidentRecord|null>){
 const page=shallowRef<IncidentNotePage>({items:[],next_cursor:''}),pending=shallowRef(false),error=shallowRef(''),cursors=shallowRef(['']),status=shallowRef('')
 const selected=shallowRef<IncidentNoteRecord|null>(null),detailPending=shallowRef(false),detailError=shallowRef('')
 const history=shallowRef<IncidentNoteRecord[]>([]),historyNext=shallowRef(''),historyPending=shallowRef(false),historyError=shallowRef(''),historyLoaded=shallowRef(false)
 const busy=shallowRef(false),unconfirmed=shallowRef(false),actionError=shallowRef('')
 let stopped=false,readsOpen=true,epoch=0,detailEpoch=0,historyEpoch=0
 let listRead:AbortController|undefined,detailRead:AbortController|undefined,historyRead:AbortController|undefined,mutation:AbortController|undefined
 let attempt:(IncidentNoteAttempt&{key:string})|undefined
 const path=(caseID:string)=>'/incidents/'+encodeURIComponent(caseID)+'/notes'
 async function refresh(){
  if(stopped||!readsOpen||!parent.value)return
  const id=parent.value.id,token=++epoch;listRead?.abort();const controller=new AbortController();listRead=controller;pending.value=true;error.value=''
  try{const result=await session.api.request<unknown>(path(id)+'?'+new URLSearchParams({status:status.value,before:cursors.value.at(-1)??''}),{signal:controller.signal});if(stopped||token!==epoch)return;if(!validNotePage(result,id))throw new Error('调查笔记列表未能完整返回');page.value=result}
  catch(e){if(!controller.signal.aborted)error.value=e instanceof Error?e.message:'调查笔记读取失败'}finally{if(!stopped&&token===epoch)pending.value=false}
 }
 function search(value:string){status.value=value;cursors.value=[''];void refresh()}
 function next(){if(!pending.value&&page.value.next_cursor){cursors.value=[...cursors.value,page.value.next_cursor];void refresh()}}
 function previous(){if(!pending.value&&cursors.value.length>1){cursors.value=cursors.value.slice(0,-1);void refresh()}}
 function clearSelection(){detailEpoch++;historyEpoch++;detailRead?.abort();historyRead?.abort();selected.value=null;detailPending.value=false;detailError.value='';history.value=[];historyNext.value='';historyPending.value=false;historyError.value='';historyLoaded.value=false}
 function open(){if(stopped)return;readsOpen=true;if(!pending.value)void refresh()}
 // 关闭只结束读取；未知提交的原键与材料保留到明确确认或身份失效。
 function close(){readsOpen=false;epoch++;listRead?.abort();page.value={items:[],next_cursor:''};cursors.value=[''];pending.value=false;error.value='';clearSelection()}
 async function select(id:string){
  if(stopped||!readsOpen||!parent.value)return
  clearSelection();const caseID=parent.value.id,token=++detailEpoch,controller=new AbortController();detailRead=controller;detailPending.value=true
  try{const result=await session.api.request<unknown>(path(caseID)+'/'+encodeURIComponent(id),{signal:controller.signal});if(stopped||token!==detailEpoch)return;if(!validNoteRecord(result,caseID)||result.id!==id)throw new Error('调查笔记详情未能完整返回');selected.value=result}
  catch(e){if(!controller.signal.aborted)detailError.value=e instanceof Error?e.message:'调查笔记详情读取失败'}finally{if(!stopped&&token===detailEpoch)detailPending.value=false}
 }
 async function loadHistory(before=''){
  if(stopped||!readsOpen||!parent.value||!selected.value)return
  const anchor=selected.value,caseID=parent.value.id,id=anchor.id,token=++historyEpoch;historyRead?.abort();const controller=new AbortController();historyRead=controller;historyPending.value=true;historyError.value=''
  try{const result=await session.api.request<unknown>(path(caseID)+'/'+encodeURIComponent(id)+'/history?'+new URLSearchParams({before}),{signal:controller.signal});if(stopped||token!==historyEpoch)return;if(!validNoteHistory(result,caseID,id)||result.items.some(r=>r.author_id!==anchor.author_id||r.author_name!==anchor.author_name)||(before&&result.items.some(r=>r.revision>=Number(before))))throw new Error('调查笔记历史未能完整返回');history.value=before?[...history.value,...result.items.filter(r=>!history.value.some(old=>old.revision===r.revision))]:result.items;historyNext.value=result.next_cursor;historyLoaded.value=true}
  catch(e){if(!controller.signal.aborted)historyError.value=e instanceof Error?e.message:'调查笔记历史读取失败'}finally{if(!stopped&&token===historyEpoch)historyPending.value=false}
 }
 async function save(id:string,input:IncidentNoteInput){
  if(stopped||busy.value||!parent.value)return undefined
  if(attempt&&(attempt.id!==id||attempt.parent.id!==parent.value.id||JSON.stringify(attempt.input)!==JSON.stringify(input))){actionError.value='上次笔记操作尚未确认，请先核对原提交。';return undefined}
  if(!attempt)attempt={parent:structuredClone(parent.value),id,input:structuredClone(input),key:crypto.randomUUID()}
  const frozen=attempt,controller=new AbortController();mutation=controller;busy.value=true;actionError.value=''
  const timeout=setTimeout(()=>controller.abort(),30000)
  try{
   const result=await session.api.request<unknown>(path(frozen.parent.id)+(id?'/'+encodeURIComponent(id):''),{method:'POST',body:frozen.input,headers:{'Idempotency-Key':frozen.key},signal:controller.signal})
   if(stopped||mutation!==controller)return undefined
   if(controller.signal.aborted)throw new Error('笔记提交结果尚未确认，请核对原提交。')
   const wanted='expected_revision' in frozen.input?frozen.input.expected_revision+1:1
   if(!validNoteRecord(result,frozen.parent.id)||(id&&result.id!==id)||result.revision!==wanted||result.incident_revision!==frozen.input.incident_revision||result.actor_id!==session.current.value?.id||!sameNoteSpec(result.spec,frozen.input.spec)||(result.reason!==('reason' in frozen.input?frozen.input.reason:'建立调查笔记')))throw new Error('笔记提交回执不完整，请核对原提交。')
   attempt=undefined;unconfirmed.value=false;void refresh();return result
  }catch(e){if(!stopped&&mutation===controller){actionError.value=controller.signal.aborted?'笔记提交结果尚未确认，请核对原提交。':e instanceof Error?e.message:'笔记提交结果尚未确认';if(e instanceof ApiError&&e.status>=400&&e.status<500&&e.status!==408){attempt=undefined;unconfirmed.value=false}else unconfirmed.value=true}return undefined}
  finally{clearTimeout(timeout);if(mutation===controller){mutation=undefined;busy.value=false}}
 }
 function pendingInput():IncidentNoteAttempt|undefined{return attempt?structuredClone({parent:attempt.parent,id:attempt.id,input:attempt.input}):undefined}
 function confirm(){return attempt?save(attempt.id,attempt.input):Promise.resolve(undefined)}
 function clearActionError(){if(!attempt)actionError.value=''}
 watch([()=>parent.value?.id??'',()=>parent.value?.revision??0] as const,([id],[previousID])=>{if(id!==previousID)status.value='';epoch++;listRead?.abort();page.value={items:[],next_cursor:''};cursors.value=[''];pending.value=false;error.value='';clearSelection();if(parent.value)void refresh()},{immediate:true})
 watch(()=>`${session.current.value?.tenant_id??''}/${session.current.value?.id??''}/${session.current.value?.role??''}`,()=>{epoch++;listRead?.abort();mutation?.abort();mutation=undefined;attempt=undefined;page.value={items:[],next_cursor:''};status.value='';cursors.value=[''];pending.value=false;busy.value=false;unconfirmed.value=false;actionError.value='';error.value='';clearSelection()})
 onScopeDispose(()=>{stopped=true;epoch++;detailEpoch++;historyEpoch++;[listRead,detailRead,historyRead,mutation].forEach(c=>c?.abort())})
 return{page:shallowReadonly(page),pending:shallowReadonly(pending),error:shallowReadonly(error),cursors:shallowReadonly(cursors),status:shallowReadonly(status),selected:shallowReadonly(selected),detailPending:shallowReadonly(detailPending),detailError:shallowReadonly(detailError),history:shallowReadonly(history),historyNext:shallowReadonly(historyNext),historyPending:shallowReadonly(historyPending),historyError:shallowReadonly(historyError),historyLoaded:shallowReadonly(historyLoaded),busy:shallowReadonly(busy),unconfirmed:shallowReadonly(unconfirmed),actionError:shallowReadonly(actionError),refresh,search,next,previous,select,clearSelection,loadHistory,save,pendingInput,confirm,clearActionError,open,close}
}
export type IncidentNotesState=ReturnType<typeof useIncidentNotes>
