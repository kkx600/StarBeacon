import {onScopeDispose,shallowReadonly,shallowRef,watch} from 'vue'
import {ApiError} from '@starbeacon/shared/api.ts'
import {session} from '../../session'
import {incidentID,validIncidentPage,validIncidentRecord,validIncidentAssignees,validIncidentHistory,sameIncidentSpec,type IncidentAssignee,type IncidentInput,type IncidentPage,type IncidentRecord} from './incident'

export function useIncidents(){
 const page=shallowRef<IncidentPage>({items:[],next_cursor:''}),pending=shallowRef(false),error=shallowRef(''),cursors=shallowRef([''])
 const selected=shallowRef<IncidentRecord|null>(null),detailPending=shallowRef(false),detailError=shallowRef(''),history=shallowRef<IncidentRecord[]>([]),historyNext=shallowRef(''),historyPending=shallowRef(false),historyError=shallowRef('')
 const assignees=shallowRef<IncidentAssignee[]>([]),assigneeError=shallowRef(''),assigneePending=shallowRef(false),busy=shallowRef(false),unconfirmed=shallowRef(false),actionError=shallowRef(''),linkedID=shallowRef('')
 let stopped=false,listEpoch=0,detailEpoch=0,historyEpoch=0,assigneeEpoch=0,selectedID='',status='',severity=''
 let listRead:AbortController|undefined,detailRead:AbortController|undefined,historyRead:AbortController|undefined,ownerRead:AbortController|undefined,mutation:AbortController|undefined
 let attempt:{id:string;input:IncidentInput;key:string}|undefined
 async function refresh(){
  if(stopped)return
  const epoch=++listEpoch;listRead?.abort();const controller=new AbortController();listRead=controller;pending.value=true;error.value=''
  try{const result=await session.api.request<unknown>('/incidents?'+new URLSearchParams({status,severity,before:cursors.value.at(-1)??''}),{signal:controller.signal});if(stopped||epoch!==listEpoch)return;if(!validIncidentPage(result))throw new Error('事件列表未能完整返回');page.value=result}
  catch(e){if(!controller.signal.aborted)error.value=e instanceof Error?e.message:'事件列表读取失败'}finally{if(!stopped&&epoch===listEpoch)pending.value=false}
 }
 function search(s:string,v:string){if(stopped)return;status=s;severity=v;cursors.value=[''];void refresh()}
 function next(){if(!pending.value&&page.value.next_cursor){cursors.value=[...cursors.value,page.value.next_cursor];void refresh()}}
 function previous(){if(!pending.value&&cursors.value.length>1){cursors.value=cursors.value.slice(0,-1);void refresh()}}
 async function select(id:string){
  if(stopped)return
  const epoch=++detailEpoch;selectedID=id;detailRead?.abort();historyRead?.abort();historyEpoch++;history.value=[];historyNext.value='';historyError.value='';selected.value=null;detailPending.value=true;detailError.value=''
  const controller=new AbortController();detailRead=controller
  try{const result=await session.api.request<unknown>('/incidents/'+encodeURIComponent(id),{signal:controller.signal});if(stopped||epoch!==detailEpoch)return;if(!validIncidentRecord(result)||result.id!==id)throw new Error('事件详情未能完整返回');selected.value=result}
  catch(e){if(!controller.signal.aborted)detailError.value=e instanceof Error?e.message:'事件详情读取失败'}finally{if(!stopped&&epoch===detailEpoch)detailPending.value=false}
 }
 function clearSelection(){selectedID='';detailEpoch++;historyEpoch++;detailRead?.abort();historyRead?.abort();selected.value=null;detailPending.value=false;historyPending.value=false;detailError.value='';history.value=[];historyNext.value='';historyError.value=''}
 async function loadHistory(before=''){
  if(stopped||!selectedID)return
  const id=selectedID,epoch=++historyEpoch;historyRead?.abort();const controller=new AbortController();historyRead=controller;historyPending.value=true;historyError.value=''
  try{const result=await session.api.request<unknown>('/incidents/'+encodeURIComponent(id)+'/history?'+new URLSearchParams({before}),{signal:controller.signal});if(stopped||epoch!==historyEpoch)return;if(!validIncidentHistory(result,id)||(before&&result.items.some(r=>r.revision>=Number(before))))throw new Error('调查时间线未能完整返回');history.value=before?[...history.value,...result.items.filter(r=>!history.value.some(old=>old.revision===r.revision))]:result.items;historyNext.value=result.next_cursor}
  catch(e){if(!controller.signal.aborted)historyError.value=e instanceof Error?e.message:'调查时间线读取失败'}finally{if(!stopped&&epoch===historyEpoch)historyPending.value=false}
 }
 async function loadAssignees(){
  if(stopped)return
  const epoch=++assigneeEpoch;ownerRead?.abort();const controller=new AbortController();ownerRead=controller;assigneePending.value=true;assigneeError.value=''
  try{const result=await session.api.request<unknown>('/incidents/assignees',{signal:controller.signal});if(stopped||epoch!==assigneeEpoch)return;if(!validIncidentAssignees(result))throw new Error('责任人列表未能完整返回');assignees.value=result.items}
  catch(e){if(!controller.signal.aborted)assigneeError.value=e instanceof Error?e.message:'责任人列表读取失败'}finally{if(!stopped&&epoch===assigneeEpoch)assigneePending.value=false}
 }
 async function save(id:string,input:IncidentInput){
  if(stopped||busy.value)return undefined
  if(attempt&&(attempt.id!==id||JSON.stringify(attempt.input)!==JSON.stringify(input))){actionError.value='上次操作结果尚未确认，请先核对原提交。';return undefined}
  if(!attempt)attempt={id,input:structuredClone(input),key:crypto.randomUUID()}
  const frozen=attempt,controller=new AbortController();mutation=controller;busy.value=true;actionError.value='';linkedID.value=''
  const timeout=setTimeout(()=>controller.abort(),30000)
  try{
   const result=await session.api.request<unknown>('/incidents'+(id?'/'+encodeURIComponent(id):''),{method:'POST',body:frozen.input,headers:{'Idempotency-Key':frozen.key},signal:controller.signal})
   if(stopped||mutation!==controller)return undefined
   if(controller.signal.aborted){unconfirmed.value=true;actionError.value='提交结果尚未确认，请核对原提交。';return undefined}
   const revision='expected_revision' in frozen.input?frozen.input.expected_revision+1:1,refs='alerts' in frozen.input?frozen.input.alerts:frozen.input.add_alerts
   if(!validIncidentRecord(result)||(id&&result.id!==id)||result.revision!==revision||result.actor_id!==session.current.value?.id||!sameIncidentSpec(result.spec,frozen.input.spec)||refs.some(ref=>!result.alerts.some(a=>a.event_id===ref.event_id&&a.raw_sha256===ref.raw_sha256)))throw new Error('事件操作回执不完整，请核对原提交。')
   attempt=undefined;unconfirmed.value=false;selected.value=result;selectedID=result.id;history.value=[];historyNext.value='';void refresh();return result
  }catch(e){if(!stopped&&mutation===controller){actionError.value=controller.signal.aborted?'提交结果尚未确认，请核对原提交。':e instanceof Error?e.message:'事件操作结果尚未确认';if(e instanceof ApiError&&e.status>=400&&e.status<500&&e.status!==408){attempt=undefined;unconfirmed.value=false;if(e.code==='alert_already_linked'&&incidentID(e.details.related_incident_id))linkedID.value=e.details.related_incident_id}else unconfirmed.value=true}return undefined}
  finally{clearTimeout(timeout);if(mutation===controller){mutation=undefined;busy.value=false}}
 }
 function confirm(){return attempt?save(attempt.id,attempt.input):Promise.resolve(undefined)}
 function pendingInput(){return attempt?structuredClone({id:attempt.id,input:attempt.input}):undefined}
 function clearActionError(){if(!attempt){actionError.value='';linkedID.value=''}}
 onScopeDispose(()=>{stopped=true;listEpoch++;detailEpoch++;historyEpoch++;assigneeEpoch++;[listRead,detailRead,historyRead,ownerRead,mutation].forEach(c=>c?.abort())})
 watch(()=>session.current.value?.tenant_id,()=>{listEpoch++;assigneeEpoch++;listRead?.abort();ownerRead?.abort();mutation?.abort();mutation=undefined;attempt=undefined;clearSelection();page.value={items:[],next_cursor:''};assignees.value=[];cursors.value=[''];busy.value=false;unconfirmed.value=false;pending.value=false;assigneePending.value=false;actionError.value='';linkedID.value='';if(session.current.value)void refresh()})
 void refresh()
 return{page:shallowReadonly(page),pending:shallowReadonly(pending),error:shallowReadonly(error),cursors:shallowReadonly(cursors),selected:shallowReadonly(selected),detailPending:shallowReadonly(detailPending),detailError:shallowReadonly(detailError),history:shallowReadonly(history),historyNext:shallowReadonly(historyNext),historyPending:shallowReadonly(historyPending),historyError:shallowReadonly(historyError),assignees:shallowReadonly(assignees),assigneeError:shallowReadonly(assigneeError),assigneePending:shallowReadonly(assigneePending),busy:shallowReadonly(busy),unconfirmed:shallowReadonly(unconfirmed),actionError:shallowReadonly(actionError),linkedID:shallowReadonly(linkedID),refresh,search,next,previous,select,reloadDetail:()=>selectedID?select(selectedID):Promise.resolve(),clearSelection,loadHistory,loadAssignees,save,confirm,pendingInput,clearActionError}
}
