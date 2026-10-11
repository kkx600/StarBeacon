import {onScopeDispose,shallowReadonly,shallowRef,watch} from 'vue'
import {ApiError} from '@starbeacon/shared/api.ts'
import {session} from '../../session'
import {validUserPage,validUserRecord,type UserInput,type UserPage,type UserRecord} from './user'

export function useUsers(){
 const page=shallowRef<UserPage>({items:[],next_cursor:''}),pending=shallowRef(false),error=shallowRef(''),cursors=shallowRef([''])
 const selected=shallowRef<UserRecord|null>(null),detailPending=shallowRef(false),detailError=shallowRef(''),busy=shallowRef(false),unconfirmed=shallowRef(false),actionError=shallowRef('')
 let stopped=false,listEpoch=0,detailEpoch=0,selectedID='',role='',active=''
 let listRead:AbortController|undefined,detailRead:AbortController|undefined,mutation:AbortController|undefined
 let attempt:{id:string;input:UserInput;key:string}|undefined
 async function refresh(){
  if(stopped)return
  const epoch=++listEpoch;listRead?.abort();const controller=new AbortController();listRead=controller;pending.value=true;error.value=''
  try{const result=await session.api.request<unknown>('/users?'+new URLSearchParams({role,active,before:cursors.value.at(-1)??''}),{signal:controller.signal});if(stopped||epoch!==listEpoch)return;if(!validUserPage(result))throw new Error('用户列表未能完整返回');page.value=result}
  catch(e){if(!stopped&&epoch===listEpoch&&!controller.signal.aborted)error.value=e instanceof Error?e.message:'用户列表读取失败'}finally{if(!stopped&&epoch===listEpoch)pending.value=false}
 }
 function search(r:string,a:string){if(stopped)return;role=r;active=a;cursors.value=[''];void refresh()}
 function next(){if(!pending.value&&page.value.next_cursor){cursors.value=[...cursors.value,page.value.next_cursor];void refresh()}}
 function previous(){if(!pending.value&&cursors.value.length>1){cursors.value=cursors.value.slice(0,-1);void refresh()}}
 async function select(id:string){
  if(stopped)return
  const epoch=++detailEpoch;selectedID=id;detailRead?.abort();const controller=new AbortController();detailRead=controller;selected.value=null;detailPending.value=true;detailError.value=''
  try{const result=await session.api.request<unknown>('/users/'+encodeURIComponent(id),{signal:controller.signal});if(stopped||epoch!==detailEpoch)return;if(!validUserRecord(result)||result.id!==id)throw new Error('用户详情未能完整返回');selected.value=result}
  catch(e){if(!stopped&&epoch===detailEpoch&&!controller.signal.aborted)detailError.value=e instanceof Error?e.message:'用户详情读取失败'}finally{if(!stopped&&epoch===detailEpoch)detailPending.value=false}
 }
 function clearSelection(){selectedID='';detailEpoch++;detailRead?.abort();selected.value=null;detailPending.value=false;detailError.value=''}
 async function save(id:string,input:UserInput){
  if(stopped||busy.value)return undefined
  if(attempt&&(attempt.id!==id||JSON.stringify(attempt.input)!==JSON.stringify(input))){actionError.value='上次操作结果尚未确认，请先核对原提交。';return undefined}
  if(!attempt)attempt={id,input:structuredClone(input),key:crypto.randomUUID()}
  const frozen=attempt,controller=new AbortController();mutation=controller;busy.value=true;actionError.value=''
  const timer=setTimeout(()=>controller.abort(),30000)
  try{
   const result=await session.api.request<unknown>('/users'+(id?'/'+encodeURIComponent(id):''),{method:id?'PATCH':'POST',body:frozen.input,headers:{'Idempotency-Key':frozen.key},signal:controller.signal})
   if(stopped||mutation!==controller)return undefined
   if(controller.signal.aborted){unconfirmed.value=true;actionError.value='提交结果尚未确认，请核对原提交。';return undefined}
   const revision='expected_revision' in frozen.input?frozen.input.expected_revision+1:1
   if(!validUserRecord(result)||(id&&result.id!==id)||result.revision!==revision||result.role!==frozen.input.role||result.active!==frozen.input.active||('username' in frozen.input&&result.username!==frozen.input.username))throw new Error('用户操作回执不完整，请核对原提交。')
   attempt=undefined;unconfirmed.value=false;void refresh();return result
  }catch(e){if(!stopped&&mutation===controller){actionError.value=controller.signal.aborted?'提交结果尚未确认，请核对原提交。':e instanceof Error?e.message:'用户操作结果尚未确认';if(e instanceof ApiError&&e.status>=400&&e.status<500&&e.status!==408){attempt=undefined;unconfirmed.value=false}else unconfirmed.value=true}return undefined}
  finally{clearTimeout(timer);if(mutation===controller){mutation=undefined;busy.value=false}}
 }
 function confirm(){return attempt?save(attempt.id,attempt.input):Promise.resolve(undefined)}
 function pendingInput(){return attempt?structuredClone({id:attempt.id,input:attempt.input}):undefined}
 function clearActionError(){if(!attempt)actionError.value=''}
 onScopeDispose(()=>{stopped=true;listEpoch++;detailEpoch++;[listRead,detailRead,mutation].forEach(c=>c?.abort());attempt=undefined})
 watch(()=>[session.current.value?.tenant_id,session.current.value?.id].join('/'),()=>{listEpoch++;listRead?.abort();mutation?.abort();mutation=undefined;attempt=undefined;clearSelection();page.value={items:[],next_cursor:''};cursors.value=[''];busy.value=false;unconfirmed.value=false;pending.value=false;actionError.value='';if(session.current.value)void refresh()})
 void refresh()
 return{page:shallowReadonly(page),pending:shallowReadonly(pending),error:shallowReadonly(error),cursors:shallowReadonly(cursors),selected:shallowReadonly(selected),detailPending:shallowReadonly(detailPending),detailError:shallowReadonly(detailError),busy:shallowReadonly(busy),unconfirmed:shallowReadonly(unconfirmed),actionError:shallowReadonly(actionError),refresh,search,next,previous,select,reloadDetail:()=>selectedID?select(selectedID):Promise.resolve(),clearSelection,save,confirm,pendingInput,clearActionError}
}
