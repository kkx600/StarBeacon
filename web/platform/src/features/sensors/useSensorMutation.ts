import {onScopeDispose,shallowReadonly,shallowRef,watch} from 'vue'
import {ApiError} from '@starbeacon/shared/api.ts'
import {session} from '../../session'
import {managementID,managementInputError,validManagementReceipt,type ManagementInput} from './management'

export function useSensorMutation(){
 const busy=shallowRef(false),unconfirmed=shallowRef(false),error=shallowRef('')
 let stopped=false,mutation:AbortController|undefined,attempt:{kind:'group'|'metadata';id:string;input:ManagementInput;key:string}|undefined
 async function save(kind:'group'|'metadata',id:string,input:ManagementInput){
  if(stopped||busy.value)return undefined
  if(!managementID(id)||(kind==='group')!==('id' in input)||'id' in input&&input.id!==id){error.value='管理对象或操作类型无效。';return undefined}
  if(attempt&&(attempt.kind!==kind||attempt.id!==id||JSON.stringify(attempt.input)!==JSON.stringify(input))){error.value='上次操作结果尚未确认，请先核对原提交。';return undefined}
  const invalid=managementInputError(input);if(invalid){error.value=invalid;return undefined}
  if(!attempt)attempt={kind,id,input:structuredClone(input),key:crypto.randomUUID()}
  const frozen=attempt,controller=new AbortController();mutation=controller;busy.value=true;error.value=''
  const timer=setTimeout(()=>controller.abort(),30000)
  try{
   const value=await session.api.request<unknown>(kind==='group'?'/sensor-groups':'/sensors/'+encodeURIComponent(id)+'/metadata',{method:kind==='group'?'POST':'PUT',body:frozen.input,headers:{'Idempotency-Key':frozen.key},signal:controller.signal})
   if(stopped||mutation!==controller)return undefined
   if(controller.signal.aborted)throw new Error('提交结果尚未确认，请核对原提交。')
   if(!validManagementReceipt(value,kind,id,input))throw new Error('管理操作回执不完整，请核对原提交。')
   attempt=undefined;unconfirmed.value=false;return value
  }catch(e){if(!stopped&&mutation===controller){error.value=controller.signal.aborted?'提交结果尚未确认，请核对原提交。':e instanceof Error?e.message:'管理操作结果尚未确认';if(e instanceof ApiError&&e.status>=400&&e.status<500&&e.status!==408){attempt=undefined;unconfirmed.value=false}else unconfirmed.value=true}return undefined}
  finally{clearTimeout(timer);if(mutation===controller){mutation=undefined;busy.value=false}}
 }
 function confirm(){return attempt?save(attempt.kind,attempt.id,attempt.input):Promise.resolve(undefined)}
 function clearError(){if(!attempt)error.value=''}
 function pendingInput(){return attempt?structuredClone(attempt):undefined}
 onScopeDispose(()=>{stopped=true;mutation?.abort();attempt=undefined})
 watch(()=>[session.current.value?.tenant_id,session.current.value?.id].join('/'),()=>{mutation?.abort();mutation=undefined;attempt=undefined;busy.value=false;unconfirmed.value=false;error.value=''})
 return {busy:shallowReadonly(busy),unconfirmed:shallowReadonly(unconfirmed),error:shallowReadonly(error),save,confirm,clearError,pendingInput}
}
