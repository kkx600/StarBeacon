import {onScopeDispose,shallowReadonly,shallowRef,watch} from 'vue'
import {ApiError} from '@starbeacon/shared/api.ts'
import {session} from '../../session'
import {createEnrollmentInput,validEnrollment,enrollmentError,type Enrollment,type EnrollmentDraft,type EnrollmentInput} from './pki'

export function useProbeEnrollment(){
 const busy=shallowRef(false),unconfirmed=shallowRef(false),error=shallowRef(''),receipt=shallowRef<Enrollment|null>(null),token=shallowRef('')
 const frozenDraft=shallowRef<EnrollmentDraft|null>(null)
 let attempt:EnrollmentInput|undefined,stopped=false,controller:AbortController|undefined
 async function submit(draft?:EnrollmentDraft){
  if(stopped||busy.value||receipt.value||session.current.value?.role!=='admin')return
  if(attempt&&draft&&JSON.stringify(draft)!==JSON.stringify(frozenDraft.value)){error.value='原注册提交尚未确认，请先核对原提交。';return}
  if(!attempt){if(!draft||enrollmentError(draft)){error.value=draft?enrollmentError(draft):'请填写注册信息。';return}try{attempt=createEnrollmentInput(session.current.value?.tenant_id??'',draft);frozenDraft.value={...draft}}catch{error.value='无法创建安全注册凭据，请核对当前登录和浏览器环境。';return}}
  const frozen=attempt,current=new AbortController();controller=current;busy.value=true;error.value=''
  const timer=setTimeout(()=>current.abort(),30000)
  try{
   const raw=await session.api.request<unknown>('/sensor-enrollments',{method:'POST',body:frozen,signal:current.signal})
   if(stopped||controller!==current)return
   const parts=frozen.token.split('.')
   if(current.signal.aborted||!validEnrollment(raw)||raw.id!==parts[4]||raw.sensor_id!==parts[2]||raw.registration_id!==parts[3])throw new Error('注册提交结果尚未确认，请核对原提交。')
   if(raw.revoked||Date.parse(raw.expires_at)<=Date.now())throw new ApiError(410,'enrollment_unavailable','原注册凭据已到期或撤销，请创建独立凭据。')
   receipt.value=raw;token.value=frozen.token;attempt=undefined;unconfirmed.value=false
  }catch(e){if(!stopped&&controller===current){error.value=current.signal.aborted?'注册提交结果尚未确认，请核对原提交。':e instanceof Error?e.message:'注册提交结果尚未确认。';if(e instanceof ApiError&&e.status>=400&&e.status<500&&e.status!==408){attempt=undefined;frozenDraft.value=null;unconfirmed.value=false}else unconfirmed.value=true}}
  finally{clearTimeout(timer);if(controller===current){controller=undefined;busy.value=false}}
 }
 function reset(){controller?.abort();controller=undefined;attempt=undefined;frozenDraft.value=null;token.value='';receipt.value=null;busy.value=false;unconfirmed.value=false;error.value=''}
 watch(()=>[session.current.value?.tenant_id,session.current.value?.id,session.current.value?.role].join('/'),reset)
 onScopeDispose(()=>{stopped=true;reset()})
 return {busy:shallowReadonly(busy),unconfirmed:shallowReadonly(unconfirmed),error:shallowReadonly(error),receipt:shallowReadonly(receipt),token:shallowReadonly(token),draft:shallowReadonly(frozenDraft),submit,reset}
}
