import {onScopeDispose,shallowReadonly,shallowRef,watch} from 'vue'
import {ApiError} from '@starbeacon/shared/api.ts'
import {session} from '../../session'
import {validCertificate,validEnrollment,type ProbeCertificate,type Enrollment} from './pki'
export type RevocationTarget={kind:'enrollment';record:Enrollment}|{kind:'certificate';record:ProbeCertificate}
export function useProbeRevocation(){
 const target=shallowRef<RevocationTarget|null>(null),busy=shallowRef(false),unconfirmed=shallowRef(false),error=shallowRef(''),result=shallowRef<ProbeCertificate|'revoked'|null>(null)
 let stopped=false,controller:AbortController|undefined
 function choose(value:RevocationTarget){if(stopped||session.current.value?.role!=='admin'||busy.value||unconfirmed.value)return false;if(value.kind==='enrollment'?!validEnrollment(value.record):!validCertificate(value.record))return false;target.value=value.kind==='enrollment'?{kind:'enrollment',record:{...value.record}}:{kind:'certificate',record:{...value.record}};result.value=null;error.value='';return true}
 async function submit(){
  if(stopped||busy.value||!target.value||result.value||session.current.value?.role!=='admin')return
  const current=new AbortController(),frozen=target.value;controller=current;busy.value=true;error.value=''
  const timer=setTimeout(()=>current.abort(),20000)
  try{
   const path=(frozen.kind==='enrollment'?'/sensor-enrollments/':'/sensor-certificates/')+encodeURIComponent(frozen.record.id)+'/revoke'
   const raw=await session.api.request<unknown>(path,{method:'POST',body:{},signal:current.signal})
   if(stopped||controller!==current)return
   if(current.signal.aborted)throw new Error('撤销结果尚未确认，请核对原操作。')
   if(frozen.kind==='enrollment'){if(!raw||typeof raw!=='object'||(raw as {revoked?:unknown}).revoked!==true)throw new Error('注册令牌撤销回执不完整。');result.value='revoked'}
   else{if(!validCertificate(raw)||raw.id!==frozen.record.id||raw.fingerprint_sha256!==frozen.record.fingerprint_sha256||!raw.revoked_at)throw new Error('证书吊销回执未绑定原指纹。');result.value=raw}
   unconfirmed.value=false
  }catch(e){if(!stopped&&controller===current){error.value=current.signal.aborted?'撤销结果尚未确认，请核对原操作。':e instanceof Error?e.message:'撤销结果尚未确认。';unconfirmed.value=!(e instanceof ApiError&&e.status>=400&&e.status<500&&e.status!==408)}}
  finally{clearTimeout(timer);if(controller===current){controller=undefined;busy.value=false}}
 }
 function reset(){controller?.abort();controller=undefined;target.value=null;result.value=null;busy.value=false;unconfirmed.value=false;error.value=''}
 watch(()=>[session.current.value?.tenant_id,session.current.value?.id,session.current.value?.role].join('/'),reset)
 onScopeDispose(()=>{stopped=true;reset()})
 return {target:shallowReadonly(target),busy:shallowReadonly(busy),unconfirmed:shallowReadonly(unconfirmed),error:shallowReadonly(error),result:shallowReadonly(result),choose,submit,reset}
}
