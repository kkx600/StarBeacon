import {onMounted,onScopeDispose,shallowReadonly,shallowRef,watch} from 'vue'
import {validProbeIdentity,type ProbeIdentityStatus} from '@starbeacon/shared/utils/probeIdentity.ts'
import {session} from '../../session'
export function useProbeIdentity(){
 const identity=shallowRef<ProbeIdentityStatus|null>(null),pending=shallowRef(false),error=shallowRef('')
 let controller:AbortController|undefined,stopped=false
 async function refresh(){
  if(stopped||session.current.value?.role!=='admin')return
  controller?.abort();const current=new AbortController();controller=current;identity.value=null;pending.value=true;error.value=''
  const timer=setTimeout(()=>current.abort(),10000)
  try{const raw=await session.api.request<unknown>('/identity',{signal:current.signal});if(stopped||controller!==current)return;if(current.signal.aborted)throw new Error('读取超时');if(!validProbeIdentity(raw))throw new Error('本机证书状态回执不完整，请核对采集器版本。');identity.value=raw}
  catch(e){if(!stopped&&controller===current)error.value=current.signal.aborted?'证书状态读取超时，请重试。':e instanceof Error?e.message:'证书状态读取失败，请重试。'}
  finally{clearTimeout(timer);if(controller===current){controller=undefined;pending.value=false}}
 }
 function reset(){controller?.abort();controller=undefined;identity.value=null;error.value='';pending.value=false}
 watch(()=>[session.current.value?.tenant_id,session.current.value?.id,session.current.value?.role].join('/'),()=>{reset();void refresh()})
 onMounted(refresh);onScopeDispose(()=>{stopped=true;reset()})
 return {identity:shallowReadonly(identity),pending:shallowReadonly(pending),error:shallowReadonly(error),refresh}
}
