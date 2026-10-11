import { onMounted,onScopeDispose,shallowRef,shallowReadonly } from 'vue'
import type { HostHealth,NetworkInterface,CaptureConfig,CaptureSettings } from '@starbeacon/shared/types.ts'
import { session } from '../../session'
export function useCollector(){
  const health=shallowRef<HostHealth|null>(null),interfaces=shallowRef<NetworkInterface[]>([]),capture=shallowRef<CaptureConfig>({interfaces:[],status:'not_applied'}),pending=shallowRef(true),saving=shallowRef(false),error=shallowRef('')
  let controller:AbortController|undefined
  let mutation:AbortController|undefined
  let disposed=false
  async function refresh(){controller?.abort();const current=new AbortController();controller=current;pending.value=true;error.value='';try{const [h,i,c]=await Promise.all([session.api.request<HostHealth>('/health',{signal:current.signal}),session.api.request<{items:NetworkInterface[]}>('/network/interfaces',{signal:current.signal}),session.api.request<CaptureConfig>('/capture-config',{signal:current.signal})]);if(!current.signal.aborted){health.value=h;interfaces.value=i.items;capture.value=c}}catch(e){if(!current.signal.aborted)error.value=e instanceof Error?e.message:'读取失败'}finally{if(controller===current)pending.value=false}}
  async function save(settings:CaptureSettings|string[]){if(saving.value||disposed)return false;controller?.abort();const current=new AbortController();mutation=current;saving.value=true;try{const value=await session.api.request<CaptureConfig>('/capture-config',{method:'PUT',body:Array.isArray(settings)?{interfaces:settings}:settings,signal:current.signal});if(current.signal.aborted)return false;capture.value=value;return true}finally{if(mutation===current)saving.value=false}}
  onMounted(refresh);onScopeDispose(()=>{disposed=true;controller?.abort();mutation?.abort()})
  return {health:shallowReadonly(health),interfaces:shallowReadonly(interfaces),capture:shallowReadonly(capture),pending:shallowReadonly(pending),saving:shallowReadonly(saving),error:shallowReadonly(error),refresh,save}
}
