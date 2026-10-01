import { onMounted,onScopeDispose,shallowRef,shallowReadonly } from 'vue'
import type { HostHealth,NetworkInterface,CaptureConfig } from '@starbeacon/shared/types.ts'
import { session } from '../../session'
export function useCollector(){
  const health=shallowRef<HostHealth|null>(null),interfaces=shallowRef<NetworkInterface[]>([]),capture=shallowRef<CaptureConfig>({interfaces:[],status:'not_applied'}),pending=shallowRef(true),saving=shallowRef(false),error=shallowRef('')
  let controller:AbortController|undefined
  async function refresh(){controller?.abort();const current=new AbortController();controller=current;pending.value=true;error.value='';try{const [h,i,c]=await Promise.all([session.api.request<HostHealth>('/health',{signal:current.signal}),session.api.request<{items:NetworkInterface[]}>('/network/interfaces',{signal:current.signal}),session.api.request<CaptureConfig>('/capture-config',{signal:current.signal})]);if(!current.signal.aborted){health.value=h;interfaces.value=i.items;capture.value=c}}catch(e){if(!current.signal.aborted)error.value=e instanceof Error?e.message:'读取失败'}finally{if(controller===current)pending.value=false}}
  async function save(names:string[]){saving.value=true;try{capture.value=await session.api.request<CaptureConfig>('/capture-config',{method:'PUT',body:{interfaces:names}})}finally{saving.value=false}}
  onMounted(refresh);onScopeDispose(()=>controller?.abort())
  return {health:shallowReadonly(health),interfaces:shallowReadonly(interfaces),capture:shallowReadonly(capture),pending:shallowReadonly(pending),saving:shallowReadonly(saving),error:shallowReadonly(error),refresh,save}
}
