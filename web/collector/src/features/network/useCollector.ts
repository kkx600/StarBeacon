import { computed,onMounted,onScopeDispose,shallowRef,shallowReadonly,watch } from 'vue'
import type { HostHealth,NetworkInterface,CaptureConfig,CaptureSettings } from '@starbeacon/shared/types.ts'
import { session } from '../../session'
type Resource = 'health' | 'interfaces' | 'capture'
export function useCollector(options: {resources?:()=>readonly Resource[]} = {}){
  const health=shallowRef<HostHealth|null>(null),interfaces=shallowRef<NetworkInterface[]>([]),capture=shallowRef<CaptureConfig>({interfaces:[],status:'not_applied'}),pending=shallowRef(true),saving=shallowRef(false),error=shallowRef('')
  const resources=computed(()=>options.resources?.()??['health','interfaces','capture'])
  const scope=computed(()=>resources.value.join(','))
  let controller:AbortController|undefined
  let mutation:AbortController|undefined
  let disposed=false,mounted=false
  function reset(){
    controller?.abort();mutation?.abort();controller=undefined;mutation=undefined
    health.value=null;interfaces.value=[];capture.value={interfaces:[],status:'not_applied'}
    pending.value=false;saving.value=false;error.value=''
  }
  async function refresh(){
    if(disposed||saving.value)return
    if(!resources.value.length){pending.value=false;return}
    controller?.abort();const current=new AbortController();controller=current;pending.value=true;error.value=''
    const selected=resources.value
    try{
      const [h,i,c]=await Promise.all([
        selected.includes('health')?session.api.request<HostHealth>('/health',{signal:current.signal}):null,
        selected.includes('interfaces')?session.api.request<{items:NetworkInterface[]}>('/network/interfaces',{signal:current.signal}):null,
        selected.includes('capture')?session.api.request<CaptureConfig>('/capture-config',{signal:current.signal}):null,
      ])
      if(!current.signal.aborted){if(h)health.value=h;if(i)interfaces.value=i.items;if(c)capture.value=c}
    }catch(e){if(!current.signal.aborted)error.value=e instanceof Error?e.message:'读取失败'}
    finally{if(controller===current)pending.value=false}
  }
  async function save(settings:CaptureSettings|string[]){
    if(saving.value||disposed||!resources.value.includes('capture'))return false
    controller?.abort();const current=new AbortController();mutation=current;saving.value=true
    try{
      const value=await session.api.request<CaptureConfig>('/capture-config',{method:'PUT',body:Array.isArray(settings)?{interfaces:settings}:settings,signal:current.signal})
      if(current.signal.aborted)return false
      capture.value=value;return true
    }catch(cause){if(current.signal.aborted||disposed)return false;throw cause}
    finally{if(mutation===current)saving.value=false}
  }
  // 路径及权限变化清除旧观测，取消读取和写入，迟到回执不能恢复离开的页面。
  watch(scope,()=>{reset();if(mounted)void refresh()},{flush:'sync'})
  onMounted(()=>{mounted=true;void refresh()})
  onScopeDispose(()=>{disposed=true;reset()})
  return {health:shallowReadonly(health),interfaces:shallowReadonly(interfaces),capture:shallowReadonly(capture),pending:shallowReadonly(pending),saving:shallowReadonly(saving),error:shallowReadonly(error),refresh,save}
}
