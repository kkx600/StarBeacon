import {computed,onScopeDispose,shallowReadonly,shallowRef,watch} from 'vue'
import type {CaptureConfig,HostHealth} from '@starbeacon/shared/types.ts'
import {session} from '../../session'

export function useCollectorDiagnostics(options:{enabled:()=>boolean;open:()=>boolean}){
  const health=shallowRef<HostHealth|null>(null),capture=shallowRef<CaptureConfig>(),pending=shallowRef(false),error=shallowRef('')
  const enabled=computed(options.enabled),open=computed(options.open)
  let controller:AbortController|undefined,disposed=false
  function cancel(){controller?.abort();controller=undefined;pending.value=false}
  function reset(){cancel();health.value=null;capture.value=undefined;error.value=''}
  async function refresh(){
    if(disposed||!enabled.value||!open.value)return
    cancel();const current=new AbortController();controller=current;pending.value=true;error.value=''
    try{
      const [observedHealth,observedCapture]=await Promise.all([
        session.api.request<HostHealth>('/health',{signal:current.signal}),
        session.api.request<CaptureConfig>('/capture-config',{signal:current.signal}),
      ])
      // 诊断快照整体更新，部分失败不能拼接出不同观测批次，也不能覆盖主表单草稿。
      if(!current.signal.aborted&&controller===current){health.value=observedHealth;capture.value=observedCapture}
    }catch(cause){
      if(!current.signal.aborted&&controller===current){error.value=cause instanceof Error?cause.message:'诊断观测读取失败，请稍后重试。';current.abort()}
    }finally{if(controller===current){controller=undefined;pending.value=false}}
  }
  watch([enabled,open],([allowed,visible])=>{if(!allowed)reset();else if(visible)void refresh();else cancel()},{immediate:true,flush:'sync'})
  onScopeDispose(()=>{disposed=true;reset()})
  return {health:shallowReadonly(health),capture:shallowReadonly(capture),pending:shallowReadonly(pending),error:shallowReadonly(error),refresh}
}
