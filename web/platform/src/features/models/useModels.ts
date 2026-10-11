import {onScopeDispose,shallowRef,shallowReadonly,watch} from 'vue'
import {session} from '../../session'
import type {ModelChange,ModelProvider,ModelCheck} from './models'

export function useModels(){
  const items=shallowRef<ModelProvider[]>([]),available=shallowRef(false),pending=shallowRef(true),error=shallowRef(''),busy=shallowRef(false),actionError=shallowRef(''),generation=shallowRef(0)
  const keys=new Map<string,{revision:number;key:string}>()
  let stopped=false,mutation:AbortController|undefined
  const stop=watch(generation,async(_value,_old,onCleanup)=>{
    const controller=new AbortController();onCleanup(()=>controller.abort());pending.value=true;error.value=''
    try{
      const result=await session.api.request<{items:ModelProvider[];available:boolean}>('/models/providers',{signal:controller.signal})
      if(!controller.signal.aborted){items.value=result.items;available.value=result.available}
    }catch(e){if(!controller.signal.aborted)error.value=e instanceof Error?e.message:'模型配置读取失败'}finally{if(!controller.signal.aborted)pending.value=false}
  },{immediate:true})
  onScopeDispose(()=>{stopped=true;stop();mutation?.abort();keys.clear()})
  function refresh(){generation.value++}
  async function mutate<T>(path:string,body:unknown,headers?:Record<string,string>):Promise<T|undefined>{
    if(stopped||busy.value)return undefined
    const controller=new AbortController();mutation=controller;busy.value=true;actionError.value=''
    try{
      const result=await session.api.request<T>(path,{method:'POST',body,headers,signal:controller.signal})
      if(stopped||controller.signal.aborted)return undefined
      refresh();return result
    }catch(e){if(!controller.signal.aborted)actionError.value=e instanceof Error?e.message:'模型操作失败';return undefined}finally{if(mutation===controller){mutation=undefined;busy.value=false}}
  }
  async function test(provider:ModelProvider){
    let entry=keys.get(provider.id)
    if(!entry||entry.revision!==provider.revision){entry={revision:provider.revision,key:crypto.randomUUID().replaceAll('-','')};keys.set(provider.id,entry)}
    const result=await mutate<ModelCheck>('/models/providers/'+encodeURIComponent(provider.id)+'/test',{expected_revision:provider.revision},{'Idempotency-Key':entry.key})
    if(result&&result.state!=='running')keys.delete(provider.id)
    return result
  }
  return{items:shallowReadonly(items),available:shallowReadonly(available),pending:shallowReadonly(pending),error:shallowReadonly(error),busy:shallowReadonly(busy),actionError:shallowReadonly(actionError),refresh,test,save:(change:ModelChange)=>mutate<ModelProvider>('/models/providers',change),clearActionError:()=>{actionError.value=''}}
}
