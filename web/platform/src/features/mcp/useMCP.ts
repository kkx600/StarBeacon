import {onScopeDispose,shallowReadonly,shallowRef,watch} from 'vue'
import {session} from '../../session'
import type {Binding,BindingChange,MCPInfo} from './mcp'
export function useMCP(){
  const items=shallowRef<Binding[]>([]),info=shallowRef<MCPInfo|null>(null),pending=shallowRef(true),error=shallowRef(''),busy=shallowRef(false),actionError=shallowRef(''),generation=shallowRef(0)
  let stopped=false,mutation:AbortController|undefined
  const stop=watch(generation,async(_value,_old,onCleanup)=>{
    const controller=new AbortController();onCleanup(()=>controller.abort());pending.value=true;error.value=''
    try{const[result,bindings]=await Promise.all([session.api.request<MCPInfo>('/mcp',{signal:controller.signal}),session.api.request<{items:Binding[]}>('/mcp/bindings',{signal:controller.signal})]);if(!controller.signal.aborted){info.value=result;items.value=bindings.items}}
    catch(e){if(!controller.signal.aborted)error.value=e instanceof Error?e.message:'MCP 服务读取失败'}finally{if(!controller.signal.aborted)pending.value=false}
  },{immediate:true})
  onScopeDispose(()=>{stopped=true;stop();mutation?.abort()})
  function refresh(){generation.value++}
  async function mutate<T>(path:string,method:'POST'|'DELETE',body:unknown){
    if(stopped||busy.value||(method==='POST'&&!info.value?.enabled))return undefined
    const controller=new AbortController();mutation=controller;busy.value=true;actionError.value=''
    try{const result=await session.api.request<T>(path,{method,body,signal:controller.signal});if(stopped||controller.signal.aborted)return undefined;refresh();return result}
    catch(e){if(!controller.signal.aborted)actionError.value=e instanceof Error?e.message:'MCP 服务身份保存失败';return undefined}finally{if(mutation===controller){mutation=undefined;busy.value=false}}
  }
  return{items:shallowReadonly(items),info:shallowReadonly(info),pending:shallowReadonly(pending),error:shallowReadonly(error),busy:shallowReadonly(busy),actionError:shallowReadonly(actionError),refresh,save:(change:BindingChange)=>mutate<Binding>('/mcp/bindings','POST',change),remove:(record:Binding)=>mutate<{ok:boolean}>('/mcp/bindings/'+encodeURIComponent(record.id),'DELETE',{expected_revision:record.revision}),clearActionError:()=>{actionError.value=''}}
}
