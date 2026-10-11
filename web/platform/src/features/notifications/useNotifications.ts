import {onScopeDispose,shallowRef,watch,type Ref,shallowReadonly} from 'vue'
import {session} from '../../session'
import type {Channel,ChannelChange,Delivery} from './notifications'

export function useNotifications(view:Ref<string>){
  const channels=shallowRef<Channel[]>([]),deliveries=shallowRef<Delivery[]>([]),available=shallowRef(false),development=shallowRef(false)
  const pending=shallowRef(true),error=shallowRef(''),busy=shallowRef(false),actionError=shallowRef('')
  const filter=shallowRef(''),cursors=shallowRef(['']),nextCursor=shallowRef(''),generation=shallowRef(0)
  let stopped=false,actionController:AbortController|undefined
  const testKeys=new Map<string,string>()
  watch(view,()=>{filter.value='';cursors.value=[''];nextCursor.value='';actionError.value='';actionController?.abort();busy.value=false})
  const stop=watch([view,filter,cursors,generation],async(_v,_old,onCleanup)=>{
    const controller=new AbortController();onCleanup(()=>controller.abort());pending.value=true;error.value=''
    try{
      if(view.value==='channels'){
        const result=await session.api.request<{items:Channel[];available:boolean;development:boolean}>('/notifications/channels',{signal:controller.signal})
        if(!controller.signal.aborted){channels.value=result.items;available.value=result.available;development.value=result.development}
      }else{
        const query=new URLSearchParams({cursor:cursors.value.at(-1)??'',state:filter.value})
        const result=await session.api.request<{items:Delivery[];next_cursor:string}>('/notifications/deliveries?'+query,{signal:controller.signal})
        if(!controller.signal.aborted){deliveries.value=result.items;nextCursor.value=result.next_cursor}
      }
    }catch(e){if(!controller.signal.aborted)error.value=e instanceof Error?e.message:'通知数据读取失败'}finally{if(!controller.signal.aborted)pending.value=false}
  },{immediate:true})
  onScopeDispose(()=>{stopped=true;stop();actionController?.abort()})
  function refresh(){generation.value++}
  function search(state:string){filter.value=state;cursors.value=[''];refresh()}
  function next(){if(!pending.value&&nextCursor.value)cursors.value=[...cursors.value,nextCursor.value]}
  function previous(){if(!pending.value&&cursors.value.length>1)cursors.value=cursors.value.slice(0,-1)}
  async function mutate(path:string,body:unknown,headers?:Record<string,string>){
    if(stopped||busy.value)return false
    busy.value=true;actionError.value='';const controller=new AbortController();actionController=controller
    try{await session.api.request(path,{method:'POST',body,headers,signal:controller.signal});if(stopped||controller.signal.aborted)return false;refresh();return true}catch(e){if(!controller.signal.aborted)actionError.value=e instanceof Error?e.message:'通知操作失败';return false}finally{if(actionController===controller){actionController=undefined;busy.value=false}}
  }
  async function test(channel:Channel){
    const key=channel.id+'/'+channel.revision
    if(!testKeys.has(key))testKeys.set(key,crypto.randomUUID().replaceAll('-',''))
    const success=await mutate('/notifications/channels/'+encodeURIComponent(channel.id)+'/test',{}, {'Idempotency-Key':testKeys.get(key)!})
    if(success)testKeys.delete(key)
    return success
  }
  return {channels:shallowReadonly(channels),deliveries:shallowReadonly(deliveries),available:shallowReadonly(available),development:shallowReadonly(development),pending:shallowReadonly(pending),error:shallowReadonly(error),busy:shallowReadonly(busy),actionError:shallowReadonly(actionError),cursors:shallowReadonly(cursors),nextCursor:shallowReadonly(nextCursor),refresh,search,next,previous,test,save:(change:ChannelChange)=>mutate('/notifications/channels',change),retry:(delivery:Delivery)=>mutate('/notifications/deliveries/'+encodeURIComponent(delivery.id)+'/retry',{expected_version:delivery.version,acknowledge_duplicates:true}),clearActionError:()=>{actionError.value=''}}
}
