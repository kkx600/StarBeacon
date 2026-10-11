import {onScopeDispose,shallowRef,watch} from 'vue'
import type {ApiClient} from './api'
import {validPacketPage,validPacketRecord,type PacketPage,type PacketRecord} from './packetArchives'

export function usePacketArchives(api:ApiClient,local=false){
  const page=shallowRef<PacketPage>({items:[],available:false}),pending=shallowRef(true),error=shallowRef(''),query=shallowRef({sensor:'',cursor:'',generation:0}),history=shallowRef<string[]>([])
  const selected=shallowRef<PacketRecord|null>(null),detailPending=shallowRef(false),detailError=shallowRef('')
  let detailController:AbortController|undefined
  const stop=watch(query,async(requested,_old,onCleanup)=>{
    const controller=new AbortController();onCleanup(()=>controller.abort());pending.value=true;error.value=''
    const params=new URLSearchParams();if(!local&&requested.sensor)params.set('sensor_id',requested.sensor);if(!local&&requested.cursor)params.set('cursor',requested.cursor)
    try{const value=await api.request<unknown>('/packet-archives'+(params.size?'?'+params.toString():''),{signal:controller.signal});if(controller.signal.aborted)return;if(!validPacketPage(value,local))throw new Error('原包目录响应不完整，请重新读取');page.value=value}
    catch(e){if(!controller.signal.aborted)error.value=e instanceof Error?e.message:'原包目录读取失败'}
    finally{if(!controller.signal.aborted)pending.value=false}
  },{immediate:true})
  function close(){detailController?.abort();selected.value=null;detailPending.value=false;detailError.value=''}
  async function view(row:PacketRecord){
    close();selected.value=row;detailPending.value=true
    const controller=new AbortController();detailController=controller
    try{const value=await api.request<unknown>('/packet-archives/'+encodeURIComponent(row.id),{signal:controller.signal});if(controller.signal.aborted)return;if(!validPacketRecord(value,local,true)||value.id!==row.id)throw new Error('原包详情与所选目录不一致，请重新读取');selected.value=value}
    catch(e){if(!controller.signal.aborted)detailError.value=e instanceof Error?e.message:'原包详情读取失败'}
    finally{if(!controller.signal.aborted)detailPending.value=false}
  }
  function refresh(){close();history.value=[];query.value={...query.value,cursor:'',generation:query.value.generation+1}}
  function filter(sensor:string){close();history.value=[];query.value={sensor:sensor.trim(),cursor:'',generation:query.value.generation+1}}
  function next(){if(pending.value||!page.value.next)return;close();history.value=[...history.value,query.value.cursor];query.value={...query.value,cursor:page.value.next}}
  function previous(){if(pending.value||!history.value.length)return;close();const stack=[...history.value],cursor=stack.pop()!;history.value=stack;query.value={...query.value,cursor}}
  onScopeDispose(()=>{stop();close()})
  return{page,pending,error,selected,detailPending,detailError,history,view,close,refresh,filter,next,previous}
}
