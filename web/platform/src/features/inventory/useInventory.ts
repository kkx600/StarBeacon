import {computed,onScopeDispose,shallowRef,shallowReadonly,watch,type Ref} from 'vue'
import {session} from '../../session'
import type {InventoryKind,InventoryPage,InventoryRecord,InventoryData} from './inventory'

export function useInventory(kind:Ref<InventoryKind>){
  const result=shallowRef<InventoryPage>({items:[],next_cursor:''}),pending=shallowRef(true),error=shallowRef(''),saving=shallowRef(false),saveError=shallowRef('')
  const keyword=shallowRef(''),cursors=shallowRef(['']),refreshTick=shallowRef(0)
  let saveController:AbortController|undefined
  const query=computed(()=>({kind:kind.value,keyword:keyword.value,cursor:cursors.value.at(-1)??'',tick:refreshTick.value}))
  watch(kind,()=>{saveController?.abort();saving.value=false;keyword.value='';cursors.value=[''];saveError.value=''})
  watch(query,async(value,_previous,onCleanup)=>{
    const controller=new AbortController();onCleanup(()=>controller.abort());pending.value=true;error.value=''
    try {const page=await session.api.request<InventoryPage>(`/inventory/${value.kind}?${new URLSearchParams({cursor:value.cursor,keyword:value.keyword,limit:'20'})}`,{signal:controller.signal});if(!controller.signal.aborted)result.value=page}
    catch(e){if(!controller.signal.aborted)error.value=e instanceof Error?e.message:'对象列表读取失败'}finally{if(!controller.signal.aborted)pending.value=false}
  },{immediate:true})
  onScopeDispose(()=>saveController?.abort())
  async function save(data:InventoryData,record:InventoryRecord|null){
    if(saving.value)return false
    saveError.value='';saving.value=true;const controller=new AbortController();saveController=controller
    try {await session.api.request(`/inventory/${kind.value}`,{method:'POST',body:{id:record?.id??'',expected_revision:record?.revision??0,data},signal:controller.signal});if(controller.signal.aborted)return false;refreshTick.value++;return true}
    catch(e){if(!controller.signal.aborted)saveError.value=e instanceof Error?e.message:'对象保存失败';return false}finally{if(!controller.signal.aborted)saving.value=false}
  }
  return {result:shallowReadonly(result),pending:shallowReadonly(pending),error:shallowReadonly(error),saving:shallowReadonly(saving),saveError:shallowReadonly(saveError),save,cursors:shallowReadonly(cursors),clearSaveError:()=>{saveError.value=''},refresh:()=>{refreshTick.value++},search:(value:string)=>{keyword.value=value;cursors.value=['']},next:()=>{if(result.value.next_cursor&&!pending.value)cursors.value=[...cursors.value,result.value.next_cursor]},previous:()=>{if(cursors.value.length>1&&!pending.value)cursors.value=cursors.value.slice(0,-1)}}
}
