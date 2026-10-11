import {computed,shallowReadonly,shallowRef,watch,type Ref} from 'vue'
import type {AuditResult} from '@starbeacon/shared/types.ts'
import {session} from '../../session'
export type AuditCategory='operations'|'logins'
export interface AuditFilters {username:string;action:string;success:string;hours:number}
export function useAudits(category:Ref<AuditCategory>){
  const result=shallowRef<AuditResult>({items:[],next_cursor:''}),pending=shallowRef(true),error=shallowRef(''),cursors=shallowRef(['']),tick=shallowRef(0)
  const end=shallowRef(new Date().toISOString()),filters=shallowRef<AuditFilters>({username:'',action:'',success:'',hours:168})
  const query=computed(()=>({category:category.value,filters:filters.value,end:end.value,cursor:cursors.value.at(-1)??'',tick:tick.value}))
  watch(category,()=>{cursors.value=[''];filters.value={username:'',action:'',success:'',hours:168};end.value=new Date().toISOString()})
  watch(query,async(value,_previous,onCleanup)=>{
    const controller=new AbortController();onCleanup(()=>controller.abort());pending.value=true;error.value=''
    const parameters=new URLSearchParams({start:new Date(new Date(value.end).getTime()-value.filters.hours*3600000).toISOString(),end:value.end,limit:'20',cursor:value.cursor,username:value.filters.username})
    parameters.set(value.category==='operations'?'action':'success',value.category==='operations'?value.filters.action:value.filters.success)
    try{const page=await session.api.request<AuditResult>(`/audits/${value.category}?${parameters}`,{signal:controller.signal});if(!controller.signal.aborted)result.value=page}
    catch(e){if(!controller.signal.aborted)error.value=e instanceof Error?e.message:'审计日志读取失败'}finally{if(!controller.signal.aborted)pending.value=false}
  },{immediate:true})
  function search(value:AuditFilters){filters.value={...value};end.value=new Date().toISOString();cursors.value=[''];tick.value++}
  function refresh(){end.value=new Date().toISOString();cursors.value=[''];tick.value++}
  return {result:shallowReadonly(result),pending:shallowReadonly(pending),error:shallowReadonly(error),cursors:shallowReadonly(cursors),search,refresh,next:()=>{if(result.value.next_cursor&&!pending.value)cursors.value=[...cursors.value,result.value.next_cursor]},previous:()=>{if(cursors.value.length>1&&!pending.value)cursors.value=cursors.value.slice(0,-1)}}
}
