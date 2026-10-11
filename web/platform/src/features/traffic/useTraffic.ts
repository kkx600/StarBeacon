import {computed,onScopeDispose,shallowReadonly,shallowRef,watch} from 'vue'
import {session} from '../../session'
import {defaultTrafficFilters,validTrafficResult,type TrafficQuery,type TrafficResult,type TrafficFilters} from './traffic'
import {definitionFromQuery} from '../search/savedSearch'
export function useTraffic(){
 const now=new Date(),query=shallowRef<TrafficQuery>({...defaultTrafficFilters(),start:new Date(now.getTime()-86400000).toISOString(),end:now.toISOString(),page:1,page_size:20})
 const result=shallowRef<TrafficResult>({items:[],total:0,page:1,page_size:20}),pending=shallowRef(true),error=shallowRef(''),lastWindow=shallowRef<{start:string;end:string}|null>(null)
 const hours=shallowRef(24),fixed=shallowRef<{start:string;end:string}|null>(null)
 const stop=watch(query,async (requested,_old,onCleanup)=>{
  const controller=new AbortController();onCleanup(()=>controller.abort());pending.value=true;error.value=''
  try{const value=await session.api.request<unknown>('/traffic/search',{method:'POST',body:requested,signal:controller.signal});if(controller.signal.aborted)return;if(!validTrafficResult(value,requested,session.current.value?.tenant_id??''))throw new Error('流量记录响应不完整或与检索范围不一致，请重试');result.value=value;lastWindow.value={start:requested.start,end:requested.end}}
  catch(e){if(!controller.signal.aborted)error.value=e instanceof Error?e.message:'流量检索失败'}
  finally{if(!controller.signal.aborted)pending.value=false}
 },{immediate:true})
 onScopeDispose(stop)
 function search(filters:TrafficFilters,windowHours:number){hours.value=windowHours===0&&fixed.value?0:[24,168,720].includes(windowHours)?windowHours:24;if(hours.value!==0)fixed.value=null;const end=new Date();query.value={...filters,start:hours.value===0?fixed.value!.start:new Date(end.getTime()-hours.value*3600000).toISOString(),end:hours.value===0?fixed.value!.end:end.toISOString(),page:1,page_size:20}}
 function applyQuery(value:TrafficQuery,windowHours:number){hours.value=windowHours;fixed.value=windowHours===0?{start:value.start,end:value.end}:null;query.value={...value,page:1,page_size:20}}
 function page(value:number,size:number){if(!Number.isSafeInteger(value)||!Number.isSafeInteger(size)||value<1||![20,50,100].includes(size)||value*size>10000)return;query.value={...query.value,page:value,page_size:size}}
 function refresh(){const end=new Date();query.value={...query.value,start:hours.value===0?query.value.start:new Date(end.getTime()-hours.value*3600000).toISOString(),end:hours.value===0?query.value.end:end.toISOString(),page:1}}
 watch(()=>[session.current.value?.tenant_id,session.current.value?.id,session.current.value?.role].join('/'),()=>{result.value={items:[],total:0,page:1,page_size:20};lastWindow.value=null;fixed.value=null;search(defaultTrafficFilters(),24)})
 return {result:shallowReadonly(result),pending:shallowReadonly(pending),error:shallowReadonly(error),appliedQuery:shallowReadonly(query),range:computed(()=>lastWindow.value),definition:computed(()=>definitionFromQuery('context',query.value,hours.value)),fixed:computed(()=>!!fixed.value),search,page,refresh,applyQuery}
}
