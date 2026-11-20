import {onScopeDispose,shallowReadonly,shallowRef,watch} from 'vue'
import {ApiError} from '@starbeacon/shared/api.ts'
import {readWatchlistImpact,watchlistImpactRequest,type WatchlistImpact,type WatchlistImpactRequest} from '@starbeacon/shared/watchlists.ts'
import {session} from '../../session'

// 历史检索不完整时不交付部分计数；宁可不给数，也不展示半个数。
const incomplete='历史检索结果不完整，本次未交付计数'
// 每租户滚动 24 小时最多 200 次预览；额度用尽稍后可重试，不是服务故障。
const exhausted='预览额度已用尽，请稍后重试'

export function useWatchlistImpact(){
 const result=shallowRef<WatchlistImpact|null>(null),pending=shallowRef(false),error=shallowRef(''),input=shallowRef<WatchlistImpactRequest|null>(null),truncated=shallowRef(false)
 let stopped=false,read:AbortController|undefined,target=''
 function clear(){read?.abort();read=undefined;result.value=null;pending.value=false;error.value='';input.value=null;truncated.value=false;target=''}
 async function run(listId:string,revision:number,start:string,end:string){
  if(stopped||!session.current.value||session.current.value.role!=='admin')return
  clear()
  let request:WatchlistImpactRequest
  try{request=watchlistImpactRequest(revision,start,end)}catch(cause){error.value=cause instanceof Error?cause.message:'核对范围无效。';return}
  const controller=new AbortController();read=controller;target=listId;input.value=request;pending.value=true
  const timer=setTimeout(()=>controller.abort(),30000)
  try{
   const value=await session.api.request<unknown>(`/watchlists/${encodeURIComponent(listId)}/impact`,{method:'POST',body:request,signal:controller.signal})
   if(read!==controller||stopped)return
   if(controller.signal.aborted)throw new Error('历史影响核对超时，请重试。')
   const checked=readWatchlistImpact(value,listId,request)
   if(read!==controller||stopped)return
   if(controller.signal.aborted)throw new Error('历史影响核对超时，请重试。')
   result.value=checked
  }catch(cause){
   if(stopped||read!==controller)return
   // 平台用 503 watchlist_impact_incomplete 表示检索不完整；此时不展示任何部分数字。
   truncated.value=cause instanceof ApiError&&cause.code==='watchlist_impact_incomplete'
   // 额度用尽是 429，与服务不可用是两回事：前者稍后可再预览，不该提示为故障。
   const quota=cause instanceof ApiError&&cause.status===429
   error.value=controller.signal.aborted?'历史影响核对超时，请重试。':truncated.value?incomplete:quota?exhausted:cause instanceof Error?cause.message:'历史影响核对失败，请重试。'
  }finally{clearTimeout(timer);if(read===controller)pending.value=false}
 }
 const retry=()=>input.value&&target?run(target,input.value.revision,input.value.start,input.value.end):Promise.resolve()
 watch(()=>[session.current.value?.tenant_id,session.current.value?.id,session.current.value?.role,session.current.value?.csrf_token].join('/'),clear,{flush:'sync'})
 onScopeDispose(()=>{stopped=true;clear()})
 return {result:shallowReadonly(result),pending:shallowReadonly(pending),error:shallowReadonly(error),incomplete:shallowReadonly(truncated),input:shallowReadonly(input),run,retry,clear}
}
