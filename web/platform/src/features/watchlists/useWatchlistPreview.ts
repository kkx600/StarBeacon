import {onScopeDispose,shallowReadonly,shallowRef,watch} from 'vue'
import {readWatchlistPreview,watchlistPreviewError,type WatchlistPreviewRequest,type WatchlistPreviewResult} from '@starbeacon/shared/watchlists.ts'
import {session} from '../../session'

export function useWatchlistPreview(){
 const result=shallowRef<WatchlistPreviewResult|null>(null),pending=shallowRef(false),error=shallowRef(''),input=shallowRef<WatchlistPreviewRequest|null>(null)
 let stopped=false,read:AbortController|undefined
 function clear(){read?.abort();read=undefined;result.value=null;pending.value=false;error.value='';input.value=null}
 async function run(request:WatchlistPreviewRequest){
  if(stopped||!session.current.value||session.current.value.role!=='admin')return
  clear();const invalid=watchlistPreviewError(request);if(invalid){error.value=invalid;return}
  const frozen=structuredClone(request),controller=new AbortController();read=controller;input.value=frozen;pending.value=true
  const timer=setTimeout(()=>controller.abort(),30000)
  try{const value=await session.api.request<unknown>('/watchlists/preview',{method:'POST',body:frozen,signal:controller.signal});if(read!==controller||stopped)return;if(controller.signal.aborted)throw new Error('范围核验超时，请重试。');const checked=await readWatchlistPreview(value,frozen);if(read!==controller||stopped)return;if(controller.signal.aborted)throw new Error('范围核验超时，请重试。');result.value=checked}
  catch(cause){if(!stopped&&read===controller)error.value=controller.signal.aborted?'范围核验超时，请重试。':cause instanceof Error?cause.message:'范围核验失败，请重试。'}finally{clearTimeout(timer);if(read===controller)pending.value=false}
 }
 const retry=()=>input.value?run(input.value):Promise.resolve()
 watch(()=>[session.current.value?.tenant_id,session.current.value?.id,session.current.value?.role,session.current.value?.csrf_token].join('/'),clear,{flush:'sync'})
 onScopeDispose(()=>{stopped=true;clear()})
 return {result:shallowReadonly(result),pending:shallowReadonly(pending),error:shallowReadonly(error),input:shallowReadonly(input),run,retry,clear}
}
