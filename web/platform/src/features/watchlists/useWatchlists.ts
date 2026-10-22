import {onScopeDispose,shallowReadonly,shallowRef,watch} from 'vue'
import {ApiError} from '@starbeacon/shared/api.ts'
import {readWatchlistPage,readWatchlistReceipt,watchlistChangeError,type WatchlistChange,type WatchlistPage,type WatchlistQuery} from '@starbeacon/shared/watchlists.ts'
import {session} from '../../session'

export function useWatchlists(){
 const page=shallowRef<WatchlistPage>({items:[],next_cursor:''}),pending=shallowRef(false),error=shallowRef(''),query=shallowRef<WatchlistQuery>({cursor:'',keyword:'',kind:'',active:'',limit:20}),cursors=shallowRef([''])
 const busy=shallowRef(false),unconfirmed=shallowRef(false),mutationError=shallowRef('')
 let stopped=false,read:AbortController|undefined,write:AbortController|undefined,attempt:{input:WatchlistChange;key:string}|undefined
 async function refresh(){
  if(stopped||!session.current.value)return
  read?.abort();const controller=new AbortController();read=controller;pending.value=true;error.value=''
  const tenant=session.current.value.tenant_id,scope={...query.value,cursor:cursors.value.at(-1)??''},timer=setTimeout(()=>controller.abort(),30000)
  try{const value=await session.api.request<unknown>('/watchlists?'+new URLSearchParams({limit:String(scope.limit),cursor:scope.cursor,keyword:scope.keyword,active:scope.active,kind:scope.kind}),{signal:controller.signal});if(read!==controller||stopped)return;if(controller.signal.aborted)throw new Error('名单读取超时，请重试。');const checked=await readWatchlistPage(value,scope,tenant);if(read!==controller||stopped)return;if(controller.signal.aborted)throw new Error('名单读取超时，请重试。');page.value=checked}
  catch(cause){if(read===controller&&!stopped)error.value=controller.signal.aborted?'名单读取超时，请重试。':cause instanceof Error?cause.message:'名单读取失败，请重试。'}finally{clearTimeout(timer);if(read===controller)pending.value=false}
 }
 function search(keyword:string,active:string,kind:string){query.value={cursor:'',keyword:keyword.trim(),active,kind,limit:20};cursors.value=[''];page.value={items:[],next_cursor:''};void refresh()}
 function next(){if(pending.value||error.value||!page.value.next_cursor)return;cursors.value=[...cursors.value,page.value.next_cursor];page.value={items:[],next_cursor:''};void refresh()}
 function previous(){if(pending.value||cursors.value.length<=1)return;cursors.value=cursors.value.slice(0,-1);page.value={items:[],next_cursor:''};void refresh()}
 async function save(input:WatchlistChange){
  if(stopped||busy.value)return undefined
  const user=session.current.value
  if(!user||user.role!=='admin'){mutationError.value='当前账号无权维护名单。';return undefined}
  if(attempt&&JSON.stringify(attempt.input)!==JSON.stringify(input)){mutationError.value='上次提交结果尚未确认，请先核对原提交。';return undefined}
  // 原提交可能已保存并在确认前到期；确认只回读原请求，不能以当前时间改写其结果。
  const invalid=attempt?'':watchlistChangeError(input);if(invalid){mutationError.value=invalid;return undefined}
  if(!attempt)attempt={input:structuredClone(input),key:crypto.randomUUID()}
  const frozen=attempt,controller=new AbortController();write=controller;busy.value=true;mutationError.value=''
  const timer=setTimeout(()=>controller.abort(),30000)
  try{
   const value=await session.api.request<unknown>('/watchlists',{method:'POST',body:frozen.input,headers:{'Idempotency-Key':frozen.key},signal:controller.signal})
   if(stopped||write!==controller)return undefined
   if(controller.signal.aborted)throw new Error('名单提交结果尚未完整确认，请核对原提交。')
   const checked=await readWatchlistReceipt(value,user.tenant_id,frozen.input,user.id)
   if(write!==controller||stopped)return undefined
   if(controller.signal.aborted)throw new Error('名单回执尚未完整确认，请核对原提交。')
   attempt=undefined;unconfirmed.value=false;return checked
  }catch(cause){
   if(!stopped&&write===controller){
    mutationError.value=controller.signal.aborted?'名单提交结果尚未确认，请核对原提交。':cause instanceof ApiError&&cause.status===409?'名单或探针注册已变化，请关闭表单并刷新目录和探针后重新编辑。':cause instanceof Error?cause.message:'名单提交结果尚未确认。'
    if(cause instanceof ApiError&&cause.status>=400&&cause.status<500&&cause.status!==408){attempt=undefined;unconfirmed.value=false}else unconfirmed.value=true
   }
   return undefined
  }finally{clearTimeout(timer);if(write===controller){write=undefined;busy.value=false}}
 }
 const confirm=()=>attempt?save(attempt.input):Promise.resolve(undefined)
 function clearError(){if(!attempt)mutationError.value=''}
 function draft(){return attempt?structuredClone(attempt.input):undefined}
 function reset(){read?.abort();read=undefined;write?.abort();write=undefined;attempt=undefined;busy.value=false;unconfirmed.value=false;mutationError.value='';page.value={items:[],next_cursor:''};cursors.value=[''];query.value={cursor:'',keyword:'',kind:'',active:'',limit:20};error.value='';pending.value=false;if(session.current.value)void refresh()}
 watch(()=>[session.current.value?.tenant_id,session.current.value?.id,session.current.value?.role,session.current.value?.csrf_token].join('/'),reset,{flush:'sync'})
 onScopeDispose(()=>{stopped=true;read?.abort();write?.abort();attempt=undefined})
 void refresh()
 return {page:shallowReadonly(page),pending:shallowReadonly(pending),error:shallowReadonly(error),query:shallowReadonly(query),cursors:shallowReadonly(cursors),busy:shallowReadonly(busy),unconfirmed:shallowReadonly(unconfirmed),mutationError:shallowReadonly(mutationError),refresh,search,next,previous,save,confirm,clearError,draft}
}
