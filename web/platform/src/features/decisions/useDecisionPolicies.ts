import {onScopeDispose,shallowReadonly,shallowRef,watch} from 'vue'
import {ApiError} from '@starbeacon/shared/api.ts'
import {session} from '../../session'
import {policyChangeError,validPolicyPage,validPolicyReceipt,type PolicyChange,type PolicyPage,type PolicyRecord} from './decisionPolicies'

export function useDecisionPolicies(){
 const page=shallowRef<PolicyPage>({items:[],next_cursor:''}),pending=shallowRef(true),error=shallowRef(''),keyword=shallowRef(''),active=shallowRef(''),cursors=shallowRef([''])
 const busy=shallowRef(false),unconfirmed=shallowRef(false),mutationError=shallowRef('')
 let stopped=false,read:AbortController|undefined,write:AbortController|undefined,attempt:{input:PolicyChange;key:string}|undefined
 async function refresh(){
  if(stopped)return
  read?.abort();const controller=new AbortController();read=controller;pending.value=true;error.value=''
  const tenant=session.current.value?.tenant_id??'',cursor=cursors.value.at(-1)??'',state=active.value
  const query=new URLSearchParams({limit:'20',cursor,keyword:keyword.value,active:state})
  try{const value=await session.api.request<unknown>('/decision-policies?'+query,{signal:controller.signal});if(controller.signal.aborted)return;if(!await validPolicyPage(value,tenant,cursor,state))throw new Error('决策策略目录未能完整返回，请重试。');if(!controller.signal.aborted)page.value=value as PolicyPage}
  catch(e){if(!controller.signal.aborted)error.value=e instanceof Error?e.message:'决策策略读取失败。'}finally{if(read===controller)pending.value=false}
 }
 function search(value:string,state:string){keyword.value=value.trim();active.value=state;cursors.value=[''];void refresh()}
 function next(){if(pending.value||error.value||!page.value.next_cursor)return;cursors.value=[...cursors.value,page.value.next_cursor];void refresh()}
 function previous(){if(pending.value||cursors.value.length<2)return;cursors.value=cursors.value.slice(0,-1);void refresh()}
 async function save(input:PolicyChange):Promise<PolicyRecord|undefined>{
  if(stopped||busy.value)return undefined
  const invalid=policyChangeError(input);if(invalid){mutationError.value=invalid;return undefined}
  if(attempt&&JSON.stringify(attempt.input)!==JSON.stringify(input)){mutationError.value='上次提交结果尚未确认，请先核对原提交。';return undefined}
  if(!attempt)attempt={input:structuredClone(input),key:crypto.randomUUID()}
  const frozen=attempt,controller=new AbortController();write=controller;busy.value=true;mutationError.value=''
  const tenant=session.current.value?.tenant_id??'',timer=setTimeout(()=>controller.abort(),30000)
  try{const value=await session.api.request<unknown>('/decision-policies',{method:'POST',body:frozen.input,headers:{'Idempotency-Key':frozen.key},signal:controller.signal});if(stopped||write!==controller)return undefined;if(controller.signal.aborted||!await validPolicyReceipt(value,tenant,frozen.input))throw new Error('策略回执尚未完整确认，请核对原提交。');if(controller.signal.aborted||write!==controller)return undefined;attempt=undefined;unconfirmed.value=false;return value as PolicyRecord}
  catch(e){if(!stopped&&write===controller){mutationError.value=controller.signal.aborted?'策略提交结果尚未确认，请核对原提交。':e instanceof Error?e.message:'策略提交结果尚未确认。';if(e instanceof ApiError&&e.status>=400&&e.status<500&&e.status!==408){attempt=undefined;unconfirmed.value=false}else unconfirmed.value=true}return undefined}
  finally{clearTimeout(timer);if(write===controller){write=undefined;busy.value=false}}
 }
 function confirm(){return attempt?save(attempt.input):Promise.resolve(undefined)}
 function clearError(){if(!attempt)mutationError.value=''}
 function draft(){return attempt?structuredClone(attempt.input):undefined}
 function reset(){read?.abort();write?.abort();write=undefined;attempt=undefined;busy.value=false;unconfirmed.value=false;mutationError.value='';page.value={items:[],next_cursor:''};keyword.value='';active.value='';cursors.value=[''];void refresh()}
 watch(()=>[session.current.value?.tenant_id,session.current.value?.id,session.current.value?.role].join('/'),reset)
 onScopeDispose(()=>{stopped=true;read?.abort();write?.abort();attempt=undefined})
 void refresh()
 return {page:shallowReadonly(page),pending:shallowReadonly(pending),error:shallowReadonly(error),keyword:shallowReadonly(keyword),active:shallowReadonly(active),cursors:shallowReadonly(cursors),busy:shallowReadonly(busy),unconfirmed:shallowReadonly(unconfirmed),mutationError:shallowReadonly(mutationError),refresh,search,next,previous,save,confirm,clearError,draft}
}
