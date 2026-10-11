import {onMounted,onScopeDispose,shallowReadonly,shallowRef} from 'vue'
import {ApiError} from '@starbeacon/shared/api.ts'
import {session} from '../../session'
import {validPage,validPolicy,validPreview,type RetentionCandidate,type RetentionPage,type RetentionPolicy,type RetentionPreview} from './retention'

export function useRetention(){
 const data=shallowRef<RetentionPage|null>(null),pending=shallowRef(false),error=shallowRef(''),actionError=shallowRef(''),busy=shallowRef(false),checking=shallowRef(false),preview=shallowRef<RetentionPreview|null>(null),unconfirmed=shallowRef(false)
 let stopped=false,generation=0,previewGeneration=0,read:AbortController|undefined,check:AbortController|undefined,write:AbortController|undefined
 let attempt:{key:string;input:{preview_id:string;candidate:RetentionCandidate}}|undefined
 async function refresh(){if(stopped)return;const epoch=++generation;read?.abort();const control=new AbortController();read=control;pending.value=true;error.value='';try{const page=await session.api.request<RetentionPage>('/retention-policies',{signal:control.signal});if(stopped||epoch!==generation)return;if(!validPage(page))throw new Error('分类留存策略未能完整返回');data.value=page}catch(e){if(!control.signal.aborted)error.value=e instanceof Error?e.message:'留存策略读取失败'}finally{if(!stopped&&epoch===generation)pending.value=false}}
 function invalidate(){if(attempt)return;previewGeneration++;check?.abort();preview.value=null;checking.value=false;actionError.value=''}
 async function inspect(candidate:RetentionCandidate){if(stopped||busy.value||attempt)return;const epoch=++previewGeneration;check?.abort();const control=new AbortController();check=control;checking.value=true;actionError.value='';preview.value=null;try{const result=await session.api.request<RetentionPreview>('/retention-policies/preview',{method:'POST',body:candidate,signal:control.signal});if(stopped||epoch!==previewGeneration)return;if(!validPreview(result,candidate))throw new Error('影响预览未能完整返回');preview.value=result}catch(e){if(!control.signal.aborted)actionError.value=e instanceof Error?e.message:'影响预览读取失败'}finally{if(!stopped&&epoch===previewGeneration)checking.value=false}}
 async function save(){
  if(stopped||busy.value||(!preview.value&&!attempt))return undefined
  if(!attempt&&preview.value)attempt={key:crypto.randomUUID().replaceAll('-',''),input:{preview_id:preview.value.id,candidate:structuredClone(preview.value.candidate)}}
  const current=attempt!;const control=new AbortController();write=control;busy.value=true;actionError.value='';let timedOut=false;const timeout=setTimeout(()=>{timedOut=true;control.abort()},30000)
  try{const policy=await session.api.request<RetentionPolicy>('/retention-policies/'+encodeURIComponent(current.input.candidate.category),{method:'PUT',body:current.input,headers:{'Idempotency-Key':current.key},signal:control.signal});if(stopped)return undefined;if(!validPolicy(policy)||policy.category!==current.input.candidate.category||policy.days!==current.input.candidate.days||policy.revision!==current.input.candidate.expected_revision+1)throw new Error('策略发布结果未能完整返回，请确认原提交');attempt=undefined;preview.value=null;unconfirmed.value=false;void refresh();return policy}
  catch(e){if(!stopped){actionError.value=timedOut?'策略发布结果未确认，请确认原提交':e instanceof Error?e.message:'策略发布结果未确认';if(e instanceof ApiError&&e.status>=400&&e.status<500&&e.status!==408){attempt=undefined;preview.value=null;unconfirmed.value=false;void refresh()}else unconfirmed.value=true};return undefined}
  finally{clearTimeout(timeout);if(write===control){write=undefined;busy.value=false}}
 }
 onMounted(()=>void refresh());onScopeDispose(()=>{stopped=true;generation++;previewGeneration++;read?.abort();check?.abort();write?.abort()})
 return{data:shallowReadonly(data),pending:shallowReadonly(pending),error:shallowReadonly(error),actionError:shallowReadonly(actionError),busy:shallowReadonly(busy),checking:shallowReadonly(checking),preview:shallowReadonly(preview),unconfirmed:shallowReadonly(unconfirmed),refresh,invalidate,inspect,save}
}
