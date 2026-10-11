import {onMounted,onScopeDispose,shallowReadonly,shallowRef} from 'vue'
import {ApiError} from '@starbeacon/shared/api.ts'
import type {RulePackage} from '@starbeacon/shared/types.ts'
import {session} from '../../session'
import {generationWorking,sameGenerationRequest,validGenerationJob,validGenerationPage,validGenerationRequest,type GenerationJob,type GenerationPage,type GenerationRequest,type GenerationSummary,type RuleCandidate} from './generation'

export function useRuleGeneration(){
  const items=shallowRef<GenerationSummary[]>([]),next=shallowRef(''),pending=shallowRef(false),error=shallowRef(''),available=shallowRef(false)
  const selected=shallowRef<GenerationJob|null>(null),loading=shallowRef(false),detailError=shallowRef(''),busy=shallowRef(false),actionError=shallowRef(''),unconfirmed=shallowRef(false)
  let stopped=false,listEpoch=0,detailEpoch=0,failures=0,listController:AbortController|undefined,detailController:AbortController|undefined,mutation:AbortController|undefined,timer:ReturnType<typeof setTimeout>|undefined
  let attempt:{key:string;input:GenerationRequest}|undefined
  function schedule(failed=false){
    if(timer)clearTimeout(timer)
    if(stopped||failed&&++failures>=3)return
    if(!failed)failures=0
    if(!failed&&!items.value.some(row=>generationWorking(row.state))&&!(selected.value&&generationWorking(selected.value.state)))return
    timer=setTimeout(async()=>{if(document.visibilityState==='visible'){await refresh();if(selected.value&&generationWorking(selected.value.state))await load(selected.value.id)}else schedule()},failed?5000*2**Math.max(0,failures-1):3000)
  }
  async function refresh(before='',append=false){
    if(stopped)return
    const epoch=++listEpoch;listController?.abort();const control=new AbortController();listController=control;pending.value=true;error.value=''
    let failed=false
    try{
      const page=await session.api.request<GenerationPage>('/rule-generation/jobs'+(before?'?before='+encodeURIComponent(before):''),{signal:control.signal})
      if(stopped||control.signal.aborted||epoch!==listEpoch)return
      if(!validGenerationPage(page))throw new Error('规则生成记录未能完整返回')
      const known=new Set(items.value.map(row=>row.id))
      items.value=append?[...items.value,...page.items.filter(row=>!known.has(row.id))]:page.items;next.value=page.next_cursor;available.value=page.model_execution_available
    }catch(e){if(!control.signal.aborted){failed=true;error.value=e instanceof Error?e.message:'规则生成记录读取失败'}}
    finally{if(!stopped&&epoch===listEpoch){pending.value=false;schedule(failed)}}
  }
  async function load(id:string){
    if(stopped)return
    const epoch=++detailEpoch;detailController?.abort();const control=new AbortController();detailController=control;loading.value=true;detailError.value=''
    try{
      const job=await session.api.request<GenerationJob>('/rule-generation/jobs/'+encodeURIComponent(id),{signal:control.signal})
      if(stopped||control.signal.aborted||epoch!==detailEpoch)return
      if(!validGenerationJob(job)||job.id!==id)throw new Error('规则生成结果未能完整返回')
      selected.value=job;items.value=items.value.map(row=>row.id===job.id?{...row,state:job.state,cancel_requested:job.cancel_requested}:row)
    }catch(e){if(!control.signal.aborted)detailError.value=e instanceof Error?e.message:'规则生成结果读取失败'}
    finally{if(!stopped&&epoch===detailEpoch)loading.value=false}
  }
  async function submit(input:GenerationRequest):Promise<GenerationJob|undefined>{
    if(stopped||busy.value)return undefined
    if(!validGenerationRequest(input)){actionError.value='请核对检测说明、样本、模型修订及数据使用许可';return undefined}
    if(attempt&&!sameGenerationRequest(attempt.input,input)){actionError.value='上次提交结果尚未确认，请先确认原请求';return undefined}
    attempt??={key:crypto.randomUUID().replaceAll('-',''),input:structuredClone(input)}
    const control=new AbortController();mutation=control;busy.value=true;actionError.value=''
    try{
      const job=await session.api.request<GenerationJob>('/rule-generation/jobs',{method:'POST',body:attempt.input,headers:{'Idempotency-Key':attempt.key},signal:control.signal})
      if(stopped||control.signal.aborted)return undefined
      if(!validGenerationJob(job)||!sameGenerationRequest(job.request,attempt.input))throw new Error('提交结果未能完整返回，请确认原请求')
      selected.value=job;attempt=undefined;unconfirmed.value=false;void refresh();return job
    }catch(e){if(!control.signal.aborted){actionError.value=e instanceof Error?e.message:'规则生成提交结果未确认';if(e instanceof ApiError&&e.status>=400&&e.status<500&&e.status!==408){attempt=undefined;unconfirmed.value=false}else unconfirmed.value=true}return undefined}
    finally{if(mutation===control){mutation=undefined;busy.value=false}}
  }
  async function cancel(id:string){
    if(stopped||busy.value)return
    const control=new AbortController();mutation=control;busy.value=true;actionError.value=''
    try{const job=await session.api.request<GenerationJob>('/rule-generation/jobs/'+encodeURIComponent(id)+'/cancel',{method:'POST',body:{},signal:control.signal});if(stopped||control.signal.aborted)return;if(!validGenerationJob(job)||job.id!==id)throw new Error('取消结果未能完整返回，请刷新记录核对');selected.value=job;void refresh()}
    catch(e){if(!control.signal.aborted)actionError.value=e instanceof Error?e.message:'取消请求未确认'}finally{if(mutation===control){mutation=undefined;busy.value=false}}
  }
  async function adopt(candidate:RuleCandidate){
    if(stopped||busy.value||!selected.value||selected.value.state!=='succeeded'||!selected.value.candidates.some(row=>row.sid===candidate.sid&&row.sha256===candidate.sha256))return undefined
    const job=selected.value,control=new AbortController();mutation=control;busy.value=true;actionError.value=''
    try{
      const pkg=await session.api.request<RulePackage>('/rule-generation/jobs/'+encodeURIComponent(job.id)+'/adopt',{method:'POST',body:{sid:candidate.sid},signal:control.signal})
      if(stopped||control.signal.aborted)return undefined
      if(pkg.id!==candidate.package_id||pkg.revision!==1||pkg.sha256!==candidate.sha256||pkg.generation_id!==job.id||pkg.generation_sid!==candidate.sid)throw new Error('采纳结果未能核对，请按原候选重试或检查规则包')
      return pkg
    }catch(e){if(!control.signal.aborted)actionError.value=e instanceof Error?e.message:'规则采纳结果未确认';return undefined}
    finally{if(mutation===control){mutation=undefined;busy.value=false}}
  }
  function clear(){detailEpoch++;detailController?.abort();selected.value=null;loading.value=false;detailError.value='';actionError.value=''}
  onMounted(()=>void refresh())
  onScopeDispose(()=>{stopped=true;listEpoch++;detailEpoch++;listController?.abort();detailController?.abort();mutation?.abort();if(timer)clearTimeout(timer)})
  return {items:shallowReadonly(items),next:shallowReadonly(next),pending:shallowReadonly(pending),error:shallowReadonly(error),available:shallowReadonly(available),selected:shallowReadonly(selected),loading:shallowReadonly(loading),detailError:shallowReadonly(detailError),busy:shallowReadonly(busy),actionError:shallowReadonly(actionError),unconfirmed:shallowReadonly(unconfirmed),refresh,load,submit,confirm:()=>attempt?submit(attempt.input):Promise.resolve(undefined),cancel,adopt,clear}
}
