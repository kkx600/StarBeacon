import {onScopeDispose,shallowRef,shallowReadonly} from 'vue'
import {ApiError} from '@starbeacon/shared/api.ts'
import {session} from '../../session'
import {validAssessment,validAssessmentPage,sameAssessmentSpec,type AlertAssessment,type AssessmentChange,type AssessmentPage} from './assessment'

export function useAssessment(eventID:string,digest:string){
 const current=shallowRef<AlertAssessment|null>(null),pending=shallowRef(false),error=shallowRef(''),busy=shallowRef(false),unconfirmed=shallowRef(false),actionError=shallowRef('')
 const history=shallowRef<AlertAssessment[]>([]),historyPending=shallowRef(false),historyError=shallowRef(''),next=shallowRef('')
 const path='/alerts/'+encodeURIComponent(eventID)+'/assessment?sha256='+encodeURIComponent(digest)
 let stopped=false,epoch=0,historyEpoch=0,read:AbortController|undefined,historyRead:AbortController|undefined,mutation:AbortController|undefined
 let attempt:{change:AssessmentChange;key:string}|undefined
 const matches=(row:AlertAssessment)=>row.event_id===eventID&&row.raw_sha256===digest
 async function refresh(){
  if(stopped||busy.value||unconfirmed.value)return
  const token=++epoch;read?.abort();const controller=new AbortController();read=controller;pending.value=true;error.value=''
  try{const result=await session.api.request<AlertAssessment>(path,{signal:controller.signal});if(stopped||token!==epoch)return;if(!validAssessment(result)||!matches(result))throw new Error('研判记录未能完整返回');current.value=result}
  catch(e){if(!controller.signal.aborted)error.value=e instanceof Error?e.message:'研判记录读取失败'}finally{if(!stopped&&token===epoch)pending.value=false}
 }
 async function save(change:AssessmentChange){
  if(stopped||busy.value)return undefined
  if(attempt&&JSON.stringify(attempt.change)!==JSON.stringify(change)){actionError.value='上次保存结果尚未确认，请先确认原请求。';return undefined}
  if(!attempt)attempt={change:structuredClone(change),key:crypto.randomUUID()}
  const controller=new AbortController();mutation=controller;busy.value=true;actionError.value=''
  try{
   const saved=await session.api.request<AlertAssessment>(path,{method:'POST',body:attempt.change,headers:{'Idempotency-Key':attempt.key},signal:controller.signal})
   if(stopped||controller.signal.aborted)return undefined
   if(!validAssessment(saved)||!matches(saved)||saved.revision!==attempt.change.expected_revision+1||!sameAssessmentSpec(saved.spec,attempt.change.spec)||(attempt.change.claim&&saved.owner_id!==session.current.value?.id))throw new Error('研判保存结果未能完整返回，请确认原请求。')
   current.value=saved;attempt=undefined;unconfirmed.value=false;error.value='';return saved
  }catch(e){if(!controller.signal.aborted){actionError.value=e instanceof Error?e.message:'研判保存结果尚未确认';if(e instanceof ApiError&&e.status>=400&&e.status<500&&e.status!==408){attempt=undefined;unconfirmed.value=false}else unconfirmed.value=true}return undefined}
  finally{if(mutation===controller){mutation=undefined;busy.value=false}}
 }
 async function confirm(){if(attempt)return save(attempt.change);return undefined}
 async function loadHistory(before=''){
  if(stopped)return
  const token=++historyEpoch;historyRead?.abort();const controller=new AbortController();historyRead=controller;historyPending.value=true;historyError.value=''
  try{const page=await session.api.request<AssessmentPage>(path.replace('/assessment?','/assessment/history?')+(before?'&before='+encodeURIComponent(before):''),{signal:controller.signal});if(stopped||token!==historyEpoch)return;if(!validAssessmentPage(page)||page.items.some(row=>!matches(row)))throw new Error('研判历史未能完整返回');history.value=before?[...history.value,...page.items.filter(row=>!history.value.some(old=>old.revision===row.revision))]:page.items;next.value=page.next_cursor}
  catch(e){if(!controller.signal.aborted)historyError.value=e instanceof Error?e.message:'研判历史读取失败'}finally{if(!stopped&&token===historyEpoch)historyPending.value=false}
 }
 onScopeDispose(()=>{stopped=true;epoch++;historyEpoch++;read?.abort();historyRead?.abort();mutation?.abort()})
 return{current:shallowReadonly(current),pending:shallowReadonly(pending),error:shallowReadonly(error),busy:shallowReadonly(busy),unconfirmed:shallowReadonly(unconfirmed),actionError:shallowReadonly(actionError),history:shallowReadonly(history),historyPending:shallowReadonly(historyPending),historyError:shallowReadonly(historyError),next:shallowReadonly(next),refresh,save,confirm,loadHistory}
}
