import {computed,onScopeDispose,shallowReadonly,shallowRef,watch} from 'vue'
import {ApiError} from '@starbeacon/shared/api.ts'
import {readSensorDirectory} from '@starbeacon/shared/sensors.ts'
import {session} from '../../session'
import {applicationTargets,deploymentTargetFresh,validAppSnapshot,type AppDeploymentInput,type AppSnapshot,type AppTarget} from './applicationDeployment'

export function useApplicationDeployment(){
 const open=shallowRef(false),pending=shallowRef(false),busy=shallowRef(false),unconfirmed=shallowRef(false),error=shallowRef(''),targets=shallowRef<AppTarget[]>([]),snapshot=shallowRef<AppSnapshot|null>(null),selected=shallowRef(''),taskID=shallowRef('')
 const target=computed(()=>targets.value.find(row=>row.id===selected.value)??null)
 const canManage=computed(()=>session.current.value?.role==='admin')
 let stopped=false,read:AbortController|undefined,write:AbortController|undefined,attempt:{target:AppTarget;input:AppDeploymentInput;key:string}|undefined
 async function refresh(){
  if(stopped||!canManage.value||unconfirmed.value||busy.value)return
  read?.abort();const controller=new AbortController();read=controller
  const timer=setTimeout(()=>{if(read===controller){controller.abort();pending.value=false;error.value='读取规则快照与探针状态超过期限，请刷新后重试。'}},30000)
  pending.value=true;error.value='';snapshot.value=null;targets.value=[];selected.value=''
  try{
   const [rules,sensors]=await Promise.all([session.api.request<unknown>('/application-rules/snapshot',{signal:controller.signal}),readSensorDirectory(session.api,controller.signal)])
   if(!await validAppSnapshot(rules))throw new Error('应用规则快照不完整或摘要不一致，无法部署。')
   const available=await applicationTargets({items:sensors})
   if(controller.signal.aborted||stopped)return
   snapshot.value=rules as AppSnapshot;targets.value=available
  }catch(e){if(!controller.signal.aborted)error.value=e instanceof Error?e.message:'应用规则部署材料读取失败。'}finally{clearTimeout(timer);if(read===controller)pending.value=false}
 }
 function show(){if(!canManage.value||stopped)return;open.value=true;if(!unconfirmed.value){taskID.value='';void refresh()}}
 function hide(){if(busy.value)return;read?.abort();pending.value=false;open.value=false}
 function choose(id:string){if(!busy.value&&!unconfirmed.value){selected.value=id;error.value='';taskID.value=''}}
 async function execute(){
  if(stopped||!canManage.value||busy.value||!attempt)return
  const frozen=attempt,controller=new AbortController();write=controller;busy.value=true;error.value=''
  const timer=setTimeout(()=>{if(write===controller){controller.abort();busy.value=false;unconfirmed.value=true;error.value='提交超过期限，结果尚未确认。原输入与请求键已保留，请核对原提交。'}},30000)
  try{
   const response=await session.api.request<unknown>(`/sensors/${encodeURIComponent(frozen.target.id)}/application-rules`,{method:'POST',body:frozen.input,headers:{'Idempotency-Key':frozen.key},signal:controller.signal})
   if(!response||typeof response!=='object'||!('id'in response)||typeof response.id!=='string'||!/^[a-z0-9][a-z0-9_-]{0,63}$/.test(response.id))throw new Error('部署受理回执不完整，请核对原提交。')
   if(controller.signal.aborted||stopped||attempt!==frozen)return
   taskID.value=response.id;attempt=undefined;unconfirmed.value=false
  }catch(e){
   if(controller.signal.aborted||stopped||attempt!==frozen)return
   const definite=e instanceof ApiError&&[400,403,404,409,429].includes(e.status)
   unconfirmed.value=!definite
   error.value=(e instanceof Error?e.message:'应用规则部署提交失败。')+(definite?'':' 原输入与请求键已保留，请核对原提交。')
   if(definite)attempt=undefined
  }finally{clearTimeout(timer);if(write===controller)busy.value=false}
 }
 async function submit(){
  if(stopped||!canManage.value||busy.value||pending.value||unconfirmed.value||!snapshot.value||!target.value)return
  if(!deploymentTargetFresh(target.value)){error.value='探针状态观测已过期，请刷新后重新选择。';return}
  attempt={target:structuredClone(target.value),input:{expected_registration_id:target.value.registration_id,expected_state_sha256:target.value.state.state_sha256,rules_sha256:snapshot.value.rules_sha256},key:crypto.randomUUID()}
  await execute()
 }
 async function confirm(){if(unconfirmed.value)await execute()}
 function reset(){read?.abort();write?.abort();attempt=undefined;open.value=false;pending.value=false;busy.value=false;unconfirmed.value=false;error.value='';targets.value=[];snapshot.value=null;selected.value='';taskID.value=''}
 watch(()=>[session.current.value?.id,session.current.value?.tenant_id,session.current.value?.role,session.current.value?.csrf_token].join('/'),reset)
 onScopeDispose(()=>{stopped=true;read?.abort();write?.abort()})
 return {open:shallowReadonly(open),pending:shallowReadonly(pending),busy:shallowReadonly(busy),unconfirmed:shallowReadonly(unconfirmed),error:shallowReadonly(error),targets:shallowReadonly(targets),snapshot:shallowReadonly(snapshot),selected:shallowReadonly(selected),taskID:shallowReadonly(taskID),target,show,hide,refresh,choose,submit,confirm}
}
