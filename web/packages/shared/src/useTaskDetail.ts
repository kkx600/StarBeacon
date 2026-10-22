import {onScopeDispose,reactive,watch,type ComputedRef} from 'vue'
import type {SensorTask,TaskDetailState,Principal} from './types'
import type {ApiClient} from './api'
import {validApplicationState} from './application'
import {validResponseProtection} from './responseProtection'

const id=/^[a-z0-9][a-z0-9_-]{0,63}$/
const kinds=new Set(['diagnostics','capture.configure','applications.apply','rules.validate','rules.replay','rules.apply','rules.reconcile','response.block','response.read','response.revoke'])
const states=new Set(['queued','delivered','running','succeeded','failed','unknown','expired','cancelled'])
const object=(v:unknown):v is Record<string,unknown>=>!!v&&typeof v==='object'&&!Array.isArray(v)
export function validTask(v:unknown,requested:string,sensor?:string,local=false):v is SensorTask{
 if(local){
  if(!object(v)||v.id!==requested||typeof v.sensor_id!=='string'||!id.test(v.sensor_id)||sensor&&v.sensor_id!==sensor||!kinds.has(String(v.kind))||!['running','succeeded','failed','unknown'].includes(String(v.state))||!['local','platform'].includes(String(v.origin))||typeof v.acknowledged!=='boolean'||typeof v.retention_protected!=='boolean'||!object(v.receipt))return false
  if(!['created_at','expires_at','retain_until'].every(key=>typeof v[key]==='string'&&Number.isFinite(Date.parse(v[key] as string)))||Date.parse(v.expires_at as string)<=Date.parse(v.created_at as string)||Date.parse(v.retain_until as string)<=Date.now()&&!v.retention_protected)return false
  const receipt=v.receipt
  if(receipt.command_id!==requested||receipt.state!==v.state||typeof receipt.command_sha256!=='string'||!/^[a-f0-9]{64}$/.test(receipt.command_sha256)||!object(receipt.result)||typeof receipt.started_at!=='string'||!Number.isFinite(Date.parse(receipt.started_at))||Date.parse(v.retain_until as string)<=Date.parse(receipt.started_at))return false
  if(v.state!=='running'&&(typeof receipt.finished_at!=='string'||!Number.isFinite(Date.parse(receipt.finished_at))||Date.parse(receipt.finished_at)<Date.parse(receipt.started_at)))return false
  if(v.rule_resolution!==undefined&&!object(v.rule_resolution))return false
  if(v.retention_protected!==(!v.acknowledged||v.state==='running'||v.state==='unknown'&&!v.rule_resolution))return false
  return v.origin!=='local'||String(v.kind)==='rules.replay'&&requested.startsWith('localtask_')
 }
 if(!object(v)||v.id!==requested||typeof v.sensor_id!=='string'||!id.test(v.sensor_id)||sensor&&v.sensor_id!==sensor||typeof v.created_by!=='string'||!id.test(v.created_by)||!kinds.has(String(v.kind))||!states.has(String(v.state))||!Number.isSafeInteger(v.delivery_count)||Number(v.delivery_count)<0||!object(v.receipt))return false
 if(!['created_at','expires_at','updated_at','retain_until'].every(key=>typeof v[key]==='string'&&Number.isFinite(Date.parse(v[key] as string))))return false
 if(Date.parse(v.retain_until as string)<=Date.now()||Date.parse(v.expires_at as string)<=Date.parse(v.created_at as string))return false
 if(v.rule_resolution!==undefined&&!object(v.rule_resolution))return false
 if(String(v.kind).startsWith('response.')){
  const a=v.response_action
  if(!object(a)||a.schema_version!=='response.action.v1'||!['connector_id','device_id','lease_id'].every(key=>typeof a[key]==='string'&&id.test(a[key] as string))||!['config_sha256','owner_sha256'].every(key=>typeof a[key]==='string'&&/^[a-f0-9]{64}$/.test(a[key] as string))||typeof a.target_ip!=='string'||!a.target_ip||typeof a.reason!=='string'||!a.reason||!['requested_at','expires_at'].every(key=>typeof a[key]==='string'&&Number.isFinite(Date.parse(a[key] as string)))||v.kind==='response.block'&&a.lease_id!==requested)return false
  if(!validResponseProtection(v.response_protection,String(v.kind),String(a.requested_at),String(a.expires_at)))return false
 }
 if(v.response_protection!==undefined&&!String(v.kind).startsWith('response.'))return false
 return true
}

// 详情独立读取主键，不能把最近列表或旧回执当作当前任务快照。
export function useTaskDetail(task:ComputedRef<unknown>,options:{api:()=>ApiClient;principal:()=>Principal|null|undefined;sensor?:()=>string|undefined;local?:()=>boolean;enabled?:()=>boolean;responseOnly?:()=>boolean}){
 const sensor=()=>options.sensor?.(),local=()=>options.local?.()??false,enabled=()=>options.enabled?.()??true
 const detail=reactive<TaskDetailState>({open:false,item:null,pending:false,error:''})
 let controller:AbortController|undefined,timer:ReturnType<typeof setTimeout>|undefined,stopped=false,failures=0
 function abort(){controller?.abort();controller=undefined;if(timer)clearTimeout(timer);timer=undefined}
 async function refresh(){
  if(stopped||!detail.open||options.principal()?.role!=='admin')return
  abort();const requested=task.value
  detail.item=null;detail.error='';detail.pending=false
  if(typeof requested!=='string'||!id.test(requested)){detail.error='任务链接无效，请从任务记录或处置档案重新打开。';return}
  const current=new AbortController();controller=current;detail.pending=true
  try{
   const result=await options.api().request<unknown>((options.responseOnly?.()?'/response-actions/':'/tasks/')+encodeURIComponent(requested),{signal:current.signal})
   if(current.signal.aborted||controller!==current)return
   if(!validTask(result,requested,sensor(),local())||options.responseOnly?.()&&!result.kind.startsWith('response.'))throw new Error('任务详情未能完整返回，请刷新核对；不使用列表或历史回执代替。')
   if(result.kind==='applications.apply'&&result.state==='succeeded'){
    const installed=result.receipt.result
    if(!await validApplicationState(installed)||installed?.deployment_id!==requested)throw new Error('应用规则安装回执与原任务不一致，请刷新后核对。')
   }
   if(current.signal.aborted||controller!==current)return
   detail.item=result;failures=0
  }catch(cause){if(!current.signal.aborted&&controller===current){detail.error=cause instanceof Error?cause.message:'任务详情读取失败，请重试。';failures++}}
  finally{
   if(!current.signal.aborted&&controller===current){detail.pending=false;if(failures<3&&(detail.error||detail.item&&['queued','delivered','running'].includes(detail.item.state)))timer=setTimeout(()=>void refresh(),detail.error?5000*2**Math.max(0,failures-1):5000)}
  }
 }
 watch(()=>[task.value,sensor(),options.principal()?.tenant_id,options.principal()?.id,options.principal()?.role,options.api(),local(),enabled(),options.responseOnly?.()],()=>{
  abort();detail.item=null;detail.pending=false;detail.error='';failures=0
  detail.open=enabled()&&task.value!==undefined&&options.principal()?.role==='admin'
  if(detail.open)void refresh()
 },{immediate:true})
 onScopeDispose(()=>{stopped=true;abort();detail.item=null})
 return {detail,refresh}
}
