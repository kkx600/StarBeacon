import {syncPlanValid,type RuleSyncPlan,type RuleSyncRun,type RuleSyncSpec} from './sync'

export interface RolloutSelection {plan_id:string;revision:number}
export interface RolloutSpec {name:string;plans:RolloutSelection[];canary_count:number;batch_size:number;observation_seconds:number;timeout_seconds:number}
export interface RolloutCreate {id:string;spec:RolloutSpec}
export interface RolloutTarget {ordinal:number;batch:number;plan_id:string;authorized_revision:number;execution_revision:number;spec:RuleSyncSpec;state:string;code:string;run?:RuleSyncRun}
export interface RuleRollout {id:string;spec:RolloutSpec;created_by:string;state:string;code:string;current_batch:number;package_sha256:string;created_at:string;deadline:string;next_at:string;observation_started_at?:string;finished_at?:string;expires_at:string;stop_reason:string;stopped_by:string;targets?:RolloutTarget[]}
export interface RolloutPage {items:RuleRollout[];next_cursor:string}
export const rolloutStates:Record<string,string>={pending:'等待启动批次',running:'逐台验证与发布',observing:'核对原生观测',stopping:'停止提交，等待在途回执',succeeded:'全部批次已核对',stopped:'已停止后续发布',blocked:'发布受阻'}
export const targetStates:Record<string,string>={queued:'尚未启用',active:'执行中',observing:'等待生效观察',succeeded:'生效已记录',blocked:'目标受阻',stopped:'未继续提交'}
export const rolloutCodes:Record<string,string>={observing:'等待完整观察时间及窗口后的心跳和原生观测',waiting_for_results:'等待独立任务回执',waiting_for_heartbeat:'等待发布完成后的新心跳',waiting_for_engine:'等待发布后的有效原生观测',engine_health_failed:'原生进程或规则装载核对未通过，停止后续提交',waiting_for_rule_task:'设备还有规则写入或未核实任务',owner_unavailable:'批准账号已停用或权限变化',deadline_exceeded:'执行期限已到，停止后续提交',target_failed:'目标验证失败或执行结果待核实',sensor_identity_changed:'目标已停用或注册代次变化',rules_digest_changed:'设备当前规则摘要与批准修订不一致',plan_changed:'批准计划修订已变化',operator_stopped:'管理员停止后续发布',not_dispatched:'未继续提交设备任务',applied:'独立发布回执已核对',observed:'发布后心跳与观察窗口已核对'}
const id=/^[a-z0-9][a-z0-9_-]{0,63}$/
const revision=(n:unknown):n is number=>Number.isSafeInteger(n)&&Number(n)>0&&Number(n)<Number.MAX_SAFE_INTEGER-1
const integer=(n:unknown,min:number,max:number)=>Number.isInteger(n)&&Number(n)>=min&&Number(n)<=max
export const rolloutTerminal=(state:string)=>['succeeded','stopped','blocked'].includes(state)
export function rolloutInputError(c:RolloutCreate):string {
 if(!c||!id.test(c.id??''))return '发布标识无效'
 const s=c.spec
 if(!s||typeof s.name!=='string'||!s.name||s.name.trim()!==s.name||[...s.name].length>128||/\p{Cc}/u.test(s.name))return '请填写 1–128 字的发布名称'
 if(!Array.isArray(s.plans)||s.plans.length<2||s.plans.length>200||s.plans.some(p=>!p||!id.test(p.plan_id)||!revision(p.revision))||new Set(s.plans.map(p=>p.plan_id)).size!==s.plans.length)return '请选择 2–200 个不同的停用计划，并核对批准修订'
 if(!integer(s.canary_count,1,Math.min(20,s.plans.length-1)))return '首批探针数须为 1–20，且小于全部目标数'
 if(!integer(s.batch_size,1,20))return '后续每批探针数范围为 1–20'
 if(!integer(s.observation_seconds,30,3600))return '批次观察时间范围为 30–3600 秒'
 if(!integer(s.timeout_seconds,300,86400)||s.timeout_seconds<=s.observation_seconds)return '执行期限范围为 300–86400 秒，且须大于观察时间'
 return ''
}
export function stopReasonError(reason:string):string{return typeof reason==='string'&&!!reason&&reason.trim()===reason&&[...reason].length<=512&&!/\p{Cc}/u.test(reason)?'':'请填写 1–512 字的停止原因'}
export function batchOf(s:RolloutSpec,index:number):number{return index<s.canary_count?0:1+Math.floor((index-s.canary_count)/s.batch_size)}
export function sameRolloutSpec(a:RolloutSpec,b:RolloutSpec):boolean{return a.name===b.name&&a.canary_count===b.canary_count&&a.batch_size===b.batch_size&&a.observation_seconds===b.observation_seconds&&a.timeout_seconds===b.timeout_seconds&&a.plans.length===b.plans.length&&a.plans.every((p,i)=>p.plan_id===b.plans[i]?.plan_id&&p.revision===b.plans[i]?.revision)}
export function validRollout(r:RuleRollout,detail=false):boolean{
 if(!r||rolloutInputError({id:r.id,spec:r.spec})||!id.test(r.created_by)||!Object.hasOwn(rolloutStates,r.state)||typeof r.code!=='string'||!integer(r.current_batch,0,batchOf(r.spec,r.spec.plans.length-1))||!/^([a-f0-9]{64})$/.test(r.package_sha256)||![r.created_at,r.deadline,r.next_at,r.expires_at].every(d=>typeof d==='string'&&Number.isFinite(Date.parse(d)))||Date.parse(r.expires_at)<=Date.parse(r.created_at)||typeof r.stop_reason!=='string'||typeof r.stopped_by!=='string'||r.stopped_by!==''&&!id.test(r.stopped_by)||!!r.finished_at!==rolloutTerminal(r.state)||r.finished_at&&!Number.isFinite(Date.parse(r.finished_at))||r.observation_started_at&&!Number.isFinite(Date.parse(r.observation_started_at)))return false
 if(!detail&&r.targets===undefined)return true
 return Array.isArray(r.targets)&&r.targets.length===r.spec.plans.length&&r.targets.every((t,i)=>{
  if(!t||t.ordinal!==i||t.batch!==batchOf(r.spec,i)||t.plan_id!==r.spec.plans[i]!.plan_id||t.authorized_revision!==r.spec.plans[i]!.revision||![0,t.authorized_revision+1].includes(t.execution_revision)||!Object.hasOwn(targetStates,t.state)||typeof t.code!=='string'||!t.spec||t.spec.enabled!==false)return false
  const plan:RuleSyncPlan={id:t.plan_id,revision:t.execution_revision||t.authorized_revision,spec:t.spec,created_by:r.created_by,updated_at:r.created_at,next_at:r.next_at,processed_revision:0,...(t.run?{run:t.run}:{})}
  return syncPlanValid(plan)&&(!t.run||t.run.plan_revision===t.execution_revision&&t.run.created_by===r.created_by&&Object.keys(t.spec).every(key=>t.run!.spec[key as keyof RuleSyncSpec]===(key==='enabled'?true:t.spec[key as keyof RuleSyncSpec])))
 })
}
