import {policyID,type PolicyRecord} from './decisionPolicies'
export const triggerStates={pending:'等待模型队列',submitted:'模型队列已受理',skipped:'未提交'} as const
export const triggerCodes={awaiting_model_queue:'等待执行服务核对',model_queue_accepted:'已创建独立研判作业',authorization_unavailable:'许可已撤回、配置变化或材料超时',evidence_changed:'原告警不存在或材料已变化',model_quota:'模型或租户费用额度已用尽'} as const
export interface AutomaticTriageRecord {id:string;policy_id:string;policy_revision:number;definition_sha256:string;event_id:string;raw_sha256:string;sensor_id:string;registration_id:string;state:keyof typeof triggerStates;code:keyof typeof triggerCodes;triage_id:string;created_at:string;expires_at:string}
export interface AutomaticTriagePage {items:AutomaticTriageRecord[];next_cursor:string}
const object=(v:unknown):v is Record<string,unknown>=>!!v&&typeof v==='object'&&!Array.isArray(v)
const digest=(v:unknown)=>typeof v==='string'&&/^[a-f0-9]{64}$/.test(v)
export function validAutomaticTriagePage(v:unknown,p:PolicyRecord,cursor:string):v is AutomaticTriagePage {
 if(!object(v)||Object.keys(v).length!==2||!Array.isArray(v.items)||v.items.length>20||typeof v.next_cursor!=='string'||v.next_cursor!==''&&(!policyID(v.next_cursor)||v.items.length!==20||!object(v.items.at(-1))||v.items.at(-1).id!==v.next_cursor))return false
 let prior=cursor
 for(const row of v.items){
  const a=p.definition.continuous?.automatic
  if(!object(row)||Object.keys(row).length!==13||!policyID(row.id)||row.id<=prior||row.policy_id!==p.id||row.policy_revision!==p.revision||row.definition_sha256!==p.definition_sha256||!policyID(row.event_id)||!digest(row.raw_sha256)||!a||row.sensor_id!==a.sensor_id||row.registration_id!==a.registration_id||typeof row.state!=='string'||!Object.hasOwn(triggerStates,row.state)||typeof row.code!=='string'||!Object.hasOwn(triggerCodes,row.code)||typeof row.triage_id!=='string'||typeof row.created_at!=='string'||!Number.isFinite(Date.parse(row.created_at))||typeof row.expires_at!=='string'||!Number.isFinite(Date.parse(row.expires_at))||Date.parse(row.expires_at)<=Date.parse(row.created_at))return false
  if(row.state==='submitted'?row.code!=='model_queue_accepted'||!policyID(row.triage_id):row.triage_id!==''||(row.state==='pending'?row.code!=='awaiting_model_queue':!['authorization_unavailable','evidence_changed','model_quota'].includes(row.code)))return false
  prior=row.id
 }
 return true
}
