import {goJSONDigest} from '@starbeacon/shared/utils/goJSONDigest.ts'
import {policyID,policyReasons,policyStatuses,policyActions,orderedPolicy,validPolicy,type PolicyRecord,type PolicyResult} from './decisionPolicies'

export interface EvaluationRecord {schema_version:'decision-evaluation.v1';tenant_id:string;id:string;created_by:string;expires_at:string;policy:PolicyRecord;result:PolicyResult;sha256:string}
export interface EvaluationPage {items:EvaluationRecord[];next_cursor:string}
export interface EvaluationFilter {policy_id:string;triage_id:string;status:string}
const object=(v:unknown):v is Record<string,unknown>=>!!v&&typeof v==='object'&&!Array.isArray(v)
const digest=(v:unknown)=>typeof v==='string'&&/^[a-f0-9]{64}$/.test(v)
const date=(v:unknown)=>typeof v==='string'&&Number.isFinite(Date.parse(v))
function orderedResult(r:PolicyResult):PolicyResult {return {schema_version:r.schema_version,policy_id:r.policy_id,policy_revision:r.policy_revision,definition_sha256:r.definition_sha256,triage_id:r.triage_id,provider_id:r.provider_id,provider_revision:r.provider_revision,event_id:r.event_id,raw_sha256:r.raw_sha256,evidence_sha256:r.evidence_sha256,evaluated_at:r.evaluated_at,status:r.status,confidence:r.confidence,confidence_kind:r.confidence_kind,candidate_action:r.candidate_action,target_ip:r.target_ip,execution_authorized:r.execution_authorized,reasons:[...r.reasons],limitations:[...r.limitations],cost:r.cost}}
export function orderedEvaluation(e:EvaluationRecord):EvaluationRecord {const p=e.policy;return {schema_version:e.schema_version,tenant_id:e.tenant_id,id:e.id,created_by:e.created_by,expires_at:e.expires_at,policy:{tenant_id:p.tenant_id,id:p.id,revision:p.revision,name:p.name,description:p.description,active:p.active,definition:orderedPolicy(p.definition),definition_sha256:p.definition_sha256,created_by:p.created_by,created_at:p.created_at,expires_at:p.expires_at},result:orderedResult(e.result),sha256:''}}
export async function validEvaluation(v:unknown,tenant:string,owner:string):Promise<boolean> {
 if(!object(v)||Object.keys(v).length!==8||v.schema_version!=='decision-evaluation.v1'||v.tenant_id!==tenant||v.created_by!==owner||!policyID(v.id)||!date(v.expires_at)||!digest(v.sha256)||!object(v.policy)||!await validPolicy(v.policy,tenant)||!object(v.result))return false
 const p=v.policy as unknown as PolicyRecord,r=v.result
 if(r.schema_version!=='decision-shadow.v1'||r.policy_id!==p.id||r.policy_revision!==p.revision||r.definition_sha256!==p.definition_sha256||r.candidate_action!==p.definition.candidate_action||!policyID(r.triage_id)||!policyID(r.provider_id)||!policyID(r.event_id)||!Number.isSafeInteger(r.provider_revision)||Number(r.provider_revision)<1||!digest(r.raw_sha256)||!digest(r.evidence_sha256)||!date(r.evaluated_at)||Date.parse(String(v.expires_at))<=Date.parse(String(r.evaluated_at))||Date.parse(p.created_at)>Date.parse(String(r.evaluated_at))||!Object.hasOwn(policyStatuses,String(r.status))||!Object.hasOwn(policyActions,String(r.candidate_action))||r.confidence_kind!=='self_reported'||r.execution_authorized!==false||typeof r.target_ip!=='string'||r.target_ip.length>128||!Array.isArray(r.reasons)||r.reasons.length<1||r.reasons.length>3||new Set(r.reasons).size!==r.reasons.length||!r.reasons.every(x=>Object.hasOwn(policyReasons,String(x)))||!Array.isArray(r.limitations)||r.limitations.length!==7||!r.limitations.every(s=>typeof s==='string'&&s.trim()===s&&s.length>0&&[...s].length<=256&&!/\p{Cc}/u.test(s))||r.limitations[5]!=='影子评估不创建通知、研判修改或设备动作'||r.limitations[6]!=='模型自报分数未获得场景校准资格'||!(r.confidence===null||typeof r.confidence==='number'&&Number.isFinite(r.confidence)&&r.confidence>=0&&r.confidence<=1)||!(r.cost===null||Number.isSafeInteger(r.cost)&&Number(r.cost)>=0))return false
 if(r.status==='matched'||r.status==='not_matched'){if(!p.active||r.confidence===null||r.cost===null||Number(r.cost)>1000||r.reasons.length!==1||r.reasons[0]!==('expression_'+r.status)||r.candidate_action==='block_source'&&!r.target_ip)return false}
 else if(r.status==='protected'){if(!p.active||r.confidence===null||r.cost!==null||!r.target_ip||r.reasons.length!==1||r.reasons[0]!=='protected_source')return false}
 else if(r.reasons.some(x=>x==='expression_matched'||x==='expression_not_matched'||x==='protected_source'))return false
 return await goJSONDigest(orderedEvaluation(v as unknown as EvaluationRecord))===v.sha256
}
export async function validEvaluationPage(v:unknown,tenant:string,owner:string,filter:EvaluationFilter,limit=20):Promise<boolean> {
 if(!object(v)||!Array.isArray(v.items)||v.items.length>limit||typeof v.next_cursor!=='string'||v.next_cursor!==''&&(!policyID(v.next_cursor)||v.items.length!==limit||!object(v.items.at(-1))||v.items.at(-1).id!==v.next_cursor))return false
 const seen=new Set<string>()
 for(const value of v.items){if(!await validEvaluation(value,tenant,owner))return false;const e=value as EvaluationRecord;if(seen.has(e.id)||filter.policy_id&&e.result.policy_id!==filter.policy_id||filter.triage_id&&e.result.triage_id!==filter.triage_id||filter.status&&e.result.status!==filter.status)return false;seen.add(e.id)}
 return true
}
