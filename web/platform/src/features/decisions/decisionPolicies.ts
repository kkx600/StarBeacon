import {goJSONDigest} from '@starbeacon/shared/utils/goJSONDigest.ts'
import {validTriageJob,type TriageJob} from '../alerts/triage'
export const policyActions={investigate:'继续调查',notify:'建议通知安全人员',block_source:'建议评估源 IP 封禁'} as const
export const policyStatuses={matched:'策略命中',not_matched:'策略未命中',protected:'保护网段排除',abstained:'不参与决策'} as const
export const policyReasons={policy_inactive:'策略已停用',triage_not_eligible:'研判未完成、已取消或已到期',evidence_outside_window:'材料观测时间超出策略范围',source_identity_unavailable:'源 IP 不可用于目标识别',protected_source:'源 IP 属于保护网段',expression_evaluation_failed:'表达式运行错误或超出计算额度',expression_matched:'表达式命中',expression_not_matched:'表达式未命中'} as const
export interface PolicyDefinition {schema_version:'decision-policy.v1';mode:'shadow';expression:string;threshold:number;candidate_action:keyof typeof policyActions;max_age_seconds:number;protected_prefixes:string[]}
export interface PolicyChange {id:string;expected_revision:number;name:string;description:string;active:boolean;definition:PolicyDefinition}
export interface PolicyRecord {tenant_id:string;id:string;revision:number;name:string;description:string;active:boolean;definition:PolicyDefinition;definition_sha256:string;created_by:string;created_at:string;expires_at:string}
export interface PolicyPage {items:PolicyRecord[];next_cursor:string}
export interface PolicyResult {schema_version:'decision-shadow.v1';policy_id:string;policy_revision:number;definition_sha256:string;triage_id:string;provider_id:string;provider_revision:number;event_id:string;raw_sha256:string;evidence_sha256:string;evaluated_at:string;status:keyof typeof policyStatuses;confidence:number|null;confidence_kind:'self_reported';candidate_action:keyof typeof policyActions;target_ip:string;execution_authorized:false;reasons:(keyof typeof policyReasons)[];limitations:string[];cost:number|null}
const object=(v:unknown):v is Record<string,unknown>=>!!v&&typeof v==='object'&&!Array.isArray(v)
export const policyID=(v:unknown):v is string=>typeof v==='string'&&/^[a-z0-9][a-z0-9_-]{0,63}$/.test(v)
const text=(v:unknown,max:number,required=false,multiline=false):v is string=>typeof v==='string'&&v===v.trim()&&(!required||v!=='')&&[...v].length<=max&&!/\p{Cc}/u.test(multiline?v.replace(/[\n\t]/g,''):v)
const revision=(v:unknown,min=1)=>Number.isSafeInteger(v)&&Number(v)>=min&&Number(v)<=1000000
const digest=(v:unknown)=>typeof v==='string'&&/^[a-f0-9]{64}$/.test(v)
const date=(v:unknown)=>typeof v==='string'&&Number.isFinite(Date.parse(v))
export function orderedPolicy(d:PolicyDefinition):PolicyDefinition {return {schema_version:d.schema_version,mode:d.mode,expression:d.expression,threshold:d.threshold,candidate_action:d.candidate_action,max_age_seconds:d.max_age_seconds,protected_prefixes:[...d.protected_prefixes]}}
export function validPolicyDefinition(v:unknown):v is PolicyDefinition {
 return object(v)&&Object.keys(v).length===7&&v.schema_version==='decision-policy.v1'&&v.mode==='shadow'&&text(v.expression,2048,true,true)&&new TextEncoder().encode(v.expression).length<=2048&&typeof v.threshold==='number'&&Number.isFinite(v.threshold)&&v.threshold>0&&v.threshold<=1&&Object.hasOwn(policyActions,String(v.candidate_action))&&Number.isSafeInteger(v.max_age_seconds)&&Number(v.max_age_seconds)>=60&&Number(v.max_age_seconds)<=86400&&Array.isArray(v.protected_prefixes)&&v.protected_prefixes.length<=32&&new Set(v.protected_prefixes).size===v.protected_prefixes.length&&v.protected_prefixes.every(p=>text(p,128,true)&&/^[0-9a-f.:]+\/[0-9]{1,3}$/.test(p))
}
export function policyChangeError(v:PolicyChange):string {
 if(!policyID(v.id)||!revision(v.expected_revision,0)||v.expected_revision===1000000)return '策略标识或期望修订无效。'
 if(!text(v.name,128,true)||!text(v.description,1000))return '请填写策略名称，说明不能包含控制字符。'
 if(typeof v.active!=='boolean'||v.expected_revision===0&&!v.active)return '创建策略时须启用。'
 if(!validPolicyDefinition(v.definition))return '请核对表达式、分数阈值、材料时限与保护网段。'
 return ''
}
export async function validPolicy(v:unknown,tenant:string):Promise<boolean> {
 return object(v)&&v.tenant_id===tenant&&policyID(v.id)&&revision(v.revision)&&text(v.name,128,true)&&text(v.description,1000)&&typeof v.active==='boolean'&&validPolicyDefinition(v.definition)&&digest(v.definition_sha256)&&policyID(v.created_by)&&date(v.created_at)&&date(v.expires_at)&&Date.parse(String(v.expires_at))>Date.parse(String(v.created_at))&&await goJSONDigest(orderedPolicy(v.definition))===v.definition_sha256
}
export async function validPolicyPage(v:unknown,tenant:string,cursor:string,active:string,limit=20):Promise<boolean> {
 if(!object(v)||!Array.isArray(v.items)||v.items.length>limit||typeof v.next_cursor!=='string'||v.next_cursor!==''&&(!policyID(v.next_cursor)||v.items.length!==limit||!object(v.items.at(-1))||v.items.at(-1).id!==v.next_cursor))return false
 let prior=cursor
 for(const row of v.items){if(!object(row)||typeof row.id!=='string'||row.id<=prior||active!==''&&row.active!==(active==='true')||!await validPolicy(row,tenant))return false;prior=row.id}
 return true
}
export async function validPolicyReceipt(v:unknown,tenant:string,input:PolicyChange):Promise<boolean> {
 return object(v)&&v.id===input.id&&v.revision===input.expected_revision+1&&v.name===input.name&&v.description===input.description&&v.active===input.active&&await validPolicy(v,tenant)&&await goJSONDigest(orderedPolicy(input.definition))===v.definition_sha256
}
export async function validPolicyValidation(v:unknown,d:PolicyDefinition):Promise<boolean> {return object(v)&&v.valid===true&&v.schema_version==='decision-policy.v1'&&v.execution_authorized===false&&await goJSONDigest(orderedPolicy(d))===v.definition_sha256}
export async function validShadowResult(v:unknown,p:PolicyRecord,j:TriageJob):Promise<boolean> {
 if(!validTriageJob(j)||!object(v)||v.schema_version!=='decision-shadow.v1'||v.policy_id!==p.id||v.policy_revision!==p.revision||v.definition_sha256!==p.definition_sha256||v.triage_id!==j.id||v.provider_id!==j.request.provider_id||v.provider_revision!==j.request.provider_revision||v.event_id!==j.request.event_id||v.raw_sha256!==j.request.raw_sha256||v.evidence_sha256!==j.evidence.sha256||!date(v.evaluated_at)||!Object.hasOwn(policyStatuses,String(v.status))||v.confidence_kind!=='self_reported'||v.execution_authorized!==false||v.candidate_action!==p.definition.candidate_action||typeof v.target_ip!=='string'||v.target_ip.length>128||!Array.isArray(v.reasons)||v.reasons.length<1||v.reasons.length>3||!v.reasons.every(r=>Object.hasOwn(policyReasons,String(r)))||!Array.isArray(v.limitations)||v.limitations.length!==7||!v.limitations.every(s=>text(s,256,true))||!(v.cost===null||Number.isSafeInteger(v.cost)&&Number(v.cost)>=0)||!(v.confidence===null||typeof v.confidence==='number'&&v.confidence===j.answer?.confidence))return false
 const e=j.evidence
 if(await goJSONDigest({event_id:e.event_id,raw_sha256:e.raw_sha256,observed_at:e.observed_at,facts:e.facts.map(f=>({id:f.id,label:f.label,value:f.value})),limitations:[...e.limitations],limited:e.limited,sha256:''})!==e.sha256)return false
 const limitations=v.limitations as string[]
 if(!e.limitations.every((s,i)=>limitations[i]===s))return false
 if(v.status==='matched'||v.status==='not_matched')return v.confidence!==null&&v.cost!==null&&v.reasons.length===1&&v.reasons[0]===(v.status==='matched'?'expression_matched':'expression_not_matched')
 if(v.status==='protected')return v.confidence!==null&&v.cost===null&&v.reasons.length===1&&v.reasons[0]==='protected_source'&&!!v.target_ip
 return !v.reasons.some(r=>r==='expression_matched'||r==='expression_not_matched'||r==='protected_source')
}
