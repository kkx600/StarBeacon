import type {ModelResult} from '../models/models'

export const triageStates={queued:'等待研判',running:'研判中',succeeded:'建议已生成',failed:'研判失败',refused:'提供方拒答',incomplete:'输出未完成',uncertain:'结果未知',cancelled:'已取消'} as const
export const triageVerdicts={undetermined:'证据不足',suspicious:'待核实',false_positive:'疑似误报',confirmed:'疑似威胁'} as const
export const triageOutcomes={unknown:'攻击结果尚未确认',attempt:'观察到攻击尝试'} as const
export const triageRecommendations={investigate:'继续调查',notify:'通知安全人员',block_source:'建议评估源 IP 封禁'} as const
export const triageCodes:Record<string,string>={awaiting_execution:'作业等待执行',request_in_progress:'正在请求模型，结果尚未返回',invalid_triage_output:'研判结构、结论或事实引用未通过校验',alert_source_unavailable:'告警来源已变化、过期或不可访问，调用未执行',authorization_revoked:'作业所有者已失去执行权限，调用未执行',provider_revision_changed:'模型修订已改变，调用未执行',provider_disabled:'模型提供方已停用，调用未执行',provider_config_unavailable:'模型配置或凭据不可用，调用未执行',triage_input_invalid:'冻结材料或研判模板无法核验，调用未执行',queue_wait_expired:'等待执行超时，调用未执行',cancelled_before_execution:'作业在模型调用前取消'}
export type TriageState=keyof typeof triageStates
export interface TriageRequest {event_id:string;raw_sha256:string;provider_id:string;provider_revision:number;note:string;allow_context:boolean}
export interface TriageFact {id:string;label:string;value:string}
export interface TriageEvidence {event_id:string;raw_sha256:string;observed_at:string;facts:TriageFact[];limitations:string[];limited:boolean;sha256:string}
export interface TriageAnswer {verdict:keyof typeof triageVerdicts;outcome:keyof typeof triageOutcomes;confidence:number;reason:string;references:string[];counter_evidence:string[];missing:string[];recommendation:keyof typeof triageRecommendations;needs_review:true}
export interface TriageJob {id:string;request:TriageRequest;state:TriageState;cancel_requested:boolean;template:'alert-triage/1';evidence:TriageEvidence;answer:TriageAnswer|null;result:ModelResult;confidence_kind:'self_reported';created_at:string;started_at:string|null;finished_at:string|null;expires_at:string}
export interface TriageSummary {id:string;state:TriageState;provider_id:string;created_at:string}
export interface TriagePage {items:TriageSummary[];next_cursor:string;model_execution_available:boolean}
export interface TriageProvider {id:string;revision:number;name:string;enabled:boolean;has_key:boolean}
const factIDs=['event.time','sensor.id','sensor.registration','source.ip','destination.ip','network.transport','network.protocol','rule.id','rule.revision','rule.name','http.method','http.hostname','http.path','severity','suricata.flow','suricata.action','evidence.status']
function record(v:unknown):v is Record<string,unknown>{return !!v&&typeof v==='object'&&!Array.isArray(v)}
function id(v:unknown){return typeof v==='string'&&/^[a-z0-9][a-z0-9_-]{0,63}$/.test(v)}
function hash(v:unknown){return typeof v==='string'&&/^[a-f0-9]{64}$/.test(v)}
function text(v:unknown,max:number,empty=false){return typeof v==='string'&&[...v].length<=max&&(empty||!!v.trim())&&!/\p{Cc}/u.test(v.replace(/[\n\t]/g,''))}
function date(v:unknown){return typeof v==='string'&&Number.isFinite(Date.parse(v))}
function count(v:unknown){return Number.isSafeInteger(v)&&Number(v)>=0}
function state(v:unknown){return typeof v==='string'&&Object.hasOwn(triageStates,v)}
function list(v:unknown):v is string[]{return Array.isArray(v)&&v.length<=8&&new Set(v).size===v.length&&v.every(s=>text(s,512))}
export function triageWorking(value:string){return value==='queued'||value==='running'}
export function sameTriageRequest(a:TriageRequest,b:TriageRequest){return a.event_id===b.event_id&&a.raw_sha256===b.raw_sha256&&a.provider_id===b.provider_id&&a.provider_revision===b.provider_revision&&a.note===b.note&&a.allow_context===b.allow_context}
export function validTriageRequest(v:unknown):v is TriageRequest{return record(v)&&id(v.event_id)&&hash(v.raw_sha256)&&id(v.provider_id)&&Number.isSafeInteger(v.provider_revision)&&Number(v.provider_revision)>0&&text(v.note,2000,true)&&v.allow_context===true}
export function validTriageProviders(v:unknown):v is {items:TriageProvider[];available:boolean}{return record(v)&&typeof v.available==='boolean'&&Array.isArray(v.items)&&v.items.length<=100&&new Set(v.items.map(r=>record(r)?r.id:null)).size===v.items.length&&v.items.every(r=>record(r)&&id(r.id)&&Number.isSafeInteger(r.revision)&&Number(r.revision)>0&&text(r.name,128)&&typeof r.enabled==='boolean'&&typeof r.has_key==='boolean')}
export function validTriagePage(v:unknown):v is TriagePage{
 if(!record(v)||typeof v.model_execution_available!=='boolean'||!Array.isArray(v.items)||v.items.length>20||new Set(v.items.map(r=>record(r)?r.id:null)).size!==v.items.length)return false
 return v.items.every(r=>record(r)&&id(r.id)&&id(r.provider_id)&&state(r.state)&&date(r.created_at))&&(v.next_cursor===''||v.items.length===20&&v.next_cursor===v.items[19].id)
}
export function validTriageAnswer(v:unknown,e:TriageEvidence):v is TriageAnswer{
 if(!record(v)||!Object.hasOwn(triageVerdicts,String(v.verdict))||!Object.hasOwn(triageOutcomes,String(v.outcome))||!Object.hasOwn(triageRecommendations,String(v.recommendation))||v.needs_review!==true||typeof v.confidence!=='number'||!Number.isFinite(v.confidence)||v.confidence<0||v.confidence>1||!text(v.reason,2000)||!list(v.references)||!list(v.counter_evidence)||!list(v.missing))return false
 if(v.references.some(ref=>!e.facts.some(f=>f.id===ref))||v.verdict!=='undetermined'&&!v.references.length||v.verdict==='false_positive'&&(v.outcome!=='unknown'||!v.counter_evidence.length)||v.verdict!=='confirmed'&&v.outcome!=='unknown')return false
 return v.recommendation!=='block_source'||v.verdict==='confirmed'&&v.references.length>0&&v.counter_evidence.length>0&&e.facts.some(f=>f.id==='source.ip')
}
export function validTriageJob(v:unknown):v is TriageJob{
 if(!record(v)||!id(v.id)||!validTriageRequest(v.request)||!state(v.state)||typeof v.cancel_requested!=='boolean'||v.template!=='alert-triage/1'||v.confidence_kind!=='self_reported'||!date(v.created_at)||!date(v.expires_at)||!(v.started_at===null||date(v.started_at))||!(v.finished_at===null||date(v.finished_at)))return false
 const e=v.evidence,r=v.result
 if(!record(e)||e.event_id!==v.request.event_id||e.raw_sha256!==v.request.raw_sha256||!date(e.observed_at)||!hash(e.sha256)||typeof e.limited!=='boolean'||!Array.isArray(e.facts)||e.facts.length<3||e.facts.length>17||new Set(e.facts.map(f=>record(f)?f.id:null)).size!==e.facts.length||!e.facts.every(f=>record(f)&&factIDs.includes(String(f.id))&&text(f.label,32)&&text(f.value,2048))||!Array.isArray(e.limitations)||e.limitations.length!==5||!e.limitations.every(s=>text(s,256)))return false
 const facts=e.facts as TriageFact[]
 if(!['event.time','sensor.id','sensor.registration'].every(required=>facts.some(f=>f.id===required)))return false
 if(!record(r)||r.state!==v.state||!text(r.code,100)||!(r.duration_ms===null||count(r.duration_ms))||!(r.returned_model===undefined||text(r.returned_model,512))||!(r.http_status===undefined||Number.isInteger(r.http_status)&&Number(r.http_status)>=100&&Number(r.http_status)<=599)||r.text!==undefined)return false
 if(r.usage!==null&&(!record(r.usage)||!count(r.usage.input_tokens)||!count(r.usage.output_tokens)||!count(r.usage.total_tokens)||Number(r.usage.input_tokens)+Number(r.usage.output_tokens)!==r.usage.total_tokens))return false
 if(triageWorking(String(v.state))?v.finished_at!==null:v.finished_at===null)return false
 return v.state==='succeeded'?validTriageAnswer(v.answer,e as unknown as TriageEvidence):v.answer===null
}
