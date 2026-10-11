import type {Overview} from '../overview/overview'
import type {ModelResult} from '../models/models'
export type AnalysisKind='chat'|'daily'|'weekly'|'monthly'
export interface AnalysisRequest {kind:AnalysisKind;provider_id:string;provider_revision:number;thread_id:string;parent_id:string;question:string;window:{start:string;end:string};period:string;timezone:string;allow_context:boolean}
export interface AnalysisAnswer {summary:string;observations:{text:string;sources:string[]}[];recommendations:{text:string;sources:string[]}[]}
export interface AnalysisJob {id:string;revision:number;request:AnalysisRequest;state:string;cancel_requested:boolean;template:string;evidence:{window:{start:string;end:string};segments:Overview[];sha256:string};answer:AnalysisAnswer|null;result:ModelResult;created_at:string;started_at:string|null;finished_at:string|null;expires_at:string}
export interface AnalysisSummary {id:string;kind:AnalysisKind;thread_id:string;title:string;state:string;revision:number;window:{start:string;end:string};created_at:string;cancel_requested:boolean}
export interface AnalysisThread {id:string;title:string;updated_at:string;last_job_id:string;state:string}
export interface Conversation {id:string;title:string;jobs:AnalysisJob[];next_cursor:string}
export interface AnalysisPage {items:AnalysisSummary[];next_cursor:string;model_execution_available:boolean}
export interface ThreadPage {items:AnalysisThread[];next_cursor:string}
export const kindNames:Record<AnalysisKind,string>={chat:'智能助手',daily:'安全日报',weekly:'安全周报',monthly:'安全月报'}
export const stateNames:Record<string,string>={queued:'等待分析',running:'分析中',succeeded:'处理完成',failed:'分析失败',refused:'提供方拒答',incomplete:'输出未完成',uncertain:'结果未知',cancelled:'已取消'}
export const analysisCodes:Record<string,string>={awaiting_execution:'作业等待执行',statistics_only:'已生成统计报告，未调用模型',invalid_analysis_output:'模型输出或来源引用校验未通过',authorization_revoked:'作业所有者已失去执行权限',provider_revision_changed:'模型配置修订已改变，调用未执行',provider_disabled:'模型提供方已停用，调用未执行',provider_config_unavailable:'模型配置或凭据不可用，调用未执行',analysis_input_invalid:'分析输入校验未通过，调用未执行',queue_wait_expired:'等待执行超时，调用未执行',cancelled_before_execution:'作业在模型调用前取消'}
export function working(state:string){return state==='queued'||state==='running'}
export function totalAlerts(job:AnalysisJob){return job.evidence.segments.reduce((sum,s)=>sum+BigInt(s.events.total),0n).toString()}
function record(value:unknown):value is Record<string,unknown>{return value!==null&&typeof value==='object'&&!Array.isArray(value)}
function id(value:unknown){return typeof value==='string'&&/^[a-zA-Z0-9_-]{1,128}$/.test(value)}
function cursor(value:unknown){return value===''||id(value)}
function text(value:unknown,maximum:number){return typeof value==='string'&&[...value].length<=maximum}
function date(value:unknown){return typeof value==='string'&&Number.isFinite(Date.parse(value))}
function window(value:unknown):value is {start:string;end:string}{return record(value)&&date(value.start)&&date(value.end)&&Date.parse(String(value.end))>Date.parse(String(value.start))}
function count(value:unknown){return typeof value==='string'&&/^(0|[1-9][0-9]{0,18})$/.test(value)&&BigInt(value)<=9223372036854775807n}
function state(value:unknown){return typeof value==='string'&&Object.hasOwn(stateNames,value)}
function kind(value:unknown){return typeof value==='string'&&Object.hasOwn(kindNames,value)}
function unique(values:unknown[]){return new Set(values).size===values.length}
export function validPage(value:unknown):value is AnalysisPage{
 return record(value)&&typeof value.model_execution_available==='boolean'&&cursor(value.next_cursor)&&Array.isArray(value.items)&&value.items.length<=50&&unique(value.items.map(row=>record(row)?row.id:null))&&value.items.every(row=>record(row)&&id(row.id)&&kind(row.kind)&&state(row.state)&&Number.isSafeInteger(row.revision)&&Number(row.revision)>0&&cursor(row.thread_id)&&text(row.title,80)&&window(row.window)&&date(row.created_at)&&typeof row.cancel_requested==='boolean')
}
export function validThreads(value:unknown):value is ThreadPage{
 return record(value)&&cursor(value.next_cursor)&&Array.isArray(value.items)&&value.items.length<=20&&unique(value.items.map(row=>record(row)?row.id:null))&&value.items.every(row=>record(row)&&id(row.id)&&text(row.title,80)&&date(row.updated_at)&&id(row.last_job_id)&&state(row.state))
}
export function validConversation(value:unknown,expectedID:string):value is Conversation{
 return record(value)&&value.id===expectedID&&id(value.id)&&text(value.title,80)&&cursor(value.next_cursor)&&Array.isArray(value.jobs)&&value.jobs.length<=10&&unique(value.jobs.map(job=>record(job)?job.id:null))&&value.jobs.every(job=>validJob(job)&&job.request.kind==='chat'&&job.request.thread_id===expectedID)
}
export function validJob(value:unknown):value is AnalysisJob {
 if(!record(value)||!id(value.id)||!state(value.state)||!Number.isSafeInteger(value.revision)||Number(value.revision)<1||typeof value.cancel_requested!=='boolean'||!date(value.created_at)||!date(value.expires_at)||!record(value.request)||!kind(value.request.kind)||!window(value.request.window)||!record(value.result)||!state(value.result.state)||!text(value.result.code,128)||!record(value.evidence)||!window(value.evidence.window)||typeof value.evidence.sha256!=='string'||!/^[a-f0-9]{64}$/.test(value.evidence.sha256))return false
 const segments=value.evidence.segments
 if(!Array.isArray(segments)||segments.length<1||segments.length>2)return false
 let boundary=value.evidence.window.start
 for(const s of segments){
  if(!record(s)||!window(s.window)||s.window.start!==boundary||!date(s.observed_at)||!record(s.events)||!record(s.inventory)||!count(s.events.total)||!(['assets','groups','networks','sensors','online','offline','disabled'] as const).every(key=>count((s.inventory as Record<string,unknown>)[key])))return false
  for(const key of ['severity','protocols','rules','sensors'] as const){const distribution=s.events[key];if(!record(distribution)||!count(distribution.other)||!count(distribution.error_upper_bound)||!Array.isArray(distribution.buckets)||distribution.buckets.length>10||!distribution.buckets.every(b=>record(b)&&text(b.key,128)&&count(b.count)))return false}
  boundary=s.window.end
 }
 if(boundary!==value.evidence.window.end||value.request.window.start!==value.evidence.window.start||value.request.window.end!==value.evidence.window.end)return false
 const usage=value.result.usage
 if(usage!==null&&(!record(usage)||!['input_tokens','output_tokens','total_tokens'].every(key=>Number.isSafeInteger(usage[key])&&Number(usage[key])>=0)||Number(usage.input_tokens)+Number(usage.output_tokens)!==usage.total_tokens))return false
 if(value.result.duration_ms!=null&&(!Number.isSafeInteger(value.result.duration_ms)||Number(value.result.duration_ms)<0))return false
 const answer=value.answer
 if(answer===null)return true
 if(!record(answer)||!text(answer.summary,1200)||!Array.isArray(answer.observations)||!Array.isArray(answer.recommendations)||answer.observations.length>10||answer.recommendations.length>10)return false
 const sources=new Set(analysisFacts(value as unknown as AnalysisJob).map(f=>f.id))
 return [...answer.observations,...answer.recommendations].every(row=>record(row)&&text(row.text,512)&&Array.isArray(row.sources)&&row.sources.length>0&&row.sources.length<=5&&unique(row.sources)&&row.sources.every(source=>typeof source==='string'&&sources.has(source)))
}
export function analysisFacts(job:AnalysisJob){
 const facts=[{id:'window',label:'完整统计范围',value:`${job.evidence.window.start} — ${job.evidence.window.end}`},{id:'alerts.total',label:'已索引告警总数',value:totalAlerts(job)}]
 for(const[sIndex,s]of job.evidence.segments.entries()){
  facts.push({id:`segment.${sIndex}.window`,label:'分段统计范围',value:`${s.window.start} — ${s.window.end}`})
  for(const key of ['severity','protocols','rules','sensors'] as const){const label=key==='severity'?'告警级别':key==='protocols'?'协议':key==='rules'?'规则':'探针';facts.push({id:`segment.${sIndex}.${key}.other`,label:label+'分布其他数量',value:s.events[key].other},{id:`segment.${sIndex}.${key}.error`,label:label+'分布误差上界',value:s.events[key].error_upper_bound});s.events[key].buckets.forEach((b,index)=>facts.push({id:`segment.${sIndex}.${key}.${index}`,label:label+'：'+b.key,value:b.count}))}
 }
 const latest=job.evidence.segments.at(-1)!
 facts.push({id:'inventory.assets',label:'登记资产（生成时）',value:latest.inventory.assets},{id:'inventory.online',label:'在线探针（生成时）',value:latest.inventory.online},{id:'inventory.offline',label:'离线探针（生成时）',value:latest.inventory.offline},{id:'observed_at',label:'末段观测时间',value:latest.observed_at})
 return facts
}
export function blankRequest(kind:AnalysisKind):AnalysisRequest{return{kind,provider_id:'',provider_revision:0,thread_id:'',parent_id:'',question:'',window:{start:'0001-01-01T00:00:00Z',end:'0001-01-01T00:00:00Z'},period:'',timezone:'',allow_context:false}}
