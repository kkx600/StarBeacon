import {stateNames,type AnalysisRequest} from './analysis'

export interface ReportPlanSpec {name:string;kind:'daily'|'weekly'|'monthly';timezone:string;at:string;enabled:boolean;provider_id:string;provider_revision:number;allow_context:boolean}
export interface ReportPlan {id:string;revision:number;spec:ReportPlanSpec;next_at:string|null;updated_at:string}
export interface ReportPlanChange {id:string;expected_revision:number;spec:ReportPlanSpec}
export interface ReportPlanPage {items:ReportPlan[];execution_available:boolean;model_execution_available:boolean;limit:32}
export interface ReportPlanRun {id:string;plan_revision:number;due_at:string;effective_at:string;skipped_from:string|null;skipped_until:string|null;request:AnalysisRequest;state:'preparing'|'submitted'|'failed'|'cancelled';code:string;analysis_id:string;analysis_state:string;created_at:string;finished_at:string|null;expires_at:string}
export interface ReportRunPage {items:ReportPlanRun[];next_cursor:string}

export const planCodes:Record<string,string>={report_submitted:'报告已提交，处理结果以报告状态为准',preparation_unavailable:'统计或执行服务未能完整返回，本周期未提交',plan_qualification_changed:'计划、所有者权限或模型修订已变化，本周期未提交',model_quota_exceeded:'模型额度或并发名额不足，本周期未提交',preparation_interrupted:'统计准备中断或超时，本周期未提交'}
export function planRunState(run:ReportPlanRun){return run.state==='submitted'?(run.analysis_state&&Object.hasOwn(stateNames,run.analysis_state)?stateNames[run.analysis_state]!:'报告已到保留期限'):run.state==='preparing'?'准备统计':run.state==='cancelled'?'已取消':'本周期未提交'}
function record(value:unknown):value is Record<string,unknown>{return !!value&&typeof value==='object'&&!Array.isArray(value)}
function id(value:unknown){return typeof value==='string'&&/^[a-z0-9][a-z0-9_-]{0,63}$/.test(value)}
function date(value:unknown){return typeof value==='string'&&Number.isFinite(Date.parse(value))}
function revision(value:unknown){return Number.isSafeInteger(value)&&Number(value)>0}
function cursor(value:unknown){return value===''||id(value)}
export function validPlanSpec(value:unknown):value is ReportPlanSpec{
 if(!record(value)||typeof value.name!=='string'||!value.name.trim()||value.name.trim()!==value.name||[...value.name].length>80||/[\p{Cc}]/u.test(value.name)||!['daily','weekly','monthly'].includes(String(value.kind))||typeof value.timezone!=='string'||value.timezone.length>128||!value.timezone||value.timezone==='Local'||value.timezone.includes('..')||typeof value.at!=='string'||!/^([01]\d|2[0-3]):[0-5]\d$/.test(value.at)||typeof value.enabled!=='boolean'||typeof value.allow_context!=='boolean')return false
 try{new Intl.DateTimeFormat('zh-CN',{timeZone:value.timezone})}catch{return false}
 return value.provider_id===''?value.provider_revision===0&&!value.allow_context:id(value.provider_id)&&revision(value.provider_revision)&&value.allow_context
}
export function validPlan(value:unknown):value is ReportPlan{
 return record(value)&&id(value.id)&&revision(value.revision)&&validPlanSpec(value.spec)&&date(value.updated_at)&&(value.spec.enabled?date(value.next_at):value.next_at===null)
}
export function validPlanPage(value:unknown):value is ReportPlanPage{
 return record(value)&&value.limit===32&&typeof value.execution_available==='boolean'&&typeof value.model_execution_available==='boolean'&&Array.isArray(value.items)&&value.items.length<=32&&value.items.every(validPlan)&&new Set(value.items.map(row=>row.id)).size===value.items.length
}
export function validPlanRun(value:unknown):value is ReportPlanRun{
 if(!record(value)||!id(value.id)||!revision(value.plan_revision)||!date(value.due_at)||!date(value.effective_at)||Date.parse(String(value.effective_at))<Date.parse(String(value.due_at))||!date(value.created_at)||!date(value.expires_at)||!(value.finished_at===null||date(value.finished_at))||!['preparing','submitted','failed','cancelled'].includes(String(value.state))||typeof value.code!=='string'||value.code.length>128||!record(value.request)||!['daily','weekly','monthly'].includes(String(value.request.kind))||!record(value.request.window)||!date(value.request.window.start)||!date(value.request.window.end)||Date.parse(String(value.request.window.end))<=Date.parse(String(value.request.window.start))||typeof value.request.period!=='string'||!/^\d{4}-\d{2}-\d{2}$/.test(value.request.period)||typeof value.request.timezone!=='string')return false
 if(value.skipped_from!==null||value.skipped_until!==null){if(!date(value.skipped_from)||!date(value.skipped_until)||Date.parse(String(value.skipped_from))!==Date.parse(String(value.due_at))||Date.parse(String(value.skipped_until))!==Date.parse(String(value.effective_at))||Date.parse(String(value.skipped_until))<=Date.parse(String(value.skipped_from)))return false}
 return value.state==='submitted'?id(value.analysis_id)&&(value.analysis_state===''||typeof value.analysis_state==='string'&&Object.hasOwn(stateNames,value.analysis_state)):value.analysis_id===''&&value.analysis_state===''
}
export function validRunPage(value:unknown):value is ReportRunPage{
 return record(value)&&cursor(value.next_cursor)&&Array.isArray(value.items)&&value.items.length<=20&&value.items.every(validPlanRun)&&new Set(value.items.map(row=>row.id)).size===value.items.length
}
