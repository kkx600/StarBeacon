export const incidentStatuses={open:'待调查',investigating:'调查中',closed:'已结案'} as const
export const incidentCategories={network_intrusion:'网络入侵',malware:'恶意软件',exposure:'风险暴露',abnormal:'异常行为',other:'其他事件'} as const
export const incidentSeverities={low:'低',medium:'中',high:'高',critical:'严重'} as const
export interface IncidentRef{event_id:string;raw_sha256:string}
export interface IncidentEvidence extends IncidentRef{sensor_id:string;observed_at:string;event_time:string}
export interface IncidentClosure{reason:'resolved'|'false_positive';root_cause:string;impact:string;remediation:string;verification:string;evidence:string[]}
export interface IncidentSpec{title:string;category:keyof typeof incidentCategories;severity:keyof typeof incidentSeverities;status:keyof typeof incidentStatuses;summary:string;owner_id:string;closure:IncidentClosure|null}
export interface IncidentRecord{id:string;revision:number;spec:IncidentSpec;owner_name:string;alerts:IncidentEvidence[];note:string;actor_id:string;actor_name:string;created_at:string;recorded_at:string;expires_at:string}
export interface IncidentPage{items:IncidentRecord[];next_cursor:string}
export interface IncidentAssignee{id:string;name:string}
export interface IncidentCreate{spec:IncidentSpec;alerts:IncidentRef[]}
export interface IncidentChange{expected_revision:number;spec:IncidentSpec;note:string;add_alerts:IncidentRef[]}
export type IncidentInput=IncidentCreate|IncidentChange
export const newIncidentSpec=():IncidentSpec=>({title:'',category:'network_intrusion',severity:'high',status:'open',summary:'',owner_id:'',closure:null})
const object=(v:unknown):v is Record<string,unknown>=>!!v&&typeof v==='object'&&!Array.isArray(v)
export const incidentID=(v:unknown):v is string=>typeof v==='string'&&/^[a-z0-9][a-z0-9_-]{0,63}$/.test(v)
const digest=(v:unknown):v is string=>typeof v==='string'&&/^[a-f0-9]{64}$/.test(v)
const text=(v:unknown,max:number,multiline=false):v is string=>typeof v==='string'&&v.trim()===v&&[...v].length<=max&&!/\p{Cc}/u.test(multiline?v.replace(/[\n\t]/g,''):v)
const date=(v:unknown):v is string=>typeof v==='string'&&Number.isFinite(Date.parse(v))
export function validIncidentRef(v:unknown):v is IncidentRef{return object(v)&&incidentID(v.event_id)&&digest(v.raw_sha256)}
export function incidentSpecError(spec:IncidentSpec){
 if(!spec.title||!text(spec.title,120)||!spec.summary||!text(spec.summary,4096,true))return '请填写事件标题和概述，并核对字符长度。'
 if(!Object.hasOwn(incidentCategories,spec.category)||!Object.hasOwn(incidentSeverities,spec.severity)||!Object.hasOwn(incidentStatuses,spec.status)||(spec.owner_id!==''&&!incidentID(spec.owner_id)))return '请选择有效的事件分类、严重度、状态和责任人。'
 if(spec.status!=='closed')return spec.closure===null?'':'未结案时不应提交结案材料。'
 const c=spec.closure
 if(!spec.owner_id||!c||!['resolved','false_positive'].includes(c.reason))return '结案前请明确责任人和结案原因。'
 if(![c.root_cause,c.impact,c.remediation,c.verification].every(v=>!!v&&text(v,2048,true)))return '请填写根因、影响、修复和复测说明，每项最多 2048 字符。'
 if(!Array.isArray(c.evidence)||c.evidence.length>8||c.evidence.some(v=>!v||!text(v,256))||new Set(c.evidence).size!==c.evidence.length)return '复测证据引用最多 8 条，不能重复，每条最多 256 字符。'
 if(c.reason==='resolved'&&!c.evidence.length)return '确认处置完成时，需要提供可复核的复测证据引用。'
 return ''
}
export function validIncidentRecord(v:unknown):v is IncidentRecord{
 if(!object(v)||!incidentID(v.id)||!Number.isSafeInteger(v.revision)||Number(v.revision)<1||Number(v.revision)>1000||!object(v.spec)||incidentSpecError(v.spec as unknown as IncidentSpec)||!incidentID(v.actor_id)||!v.actor_name||!text(v.actor_name,64)||!v.note||!text(v.note,2048,true)||!date(v.created_at)||!date(v.recorded_at)||!date(v.expires_at)||Date.parse(v.recorded_at)<Date.parse(v.created_at)||Date.parse(v.expires_at)<=Date.parse(v.recorded_at)||typeof v.owner_name!=='string')return false
 const spec=v.spec as unknown as IncidentSpec
 if(spec.owner_id===''?v.owner_name!=='':!v.owner_name||!text(v.owner_name,64))return false
 if(!Array.isArray(v.alerts)||v.alerts.length>16||new Set(v.alerts.map(a=>a?.event_id)).size!==v.alerts.length)return false
 return v.alerts.every(a=>validIncidentRef(a)&&object(a)&&incidentID(a.sensor_id)&&date(a.event_time)&&date(a.observed_at))
}
export function validIncidentPage(v:unknown):v is IncidentPage{
 return object(v)&&Array.isArray(v.items)&&v.items.length<=20&&v.items.every(validIncidentRecord)&&new Set(v.items.map(i=>i.id)).size===v.items.length&&typeof v.next_cursor==='string'&&(v.next_cursor===''||v.items.length===20&&v.next_cursor===v.items[19]?.id)
}
export function validIncidentHistory(v:unknown,id:string):v is IncidentPage{
 if(!object(v)||!Array.isArray(v.items)||v.items.length>20||!v.items.every(i=>validIncidentRecord(i)&&i.id===id)||typeof v.next_cursor!=='string')return false
 const rows=v.items as IncidentRecord[]
 return rows.every((r,i)=>i===0||r.revision<rows[i-1]!.revision)&&(v.next_cursor===''||rows.length===20&&v.next_cursor===String(rows[19]?.revision))
}
export function validIncidentAssignees(v:unknown):v is {items:IncidentAssignee[]}{return object(v)&&Array.isArray(v.items)&&v.items.length<=100&&new Set(v.items.map(i=>i?.id)).size===v.items.length&&v.items.every(i=>object(i)&&incidentID(i.id)&&!!i.name&&text(i.name,64))}
export function sameIncidentSpec(a:IncidentSpec,b:IncidentSpec){
 if(!['title','category','severity','status','summary','owner_id'].every(key=>a[key as keyof IncidentSpec]===b[key as keyof IncidentSpec]))return false
 if(!a.closure||!b.closure)return a.closure===b.closure
 return ['reason','root_cause','impact','remediation','verification'].every(key=>a.closure![key as keyof IncidentClosure]===b.closure![key as keyof IncidentClosure])&&JSON.stringify(a.closure.evidence)===JSON.stringify(b.closure.evidence)
}
