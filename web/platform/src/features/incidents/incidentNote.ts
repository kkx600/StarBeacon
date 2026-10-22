import {incidentID,type IncidentRecord} from './incident'

export const noteStatuses={active:'有效',withdrawn:'已撤回'} as const
export interface IncidentNoteSpec{title:string;body:string;status:keyof typeof noteStatuses;withdrawal_reason:string}
export interface IncidentNoteRecord{
 id:string;incident_id:string;incident_revision:number;revision:number;spec:IncidentNoteSpec
 author_id:string;author_name:string;reason:string;actor_id:string;actor_name:string
 created_at:string;recorded_at:string;expires_at:string
}
export interface IncidentNotePage{items:IncidentNoteRecord[];next_cursor:string}
export interface IncidentNoteCreate{incident_revision:number;spec:IncidentNoteSpec}
export interface IncidentNoteChange extends IncidentNoteCreate{expected_revision:number;reason:string}
export type IncidentNoteInput=IncidentNoteCreate|IncidentNoteChange
export interface IncidentNoteAttempt{parent:IncidentRecord;id:string;input:IncidentNoteInput}
export const newNoteSpec=():IncidentNoteSpec=>({title:'',body:'',status:'active',withdrawal_reason:''})
const object=(v:unknown):v is Record<string,unknown>=>!!v&&typeof v==='object'&&!Array.isArray(v)
const text=(v:unknown,max:number,multiline=false):v is string=>typeof v==='string'&&v.trim()===v&&[...v].length<=max&&!/\p{Cc}/u.test(multiline?v.replace(/[\n\t]/g,''):v)
const revision=(v:unknown):v is number=>Number.isSafeInteger(v)&&Number(v)>=1&&Number(v)<=1000
const timestamp=/^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(?:\.(\d{1,9}))?(Z|[+-]\d\d:\d\d)$/
function date(v:unknown):v is string{if(typeof v!=='string'||!Number.isFinite(Date.parse(v)))return false;const m=timestamp.exec(v);return !!m&&new Date(Date.parse(m[1]+'Z')).toISOString().startsWith(m[1]!)}
function instant(v:string){const m=timestamp.exec(v)!;return BigInt(Date.parse(m[1]!+m[3]!))*1000000n+BigInt((m[2]??'').padEnd(9,'0'))}
export function noteSpecError(s:IncidentNoteSpec):string{
 if(!s.title||!text(s.title,120)||!s.body||!text(s.body,8192,true))return '请填写笔记标题和正文，并核对字符长度。'
 if(!Object.hasOwn(noteStatuses,s.status))return '请选择有效的笔记状态。'
 if(s.status==='withdrawn')return s.withdrawal_reason&&text(s.withdrawal_reason,2048,true)?'':'撤回笔记需要填写原因，最多 2048 字符。'
 return s.withdrawal_reason===''?'':'恢复或保存有效笔记时，请清空撤回原因。'
}
export function validNoteSpec(v:unknown):v is IncidentNoteSpec{return object(v)&&Object.keys(v).length===4&&['title','body','status','withdrawal_reason'].every(k=>Object.hasOwn(v,k))&&!noteSpecError(v as unknown as IncidentNoteSpec)}
export function validNoteRecord(v:unknown,parent:string):v is IncidentNoteRecord{
 return object(v)&&incidentID(v.id)&&v.incident_id===parent&&revision(v.incident_revision)&&revision(v.revision)&&validNoteSpec(v.spec)&&incidentID(v.author_id)&&!!v.author_name&&text(v.author_name,64)&&v.actor_id===v.author_id&&!!v.actor_name&&text(v.actor_name,64)&&!!v.reason&&text(v.reason,2048,true)&&date(v.created_at)&&date(v.recorded_at)&&date(v.expires_at)&&instant(v.recorded_at)>=instant(v.created_at)&&instant(v.expires_at)>instant(v.recorded_at)
}
export function validNotePage(v:unknown,parent:string):v is IncidentNotePage{
 if(!object(v)||!Array.isArray(v.items)||v.items.length>20||!v.items.every(r=>validNoteRecord(r,parent))||new Set(v.items.map(r=>r.id)).size!==v.items.length||typeof v.next_cursor!=='string')return false
 const rows=v.items as IncidentNoteRecord[]
 return rows.every((r,i)=>i===0||instant(r.created_at)<=instant(rows[i-1]!.created_at))&&(v.next_cursor===''||rows.length===20&&v.next_cursor===rows[19]!.id)
}
export function validNoteHistory(v:unknown,parent:string,id:string):v is IncidentNotePage{
 if(!object(v)||!Array.isArray(v.items)||v.items.length>20||!v.items.every(r=>validNoteRecord(r,parent)&&r.id===id)||typeof v.next_cursor!=='string')return false
 const rows=v.items as IncidentNoteRecord[]
 return rows.every((r,i)=>i===0||r.revision<rows[i-1]!.revision)&&(v.next_cursor===''||rows.length===20&&v.next_cursor===String(rows[19]!.revision))
}
export function sameNoteSpec(a:IncidentNoteSpec,b:IncidentNoteSpec){return ['title','body','status','withdrawal_reason'].every(k=>a[k as keyof IncidentNoteSpec]===b[k as keyof IncidentNoteSpec])}
