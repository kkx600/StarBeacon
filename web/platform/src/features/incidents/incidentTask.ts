import {incidentID,type IncidentRecord} from './incident'

export const taskStatuses={open:'待处理',in_progress:'处理中',completed:'已完成',cancelled:'已取消'} as const
export const taskPriorities={low:'低',medium:'中',high:'高'} as const
export interface IncidentTaskSpec {
 title:string;description:string;status:keyof typeof taskStatuses;priority:keyof typeof taskPriorities
 assignee_id:string;due_at:string|null;resolution:string
}
export interface IncidentTaskRecord {
 id:string;incident_id:string;incident_revision:number;revision:number;spec:IncidentTaskSpec
 assignee_name:string;note:string;actor_id:string;actor_name:string
 created_at:string;recorded_at:string;expires_at:string
}
export interface IncidentTaskPage{items:IncidentTaskRecord[];next_cursor:string}
export interface IncidentTaskCreate{incident_revision:number;spec:IncidentTaskSpec}
export interface IncidentTaskChange extends IncidentTaskCreate{expected_revision:number;note:string}
export type IncidentTaskInput=IncidentTaskCreate|IncidentTaskChange
export interface IncidentTaskAttempt{parent:IncidentRecord;id:string;input:IncidentTaskInput}
export const newTaskSpec=():IncidentTaskSpec=>({title:'',description:'',status:'open',priority:'medium',assignee_id:'',due_at:null,resolution:''})
const object=(v:unknown):v is Record<string,unknown>=>!!v&&typeof v==='object'&&!Array.isArray(v)
const text=(v:unknown,max:number,multiline=false):v is string=>typeof v==='string'&&v.trim()===v&&[...v].length<=max&&!/\p{Cc}/u.test(multiline?v.replace(/[\n\t]/g,''):v)
const revision=(v:unknown):v is number=>Number.isSafeInteger(v)&&Number(v)>=1&&Number(v)<=1000
const timestamp=/^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(?:\.(\d{1,9}))?(Z|[+-]\d\d:\d\d)$/
const date=(v:unknown):v is string=>{if(typeof v!=='string'||!Number.isFinite(Date.parse(v)))return false;const match=timestamp.exec(v);return !!match&&new Date(Date.parse(match[1]+'Z')).toISOString().startsWith(match[1]!)}
function instant(value:string){const match=timestamp.exec(value)!;return BigInt(Date.parse(match[1]!+match[3]!))*1000000n+BigInt((match[2]??'').padEnd(9,'0'))}
export function taskSpecError(s:IncidentTaskSpec):string {
 if(!s.title||!text(s.title,120)||!s.description||!text(s.description,4096,true))return '请填写任务标题与说明，并核对字符长度。'
 if(!Object.hasOwn(taskStatuses,s.status)||!Object.hasOwn(taskPriorities,s.priority)||(s.assignee_id!==''&&!incidentID(s.assignee_id)))return '请选择有效的任务状态、优先级和负责人。'
 if(s.due_at!==null&&(!date(s.due_at)||new Date(s.due_at).getUTCFullYear()<2000||new Date(s.due_at).getUTCFullYear()>2100))return '截止时间须为 2000–2100 年的有效时间，也可留空。'
 if((s.status==='in_progress'||s.status==='completed')&&!s.assignee_id)return '开始处理或完成任务前，请先指定负责人。'
 if(s.status==='completed'||s.status==='cancelled')return s.resolution&&text(s.resolution,2048,true)?'':'请填写完成依据或取消原因，最多 2048 字符。'
 return s.resolution===''?'':'重开或处理任务时，请清空原完成或取消说明。'
}
export function validTaskSpec(v:unknown):v is IncidentTaskSpec {
 return object(v)&&Object.keys(v).length===7&&['title','description','status','priority','assignee_id','due_at','resolution'].every(k=>Object.hasOwn(v,k))&&!taskSpecError(v as unknown as IncidentTaskSpec)
}
export function validTaskRecord(v:unknown,parent:string):v is IncidentTaskRecord {
 if(!object(v)||!incidentID(v.id)||v.incident_id!==parent||!revision(v.incident_revision)||!revision(v.revision)||!validTaskSpec(v.spec)||!incidentID(v.actor_id)||!v.actor_name||!text(v.actor_name,64)||!v.note||!text(v.note,2048,true)||!date(v.created_at)||!date(v.recorded_at)||!date(v.expires_at)||Date.parse(v.recorded_at)<Date.parse(v.created_at)||Date.parse(v.expires_at)<=Date.parse(v.recorded_at)||typeof v.assignee_name!=='string')return false
 return v.spec.assignee_id===''?v.assignee_name==='':!!v.assignee_name&&text(v.assignee_name,64)
}
export function validTaskPage(v:unknown,parent:string):v is IncidentTaskPage {
 if(!object(v)||!Array.isArray(v.items)||v.items.length>20||!v.items.every(r=>validTaskRecord(r,parent))||new Set(v.items.map(r=>r.id)).size!==v.items.length||typeof v.next_cursor!=='string')return false
 const rows=v.items as IncidentTaskRecord[]
 return rows.every((r,i)=>i===0||Date.parse(r.created_at)<=Date.parse(rows[i-1]!.created_at))&&(v.next_cursor===''||rows.length===20&&v.next_cursor===rows[19]?.id)
}
export function validTaskHistory(v:unknown,parent:string,id:string):v is IncidentTaskPage {
 if(!object(v)||!Array.isArray(v.items)||v.items.length>20||!v.items.every(r=>validTaskRecord(r,parent)&&r.id===id)||typeof v.next_cursor!=='string')return false
 const rows=v.items as IncidentTaskRecord[]
 return rows.every((r,i)=>i===0||r.revision<rows[i-1]!.revision)&&(v.next_cursor===''||rows.length===20&&v.next_cursor===String(rows[19]?.revision))
}
export function sameTaskSpec(a:IncidentTaskSpec,b:IncidentTaskSpec):boolean {
 return ['title','description','status','priority','assignee_id','resolution'].every(k=>a[k as keyof IncidentTaskSpec]===b[k as keyof IncidentTaskSpec])&&(a.due_at===b.due_at||a.due_at!==null&&b.due_at!==null&&date(a.due_at)&&date(b.due_at)&&instant(a.due_at)===instant(b.due_at))
}
