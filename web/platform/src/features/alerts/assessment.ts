export const assessmentStatuses={open:'待处理',investigating:'调查中',closed:'已关闭'} as const
export const assessmentVerdicts={unreviewed:'未研判',suspicious:'待核实',false_positive:'误报',confirmed:'确认威胁'} as const
export const assessmentOutcomes={unknown:'尚未确认',attempt:'观察到攻击尝试',success:'人工确认攻击成功',prevented:'人工确认已阻止'} as const
export interface AssessmentSpec {status:keyof typeof assessmentStatuses;verdict:keyof typeof assessmentVerdicts;outcome:keyof typeof assessmentOutcomes;note:string;evidence:string[]}
export interface AssessmentChange {expected_revision:number;spec:AssessmentSpec;claim:boolean}
export interface AlertAssessment {event_id:string;raw_sha256:string;revision:number;spec:AssessmentSpec;owner_id:string;owner_name:string;analyst_id:string;analyst:string;basis:'human'|'unreviewed';updated_at:string|null;expires_at:string|null}
export interface AssessmentPage {items:AlertAssessment[];next_cursor:string}
export const initialAssessment=():AssessmentSpec=>({status:'open',verdict:'unreviewed',outcome:'unknown',note:'',evidence:[]})
const object=(v:unknown):v is Record<string,unknown>=>!!v&&typeof v==='object'&&!Array.isArray(v)
const id=(v:unknown)=>typeof v==='string'&&/^[a-z0-9][a-z0-9_-]{0,63}$/.test(v)
const text=(v:unknown,max:number,multiline=false)=>typeof v==='string'&&v.trim()===v&&[...v].length<=max&&!/\p{Cc}/u.test(multiline?v.replace(/[\n\t]/g,''):v)
const date=(v:unknown)=>typeof v==='string'&&Number.isFinite(Date.parse(v))
export function assessmentInputError(spec:AssessmentSpec){
 if(!Object.hasOwn(assessmentStatuses,spec.status)||!Object.hasOwn(assessmentVerdicts,spec.verdict)||!Object.hasOwn(assessmentOutcomes,spec.outcome))return '请选择有效的处理状态和研判结论。'
 if(!spec.note||!text(spec.note,2048,true))return '请填写研判说明，最多 2048 字符。'
 if(!Array.isArray(spec.evidence)||spec.evidence.length>8||spec.evidence.some(v=>!v||!text(v,256))||new Set(spec.evidence).size!==spec.evidence.length)return '证据引用最多 8 条，每条不超过 256 字符，不能重复。'
 if(spec.status==='closed'&&!['false_positive','confirmed'].includes(spec.verdict))return '请先明确研判结论，再关闭告警。'
 if(spec.verdict!=='confirmed'&&spec.outcome!=='unknown')return '只有确认威胁后才能记录攻击结果。'
 if(['success','prevented'].includes(spec.outcome)&&!spec.evidence.length)return '确认攻击成功或已阻止时，需要提供可复核的证据引用。'
 return ''
}
export function validAssessment(v:unknown):v is AlertAssessment{
 if(!object(v)||!id(v.event_id)||typeof v.raw_sha256!=='string'||!/^[a-f0-9]{64}$/.test(v.raw_sha256)||!Number.isSafeInteger(v.revision)||Number(v.revision)<0||!object(v.spec)||!Object.hasOwn(assessmentStatuses,String(v.spec.status))||!Object.hasOwn(assessmentVerdicts,String(v.spec.verdict))||!Object.hasOwn(assessmentOutcomes,String(v.spec.outcome))||typeof v.spec.note!=='string'||!Array.isArray(v.spec.evidence)||!['owner_id','owner_name','analyst_id','analyst'].every(key=>typeof v[key]==='string'))return false
 if(v.revision===0)return v.basis==='unreviewed'&&v.updated_at===null&&v.expires_at===null&&sameAssessmentSpec(v.spec as unknown as AssessmentSpec,initialAssessment())&&v.owner_id===''&&v.owner_name===''&&v.analyst_id===''&&v.analyst===''
 return v.basis==='human'&&date(v.updated_at)&&date(v.expires_at)&&id(v.analyst_id)&&text(v.analyst,64)&&(v.owner_id===''?v.owner_name==='':id(v.owner_id)&&text(v.owner_name,64))&&!assessmentInputError(v.spec as unknown as AssessmentSpec)
}
export function sameAssessmentSpec(a:AssessmentSpec,b:AssessmentSpec){return a.status===b.status&&a.verdict===b.verdict&&a.outcome===b.outcome&&a.note===b.note&&JSON.stringify(a.evidence)===JSON.stringify(b.evidence)}
export function validAssessmentPage(v:unknown):v is AssessmentPage{
 if(!object(v)||!Array.isArray(v.items)||v.items.length>20||!v.items.every(row=>validAssessment(row)&&row.revision>0)||typeof v.next_cursor!=='string')return false
 const items=v.items as AlertAssessment[]
 return items.every((row,i)=>i===0||row.revision<items[i-1]!.revision)&&(v.next_cursor===''||items.length===20&&v.next_cursor===String(items[19]!.revision))
}
