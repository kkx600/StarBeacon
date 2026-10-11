import type {Principal,SearchRequest} from '@starbeacon/shared/types.ts'
import {instant} from '@starbeacon/shared/utils/instant.ts'
import type {TrafficQuery} from '../traffic/traffic'

export const parserVersion='1.0'
export type Dataset='alerts'|'context'
export type SearchTerms=Omit<TrafficQuery,'start'|'end'|'page'|'page_size'>&{filter:string}
export type SearchWindow={mode:'relative';hours:24|168|720}|{mode:'absolute';start:string;end:string}
export interface SavedDefinition {schema_version:'saved.search.v1';parser_version:string;dataset:Dataset;mode:'visual'|'advanced';window:SearchWindow;terms:SearchTerms}
export interface SavedQuery {tenant_id:string;id:string;generation_id:string;owner_id:string;revision:number;name:string;description:string;visibility:'personal'|'team';active:boolean;definition:SavedDefinition;created_at:string;updated_at:string;expires_at:string|null}
export interface SavedChange {id:string;expected_revision:number;expected_generation_id:string;name:string;description:string;visibility:'personal'|'team';active:boolean;definition:SavedDefinition}
export interface SavedPage {items:SavedQuery[];next_cursor:string}
export interface SavedResolution {tenant_id:string;id:string;generation_id:string;revision:number;definition:SavedDefinition;query:SearchRequest|TrafficQuery}
export interface SavedListFilter {keyword:string;visibility:''|'personal'|'team';active:''|'true'|'false'}
export const savedID=(value:unknown):value is string=>typeof value==='string'&&/^[a-z0-9][a-z0-9_-]{0,63}$/.test(value)
const object=(value:unknown):value is Record<string,unknown>=>!!value&&typeof value==='object'&&!Array.isArray(value)
const date=(value:unknown):value is string=>typeof value==='string'&&Number.isFinite(Date.parse(value))
const integer=(value:unknown,min:number,max:number)=>Number.isSafeInteger(value)&&Number(value)>=min&&Number(value)<=max
const text=(value:unknown,max:number,required=false):value is string=>typeof value==='string'&&value===value.trim()&&(!required||!!value)&&Array.from(value).length<=max&&!/[\p{Cc}\uD800-\uDFFF]/u.test(value)
export const emptyTerms=():SearchTerms=>({keyword:'',source_ip:'',destination_ip:'',protocol:'',method:'',path:'',severity:'',filter:'',event_kind:'',sensor_id:'',sensor_registration_id:'',source_generation_id:'',flow_id:''})

export function validDefinition(value:unknown):value is SavedDefinition{
 if(!object(value)||value.schema_version!=='saved.search.v1'||!text(value.parser_version,32,true)||!['alerts','context'].includes(String(value.dataset))||!['visual','advanced'].includes(String(value.mode))||!object(value.window)||!object(value.terms))return false
 const window=value.window,terms=value.terms
 if(window.mode==='relative'){if(![24,168,720].includes(Number(window.hours))||typeof window.hours!=='number'||window.start!==undefined||window.end!==undefined)return false}
 else if(window.mode==='absolute'){if(window.hours!==undefined||!date(window.start)||!date(window.end)||Date.parse(window.end)<=Date.parse(window.start)||Date.parse(window.end)-Date.parse(window.start)>31*86400000)return false}
 else return false
 if(!Object.keys(emptyTerms()).every(key=>typeof terms[key]==='string')||Object.keys(terms).some(key=>!Object.hasOwn(emptyTerms(),key)))return false
 if(Object.entries(terms).some(([key,v])=>key!=='filter'&&(/[\p{Cc}\uD800-\uDFFF]/u.test(String(v))||new TextEncoder().encode(String(v)).length>(key==='path'?1024:key==='keyword'?256:key==='protocol'?32:key==='method'?16:128))))return false
 if(new TextEncoder().encode(String(terms.filter)).length>4096||value.mode==='visual'&&terms.filter!=='')return false
 if(value.dataset==='alerts'&&(['event_kind','sensor_id','sensor_registration_id','source_generation_id','flow_id'].some(key=>terms[key]!=='')||value.mode==='advanced'&&['keyword','source_ip','destination_ip','protocol','method','path','severity'].some(key=>terms[key]!=='')))return false
 if(value.dataset==='context'&&(terms.keyword!==''||terms.severity!==''))return false
 return true
}

export function changeError(input:SavedChange):string{
 if(!savedID(input.id)||!integer(input.expected_revision,0,999999)||input.expected_revision===0&&input.expected_generation_id!==''||input.expected_revision>0&&!savedID(input.expected_generation_id))return '查询实例或修订无效，请刷新列表后核对。'
 if(!text(input.name,128,true))return '请填写 1–128 个字符的查询名称，不含控制字符。'
 if(!text(input.description,1000))return '用途说明最多 1,000 个字符，不含控制字符。'
 if(!['personal','team'].includes(input.visibility)||typeof input.active!=='boolean'||input.expected_revision===0&&!input.active)return '查询可见范围或状态无效。'
 if(!validDefinition(input.definition))return '查询条件、模式或时间窗口不完整，请先完成检索。'
 if(input.definition.parser_version!==parserVersion)return '查询解析器版本不兼容，请核对当前查询后重新保存。'
 return ''
}

export function validSavedQuery(value:unknown,principal:Principal,dataset:Dataset):value is SavedQuery{
 if(!object(value)||value.tenant_id!==principal.tenant_id||!savedID(value.id)||!savedID(value.generation_id)||!savedID(value.owner_id)||!integer(value.revision,1,1000000)||!text(value.name,128,true)||!text(value.description,1000)||!['personal','team'].includes(String(value.visibility))||value.visibility==='personal'&&value.owner_id!==principal.id||typeof value.active!=='boolean'||!validDefinition(value.definition)||value.definition.dataset!==dataset||!date(value.created_at)||!date(value.updated_at)||Date.parse(value.updated_at)<Date.parse(value.created_at))return false
 return value.active?value.expires_at===null:date(value.expires_at)&&Date.parse(value.expires_at)>Date.parse(value.updated_at)
}

export function canEditSaved(record:SavedQuery,principal:Principal):boolean{return record.owner_id===principal.id&&(record.visibility==='personal'||principal.role==='admin')}

export function validSavedPage(value:unknown,principal:Principal,dataset:Dataset,filter:SavedListFilter,cursor:string):value is SavedPage{
 if(!object(value)||!Array.isArray(value.items)||value.items.length>20||typeof value.next_cursor!=='string'||value.next_cursor!==''&&(!savedID(value.next_cursor)||value.items.length!==20||value.next_cursor!==value.items.at(-1)?.id))return false
 let previous=cursor
 return value.items.every(item=>{if(!validSavedQuery(item,principal,dataset)||item.id<=previous||filter.visibility&&item.visibility!==filter.visibility||filter.active&&item.active!==(filter.active==='true'))return false;previous=item.id;return true})
}

export function validSavedReceipt(value:unknown,input:SavedChange,principal:Principal):value is SavedQuery{
 return validSavedQuery(value,principal,input.definition.dataset)&&value.owner_id===principal.id&&value.id===input.id&&value.revision===input.expected_revision+1&&(input.expected_revision===0||value.generation_id===input.expected_generation_id)&&value.name===input.name&&value.description===input.description&&value.visibility===input.visibility&&value.active===input.active&&sameDefinition(value.definition,input.definition)
}

export function sameDefinition(a:SavedDefinition,b:SavedDefinition):boolean{
 if(a.schema_version!==b.schema_version||a.parser_version!==b.parser_version||a.dataset!==b.dataset||a.mode!==b.mode||a.window.mode!==b.window.mode||!Object.entries(a.terms).every(([key,value])=>value===b.terms[key as keyof SearchTerms]))return false
 if(a.window.mode==='relative'&&b.window.mode==='relative')return a.window.hours===b.window.hours
 return a.window.mode==='absolute'&&b.window.mode==='absolute'&&instant(a.window.start)!==null&&instant(a.window.start)===instant(b.window.start)&&instant(a.window.end)!==null&&instant(a.window.end)===instant(b.window.end)
}

export function validSavedResolution(value:unknown,record:SavedQuery,principal:Principal):value is SavedResolution{
 if(!object(value)||value.tenant_id!==principal.tenant_id||value.id!==record.id||value.generation_id!==record.generation_id||value.revision!==record.revision||!validDefinition(value.definition)||value.definition.parser_version!==parserVersion||!sameDefinition(value.definition,record.definition)||!object(value.query))return false
 const q=value.query,w=record.definition.window,t=record.definition.terms
 if(!date(q.start)||!date(q.end)||Date.parse(q.end)<=Date.parse(q.start)||Date.parse(q.end)-Date.parse(q.start)>31*86400000||q.page!==1||q.page_size!==20)return false
 const start=instant(q.start),end=instant(q.end)
 if(start===null||end===null||w.mode==='absolute'&&(start!==instant(w.start)||end!==instant(w.end))||w.mode==='relative'&&end-start!==BigInt(w.hours)*3600000000000n)return false
 const allowed=['start','end','page','page_size',...Object.keys(emptyTerms()).filter(key=>record.definition.dataset==='context'||!['event_kind','sensor_id','sensor_registration_id','source_generation_id','flow_id'].includes(key))]
 if(Object.keys(q).some(key=>!allowed.includes(key)))return false
 return Object.entries(t).every(([key,v])=>!allowed.includes(key)||q[key]===v)
}

export function definitionFromQuery(dataset:Dataset,query:SearchRequest|TrafficQuery,hours:number):SavedDefinition{
 const terms=emptyTerms()
 for(const key of Object.keys(terms) as (keyof SearchTerms)[]){const value=(query as unknown as Record<string,unknown>)[key];if(typeof value==='string')terms[key]=value}
 return {schema_version:'saved.search.v1',parser_version:parserVersion,dataset,mode:terms.filter?'advanced':'visual',window:hours===0?{mode:'absolute',start:query.start,end:query.end}:{mode:'relative',hours:hours as 24|168|720},terms}
}

export function copyDefinition(value:SavedDefinition):SavedDefinition{return {...value,window:{...value.window},terms:{...value.terms}}}
export function editSaved(record:SavedQuery):SavedChange{return {id:record.id,expected_revision:record.revision,expected_generation_id:record.generation_id,name:record.name,description:record.description,visibility:record.visibility,active:record.active,definition:copyDefinition(record.definition)}}
export const savedWindowLabel=(window:SearchWindow)=>window.mode==='absolute'?'固定时间范围':window.hours===24?'最近 24 小时':window.hours===168?'最近 7 天':'最近 30 天'
