import type {Sensor} from '@starbeacon/shared/types.ts'

export interface SensorGroup {id:string;revision:number;name:string;description:string;active:boolean;member_count:number;created_at:string;updated_at:string}
export interface GroupPage {items:SensorGroup[];next_cursor:string}
export interface GroupChange {id:string;expected_revision:number;name:string;description:string;active:boolean}
export interface MetadataChange {expected_revision:number;registration_id:string;name:string;group_id:string;site:string;description:string}
export interface MetadataRecord {id:string;revision:number;registration_id:string;name:string;group_id:string;site:string;description:string;updated_at:string}
export type ManagementInput = GroupChange|MetadataChange
export type ManagementTarget = {kind:'group';record:SensorGroup|null}|{kind:'metadata';record:Sensor}
export const managementID=(v:unknown):v is string=>typeof v==='string'&&/^[a-z0-9][a-z0-9_-]{0,63}$/.test(v)
function record(v:unknown):v is Record<string,unknown>{return !!v&&typeof v==='object'&&!Array.isArray(v)}
function text(v:unknown,max:number,required=false):v is string {return typeof v==='string'&&v===v.trim()&&[...v].length<=max&&(!required||!!v)&&!/[\p{Cc}\p{Cs}]/u.test(v)}
function revision(v:unknown,min=1):v is number{return Number.isSafeInteger(v)&&Number(v)>=min&&Number(v)<=1000000}
function time(v:unknown){return typeof v==='string'&&Number.isFinite(Date.parse(v))}
export function validGroup(v:unknown):v is SensorGroup {return record(v)&&managementID(v.id)&&revision(v.revision)&&text(v.name,128,true)&&text(v.description,1000)&&typeof v.active==='boolean'&&Number.isSafeInteger(v.member_count)&&Number(v.member_count)>=0&&time(v.created_at)&&time(v.updated_at)}
export function validGroupPage(v:unknown):v is GroupPage{return record(v)&&Array.isArray(v.items)&&v.items.length<=100&&v.items.every(validGroup)&&new Set(v.items.map(g=>g.id)).size===v.items.length&&typeof v.next_cursor==='string'&&(!v.next_cursor||managementID(v.next_cursor)&&v.items.at(-1)?.id===v.next_cursor)}
export function managementInputError(input:ManagementInput){
 if(!text(input.name,128,true)||!text(input.description,1000))return '请填写探针或分组名称，名称最多 128 个字符，说明最多 1000 个字符，不含控制字符。'
 if(!revision(input.expected_revision,'id' in input?0:1)||input.expected_revision>=1000000)return '管理修订无效或已达上限，请刷新后核对。'
 if('id' in input){if(!managementID(input.id)||input.id==='ungrouped'||typeof input.active!=='boolean'||input.expected_revision===0&&!input.active)return '分组参数无效。'}
 else if(!managementID(input.registration_id)||input.group_id!==''&&!managementID(input.group_id)||!text(input.site,128))return '探针注册代次、分组或站点参数无效。'
 return ''
}
export function validManagementReceipt(v:unknown,kind:'group'|'metadata',id:string,input:ManagementInput):v is SensorGroup|MetadataRecord {
 if(!record(v)||v.id!==id||v.revision!==input.expected_revision+1||v.name!==input.name||v.description!==input.description||!time(v.updated_at))return false
 if(kind==='group')return 'id' in input&&validGroup(v)&&v.active===input.active
 return 'registration_id' in input&&v.registration_id===input.registration_id&&v.group_id===input.group_id&&v.site===input.site
}
