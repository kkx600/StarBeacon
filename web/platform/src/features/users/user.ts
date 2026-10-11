export const userRoles={admin:'管理员',viewer:'只读用户'} as const
export interface UserRecord{id:string;username:string;role:keyof typeof userRoles;active:boolean;revision:number;created_at:string;updated_at:string}
export interface UserCreate{username:string;password:string;role:UserRecord['role'];active:boolean}
export interface UserChange{expected_revision:number;role:UserRecord['role'];active:boolean}
export type UserInput=UserCreate|UserChange
export interface UserPage{items:UserRecord[];next_cursor:string}
const object=(v:unknown):v is Record<string,unknown>=>!!v&&typeof v==='object'&&!Array.isArray(v)
export const userID=(v:unknown):v is string=>typeof v==='string'&&/^[a-z0-9][a-z0-9_-]{0,63}$/.test(v)
export function validUsername(v:unknown):v is string{return typeof v==='string'&&v.trim()===v&&!/[\p{Cc}\p{Cf}]/u.test(v)&&new TextEncoder().encode(v).length>=3&&new TextEncoder().encode(v).length<=64}
export function userInputError(input:UserInput){
 if(!Object.hasOwn(userRoles,input.role)||typeof input.active!=='boolean')return '请选择有效的角色和账号状态。'
 if('expected_revision' in input)return Number.isSafeInteger(input.expected_revision)&&input.expected_revision>=1&&input.expected_revision<1000000?'':'当前用户修订不可修改，请刷新后核对。'
 if(!validUsername(input.username))return '账号名称须为 3～64 个 UTF-8 字节，不能有首尾空格或不可见控制字符。'
 if(typeof input.password!=='string'||/\p{Cc}/u.test(input.password)||new TextEncoder().encode(input.password).length<12||new TextEncoder().encode(input.password).length>72)return '密码须为 12～72 个 UTF-8 字节，不能包含控制字符。'
 return ''
}
export function validUserRecord(v:unknown):v is UserRecord{
 return object(v)&&userID(v.id)&&validUsername(v.username)&&typeof v.role==='string'&&Object.hasOwn(userRoles,v.role)&&typeof v.active==='boolean'&&Number.isSafeInteger(v.revision)&&Number(v.revision)>=1&&Number(v.revision)<=1000000&&typeof v.created_at==='string'&&typeof v.updated_at==='string'&&Number.isFinite(Date.parse(v.created_at))&&Number.isFinite(Date.parse(v.updated_at))&&Date.parse(v.updated_at)>=Date.parse(v.created_at)&&!('password' in v)&&!('password_hash' in v)&&!('current_password' in v)&&!('new_password' in v)
}
export function validUserPage(v:unknown):v is UserPage{
 if(!object(v)||!Array.isArray(v.items)||v.items.length>20||!v.items.every(validUserRecord)||typeof v.next_cursor!=='string')return false
 const rows=v.items as UserRecord[]
 return rows.every((r,i)=>i===0||r.id<rows[i-1]!.id)&&(v.next_cursor===''||rows.length===20&&v.next_cursor===rows[19]!.id)
}
