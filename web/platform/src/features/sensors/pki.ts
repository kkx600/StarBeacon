export interface Enrollment {
 id:string;sensor_id:string;registration_id:string;created_at:string;expires_at:string;revoked:boolean;state:string;job_id?:string;csr_sha256?:string
}
export interface ProbeCertificate {
 id:string;sensor_id:string;registration_id:string;fingerprint_sha256:string;serial:string;not_before:string;not_after:string;revoked_at?:string;ca_revocation:'none'|'pending'|'confirmed'|'unknown';state:'signing'|'issued'|'unknown';csr_sha256?:string
}
export interface EnrollmentDraft {sensor_id:string;registration_id:string;name:string;ttl_seconds:number}
export interface EnrollmentInput {token:string;name:string;ttl_seconds:number}
export interface EnrollmentPage {items:Enrollment[];next_cursor:string;ca_configured:boolean}
export interface CertificatePage {items:ProbeCertificate[];next_cursor:string}
export const pkiID=(value:unknown):value is string=>typeof value==='string'&&/^[a-z0-9][a-z0-9_-]{0,63}$/.test(value)
const hash=(value:unknown):value is string=>typeof value==='string'&&/^[a-f0-9]{64}$/.test(value)
const object=(value:unknown):value is Record<string,unknown>=>!!value&&typeof value==='object'&&!Array.isArray(value)
const date=(value:unknown):value is string=>typeof value==='string'&&Number.isFinite(Date.parse(value))
export function enrollmentError(value:EnrollmentDraft):string {
 if(!pkiID(value.sensor_id))return '探针标识须为 1–64 位小写字母、数字、下划线或连字符，且以字母或数字开头。'
 if(!pkiID(value.registration_id))return '注册身份无效，请重新打开创建窗口。'
 if(!value.name||value.name!==value.name.trim()||[...value.name].length>128||/[\r\n\0]/.test(value.name))return '请填写 1–128 个字符的探针名称，不含首尾空格或换行。'
 if(!Number.isSafeInteger(value.ttl_seconds)||value.ttl_seconds<60||value.ttl_seconds>86400)return '注册凭据有效期须为 60–86400 秒。'
 return ''
}
export function createEnrollmentInput(tenant:string,value:EnrollmentDraft):EnrollmentInput {
 if(!pkiID(tenant)||enrollmentError(value))throw new Error('注册绑定信息无效')
 const secret=btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(32)))).replaceAll('+','-').replaceAll('/','_').replace(/=+$/,'')
 const id='enroll_'+crypto.randomUUID().replaceAll('-','')
 return {token:['sbe1',tenant,value.sensor_id,value.registration_id,id,secret].join('.'),name:value.name,ttl_seconds:value.ttl_seconds}
}
export function validEnrollment(value:unknown):value is Enrollment {
 if(!object(value)||!pkiID(value.id)||!pkiID(value.sensor_id)||!pkiID(value.registration_id)||!date(value.created_at)||!date(value.expires_at)||Date.parse(value.expires_at)<=Date.parse(value.created_at)||typeof value.revoked!=='boolean'||!['created','unused','signing','issued','unknown','revoked','expired'].includes(String(value.state)))return false
 return (value.job_id===undefined||value.job_id===''||pkiID(value.job_id))&&(value.csr_sha256===undefined||value.csr_sha256===''||hash(value.csr_sha256))
}
export function validCertificate(value:unknown):value is ProbeCertificate {
 if(!object(value)||!pkiID(value.id)||!pkiID(value.sensor_id)||!pkiID(value.registration_id)||!['signing','issued','unknown'].includes(String(value.state))||!['none','pending','confirmed','unknown'].includes(String(value.ca_revocation)))return false
 if(value.chain_pem!==undefined)return false
 if(value.state==='issued'&&(!hash(value.fingerprint_sha256)||typeof value.serial!=='string'||!/^[1-9][0-9]{0,99}$/.test(value.serial)||!date(value.not_before)||!date(value.not_after)||Date.parse(value.not_after)<=Date.parse(value.not_before)))return false
 return (value.revoked_at===undefined||date(value.revoked_at))&&(value.csr_sha256===undefined||hash(value.csr_sha256))
}
function validPage<T>(value:unknown,validate:(item:unknown)=>item is T,key:(item:T)=>string):value is {items:T[];next_cursor:string} {
 if(!object(value)||!Array.isArray(value.items)||value.items.length>20||!value.items.every(validate)||typeof value.next_cursor!=='string'||value.next_cursor!==''&&!pkiID(value.next_cursor))return false
 const ids=value.items.map(key)
 // 标识排序由数据库排序规则决定；保留服务端顺序，核对唯一性与末行游标绑定。
 return new Set(ids).size===ids.length&&(value.next_cursor===''||ids.length===20&&value.next_cursor===ids.at(-1))
}
export function validEnrollmentPage(value:unknown):value is EnrollmentPage {return object(value)&&typeof value.ca_configured==='boolean'&&validPage(value,validEnrollment,v=>v.id)}
export function validCertificatePage(value:unknown,sensor:string):value is CertificatePage {return validPage(value,validCertificate,v=>v.id)&&value.items.every(v=>v.sensor_id===sensor)}
export const enrollmentStates:Record<string,string>={created:'等待注册',unused:'等待注册',signing:'签发中',issued:'已签发',unknown:'结果待核实',revoked:'令牌已撤销',expired:'令牌已到期'}
export const certificateStates:Record<string,string>={signing:'签发中',issued:'已签发',unknown:'结果待核实'}
export const revocationStates:Record<string,string>={none:'未申请',pending:'等待确认',confirmed:'已确认',unknown:'结果待核实'}
