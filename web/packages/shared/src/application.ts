import {goJSONDigest} from './utils/goJSONDigest'
import {instant} from './utils/instant'

export interface ApplicationState {
 schema_version:'application-state.v1';deployment_id:string;rules_sha256:string;state_sha256:string;rule_count:number;installed_at:string|null
}
export interface ApplicationMatch {
 rule_id:string;revision:number;product_id:string;product_name:string;category_id:string
 evidence:{field:string;op:string;pattern:string}[];evidence_limited:boolean
}
export interface ApplicationAttribution {
 schema_version:'application-attribution.v1';deployment_id:string;state_sha256:string;raw_sha256:string;product_id:string;product_name:string;category_id:string
 result:{schema_version:'application-test.v1';origin:'suricata_visible_metadata';protocol:string;status:'unknown'|'candidate'|'conflict';reason:string;evaluated_at:string;observation_sha256:string;rules_sha256:string;rule_count:number;matched_rule_count:number;matches:ApplicationMatch[];limited:boolean}
}
export const applicationStatuses={unknown:'未知',candidate:'规则候选',conflict:'证据冲突'} as const
export const applicationReasons:Record<string,string>={no_matching_rule:'未命中部署时的规则快照',visible_name_rule:'可见名称与附加规则条件匹配',multiple_products:'多个不同产品的规则同时命中',metadata_unavailable:'未观测到可用名称或协议属性',metadata_invalid:'可见元数据无效或超过匹配范围',transaction_unbound:'协议事务由引擎估计，未用于产品归因'}
export const applicationCategoryNames:Record<string,string>={cloud_storage:'云存储',video:'在线视频',communication:'即时通信',office:'办公协作',development:'研发工具',remote_access:'远程访问',business:'业务系统',other:'其他应用'}
const object=(v:unknown):v is Record<string,unknown>=>!!v&&typeof v==='object'&&!Array.isArray(v)
const id=(v:unknown):v is string=>typeof v==='string'&&/^[a-z0-9][a-z0-9_-]{0,63}$/.test(v)
const digest=(v:unknown):v is string=>typeof v==='string'&&/^[a-f0-9]{64}$/.test(v)
const count=(v:unknown,min=0,max=128):v is number=>typeof v==='number'&&Number.isSafeInteger(v)&&v>=min&&v<=max
const text=(v:unknown,limit:number):v is string=>typeof v==='string'&&v.length>0&&[...v].length<=limit&&v===v.trim()&&!/[\x00-\x1f\x7f]/.test(v)
export function basicApplicationState(v:unknown):v is ApplicationState {
 return object(v)&&v.schema_version==='application-state.v1'&&digest(v.rules_sha256)&&digest(v.state_sha256)&&count(v.rule_count)&&(v.deployment_id===''?v.installed_at===null&&v.rule_count===0:id(v.deployment_id)&&typeof v.installed_at==='string'&&instant(v.installed_at)!==null)
}
export async function validApplicationState(v:unknown):Promise<boolean>{
 if(!basicApplicationState(v)||await goJSONDigest({deployment_id:v.deployment_id,rules_sha256:v.rules_sha256})!==v.state_sha256)return false
 return v.deployment_id!==''||await goJSONDigest([])===v.rules_sha256
}
export function validApplicationAttribution(v:unknown,rawSHA256:string,observed:string):v is ApplicationAttribution {
 if(!object(v)||v.schema_version!=='application-attribution.v1'||!id(v.deployment_id)||!digest(v.state_sha256)||v.raw_sha256!==rawSHA256||!digest(v.raw_sha256)||!object(v.result))return false
 const r=v.result
 if(r.schema_version!=='application-test.v1'||r.origin!=='suricata_visible_metadata'||!['http','tls','quic','dns'].includes(String(r.protocol))||!Object.hasOwn(applicationStatuses,String(r.status))||!Object.hasOwn(applicationReasons,String(r.reason))||typeof r.evaluated_at!=='string'||instant(r.evaluated_at)===null||instant(r.evaluated_at)!==instant(observed)||!digest(r.rules_sha256)||!digest(r.observation_sha256)||!count(r.rule_count)||!count(r.matched_rule_count,0,Number(r.rule_count))||!Array.isArray(r.matches)||r.matches.length!==Math.min(Number(r.matched_rule_count),16)||typeof r.limited!=='boolean'||r.limited!==(Number(r.matched_rule_count)>16))return false
 const rules=new Set<string>(),products=new Set<string>()
 for(const m of r.matches){
  if(!object(m)||!id(m.rule_id)||rules.has(m.rule_id)||!count(m.revision,1,1000000)||!id(m.product_id)||!text(m.product_name,128)||!Object.hasOwn(applicationCategoryNames,String(m.category_id))||typeof m.evidence_limited!=='boolean'||!Array.isArray(m.evidence)||m.evidence.length<1||m.evidence.length>8||!m.evidence.every(e=>object(e)&&['http.host','tls.sni','dns.name','http.method','http.path','http.user_agent','tls.alpn'].includes(String(e.field))&&['eq','domain_suffix','prefix','contains'].includes(String(e.op))&&text(e.pattern,1024)))return false
  rules.add(m.rule_id);products.add(m.product_id)
 }
 if(r.status==='candidate'){const first=r.matches[0];return r.reason==='visible_name_rule'&&products.size===1&&object(first)&&v.product_id===first.product_id&&v.product_name===first.product_name&&v.category_id===first.category_id}
 if(v.product_id!==''||v.product_name!==''||v.category_id!=='')return false
 return r.status==='unknown'?r.matched_rule_count===0&&['no_matching_rule','metadata_unavailable','metadata_invalid','transaction_unbound'].includes(String(r.reason)):r.reason==='multiple_products'&&Number(r.matched_rule_count)>=2&&(r.limited||products.size>1)
}
