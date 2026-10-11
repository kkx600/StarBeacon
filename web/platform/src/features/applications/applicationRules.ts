import {goJSONDigest} from '@starbeacon/shared/utils/goJSONDigest.ts'
export const applicationCategories = {cloud_storage:'云存储',video:'在线视频',communication:'即时通信',office:'办公协作',development:'研发工具',remote_access:'远程访问',business:'业务系统',other:'其他应用'} as const
export const applicationFields = {'http.host':'HTTP Host','tls.sni':'可见 SNI','dns.name':'DNS 查询名称','http.method':'HTTP 请求方法','http.path':'可见 HTTP 路径','http.user_agent':'HTTP User-Agent','tls.alpn':'可见 ALPN'} as const
export const applicationOperators = {eq:'精确匹配',domain_suffix:'域名及子域',prefix:'前缀匹配',contains:'包含文本'} as const
export interface AppCondition {field:keyof typeof applicationFields;op:keyof typeof applicationOperators;value:string}
export interface AppDefinition {schema_version:'application-rule.v1';product_id:string;product_name:string;category_id:keyof typeof applicationCategories;protocols:string[];any:AppCondition[];all:AppCondition[];exclude:AppCondition[]}
export interface AppChange {id:string;expected_revision:number;name:string;description:string;active:boolean;definition:AppDefinition}
export interface AppRule {tenant_id:string;id:string;revision:number;name:string;description:string;active:boolean;definition:AppDefinition;definition_sha256:string;created_by:string;created_at:string;expires_at:string}
export interface AppPage {items:AppRule[];next_cursor:string}
export interface AppObservation {schema_version:'application-observation.v1';protocol:string;http_host:string;http_method:string;http_path:string;http_user_agent:string;tls_sni:string;tls_alpn:string[];dns_names:string[]}
export interface AppMatch {rule_id:string;revision:number;product_id:string;product_name:string;category_id:keyof typeof applicationCategories;evidence:{field:keyof typeof applicationFields;op:keyof typeof applicationOperators;pattern:string}[];evidence_limited:boolean}
export interface AppResult {schema_version:'application-test.v1';origin:'user_supplied_metadata';protocol:string;status:'unknown'|'candidate'|'conflict';reason:'no_matching_rule'|'visible_name_rule'|'multiple_products'|'metadata_unavailable';evaluated_at:string;observation_sha256:string;rules_sha256:string;rule_count:number;matched_rule_count:number;matches:AppMatch[];limited:boolean}
export const appStatuses = {unknown:'未知',candidate:'规则候选',conflict:'证据冲突'} as const
const object=(v:unknown):v is Record<string,unknown>=>!!v&&typeof v==='object'&&!Array.isArray(v)
const id=(v:unknown):v is string=>typeof v==='string'&&/^[a-z0-9][a-z0-9_-]{0,63}$/.test(v)
const text=(v:unknown,max:number,required=false):v is string=>typeof v==='string'&&v===v.trim()&&(!required||v!=='')&&[...v].length<=max&&!/[\u0000-\u001f\u007f-\u009f]/.test(v)
const rev=(v:unknown,min=1)=>Number.isSafeInteger(v)&&Number(v)>=min&&Number(v)<=1000000
const digest=(v:unknown):v is string=>typeof v==='string'&&/^[a-f0-9]{64}$/.test(v)
const date=(v:unknown):v is string=>typeof v==='string'&&Number.isFinite(Date.parse(v))
const known=(v:Record<string,unknown>,keys:string[])=>Object.keys(v).every(k=>keys.includes(k))&&keys.every(k=>Object.hasOwn(v,k))
export const domainCondition=(field:string)=>['http.host','tls.sni','dns.name'].includes(field)
export function conditionOperators(field:string):AppCondition['op'][] {return domainCondition(field)?['eq','domain_suffix']:field==='http.path'?['eq','prefix']:field==='http.user_agent'?['eq','contains']:['eq']}
export function validDefinition(v:unknown):v is AppDefinition {
 if(!object(v)||!known(v,['schema_version','product_id','product_name','category_id','protocols','any','all','exclude'])||v.schema_version!=='application-rule.v1'||!id(v.product_id)||!text(v.product_name,128,true)||!Object.hasOwn(applicationCategories,String(v.category_id))||!Array.isArray(v.protocols)||v.protocols.length<1||v.protocols.length>4||new Set(v.protocols).size!==v.protocols.length||!v.protocols.every(p=>['http','tls','quic','dns'].includes(p))||!Array.isArray(v.any)||v.any.length<1||v.any.length>16||!Array.isArray(v.all)||!Array.isArray(v.exclude)||v.any.length+v.all.length+v.exclude.length>32)return false
 return [v.any,v.all,v.exclude].every((conditions,group)=>{
  const seen=new Set<string>()
  return conditions.every(c=>{
   if(!object(c)||!known(c,['field','op','value'])||!Object.hasOwn(applicationFields,String(c.field))||!conditionOperators(String(c.field)).includes(c.op as AppCondition['op'])||!text(c.value,domainCondition(String(c.field))?1024:c.field==='http.path'?256:c.field==='http.user_agent'?128:64,true)||group===0&&!domainCondition(String(c.field)))return false
   const field=String(c.field),protocols=v.protocols as string[],compatible=field.startsWith('http.')&&protocols.includes('http')||field.startsWith('tls.')&&protocols.some(p=>p==='tls'||p==='quic')||field==='dns.name'&&protocols.includes('dns')
   if(!compatible||field==='http.path'&&!c.value.startsWith('/')||field==='http.method'&&!['GET','POST','PUT','DELETE','PATCH','HEAD','OPTIONS','CONNECT','TRACE'].includes(c.value)||domainCondition(field)&&(/[/*:@\\?#\[\]]/.test(c.value)||!c.value.includes('.')))return false
   const key=JSON.stringify(c);if(seen.has(key))return false;seen.add(key);return true
  })
 })
}
export function changeError(v:AppChange):string {
 if(!id(v.id)||!rev(v.expected_revision,0)||v.expected_revision===1000000)return '规则标识或期望修订无效。'
 if(!text(v.name,128,true)||!text(v.description,1000))return '请填写规则名称，说明不能包含控制字符。'
 if(typeof v.active!=='boolean'||v.expected_revision===0&&!v.active)return '规则状态无效，创建时须启用。'
 if(!validDefinition(v.definition))return '请核对产品、类别、协议与条件；正向条件须为产品域名，最多 32 条。'
 return ''
}
// 按公开契约顺序重建对象，以便与 Go 结构体摘要进行独立核对。
export function orderedDefinition(d:AppDefinition):AppDefinition {
 const conditions=(values:AppCondition[])=>values.map(c=>({field:c.field,op:c.op,value:c.value}))
 return {schema_version:d.schema_version,product_id:d.product_id,product_name:d.product_name,category_id:d.category_id,protocols:[...d.protocols],any:conditions(d.any),all:conditions(d.all),exclude:conditions(d.exclude)}
}
export const appDigest=goJSONDigest
export async function validRule(v:unknown,tenant:string):Promise<boolean> {
 if(!object(v)||v.tenant_id!==tenant||!id(v.id)||!rev(v.revision)||!text(v.name,128,true)||!text(v.description,1000)||typeof v.active!=='boolean'||!validDefinition(v.definition)||!digest(v.definition_sha256)||!id(v.created_by)||!date(v.created_at)||!date(v.expires_at)||Date.parse(v.expires_at)<=Date.parse(v.created_at))return false
 return await appDigest(orderedDefinition(v.definition))===v.definition_sha256
}
export async function validRulePage(v:unknown,tenant:string,cursor:string,active:string,limit=20):Promise<boolean> {
 if(!object(v)||!Array.isArray(v.items)||v.items.length>limit||typeof v.next_cursor!=='string'||v.next_cursor!==''&&(!id(v.next_cursor)||v.items.length!==limit||!object(v.items.at(-1))||v.items.at(-1).id!==v.next_cursor))return false
 let prior=cursor
 for(const row of v.items){if(!object(row)||typeof row.id!=='string'||row.id<=prior||active!==''&&row.active!==(active==='true')||!await validRule(row,tenant))return false;prior=row.id}
 return true
}
export async function validRuleReceipt(v:unknown,tenant:string,input:AppChange):Promise<boolean> {
 return object(v)&&v.id===input.id&&v.revision===input.expected_revision+1&&v.name===input.name&&v.description===input.description&&v.active===input.active&&await validRule(v,tenant)&&await appDigest(orderedDefinition(input.definition))===v.definition_sha256
}
export function orderedObservation(o:AppObservation):AppObservation {return {schema_version:o.schema_version,protocol:o.protocol,http_host:o.http_host,http_method:o.http_method,http_path:o.http_path,http_user_agent:o.http_user_agent,tls_sni:o.tls_sni,tls_alpn:[...o.tls_alpn],dns_names:[...o.dns_names]}}
export async function validTestResult(v:unknown,o:AppObservation,definition?:AppDefinition):Promise<boolean> {
 if(!object(v)||v.schema_version!=='application-test.v1'||v.origin!=='user_supplied_metadata'||v.protocol!==o.protocol||!Object.hasOwn(appStatuses,String(v.status))||!date(v.evaluated_at)||!digest(v.observation_sha256)||!digest(v.rules_sha256)||!rev(v.rule_count,0)||Number(v.rule_count)>128||!rev(v.matched_rule_count,0)||Number(v.matched_rule_count)>Number(v.rule_count)||!Array.isArray(v.matches)||v.matches.length!==Math.min(Number(v.matched_rule_count),16)||typeof v.limited!=='boolean'||v.limited!==(Number(v.matched_rule_count)>16))return false
 const count=Number(v.matched_rule_count)
 if(v.status==='unknown'&&(count!==0||!['no_matching_rule','metadata_unavailable'].includes(String(v.reason)))||v.status==='candidate'&&(count===0||v.reason!=='visible_name_rule')||v.status==='conflict'&&(count<2||v.reason!=='multiple_products'))return false
 const ids=new Set<string>(),products=new Set<string>()
 for(const match of v.matches){if(!object(match)||!id(match.rule_id)||ids.has(match.rule_id)||!rev(match.revision)||!id(match.product_id)||!text(match.product_name,128,true)||!Object.hasOwn(applicationCategories,String(match.category_id))||typeof match.evidence_limited!=='boolean'||!Array.isArray(match.evidence)||match.evidence.length<1||match.evidence.length>8||!match.evidence.every(e=>object(e)&&Object.hasOwn(applicationFields,String(e.field))&&conditionOperators(String(e.field)).includes(e.op as AppCondition['op'])&&text(e.pattern,1024,true)))return false;ids.add(match.rule_id);products.add(match.product_id)}
 if(v.status==='candidate'&&products.size!==1||v.status==='conflict'&&!v.limited&&products.size<2)return false
 if(await appDigest(orderedObservation(o))!==v.observation_sha256)return false
 if(definition){if(v.rule_count!==1||await appDigest([{id:'candidate_rule',revision:1,definition:orderedDefinition(definition)}])!==v.rules_sha256||v.matches.some(m=>m.rule_id!=='candidate_rule'||m.revision!==1||m.product_id!==definition.product_id||m.product_name!==definition.product_name||m.category_id!==definition.category_id))return false}
 return true
}
export function emptyObservation(protocol='http'):AppObservation {return {schema_version:'application-observation.v1',protocol,http_host:'',http_method:'',http_path:'',http_user_agent:'',tls_sni:'',tls_alpn:[],dns_names:[]}}
