import {instant} from './utils/instant'
import {goJSONDigest} from './utils/goJSONDigest'

export const watchlistKinds={protect:'保护名单',observe:'观察名单'} as const
export const watchlistMatchTypes={ip:'IP 地址',cidr:'CIDR 网段',domain:'精确域名'} as const
export const watchlistReasons={scope_too_broad:'CIDR 范围超过启用限制，当前仅允许停用保存。',expired:'名单业务有效期已结束。',not_yet_valid:'名单尚未到生效时间。',inactive:'名单处于停用状态。'} as const
export interface WatchlistScope {sensor_id:string;registration_id:string}
export interface WatchlistSensor extends WatchlistScope {name:string;available?:boolean}
export interface WatchlistDefinition {schema_version:'watchlist.v1';kind:keyof typeof watchlistKinds;match_type:keyof typeof watchlistMatchTypes;values:string[];sensors:WatchlistScope[];valid_from:string;valid_until:string}
export interface WatchlistRecord {tenant_id:string;id:string;revision:number;name:string;description:string;active:boolean;definition:WatchlistDefinition;definition_sha256:string;created_by:string;created_at:string;expires_at:string}
export interface WatchlistChange {id:string;expected_revision:number;name:string;description:string;active:boolean;definition:WatchlistDefinition}
export interface WatchlistQuery {cursor:string;keyword:string;active:string;kind:string;limit:number}
export interface WatchlistPage {items:WatchlistRecord[];next_cursor:string}
export interface WatchlistTarget extends WatchlistScope {type:'ip'|'domain';value:string}
export interface WatchlistPreviewRequest {definition:WatchlistDefinition;active:boolean;targets:WatchlistTarget[]}
export interface WatchlistPreviewResult {schema_version:'watchlist-preview.v1';definition_sha256:string;active:boolean;admissible:boolean;effective:boolean;checked_at:string;scope_sensor_count:number;value_count:number;reasons:string[];matches:{index:number;matched:boolean}[];execution_authorized:false;fact_deletion_allowed:false}

const object=(v:unknown):v is Record<string,unknown>=>!!v&&typeof v==='object'&&!Array.isArray(v)
const id=(v:unknown):v is string=>typeof v==='string'&&/^[a-z0-9][a-z0-9_-]{0,63}$/.test(v)
const integer=(v:unknown,min:number,max:number):v is number=>typeof v==='number'&&Number.isSafeInteger(v)&&v>=min&&v<=max
const text=(v:unknown,max:number,required=false):v is string=>typeof v==='string'&&v===v.trim()&&(!required||!!v)&&Array.from(v).length<=max&&!/[\p{Cc}\uD800-\uDFFF]/u.test(v)
const digest=(v:unknown):v is string=>typeof v==='string'&&/^[a-f0-9]{64}$/.test(v)
const date=(v:unknown):v is string=>typeof v==='string'&&instant(v)!==null
const fields=(v:Record<string,unknown>,keys:string[])=>Object.keys(v).length===keys.length&&keys.every(key=>Object.hasOwn(v,key))
const failure=()=>new Error('名单数据与当前租户、修订或核验范围不一致，请刷新后重试。')
function canonicalIP(value:string,reserved=false):boolean {
 if(!/^[0-9a-f:.]+$/.test(value))return false
 if(!value.includes(':')){const parts=value.split('.');return parts.length===4&&parts.every(part=>/^(0|[1-9]\d{0,2})$/.test(part)&&Number(part)<=255)&&(reserved||value!=='0.0.0.0'&&(Number(parts[0])<224||Number(parts[0])>239))}
 try{return new URL('http://['+value+']/').hostname==='['+value+']'&&!value.startsWith('::ffff:')&&(reserved||value!=='::'&&!value.startsWith('ff'))}catch{return false}
}
function canonicalPrefix(value:string):boolean {
 const parts=value.split('/'),address=parts[0]??'',bits=parts[1]??''
 if(parts.length!==2||!canonicalIP(address,true)||!/^(0|[1-9]\d{0,2})$/.test(bits))return false
 const width=address.includes(':')?128:32,prefix=Number(bits);if(prefix>width)return false
 const number=addressNumber(address)
 return (number&((1n<<BigInt(width-prefix))-1n))===0n
}
function addressNumber(address:string):bigint {
 if(!address.includes(':'))return address.split('.').reduce((v,part)=>(v<<8n)+BigInt(part),0n)
 const [left,right]=address.split('::'),a=left?left.split(':'):[],b=right?right.split(':'):[],words=right===undefined?a:[...a,...Array(8-a.length-b.length).fill('0'),...b]
 return words.reduce((v,part)=>(v<<16n)+BigInt('0x'+part),0n)
}
export function watchlistValueValid(type:string,value:string):boolean {
 if(type==='ip')return canonicalIP(value)
 if(type==='cidr')return canonicalPrefix(value)
 if(type!=='domain'||!value.includes('.')||value.length>253||canonicalIP(value,true))return false
 return value.split('.').every(part=>part.length<=63&&/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(part))
}
export const watchlistScopeKey=(v:WatchlistScope)=>v.sensor_id+'/'+v.registration_id
export const emptyWatchlistQuery=():WatchlistQuery=>({cursor:'',keyword:'',active:'',kind:'',limit:20})
export function emptyWatchlistDefinition(now=Date.now()):WatchlistDefinition {
 const start=Math.floor(now/1000)*1000
 return {schema_version:'watchlist.v1',kind:'protect',match_type:'ip',values:[],sensors:[],valid_from:new Date(start).toISOString().replace('.000Z','Z'),valid_until:new Date(start+180*86400000).toISOString().replace('.000Z','Z')}
}
// 定义摘要按服务端结构顺序核对，业务有效期与历史留存期限不互相替代。
export function watchlistDefinitionShape(v:WatchlistDefinition):WatchlistDefinition {
 return {schema_version:v.schema_version,kind:v.kind,match_type:v.match_type,values:[...v.values],sensors:v.sensors.map(s=>({sensor_id:s.sensor_id,registration_id:s.registration_id})),valid_from:v.valid_from,valid_until:v.valid_until}
}
export function watchlistDefinitionError(v:unknown):string {
 if(!object(v)||!fields(v,['schema_version','kind','match_type','values','sensors','valid_from','valid_until'])||v.schema_version!=='watchlist.v1'||!Object.hasOwn(watchlistKinds,String(v.kind))||!Object.hasOwn(watchlistMatchTypes,String(v.match_type)))return '请选择支持的名单类型和匹配方式。'
 if(!Array.isArray(v.values)||v.values.length<1||v.values.length>64||new Set(v.values).size!==v.values.length||!v.values.every(s=>text(s,253,true)))return '请填写 1–64 个不重复的规范值，每行一项。'
 const invalidValue=v.values.findIndex(s=>!watchlistValueValid(String(v.match_type),s));if(invalidValue!==-1)return `第 ${invalidValue+1} 项匹配值格式无效，请核对规范 IP、网段边界或精确小写域名。`
 if(!Array.isArray(v.sensors)||v.sensors.length<1||v.sensors.length>32||!v.sensors.every(s=>object(s)&&fields(s,['sensor_id','registration_id'])&&id(s.sensor_id)&&id(s.registration_id))||new Set(v.sensors.map(s=>s.sensor_id)).size!==v.sensors.length)return '请选择 1–32 个有效探针及注册代次，同一探针不能重复。'
 if(!date(v.valid_from)||!date(v.valid_until)||!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(v.valid_from)||!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(v.valid_until))return '请填写精确到秒的 UTC 生效和到期时间。'
 const start=instant(v.valid_from)!,end=instant(v.valid_until)!
 if(start<946684800000000000n||end<=start||end-start>3650n*86400000000000n)return '到期时间须晚于生效时间，单次业务有效期最多 3650 天。'
 return ''
}
export function watchlistChangeError(v:WatchlistChange,now=Date.now()):string {
 if(!id(v.id)||!integer(v.expected_revision,0,999999)||!text(v.name,128,true)||!text(v.description,1000,true)||typeof v.active!=='boolean')return '请填写名单名称、必填依据及有效修订；依据最多 1000 字。'
 const invalid=watchlistDefinitionError(v.definition);if(invalid)return invalid
 if(v.active&&instant(v.definition.valid_until)!<=BigInt(now)*1000000n)return '名单已到期，不能启用；请先设置有效期限。'
 if(v.active&&watchlistBroad(v.definition))return 'CIDR 范围超过启用限制，请缩小范围或停用保存。'
 return ''
}
export function watchlistBroad(v:WatchlistDefinition):boolean {
 return v.match_type==='cidr'&&v.values.some(value=>{const [address,bits]=value.split('/');return !address||bits===undefined||!/^\d+$/.test(bits)||Number(bits)<(address.includes(':')?120:24)})
}
export function watchlistState(v:Pick<WatchlistRecord,'active'|'definition'>,now=Date.now()):'disabled'|'scheduled'|'expired'|'effective' {
 if(!v.active)return 'disabled'
 const clock=BigInt(now)*1000000n
 if(instant(v.definition.valid_until)!<=clock)return 'expired'
 return instant(v.definition.valid_from)!>clock?'scheduled':'effective'
}
export const watchlistStates={disabled:'已停用',scheduled:'待生效',expired:'已到期',effective:'有效'} as const
export async function readWatchlist(v:unknown,tenant:string):Promise<WatchlistRecord> {
 if(!object(v)||v.tenant_id!==tenant||!id(v.id)||!id(v.created_by)||!integer(v.revision,1,1000000)||!text(v.name,128,true)||!text(v.description,1000,true)||typeof v.active!=='boolean'||watchlistDefinitionError(v.definition)||v.active&&watchlistBroad(v.definition as unknown as WatchlistDefinition)||!digest(v.definition_sha256)||!date(v.created_at)||!date(v.expires_at)||instant(v.expires_at)!<=instant(v.created_at)!)throw failure()
 if(await goJSONDigest(watchlistDefinitionShape(v.definition as unknown as WatchlistDefinition))!==v.definition_sha256)throw failure()
 return v as unknown as WatchlistRecord
}
async function cursorPosition(value:string,q:WatchlistQuery,tenant:string):Promise<string> {
 if(!value)return ''
 if(!/^[A-Za-z0-9_-]{1,2048}$/.test(value))throw failure()
 let decoded:unknown
 try{const raw=atob(value.replaceAll('-','+').replaceAll('_','/'));if(btoa(raw).replaceAll('+','-').replaceAll('/','_').replaceAll('=','')!==value)throw failure();decoded=JSON.parse(raw)}catch{throw failure()}
 if(!object(decoded)||!fields(decoded,['after','scope'])||!id(decoded.after)||decoded.scope!==await goJSONDigest({tenant,query:{cursor:'',keyword:q.keyword,active:q.active,kind:q.kind,limit:q.limit}}))throw failure()
 return decoded.after
}
export async function readWatchlistPage(v:unknown,q:WatchlistQuery,tenant:string):Promise<WatchlistPage> {
 if(!object(v)||!Array.isArray(v.items)||v.items.length>q.limit||typeof v.next_cursor!=='string')throw failure()
 let previous=await cursorPosition(q.cursor,q,tenant)
 for(const raw of v.items){const item=await readWatchlist(raw,tenant);if(item.id<=previous||q.active&&item.active!==(q.active==='true')||q.kind&&item.definition.kind!==q.kind)throw failure();previous=item.id}
 if(v.next_cursor&&(v.items.length!==q.limit||await cursorPosition(v.next_cursor,q,tenant)!==previous))throw failure()
 return v as unknown as WatchlistPage
}
export async function readWatchlistReceipt(v:unknown,tenant:string,input:WatchlistChange,actor:string):Promise<WatchlistRecord> {
 const record=await readWatchlist(v,tenant)
 if(record.created_by!==actor||record.id!==input.id||record.revision!==input.expected_revision+1||record.name!==input.name||record.description!==input.description||record.active!==input.active||record.definition_sha256!==await goJSONDigest(watchlistDefinitionShape(input.definition)))throw failure()
 return record
}
export function watchlistPreviewError(v:WatchlistPreviewRequest):string {
 const invalid=watchlistDefinitionError(v.definition);if(invalid)return invalid
 if(typeof v.active!=='boolean'||!Array.isArray(v.targets)||v.targets.length>128||!v.targets.every(t=>object(t)&&id(t.sensor_id)&&id(t.registration_id)&&['ip','domain'].includes(t.type)&&text(t.value,253,true)&&watchlistValueValid(t.type,t.value)))return '匹配核验最多 128 项，目标须包含探针、注册代次、类型和规范值。'
 return ''
}
// 材料匹配与名单是否正在生效分开计算，避免把到期或停用误写为不曾匹配。
export function watchlistTargetMatched(definition:WatchlistDefinition,target:WatchlistTarget):boolean {
 if(watchlistDefinitionError(definition)||!watchlistValueValid(target.type,target.value)||!definition.sensors.some(s=>s.sensor_id===target.sensor_id&&s.registration_id===target.registration_id))return false
 if(definition.match_type==='domain')return target.type==='domain'&&definition.values.includes(target.value)
 if(target.type!=='ip')return false
 if(definition.match_type==='ip')return definition.values.includes(target.value)
 const address=addressNumber(target.value),width=target.value.includes(':')?128:32
 return definition.values.some(value=>{const [prefix,bits]=value.split('/');if(prefix!.includes(':')!==(width===128))return false;const shift=BigInt(width-Number(bits));return (address>>shift)===(addressNumber(prefix!)>>shift)})
}
export async function readWatchlistPreview(v:unknown,input:WatchlistPreviewRequest):Promise<WatchlistPreviewResult> {
 if(!object(v)||v.schema_version!=='watchlist-preview.v1'||v.active!==input.active||v.definition_sha256!==await goJSONDigest(watchlistDefinitionShape(input.definition))||typeof v.admissible!=='boolean'||typeof v.effective!=='boolean'||!date(v.checked_at)||v.scope_sensor_count!==input.definition.sensors.length||v.value_count!==input.definition.values.length||!Array.isArray(v.reasons)||v.reasons.length>16||new Set(v.reasons).size!==v.reasons.length||!v.reasons.every(r=>text(r,128,true))||!Array.isArray(v.matches)||v.matches.length!==input.targets.length||v.execution_authorized!==false||v.fact_deletion_allowed!==false)throw failure()
 const broad=watchlistBroad(input.definition),expired=instant(v.checked_at)!>=instant(input.definition.valid_until)!,future=instant(v.checked_at)!<instant(input.definition.valid_from)!
 const reasons=[...(broad?['scope_too_broad']:[]),...(expired?['expired']:future?['not_yet_valid']:[]),...(!input.active?['inactive']:[])]
 if(v.admissible!==(!broad&&!expired)||v.effective!==(input.active&&!broad&&!expired&&!future)||JSON.stringify(v.reasons)!==JSON.stringify(reasons))throw failure()
 for(const [index,result] of v.matches.entries())if(!object(result)||!fields(result,['index','matched'])||result.index!==index||typeof result.matched!=='boolean'||result.matched!==watchlistTargetMatched(input.definition,input.targets[index]!))throw failure()
 return v as unknown as WatchlistPreviewResult
}
