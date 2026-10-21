import {instant} from './utils/instant'
import {goJSONDigest} from './utils/goJSONDigest'
export interface LogBinding {source_id:string;source_name:string;network_domain:string;config_sha256:string;transport:'tls'|'tcp'|'udp';format:'rfc5424'|'rfc3164';timezone:string;year_policy:string}
export interface SyslogSource extends LogBinding {state:string;reason:string;observed_at:string;started_at:string;received:string;persisted:string;dropped:string;rejected:string;framing_errors:string;last_persisted_at:string|null;max_message_bytes:number;identity_quality:string;upstream_loss:string;sensor_id?:string;sensor_name?:string;registration_id?:string;sensor_status?:string;observation?:string;last_seen?:string|null}
export interface SourceQuery {sensor_id:string;source_id:string;cursor:string;limit:number}
export interface SourcePage {items:SyslogSource[];query:SourceQuery;next_cursor:string;observed_at:string}
export interface LogRecord {schema_version:string;binding:LogBinding;source_epoch:string;source_sequence:string;observed_at:string;peer:{ip:string;port:number;certificate_sha256:string};raw_base64?:string;raw_sha256:string}
export interface LogDocument {message_truncated?:boolean;schema_version:string;event_id:string;tenant_id:string;sensor_id:string;sensor_registration_id:string;sequence:string;payload_sha256:string;partition:string;received_at:string;record:LogRecord;parsed:{parser_version:string;state:'parsed'|'quarantined';reason:string;time_quality:string;source_time:string|null;priority:number|null;facility:number|null;severity:number|null;hostname:string;application:string;process_id:string;message_id:string;message:string;message_utf8:boolean;structured_data?:Record<string,Record<string,string>>}}
export interface LogQuery {start:string;end:string;sensor_id:string;source_id:string;network_domain:string;peer_ip:string;hostname:string;application:string;state:string;severity:number|null;keyword:string;cursor:string;limit:number}
export interface LogPage {items:LogDocument[];query:LogQuery;next_cursor:string}
export const sourceStates:Record<string,string>={starting:'启动中',listening:'正在接收',unavailable:'监听不可用',degraded:'持久缓冲不可用',stopped:'已停止'}
export const timeQualities:Record<string,string>={source_timezone:'原文包含时区',inferred_year_timezone:'年份与时区按配置推断',missing_source_time:'原文未提供时间',ambiguous_year:'年份无法确定',ambiguous_local_time:'本地时间存在歧义',source_time_out_of_range:'来源时间超出范围',future_source_time:'来源时间超前',unavailable:'时间无法解析'}
const id=/^[a-z0-9][a-z0-9_-]{0,63}$/,hash=/^[a-f0-9]{64}$/,object=(v:unknown):v is Record<string,unknown>=>!!v&&typeof v==='object'&&!Array.isArray(v),counter=(v:unknown)=>typeof v==='string'&&/^(0|[1-9]\d{0,19})$/.test(v)&&BigInt(v)<=18446744073709551615n
const validTime=(v:unknown)=>typeof v==='string'&&instant(v)!==null
function binding(v:unknown):v is LogBinding{return object(v)&&typeof v.source_id==='string'&&id.test(v.source_id)&&typeof v.source_name==='string'&&!!v.source_name.trim()&&typeof v.network_domain==='string'&&id.test(v.network_domain)&&typeof v.config_sha256==='string'&&hash.test(v.config_sha256)&&['tls','tcp','udp'].includes(String(v.transport))&&['rfc5424','rfc3164'].includes(String(v.format))&&typeof v.timezone==='string'&&typeof v.year_policy==='string'}
export function sourceQuery(q:SourceQuery):SourceQuery {if(q.limit<1||q.limit>100||![q.sensor_id,q.source_id].every(v=>!v||id.test(v)))throw new Error('探针和来源标识需为 1–64 位小写字母、数字、下划线或连字符。');return {...q}}
export function readSources(v:unknown):SyslogSource[]{
 if(!Array.isArray(v)||v.length>1600)throw new Error('日志来源目录不完整。')
 const seen=new Set<string>()
 for(const row of v){if(!binding(row)||!object(row)||!Object.hasOwn(sourceStates,String(row.state))||!validTime(row.observed_at)||!validTime(row.started_at)||![row.received,row.persisted,row.dropped,row.rejected,row.framing_errors].every(counter)||!Number.isInteger(row.max_message_bytes)||Number(row.max_message_bytes)<256||Number(row.max_message_bytes)>65536||row.last_persisted_at!==null&&!validTime(row.last_persisted_at)||typeof row.identity_quality!=='string'||typeof row.upstream_loss!=='string')throw new Error('日志来源状态无法核对。')
  const key=String(row.sensor_id??'local')+'/'+row.source_id;if(seen.has(key))throw new Error('日志来源目录存在重复身份。');seen.add(key)
  if(row.sensor_id!==undefined&&(typeof row.sensor_id!=='string'||!id.test(row.sensor_id)||typeof row.registration_id!=='string'||!id.test(row.registration_id)||typeof row.sensor_name!=='string'||!['online','offline','disabled'].includes(String(row.sensor_status))||!['fresh','stale'].includes(String(row.observation))))throw new Error('日志来源探针身份不完整。')
 }
 return v as SyslogSource[]
}
export function readSourcePage(v:unknown,q:SourceQuery):SourcePage {
 if(!object(v)||!object(v.query)||!Object.entries(q).every(([k,n])=>v.query&&object(v.query)&&v.query[k]===n)||typeof v.next_cursor!=='string'||v.next_cursor&&!/^[A-Za-z0-9_-]{1,512}$/.test(v.next_cursor)||!validTime(v.observed_at))throw new Error('日志来源分页条件不一致。')
 const items=readSources(v.items);if(items.length>q.limit||items.some(row=>!row.sensor_id||q.sensor_id&&q.sensor_id!==row.sensor_id||q.source_id&&q.source_id!==row.source_id))throw new Error('日志来源筛选结果不一致。')
 return v as unknown as SourcePage
}
export function emptySourceQuery():SourceQuery{return {sensor_id:'',source_id:'',cursor:'',limit:20}}
export function emptyLogQuery():LogQuery {const end=new Date();return {start:new Date(end.getTime()-86400000).toISOString(),end:end.toISOString(),sensor_id:'',source_id:'',network_domain:'',peer_ip:'',hostname:'',application:'',state:'',severity:null,keyword:'',cursor:'',limit:20}}
export function logQuery(q:LogQuery):LogQuery {
 const start=instant(q.start),end=instant(q.end)
 if(start===null||end===null||end<=start||end-start>31n*86400000000000n||q.limit<1||q.limit>100||![q.sensor_id,q.source_id,q.network_domain].every(v=>!v||id.test(v))||!['','parsed','quarantined'].includes(q.state)||q.severity!==null&&(!Number.isInteger(q.severity)||q.severity<0||q.severity>7)||[q.keyword,q.hostname,q.application].some(v=>v.length>256||/[\p{Cc}\p{Cs}]/u.test(v))||q.peer_ip.length>45)throw new Error('请核对不超过 31 天的时间范围、来源标识、严重级别和检索文本。')
 return {...q,start:q.start,end:q.end}
}
function readDocument(v:unknown,tenant:string,raw:boolean):LogDocument{
 if(!object(v)||v.schema_version!=='syslog.index.v1'||v.tenant_id!==tenant||typeof v.event_id!=='string'||!hash.test(v.event_id)||typeof v.sensor_id!=='string'||!id.test(v.sensor_id)||typeof v.sensor_registration_id!=='string'||!id.test(v.sensor_registration_id)||!counter(v.sequence)||typeof v.payload_sha256!=='string'||!hash.test(v.payload_sha256)||typeof v.partition!=='string'||!/^\d{4}-\d{2}-\d{2}$/.test(v.partition)||!validTime(v.received_at)||!object(v.record)||!binding(v.record.binding)||v.record.schema_version!=='syslog.raw.v1'||!counter(v.record.source_sequence)||!validTime(v.record.observed_at)||typeof v.record.raw_sha256!=='string'||!hash.test(v.record.raw_sha256)||!object(v.record.peer)||typeof v.record.peer.ip!=='string'||!Number.isInteger(v.record.peer.port)||!object(v.parsed)||!['parsed','quarantined'].includes(String(v.parsed.state))||!Object.hasOwn(timeQualities,String(v.parsed.time_quality))||typeof v.parsed.message!=='string'||v.parsed.message.length>65536||typeof v.parsed.hostname!=='string'||typeof v.parsed.application!=='string'||v.parsed.source_time!==null&&!validTime(v.parsed.source_time)||raw&&typeof v.record.raw_base64!=='string'||!raw&&v.record.raw_base64!==undefined)throw new Error('日志记录的来源、解析质量或原始事实不完整。')
 return v as unknown as LogDocument
}
// 时间回显按纳秒时刻绑定，允许 RFC 3339 的等价时区及小数秒表示。
function sameLogQuery(actual:Record<string,unknown>,q:LogQuery):boolean{return Object.entries(q).every(([key,expected])=>{const value=actual[key];if(key==='start'||key==='end'){if(typeof value!=='string'||typeof expected!=='string')return false;const time=instant(value);return time!==null&&time===instant(expected)}return value===expected})}
export function readLogPage(v:unknown,q:LogQuery,tenant:string):LogPage{
 if(!object(v)||!object(v.query)||!sameLogQuery(v.query,q)||!Array.isArray(v.items)||v.items.length>q.limit||typeof v.next_cursor!=='string'||v.next_cursor&&!/^[A-Za-z0-9_-]{1,512}$/.test(v.next_cursor))throw new Error('日志检索结果与当前查询不一致。')
 let previous=instant(q.end)!,last='';const seen=new Set<string>()
 for(const item of v.items){const row=readDocument(item,tenant,false),t=instant(row.received_at)!;if(t<instant(q.start)!||t>=instant(q.end)!||t>previous||t===previous&&row.event_id>=last||seen.has(row.event_id)||q.sensor_id&&row.sensor_id!==q.sensor_id||q.source_id&&row.record.binding.source_id!==q.source_id||q.state&&row.parsed.state!==q.state)throw new Error('日志检索顺序或筛选结果不一致。');previous=t;last=row.event_id;seen.add(last)}
 return v as unknown as LogPage
}
export async function readLogDetail(v:unknown,tenant:string,event:string,partition:string):Promise<LogDocument>{
 const row=readDocument(v,tenant,true),encoded=row.record.raw_base64!
 if(row.event_id!==event||row.partition!==partition||encoded.length>87384||!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(encoded)||!crypto.subtle)throw new Error('日志原文无法核对，请使用 HTTPS 或本机安全入口访问。')
 const decoded=Uint8Array.from(atob(encoded),c=>c.charCodeAt(0));if(!decoded.length||decoded.length>65536)throw new Error('日志原文长度不符合接收上限。')
 const sum=await crypto.subtle.digest('SHA-256',decoded),digest=Array.from(new Uint8Array(sum),n=>n.toString(16).padStart(2,'0')).join('')
 if(digest!==row.record.raw_sha256||await goJSONDigest(row.record)!==row.payload_sha256)throw new Error('日志原文摘要不一致，请重新查询。')
 return row
}
