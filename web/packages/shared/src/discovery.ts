import {instant} from './utils/instant'

export interface DiscoveryQuery {network_id:string;network_revision:number;sensor_id:string;registration_id:string;prefix:string;start:string;end:string}
export interface DiscoveryScope {network_id:string;network_revision:number;network_name:string;network_domain:string;network_prefix:string;sensor_id:string;sensor_name:string;registration_id:string}
export interface DiscoveryWitness {event_id:string;timestamp:string;observed_at:string;generation_id:string;sequence:string;raw_sha256:string;flow_id:string;side:'source'|'destination';source:{ip?:string;port?:number;mac?:string};destination:{ip?:string;port?:number;mac?:string}}
export interface DiscoveryAddress {ip:string;source_records:string;destination_records:string;first:DiscoveryWitness;last:DiscoveryWitness}
export interface DiscoveryResult {schema_version:'1.0';query:DiscoveryQuery;scope:DiscoveryScope;queried_at:string;addresses:DiscoveryAddress[];source_excluded:string;destination_excluded:string;partition_status:'available'|'absent'}
const id=(v:unknown):v is string=>typeof v==='string'&&/^[a-z0-9][a-z0-9_-]{0,63}$/.test(v)
const text=(v:unknown):v is string=>typeof v==='string'&&v.length>0&&v.length<=128&&!/[\x00-\x1f\x7f]/.test(v)
const ip=(v:unknown):v is string=>typeof v==='string'&&v.length<=45&&/^[0-9a-f:.]+$/.test(v)
const object=(v:unknown):v is Record<string,unknown>=>!!v&&typeof v==='object'&&!Array.isArray(v)
const unsigned=(v:unknown,max:bigint):v is string=>typeof v==='string'&&/^(0|[1-9][0-9]{0,19})$/.test(v)&&BigInt(v)<=max
const count=(v:unknown):v is string=>unsigned(v,9223372036854775807n)
function witness(value:unknown,q:DiscoveryQuery,address:string):value is DiscoveryWitness {
 if(!object(value)||!id(value.event_id)||!id(value.generation_id)||!unsigned(value.sequence,18446744073709551615n)||!unsigned(value.flow_id,18446744073709551615n)||typeof value.raw_sha256!=='string'||!/^[0-9a-f]{64}$/.test(value.raw_sha256)||!['source','destination'].includes(String(value.side))||typeof value.timestamp!=='string'||typeof value.observed_at!=='string'||instant(value.observed_at)===null)return false
 const at=instant(value.timestamp),start=instant(q.start),end=instant(q.end)
 if(at===null||start===null||end===null||at<start||at>=end)return false
 for(const side of ['source','destination']){const v=value[side];if(!object(v)||v.ip!==undefined&&!ip(v.ip)||v.port!==undefined&&(!Number.isInteger(v.port)||Number(v.port)<0||Number(v.port)>65535)||v.mac!==undefined&&(typeof v.mac!=='string'||v.mac!==''&&!/^(?:[0-9a-f]{2}:){5}[0-9a-f]{2}$/.test(v.mac)))return false}
 return (value[value.side as string] as Record<string,unknown>).ip===address
}

// 回执必须与提交时冻结的范围一致；计数和纳秒时间不经过浮点转换。
export function readDiscovery(value:unknown,q:DiscoveryQuery):DiscoveryResult {
 const start=instant(q.start),end=instant(q.end)
 if(start===null||end===null||end<=start||end-start>86400000000000n||!id(q.sensor_id)||!id(q.registration_id)||!id(q.network_id)||!Number.isSafeInteger(q.network_revision)||q.network_revision<1||!object(value)||value.schema_version!=='1.0'||!object(value.query)||Object.keys(q).filter(key=>key!=='start'&&key!=='end').some(key=>(value.query as Record<string,unknown>)[key]!==q[key as keyof DiscoveryQuery])||typeof value.query.start!=='string'||typeof value.query.end!=='string'||instant(value.query.start)!==start||instant(value.query.end)!==end||!object(value.scope)||!text(value.scope.network_name)||!text(value.scope.network_domain)||!text(value.scope.sensor_name)||!text(value.scope.network_prefix)||value.scope.network_id!==q.network_id||value.scope.network_revision!==q.network_revision||value.scope.sensor_id!==q.sensor_id||value.scope.registration_id!==q.registration_id||typeof value.queried_at!=='string'||instant(value.queried_at)===null||!count(value.source_excluded)||!count(value.destination_excluded)||!['available','absent'].includes(String(value.partition_status))||!Array.isArray(value.addresses)||value.addresses.length>512)throw new Error('观测回执与查询范围不一致，请刷新目录后重试。')
 const seen=new Set<string>()
 for(const row of value.addresses){
  if(!object(row)||!ip(row.ip)||seen.has(row.ip)||!count(row.source_records)||!count(row.destination_records)||BigInt(row.source_records)+BigInt(row.destination_records)===0n||!witness(row.first,q,row.ip)||!witness(row.last,q,row.ip))throw new Error('地址观测证据不完整，本次结果未交付。')
  seen.add(row.ip)
  const first=instant(row.first.timestamp)!,last=instant(row.last.timestamp)!,source=BigInt(row.source_records),destination=BigInt(row.destination_records)
  if(last<first||last===first&&row.last.event_id<row.first.event_id||[row.first,row.last].some(sample=>(sample.side==='source'?source:destination)===0n))throw new Error('地址观测顺序或方向计数不一致。')
 }
 if(value.partition_status==='absent'&&(value.addresses.length!==0||value.source_excluded!=='0'||value.destination_excluded!=='0'))throw new Error('分区状态与观测结果不一致。')
 return structuredClone(value) as unknown as DiscoveryResult
}
export const discoveryCount=(value:string)=>BigInt(value).toLocaleString('zh-CN')
export function discoveryEndpoint(value:DiscoveryWitness['source']){return `${value.ip?.includes(':')?'['+value.ip+']':value.ip||'未记录'}:${value.port??'未记录'}`}
