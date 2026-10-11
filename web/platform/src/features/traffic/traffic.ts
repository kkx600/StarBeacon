import type {Alert,SearchRequest} from '@starbeacon/shared/types.ts'
export const trafficKinds:Record<string,string>={flow:'会话摘要',http:'HTTP',http2:'HTTP/2',dns:'DNS',tls:'TLS',quic:'QUIC',ssh:'SSH',smtp:'SMTP',ftp:'FTP',smb:'SMB',nfs:'NFS',dhcp:'DHCP',rdp:'RDP',anomaly:'协议异常',fileinfo:'文件元数据'}
export interface TrafficQuery extends SearchRequest {event_kind:string;sensor_id:string;sensor_registration_id:string;source_generation_id:string;flow_id:string}
export type TrafficFilters=Omit<TrafficQuery,'start'|'end'|'page'|'page_size'>&{filter:string}
export interface TrafficFlow {start:string|null;end:string|null;state:string;reason:string;packets_to_server:string;packets_to_client:string;bytes_to_server:string;bytes_to_client:string}
export interface TrafficDetails {state:'available'|'unavailable';truncated:boolean;flow:TrafficFlow|null;tls:{sni:string;version:string;subject:string;issuer:string;fingerprint:string}|null;dns:{version:string;type:string;rcode:string;queries:{name:string;type:string}[]}|null;source_macs:string[];destination_macs:string[];community_id:string;packet_source:string;direction:string}
export interface TrafficRecord extends Alert {details:TrafficDetails;sensor_registration_id?:string;source_generation_id?:string}
export interface TrafficResult {items:TrafficRecord[];total:number;page:number;page_size:number}
export const defaultTrafficFilters=():TrafficFilters=>({event_kind:'flow',sensor_id:'',sensor_registration_id:'',source_generation_id:'',flow_id:'',protocol:'',source_ip:'',destination_ip:'',method:'',path:'',filter:'',keyword:'',severity:''})
export function endpoint(ip:string|undefined,port:number|undefined):string {
 if(!ip)return '未观测到'
 return port ? `${ip.includes(':')?'['+ip+']':ip}:${port}` : ip
}
const object=(value:unknown):value is Record<string,unknown>=>!!value&&typeof value==='object'&&!Array.isArray(value)
const count=(value:unknown):value is string=>typeof value==='string'&&(value===''||/^(0|[1-9]\d{0,19})$/.test(value)&&BigInt(value)<=18446744073709551615n)
const date=(value:unknown)=>value===null||typeof value==='string'&&Number.isFinite(Date.parse(value))
const strings=(value:unknown,limit:number)=>Array.isArray(value)&&value.length<=limit&&value.every(v=>typeof v==='string')
function validDetails(value:unknown):value is TrafficDetails {
 if(!object(value)||!['available','unavailable'].includes(String(value.state))||typeof value.truncated!=='boolean'||!strings(value.source_macs,16)||!strings(value.destination_macs,16))return false
 // 不可用视图仍保留原事件身份，不要求伪造协议字段。
 if(value.state==='unavailable')return value.flow===null&&value.tls===null&&value.dns===null
 if(!['community_id','packet_source','direction'].every(k=>typeof value[k]==='string'))return false
 const flow=value.flow,tls=value.tls,dns=value.dns
 if(flow!==null){if(!object(flow)||!['state','reason'].every(k=>typeof flow[k]==='string')||!['packets_to_server','packets_to_client','bytes_to_server','bytes_to_client'].every(k=>count(flow[k]))||!date(flow.start)||!date(flow.end))return false;if(flow.start!==null&&flow.end!==null&&Date.parse(String(flow.end))<Date.parse(String(flow.start)))return false}
 if(tls!==null&&(!object(tls)||!['sni','version','subject','issuer','fingerprint'].every(k=>typeof tls[k]==='string')))return false
 if(dns!==null&&(!object(dns)||!['version','type','rcode'].every(k=>typeof dns[k]==='string')||!Array.isArray(dns.queries)||dns.queries.length>32||!dns.queries.every(q=>object(q)&&typeof q.name==='string'&&typeof q.type==='string')))return false
 return true
}
export function validTrafficResult(value:unknown,query:TrafficQuery,tenant:string):value is TrafficResult {
 if(!object(value)||!Number.isSafeInteger(value.total)||Number(value.total)<0||value.page!==query.page||value.page_size!==query.page_size||!Array.isArray(value.items)||value.items.length!==Math.min(query.page_size,Math.max(Number(value.total)-(query.page-1)*query.page_size,0)))return false
 const ids=new Set<string>()
 return value.items.every(row=>{
  if(!object(row)||typeof row.event_id!=='string'||ids.has(row.event_id)||row.tenant_id!==tenant||typeof row.sensor_id!=='string'||!object(row.event)||!Object.hasOwn(trafficKinds,String(row.event.kind))||typeof row.event.original!=='string'||!['source','destination','network','http','suricata','rule'].every(k=>object(row[k]))||typeof row['@timestamp']!=='string'||!Number.isFinite(Date.parse(row['@timestamp']))||Date.parse(row['@timestamp'])<Date.parse(query.start)||Date.parse(row['@timestamp'])>=Date.parse(query.end)||!validDetails(row.details))return false
  if(query.event_kind&&row.event.kind!==query.event_kind)return false
  ids.add(row.event_id);return true
 })
}
