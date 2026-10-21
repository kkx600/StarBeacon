import type {ResponseConnector} from './response'
import {readyConnector} from './response'
import {instant} from './utils/instant'
import {goJSONDigest} from './utils/goJSONDigest'

export interface DeviceQuery {sensor_id:string;device_id:string;status:string;cursor:string;limit:number}
export interface ResponseDevice extends ResponseConnector {sensor_id:string;sensor_name:string;registration_id:string;sensor_status:'online'|'offline'|'disabled';last_seen:string|null;host_observed_at:string;observation:'fresh'|'stale'|'pending';task_supported:boolean}
export interface DevicePage {items:ResponseDevice[];next_cursor:string;query:DeviceQuery;observed_at:string}
export interface ConfigCheck {schema_version:'response.config-check.v1';state:'not_configured'|'invalid'|'current'|'restart_required';running_count:number;file_count:number;checked_at:string}
const id=/^[a-z0-9][a-z0-9_-]{0,63}$/
const object=(v:unknown):v is Record<string,unknown>=>!!v&&typeof v==='object'&&!Array.isArray(v)
const zero='0001-01-01T00:00:00Z'
export const emptyDeviceQuery=():DeviceQuery=>({sensor_id:'',device_id:'',status:'',cursor:'',limit:20})
export const connectorStatuses=[{value:'',label:'全部核验状态'},{value:'ready',label:'身份已核验'},{value:'unverified',label:'身份待核验'},{value:'unavailable',label:'设备不可用'}]
export function deviceQuery(v:DeviceQuery):DeviceQuery{
 if([v.sensor_id,v.device_id].some(value=>value&&!id.test(value))||!connectorStatuses.some(option=>option.value===v.status))throw new Error('探针与设备标识须为 1–64 位小写字母、数字、下划线或连字符，请核对设备核验状态。')
 return {...v,cursor:'',limit:20}
}
export function usableDevice(v:ResponseDevice,now=Date.now()){
 const host=Date.parse(v.host_observed_at),seen=Date.parse(v.last_seen??'')
 return v.sensor_status==='online'&&v.task_supported&&v.observation==='fresh'&&readyConnector(v,now)&&Number.isFinite(host)&&Number.isFinite(seen)&&host>=now-35000&&host<=now+30000&&seen>=now-35000&&seen<=now+30000
}
export function deviceState(v:ResponseDevice,now=Date.now()){
 if(v.sensor_status==='disabled')return '探针已停用'
 if(v.sensor_status==='offline')return '探针离线或心跳过期'
 if(v.observation==='pending')return '等待设备核验'
 if(v.observation==='stale'||Date.parse(v.observed_at)<now-35000||Date.parse(v.observed_at)>now+30000)return '设备观测已过期'
 if(v.status==='unavailable')return '设备不可用'
 if(v.status==='unverified')return '身份待核验'
 if(!v.task_supported)return '执行能力不完整'
 return usableDevice(v,now)?'具备提交条件':'探针观测已过期'
}
function position(value:string){
 try{
  if(!/^[A-Za-z0-9_-]{1,512}$/.test(value))throw new Error()
  const decoded=atob(value.replaceAll('-','+').replaceAll('_','/')),v:unknown=JSON.parse(decoded)
  if(!object(v)||Object.keys(v).sort().join(',')!=='connector_id,query,sensor_id'||typeof v.sensor_id!=='string'||!id.test(v.sensor_id)||typeof v.connector_id!=='string'||!id.test(v.connector_id)||typeof v.query!=='string'||!/^[a-f0-9]{64}$/.test(v.query)||btoa(JSON.stringify({sensor_id:v.sensor_id,connector_id:v.connector_id,query:v.query})).replaceAll('+','-').replaceAll('/','_').replace(/=+$/,'')!==value)throw new Error()
  return v as {sensor_id:string;connector_id:string;query:string}
 }catch{throw new Error('联动设备分页凭据不完整，请重新查询。')}
}
export async function readDevicePage(v:unknown,q:DeviceQuery):Promise<DevicePage>{
 const invalid=()=>new Error('联动设备目录未能完整返回，请刷新后核对。')
 if(!object(v)||!Array.isArray(v.items)||v.items.length>q.limit||!object(v.query)||typeof v.observed_at!=='string'||instant(v.observed_at)===null||typeof v.next_cursor!=='string')throw invalid()
 const echo=v.query
 if(!Object.keys(q).every(key=>echo[key]===q[key as keyof DeviceQuery]))throw invalid()
 const fingerprint=await goJSONDigest({sensor_id:q.sensor_id,device_id:q.device_id,status:q.status,cursor:'',limit:q.limit}),at=Date.parse(v.observed_at)
 let previous=q.cursor?position(q.cursor):null
 if(previous&&previous.query!==fingerprint)throw invalid()
 for(const row of v.items){
  if(!object(row)||typeof row.sensor_id!=='string'||!id.test(row.sensor_id)||typeof row.connector_id!=='string'||!id.test(row.connector_id)||typeof row.device_id!=='string'||!id.test(row.device_id)||typeof row.registration_id!=='string'||!id.test(row.registration_id)||typeof row.sensor_name!=='string'||!row.sensor_name||typeof row.version!=='string'||!row.version.trim()||row.version!==row.version.trim()||[...row.version].length>64||/\p{Cc}/u.test(row.version)||typeof row.config_sha256!=='string'||!/^[a-f0-9]{64}$/.test(row.config_sha256)||!['ready','unavailable','unverified'].includes(String(row.status))||!Number.isInteger(row.max_ttl_seconds)||Number(row.max_ttl_seconds)<30||Number(row.max_ttl_seconds)>3600||!['online','offline','disabled'].includes(String(row.sensor_status))||typeof row.task_supported!=='boolean'||typeof row.host_observed_at!=='string'||instant(row.host_observed_at)===null||row.last_seen!==null&&(typeof row.last_seen!=='string'||instant(row.last_seen)===null)||typeof row.observed_at!=='string'||instant(row.observed_at)===null||row.status!=='unverified'&&row.observed_at===zero||q.sensor_id&&row.sensor_id!==q.sensor_id||q.device_id&&row.device_id!==q.device_id||q.status&&row.status!==q.status)throw invalid()
  const expected=row.observed_at===zero?'pending':Date.parse(row.observed_at)<at-35000||Date.parse(row.observed_at)>at+30000?'stale':'fresh'
  if(row.observation!==expected||previous&&(row.sensor_id<previous.sensor_id||row.sensor_id===previous.sensor_id&&row.connector_id<=previous.connector_id))throw invalid()
  previous={sensor_id:row.sensor_id,connector_id:row.connector_id,query:fingerprint}
 }
 if(v.next_cursor){const next=position(v.next_cursor);if(v.items.length!==q.limit||!previous||next.query!==fingerprint||next.sensor_id!==previous.sensor_id||next.connector_id!==previous.connector_id)throw invalid()}
 return v as unknown as DevicePage
}
export function readConfigCheck(v:unknown):ConfigCheck{
 if(!object(v)||v.schema_version!=='response.config-check.v1'||!['not_configured','invalid','current','restart_required'].includes(String(v.state))||![v.running_count,v.file_count].every(n=>Number.isInteger(n)&&Number(n)>=0&&Number(n)<=8)||typeof v.checked_at!=='string'||instant(v.checked_at)===null||v.state==='not_configured'&&(v.running_count!==0||v.file_count!==0)||v.state==='current'&&(v.running_count!==v.file_count||Number(v.file_count)<1))throw new Error('本地配置核对结果不完整，请重新读取。')
 return v as unknown as ConfigCheck
}
