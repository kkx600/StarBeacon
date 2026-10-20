import type {SensorTask} from './types'
import {validTask} from './useTaskDetail'
import {instant} from './utils/instant'
import {goJSONDigest} from './utils/goJSONDigest'

export interface ResponseFilters {start:string;end:string;sensor_id:string;device_id:string;target_ip:string;kind:string;state:string}
export interface ResponseQuery extends ResponseFilters {cursor:string;limit:number}
export interface ResponsePage {items:SensorTask[];next_cursor:string;query:ResponseQuery;observed_at:string}
const id=/^[a-z0-9][a-z0-9_-]{0,63}$/
const object=(value:unknown):value is Record<string,unknown>=>!!value&&typeof value==='object'&&!Array.isArray(value)
export const responseKinds=[{value:'',label:'全部动作'},{value:'response.block',label:'限时封禁'},{value:'response.read',label:'租约回读'},{value:'response.revoke',label:'解除租约'}]

function localInput(at:number){const value=new Date(at);return new Date(at-value.getTimezoneOffset()*60000).toISOString().slice(0,19)}
export function defaultResponseFilters(now=Date.now()):ResponseFilters{return {start:localInput(now-24*3600000),end:localInput(now),sensor_id:'',device_id:'',target_ip:'',kind:'',state:''}}
export function responseQuery(filters:ResponseFilters):ResponseQuery{
 const start=new Date(filters.start).getTime(),end=new Date(filters.end).getTime()
 if(!Number.isFinite(start)||!Number.isFinite(end)||end<=start||end-start>31*86400000||end>Date.now()+30000)throw new Error('请选择有效的本地时间，结束时间须晚于开始时间，窗口最多 31 天。')
 if(['sensor_id','device_id'].some(key=>!!filters[key as keyof ResponseFilters]&&!id.test(filters[key as keyof ResponseFilters])))throw new Error('探针与设备标识须为 1–64 位小写字母、数字、下划线或连字符。')
 return {...filters,start:new Date(start).toISOString(),end:new Date(end).toISOString(),cursor:'',limit:20}
}

function cursor(value:string){
 try{
 if(!/^[A-Za-z0-9_-]{1,512}$/.test(value))throw new Error('分页凭据不完整')
 const decoded=atob(value.replaceAll('-','+').replaceAll('_','/')),c:unknown=JSON.parse(decoded)
 if(!object(c)||Object.keys(c).sort().join(',')!=='id,query,time'||typeof c.time!=='string'||instant(c.time)===null||typeof c.id!=='string'||!id.test(c.id)||typeof c.query!=='string'||!/^[a-f0-9]{64}$/.test(c.query)||btoa(JSON.stringify({time:c.time,id:c.id,query:c.query})).replaceAll('+','-').replaceAll('/','_').replace(/=+$/,'')!==value)throw new Error('分页凭据不完整')
 return c as {time:string;id:string;query:string}
 }catch{throw new Error('分页凭据不完整，请重新查询。')}
}

// 同时核对筛选回显、纳秒顺序与续页绑定，不用不完整结果覆盖当前页面。
export async function readResponsePage(value:unknown,q:ResponseQuery):Promise<ResponsePage>{
 const invalid=()=>new Error('响应动作列表未能完整返回，请刷新后核对。')
 if(!object(value)||!Array.isArray(value.items)||value.items.length>q.limit||!object(value.query)||typeof value.observed_at!=='string'||instant(value.observed_at)===null||typeof value.next_cursor!=='string')throw invalid()
 const echo=value.query,start=instant(q.start)!,end=instant(q.end)!
 if(typeof echo.start!=='string'||typeof echo.end!=='string'||instant(echo.start)!==start||instant(echo.end)!==end||!['sensor_id','device_id','target_ip','kind','state','cursor','limit'].every(key=>echo[key]===q[key as keyof ResponseQuery]))throw invalid()
 const fingerprint=await goJSONDigest({start:echo.start,end:echo.end,sensor_id:q.sensor_id,kind:q.kind,state:q.state,target_ip:q.target_ip,device_id:q.device_id,cursor:'',limit:q.limit})
 let previous=q.cursor?cursor(q.cursor):null
 if(previous&&previous.query!==fingerprint)throw invalid()
 for(const row of value.items){
  if(!object(row)||typeof row.id!=='string'||!validTask(row,row.id)||!row.kind.startsWith('response.')||!row.response_action||q.sensor_id&&row.sensor_id!==q.sensor_id||q.kind&&row.kind!==q.kind||q.state&&row.state!==q.state||q.target_ip&&row.response_action.target_ip!==q.target_ip||q.device_id&&row.response_action.device_id!==q.device_id)throw invalid()
  const created=instant(row.created_at),before=previous?instant(previous.time):null
  if(created===null||created<start||created>=end||before!==null&&(created>before||created===before&&row.id>=previous!.id))throw invalid()
  previous={time:row.created_at,id:row.id,query:fingerprint}
 }
 if(value.next_cursor){const next=cursor(value.next_cursor);if(value.items.length!==q.limit||!previous||next.id!==previous.id||instant(next.time)!==instant(previous.time)||next.query!==fingerprint)throw invalid()}
 return value as unknown as ResponsePage
}
