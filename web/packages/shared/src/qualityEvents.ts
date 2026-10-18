import {instant} from './utils/instant'
import {qualityCounters,readQuality,type QualityReport} from './detectionQuality'

export const qualityEventNames={limitation:'检测区间存在限制',policy:'检测策略产生影响',uncertain:'检测区间无法核对',interval_clear:'原限制未再报告增量',observation_resumed:'连续区间重新可观测'} as const
export type QualityEventKind=keyof typeof qualityEventNames
export interface QualityEvent {schema_version:1;id:string;tenant_id:string;sensor_id:string;sensor_registration_id:string;created_at:string;signal:{kind:QualityEventKind;reasons:string[];fingerprint:string;prior_event_id?:string;reminder?:boolean};report:QualityReport}
export interface QualityPage {items:QualityEvent[];total:string;page:number;page_size:20}
export interface QualityQuery {start:string;end:string;page:string;sensor_id?:string;registration_id?:string;kind?:string}
export interface QualityFilters {start:string;end:string;sensor:string;registration:string;kind:string}
const id=(v:unknown):v is string=>typeof v==='string'&&/^[a-z0-9][a-z0-9_-]{0,63}$/.test(v)
const digest=(v:unknown):v is string=>typeof v==='string'&&/^[a-f0-9]{64}$/.test(v)
const object=(v:unknown):v is Record<string,unknown>=>!!v&&typeof v==='object'&&!Array.isArray(v)
export const localQualityTime=(value:Date)=>new Date(value.getTime()-value.getTimezoneOffset()*60000).toISOString().slice(0,19)
export function qualityQuery(form:QualityFilters,page=1):QualityQuery{
 const start=new Date(form.start),end=new Date(form.end),sensor=form.sensor.trim(),registration=form.registration.trim()
 if(!Number.isFinite(start.getTime())||!Number.isFinite(end.getTime())||start.getUTCFullYear()<2000||end.getUTCFullYear()>2100||end<=start||end.getTime()-start.getTime()>31*86400000||!Number.isInteger(page)||page<1||page>500||sensor&&!id(sensor)||registration&&(!id(registration)||!sensor)||form.kind&&!(form.kind in qualityEventNames))throw new Error('请核对探针、注册代次和时间：窗口须大于 0 且不超过 31 天，注册代次须同时指定探针。')
 return {start:start.toISOString(),end:end.toISOString(),page:String(page),...(sensor?{sensor_id:sensor}:{}),...(registration?{registration_id:registration}:{}),...(form.kind?{kind:form.kind}:{})}
}

// 历史区间保留纳秒边界；总数与原生累计值不经过浮点转换。
export function readQualityPage(value:unknown,q:QualityQuery,tenant:string):QualityPage{
 const fail=()=>{throw new Error('质量事件回执不完整或与查询范围不一致，本次未交付结果。')}
 const start=instant(q.start),end=instant(q.end),page=Number(q.page)
 if(!id(tenant)||start===null||end===null||end<=start||end-start>2678400000000000n||!Number.isInteger(page)||page<1||page>500||!object(value)||!Array.isArray(value.items)||value.items.length>20||typeof value.total!=='string'||!/^(0|[1-9][0-9]{0,18})$/.test(value.total)||BigInt(value.total)>9223372036854775807n||value.page!==page||value.page_size!==20) return fail()
 const seen=new Set<string>()
 for(const row of value.items){
  if(!object(row)||row.schema_version!==1||!digest(row.id)||seen.has(row.id)||row.tenant_id!==tenant||!id(row.sensor_id)||!id(row.sensor_registration_id)||q.sensor_id&&row.sensor_id!==q.sensor_id||q.registration_id&&row.sensor_registration_id!==q.registration_id||typeof row.created_at!=='string'||!object(row.signal)||typeof row.signal.kind!=='string'||!Object.hasOwn(qualityEventNames,row.signal.kind)||q.kind&&row.signal.kind!==q.kind||!digest(row.signal.fingerprint)||!Array.isArray(row.signal.reasons)||row.signal.reasons.length<1||row.signal.reasons.length>25||row.signal.reminder!==undefined&&typeof row.signal.reminder!=='boolean')return fail()
  const created=instant(row.created_at),report=object(row.report)&&typeof row.report.config_sha256==='string'?readQuality(row.report,row.report.config_sha256):null,signal=row.signal
  if(created===null||created<start||created>=end||!report||!report.sampled_at||!report.received_at||!report.engine_run_id||!report.config_sha256)return fail()
  const reasons=signal.reasons as unknown[]
  if(reasons.some((key,index)=>typeof key!=='string'||index>0&&String(reasons[index-1])>=key))return fail()
  if(signal.kind==='interval_clear'||signal.kind==='observation_resumed'){
   if(!digest(signal.prior_event_id)||signal.reminder===true||report.state!=='observed')return fail()
   if(signal.kind==='observation_resumed'){if(reasons.length!==1||reasons[0]!=='continuous_interval')return fail()}
   else if(reasons.some(key=>!Object.hasOwn(qualityCounters,String(key))||!report.counters.some(c=>c.key===key&&c.kind==='counter'&&c.delta==='0')))return fail()
  }else{
   if(signal.prior_event_id!==undefined)return fail()
   if(signal.kind==='uncertain'){if(!['counter_reset','sample_gap','stale','stopped'].includes(report.state)||reasons.length!==1||reasons[0]!==report.state)return fail()}
   else {
    const expected=[...report.capture.reasons,...report.inspection.reasons,...report.alerting.reasons,...report.policy.reasons].sort()
    const limited=[report.capture,report.inspection,report.alerting].some(f=>f.state==='limited')
    if(report.state!=='observed'||signal.kind!==(limited?'limitation':'policy')||!expected.length||JSON.stringify(expected)!==JSON.stringify(reasons))return fail()
   }
  }
  seen.add(row.id)
 }
 const offset=BigInt(page-1)*20n,total=BigInt(value.total)
 if(value.items.length>0&&total<offset+BigInt(value.items.length)||value.items.length!==Number(total>offset?total-offset>20n?20n:total-offset:0n))return fail()
 for(let i=1;i<value.items.length;i++){const prior=value.items[i-1] as QualityEvent,current=value.items[i] as QualityEvent;if(instant(prior.created_at)!<instant(current.created_at)!||instant(prior.created_at)===instant(current.created_at)&&prior.id>current.id)return fail()}
 return structuredClone(value) as unknown as QualityPage
}
