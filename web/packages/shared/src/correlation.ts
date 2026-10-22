import {instant} from './utils/instant'
import {goJSONDigest} from './utils/goJSONDigest'

export const correlationFields:Record<string,string>={'source.ip':'源 IP','destination.ip':'目的 IP','source.port':'源端口','destination.port':'目的端口','rule.id':'规则 SID'}
export const correlationStates:Record<string,string>={threshold_observed:'已观察到阈值',threshold_not_observed:'未观察到阈值',partial_window:'边界窗口不完整'}
export interface CorrelationDefinition {schema_version:'correlation-rule.v1';dataset:'alerts';filter:string;group_by:string;metric:'count'|'distinct';distinct_field:string;window_seconds:number;threshold:number}
export interface CorrelationRule {tenant_id:string;id:string;revision:number;name:string;description:string;active:boolean;definition:CorrelationDefinition;definition_sha256:string;created_by:string;created_at:string;expires_at:string}
export interface CorrelationChange {id:string;expected_revision:number;name:string;description:string;active:boolean;definition:CorrelationDefinition}
export interface CorrelationQuery {cursor:string;keyword:string;active:string;limit:number}
export interface CorrelationPage {items:CorrelationRule[];next_cursor:string}
export interface CorrelationRequest {expected_revision:number;start:string;end:string}
export interface CorrelationEvidence {event_id:string;raw_sha256:string;timestamp:string}
export interface CorrelationWindow {detection_id:string;sensor_id:string;sensor_registration_id:string;group_value:string;start:string;end:string;count:number;metric_value:number;missing_metric:number;status:string;evidence_sha256:string;evidence:CorrelationEvidence[];evidence_truncated:boolean}
export interface CorrelationResult {schema_version:'correlation-backtest.v1';tenant_id:string;rule_id:string;rule_revision:number;definition_sha256:string;query:CorrelationRequest;observed_at:string;snapshot_sha256:string;unique_events:number;duplicate_events:number;missing_group:number;threshold_windows:number;partial_windows:number;source_coverage:'not_attested';execution_authorized:false;windows:CorrelationWindow[]}

const object=(v:unknown):v is Record<string,unknown>=>!!v&&typeof v==='object'&&!Array.isArray(v)
const id=(v:unknown):v is string=>typeof v==='string'&&/^[a-z0-9][a-z0-9_-]{0,63}$/.test(v)
const digest=(v:unknown):v is string=>typeof v==='string'&&/^[a-f0-9]{64}$/.test(v)
const integer=(v:unknown,min:number,max:number):v is number=>typeof v==='number'&&Number.isSafeInteger(v)&&v>=min&&v<=max
const text=(v:unknown,max:number,required=false):v is string=>typeof v==='string'&&v===v.trim()&&(!required||!!v)&&Array.from(v).length<=max&&!/[\p{Cc}\uD800-\uDFFF]/u.test(v)
const time=(v:unknown):v is string=>typeof v==='string'&&instant(v)!==null
const failure=()=>new Error('关联回测数据与当前规则、查询或证据范围不一致，请刷新后重试。')
export const emptyCorrelationQuery=():CorrelationQuery=>({cursor:'',keyword:'',active:'',limit:20})
export const emptyCorrelationDefinition=():CorrelationDefinition=>({schema_version:'correlation-rule.v1',dataset:'alerts',filter:'',group_by:'source.ip',metric:'count',distinct_field:'',window_seconds:300,threshold:20})
export function definitionError(d:unknown):string {
 if(!object(d)||Object.keys(d).sort().join(',')!=='dataset,distinct_field,filter,group_by,metric,schema_version,threshold,window_seconds'||d.schema_version!=='correlation-rule.v1'||d.dataset!=='alerts'||!text(d.filter,4096)||new TextEncoder().encode(d.filter).length>4096||!['source.ip','destination.ip','rule.id'].includes(String(d.group_by))||!['count','distinct'].includes(String(d.metric))||!integer(d.window_seconds,15,3600)||!integer(d.threshold,2,5000)||d.metric==='count'&&d.distinct_field!==''||d.metric==='distinct'&&(!Object.hasOwn(correlationFields,String(d.distinct_field))||d.distinct_field===d.group_by))return '请选择支持的分组、计量字段及范围；窗口为 15–3600 秒，阈值为 2–5000。'
 return ''
}
export function correlationChangeError(v:CorrelationChange):string {
 if(!id(v.id)||!integer(v.expected_revision,0,999999)||!text(v.name,128,true)||!text(v.description,1000)||typeof v.active!=='boolean')return '请填写规则名称与有效修订，维护说明最多 1000 字。'
 return definitionError(v.definition)
}
export function definitionShape(d:CorrelationDefinition):CorrelationDefinition{return {schema_version:d.schema_version,dataset:d.dataset,filter:d.filter,group_by:d.group_by,metric:d.metric,distinct_field:d.distinct_field,window_seconds:d.window_seconds,threshold:d.threshold}}
export async function readCorrelationRule(v:unknown,tenant:string):Promise<CorrelationRule> {
 if(!object(v)||v.tenant_id!==tenant||!id(v.id)||!id(v.created_by)||!integer(v.revision,1,1000000)||!text(v.name,128,true)||!text(v.description,1000)||typeof v.active!=='boolean'||definitionError(v.definition)||!digest(v.definition_sha256)||!time(v.created_at)||!time(v.expires_at)||instant(v.expires_at)!<=instant(v.created_at)!)throw failure()
 if(await goJSONDigest(definitionShape(v.definition as unknown as CorrelationDefinition))!==v.definition_sha256)throw failure()
 return v as unknown as CorrelationRule
}
async function cursorPosition(cursor:string,q:CorrelationQuery,tenant:string):Promise<string>{
 if(!cursor)return ''
 if(!/^[A-Za-z0-9_-]{1,2048}$/.test(cursor))throw failure()
 let v:unknown
 try{const raw=atob(cursor.replaceAll('-','+').replaceAll('_','/'));if(btoa(raw).replaceAll('+','-').replaceAll('/','_').replaceAll('=','')!==cursor)throw failure();v=JSON.parse(raw)}catch{throw failure()}
 if(!object(v)||Object.keys(v).sort().join(',')!=='after,scope'||!id(v.after)||v.scope!==await goJSONDigest({tenant,query:{cursor:'',keyword:q.keyword,active:q.active,limit:q.limit}}))throw failure()
 return v.after
}
export async function readCorrelationPage(v:unknown,q:CorrelationQuery,tenant:string):Promise<CorrelationPage>{
 if(!object(v)||!Array.isArray(v.items)||v.items.length>q.limit||typeof v.next_cursor!=='string')throw failure()
 let previous=await cursorPosition(q.cursor,q,tenant)
 for(const raw of v.items){const item=await readCorrelationRule(raw,tenant);if(item.id<=previous||q.active&&item.active!==(q.active==='true'))throw failure();previous=item.id}
 if(v.next_cursor&&(v.items.length!==q.limit||await cursorPosition(v.next_cursor,q,tenant)!==previous))throw failure()
 return v as unknown as CorrelationPage
}
export async function readCorrelationReceipt(v:unknown,tenant:string,input:CorrelationChange,actor?:string):Promise<CorrelationRule>{
 const r=await readCorrelationRule(v,tenant)
 if(actor!==undefined&&r.created_by!==actor||r.id!==input.id||r.revision!==input.expected_revision+1||r.name!==input.name||r.description!==input.description||r.active!==input.active||r.definition_sha256!==await goJSONDigest(definitionShape(input.definition)))throw failure()
 return r
}
export function correlationRequestError(q:CorrelationRequest,now=Date.now()):string {
 const start=instant(q.start),end=instant(q.end)
 if(!integer(q.expected_revision,1,1000000)||start===null||end===null||start<946684800000000000n||end<=start||end-start>3600000000000n||start%1000000000n!==0n||end%1000000000n!==0n||end>BigInt(now)*1000000n)return '请选择已过去的起止时间，精确到秒；单次范围最多一小时。'
 return ''
}
export async function readCorrelationResult(v:unknown,rule:CorrelationRule,q:CorrelationRequest):Promise<CorrelationResult>{
	if(q.expected_revision!==rule.revision)throw failure()
 if(!object(v)||v.schema_version!=='correlation-backtest.v1'||v.tenant_id!==rule.tenant_id||v.rule_id!==rule.id||v.rule_revision!==rule.revision||v.definition_sha256!==rule.definition_sha256||!object(v.query)||v.query.expected_revision!==q.expected_revision||instant(String(v.query.start))!==instant(q.start)||instant(String(v.query.end))!==instant(q.end)||!time(v.observed_at)||instant(v.observed_at)!<instant(q.end)!||!digest(v.snapshot_sha256)||!integer(v.unique_events,0,5000)||!integer(v.duplicate_events,0,5000-v.unique_events)||!integer(v.missing_group,0,v.unique_events)||!integer(v.threshold_windows,0,512)||!integer(v.partial_windows,0,512)||v.source_coverage!=='not_attested'||v.execution_authorized!==false||!Array.isArray(v.windows)||v.windows.length>512)throw failure()
 const seen=new Set<string>(),evidenceIDs=new Set<string>(),step=BigInt(rule.definition.window_seconds)*1000000000n,start=instant(q.start)!,end=instant(q.end)!
 let count=0,threshold=0,partial=0,previous=-1n,last=''
 for(const raw of v.windows){
  if(!object(raw)||!digest(raw.detection_id)||seen.has(raw.detection_id)||!id(raw.sensor_id)||!id(raw.sensor_registration_id)||!text(raw.group_value,128,true)||!time(raw.start)||!time(raw.end)||!integer(raw.count,1,5000)||!integer(raw.metric_value,0,raw.count)||!integer(raw.missing_metric,0,raw.count)||!digest(raw.evidence_sha256)||!Array.isArray(raw.evidence)||raw.evidence.length!==Math.min(8,raw.count)||raw.evidence_truncated!==(raw.count>8))throw failure()
  const a=instant(raw.start)!,b=instant(raw.end)!,status=a<start||b>end?'partial_window':raw.metric_value>=rule.definition.threshold?'threshold_observed':'threshold_not_observed'
  if(a%step!==0n||b-a!==step||a>=end||b<=start||raw.status!==status||rule.definition.metric==='count'&&(raw.metric_value!==raw.count||raw.missing_metric!==0)||rule.definition.metric==='distinct'&&raw.metric_value>raw.count-raw.missing_metric||a<previous||a===previous&&raw.detection_id<=last)throw failure()
  const expected=await goJSONDigest([rule.tenant_id,rule.id,String(rule.revision),rule.definition_sha256,raw.sensor_id,raw.sensor_registration_id,rule.definition.group_by,raw.group_value,new Date(Number(a/1000000n)).toISOString().replace('.000Z','Z'),'threshold'])
  if(expected!==raw.detection_id)throw failure()
  let prior=''
  for(const item of raw.evidence){if(!object(item)||!id(item.event_id)||item.event_id<=prior||evidenceIDs.has(item.event_id)||!digest(item.raw_sha256)||!time(item.timestamp)||instant(item.timestamp)!<start||instant(item.timestamp)!>=end||instant(item.timestamp)!<a||instant(item.timestamp)!>=b)throw failure();prior=item.event_id;evidenceIDs.add(item.event_id)}
  count+=raw.count;threshold+=status==='threshold_observed'?1:0;partial+=status==='partial_window'?1:0;previous=a;last=raw.detection_id;seen.add(raw.detection_id)
 }
 if(count!==v.unique_events-v.missing_group||threshold!==v.threshold_windows||partial!==v.partial_windows)throw failure()
 return v as unknown as CorrelationResult
}
