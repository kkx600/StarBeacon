import type {ReplaySample} from '@starbeacon/shared/types.ts'
import type {ModelResult} from '../models/models'
import {sampleOrigin} from '@starbeacon/shared/utils/sample.ts'

export type GenerationSource='natural_language'|'pcap'|'http_raw'
export interface GenerationRequest {description:string;source:GenerationSource;sample_id:string;sample_sha256:string;provider_id:string;provider_revision:number;candidate_count:number;allow_context:boolean}
export interface PacketSnippet {packet:number;protocol:'tcp'|'udp';source_ip:string;destination_ip:string;source_port:number;destination_port:number;payload_hex:string;payload_limited:boolean}
export interface RuleCandidate {sid:number;engine_version:'8.0.7';title:string;rule:string;explanation:string;risks:string[];references:number[];package_id:string;sha256:string}
export interface GenerationEvidence {sample:ReplaySample|null;metadata:Record<string,unknown>|null;packets:PacketSnippet[];limited:boolean;sha256:string}
export interface GenerationJob {id:string;request:GenerationRequest;state:string;cancel_requested:boolean;template:'suricata-rule/1';evidence:GenerationEvidence;sids:number[];candidates:RuleCandidate[];result:ModelResult;created_at:string;started_at:string|null;finished_at:string|null;expires_at:string}
export interface GenerationSummary {id:string;title:string;source:GenerationSource;state:string;provider_id:string;created_at:string;cancel_requested:boolean}
export interface GenerationPage {items:GenerationSummary[];next_cursor:string;model_execution_available:boolean}
export const sourceNames:Record<GenerationSource,string>={natural_language:'自然语言',pcap:'PCAP 样本',http_raw:'HTTP Raw'}
export const generationStates:Record<string,string>={queued:'等待生成',running:'生成中',succeeded:'候选已生成',failed:'生成失败',refused:'提供方拒答',incomplete:'输出未完成',uncertain:'结果未知',cancelled:'已取消'}
export const generationCodes:Record<string,string>={awaiting_execution:'作业等待执行',request_in_progress:'正在请求模型，结果尚未返回',invalid_generation_output:'候选规则格式、SID 或材料引用校验未通过',authorization_revoked:'作业所有者已失去执行权限，调用未执行',provider_revision_changed:'模型修订已改变，调用未执行',provider_disabled:'模型提供方已停用，调用未执行',provider_config_unavailable:'模型配置或凭据不可用，调用未执行',generation_input_invalid:'生成输入或冻结材料不符合要求，调用未执行',sample_unavailable:'样本已过期或不可访问，调用未执行',queue_wait_expired:'等待执行超时，调用未执行',cancelled_before_execution:'作业在模型调用前取消'}
export function generationWorking(state:string){return state==='queued'||state==='running'}
export function sameGenerationRequest(a:GenerationRequest,b:GenerationRequest){
  const fields=['description','source','sample_id','sample_sha256','provider_id','provider_revision','candidate_count','allow_context'] as const
  return fields.every(key=>a[key]===b[key])
}
function record(value:unknown):value is Record<string,unknown>{return !!value&&typeof value==='object'&&!Array.isArray(value)}
function id(value:unknown){return typeof value==='string'&&/^[a-z0-9][a-z0-9_-]{0,63}$/.test(value)}
function hash(value:unknown){return typeof value==='string'&&/^[a-f0-9]{64}$/.test(value)}
function text(value:unknown,limit:number){return typeof value==='string'&&[...value].length<=limit&&!/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/.test(value)}
function date(value:unknown){return typeof value==='string'&&Number.isFinite(Date.parse(value))}
function sid(value:unknown){return Number.isInteger(value)&&Number(value)>=1000000&&Number(value)<=1999999}
function state(value:unknown){return typeof value==='string'&&Object.hasOwn(generationStates,value)}
function source(value:unknown){return typeof value==='string'&&Object.hasOwn(sourceNames,value)}
function unique(values:unknown[]){return new Set(values).size===values.length}
export function validGenerationRequest(value:unknown):value is GenerationRequest{
  if(!record(value)||!text(value.description,4000)||!String(value.description).trim()||!source(value.source)||!id(value.provider_id)||!Number.isSafeInteger(value.provider_revision)||Number(value.provider_revision)<1||!Number.isInteger(value.candidate_count)||Number(value.candidate_count)<1||Number(value.candidate_count)>3||value.allow_context!==true)return false
  return value.source==='natural_language'?value.sample_id===''&&value.sample_sha256==='':id(value.sample_id)&&hash(value.sample_sha256)
}
export function validGenerationPage(value:unknown):value is GenerationPage{
  return record(value)&&typeof value.model_execution_available==='boolean'&&(value.next_cursor===''||id(value.next_cursor))&&Array.isArray(value.items)&&value.items.length<=20&&unique(value.items.map(row=>record(row)?row.id:null))&&value.items.every(row=>record(row)&&id(row.id)&&text(row.title,80)&&source(row.source)&&state(row.state)&&id(row.provider_id)&&date(row.created_at)&&typeof row.cancel_requested==='boolean')
}
export function validGenerationSample(value:unknown):value is ReplaySample{
  return record(value)&&id(value.id)&&text(value.name,128)&&Number.isSafeInteger(value.size)&&Number(value.size)>=24&&Number(value.size)<=100*1024*1024&&hash(value.sha256)&&['pcap','pcapng'].includes(String(value.format))&&date(value.created_at)&&date(value.expires_at)&&(value.origin===undefined||!!sampleOrigin(value.origin))
}
export function validGenerationJob(value:unknown):value is GenerationJob{
  if(!record(value)||!id(value.id)||!validGenerationRequest(value.request)||!state(value.state)||typeof value.cancel_requested!=='boolean'||value.template!=='suricata-rule/1'||!date(value.created_at)||!date(value.expires_at)||!(value.started_at===null||date(value.started_at))||!(value.finished_at===null||date(value.finished_at))||!Array.isArray(value.sids)||value.sids.length!==value.request.candidate_count||!value.sids.every(sid)||!unique(value.sids)||!record(value.result)||!text(value.result.code,100)||!state(value.result.state))return false
  const evidence=value.evidence
  if(!record(evidence)||!hash(evidence.sha256)||typeof evidence.limited!=='boolean'||!Array.isArray(evidence.packets)||evidence.packets.length>8||!unique(evidence.packets.map(row=>record(row)?row.packet:null)))return false
  if(value.request.source==='natural_language'){
    if(evidence.sample!==null||evidence.metadata!==null||evidence.packets.length!==0)return false
  }else if(!validGenerationSample(evidence.sample)||!record(evidence.metadata)||evidence.sample.id!==value.request.sample_id||evidence.sample.sha256!==value.request.sample_sha256||(value.request.source==='http_raw')!==!!evidence.sample.origin?.synthetic)return false
  if(!evidence.packets.every(row=>record(row)&&Number.isInteger(row.packet)&&Number(row.packet)>=1&&Number(row.packet)<=128&&['tcp','udp'].includes(String(row.protocol))&&text(row.source_ip,45)&&text(row.destination_ip,45)&&Number.isInteger(row.source_port)&&Number(row.source_port)>=0&&Number(row.source_port)<=65535&&Number.isInteger(row.destination_port)&&Number(row.destination_port)>=0&&Number(row.destination_port)<=65535&&typeof row.payload_hex==='string'&&/^(?:[a-f0-9]{2}){1,256}$/.test(row.payload_hex)&&typeof row.payload_limited==='boolean'))return false
  if(!Array.isArray(value.candidates)||value.candidates.length>3||!unique(value.candidates.map(row=>record(row)?row.sid:null))||(value.state==='succeeded'?value.candidates.length!==value.sids.length:value.candidates.length!==0))return false
  const sids=value.sids,packets=evidence.packets
  return value.candidates.every(row=>record(row)&&sid(row.sid)&&sids.includes(row.sid)&&row.engine_version==='8.0.7'&&text(row.title,128)&&text(row.rule,16384)&&text(row.explanation,1000)&&id(row.package_id)&&hash(row.sha256)&&Array.isArray(row.risks)&&row.risks.length<=8&&row.risks.every(risk=>text(risk,300))&&Array.isArray(row.references)&&row.references.length<=8&&unique(row.references)&&row.references.every(ref=>packets.some(packet=>packet.packet===ref)))
}
