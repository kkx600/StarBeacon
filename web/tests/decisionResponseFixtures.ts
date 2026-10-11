import {goJSONDigest} from '@starbeacon/shared/utils/goJSONDigest.ts'
import type {Sensor} from '@starbeacon/shared/types.ts'
import {principal,sensor} from './fixtures'
import {triageJob} from './triageFixtures'
import {orderedPolicy,type PolicyRecord} from '../platform/src/features/decisions/decisionPolicies'
import {orderedEvaluation,type EvaluationRecord} from '../platform/src/features/decisions/decisionEvaluations'
import {orderedDecisionResponse,type DecisionResponseRecord,type DecisionResponseRequest} from '../platform/src/features/decisions/decisionResponses'

export async function responseEvaluation():Promise<EvaluationRecord>{
 const job=structuredClone(triageJob),material=job.evidence
 material.sha256=await goJSONDigest({...material,sha256:''})
 const definition={schema_version:'decision-policy.v1' as const,mode:'shadow' as const,expression:'confidence >= threshold',threshold:.8,candidate_action:'block_source' as const,max_age_seconds:3600,protected_prefixes:[]}
 const policy:PolicyRecord={tenant_id:principal.tenant_id,id:'policy_owned',revision:1,name:'攻击尝试策略',description:'管理员核对原告警',active:true,definition,definition_sha256:await goJSONDigest(orderedPolicy(definition)),created_by:principal.id,created_at:'2026-10-10T00:00:00Z',expires_at:'2027-04-08T00:00:00Z'}
 const value:EvaluationRecord={schema_version:'decision-evaluation.v1',tenant_id:principal.tenant_id,id:'evaluation_owned',created_by:principal.id,expires_at:'2027-04-08T00:00:00Z',policy,result:{schema_version:'decision-shadow.v1',policy_id:policy.id,policy_revision:1,definition_sha256:policy.definition_sha256,triage_id:job.id,provider_id:job.request.provider_id,provider_revision:job.request.provider_revision,event_id:job.request.event_id,raw_sha256:job.request.raw_sha256,evidence_sha256:material.sha256,evaluated_at:new Date(Date.now()-60000).toISOString(),status:'matched',confidence:.87,confidence_kind:'self_reported',candidate_action:'block_source',target_ip:'198.51.100.21',execution_authorized:false,reasons:['expression_matched'],limitations:[...material.limitations,'影子评估不创建通知、研判修改或设备动作','模型自报分数未获得场景校准资格'],cost:7},sha256:''}
 value.sha256=await goJSONDigest(orderedEvaluation(value));return value
}
export function responseSensor():Sensor{return {...sensor,active:true,status:'online',last_seen:new Date().toISOString(),health:{...sensor.health,task_capabilities:['response.block','response.read','response.revoke'],response_connectors:[{connector_id:'connector_test',device_id:'device_test',version:'protocol-fixture/1',config_sha256:'a'.repeat(64),status:'ready',observed_at:new Date().toISOString(),max_ttl_seconds:3600}]}}}
export function responseInput(e:EvaluationRecord):DecisionResponseRequest{return {evaluation_sha256:e.sha256,sensor_id:sensor.id,registration_id:sensor.registration_id,connector_id:'connector_test',config_sha256:'a'.repeat(64),ttl_seconds:300,reason:'管理员核对异常通信',confirmed:true}}
export async function responseReceipt(e:EvaluationRecord,request=responseInput(e)):Promise<DecisionResponseRecord>{
 const r:DecisionResponseRecord={schema_version:'decision-response.v1',tenant_id:e.tenant_id,id:'decision_response_'+'1'.repeat(32),created_by:e.created_by,created_at:new Date().toISOString(),expires_at:new Date(Date.now()+180*86400000).toISOString(),evaluation_id:e.id,evaluation_sha256:e.sha256,policy_id:e.policy.id,policy_revision:e.policy.revision,definition_sha256:e.policy.definition_sha256,triage_id:e.result.triage_id,evidence_sha256:e.result.evidence_sha256,target_ip:e.result.target_ip,request,task_id:'task_'+'2'.repeat(32),sha256:''}
 r.sha256=await goJSONDigest(orderedDecisionResponse(r));return r
}
