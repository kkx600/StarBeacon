import { goJSONDigest } from '@starbeacon/shared/utils/goJSONDigest.ts';
import {
  automationLevels,
  decisionConfirmationWindowMs,
  orderedContinuous,
  validContinuous,
  policyID,
  type AutomationLevel,
  type ContinuousConfig,
  type PolicyResult,
} from './decisionPolicies';
import type { EvaluationRecord } from './decisionEvaluations';
export const continuousCodes = {
  policy_authorized: '策略已授权签名任务',
  manual_confirmation_required: '等待管理员确认候选',
  policy_not_matched: '当前策略或材料未满足判断条件',
  model_binding_changed: '模型处于停用状态或绑定修订已变化',
  score_below_threshold: '模型自报分数未达到固定阈值',
  conclusion_not_eligible: '结论、攻击结果或建议未满足固定门槛',
  evidence_limited: '告警材料存在未完整提供的字段',
  references_incomplete: '缺少源 IP 或命中规则的事实引用',
  sensor_binding_changed: '观测探针或执行注册代次变化',
  evidence_changed: '当前告警与冻结材料不一致',
  target_cooldown: '同一设备目标仍处于冷却期',
  event_already_authorized: '本设备已授权同一告警的任务',
  hourly_quota: '本策略每小时授权额度已用完',
  device_unavailable: '探针、设备配置、签名或期限未就绪',
  target_protected: '目标命中有效保护名单，未创建封禁任务',
  task_conflict: '探针存在在途任务或未确认结果',
  tenant_quota: '租户响应任务额度已用完',
  observation_only: '当前级别仅观察',
  manual_investigation: '方案交由人工研判',
  plan_already_recorded: '同一场景已登记原待确认方案',
} as const;
export const continuousStates = {
  queued: '任务已受理',
  awaiting_confirmation: '等待人工确认',
  skipped: '未授权执行',
} as const;
export interface DecisionPlanSummary {
  level: AutomationLevel;
  impact: 'none' | 'small' | 'high';
  action: PolicyResult['candidate_action'];
  confidence: number;
  verdict: 'confirmed' | 'undetermined' | 'false_positive';
  outcome: 'attempt' | 'unknown';
  references: string[];
  missing: string[];
  evidence_sha256: string;
  confirm_until?: string;
}
export interface ContinuousRecord {
  schema_version: 'decision-continuous.v1';
  tenant_id: string;
  id: string;
  created_by: string;
  evaluation_id: string;
  evaluation_sha256: string;
  policy_id: string;
  policy_revision: number;
  definition_sha256: string;
  triage_id: string;
  event_id: string;
  raw_sha256: string;
  target_ip: string;
  config: ContinuousConfig;
  state: keyof typeof continuousStates;
  code: keyof typeof continuousCodes;
  task_id: string;
  created_at: string;
  expires_at: string;
  sha256: string;
  plan?: DecisionPlanSummary;
}
function orderedPlan(plan: DecisionPlanSummary): DecisionPlanSummary {
  return {
    level: plan.level,
    impact: plan.impact,
    action: plan.action,
    confidence: plan.confidence,
    verdict: plan.verdict,
    outcome: plan.outcome,
    references: [...plan.references],
    missing: [...plan.missing],
    evidence_sha256: plan.evidence_sha256,
    ...(plan.confirm_until ? { confirm_until: plan.confirm_until } : {}),
  };
}
const excerpts = (v: unknown) => Array.isArray(v) && v.length <= 8 && v.every(item => typeof item === 'string');
function validPlan(r: ContinuousRecord, e: EvaluationRecord) {
  const p = r.plan;
  if (!p || typeof p !== 'object' || Array.isArray(p)) return false;
  const confirming = r.state === 'awaiting_confirmation';
  if (
    Object.keys(p).length !== (confirming ? 10 : 9) ||
    !Object.hasOwn(automationLevels, p.level) ||
    p.action !== e.result.candidate_action ||
    (p.action === 'block_source' ? !['small', 'high'].includes(p.impact) : p.impact !== 'none') ||
    !Number.isFinite(p.confidence) ||
    p.confidence < 0 ||
    p.confidence > 1 ||
    (e.result.confidence !== null && p.confidence !== e.result.confidence) ||
    !['confirmed', 'undetermined', 'false_positive'].includes(p.verdict) ||
    !['attempt', 'unknown'].includes(p.outcome) ||
    !excerpts(p.references) ||
    !excerpts(p.missing) ||
    p.evidence_sha256 !== e.result.evidence_sha256
  )
    return false;
  if (!confirming) return !Object.hasOwn(p, 'confirm_until');
  if (typeof p.confirm_until !== 'string') return false;
  const deadline = Date.parse(p.confirm_until),
    created = Date.parse(r.created_at);
  return (
    Number.isFinite(deadline) &&
    deadline >= created &&
    deadline <= Math.min(created + decisionConfirmationWindowMs, Date.parse(r.expires_at)) &&
    p.action === 'block_source' &&
    (p.level === 'approval' || (p.level === 'conditional' && p.impact === 'high'))
  );
}
export function orderedContinuousRecord(r: ContinuousRecord): ContinuousRecord {
  return {
    schema_version: r.schema_version,
    tenant_id: r.tenant_id,
    id: r.id,
    created_by: r.created_by,
    evaluation_id: r.evaluation_id,
    evaluation_sha256: r.evaluation_sha256,
    policy_id: r.policy_id,
    policy_revision: r.policy_revision,
    definition_sha256: r.definition_sha256,
    triage_id: r.triage_id,
    event_id: r.event_id,
    raw_sha256: r.raw_sha256,
    target_ip: r.target_ip,
    config: orderedContinuous(r.config),
    state: r.state,
    code: r.code,
    task_id: r.task_id,
    created_at: r.created_at,
    expires_at: r.expires_at,
    sha256: '',
    ...(r.plan ? { plan: orderedPlan(r.plan) } : {}),
  };
}
export async function validContinuousRecord(
  v: unknown,
  e: EvaluationRecord,
  tenant: string,
  owner: string,
): Promise<boolean> {
  if (!v || typeof v !== 'object' || Array.isArray(v)) return false;
  const r = v as ContinuousRecord;
  const hasPlan = Object.hasOwn(r, 'plan');
  if (
    Object.keys(r).length !== 20 + Number(hasPlan) ||
    r.schema_version !== 'decision-continuous.v1' ||
    r.tenant_id !== tenant ||
    r.created_by !== owner ||
    !policyID(r.id) ||
    r.evaluation_id !== e.id ||
    r.evaluation_sha256 !== e.sha256 ||
    r.policy_id !== e.policy.id ||
    r.policy_revision !== e.policy.revision ||
    r.definition_sha256 !== e.policy.definition_sha256 ||
    r.triage_id !== e.result.triage_id ||
    r.event_id !== e.result.event_id ||
    r.raw_sha256 !== e.result.raw_sha256 ||
    r.target_ip !== e.result.target_ip ||
    !e.policy.definition.continuous ||
    !validContinuous(r.config, e.policy.definition.mode) ||
    !Object.hasOwn(continuousStates, String(r.state)) ||
    !Object.hasOwn(continuousCodes, String(r.code)) ||
    typeof r.task_id !== 'string' ||
    typeof r.created_at !== 'string' ||
    typeof r.expires_at !== 'string' ||
    !Number.isFinite(Date.parse(r.created_at)) ||
    Date.parse(r.created_at) < Date.parse(e.result.evaluated_at) ||
    !Number.isFinite(Date.parse(r.expires_at)) ||
    Date.parse(r.expires_at) <= Date.parse(r.created_at) ||
    typeof r.sha256 !== 'string' ||
    !/^[a-f0-9]{64}$/.test(r.sha256) ||
    (hasPlan && !validPlan(r, e)) ||
    (await goJSONDigest(orderedContinuous(r.config))) !==
      (await goJSONDigest(orderedContinuous(e.policy.definition.continuous)))
  )
    return false;
  if (r.state === 'queued') {
    if (
      !r.config.automatic ||
      r.code !== 'policy_authorized' ||
      !policyID(r.task_id) ||
      !r.target_ip ||
      e.result.status !== 'matched' ||
      (r.plan && r.plan.level !== 'full' && !(r.plan.level === 'conditional' && r.plan.impact === 'small'))
    )
      return false;
  } else if (r.state === 'awaiting_confirmation') {
    if (
      (!r.plan && r.config.automatic) ||
      r.code !== 'manual_confirmation_required' ||
      r.task_id !== '' ||
      e.result.status !== 'matched'
    )
      return false;
  } else if (r.task_id !== '' || r.code === 'policy_authorized' || r.code === 'manual_confirmation_required')
    return false;
  return (await goJSONDigest(orderedContinuousRecord(r))) === r.sha256;
}
